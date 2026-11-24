//! Serialização determinística do payload (docs/format.md §7). Parser defensivo: valida contagens
//! contra limites e bytes restantes antes de alocar; nunca entra em pânico com entrada hostil.

use zeroize::Zeroizing;

use crate::error::{FormatError, Result};
use crate::limits::*;
use crate::model::{CustomField, Entry, Settings, Snapshot};

pub const PAYLOAD_MAGIC: &[u8; 4] = b"KVP1";
const HEADER_LEN: usize = 4 + 16 + 8 + 2 + 2 + 1 + 1 + 4; // 38
const MIN_ENTRY_LEN: usize = 16 + 8 + 8 + 1 + (4 + 1) + 4 * 4 + 2 + 2; // 58
const MIN_TAG_LEN: usize = 4 + 1;
const MIN_FIELD_LEN: usize = 16 + 1 + (4 + 1) + 4; // 26

fn str_len(s: &str) -> Option<usize> {
    s.len().checked_add(4)
}

/// Tamanho exato da serialização, com aritmética verificada.
pub fn encoded_len(s: &Snapshot) -> Option<usize> {
    let mut n = HEADER_LEN;
    for e in &s.entries {
        n = n.checked_add(16 + 8 + 8 + 1)?;
        for t in [&e.title, &e.url, &e.username, &e.password, &e.notes] {
            n = n.checked_add(str_len(t)?)?;
        }
        n = n.checked_add(2)?;
        for t in &e.tags {
            n = n.checked_add(str_len(t)?)?;
        }
        n = n.checked_add(2)?;
        for f in &e.fields {
            n = n.checked_add(16 + 1)?.checked_add(str_len(&f.name)?)?.checked_add(str_len(&f.value)?)?;
        }
    }
    Some(n)
}

/// Serializa após validar o snapshot. O buffer tem capacidade exata (sem realocação que deixaria
/// cópias de texto claro em memória liberada) e é zerado ao ser descartado.
pub fn encode(s: &Snapshot) -> Result<Zeroizing<Vec<u8>>> {
    s.validate()?;
    let len = encoded_len(s).ok_or(FormatError::PayloadTooLarge)?;
    if len > MAX_PAYLOAD_BYTES {
        return Err(FormatError::PayloadTooLarge.into());
    }
    let mut out = Zeroizing::new(Vec::with_capacity(len));
    let b = &mut *out;
    b.extend_from_slice(PAYLOAD_MAGIC);
    b.extend_from_slice(&s.vault_id);
    b.extend_from_slice(&s.revision.to_le_bytes());
    b.extend_from_slice(&s.settings.auto_lock_minutes.to_le_bytes());
    b.extend_from_slice(&s.settings.clipboard_seconds.to_le_bytes());
    b.push(s.settings.lock_on_blur as u8);
    b.push(0);
    b.extend_from_slice(&(s.entries.len() as u32).to_le_bytes());
    let put_str = |b: &mut Vec<u8>, t: &str| {
        b.extend_from_slice(&(t.len() as u32).to_le_bytes());
        b.extend_from_slice(t.as_bytes());
    };
    for e in &s.entries {
        b.extend_from_slice(&e.id);
        b.extend_from_slice(&e.created_at_ms.to_le_bytes());
        b.extend_from_slice(&e.updated_at_ms.to_le_bytes());
        b.push(e.favorite as u8);
        put_str(b, &e.title);
        put_str(b, &e.url);
        put_str(b, &e.username);
        put_str(b, &e.password);
        put_str(b, &e.notes);
        b.extend_from_slice(&(e.tags.len() as u16).to_le_bytes());
        for t in &e.tags {
            put_str(b, t);
        }
        b.extend_from_slice(&(e.fields.len() as u16).to_le_bytes());
        for f in &e.fields {
            b.extend_from_slice(&f.id);
            b.push(f.secret as u8);
            put_str(b, &f.name);
            put_str(b, &f.value);
        }
    }
    debug_assert_eq!(b.len(), len);
    Ok(out)
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    fn take(&mut self, n: usize) -> std::result::Result<&'a [u8], FormatError> {
        if self.remaining() < n {
            return Err(FormatError::Truncated);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn arr<const N: usize>(&mut self) -> std::result::Result<[u8; N], FormatError> {
        let mut a = [0u8; N];
        a.copy_from_slice(self.take(N)?);
        Ok(a)
    }
    fn u8(&mut self) -> std::result::Result<u8, FormatError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> std::result::Result<u16, FormatError> {
        Ok(u16::from_le_bytes(self.arr()?))
    }
    fn u32(&mut self) -> std::result::Result<u32, FormatError> {
        Ok(u32::from_le_bytes(self.arr()?))
    }
    fn u64(&mut self) -> std::result::Result<u64, FormatError> {
        Ok(u64::from_le_bytes(self.arr()?))
    }
    fn i64(&mut self) -> std::result::Result<i64, FormatError> {
        Ok(i64::from_le_bytes(self.arr()?))
    }
    fn bool(&mut self) -> std::result::Result<bool, FormatError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(FormatError::Bool),
        }
    }
    fn string(&mut self, allow_empty: bool) -> std::result::Result<String, FormatError> {
        let len = self.u32()? as usize;
        if len > MAX_FIELD_BYTES {
            return Err(FormatError::FieldTooLong);
        }
        if len == 0 && !allow_empty {
            return Err(FormatError::Empty);
        }
        let bytes = self.take(len)?;
        let s = std::str::from_utf8(bytes).map_err(|_| FormatError::Utf8)?;
        Ok(s.to_owned())
    }
    fn count(&mut self, n: usize, max: usize, min_item: usize) -> std::result::Result<usize, FormatError> {
        if n > max {
            return Err(FormatError::Count);
        }
        // Rejeita contagens impossíveis antes de reservar memória.
        if n.checked_mul(min_item).is_none_or(|need| need > self.remaining()) {
            return Err(FormatError::Truncated);
        }
        Ok(n)
    }
}

fn timestamp(r: &mut Reader<'_>) -> std::result::Result<i64, FormatError> {
    let t = r.i64()?;
    if !(0..=MAX_TIMESTAMP_MS).contains(&t) {
        return Err(FormatError::Timestamp);
    }
    Ok(t)
}

fn nonzero_id(r: &mut Reader<'_>) -> std::result::Result<[u8; 16], FormatError> {
    let id = r.arr::<16>()?;
    if id == [0u8; 16] {
        return Err(FormatError::Identifier);
    }
    Ok(id)
}

/// Parsing estrito. Só deve ser chamado com bytes já autenticados (o envelope garante isso);
/// também é exercitado diretamente por fuzzing.
pub fn decode(buf: &[u8], expect_vault_id: &[u8; 16], expect_revision: u64) -> Result<Snapshot> {
    if buf.len() > MAX_PAYLOAD_BYTES {
        return Err(FormatError::PayloadTooLarge.into());
    }
    let mut r = Reader { buf, pos: 0 };
    if r.take(4)? != PAYLOAD_MAGIC {
        return Err(FormatError::PayloadMagic.into());
    }
    let vault_id = r.arr::<16>()?;
    let revision = r.u64()?;
    if &vault_id != expect_vault_id || revision != expect_revision {
        return Err(FormatError::PayloadContext.into());
    }
    let settings = Settings { auto_lock_minutes: r.u16()?, clipboard_seconds: r.u16()?, lock_on_blur: r.bool()? };
    settings.validate()?;
    if r.u8()? != 0 {
        return Err(FormatError::Reserved.into());
    }
    let n = r.u32()? as usize;
    let n = r.count(n, MAX_ENTRIES, MIN_ENTRY_LEN)?;
    let mut snap = Snapshot { vault_id, revision, settings, entries: Vec::with_capacity(n) };
    for _ in 0..n {
        let id = nonzero_id(&mut r)?;
        let created_at_ms = timestamp(&mut r)?;
        let updated_at_ms = timestamp(&mut r)?;
        if updated_at_ms < created_at_ms {
            return Err(FormatError::Timestamp.into());
        }
        let favorite = r.bool()?;
        let mut e = Entry {
            id,
            created_at_ms,
            updated_at_ms,
            favorite,
            title: r.string(false)?,
            url: r.string(true)?,
            username: r.string(true)?,
            password: r.string(true)?,
            notes: r.string(true)?,
            tags: Vec::new(),
            fields: Vec::new(),
        };
        let tc = r.u16()? as usize;
        let tc = r.count(tc, MAX_TAGS, MIN_TAG_LEN)?;
        e.tags.reserve_exact(tc);
        for _ in 0..tc {
            let t = r.string(false)?;
            if e.tags.contains(&t) {
                return Err(FormatError::Duplicate.into());
            }
            e.tags.push(t);
        }
        let fc = r.u16()? as usize;
        let fc = r.count(fc, MAX_CUSTOM_FIELDS, MIN_FIELD_LEN)?;
        e.fields.reserve_exact(fc);
        for _ in 0..fc {
            let id = nonzero_id(&mut r)?;
            if e.fields.iter().any(|f| f.id == id) {
                return Err(FormatError::Identifier.into());
            }
            let secret = r.bool()?;
            let name = r.string(false)?;
            let value = r.string(true)?;
            e.fields.push(CustomField { id, secret, name, value });
        }
        // Duplicidade de entry_id é verificada em `snap.validate()` (ordenação, O(n log n)).
        snap.entries.push(e);
    }
    if r.remaining() != 0 {
        return Err(FormatError::TrailingBytes.into());
    }
    // Validação de domínio completa (mesmas regras da escrita).
    snap.validate()?;
    Ok(snap)
}
