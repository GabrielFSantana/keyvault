//! Envelope v1 (docs/format.md §3–§9): cabeçalho canônico, AAD com separação de domínio,
//! envelope encryption (Argon2id → KEK → DEK → snapshot).

use zeroize::Zeroizing;

use crate::crypto::*;
use crate::error::{CoreError, FormatError, Result};
use crate::limits::*;
use crate::model::{Snapshot, VaultId};
use crate::payload;
use crate::rng::SecureRandom;
use crate::secret::MasterPassword;

pub const MAGIC: &[u8; 4] = b"KVLT";
pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const SUITE_ID: u16 = 1;
pub const HEADER_LEN: usize = 132;
pub const MIN_ENVELOPE_LEN: usize = HEADER_LEN + WRAPPED_DEK_LEN + TAG_LEN;
pub const DOMAIN_SNAPSHOT: &[u8] = b"KeyVault/snapshot/v1";
pub const DOMAIN_WRAP: &[u8] = b"KeyVault/wrap/v1";
const MAX_DATA_CT_LEN: u64 = MAX_PAYLOAD_BYTES as u64 + TAG_LEN as u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum EnvelopeKind {
    /// Slot único do banco SQLite.
    VaultSlot = 1,
    /// Arquivo `.keyvault` de backup.
    Backup = 2,
}

/// Cabeçalho público (metadados técnicos). Todos os campos são autenticados via AAD.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub vault_id: VaultId,
    pub revision: u64,
    pub kdf: KdfParams,
    pub salt: [u8; SALT_LEN],
    pub kind: EnvelopeKind,
    pub data_ciphertext_len: u64,
}

impl Header {
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut h = [0u8; HEADER_LEN];
        let mut w = 0usize;
        let mut put = |bytes: &[u8]| {
            h[w..w + bytes.len()].copy_from_slice(bytes);
            w += bytes.len();
        };
        put(MAGIC);
        put(&FORMAT_VERSION.to_le_bytes());
        put(&SCHEMA_VERSION.to_le_bytes());
        put(&SUITE_ID.to_le_bytes());
        put(&(HEADER_LEN as u16).to_le_bytes());
        put(&self.vault_id);
        put(&self.revision.to_le_bytes());
        put(&0x13u32.to_le_bytes());
        put(&self.kdf.m_cost_kib.to_le_bytes());
        put(&self.kdf.t_cost.to_le_bytes());
        put(&self.kdf.p_cost.to_le_bytes());
        put(&(KEY_LEN as u32).to_le_bytes());
        put(&(SALT_LEN as u16).to_le_bytes());
        put(&self.salt);
        put(&(NONCE_LEN as u16).to_le_bytes());
        put(&ZERO_NONCE); // nonce_wrap
        put(&ZERO_NONCE); // nonce_data
        put(&(TAG_LEN as u16).to_le_bytes());
        put(&(self.kind as u16).to_le_bytes());
        put(&(WRAPPED_DEK_LEN as u32).to_le_bytes());
        put(&self.data_ciphertext_len.to_le_bytes());
        debug_assert_eq!(w, HEADER_LEN);
        h
    }

    /// Valida o cabeçalho (dados hostis) e o comprimento total do envelope, ANTES de qualquer KDF.
    pub fn parse(envelope: &[u8], expected_kind: EnvelopeKind) -> Result<Header> {
        if envelope.len() as u64 > MAX_ENVELOPE_BYTES || envelope.len() < MIN_ENVELOPE_LEN {
            return Err(FormatError::EnvelopeSize.into());
        }
        let h = &envelope[..HEADER_LEN];
        let u16_at = |o: usize| u16::from_le_bytes([h[o], h[o + 1]]);
        let u32_at = |o: usize| u32::from_le_bytes([h[o], h[o + 1], h[o + 2], h[o + 3]]);
        let u64_at = |o: usize| {
            let mut b = [0u8; 8];
            b.copy_from_slice(&h[o..o + 8]);
            u64::from_le_bytes(b)
        };
        if &h[0..4] != MAGIC {
            return Err(FormatError::Magic.into());
        }
        if u16_at(4) != FORMAT_VERSION {
            return Err(FormatError::FormatVersion.into());
        }
        if u16_at(6) != SCHEMA_VERSION {
            return Err(FormatError::SchemaVersion.into());
        }
        if u16_at(8) != SUITE_ID {
            return Err(FormatError::Suite.into());
        }
        if u16_at(10) as usize != HEADER_LEN {
            return Err(FormatError::HeaderLen.into());
        }
        let mut vault_id = [0u8; 16];
        vault_id.copy_from_slice(&h[12..28]);
        if vault_id == [0u8; 16] {
            return Err(FormatError::VaultId.into());
        }
        let revision = u64_at(28);
        if revision == 0 || revision > i64::MAX as u64 {
            return Err(FormatError::Revision.into());
        }
        if u32_at(36) != 0x13 || u32_at(52) != KEY_LEN as u32 {
            return Err(FormatError::KdfParams.into());
        }
        let kdf = KdfParams { m_cost_kib: u32_at(40), t_cost: u32_at(44), p_cost: u32_at(48) };
        kdf.validate()?;
        if u16_at(56) as usize != SALT_LEN || u16_at(90) as usize != NONCE_LEN || u16_at(116) as usize != TAG_LEN {
            return Err(FormatError::FixedLength.into());
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&h[58..90]);
        if h[92..104] != ZERO_NONCE || h[104..116] != ZERO_NONCE {
            return Err(FormatError::Nonce.into());
        }
        let kind = match u16_at(118) {
            1 => EnvelopeKind::VaultSlot,
            2 => EnvelopeKind::Backup,
            _ => return Err(FormatError::Kind.into()),
        };
        if kind != expected_kind {
            return Err(FormatError::Kind.into());
        }
        if u32_at(120) as usize != WRAPPED_DEK_LEN {
            return Err(FormatError::FixedLength.into());
        }
        let data_ciphertext_len = u64_at(124);
        if !(TAG_LEN as u64..=MAX_DATA_CT_LEN).contains(&data_ciphertext_len) {
            return Err(FormatError::CiphertextLen.into());
        }
        let total = (HEADER_LEN + WRAPPED_DEK_LEN) as u64 + data_ciphertext_len;
        if envelope.len() as u64 != total {
            return Err(if (envelope.len() as u64) < total { FormatError::Truncated } else { FormatError::TrailingBytes }.into());
        }
        Ok(Header { vault_id, revision, kdf, salt, kind, data_ciphertext_len })
    }
}

fn domain_prefix(domain: &[u8], cap_extra: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(2 + domain.len() + cap_extra);
    v.extend_from_slice(&(domain.len() as u16).to_le_bytes());
    v.extend_from_slice(domain);
    v
}

pub fn aad_snapshot(h: &[u8; HEADER_LEN]) -> Vec<u8> {
    let mut v = domain_prefix(DOMAIN_SNAPSHOT, HEADER_LEN);
    v.extend_from_slice(h);
    v
}

pub fn aad_wrap(h: &[u8; HEADER_LEN], data_ciphertext: &[u8]) -> Vec<u8> {
    let mut v = domain_prefix(DOMAIN_WRAP, HEADER_LEN + 32);
    v.extend_from_slice(h);
    v.extend_from_slice(&sha256(data_ciphertext));
    v
}

/// Parâmetros do envelope a criar.
pub struct SealRequest<'a> {
    pub password: &'a MasterPassword,
    pub kdf: KdfParams,
    pub kind: EnvelopeKind,
}

/// Cria um envelope completamente novo para `snapshot` (DEK nova, salt novo, KEK nova).
/// `snapshot.vault_id` e `snapshot.revision` vão para o cabeçalho.
pub fn seal(req: &SealRequest<'_>, snapshot: &Snapshot, rng: &dyn SecureRandom) -> Result<Vec<u8>> {
    req.kdf.validate()?;
    if snapshot.revision == 0 || snapshot.revision > i64::MAX as u64 {
        return Err(FormatError::Revision.into());
    }
    // 1. Payload candidato (zeroizável), limites validados antes de cifrar.
    let plain = payload::encode(snapshot)?;
    // 2. Material novo do CSPRNG (falha aborta sem produzir nada).
    let dek = FreshDek::generate(rng)?;
    let (kek, salt) = FreshKek::derive_with_new_salt(req.password, &req.kdf, rng)?;
    // 3. Cabeçalho com comprimentos calculados antes da criptografia.
    let header = Header {
        vault_id: snapshot.vault_id,
        revision: snapshot.revision,
        kdf: req.kdf,
        salt,
        kind: req.kind,
        data_ciphertext_len: (plain.len() + TAG_LEN) as u64,
    };
    let h = header.encode();
    // 4–6. DEK cifra o payload (uma vez); KEK embrulha a DEK (uma vez).
    let (data_ct, dek_bytes) = dek.seal_once(&plain, &aad_snapshot(&h))?;
    drop(plain);
    if data_ct.len() as u64 != header.data_ciphertext_len {
        return Err(CoreError::Crypto);
    }
    let wrapped = kek.wrap_once(dek_bytes, &aad_wrap(&h, &data_ct))?;
    let mut out = Vec::with_capacity(HEADER_LEN + wrapped.len() + data_ct.len());
    out.extend_from_slice(&h);
    out.extend_from_slice(&wrapped);
    out.extend_from_slice(&data_ct);
    Ok(out)
}

/// Abre um envelope: valida cabeçalho → KDF → autentica wrapper → autentica payload → parsing
/// estrito → valida contexto. Nada é devolvido antes de tudo passar.
pub fn open(password: &MasterPassword, envelope: &[u8], expected_kind: EnvelopeKind) -> Result<(Header, Snapshot)> {
    let header = Header::parse(envelope, expected_kind)?;
    let h: [u8; HEADER_LEN] = envelope[..HEADER_LEN].try_into().map_err(|_| FormatError::Truncated)?;
    let wrapped = &envelope[HEADER_LEN..HEADER_LEN + WRAPPED_DEK_LEN];
    let data_ct = &envelope[HEADER_LEN + WRAPPED_DEK_LEN..];
    let kek = OpeningKek::derive(password, &header.salt, &header.kdf)?;
    let dek = kek.unwrap_once(wrapped, &aad_wrap(&h, data_ct))?;
    let plain: Zeroizing<Vec<u8>> = dek.open_once(data_ct, &aad_snapshot(&h))?;
    let snapshot = payload::decode(&plain, &header.vault_id, header.revision)?;
    Ok((header, snapshot))
}
