//! Modelo de domínio em memória (texto claro somente no processo Rust, enquanto desbloqueado).

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{CoreError, Field, FormatError, Result};
use crate::limits::*;

pub type VaultId = [u8; 16];
pub type EntryId = [u8; 16];
pub type FieldId = [u8; 16];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    pub auto_lock_minutes: u16,
    pub clipboard_seconds: u16,
    pub lock_on_blur: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings { auto_lock_minutes: AUTO_LOCK_DEFAULT_MINUTES, clipboard_seconds: CLIPBOARD_DEFAULT_SECONDS, lock_on_blur: true }
    }
}

impl Settings {
    pub fn validate(&self) -> std::result::Result<(), FormatError> {
        if !(AUTO_LOCK_MIN_MINUTES..=AUTO_LOCK_MAX_MINUTES).contains(&self.auto_lock_minutes)
            || !(CLIPBOARD_MIN_SECONDS..=CLIPBOARD_MAX_SECONDS).contains(&self.clipboard_seconds)
        {
            return Err(FormatError::Settings);
        }
        Ok(())
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct CustomField {
    pub id: FieldId,
    pub secret: bool,
    pub name: String,
    pub value: String,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Entry {
    pub id: EntryId,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub favorite: bool,
    pub title: String,
    pub url: String,
    pub username: String,
    pub password: String,
    pub notes: String,
    pub tags: Vec<String>,
    pub fields: Vec<CustomField>,
}

impl std::fmt::Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Entry(<redacted>)")
    }
}
impl std::fmt::Debug for CustomField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CustomField(<redacted>)")
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Snapshot {
    pub vault_id: VaultId,
    pub revision: u64,
    #[zeroize(skip)]
    pub settings: Settings,
    pub entries: Vec<Entry>,
}

impl std::fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Snapshot(rev={}, entries={})", self.revision, self.entries.len())
    }
}

fn check_text(s: &str, field: Field, allow_empty: bool) -> Result<()> {
    if s.len() > MAX_FIELD_BYTES || (!allow_empty && s.is_empty()) {
        return Err(CoreError::Validation(field));
    }
    Ok(())
}

fn valid_ts(ts: i64) -> bool {
    (0..=MAX_TIMESTAMP_MS).contains(&ts)
}

impl Entry {
    /// Validação de domínio usada tanto na entrada do usuário quanto antes de serializar.
    pub fn validate(&self) -> Result<()> {
        if self.id == [0u8; 16] {
            return Err(CoreError::Validation(Field::Id));
        }
        if !valid_ts(self.created_at_ms) || !valid_ts(self.updated_at_ms) || self.updated_at_ms < self.created_at_ms {
            return Err(CoreError::Format(FormatError::Timestamp));
        }
        check_text(&self.title, Field::Title, false)?;
        check_text(&self.url, Field::Url, true)?;
        check_text(&self.username, Field::Username, true)?;
        check_text(&self.password, Field::Password, true)?;
        check_text(&self.notes, Field::Notes, true)?;
        if self.tags.len() > MAX_TAGS {
            return Err(CoreError::Validation(Field::Tags));
        }
        for (i, t) in self.tags.iter().enumerate() {
            check_text(t, Field::Tag, false)?;
            if self.tags[..i].iter().any(|o| o == t) {
                return Err(CoreError::Validation(Field::Tags));
            }
        }
        if self.fields.len() > MAX_CUSTOM_FIELDS {
            return Err(CoreError::Validation(Field::CustomFields));
        }
        for (i, cf) in self.fields.iter().enumerate() {
            if cf.id == [0u8; 16] || self.fields[..i].iter().any(|o| o.id == cf.id) {
                return Err(CoreError::Validation(Field::Id));
            }
            check_text(&cf.name, Field::CustomFieldName, false)?;
            check_text(&cf.value, Field::CustomFieldValue, true)?;
        }
        Ok(())
    }

    /// Texto pesquisável: título, URL, usuário, tags e notas. Nunca senha nem valores secretos.
    pub fn matches(&self, needle_lower: &str) -> bool {
        if needle_lower.is_empty() {
            return true;
        }
        let hit = |s: &str| s.to_lowercase().contains(needle_lower);
        hit(&self.title) || hit(&self.url) || hit(&self.username) || hit(&self.notes) || self.tags.iter().any(|t| hit(t))
    }
}

impl Snapshot {
    pub fn new_empty(vault_id: VaultId) -> Self {
        Snapshot { vault_id, revision: 1, settings: Settings::default(), entries: Vec::new() }
    }

    pub fn validate(&self) -> Result<()> {
        if self.vault_id == [0u8; 16] {
            return Err(FormatError::VaultId.into());
        }
        self.settings.validate()?;
        if self.entries.len() > MAX_ENTRIES {
            return Err(CoreError::Validation(Field::Entries));
        }
        let mut ids: Vec<&EntryId> = self.entries.iter().map(|e| &e.id).collect();
        ids.sort_unstable();
        if ids.windows(2).any(|w| w[0] == w[1]) {
            return Err(FormatError::Identifier.into());
        }
        for e in &self.entries {
            e.validate()?;
        }
        Ok(())
    }

    pub fn find(&self, id: &EntryId) -> Option<&Entry> {
        self.entries.iter().find(|e| &e.id == id)
    }
}
