//! DTOs do IPC. Estritos (`deny_unknown_fields`), sem chaves e com o mínimo de dados necessário.

use keyvault_core::fsutil::{hex_lower, parse_hex};
use keyvault_core::service::{EntryDetail, EntrySummary};
use keyvault_core::{CoreError, Field, FormatError};
use serde::{Deserialize, Serialize};

use crate::session::{AuthError, LockReason, Phase};

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct IpcError {
    pub code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

impl IpcError {
    pub fn code(code: &'static str) -> Self {
        IpcError { code, field: None, retry_after_ms: None }
    }
    pub fn field(f: Field) -> Self {
        IpcError { code: "validation", field: Some(f.code()), retry_after_ms: None }
    }
}

impl From<AuthError> for IpcError {
    fn from(e: AuthError) -> Self {
        match e {
            AuthError::Locked => IpcError::code("locked"),
            AuthError::StaleSession => IpcError::code("stale_session"),
        }
    }
}

impl From<CoreError> for IpcError {
    fn from(e: CoreError) -> Self {
        match e {
            CoreError::Validation(f) => IpcError::field(f),
            // Falhas estruturais e de autenticação não são distinguidas externamente.
            // Banco com schema inesperado também é "cofre inválido" para o usuário.
            CoreError::Authentication | CoreError::Format(_) | CoreError::Schema => IpcError::code("authentication_failed"),
            other => IpcError::code(other.code()),
        }
    }
}

pub type IpcResult<T> = Result<T, IpcError>;

pub fn parse_id(s: &str) -> IpcResult<[u8; 16]> {
    parse_hex::<16>(s).filter(|id| id != &[0u8; 16]).ok_or(IpcError::field(Field::Id))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultInfoDto {
    pub id: String,
    pub modified_ms: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SettingsDto {
    pub auto_lock_minutes: u16,
    pub clipboard_seconds: u16,
    pub lock_on_blur: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KdfDto {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub measured_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusDto {
    pub phase: Phase,
    pub generation: u64,
    pub vaults: Vec<VaultInfoDto>,
    pub selected_vault_id: Option<String>,
    pub settings: Option<SettingsDto>,
    pub entry_count: Option<usize>,
    pub revision: Option<u64>,
    pub kdf: Option<KdfDto>,
    pub retry_after_ms: Option<u64>,
    pub last_lock_reason: Option<LockReason>,
    pub os_integration: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntrySummaryDto {
    pub id: String,
    pub title: String,
    pub username: String,
    pub favorite: bool,
    pub updated_at_ms: i64,
}

impl From<EntrySummary> for EntrySummaryDto {
    fn from(e: EntrySummary) -> Self {
        EntrySummaryDto { id: hex_lower(&e.id), title: e.title, username: e.username, favorite: e.favorite, updated_at_ms: e.updated_at_ms }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryListDto {
    pub generation: u64,
    pub entries: Vec<EntrySummaryDto>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldViewDto {
    pub id: String,
    pub name: String,
    pub secret: bool,
    pub value: Option<String>,
    pub has_value: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryDetailDto {
    pub generation: u64,
    pub id: String,
    pub title: String,
    pub url: String,
    pub username: String,
    pub notes: String,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub has_password: bool,
    pub fields: Vec<FieldViewDto>,
}

impl EntryDetailDto {
    pub fn new(generation: u64, d: EntryDetail) -> Self {
        EntryDetailDto {
            generation,
            id: hex_lower(&d.id),
            title: d.title,
            url: d.url,
            username: d.username,
            notes: d.notes,
            tags: d.tags,
            favorite: d.favorite,
            created_at_ms: d.created_at_ms,
            updated_at_ms: d.updated_at_ms,
            has_password: d.has_password,
            fields: d
                .fields
                .into_iter()
                .map(|f| FieldViewDto { id: hex_lower(&f.id), name: f.name, secret: f.secret, value: f.value, has_value: f.has_value })
                .collect(),
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum SecretUpdateDto {
    // Variantes com `{}` (e não unitárias) para que `deny_unknown_fields` rejeite campos extras.
    Keep {},
    Set { value: String },
    Clear {},
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FieldInputDto {
    pub id: Option<String>,
    pub name: String,
    pub secret: bool,
    pub value: SecretUpdateDto,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EntryInputDto {
    pub id: Option<String>,
    pub title: String,
    pub url: String,
    pub username: String,
    pub password: SecretUpdateDto,
    pub notes: String,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub fields: Vec<FieldInputDto>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum SecretRefDto {
    Password {},
    #[serde(rename_all = "camelCase")]
    Field {
        field_id: String,
    },
}

#[derive(Deserialize, Debug, Clone, Copy)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GeneratorOptionsDto {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub exclude_ambiguous: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedDto {
    pub generation: u64,
    pub id: String,
    pub revision: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevealDto {
    pub generation: u64,
    pub value: String,
    pub expires_in_ms: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CopyDto {
    pub generation: u64,
    pub clears_in_ms: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GeneratedDto {
    pub generation: u64,
    pub password: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupExportDto {
    pub saved: bool,
    /// Somente o nome do arquivo (sem caminho completo).
    pub file_name: Option<String>,
}

#[derive(Deserialize)]
#[serde(tag = "step", rename_all = "camelCase", deny_unknown_fields)]
pub enum RestoreRequestDto {
    Select {},
    Inspect { token: String, password: String },
    Commit { token: String, password: String, confirmation: String },
    Cancel { token: String },
}

#[derive(Serialize)]
#[serde(tag = "step", rename_all = "camelCase")]
pub enum RestoreResponseDto {
    Cancelled,
    #[serde(rename_all = "camelCase")]
    Selected {
        token: String,
        file_name: String,
        revision: u64,
    },
    #[serde(rename_all = "camelCase")]
    Inspected {
        token: String,
        entry_count: usize,
        revision: u64,
    },
    #[serde(rename_all = "camelCase")]
    Restored {
        vault_id: String,
        entry_count: usize,
    },
}

pub fn invalid_file(_: FormatError) -> IpcError {
    IpcError::code("invalid_file")
}
