//! Erros do núcleo. Nenhuma variante carrega dados do usuário, caminhos ou material criptográfico.

use thiserror::Error;

/// Falha de parsing estrutural (cabeçalho/payload). Apenas códigos, sem conteúdo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum FormatError {
    #[error("tamanho do envelope fora dos limites")]
    EnvelopeSize,
    #[error("magic inválido")]
    Magic,
    #[error("versão de formato não suportada")]
    FormatVersion,
    #[error("versão de schema não suportada")]
    SchemaVersion,
    #[error("suíte criptográfica desconhecida")]
    Suite,
    #[error("comprimento de cabeçalho inválido")]
    HeaderLen,
    #[error("vault_id inválido")]
    VaultId,
    #[error("revisão inválida")]
    Revision,
    #[error("parâmetros de KDF fora dos limites")]
    KdfParams,
    #[error("comprimento fixo inválido")]
    FixedLength,
    #[error("nonce inválido")]
    Nonce,
    #[error("tipo de envelope inesperado")]
    Kind,
    #[error("comprimento do ciphertext inválido")]
    CiphertextLen,
    #[error("bytes truncados")]
    Truncated,
    #[error("bytes sobrando")]
    TrailingBytes,
    #[error("payload: magic inválido")]
    PayloadMagic,
    #[error("payload: contexto diferente do cabeçalho")]
    PayloadContext,
    #[error("payload: contagem fora dos limites")]
    Count,
    #[error("payload: texto acima do limite")]
    FieldTooLong,
    #[error("payload: UTF-8 inválido")]
    Utf8,
    #[error("payload: booleano inválido")]
    Bool,
    #[error("payload: data inválida")]
    Timestamp,
    #[error("payload: identificador inválido ou duplicado")]
    Identifier,
    #[error("payload: valor obrigatório vazio")]
    Empty,
    #[error("payload: duplicata")]
    Duplicate,
    #[error("payload: preferência fora da faixa")]
    Settings,
    #[error("payload: campo reservado não-zero")]
    Reserved,
    #[error("payload acima do limite")]
    PayloadTooLarge,
}

/// Campo de validação de entrada (identifica o campo, nunca o conteúdo).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Title,
    Url,
    Username,
    Password,
    Notes,
    Tags,
    Tag,
    CustomFields,
    CustomFieldName,
    CustomFieldValue,
    Entries,
    MasterPassword,
    MasterPasswordConfirmation,
    Settings,
    GeneratorOptions,
    Id,
}

impl Field {
    pub fn code(self) -> &'static str {
        match self {
            Field::Title => "title",
            Field::Url => "url",
            Field::Username => "username",
            Field::Password => "password",
            Field::Notes => "notes",
            Field::Tags => "tags",
            Field::Tag => "tag",
            Field::CustomFields => "custom_fields",
            Field::CustomFieldName => "custom_field_name",
            Field::CustomFieldValue => "custom_field_value",
            Field::Entries => "entries",
            Field::MasterPassword => "master_password",
            Field::MasterPasswordConfirmation => "master_password_confirmation",
            Field::Settings => "settings",
            Field::GeneratorOptions => "generator_options",
            Field::Id => "id",
        }
    }
}

#[derive(Debug, Error)]
pub enum CoreError {
    /// O CSPRNG do sistema falhou. Fatal para a operação.
    #[error("falha da fonte de aleatoriedade do sistema")]
    Rng,
    /// Falha interna da KDF (por exemplo, memória insuficiente).
    #[error("falha na derivação de chave")]
    Kdf,
    /// Falha interna do AEAD ao cifrar.
    #[error("falha criptográfica")]
    Crypto,
    /// Senha incorreta ou envelope adulterado (indistinguíveis externamente).
    #[error("senha incorreta ou cofre inválido")]
    Authentication,
    /// Estrutura inválida antes/depois da autenticação.
    #[error("formato inválido: {0}")]
    Format(#[from] FormatError),
    /// Entrada inválida do usuário.
    #[error("valor inválido no campo {}", .0.code())]
    Validation(Field),
    #[error("item não encontrado")]
    NotFound,
    /// Revisão esperada diferente da persistida (gravação obsoleta ou concorrente).
    #[error("conflito de revisão")]
    RevisionConflict,
    /// Outro processo está usando o cofre.
    #[error("cofre em uso por outro processo")]
    VaultBusy,
    #[error("banco de dados com schema inesperado")]
    Schema,
    #[error("armazenamento cheio")]
    StorageFull,
    #[error("permissão negada")]
    PermissionDenied,
    #[error("erro de armazenamento")]
    Storage,
    #[error("erro de E/S")]
    Io,
    #[error("destino já existe")]
    AlreadyExists,
    /// Falha injetada por testes.
    #[error("falha injetada (teste)")]
    InjectedFault,
}

impl CoreError {
    /// Código estável para logs/IPC (sem dados do usuário).
    pub fn code(&self) -> &'static str {
        match self {
            CoreError::Rng => "rng_failure",
            CoreError::Kdf => "kdf_failure",
            CoreError::Crypto => "crypto_failure",
            CoreError::Authentication => "authentication_failed",
            CoreError::Format(_) => "invalid_format",
            CoreError::Validation(_) => "validation",
            CoreError::NotFound => "not_found",
            CoreError::RevisionConflict => "revision_conflict",
            CoreError::VaultBusy => "vault_busy",
            CoreError::Schema => "invalid_schema",
            CoreError::StorageFull => "storage_full",
            CoreError::PermissionDenied => "permission_denied",
            CoreError::Storage => "storage_error",
            CoreError::Io => "io_error",
            CoreError::AlreadyExists => "already_exists",
            CoreError::InjectedFault => "injected_fault",
        }
    }
}

impl From<rusqlite::Error> for CoreError {
    fn from(e: rusqlite::Error) -> Self {
        match e {
            rusqlite::Error::SqliteFailure(f, _) => match f.code {
                rusqlite::ErrorCode::DiskFull => CoreError::StorageFull,
                rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked => CoreError::VaultBusy,
                rusqlite::ErrorCode::PermissionDenied | rusqlite::ErrorCode::ReadOnly | rusqlite::ErrorCode::CannotOpen => {
                    CoreError::PermissionDenied
                }
                rusqlite::ErrorCode::NotADatabase | rusqlite::ErrorCode::DatabaseCorrupt => CoreError::Schema,
                _ => CoreError::Storage,
            },
            rusqlite::Error::QueryReturnedNoRows => CoreError::Schema,
            _ => CoreError::Storage,
        }
    }
}

impl From<std::io::Error> for CoreError {
    fn from(e: std::io::Error) -> Self {
        match e.kind() {
            std::io::ErrorKind::PermissionDenied => CoreError::PermissionDenied,
            std::io::ErrorKind::StorageFull => CoreError::StorageFull,
            std::io::ErrorKind::AlreadyExists => CoreError::AlreadyExists,
            std::io::ErrorKind::NotFound => CoreError::NotFound,
            _ => CoreError::Io,
        }
    }
}

pub type Result<T, E = CoreError> = std::result::Result<T, E>;
