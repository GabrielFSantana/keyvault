//! Limites normativos (KEYVAULT.md §5 e docs/format.md).

/// Tamanho máximo de um envelope/arquivo aceito antes de qualquer parsing (64 MiB).
pub const MAX_ENVELOPE_BYTES: u64 = 64 * 1024 * 1024;
/// Tamanho máximo do payload em texto claro (32 MiB).
pub const MAX_PAYLOAD_BYTES: usize = 32 * 1024 * 1024;
/// Número máximo de entradas por cofre.
pub const MAX_ENTRIES: usize = 10_000;
/// Tamanho máximo, em bytes UTF-8, de qualquer campo de texto.
pub const MAX_FIELD_BYTES: usize = 1024 * 1024;
/// Tags por entrada.
pub const MAX_TAGS: usize = 100;
/// Campos personalizados por entrada.
pub const MAX_CUSTOM_FIELDS: usize = 100;
/// Profundidade estrutural máxima permitida pela especificação.
pub const MAX_DEPTH: usize = 16;
/// Profundidade efetiva do payload v1 (payload → entry → field → str).
pub const PAYLOAD_DEPTH: usize = 4;

/// Senha mestra: mínimo de caracteres Unicode (valores escalares) na criação/troca.
pub const MIN_PASSWORD_CHARS: usize = 15;
/// Senha mestra: máximo de bytes UTF-8.
pub const MAX_PASSWORD_BYTES: usize = 1024;

/// Argon2id: faixas aceitas.
pub const KDF_M_MIN_KIB: u32 = 65_536;
pub const KDF_M_MAX_KIB: u32 = 262_144;
pub const KDF_T_MIN: u32 = 3;
pub const KDF_T_MAX: u32 = 10;
pub const KDF_P_MIN: u32 = 1;
pub const KDF_P_MAX: u32 = 4;

/// Preferências.
pub const AUTO_LOCK_MIN_MINUTES: u16 = 1;
pub const AUTO_LOCK_MAX_MINUTES: u16 = 30;
pub const AUTO_LOCK_DEFAULT_MINUTES: u16 = 5;
pub const CLIPBOARD_MIN_SECONDS: u16 = 5;
pub const CLIPBOARD_MAX_SECONDS: u16 = 60;
pub const CLIPBOARD_DEFAULT_SECONDS: u16 = 20;

/// Datas: 0 ..= 9999-12-31T23:59:59.999Z em milissegundos Unix.
pub const MAX_TIMESTAMP_MS: i64 = 253_402_300_799_999;

/// Gerador de senhas.
pub const GEN_MIN_LEN: usize = 16;
pub const GEN_MAX_LEN: usize = 128;
pub const GEN_DEFAULT_LEN: usize = 24;

const _: () = assert!(PAYLOAD_DEPTH <= MAX_DEPTH);
