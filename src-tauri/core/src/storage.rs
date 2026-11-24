//! Persistência SQLite: um único slot `vault_state(slot=1)` com o envelope completo.
//! WAL + synchronous=FULL, conexão única de escrita, revisão esperada e trava de processo.

use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags, TransactionBehavior, params};

use crate::envelope::{EnvelopeKind, HEADER_LEN, Header};
use crate::error::{CoreError, Result};
use crate::fsutil::{self, ProcessLock, hex_lower};
use crate::model::VaultId;

pub const DB_USER_VERSION: i64 = 1;
pub const DB_EXT: &str = "kvdb";
const PARTIAL_SUFFIX: &str = ".partial";

const SCHEMA_SQL: &str = "CREATE TABLE vault_state(slot INTEGER PRIMARY KEY CHECK(slot = 1), envelope BLOB NOT NULL)";

/// Caminho do banco de um cofre: `<dir>/<vault_id hex>.kvdb` (somente metadado público no nome).
pub fn vault_path(dir: &Path, vault_id: &VaultId) -> PathBuf {
    dir.join(format!("{}.{DB_EXT}", hex_lower(vault_id)))
}

fn lock_path(db_path: &Path) -> PathBuf {
    let mut p = db_path.as_os_str().to_owned();
    p.push(".lock");
    PathBuf::from(p)
}

fn configure(conn: &Connection) -> Result<()> {
    // Sem extensões, sem schema confiável, verificação de células.
    conn.execute_batch(
        "PRAGMA trusted_schema = OFF;
         PRAGMA cell_size_check = ON;
         PRAGMA temp_store = MEMORY;
         PRAGMA secure_delete = ON;
         PRAGMA synchronous = FULL;",
    )?;
    let mode: String = conn.query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(CoreError::Storage);
    }
    // synchronous precisa ser reafirmado após trocar para WAL.
    conn.execute_batch("PRAGMA synchronous = FULL;")?;
    let sync: i64 = conn.query_row("PRAGMA synchronous", [], |r| r.get(0))?;
    if sync != 2 {
        return Err(CoreError::Storage);
    }
    Ok(())
}

fn check_schema(conn: &Connection) -> Result<()> {
    let uv: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if uv != DB_USER_VERSION {
        return Err(CoreError::Schema);
    }
    let mut stmt = conn.prepare("SELECT type, name, sql FROM sqlite_schema ORDER BY name")?;
    let rows: Vec<(String, String, Option<String>)> =
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<std::result::Result<_, _>>()?;
    let ok = rows.len() == 1 && rows[0].0 == "table" && rows[0].1 == "vault_state" && rows[0].2.as_deref() == Some(SCHEMA_SQL);
    if !ok {
        return Err(CoreError::Schema);
    }
    Ok(())
}

/// Conexão aberta e travada de um cofre.
pub struct VaultStore {
    conn: Connection,
    path: PathBuf,
    _lock: ProcessLock,
}

impl std::fmt::Debug for VaultStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VaultStore")
    }
}

impl VaultStore {
    /// Cria um banco novo contendo `envelope` (revisão inicial), sem jamais sobrescrever um existente:
    /// grava em `<nome>.partial`, faz commit, fecha (checkpoint do WAL) e publica por rename atômico.
    pub fn create_new(dir: &Path, vault_id: &VaultId, envelope: &[u8]) -> Result<PathBuf> {
        fsutil::ensure_private_dir(dir)?;
        let final_path = vault_path(dir, vault_id);
        if final_path.exists() {
            return Err(CoreError::AlreadyExists);
        }
        let _lock = ProcessLock::acquire(&lock_path(&final_path))?;
        let mut partial = final_path.as_os_str().to_owned();
        partial.push(PARTIAL_SUFFIX);
        let partial = PathBuf::from(partial);
        remove_db_files(&partial);
        let res = (|| -> Result<()> {
            Header::parse(envelope, EnvelopeKind::VaultSlot)?;
            let conn = Connection::open_with_flags(
                &partial,
                OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )?;
            configure(&conn)?;
            conn.execute_batch(&format!("BEGIN IMMEDIATE; {SCHEMA_SQL}; PRAGMA user_version = {DB_USER_VERSION};"))?;
            conn.execute("INSERT INTO vault_state(slot, envelope) VALUES (1, ?1)", params![envelope])?;
            conn.execute_batch("COMMIT;")?;
            conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))?;
            conn.close().map_err(|(_, e)| CoreError::from(e))?;
            fsutil::restrict_to_current_user(&partial)?;
            fsutil::atomic_publish(&partial, &final_path, false)
        })();
        if res.is_err() {
            remove_db_files(&partial);
        }
        res.map(|()| final_path)
    }

    /// Abre um cofre existente com trava exclusiva do processo.
    pub fn open(path: &Path) -> Result<Self> {
        let lock = ProcessLock::acquire(&lock_path(path))?;
        if !path.is_file() {
            return Err(CoreError::NotFound);
        }
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX)?;
        configure(&conn)?;
        check_schema(&conn)?;
        Ok(VaultStore { conn, path: path.to_path_buf(), _lock: lock })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Lê o envelope do slot 1 (ciphertext).
    pub fn read_envelope(&self) -> Result<Vec<u8>> {
        let len: i64 = self.conn.query_row("SELECT length(envelope) FROM vault_state WHERE slot = 1", [], |r| r.get(0))?;
        if len < 0 || len as u64 > crate::limits::MAX_ENVELOPE_BYTES {
            return Err(crate::error::FormatError::EnvelopeSize.into());
        }
        Ok(self.conn.query_row("SELECT envelope FROM vault_state WHERE slot = 1", [], |r| r.get(0))?)
    }

    /// Substitui o slot em uma transação, rejeitando gravação obsoleta (revisão esperada).
    pub fn commit(&mut self, expected_revision: u64, envelope: &[u8]) -> Result<()> {
        let new_header = Header::parse(envelope, EnvelopeKind::VaultSlot)?;
        if Some(new_header.revision) != expected_revision.checked_add(1) {
            return Err(CoreError::RevisionConflict);
        }
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (prefix, total): (Vec<u8>, i64) = tx.query_row(
            "SELECT substr(envelope, 1, ?1), length(envelope) FROM vault_state WHERE slot = 1",
            params![HEADER_LEN as i64],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let current_rev = public_revision(&prefix, total)?;
        if current_rev != expected_revision {
            return Err(CoreError::RevisionConflict);
        }
        let n = tx.execute("UPDATE vault_state SET envelope = ?1 WHERE slot = 1", params![envelope])?;
        if n != 1 {
            return Err(CoreError::Schema);
        }
        #[cfg(feature = "test-instrumentation")]
        testing::maybe_fail(testing::DbFault::BeforeCommit)?;
        tx.commit()?;
        #[cfg(feature = "test-instrumentation")]
        testing::maybe_fail(testing::DbFault::AfterCommit)?;
        Ok(())
    }

    /// Revisão pública atualmente persistida (usada para resolver "commit com status incerto").
    pub fn current_revision(&self) -> Result<u64> {
        let (prefix, total): (Vec<u8>, i64) = self.conn.query_row(
            "SELECT substr(envelope, 1, ?1), length(envelope) FROM vault_state WHERE slot = 1",
            params![HEADER_LEN as i64],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        public_revision(&prefix, total)
    }

    /// Checkpoint do WAL (chamado ao bloquear/fechar para reduzir retenção de envelopes antigos).
    pub fn checkpoint(&self) {
        let _ = self.conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()));
    }

    #[cfg(feature = "test-instrumentation")]
    pub fn connection_for_tests(&self) -> &Connection {
        &self.conn
    }
}

/// Revisão a partir dos primeiros bytes públicos do envelope persistido (validação estrutural mínima).
fn public_revision(prefix: &[u8], total: i64) -> Result<u64> {
    if prefix.len() != HEADER_LEN || total < HEADER_LEN as i64 || &prefix[0..4] != crate::envelope::MAGIC {
        return Err(CoreError::Schema);
    }
    Ok(u64::from_le_bytes(prefix[28..36].try_into().map_err(|_| CoreError::Schema)?))
}

fn remove_db_files(p: &Path) {
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let mut s = p.as_os_str().to_owned();
        s.push(suffix);
        let _ = std::fs::remove_file(PathBuf::from(s));
    }
}

/// Metadados públicos de um cofre encontrado no diretório de dados.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultFileInfo {
    pub vault_id: VaultId,
    pub path: PathBuf,
    pub modified_ms: Option<i64>,
}

/// Lista cofres `<hex32>.kvdb` e remove restos `.partial` de criações nunca publicadas.
pub fn list_vaults(dir: &Path) -> Result<Vec<VaultFileInfo>> {
    let mut out = Vec::new();
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e.into()),
    };
    for ent in rd.flatten() {
        let name = ent.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.contains(&format!(".{DB_EXT}{PARTIAL_SUFFIX}")) {
            // Criação/restauração interrompida antes da publicação: nunca foi um cofre válido.
            let _ = std::fs::remove_file(ent.path());
            continue;
        }
        let Some(stem) = name.strip_suffix(&format!(".{DB_EXT}")) else { continue };
        let Some(vault_id) = fsutil::parse_hex::<16>(stem) else { continue };
        let modified_ms = ent
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_millis() as i64);
        out.push(VaultFileInfo { vault_id, path: ent.path(), modified_ms });
    }
    out.sort_by_key(|v| std::cmp::Reverse(v.modified_ms));
    Ok(out)
}

#[cfg(feature = "test-instrumentation")]
pub mod testing {
    //! Injeção de falhas de banco (somente testes).
    use super::*;
    use std::cell::Cell;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum DbFault {
        /// Erro após UPDATE e antes de COMMIT (rollback).
        BeforeCommit,
        /// Erro reportado após COMMIT durável.
        AfterCommit,
    }

    thread_local! {
        static FAULT: Cell<Option<DbFault>> = const { Cell::new(None) };
    }

    pub fn set(f: Option<DbFault>) {
        FAULT.with(|c| c.set(f));
    }

    pub(crate) fn maybe_fail(at: DbFault) -> Result<()> {
        if FAULT.with(|c| c.get()) == Some(at) {
            FAULT.with(|c| c.set(None));
            return Err(CoreError::InjectedFault);
        }
        Ok(())
    }
}
