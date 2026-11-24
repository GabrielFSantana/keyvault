//! Serviço do cofre: regras de domínio, commits transacionais, troca de senha, backup e restauração.
//! Independente de Tauri; a camada de aplicação adiciona sessão, IPC e diálogos.

use std::path::{Path, PathBuf};
use std::time::Duration;

use zeroize::Zeroizing;

use crate::crypto::KdfParams;
use crate::envelope::{self, EnvelopeKind, Header, SealRequest};
use crate::error::{CoreError, Field, Result};
use crate::limits::*;
use crate::model::*;
use crate::rng::{SecureRandom, random_array};
use crate::secret::MasterPassword;
use crate::storage::{VaultStore, vault_path};

/// Atualização de um valor secreto vindo da UI (a UI não recebe segredos para editar).
pub enum SecretUpdate {
    Keep,
    Set(Zeroizing<String>),
    Clear,
}

pub struct FieldInput {
    pub id: Option<FieldId>,
    pub name: String,
    pub secret: bool,
    pub value: SecretUpdate,
}

pub struct EntryInput {
    pub id: Option<EntryId>,
    pub title: String,
    pub url: String,
    pub username: String,
    pub password: SecretUpdate,
    pub notes: String,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub fields: Vec<FieldInput>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntrySummary {
    pub id: EntryId,
    pub title: String,
    pub username: String,
    pub favorite: bool,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldView {
    pub id: FieldId,
    pub name: String,
    pub secret: bool,
    /// `None` para campos secretos (revelação é separada e temporária).
    pub value: Option<String>,
    pub has_value: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryDetail {
    pub id: EntryId,
    pub title: String,
    pub url: String,
    pub username: String,
    pub notes: String,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub has_password: bool,
    pub fields: Vec<FieldView>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretRef {
    Password,
    Field(FieldId),
}

fn new_id(rng: &dyn SecureRandom) -> Result<[u8; 16]> {
    loop {
        let id = random_array::<16>(rng)?;
        if id != [0u8; 16] {
            return Ok(id);
        }
    }
}

/// Cofre aberto e desbloqueado (somente no processo Rust).
pub struct OpenVault {
    store: VaultStore,
    password: MasterPassword,
    snapshot: Snapshot,
    kdf: KdfParams,
}

impl std::fmt::Debug for OpenVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OpenVault(<redacted>)")
    }
}

impl OpenVault {
    /// Cria um cofre novo em `dir` (vault_id aleatório, revisão 1) e o devolve desbloqueado.
    pub fn create(dir: &Path, password: MasterPassword, kdf: KdfParams, rng: &dyn SecureRandom) -> Result<Self> {
        let snapshot = Snapshot::new_empty(new_id(rng)?);
        let env = envelope::seal(&SealRequest { password: &password, kdf, kind: EnvelopeKind::VaultSlot }, &snapshot, rng)?;
        let path = VaultStore::create_new(dir, &snapshot.vault_id, &env)?;
        let store = VaultStore::open(&path)?;
        Ok(OpenVault { store, password, snapshot, kdf })
    }

    /// Desbloqueia: trava o arquivo, lê o envelope e o abre (falha fechada).
    pub fn unlock(path: &Path, password: MasterPassword) -> Result<Self> {
        let store = VaultStore::open(path)?;
        let env = store.read_envelope()?;
        let (header, snapshot) = envelope::open(&password, &env, EnvelopeKind::VaultSlot)?;
        // O nome do arquivo deve corresponder ao vault_id autenticado.
        if store.path().file_stem().and_then(|s| s.to_str()) != Some(crate::fsutil::hex_lower(&header.vault_id).as_str()) {
            return Err(CoreError::Format(crate::error::FormatError::VaultId));
        }
        Ok(OpenVault { store, password, snapshot, kdf: header.kdf })
    }

    pub fn vault_id(&self) -> VaultId {
        self.snapshot.vault_id
    }
    pub fn revision(&self) -> u64 {
        self.snapshot.revision
    }
    pub fn settings(&self) -> Settings {
        self.snapshot.settings
    }
    pub fn kdf(&self) -> KdfParams {
        self.kdf
    }
    pub fn path(&self) -> PathBuf {
        self.store.path().to_path_buf()
    }
    pub fn entry_count(&self) -> usize {
        self.snapshot.entries.len()
    }

    /// Commit transacional de um snapshot candidato com envelope totalmente novo. O estado em memória
    /// só muda depois do commit. Retry gera novas chaves (nova chamada a `seal`).
    fn commit_candidate(
        &mut self,
        mut candidate: Snapshot,
        password: Option<&MasterPassword>,
        kdf: KdfParams,
        rng: &dyn SecureRandom,
    ) -> Result<()> {
        let expected = self.snapshot.revision;
        candidate.revision = expected.checked_add(1).ok_or(crate::error::FormatError::Revision)?;
        let pw = password.unwrap_or(&self.password);
        let env = envelope::seal(&SealRequest { password: pw, kdf, kind: EnvelopeKind::VaultSlot }, &candidate, rng)?;
        match self.store.commit(expected, &env) {
            Ok(()) => {}
            Err(CoreError::RevisionConflict) => return Err(CoreError::RevisionConflict),
            Err(e) => {
                // Commit com status incerto: se o envelope persistido é exatamente o nosso, ele foi
                // gravado; caso contrário o estado anterior permanece válido.
                match self.store.read_envelope() {
                    Ok(cur) if cur == env => {}
                    _ => return Err(e),
                }
            }
        }
        self.snapshot = candidate;
        self.kdf = kdf;
        Ok(())
    }

    pub fn save_entry(&mut self, input: EntryInput, rng: &dyn SecureRandom, now_ms: i64) -> Result<EntryId> {
        let mut cand = self.snapshot.clone();
        let now = now_ms.clamp(0, MAX_TIMESTAMP_MS);
        let idx = match input.id {
            Some(id) => Some(cand.entries.iter().position(|e| e.id == id).ok_or(CoreError::NotFound)?),
            None => None,
        };
        if input.title.trim().is_empty() {
            return Err(CoreError::Validation(Field::Title));
        }
        let mut tags: Vec<String> = Vec::new();
        for t in input.tags {
            let t = t.trim().to_owned();
            if !t.is_empty() && !tags.contains(&t) {
                tags.push(t);
            }
        }
        let old = idx.map(|i| cand.entries[i].clone());
        let password = match input.password {
            SecretUpdate::Keep => old.as_ref().map(|o| o.password.clone()).unwrap_or_default(),
            SecretUpdate::Set(v) => v.as_str().to_owned(),
            SecretUpdate::Clear => String::new(),
        };
        let mut fields = Vec::with_capacity(input.fields.len());
        for f in input.fields {
            if f.name.trim().is_empty() {
                return Err(CoreError::Validation(Field::CustomFieldName));
            }
            let prev = match (f.id, &old) {
                (Some(fid), Some(o)) => Some(o.fields.iter().find(|x| x.id == fid).ok_or(CoreError::NotFound)?),
                (Some(_), None) => return Err(CoreError::NotFound),
                _ => None,
            };
            let value = match f.value {
                SecretUpdate::Keep => prev.map(|p| p.value.clone()).ok_or(CoreError::Validation(Field::CustomFieldValue))?,
                SecretUpdate::Set(v) => v.as_str().to_owned(),
                SecretUpdate::Clear => String::new(),
            };
            let id = match f.id {
                Some(id) => id,
                None => new_id(rng)?,
            };
            fields.push(CustomField { id, secret: f.secret, name: f.name, value });
        }
        let id = match &old {
            Some(o) => o.id,
            None => new_id(rng)?,
        };
        let created = old.as_ref().map(|o| o.created_at_ms).unwrap_or(now);
        let entry = Entry {
            id,
            created_at_ms: created,
            updated_at_ms: now.max(created),
            favorite: input.favorite,
            title: input.title,
            url: input.url,
            username: input.username,
            password,
            notes: input.notes,
            tags,
            fields,
        };
        entry.validate()?;
        match idx {
            Some(i) => cand.entries[i] = entry,
            None => {
                if cand.entries.len() >= MAX_ENTRIES {
                    return Err(CoreError::Validation(Field::Entries));
                }
                cand.entries.push(entry)
            }
        }
        self.commit_candidate(cand, None, self.kdf, rng)?;
        Ok(id)
    }

    pub fn delete_entry(&mut self, id: &EntryId, rng: &dyn SecureRandom) -> Result<()> {
        let mut cand = self.snapshot.clone();
        let before = cand.entries.len();
        cand.entries.retain(|e| &e.id != id);
        if cand.entries.len() == before {
            return Err(CoreError::NotFound);
        }
        self.commit_candidate(cand, None, self.kdf, rng)
    }

    pub fn update_settings(&mut self, settings: Settings, rng: &dyn SecureRandom) -> Result<()> {
        settings.validate().map_err(|_| CoreError::Validation(Field::Settings))?;
        let mut cand = self.snapshot.clone();
        cand.settings = settings;
        self.commit_candidate(cand, None, self.kdf, rng)
    }

    /// Verifica a senha atual em tempo constante contra o buffer em memória.
    pub fn verify_password(&self, candidate: &MasterPassword) -> bool {
        self.password.ct_eq(candidate)
    }

    /// Troca de senha: exige a atual; commit atômico de envelope novo sob a nova senha; só depois
    /// troca o buffer em memória. Não revoga backups/cópias antigas.
    pub fn change_password(&mut self, current: &MasterPassword, new_password: MasterPassword, rng: &dyn SecureRandom) -> Result<()> {
        if !self.verify_password(current) {
            return Err(CoreError::Authentication);
        }
        let cand = self.snapshot.clone();
        self.commit_candidate(cand, Some(&new_password), self.kdf, rng)?;
        self.password = new_password;
        Ok(())
    }

    /// Migração de parâmetros de KDF (ex.: recalibração): novo envelope com DEK/salt/KEK novos.
    pub fn migrate_kdf(&mut self, kdf: KdfParams, rng: &dyn SecureRandom) -> Result<()> {
        kdf.validate()?;
        let cand = self.snapshot.clone();
        self.commit_candidate(cand, None, kdf, rng)
    }

    /// Backup: envelope novo (`envelope_kind = 2`) do snapshot já salvo, com DEK/salt/KEK novos.
    pub fn export_backup(&self, rng: &dyn SecureRandom) -> Result<Vec<u8>> {
        envelope::seal(&SealRequest { password: &self.password, kdf: self.kdf, kind: EnvelopeKind::Backup }, &self.snapshot, rng)
    }

    pub fn list(&self, query: &str, favorites_only: bool) -> Vec<EntrySummary> {
        let needle = query.trim().to_lowercase();
        let mut v: Vec<EntrySummary> = self
            .snapshot
            .entries
            .iter()
            .filter(|e| (!favorites_only || e.favorite) && e.matches(&needle))
            .map(|e| EntrySummary {
                id: e.id,
                title: e.title.clone(),
                username: e.username.clone(),
                favorite: e.favorite,
                updated_at_ms: e.updated_at_ms,
            })
            .collect();
        v.sort_by(|a, b| b.favorite.cmp(&a.favorite).then_with(|| a.title.to_lowercase().cmp(&b.title.to_lowercase())));
        v
    }

    pub fn detail(&self, id: &EntryId) -> Result<EntryDetail> {
        let e = self.snapshot.find(id).ok_or(CoreError::NotFound)?;
        Ok(EntryDetail {
            id: e.id,
            title: e.title.clone(),
            url: e.url.clone(),
            username: e.username.clone(),
            notes: e.notes.clone(),
            tags: e.tags.clone(),
            favorite: e.favorite,
            created_at_ms: e.created_at_ms,
            updated_at_ms: e.updated_at_ms,
            has_password: !e.password.is_empty(),
            fields: e
                .fields
                .iter()
                .map(|f| FieldView {
                    id: f.id,
                    name: f.name.clone(),
                    secret: f.secret,
                    value: if f.secret { None } else { Some(f.value.clone()) },
                    has_value: !f.value.is_empty(),
                })
                .collect(),
        })
    }

    /// Valor secreto (senha ou campo) para revelação temporária/cópia.
    pub fn secret(&self, id: &EntryId, which: SecretRef) -> Result<Zeroizing<String>> {
        let e = self.snapshot.find(id).ok_or(CoreError::NotFound)?;
        let v = match which {
            SecretRef::Password => &e.password,
            SecretRef::Field(fid) => &e.fields.iter().find(|f| f.id == fid).ok_or(CoreError::NotFound)?.value,
        };
        Ok(Zeroizing::new(v.clone()))
    }

    /// Fecha (checkpoint do WAL); a senha e o snapshot são zerados no drop.
    pub fn close(self) {
        self.store.checkpoint();
    }

    #[cfg(feature = "test-instrumentation")]
    pub fn store_for_tests(&mut self) -> &mut VaultStore {
        &mut self.store
    }
}

/// Backup inspecionado: autenticado e validado, ainda não restaurado.
pub struct InspectedBackup {
    pub header: Header,
    snapshot: Snapshot,
}

impl std::fmt::Debug for InspectedBackup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "InspectedBackup(rev={})", self.header.revision)
    }
}

impl InspectedBackup {
    pub fn entry_count(&self) -> usize {
        self.snapshot.entries.len()
    }
}

/// Valida tamanho/cabeçalho antes da KDF (separado para a UI pedir a senha só se o arquivo é plausível).
pub fn precheck_backup(blob: &[u8]) -> Result<Header> {
    Header::parse(blob, EnvelopeKind::Backup)
}

/// Autentica todo o envelope de backup e valida o payload.
pub fn inspect_backup(blob: &[u8], password: &MasterPassword) -> Result<InspectedBackup> {
    let (header, snapshot) = envelope::open(password, blob, EnvelopeKind::Backup)?;
    Ok(InspectedBackup { header, snapshot })
}

/// Restaura como cofre NOVO: novo vault_id, revisão 1, DEK/salt/KEK novos, senha nova confirmada.
/// Nunca toca o cofre atual.
pub fn restore_as_new_vault(
    dir: &Path,
    backup: InspectedBackup,
    new_password: MasterPassword,
    kdf: KdfParams,
    rng: &dyn SecureRandom,
) -> Result<OpenVault> {
    let mut snapshot = backup.snapshot.clone();
    let mut vault_id = new_id(rng)?;
    while vault_path(dir, &vault_id).exists() || vault_id == backup.header.vault_id {
        vault_id = new_id(rng)?;
    }
    snapshot.vault_id = vault_id;
    snapshot.revision = 1;
    let env = envelope::seal(&SealRequest { password: &new_password, kdf, kind: EnvelopeKind::VaultSlot }, &snapshot, rng)?;
    let path = VaultStore::create_new(dir, &vault_id, &env)?;
    let store = VaultStore::open(&path)?;
    Ok(OpenVault { store, password: new_password, snapshot, kdf })
}

/// Calibração do Argon2id: nunca abaixo do perfil inicial (m=64 MiB, t=3, p=4); sobe memória e
/// depois iterações até ~500–1.500 ms, dentro dos limites aceitos.
pub fn calibrate_kdf(measure: &mut dyn FnMut(&KdfParams) -> Result<Duration>) -> Result<(KdfParams, Duration)> {
    const MIN_MS: u128 = 500;
    const TARGET_MS: u128 = 800;
    let mut p = KdfParams::INITIAL;
    let mut t = measure(&p)?;
    if t.as_millis() >= MIN_MS {
        return Ok((p, t));
    }
    let scale = |cur: u32, ms: u128, max: u32| -> u32 {
        let ms = ms.max(1);
        let v = (cur as u128 * TARGET_MS).div_ceil(ms);
        v.min(max as u128) as u32
    };
    // 1) Memória (múltiplos de 1 MiB).
    let m = scale(p.m_cost_kib, t.as_millis(), KDF_M_MAX_KIB).div_ceil(1024) * 1024;
    p.m_cost_kib = m.clamp(KDF_M_MIN_KIB, KDF_M_MAX_KIB);
    t = measure(&p)?;
    // 2) Iterações, no máximo duas rodadas adicionais.
    for _ in 0..2 {
        if t.as_millis() >= MIN_MS || p.t_cost >= KDF_T_MAX {
            break;
        }
        p.t_cost = scale(p.t_cost, t.as_millis(), KDF_T_MAX).max(p.t_cost + 1).min(KDF_T_MAX);
        t = measure(&p)?;
    }
    Ok((p, t))
}

/// Mede o custo real do Argon2id com dados fictícios.
pub fn measure_kdf(p: &KdfParams) -> Result<Duration> {
    let salt = [0x5au8; 32];
    let start = std::time::Instant::now();
    let _k = crate::crypto::argon2id_raw(b"calibracao-keyvault-ficticia", &salt, p)?;
    Ok(start.elapsed())
}
