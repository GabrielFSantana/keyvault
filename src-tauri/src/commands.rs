//! Comandos IPC de domínio (allowlist). Cada comando verifica janela/origem no Rust; comandos
//! sensíveis verificam estado, geração e prazo da sessão antes e depois da operação.
//! Não há SQL, shell, filesystem genérico, HTTP, eval, abertura de URL nem caminhos vindos do JS.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use keyvault_core::crypto::KdfParams;
use keyvault_core::fsutil::{self, hex_lower};
use keyvault_core::generator::{self, GeneratorOptions};
use keyvault_core::limits::MAX_ENVELOPE_BYTES;
use keyvault_core::model::Settings;
use keyvault_core::rng::{OsRandom, random_array};
use keyvault_core::secret::MasterPassword;
use keyvault_core::service::{self, EntryInput, FieldInput, OpenVault, SecretRef, SecretUpdate};
use keyvault_core::storage::{self, vault_path};
use keyvault_core::{CoreError, Field};
use subtle_eq::ct_eq_str;
use tauri::{Emitter, Manager, Runtime, State, Webview};
use zeroize::Zeroizing;

use crate::dto::*;
use crate::session::{LockReason, PendingRestore, Phase, RestoreStage, Session};

pub const MAIN_WINDOW: &str = "main";
pub const REVEAL_MS: u64 = 15_000;
pub const EVENT_LOCKED: &str = "kv://session-locked";
const MAX_QUERY_BYTES: usize = 1024;

pub struct AppCtx {
    pub session: Arc<Session>,
    pub os_integration: bool,
}

mod subtle_eq {
    /// Comparação de strings sem atalho por prefixo (confirmação de senha).
    pub fn ct_eq_str(a: &str, b: &str) -> bool {
        let (a, b) = (a.as_bytes(), b.as_bytes());
        let mut diff = (a.len() ^ b.len()) as u64;
        for i in 0..a.len().max(b.len()) {
            diff |= (a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0)) as u64;
        }
        diff == 0
    }
}

/// Verifica que a chamada vem da janela principal com origem local esperada.
pub fn check_origin<R: Runtime>(webview: &Webview<R>) -> IpcResult<()> {
    if webview.label() != MAIN_WINDOW {
        return Err(IpcError::code("forbidden_origin"));
    }
    let url = webview.url().map_err(|_| IpcError::code("forbidden_origin"))?;
    let ok = match (url.scheme(), url.host_str()) {
        ("http" | "https", Some("tauri.localhost")) => true,
        ("tauri", Some("localhost")) => true,
        ("http", Some("localhost")) => cfg!(debug_assertions) && url.port() == Some(1420),
        _ => false,
    };
    if ok { Ok(()) } else { Err(IpcError::code("forbidden_origin")) }
}

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> IpcResult<T> + Send + 'static) -> IpcResult<T> {
    tauri::async_runtime::spawn_blocking(f).await.map_err(|_| IpcError::code("internal"))?
}

pub fn emit_locked<R: Runtime>(app: &tauri::AppHandle<R>, session: &Session, reason: LockReason) {
    let generation = session.meta().generation;
    let _ = app.emit_to(MAIN_WINDOW, EVENT_LOCKED, serde_json::json!({ "reason": reason, "generation": generation }));
}

pub fn build_status(ctx: &AppCtx) -> StatusDto {
    let s = &ctx.session;
    // Prazo expirado é aplicado também aqui.
    let expired = {
        let m = s.meta();
        m.phase == Phase::Unlocked && m.deadline.is_some_and(|d| std::time::Instant::now() >= d)
    };
    if expired {
        s.lock_now(LockReason::Inactivity);
    }
    let vaults = storage::list_vaults(&s.data_dir).unwrap_or_default();
    let (unlocked_info, kdf_now) = {
        match s.vault.try_lock() {
            Ok(g) => match g.as_ref() {
                Some(v) => (Some((v.settings(), v.entry_count(), v.revision())), Some(v.kdf())),
                None => (None, None),
            },
            Err(_) => (None, None),
        }
    };
    let m = s.meta();
    let unlocked = m.phase == Phase::Unlocked;
    StatusDto {
        phase: m.phase,
        generation: m.generation,
        vaults: vaults.iter().map(|v| VaultInfoDto { id: hex_lower(&v.vault_id), modified_ms: v.modified_ms }).collect(),
        selected_vault_id: m.selected_vault.map(|id| hex_lower(&id)),
        settings: unlocked_info.filter(|_| unlocked).map(|(st, _, _)| SettingsDto {
            auto_lock_minutes: st.auto_lock_minutes,
            clipboard_seconds: st.clipboard_seconds,
            lock_on_blur: st.lock_on_blur,
        }),
        entry_count: unlocked_info.filter(|_| unlocked).map(|(_, n, _)| n),
        revision: unlocked_info.filter(|_| unlocked).map(|(_, _, r)| r),
        kdf: kdf_now.filter(|_| unlocked).map(|k| KdfDto {
            m_cost_kib: k.m_cost_kib,
            t_cost: k.t_cost,
            p_cost: k.p_cost,
            measured_ms: m.kdf_profile.filter(|(p, _)| *p == k).map(|(_, ms)| ms as u64),
        }),
        retry_after_ms: m.retry_at.and_then(|t| t.checked_duration_since(std::time::Instant::now())).map(|d| d.as_millis() as u64),
        last_lock_reason: m.last_lock_reason,
        os_integration: ctx.os_integration,
    }
}

fn apply_settings(session: &Session, st: Settings) {
    let mut m = session.meta();
    m.auto_lock = Duration::from_secs(st.auto_lock_minutes as u64 * 60);
    m.lock_on_blur = st.lock_on_blur;
    m.clipboard_secs = st.clipboard_seconds;
    m.deadline = Some(std::time::Instant::now() + m.auto_lock);
}

/// Instala um cofre aberto como sessão desbloqueada nova (geração nova).
fn install_unlocked(session: &Session, vault: OpenVault) {
    let st = vault.settings();
    let id = vault.vault_id();
    *session.vault_guard() = Some(vault);
    {
        let mut m = session.meta();
        m.generation += 1;
        m.phase = Phase::Unlocked;
        m.failures = 0;
        m.retry_at = None;
        m.selected_vault = Some(id);
        m.last_lock_reason = None;
        m.last_activity_bump = None;
        m.blurred_at = None;
    }
    apply_settings(session, st);
}

/// Perfil de KDF calibrado neste equipamento (uma vez por execução).
fn calibrated_kdf(session: &Session) -> IpcResult<KdfParams> {
    if let Some((p, _)) = session.meta().kdf_profile {
        return Ok(p);
    }
    let (p, t) = service::calibrate_kdf(&mut service::measure_kdf).map_err(IpcError::from)?;
    session.meta().kdf_profile = Some((p, t.as_millis()));
    Ok(p)
}

fn new_password(password: String, confirmation: String) -> IpcResult<MasterPassword> {
    let password = Zeroizing::new(password);
    let confirmation = Zeroizing::new(confirmation);
    if !ct_eq_str(&password, &confirmation) {
        return Err(IpcError::field(Field::MasterPasswordConfirmation));
    }
    MasterPassword::new_for_creation(password).map_err(IpcError::from)
}

/// Executa uma operação com o cofre aberto, verificando sessão antes e depois.
fn with_vault<T>(session: &Session, generation: u64, f: impl FnOnce(&mut OpenVault) -> IpcResult<T>) -> IpcResult<T> {
    session.authorize(generation)?;
    let mut guard = session.vault_guard();
    if !session.still_valid(generation) {
        return Err(IpcError::code("locked"));
    }
    let vault = guard.as_mut().ok_or(IpcError::code("locked"))?;
    let out = f(vault)?;
    drop(guard);
    if !session.still_valid(generation) {
        // Resultado tardio de sessão encerrada: descartado.
        return Err(IpcError::code("locked"));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------------

#[tauri::command]
pub async fn vault_status<R: Runtime>(webview: Webview<R>, ctx: State<'_, AppCtx>) -> IpcResult<StatusDto> {
    check_origin(&webview)?;
    Ok(build_status(&ctx))
}

#[tauri::command]
pub async fn vault_create<R: Runtime>(
    webview: Webview<R>,
    ctx: State<'_, AppCtx>,
    password: String,
    confirmation: String,
) -> IpcResult<StatusDto> {
    check_origin(&webview)?;
    let session = ctx.session.clone();
    {
        let m = session.meta();
        if m.phase != Phase::Uninitialized {
            return Err(IpcError::code("invalid_state"));
        }
    }
    let pw = new_password(password, confirmation)?;
    let s2 = session.clone();
    blocking(move || {
        let _permit = s2.kdf_permit();
        if s2.meta().phase != Phase::Uninitialized || !storage::list_vaults(&s2.data_dir).unwrap_or_default().is_empty() {
            return Err(IpcError::code("invalid_state"));
        }
        let kdf = calibrated_kdf(&s2)?;
        let vault = OpenVault::create(&s2.data_dir, pw, kdf, &OsRandom)?;
        install_unlocked(&s2, vault);
        Ok(())
    })
    .await?;
    Ok(build_status(&ctx))
}

#[tauri::command]
pub async fn vault_unlock<R: Runtime>(
    webview: Webview<R>,
    ctx: State<'_, AppCtx>,
    vault_id: String,
    password: String,
) -> IpcResult<StatusDto> {
    check_origin(&webview)?;
    let password = Zeroizing::new(password);
    let id = parse_id(&vault_id)?;
    let session = ctx.session.clone();
    let generation = {
        let mut m = session.meta();
        if m.phase != Phase::Locked {
            return Err(IpcError::code("invalid_state"));
        }
        if let Some(wait) = m.retry_at.and_then(|t| t.checked_duration_since(std::time::Instant::now())) {
            return Err(IpcError { code: "too_many_attempts", field: None, retry_after_ms: Some(wait.as_millis() as u64) });
        }
        m.phase = Phase::Unlocking;
        m.selected_vault = Some(id);
        m.generation
    };
    let pw = match MasterPassword::new_for_unlock(password) {
        Ok(p) => p,
        Err(_) => {
            session.meta().phase = Phase::Locked;
            let wait = session.register_failure();
            return Err(IpcError { code: "authentication_failed", field: None, retry_after_ms: Some(wait.as_millis() as u64) });
        }
    };
    let path = vault_path(&session.data_dir, &id);
    let s2 = session.clone();
    let result = blocking(move || {
        let _permit = s2.kdf_permit();
        OpenVault::unlock(&path, pw).map_err(IpcError::from)
    })
    .await;
    let mut m = session.meta();
    if m.generation != generation || m.phase != Phase::Unlocking {
        // Bloqueio solicitado durante a KDF: o resultado é descartado (Drop zera tudo).
        drop(result);
        if m.phase == Phase::Unlocking {
            m.phase = Phase::Locked;
        }
        return Err(IpcError::code("locked"));
    }
    match result {
        Ok(vault) => {
            drop(m);
            install_unlocked(&session, vault);
            Ok(build_status(&ctx))
        }
        Err(e) => {
            m.phase = Phase::Locked;
            drop(m);
            if e.code == "authentication_failed" {
                let wait = session.register_failure();
                return Err(IpcError { code: "authentication_failed", field: None, retry_after_ms: Some(wait.as_millis() as u64) });
            }
            Err(e)
        }
    }
}

#[tauri::command]
pub async fn vault_lock<R: Runtime>(webview: Webview<R>, ctx: State<'_, AppCtx>) -> IpcResult<StatusDto> {
    check_origin(&webview)?;
    let s = ctx.session.clone();
    blocking(move || {
        s.lock_now(LockReason::Manual);
        Ok(())
    })
    .await?;
    Ok(build_status(&ctx))
}

#[tauri::command]
pub async fn session_activity<R: Runtime>(webview: Webview<R>, ctx: State<'_, AppCtx>, session: u64) -> IpcResult<bool> {
    check_origin(&webview)?;
    Ok(ctx.session.activity(session))
}

#[tauri::command]
pub async fn entries_list<R: Runtime>(
    webview: Webview<R>,
    ctx: State<'_, AppCtx>,
    session: u64,
    favorites_only: bool,
) -> IpcResult<EntryListDto> {
    check_origin(&webview)?;
    with_vault(&ctx.session, session, |v| {
        Ok(EntryListDto { generation: session, entries: v.list("", favorites_only).into_iter().map(Into::into).collect() })
    })
}

#[tauri::command]
pub async fn entries_search<R: Runtime>(
    webview: Webview<R>,
    ctx: State<'_, AppCtx>,
    session: u64,
    query: String,
    favorites_only: bool,
) -> IpcResult<EntryListDto> {
    check_origin(&webview)?;
    if query.len() > MAX_QUERY_BYTES {
        return Err(IpcError::code("validation"));
    }
    with_vault(&ctx.session, session, |v| {
        Ok(EntryListDto { generation: session, entries: v.list(&query, favorites_only).into_iter().map(Into::into).collect() })
    })
}

#[tauri::command]
pub async fn entry_get<R: Runtime>(webview: Webview<R>, ctx: State<'_, AppCtx>, session: u64, id: String) -> IpcResult<EntryDetailDto> {
    check_origin(&webview)?;
    let id = parse_id(&id)?;
    with_vault(&ctx.session, session, |v| Ok(EntryDetailDto::new(session, v.detail(&id)?)))
}

fn secret_update(d: SecretUpdateDto) -> SecretUpdate {
    match d {
        SecretUpdateDto::Keep {} => SecretUpdate::Keep,
        SecretUpdateDto::Set { value } => SecretUpdate::Set(Zeroizing::new(value)),
        SecretUpdateDto::Clear {} => SecretUpdate::Clear,
    }
}

fn entry_input(d: EntryInputDto) -> IpcResult<EntryInput> {
    let id = d.id.as_deref().map(parse_id).transpose()?;
    if d.fields.len() > keyvault_core::limits::MAX_CUSTOM_FIELDS {
        return Err(IpcError::field(Field::CustomFields));
    }
    if d.tags.len() > keyvault_core::limits::MAX_TAGS {
        return Err(IpcError::field(Field::Tags));
    }
    let mut fields = Vec::with_capacity(d.fields.len());
    for f in d.fields {
        fields.push(FieldInput {
            id: f.id.as_deref().map(parse_id).transpose()?,
            name: f.name,
            secret: f.secret,
            value: secret_update(f.value),
        });
    }
    Ok(EntryInput {
        id,
        title: d.title,
        url: d.url,
        username: d.username,
        password: secret_update(d.password),
        notes: d.notes,
        tags: d.tags,
        favorite: d.favorite,
        fields,
    })
}

#[tauri::command]
pub async fn entry_save<R: Runtime>(
    webview: Webview<R>,
    ctx: State<'_, AppCtx>,
    session: u64,
    entry: EntryInputDto,
) -> IpcResult<SavedDto> {
    check_origin(&webview)?;
    let input = entry_input(entry)?;
    let s = ctx.session.clone();
    blocking(move || {
        let _permit = s.kdf_permit();
        with_vault(&s, session, |v| {
            let id = v.save_entry(input, &OsRandom, now_ms())?;
            Ok(SavedDto { generation: session, id: hex_lower(&id), revision: v.revision() })
        })
    })
    .await
}

#[tauri::command]
pub async fn entry_delete<R: Runtime>(webview: Webview<R>, ctx: State<'_, AppCtx>, session: u64, id: String) -> IpcResult<u64> {
    check_origin(&webview)?;
    let id = parse_id(&id)?;
    let s = ctx.session.clone();
    blocking(move || {
        let _permit = s.kdf_permit();
        with_vault(&s, session, |v| {
            v.delete_entry(&id, &OsRandom)?;
            Ok(v.revision())
        })
    })
    .await
}

#[tauri::command]
pub async fn vault_settings_update<R: Runtime>(
    webview: Webview<R>,
    ctx: State<'_, AppCtx>,
    session: u64,
    settings: SettingsDto,
) -> IpcResult<StatusDto> {
    check_origin(&webview)?;
    let st = Settings {
        auto_lock_minutes: settings.auto_lock_minutes,
        clipboard_seconds: settings.clipboard_seconds,
        lock_on_blur: settings.lock_on_blur,
    };
    let s = ctx.session.clone();
    blocking(move || {
        let _permit = s.kdf_permit();
        with_vault(&s, session, |v| Ok(v.update_settings(st, &OsRandom)?))?;
        apply_settings(&s, st);
        Ok(())
    })
    .await?;
    Ok(build_status(&ctx))
}

#[tauri::command]
pub async fn password_generate<R: Runtime>(
    webview: Webview<R>,
    ctx: State<'_, AppCtx>,
    session: u64,
    options: GeneratorOptionsDto,
) -> IpcResult<GeneratedDto> {
    check_origin(&webview)?;
    ctx.session.authorize(session)?;
    let opts = GeneratorOptions {
        length: options.length,
        lowercase: options.lowercase,
        uppercase: options.uppercase,
        digits: options.digits,
        symbols: options.symbols,
        exclude_ambiguous: options.exclude_ambiguous,
    };
    let pw = generator::generate(&opts, &OsRandom)?;
    if !ctx.session.still_valid(session) {
        return Err(IpcError::code("locked"));
    }
    Ok(GeneratedDto { generation: session, password: pw.as_str().to_owned() })
}

fn secret_ref(d: &SecretRefDto) -> IpcResult<SecretRef> {
    Ok(match d {
        SecretRefDto::Password {} => SecretRef::Password,
        SecretRefDto::Field { field_id } => SecretRef::Field(parse_id(field_id)?),
    })
}

#[tauri::command]
pub async fn entry_reveal_secret<R: Runtime>(
    webview: Webview<R>,
    ctx: State<'_, AppCtx>,
    session: u64,
    id: String,
    secret: SecretRefDto,
) -> IpcResult<RevealDto> {
    check_origin(&webview)?;
    let id = parse_id(&id)?;
    let which = secret_ref(&secret)?;
    with_vault(&ctx.session, session, |v| {
        let value = v.secret(&id, which)?;
        Ok(RevealDto { generation: session, value: value.as_str().to_owned(), expires_in_ms: REVEAL_MS })
    })
}

#[tauri::command]
pub async fn entry_copy_secret<R: Runtime>(
    webview: Webview<R>,
    ctx: State<'_, AppCtx>,
    session: u64,
    id: String,
    secret: SecretRefDto,
) -> IpcResult<CopyDto> {
    check_origin(&webview)?;
    let id = parse_id(&id)?;
    let which = secret_ref(&secret)?;
    let s = ctx.session.clone();
    blocking(move || {
        let secs = s.meta().clipboard_secs.clamp(5, 60) as u64;
        with_vault(&s, session, |v| {
            let value = v.secret(&id, which)?;
            // O segredo vai do Rust direto para o clipboard; não retorna ao JavaScript.
            s.clipboard.copy_secret(&value, Duration::from_secs(secs)).map_err(|e| match e {
                crate::clipboard::ClipboardError::Unsupported => IpcError::code("unsupported"),
                crate::clipboard::ClipboardError::Unavailable => IpcError::code("clipboard_unavailable"),
            })?;
            Ok(CopyDto { generation: session, clears_in_ms: secs * 1000 })
        })
    })
    .await
}

#[tauri::command]
pub async fn vault_change_password<R: Runtime>(
    webview: Webview<R>,
    ctx: State<'_, AppCtx>,
    session: u64,
    current: String,
    new_password: String,
    confirmation: String,
) -> IpcResult<StatusDto> {
    check_origin(&webview)?;
    let current = Zeroizing::new(current);
    ctx.session.authorize(session)?;
    if let Some(wait) = ctx.session.retry_after() {
        return Err(IpcError { code: "too_many_attempts", field: None, retry_after_ms: Some(wait.as_millis() as u64) });
    }
    let new_pw = new_password_or_field(new_password, confirmation)?;
    let cur = MasterPassword::new_for_unlock(current).map_err(|_| IpcError::code("authentication_failed"))?;
    let s = ctx.session.clone();
    let r = blocking(move || {
        let _permit = s.kdf_permit();
        with_vault(&s, session, |v| Ok(v.change_password(&cur, new_pw, &OsRandom)?))
    })
    .await;
    if let Err(e) = &r
        && e.code == "authentication_failed"
    {
        let wait = ctx.session.register_failure();
        return Err(IpcError {
            code: "authentication_failed",
            field: Some("current_password"),
            retry_after_ms: Some(wait.as_millis() as u64),
        });
    }
    r?;
    Ok(build_status(&ctx))
}

fn new_password_or_field(p: String, c: String) -> IpcResult<MasterPassword> {
    new_password(p, c)
}

#[tauri::command]
pub async fn backup_export<R: Runtime>(webview: Webview<R>, ctx: State<'_, AppCtx>, session: u64) -> IpcResult<BackupExportDto> {
    check_origin(&webview)?;
    ctx.session.authorize(session)?;
    let window = webview.app_handle().get_webview_window(MAIN_WINDOW).ok_or(IpcError::code("internal"))?;
    let s = ctx.session.clone();
    blocking(move || {
        let short = s.meta().selected_vault.map(|id| hex_lower(&id[..4])).unwrap_or_default();
        // Diálogo disparado pelo Rust; o destino é exclusivamente o escolhido nele.
        let dialog_guard = s.native_dialog();
        let dest = rfd::FileDialog::new()
            .set_title("Salvar backup criptografado do KeyVault")
            .add_filter("Backup KeyVault", &["keyvault"])
            .set_file_name(format!("keyvault-backup-{short}.keyvault"))
            .set_parent(&window)
            .save_file();
        drop(dialog_guard);
        let Some(mut dest) = dest else { return Ok(BackupExportDto { saved: false, file_name: None }) };
        if dest.extension().is_none_or(|e| !e.eq_ignore_ascii_case("keyvault")) {
            dest.set_extension("keyvault");
        }
        // O diálogo de salvar do Windows já pede confirmação para sobrescrever (FOS_OVERWRITEPROMPT).
        let replace_confirmed = dest.exists();
        let _permit = s.kdf_permit();
        let blob = with_vault(&s, session, |v| Ok(v.export_backup(&OsRandom)?))?;
        fsutil::write_file_atomically(&dest, &blob, replace_confirmed, false, &OsRandom)?;
        let name = dest.file_name().map(|n| n.to_string_lossy().into_owned());
        Ok(BackupExportDto { saved: true, file_name: name })
    })
    .await
}

fn new_token() -> IpcResult<(u64, String)> {
    let b = random_array::<8>(&OsRandom).map_err(IpcError::from)?;
    Ok((u64::from_le_bytes(b), hex_lower(&b)))
}

fn token_matches(p: &PendingRestore, token: &str) -> bool {
    hex_lower(&p.token.to_le_bytes()) == token
}

#[tauri::command]
pub async fn backup_restore<R: Runtime>(
    webview: Webview<R>,
    ctx: State<'_, AppCtx>,
    request: RestoreRequestDto,
) -> IpcResult<RestoreResponseDto> {
    check_origin(&webview)?;
    let s = ctx.session.clone();
    match request {
        RestoreRequestDto::Select {} => {
            let window = webview.app_handle().get_webview_window(MAIN_WINDOW).ok_or(IpcError::code("internal"))?;
            blocking(move || {
                let dialog_guard = s.native_dialog();
                let Some(path) = rfd::FileDialog::new()
                    .set_title("Escolher backup do KeyVault")
                    .add_filter("Backup KeyVault", &["keyvault"])
                    .set_parent(&window)
                    .pick_file()
                else {
                    return Ok(RestoreResponseDto::Cancelled);
                };
                drop(dialog_guard);
                // Tamanho antes de ler; cabeçalho antes de qualquer KDF.
                let meta = std::fs::metadata(&path).map_err(CoreError::from)?;
                if !meta.is_file() || meta.len() > MAX_ENVELOPE_BYTES {
                    return Err(IpcError::code("invalid_file"));
                }
                let bytes = std::fs::read(&path).map_err(CoreError::from)?;
                let header = service::precheck_backup(&bytes).map_err(|_| IpcError::code("invalid_file"))?;
                let (token, token_hex) = new_token()?;
                let file_name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                *s.restore_guard() = Some(PendingRestore {
                    token,
                    created: std::time::Instant::now(),
                    stage: RestoreStage::Selected { bytes, file_name: file_name.clone() },
                });
                Ok(RestoreResponseDto::Selected { token: token_hex, file_name, revision: header.revision })
            })
            .await
        }
        RestoreRequestDto::Inspect { token, password } => {
            let password = Zeroizing::new(password);
            if let Some(wait) = s.retry_after() {
                return Err(IpcError { code: "too_many_attempts", field: None, retry_after_ms: Some(wait.as_millis() as u64) });
            }
            let pw = MasterPassword::new_for_unlock(password).map_err(|_| IpcError::code("authentication_failed"))?;
            blocking(move || {
                let _permit = s.kdf_permit();
                let mut guard = s.restore_guard();
                let pending = guard.as_mut().filter(|p| token_matches(p, &token)).ok_or(IpcError::code("invalid_state"))?;
                let RestoreStage::Selected { bytes, file_name } = &pending.stage else {
                    return Err(IpcError::code("invalid_state"));
                };
                match service::inspect_backup(bytes, &pw) {
                    Ok(backup) => {
                        let entry_count = backup.entry_count();
                        let revision = backup.header.revision;
                        let file_name = file_name.clone();
                        pending.stage = RestoreStage::Inspected { backup, file_name };
                        Ok(RestoreResponseDto::Inspected { token, entry_count, revision })
                    }
                    Err(_) => {
                        drop(guard);
                        let wait = s.register_failure();
                        Err(IpcError { code: "authentication_failed", field: None, retry_after_ms: Some(wait.as_millis() as u64) })
                    }
                }
            })
            .await
        }
        RestoreRequestDto::Commit { token, password, confirmation } => {
            let pw = new_password(password, confirmation)?;
            let app = webview.app_handle().clone();
            blocking(move || {
                let _permit = s.kdf_permit();
                let pending = {
                    let mut guard = s.restore_guard();
                    match guard.as_ref() {
                        Some(p) if token_matches(p, &token) && matches!(p.stage, RestoreStage::Inspected { .. }) => guard.take(),
                        _ => None,
                    }
                }
                .ok_or(IpcError::code("invalid_state"))?;
                let RestoreStage::Inspected { backup, .. } = pending.stage else {
                    return Err(IpcError::code("invalid_state"));
                };
                let kdf = calibrated_kdf(&s)?;
                let entry_count = backup.entry_count();
                let restored = service::restore_as_new_vault(&s.data_dir, backup, pw, kdf, &OsRandom)?;
                let new_id = restored.vault_id();
                restored.close();
                // O cofre atual nunca é sobrescrito; a sessão atual é bloqueada e o novo cofre
                // passa a ser o selecionado (desbloqueio exige a nova senha).
                if s.lock_now(LockReason::Restore) {
                    emit_locked(&app, &s, LockReason::Restore);
                }
                {
                    let mut m = s.meta();
                    m.selected_vault = Some(new_id);
                    m.last_lock_reason = Some(LockReason::Restore);
                    if m.phase == Phase::Uninitialized {
                        m.phase = Phase::Locked;
                    }
                }
                Ok(RestoreResponseDto::Restored { vault_id: hex_lower(&new_id), entry_count })
            })
            .await
        }
        RestoreRequestDto::Cancel { token } => {
            let mut guard = s.restore_guard();
            if guard.as_ref().is_some_and(|p| token_matches(p, &token)) {
                guard.take();
            }
            Ok(RestoreResponseDto::Cancelled)
        }
    }
}
