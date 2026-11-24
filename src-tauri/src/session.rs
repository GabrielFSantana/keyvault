//! Sessão imposta pelo Rust: estados, geração, prazo de inatividade monotônico, bloqueio por foco,
//! atraso progressivo de tentativas, restauração pendente e limpeza ao bloquear.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use keyvault_core::crypto::KdfParams;
use keyvault_core::model::VaultId;
use keyvault_core::service::{InspectedBackup, OpenVault};

use crate::clipboard::ClipboardOwner;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Phase {
    Uninitialized,
    Locked,
    Unlocking,
    Unlocked,
    Locking,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum LockReason {
    Manual,
    Inactivity,
    FocusLost,
    OsLock,
    Suspend,
    UserSwitch,
    Shutdown,
    AppClose,
    Restore,
}

/// Bloqueio após perda de foco (quando ativado nas preferências).
pub const BLUR_LOCK_AFTER: Duration = Duration::from_secs(30);
/// Intervalo mínimo entre extensões de prazo por atividade (rate limit).
pub const ACTIVITY_MIN_INTERVAL: Duration = Duration::from_secs(5);
/// Atraso máximo entre tentativas erradas.
pub const MAX_BACKOFF: Duration = Duration::from_secs(30);
/// Validade de uma restauração pendente.
pub const RESTORE_TTL: Duration = Duration::from_secs(10 * 60);

pub struct Meta {
    pub phase: Phase,
    pub generation: u64,
    pub deadline: Option<Instant>,
    pub auto_lock: Duration,
    pub lock_on_blur: bool,
    pub clipboard_secs: u16,
    pub focused: bool,
    pub blurred_at: Option<Instant>,
    pub last_activity_bump: Option<Instant>,
    pub failures: u32,
    pub retry_at: Option<Instant>,
    pub selected_vault: Option<VaultId>,
    pub last_lock_reason: Option<LockReason>,
    pub kdf_profile: Option<(KdfParams, u128)>,
    /// Diálogo nativo do próprio app aberto (salvar/abrir backup): a janela principal perde o foco
    /// para um diálogo modal do KeyVault, o que não conta como "fora de foco". A inatividade continua.
    pub native_dialogs: u32,
}

pub enum RestoreStage {
    /// Arquivo escolhido em diálogo do Rust, cabeçalho validado, ainda não autenticado.
    Selected { bytes: Vec<u8>, file_name: String },
    /// Autenticado e validado; aguardando senha nova confirmada.
    Inspected { backup: InspectedBackup, file_name: String },
}

pub struct PendingRestore {
    pub token: u64,
    pub created: Instant,
    pub stage: RestoreStage,
}

pub struct Session {
    pub meta: Mutex<Meta>,
    pub vault: Mutex<Option<OpenVault>>,
    pub restore: Mutex<Option<PendingRestore>>,
    /// Garante no máximo uma KDF ativa por vez (desbloqueio/criação/restauração/troca/salvamento).
    pub kdf_gate: Mutex<()>,
    pub clipboard: ClipboardOwner,
    pub data_dir: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    Locked,
    StaleSession,
}

impl Session {
    pub fn new(data_dir: PathBuf, has_vaults: bool, selected: Option<VaultId>) -> Self {
        Session {
            meta: Mutex::new(Meta {
                phase: if has_vaults { Phase::Locked } else { Phase::Uninitialized },
                generation: 1,
                deadline: None,
                auto_lock: Duration::from_secs(5 * 60),
                lock_on_blur: true,
                clipboard_secs: 20,
                focused: true,
                blurred_at: None,
                last_activity_bump: None,
                failures: 0,
                retry_at: None,
                selected_vault: selected,
                last_lock_reason: None,
                kdf_profile: None,
                native_dialogs: 0,
            }),
            vault: Mutex::new(None),
            restore: Mutex::new(None),
            kdf_gate: Mutex::new(()),
            clipboard: ClipboardOwner::default(),
            data_dir,
        }
    }

    pub fn meta(&self) -> std::sync::MutexGuard<'_, Meta> {
        self.meta.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn vault_guard(&self) -> std::sync::MutexGuard<'_, Option<OpenVault>> {
        self.vault.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn restore_guard(&self) -> std::sync::MutexGuard<'_, Option<PendingRestore>> {
        self.restore.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn kdf_permit(&self) -> std::sync::MutexGuard<'_, ()> {
        self.kdf_gate.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Autoriza um comando sensível: estado Unlocked, geração informada pela UI igual à atual e
    /// prazo de inatividade não expirado (verificado aqui, independentemente de timers).
    pub fn authorize(&self, ui_generation: u64) -> Result<u64, AuthError> {
        let expired = {
            let m = self.meta();
            if m.phase != Phase::Unlocked {
                return Err(AuthError::Locked);
            }
            if m.generation != ui_generation {
                return Err(AuthError::StaleSession);
            }
            m.deadline.is_some_and(|d| Instant::now() >= d)
        };
        if expired {
            self.lock_now(LockReason::Inactivity);
            return Err(AuthError::Locked);
        }
        Ok(ui_generation)
    }

    /// A sessão que iniciou uma operação ainda é a mesma (resultados tardios são descartados).
    pub fn still_valid(&self, generation: u64) -> bool {
        let m = self.meta();
        m.phase == Phase::Unlocked && m.generation == generation
    }

    /// Estende o prazo de inatividade (rate limited).
    pub fn activity(&self, generation: u64) -> bool {
        let mut m = self.meta();
        if m.phase != Phase::Unlocked || m.generation != generation {
            return false;
        }
        let now = Instant::now();
        if m.deadline.is_some_and(|d| now >= d) {
            return false;
        }
        if m.last_activity_bump.is_some_and(|t| now.duration_since(t) < ACTIVITY_MIN_INTERVAL) {
            return true;
        }
        m.last_activity_bump = Some(now);
        m.deadline = Some(now + m.auto_lock);
        true
    }

    /// Bloqueia: incrementa a geração imediatamente (comandos e respostas antigas passam a ser
    /// rejeitados), depois zera cofre/senha/snapshot (aguardando operação em andamento terminar),
    /// limpa o clipboard próprio e restaurações pendentes. Idempotente.
    pub fn lock_now(&self, reason: LockReason) -> bool {
        {
            let mut m = self.meta();
            match m.phase {
                Phase::Unlocked | Phase::Unlocking => {
                    m.generation += 1;
                    m.phase = Phase::Locking;
                    m.deadline = None;
                    m.last_lock_reason = Some(reason);
                }
                _ => {
                    drop(m);
                    // Mesmo sem sessão, limpa clipboard próprio e restauração pendente.
                    self.clipboard.clear_if_ours();
                    if matches!(
                        reason,
                        LockReason::OsLock | LockReason::Suspend | LockReason::UserSwitch | LockReason::Shutdown | LockReason::AppClose
                    ) {
                        self.restore_guard().take();
                    }
                    return false;
                }
            }
        }
        // Espera a operação em andamento (se houver) e descarta o cofre (Drop zera os buffers).
        if let Some(v) = self.vault_guard().take() {
            v.close();
        }
        self.clipboard.clear_if_ours();
        if reason != LockReason::Restore {
            self.restore_guard().take();
        }
        let mut m = self.meta();
        if m.phase == Phase::Locking {
            m.phase = Phase::Locked;
        }
        true
    }

    /// Registra falha de desbloqueio e calcula o próximo instante permitido (1, 2, 4, … até 30 s).
    pub fn register_failure(&self) -> Duration {
        let mut m = self.meta();
        m.failures = m.failures.saturating_add(1);
        let secs = 1u64.checked_shl(m.failures.saturating_sub(1).min(16)).unwrap_or(u64::MAX);
        let wait = Duration::from_secs(secs).min(MAX_BACKOFF);
        m.retry_at = Some(Instant::now() + wait);
        wait
    }

    pub fn retry_after(&self) -> Option<Duration> {
        let m = self.meta();
        m.retry_at.and_then(|t| t.checked_duration_since(Instant::now()))
    }

    /// Tick periódico (1 s): inatividade, foco, expiração do clipboard e da restauração pendente.
    pub fn tick(&self) -> Option<LockReason> {
        let now = Instant::now();
        let reason = {
            let m = self.meta();
            if m.phase == Phase::Unlocked {
                if m.deadline.is_some_and(|d| now >= d) {
                    Some(LockReason::Inactivity)
                } else if m.lock_on_blur
                    && !m.focused
                    && m.native_dialogs == 0
                    && m.blurred_at.is_some_and(|b| now.duration_since(b) >= BLUR_LOCK_AFTER)
                {
                    Some(LockReason::FocusLost)
                } else {
                    None
                }
            } else {
                None
            }
        };
        self.clipboard.expire();
        {
            let mut r = self.restore_guard();
            if r.as_ref().is_some_and(|p| now.duration_since(p.created) > RESTORE_TTL) {
                r.take();
            }
        }
        if let Some(reason) = reason
            && self.lock_now(reason)
        {
            return Some(reason);
        }
        None
    }

    /// Marca um diálogo nativo do app como aberto até o guard ser descartado. Ao fechar, se a janela
    /// ainda estiver sem foco, a contagem de 30 s recomeça.
    pub fn native_dialog(&self) -> NativeDialogGuard<'_> {
        self.meta().native_dialogs += 1;
        NativeDialogGuard { session: self }
    }

    pub fn set_focus(&self, focused: bool) {
        let mut m = self.meta();
        m.focused = focused;
        m.blurred_at = if focused { None } else { Some(Instant::now()) };
    }
}

pub struct NativeDialogGuard<'a> {
    session: &'a Session,
}

impl Drop for NativeDialogGuard<'_> {
    fn drop(&mut self) {
        let mut m = self.session.meta();
        m.native_dialogs = m.native_dialogs.saturating_sub(1);
        if !m.focused {
            m.blurred_at = Some(Instant::now());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unlocked_session() -> Session {
        let s = Session::new(std::env::temp_dir(), true, None);
        {
            let mut m = s.meta();
            m.phase = Phase::Unlocked;
            m.generation = 7;
            m.deadline = Some(Instant::now() + Duration::from_secs(60));
        }
        s
    }

    #[test]
    fn authorize_checks_phase_generation_and_deadline() {
        let s = unlocked_session();
        assert_eq!(s.authorize(7), Ok(7));
        assert_eq!(s.authorize(6), Err(AuthError::StaleSession));
        // Prazo expirado: bloqueia no backend mesmo sem timer na UI.
        s.meta().deadline = Some(Instant::now() - Duration::from_millis(1));
        assert_eq!(s.authorize(7), Err(AuthError::Locked));
        let m = s.meta();
        assert_eq!(m.phase, Phase::Locked);
        assert_eq!(m.generation, 8);
        assert_eq!(m.last_lock_reason, Some(LockReason::Inactivity));
    }

    #[test]
    fn late_results_are_discarded_after_lock() {
        let s = unlocked_session();
        let g = s.authorize(7).unwrap();
        // Bloqueio durante a operação.
        assert!(s.lock_now(LockReason::Manual));
        assert!(!s.still_valid(g));
        assert_eq!(s.authorize(7), Err(AuthError::Locked));
        // Bloquear de novo é idempotente.
        assert!(!s.lock_now(LockReason::Manual));
    }

    #[test]
    fn activity_is_rate_limited_and_cannot_revive_expired_session() {
        let s = unlocked_session();
        s.meta().auto_lock = Duration::from_secs(300);
        assert!(s.activity(7));
        let d1 = s.meta().deadline;
        assert!(s.activity(7));
        assert_eq!(s.meta().deadline, d1, "segunda atividade dentro de 5 s não estende");
        s.meta().deadline = Some(Instant::now() - Duration::from_millis(1));
        assert!(!s.activity(7));
        assert!(!s.activity(99));
    }

    #[test]
    fn blur_lock_after_30s_when_enabled() {
        let s = unlocked_session();
        s.set_focus(false);
        assert_eq!(s.tick(), None);
        s.meta().blurred_at = Some(Instant::now() - BLUR_LOCK_AFTER);
        assert_eq!(s.tick(), Some(LockReason::FocusLost));
        let s = unlocked_session();
        s.meta().lock_on_blur = false;
        s.set_focus(false);
        s.meta().blurred_at = Some(Instant::now() - Duration::from_secs(3600));
        assert_eq!(s.tick(), None);
    }

    #[test]
    fn own_native_dialog_does_not_count_as_focus_loss_but_inactivity_still_applies() {
        let s = unlocked_session();
        s.set_focus(false);
        s.meta().blurred_at = Some(Instant::now() - BLUR_LOCK_AFTER * 4);
        {
            let _g = s.native_dialog();
            assert_eq!(s.tick(), None, "diálogo do próprio app não bloqueia por foco");
        }
        // Ao fechar o diálogo sem foco, a contagem recomeça (não bloqueia imediatamente).
        assert_eq!(s.tick(), None);
        let _g = s.native_dialog();
        s.meta().deadline = Some(Instant::now() - Duration::from_millis(1));
        assert_eq!(s.tick(), Some(LockReason::Inactivity));
    }

    #[test]
    fn progressive_backoff_capped_at_30s() {
        let s = unlocked_session();
        let waits: Vec<u64> = (0..8).map(|_| s.register_failure().as_secs()).collect();
        assert_eq!(waits, vec![1, 2, 4, 8, 16, 30, 30, 30]);
        assert!(s.retry_after().is_some());
    }
}
