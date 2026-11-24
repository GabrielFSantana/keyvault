//! Aplicação Tauri do KeyVault: sessão, IPC restrito, clipboard e integrações nativas.
#![deny(clippy::unwrap_used)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod clipboard;
pub mod commands;
pub mod dto;
pub mod os_events;
pub mod session;

use std::sync::Arc;
use std::time::Duration;

use tauri::{Manager, RunEvent, WindowEvent};

use crate::commands::{AppCtx, MAIN_WINDOW, emit_locked};
use crate::session::{LockReason, Session};

/// Comandos registrados (deve coincidir com `build.rs` e com a capability `main`).
#[macro_export]
macro_rules! keyvault_handlers {
    () => {
        tauri::generate_handler![
            $crate::commands::vault_status,
            $crate::commands::vault_create,
            $crate::commands::vault_unlock,
            $crate::commands::vault_lock,
            $crate::commands::entries_list,
            $crate::commands::entry_get,
            $crate::commands::entry_save,
            $crate::commands::entry_delete,
            $crate::commands::entries_search,
            $crate::commands::password_generate,
            $crate::commands::entry_reveal_secret,
            $crate::commands::entry_copy_secret,
            $crate::commands::vault_change_password,
            $crate::commands::backup_export,
            $crate::commands::backup_restore,
            $crate::commands::session_activity,
            $crate::commands::vault_settings_update,
        ]
    };
}

/// Cria a sessão a partir do diretório privado de dados.
pub fn make_session(data_dir: std::path::PathBuf) -> Arc<Session> {
    let _ = keyvault_core::fsutil::ensure_private_dir(&data_dir);
    let vaults = keyvault_core::storage::list_vaults(&data_dir).unwrap_or_default();
    Arc::new(Session::new(data_dir, !vaults.is_empty(), vaults.first().map(|v| v.vault_id)))
}

pub fn run() {
    let builder = tauri::Builder::default()
        // Uma instância por usuário: a segunda execução apenas foca a janela existente.
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(w) = app.get_webview_window(MAIN_WINDOW) {
                let _ = w.unminimize();
                let _ = w.set_focus();
            }
        }))
        .setup(|app| {
            let base = app.path().app_local_data_dir().map_err(|_| "diretório de dados indisponível")?;
            let session = make_session(base.join("vaults"));
            let handle = app.handle().clone();
            let s_os = session.clone();
            let os_integration = os_events::start(move |reason| {
                if s_os.lock_now(reason) {
                    emit_locked(&handle, &s_os, reason);
                }
            });
            // Tick de 1 s: inatividade, foco, clipboard e restauração pendente — independentes da UI.
            let handle = app.handle().clone();
            let s_tick = session.clone();
            std::thread::Builder::new()
                .name("kv-session-tick".into())
                .spawn(move || {
                    loop {
                        std::thread::sleep(Duration::from_secs(1));
                        if let Some(reason) = s_tick.tick() {
                            emit_locked(&handle, &s_tick, reason);
                        }
                    }
                })
                .map_err(|_| "falha ao iniciar temporizador")?;
            #[cfg(windows)]
            if let Some(w) = app.get_webview_window(MAIN_WINDOW) {
                harden_webview(&w);
            }
            app.manage(AppCtx { session, os_integration });
            Ok(())
        })
        .on_window_event(|window, event| {
            if window.label() != MAIN_WINDOW {
                return;
            }
            let Some(ctx) = window.try_state::<AppCtx>() else { return };
            match event {
                WindowEvent::Focused(f) => ctx.session.set_focus(*f),
                WindowEvent::CloseRequested { .. } | WindowEvent::Destroyed => {
                    ctx.session.lock_now(LockReason::AppClose);
                }
                _ => {}
            }
        })
        .invoke_handler(keyvault_handlers!());

    let app = match builder.build(tauri::generate_context!()) {
        Ok(app) => app,
        Err(_) => std::process::exit(1),
    };
    app.run(|handle, event| {
        if let RunEvent::Exit | RunEvent::ExitRequested { .. } = event
            && let Some(ctx) = handle.try_state::<AppCtx>()
        {
            ctx.session.lock_now(LockReason::AppClose);
        }
    });
}

/// Endurecimento das configurações do WebView2 (Windows): sem salvar senhas/autofill do navegador,
/// sem atalhos do navegador (F5/Ctrl+P/Ctrl+F…), sem barra de status, sem verificação de reputação
/// (SmartScreen) e sem páginas de erro embutidas. Melhor esforço: falhas não impedem a execução.
#[cfg(windows)]
pub fn harden_webview(window: &tauri::WebviewWindow) {
    use webview2_com::Microsoft::Web::WebView2::Win32::{ICoreWebView2Settings3, ICoreWebView2Settings4, ICoreWebView2Settings8};
    use windows_core::Interface;
    let _ = window.with_webview(|pv| unsafe {
        let Ok(core) = pv.controller().CoreWebView2() else { return };
        let Ok(settings) = core.Settings() else { return };
        let _ = settings.SetIsStatusBarEnabled(false);
        let _ = settings.SetAreDefaultContextMenusEnabled(false);
        let _ = settings.SetIsBuiltInErrorPageEnabled(false);
        let _ = settings.SetAreDevToolsEnabled(cfg!(debug_assertions));
        if let Ok(s3) = settings.cast::<ICoreWebView2Settings3>() {
            let _ = s3.SetAreBrowserAcceleratorKeysEnabled(false);
        }
        if let Ok(s4) = settings.cast::<ICoreWebView2Settings4>() {
            let _ = s4.SetIsPasswordAutosaveEnabled(false);
            let _ = s4.SetIsGeneralAutofillEnabled(false);
        }
        if let Ok(s8) = settings.cast::<ICoreWebView2Settings8>() {
            let _ = s8.SetIsReputationCheckingRequired(false);
        }
    });
}
