//! Integração com eventos do sistema operacional que exigem bloqueio imediato.
//!
//! Windows: janela oculta de nível superior (nunca exibida) em thread própria, registrada para
//! `WM_WTSSESSION_CHANGE` (bloqueio de sessão, desconexão de console/remota, logoff — troca de
//! usuário gera desconexão do console), `WM_POWERBROADCAST/PBT_APMSUSPEND` (inclusive via
//! `RegisterSuspendResumeNotification`, necessário em Modern Standby) e `WM_QUERYENDSESSION`/
//! `WM_ENDSESSION` (desligamento/logoff).

use std::sync::OnceLock;

use crate::session::LockReason;

type Handler = Box<dyn Fn(LockReason) + Send + Sync>;
static HANDLER: OnceLock<Handler> = OnceLock::new();

/// Inicia o monitor. `on_lock` é chamado na thread do monitor e deve ser rápido/robusto.
pub fn start(on_lock: impl Fn(LockReason) + Send + Sync + 'static) -> bool {
    if HANDLER.set(Box::new(on_lock)).is_err() {
        return false;
    }
    platform::start()
}

fn fire(reason: LockReason) {
    if let Some(h) = HANDLER.get() {
        h(reason);
    }
}

/// Mapeia códigos de `WM_WTSSESSION_CHANGE` para motivos de bloqueio (testável sem Win32).
pub fn map_session_change(code: u32) -> Option<LockReason> {
    const WTS_CONSOLE_DISCONNECT: u32 = 0x2;
    const WTS_REMOTE_DISCONNECT: u32 = 0x4;
    const WTS_SESSION_LOGOFF: u32 = 0x6;
    const WTS_SESSION_LOCK: u32 = 0x7;
    match code {
        WTS_SESSION_LOCK => Some(LockReason::OsLock),
        WTS_CONSOLE_DISCONNECT | WTS_REMOTE_DISCONNECT => Some(LockReason::UserSwitch),
        WTS_SESSION_LOGOFF => Some(LockReason::Shutdown),
        _ => None,
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::System::Power::RegisterSuspendResumeNotification;
    use windows_sys::Win32::System::RemoteDesktop::{NOTIFY_FOR_THIS_SESSION, WTSRegisterSessionNotification};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DEVICE_NOTIFY_WINDOW_HANDLE, DefWindowProcW, DispatchMessageW, GetMessageW, MSG, PBT_APMSUSPEND, RegisterClassExW,
        TranslateMessage, WM_ENDSESSION, WM_POWERBROADCAST, WM_QUERYENDSESSION, WM_WTSSESSION_CHANGE, WNDCLASSEXW, WS_EX_TOOLWINDOW,
        WS_OVERLAPPED,
    };

    unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
        match msg {
            WM_WTSSESSION_CHANGE => {
                if let Some(r) = map_session_change(wparam as u32) {
                    fire(r);
                }
            }
            WM_POWERBROADCAST if wparam as u32 == PBT_APMSUSPEND => fire(LockReason::Suspend),
            WM_QUERYENDSESSION => {
                fire(LockReason::Shutdown);
                return 1;
            }
            WM_ENDSESSION if wparam != 0 => fire(LockReason::Shutdown),
            _ => {}
        }
        unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
    }

    pub fn start() -> bool {
        let (tx, rx) = std::sync::mpsc::channel();
        let spawned = std::thread::Builder::new().name("kv-os-events".into()).spawn(move || unsafe {
            let class: Vec<u16> = "KeyVaultOsEvents".encode_utf16().chain(std::iter::once(0)).collect();
            let hinst = GetModuleHandleW(std::ptr::null());
            let wc = WNDCLASSEXW {
                cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
                lpfnWndProc: Some(wndproc),
                hInstance: hinst,
                lpszClassName: class.as_ptr(),
                ..Default::default()
            };
            if RegisterClassExW(&wc) == 0 {
                let _ = tx.send(false);
                return;
            }
            // Janela de nível superior nunca exibida (recebe broadcasts de energia).
            let hwnd = CreateWindowExW(
                WS_EX_TOOLWINDOW,
                class.as_ptr(),
                class.as_ptr(),
                WS_OVERLAPPED,
                0,
                0,
                0,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                hinst,
                std::ptr::null(),
            );
            if hwnd.is_null() {
                let _ = tx.send(false);
                return;
            }
            let wts = WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION) != 0;
            let pwr = RegisterSuspendResumeNotification(hwnd as _, DEVICE_NOTIFY_WINDOW_HANDLE) != 0;
            let _ = tx.send(wts && pwr);
            let mut msg: MSG = std::mem::zeroed();
            while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        });
        spawned.is_ok() && rx.recv().unwrap_or(false)
    }
}

#[cfg(not(windows))]
mod platform {
    /// Integrações de SO ainda não implementadas fora do Windows (não homologado).
    pub fn start() -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_change_codes() {
        assert_eq!(map_session_change(7), Some(LockReason::OsLock));
        assert_eq!(map_session_change(2), Some(LockReason::UserSwitch));
        assert_eq!(map_session_change(4), Some(LockReason::UserSwitch));
        assert_eq!(map_session_change(6), Some(LockReason::Shutdown));
        assert_eq!(map_session_change(8), None); // desbloqueio não faz nada (senha sempre exigida)
    }
}
