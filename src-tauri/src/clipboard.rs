//! Clipboard no Rust (o frontend não tem acesso ao clipboard).
//!
//! Windows: escrita com os formatos que pedem exclusão do histórico/sincronização do clipboard
//! (`ExcludeClipboardContentFromMonitorProcessing`, `CanIncludeInClipboardHistory = 0`,
//! `CanUploadToCloudClipboard = 0`). Limpeza somente se o clipboard ainda contém o que escrevemos:
//! com o clipboard aberto (o que impede escrita concorrente de outros processos), compara o número de
//! sequência registrado após a nossa escrita; se outro conteúdo foi copiado, nada é apagado.
//! Não guardamos o conteúdo nem hashes persistentes.

use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug)]
struct Owned {
    sequence: u32,
    expires: Instant,
}

#[derive(Debug, Default)]
pub struct ClipboardOwner {
    owned: Mutex<Option<Owned>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardError {
    Unavailable,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClearOutcome {
    Cleared,
    /// O usuário (ou outro processo) copiou outro conteúdo: preservado.
    Replaced,
    NothingOwned,
    Failed,
}

impl ClipboardOwner {
    fn guard(&self) -> std::sync::MutexGuard<'_, Option<Owned>> {
        self.owned.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn copy_secret(&self, text: &str, ttl: Duration) -> Result<(), ClipboardError> {
        let mut g = self.guard();
        let sequence = platform::write_secret(text)?;
        *g = Some(Owned { sequence, expires: Instant::now() + ttl });
        Ok(())
    }

    /// Limpa se ainda for o nosso conteúdo. Idempotente.
    pub fn clear_if_ours(&self) -> ClearOutcome {
        let mut g = self.guard();
        let Some(o) = g.take() else { return ClearOutcome::NothingOwned };
        match platform::clear_if_sequence(o.sequence) {
            Ok(true) => ClearOutcome::Cleared,
            Ok(false) => ClearOutcome::Replaced,
            Err(_) => ClearOutcome::Failed,
        }
    }

    pub fn expire(&self) -> Option<ClearOutcome> {
        let due = self.guard().as_ref().is_some_and(|o| Instant::now() >= o.expires);
        if due { Some(self.clear_if_ours()) } else { None }
    }

    pub fn owns_something(&self) -> bool {
        self.guard().is_some()
    }
}

#[cfg(windows)]
mod platform {
    use super::ClipboardError;
    use windows_sys::Win32::Foundation::{GlobalFree, HANDLE};
    use windows_sys::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, GetClipboardSequenceNumber, OpenClipboard, RegisterClipboardFormatW, SetClipboardData,
    };
    use windows_sys::Win32::System::Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock};
    use windows_sys::Win32::System::Ole::CF_UNICODETEXT;
    use zeroize::Zeroize;

    struct Open;
    impl Open {
        fn new() -> Result<Self, ClipboardError> {
            // Outro processo pode estar com o clipboard aberto: algumas tentativas curtas.
            for _ in 0..10 {
                if unsafe { OpenClipboard(std::ptr::null_mut()) } != 0 {
                    return Ok(Open);
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Err(ClipboardError::Unavailable)
        }
    }
    impl Drop for Open {
        fn drop(&mut self) {
            unsafe { CloseClipboard() };
        }
    }

    fn format(name: &str) -> u32 {
        let w: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        unsafe { RegisterClipboardFormatW(w.as_ptr()) }
    }

    unsafe fn set_bytes(fmt: u32, bytes: &[u8]) -> bool {
        unsafe {
            let h = GlobalAlloc(GMEM_MOVEABLE, bytes.len().max(1));
            if h.is_null() {
                return false;
            }
            let p = GlobalLock(h) as *mut u8;
            if p.is_null() {
                GlobalFree(h);
                return false;
            }
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), p, bytes.len());
            GlobalUnlock(h);
            if SetClipboardData(fmt, h as HANDLE).is_null() {
                GlobalFree(h);
                return false;
            }
            true
        }
    }

    pub fn write_secret(text: &str) -> Result<u32, ClipboardError> {
        let mut wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
        let mut bytes: Vec<u8> = wide.iter().flat_map(|u| u.to_le_bytes()).collect();
        wide.zeroize();
        let result = (|| {
            let _open = Open::new()?;
            unsafe {
                if EmptyClipboard() == 0 {
                    return Err(ClipboardError::Unavailable);
                }
                // Pedidos de exclusão do histórico e da sincronização em nuvem do Windows.
                set_bytes(format("ExcludeClipboardContentFromMonitorProcessing"), &[0]);
                set_bytes(format("CanIncludeInClipboardHistory"), &0u32.to_le_bytes());
                set_bytes(format("CanUploadToCloudClipboard"), &0u32.to_le_bytes());
                if !set_bytes(CF_UNICODETEXT as u32, &bytes) {
                    return Err(ClipboardError::Unavailable);
                }
            }
            Ok(())
        })();
        bytes.zeroize();
        result?;
        // Número de sequência após a nossa escrita (clipboard já fechado).
        Ok(unsafe { GetClipboardSequenceNumber() })
    }

    /// Com o clipboard aberto (bloqueia escritas concorrentes), limpa somente se a sequência ainda
    /// for a registrada após a nossa escrita.
    pub fn clear_if_sequence(seq: u32) -> Result<bool, ClipboardError> {
        let _open = Open::new()?;
        unsafe {
            if GetClipboardSequenceNumber() != seq {
                return Ok(false);
            }
            if EmptyClipboard() == 0 {
                return Err(ClipboardError::Unavailable);
            }
        }
        Ok(true)
    }

    #[cfg(test)]
    pub fn sequence() -> u32 {
        unsafe { GetClipboardSequenceNumber() }
    }
}

#[cfg(not(windows))]
mod platform {
    use super::ClipboardError;
    pub fn write_secret(_text: &str) -> Result<u32, ClipboardError> {
        Err(ClipboardError::Unsupported)
    }
    pub fn clear_if_sequence(_seq: u32) -> Result<bool, ClipboardError> {
        Err(ClipboardError::Unsupported)
    }
}

/// Testes no clipboard REAL do Windows. Somente dados fictícios; executar com
/// `cargo test -- --ignored clipboard` (altera o clipboard do usuário).
#[cfg(all(test, windows))]
mod tests {
    use super::*;

    fn read_text() -> Option<String> {
        use windows_sys::Win32::System::DataExchange::{CloseClipboard, GetClipboardData, OpenClipboard};
        use windows_sys::Win32::System::Memory::{GlobalLock, GlobalUnlock};
        unsafe {
            if OpenClipboard(std::ptr::null_mut()) == 0 {
                return None;
            }
            let h = GetClipboardData(13);
            let out = if h.is_null() {
                None
            } else {
                let p = GlobalLock(h as _) as *const u16;
                let mut n = 0;
                while *p.add(n) != 0 {
                    n += 1;
                }
                let s = String::from_utf16_lossy(std::slice::from_raw_parts(p, n));
                GlobalUnlock(h as _);
                Some(s)
            };
            CloseClipboard();
            out
        }
    }

    fn user_copies(text: &str) {
        // Simula outro aplicativo copiando (escrita normal, sem formatos de exclusão).
        use windows_sys::Win32::System::DataExchange::{CloseClipboard, EmptyClipboard, OpenClipboard};
        unsafe {
            assert!(OpenClipboard(std::ptr::null_mut()) != 0);
            EmptyClipboard();
            let wide: Vec<u8> = text.encode_utf16().chain(std::iter::once(0)).flat_map(|u| u.to_le_bytes()).collect();
            assert!(platform_set(13, &wide));
            CloseClipboard();
        }
    }

    unsafe fn platform_set(fmt: u32, bytes: &[u8]) -> bool {
        use windows_sys::Win32::System::DataExchange::SetClipboardData;
        use windows_sys::Win32::System::Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock};
        unsafe {
            let h = GlobalAlloc(GMEM_MOVEABLE, bytes.len());
            let p = GlobalLock(h) as *mut u8;
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), p, bytes.len());
            GlobalUnlock(h);
            !SetClipboardData(fmt, h as _).is_null()
        }
    }

    #[test]
    #[ignore = "usa o clipboard real do Windows"]
    fn clipboard_real_copy_clear_and_preserve_user_content() {
        let c = ClipboardOwner::default();
        c.copy_secret("segredo-ficticio-clipboard-1", Duration::from_millis(200)).unwrap();
        assert_eq!(read_text().as_deref(), Some("segredo-ficticio-clipboard-1"));
        let seq = platform::sequence();
        // Ler não altera a sequência.
        let _ = read_text();
        assert_eq!(platform::sequence(), seq);
        // Expiração limpa o próprio conteúdo.
        std::thread::sleep(Duration::from_millis(250));
        assert_eq!(c.expire(), Some(ClearOutcome::Cleared));
        assert_eq!(read_text(), None);

        // Conteúdo novo do usuário é preservado.
        c.copy_secret("segredo-ficticio-clipboard-2", Duration::from_secs(60)).unwrap();
        user_copies("texto novo do usuario");
        assert_eq!(c.clear_if_ours(), ClearOutcome::Replaced);
        assert_eq!(read_text().as_deref(), Some("texto novo do usuario"));

        // Mesmo conteúdo copiado de novo pelo usuário também é preservado (sequência mudou).
        c.copy_secret("segredo-ficticio-clipboard-3", Duration::from_secs(60)).unwrap();
        user_copies("segredo-ficticio-clipboard-3");
        assert_eq!(c.clear_if_ours(), ClearOutcome::Replaced);
        assert_eq!(read_text().as_deref(), Some("segredo-ficticio-clipboard-3"));
        user_copies("");
        assert_eq!(c.clear_if_ours(), ClearOutcome::NothingOwned);
    }
}
