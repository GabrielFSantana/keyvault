//! Utilidades de sistema de arquivos: permissões privadas, publicação atômica e travas de processo.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::error::{CoreError, Result};
use crate::rng::{SecureRandom, random_array};

/// Restringe `path` (arquivo ou diretório) ao usuário atual.
///
/// Windows: DACL protegida (sem herança dos pais) com uma única ACE de controle total para o SID do
/// usuário do processo, herdável por arquivos/subpastas (`OICI`). Unix: 0700 (dir) / 0600 (arquivo).
pub fn restrict_to_current_user(path: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        win::restrict(path)
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if path.is_dir() { 0o700 } else { 0o600 };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
        Ok(())
    }
}

/// Cria (se necessário) um diretório privado.
pub fn ensure_private_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)?;
    restrict_to_current_user(path)
}

/// Substitui/publica `tmp` em `dest` de forma atômica no mesmo volume.
/// Windows: `MoveFileExW(MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)`.
pub fn atomic_publish(tmp: &Path, dest: &Path, allow_replace: bool) -> Result<()> {
    if !allow_replace && dest.exists() {
        return Err(CoreError::AlreadyExists);
    }
    #[cfg(windows)]
    {
        win::move_file(tmp, dest, allow_replace)
    }
    #[cfg(not(windows))]
    {
        std::fs::rename(tmp, dest)?;
        if let Some(parent) = dest.parent() {
            File::open(parent)?.sync_all()?;
        }
        Ok(())
    }
}

/// Grava `bytes` em `dest` por meio de um temporário privado no mesmo diretório, com `fsync`, e
/// publica por rename atômico. Em falha remove o temporário e preserva o destino anterior.
///
/// `strict_acl`: se verdadeiro, falha quando não é possível restringir a ACL do temporário. Para
/// backups em mídias sem ACL (ex.: FAT32/exFAT) usa-se `false`: o conteúdo já é ciphertext.
pub fn write_file_atomically(dest: &Path, bytes: &[u8], allow_replace: bool, strict_acl: bool, rng: &dyn SecureRandom) -> Result<()> {
    let dir = dest.parent().ok_or(CoreError::Io)?;
    let suffix = hex_lower(&random_array::<8>(rng)?);
    let tmp: PathBuf = dir.join(format!(".keyvault-{suffix}.tmp"));
    let result = (|| -> Result<()> {
        let mut f = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        if let Err(e) = restrict_to_current_user(&tmp)
            && strict_acl
        {
            return Err(e);
        }
        #[cfg(feature = "test-instrumentation")]
        testing::maybe_fail(testing::FsFault::Write)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        #[cfg(feature = "test-instrumentation")]
        testing::maybe_fail(testing::FsFault::Publish)?;
        atomic_publish(&tmp, dest, allow_replace)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

pub fn hex_lower(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 0xf) as usize] as char);
    }
    s
}

pub fn parse_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 || !s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
        return None;
    }
    let mut out = [0u8; N];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let v = |c: u8| if c.is_ascii_digit() { c - b'0' } else { c - b'a' + 10 };
        out[i] = (v(chunk[0]) << 4) | v(chunk[1]);
    }
    Some(out)
}

/// Trava exclusiva entre processos (uma instância/escritor por cofre). Liberada ao descartar.
pub struct ProcessLock {
    _file: File,
}

impl ProcessLock {
    pub fn acquire(path: &Path) -> Result<Self> {
        let file = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path)?;
        match file.try_lock() {
            Ok(()) => Ok(ProcessLock { _file: file }),
            Err(std::fs::TryLockError::WouldBlock) => Err(CoreError::VaultBusy),
            Err(std::fs::TryLockError::Error(e)) => Err(e.into()),
        }
    }
}

#[cfg(windows)]
mod win {
    use super::*;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, HANDLE, HLOCAL, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1, SE_FILE_OBJECT,
        SetNamedSecurityInfoW,
    };
    use windows_sys::Win32::Security::{
        ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetTokenInformation, PROTECTED_DACL_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    fn wide(p: &Path) -> Vec<u16> {
        p.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
    }

    fn current_user_sid_string() -> Result<String> {
        unsafe {
            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return Err(CoreError::PermissionDenied);
            }
            let mut needed = 0u32;
            GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed);
            // Buffer alinhado para TOKEN_USER.
            let words = (needed as usize).div_ceil(8).max(1);
            let mut buf = vec![0u64; words];
            let ok = GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), (words * 8) as u32, &mut needed);
            CloseHandle(token);
            if ok == 0 {
                return Err(CoreError::PermissionDenied);
            }
            let tu = &*(buf.as_ptr() as *const TOKEN_USER);
            let mut sid_str: windows_sys::core::PWSTR = std::ptr::null_mut();
            if ConvertSidToStringSidW(tu.User.Sid, &mut sid_str) == 0 {
                return Err(CoreError::PermissionDenied);
            }
            let mut len = 0usize;
            while *sid_str.add(len) != 0 {
                len += 1;
            }
            let s = String::from_utf16_lossy(std::slice::from_raw_parts(sid_str, len));
            LocalFree(sid_str as HLOCAL);
            Ok(s)
        }
    }

    pub fn restrict(path: &Path) -> Result<()> {
        let sid = current_user_sid_string()?;
        // P = DACL protegida; OICI = herdável por objetos e contêineres; FA = controle total.
        let sddl: Vec<u16> = format!("D:P(A;OICI;FA;;;{sid})").encode_utf16().chain(std::iter::once(0)).collect();
        unsafe {
            let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut sd, std::ptr::null_mut()) == 0 {
                return Err(CoreError::PermissionDenied);
            }
            let mut present = 0;
            let mut defaulted = 0;
            let mut dacl: *mut ACL = std::ptr::null_mut();
            let ok = GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted);
            let rc = if ok != 0 && present != 0 {
                SetNamedSecurityInfoW(
                    wide(path).as_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    dacl,
                    std::ptr::null(),
                )
            } else {
                1
            };
            LocalFree(sd as HLOCAL);
            if rc != ERROR_SUCCESS {
                return Err(CoreError::PermissionDenied);
            }
        }
        Ok(())
    }

    pub fn move_file(from: &Path, to: &Path, replace: bool) -> Result<()> {
        let flags = MOVEFILE_WRITE_THROUGH | if replace { MOVEFILE_REPLACE_EXISTING } else { 0 };
        let ok = unsafe { MoveFileExW(wide(from).as_ptr(), wide(to).as_ptr(), flags) };
        if ok == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }

    /// Somente testes: aplica uma DACL vazia (nenhum acesso) para simular permissão negada.
    #[cfg(feature = "test-instrumentation")]
    pub fn deny_all(path: &Path) -> Result<()> {
        let sddl: Vec<u16> = "D:P".encode_utf16().chain(std::iter::once(0)).collect();
        unsafe {
            let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut sd, std::ptr::null_mut()) == 0 {
                return Err(CoreError::PermissionDenied);
            }
            let mut present = 0;
            let mut defaulted = 0;
            let mut dacl: *mut ACL = std::ptr::null_mut();
            GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted);
            let rc = SetNamedSecurityInfoW(
                wide(path).as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                dacl,
                std::ptr::null(),
            );
            LocalFree(sd as HLOCAL);
            if rc != ERROR_SUCCESS {
                return Err(CoreError::PermissionDenied);
            }
        }
        Ok(())
    }
}

#[cfg(feature = "test-instrumentation")]
pub mod testing {
    //! Injeção de falhas de E/S (somente testes).
    use super::*;
    use std::cell::Cell;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum FsFault {
        Write,
        Publish,
    }

    thread_local! {
        static FAULT: Cell<Option<FsFault>> = const { Cell::new(None) };
    }

    pub fn set(f: Option<FsFault>) {
        FAULT.with(|c| c.set(f));
    }

    pub(crate) fn maybe_fail(at: FsFault) -> Result<()> {
        if FAULT.with(|c| c.get()) == Some(at) {
            FAULT.with(|c| c.set(None));
            return Err(CoreError::InjectedFault);
        }
        Ok(())
    }

    #[cfg(windows)]
    pub fn deny_all(path: &Path) -> Result<()> {
        super::win::deny_all(path)
    }
}
