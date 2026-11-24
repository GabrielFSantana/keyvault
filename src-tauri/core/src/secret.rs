//! Senha mestra em buffer zeroizável.
//!
//! O protocolo exige uma KEK nova (salt novo) a cada salvamento; por isso a senha permanece neste
//! buffer, somente no processo Rust, enquanto o cofre está desbloqueado (KEYVAULT.md §5). Ela é zerada
//! ao bloquear. Isso é exposição documentada em docs/security.md: um atacante com leitura da memória do
//! processo desbloqueado obtém a senha.

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::{CoreError, Field, Result};
use crate::limits::{MAX_PASSWORD_BYTES, MIN_PASSWORD_CHARS};

pub struct MasterPassword(Zeroizing<Vec<u8>>);

impl MasterPassword {
    /// Para criação/troca: mínimo de 15 caracteres Unicode (valores escalares), máximo de 1.024 bytes
    /// UTF-8. Bytes exatos, sem trim/normalização/truncamento.
    pub fn new_for_creation(password: Zeroizing<String>) -> Result<Self> {
        if password.len() > MAX_PASSWORD_BYTES {
            return Err(CoreError::Validation(Field::MasterPassword));
        }
        if password.chars().count() < MIN_PASSWORD_CHARS {
            return Err(CoreError::Validation(Field::MasterPassword));
        }
        Ok(Self::take(password))
    }

    /// Para desbloqueio/verificação: apenas limites de tamanho (não revela política).
    pub fn new_for_unlock(password: Zeroizing<String>) -> Result<Self> {
        if password.is_empty() || password.len() > MAX_PASSWORD_BYTES {
            return Err(CoreError::Validation(Field::MasterPassword));
        }
        Ok(Self::take(password))
    }

    fn take(password: Zeroizing<String>) -> Self {
        // Copia os bytes para um buffer com capacidade exata e zera a String de origem ao sair.
        let mut v = Zeroizing::new(Vec::with_capacity(password.len()));
        v.extend_from_slice(password.as_bytes());
        MasterPassword(v)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Comparação em tempo constante (para "senha atual" na troca de senha).
    pub fn ct_eq(&self, other: &MasterPassword) -> bool {
        bool::from(self.0.as_slice().ct_eq(other.0.as_slice()))
    }

    #[cfg(any(test, feature = "test-instrumentation"))]
    pub fn for_tests(s: &str) -> Self {
        Self::take(Zeroizing::new(s.to_owned()))
    }
}

impl std::fmt::Debug for MasterPassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterPassword(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_bytes_no_trim_or_normalization() {
        let p = MasterPassword::new_for_creation(Zeroizing::new("  quinze carac  ✓ ".into())).unwrap();
        assert_eq!(p.as_bytes(), "  quinze carac  ✓ ".as_bytes());
        // NFC vs NFD não são normalizados: bytes diferentes.
        let nfc = MasterPassword::new_for_unlock(Zeroizing::new("ação".into())).unwrap();
        let nfd = MasterPassword::new_for_unlock(Zeroizing::new("ac\u{0327}a\u{0303}o".into())).unwrap();
        assert!(!nfc.ct_eq(&nfd));
    }

    #[test]
    fn length_rules() {
        // 14 caracteres: rejeitado na criação.
        assert!(MasterPassword::new_for_creation(Zeroizing::new("a".repeat(14))).is_err());
        assert!(MasterPassword::new_for_creation(Zeroizing::new("a".repeat(15))).is_ok());
        // 15 caracteres multibyte contam como 15.
        assert!(MasterPassword::new_for_creation(Zeroizing::new("🔐".repeat(15))).is_ok());
        // 1024 bytes OK; 1025 rejeitado (sem truncamento).
        assert!(MasterPassword::new_for_creation(Zeroizing::new("a".repeat(1024))).is_ok());
        assert!(MasterPassword::new_for_creation(Zeroizing::new("a".repeat(1025))).is_err());
        assert!(MasterPassword::new_for_unlock(Zeroizing::new(String::new())).is_err());
        assert!(MasterPassword::new_for_unlock(Zeroizing::new("a".repeat(1025))).is_err());
        let dbg = format!("{:?}", MasterPassword::for_tests("segredo-ficticio-123"));
        assert!(!dbg.contains("segredo"));
    }
}
