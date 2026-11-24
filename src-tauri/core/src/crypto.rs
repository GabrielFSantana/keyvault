//! Primitivas: Argon2id (RustCrypto `argon2`) e AES-256-GCM (RustCrypto `aes-gcm`).
//!
//! Regra central (KEYVAULT.md §5): cada chave participa de exatamente UMA operação GCM, sempre com
//! nonce de 96 bits zero. A API torna isso estrutural:
//!
//! * `FreshDek` / `FreshKek` só existem a partir do CSPRNG (DEK) ou de um salt novo do CSPRNG (KEK)
//!   e só podem **cifrar uma vez** (métodos consomem `self`).
//! * `OpeningKek` / `OpenedDek` vêm de material persistido e só podem **decifrar uma vez**.
//! * Nenhum tipo é `Clone`/`Copy`; todos zeram a memória ao serem descartados.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit};
use argon2::{Algorithm, Argon2, Params, Version};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{CoreError, Result};
use crate::limits::*;
use crate::rng::{SecureRandom, random_array};
use crate::secret::MasterPassword;

pub const KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const WRAPPED_DEK_LEN: usize = KEY_LEN + TAG_LEN;
/// Nonce fixo permitido SOMENTE porque cada chave é de uso único.
pub const ZERO_NONCE: [u8; NONCE_LEN] = [0u8; NONCE_LEN];

/// Parâmetros Argon2id (versão 0x13, saída de 32 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl KdfParams {
    /// Perfil inicial normativo: m=64 MiB, t=3, p=4.
    pub const INITIAL: KdfParams = KdfParams { m_cost_kib: 65_536, t_cost: 3, p_cost: 4 };

    pub fn validate(&self) -> Result<()> {
        let ok = (KDF_M_MIN_KIB..=KDF_M_MAX_KIB).contains(&self.m_cost_kib)
            && (KDF_T_MIN..=KDF_T_MAX).contains(&self.t_cost)
            && (KDF_P_MIN..=KDF_P_MAX).contains(&self.p_cost);
        if ok { Ok(()) } else { Err(crate::error::FormatError::KdfParams.into()) }
    }
}

fn argon2_derive(password: &[u8], salt: &[u8; SALT_LEN], params: &KdfParams) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    // Limites aplicados ANTES de alocar a memória da KDF.
    params.validate()?;
    if password.is_empty() || password.len() > MAX_PASSWORD_BYTES {
        return Err(CoreError::Validation(crate::error::Field::MasterPassword));
    }
    let p = Params::new(params.m_cost_kib, params.t_cost, params.p_cost, Some(KEY_LEN)).map_err(|_| CoreError::Kdf)?;
    let ctx = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    ctx.hash_password_into(password, salt, out.as_mut()).map_err(|_| CoreError::Kdf)?;
    Ok(out)
}

/// Executa Argon2id com parâmetros arbitrários dentro dos limites (usado na calibração).
pub fn argon2id_raw(password: &[u8], salt: &[u8; SALT_LEN], params: &KdfParams) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    argon2_derive(password, salt, params)
}

fn cipher_for(key: &[u8; KEY_LEN]) -> Result<Aes256Gcm> {
    Aes256Gcm::new_from_slice(key).map_err(|_| CoreError::Crypto)
}

fn gcm_seal(key: &[u8; KEY_LEN], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = cipher_for(key)?;
    let nonce = aes_gcm::Nonce::<aes_gcm::aead::consts::U12>::from(ZERO_NONCE);
    cipher.encrypt(&nonce, Payload { msg: plaintext, aad }).map_err(|_| CoreError::Crypto)
}

fn gcm_open(key: &[u8; KEY_LEN], ciphertext: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = cipher_for(key)?;
    let nonce = aes_gcm::Nonce::<aes_gcm::aead::consts::U12>::from(ZERO_NONCE);
    // API não-streaming: a tag é verificada antes de qualquer byte ser devolvido.
    cipher.decrypt(&nonce, Payload { msg: ciphertext, aad }).map(Zeroizing::new).map_err(|_| CoreError::Authentication)
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_slice());
    out
}

/// DEK nova, do CSPRNG, válida para exatamente uma cifragem.
pub struct FreshDek(Zeroizing<[u8; KEY_LEN]>);

/// Bytes de uma DEK que já cifrou seu payload; só podem ser embrulhados por uma `FreshKek`.
pub struct DekForWrapping(Zeroizing<[u8; KEY_LEN]>);

impl FreshDek {
    pub fn generate(rng: &dyn SecureRandom) -> Result<Self> {
        let mut bytes = random_array::<KEY_LEN>(rng)?;
        let dek = FreshDek(Zeroizing::new(bytes));
        bytes.zeroize();
        Ok(dek)
    }

    /// Única cifragem desta DEK. Consome a chave.
    pub fn seal_once(self, plaintext: &[u8], aad: &[u8]) -> Result<(Vec<u8>, DekForWrapping)> {
        #[cfg(feature = "test-instrumentation")]
        instrument::record(instrument::Purpose::Snapshot, &self.0, &ZERO_NONCE);
        let ct = gcm_seal(&self.0, plaintext, aad)?;
        Ok((ct, DekForWrapping(self.0)))
    }
}

/// KEK derivada de um salt NOVO do CSPRNG; válida para exatamente um wrapping.
pub struct FreshKek(Zeroizing<[u8; KEY_LEN]>);

impl FreshKek {
    /// Gera salt novo e deriva a KEK. Não existe construtor com salt externo.
    pub fn derive_with_new_salt(password: &MasterPassword, params: &KdfParams, rng: &dyn SecureRandom) -> Result<(Self, [u8; SALT_LEN])> {
        params.validate()?;
        let salt = random_array::<SALT_LEN>(rng)?;
        let key = argon2_derive(password.as_bytes(), &salt, params)?;
        Ok((FreshKek(key), salt))
    }

    /// Única cifragem desta KEK: embrulha a DEK. Consome a KEK e a DEK.
    pub fn wrap_once(self, dek: DekForWrapping, aad: &[u8]) -> Result<Vec<u8>> {
        #[cfg(feature = "test-instrumentation")]
        instrument::record(instrument::Purpose::Wrap, &self.0, &ZERO_NONCE);
        let wrapped = gcm_seal(&self.0, dek.0.as_ref(), aad)?;
        debug_assert_eq!(wrapped.len(), WRAPPED_DEK_LEN);
        Ok(wrapped)
    }
}

/// KEK derivada do salt de um envelope existente: só decifra.
pub struct OpeningKek(Zeroizing<[u8; KEY_LEN]>);

impl OpeningKek {
    pub fn derive(password: &MasterPassword, salt: &[u8; SALT_LEN], params: &KdfParams) -> Result<Self> {
        Ok(OpeningKek(argon2_derive(password.as_bytes(), salt, params)?))
    }

    pub fn unwrap_once(self, wrapped: &[u8], aad: &[u8]) -> Result<OpenedDek> {
        if wrapped.len() != WRAPPED_DEK_LEN {
            return Err(CoreError::Authentication);
        }
        let plain = gcm_open(&self.0, wrapped, aad)?;
        if plain.len() != KEY_LEN {
            return Err(CoreError::Authentication);
        }
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        key.copy_from_slice(&plain);
        Ok(OpenedDek(key))
    }
}

/// DEK recuperada de um envelope: só decifra (nunca é reutilizada para escrever).
pub struct OpenedDek(Zeroizing<[u8; KEY_LEN]>);

impl OpenedDek {
    pub fn open_once(self, ciphertext: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        gcm_open(&self.0, ciphertext, aad)
    }
}

/// Acesso direto às primitivas para vetores de teste oficiais (somente testes).
#[cfg(any(test, feature = "test-instrumentation"))]
#[allow(clippy::unwrap_used)]
pub mod testing {
    use super::*;
    pub fn aes256gcm_encrypt(key: &[u8; 32], nonce: &[u8; 12], pt: &[u8], aad: &[u8]) -> Vec<u8> {
        let c = Aes256Gcm::new_from_slice(key).unwrap();
        let n = aes_gcm::Nonce::<aes_gcm::aead::consts::U12>::from(*nonce);
        c.encrypt(&n, Payload { msg: pt, aad }).unwrap()
    }
    pub fn aes256gcm_decrypt(key: &[u8; 32], nonce: &[u8; 12], ct: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
        let c = Aes256Gcm::new_from_slice(key).unwrap();
        let n = aes_gcm::Nonce::<aes_gcm::aead::consts::U12>::from(*nonce);
        c.decrypt(&n, Payload { msg: ct, aad }).ok()
    }
}

/// Instrumentação de pares chave/nonce — SOMENTE com a feature de teste; registra a impressão
/// SHA-256 da chave (dados fictícios) por thread.
#[cfg(feature = "test-instrumentation")]
pub mod instrument {
    use std::cell::RefCell;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum Purpose {
        Snapshot,
        Wrap,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    pub struct Use {
        pub purpose: Purpose,
        pub key_fingerprint: [u8; 32],
        pub nonce: [u8; 12],
    }

    thread_local! {
        static USES: RefCell<Vec<Use>> = const { RefCell::new(Vec::new()) };
    }

    pub(crate) fn record(purpose: Purpose, key: &[u8; 32], nonce: &[u8; 12]) {
        let fp = super::sha256(key);
        USES.with(|u| u.borrow_mut().push(Use { purpose, key_fingerprint: fp, nonce: *nonce }));
    }

    /// Retorna e limpa os registros desta thread.
    pub fn take() -> Vec<Use> {
        USES.with(|u| std::mem::take(&mut *u.borrow_mut()))
    }
}

#[cfg(all(feature = "test-instrumentation", not(debug_assertions)))]
compile_error!("a feature test-instrumentation não pode ser usada em builds de release");
