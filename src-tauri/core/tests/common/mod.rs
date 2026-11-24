#![allow(dead_code, clippy::unwrap_used)]
//! Utilidades de teste. Somente dados fictícios.

use keyvault_core::crypto::KdfParams;
use keyvault_core::model::{CustomField, Entry, Settings, Snapshot};
use keyvault_core::rng::OsRandom;
use keyvault_core::secret::MasterPassword;
use keyvault_core::service::{EntryInput, FieldInput, OpenVault, SecretUpdate};
use zeroize::Zeroizing;

pub const PW: &str = "senha mestra ficticia de teste 123";
pub const PW2: &str = "outra senha mestra ficticia 456";

pub fn pw(s: &str) -> MasterPassword {
    MasterPassword::for_tests(s)
}

pub fn kdf() -> KdfParams {
    KdfParams::INITIAL
}

pub fn sample_entry(id: u8, title: &str) -> Entry {
    Entry {
        id: [id; 16],
        created_at_ms: 1_700_000_000_000,
        updated_at_ms: 1_700_000_000_000,
        favorite: id.is_multiple_of(2),
        title: title.into(),
        url: "https://exemplo.invalid".into(),
        username: "usuario".into(),
        password: "senha-ficticia".into(),
        notes: "nota".into(),
        tags: vec!["t1".into()],
        fields: vec![CustomField { id: [id.wrapping_add(100); 16], secret: true, name: "token".into(), value: "valor".into() }],
    }
}

pub fn sample_snapshot(vault_id: [u8; 16], revision: u64, n: u8) -> Snapshot {
    Snapshot {
        vault_id,
        revision,
        settings: Settings::default(),
        entries: (1..=n).map(|i| sample_entry(i, &format!("Entrada {i}"))).collect(),
    }
}

pub fn input(title: &str) -> EntryInput {
    EntryInput {
        id: None,
        title: title.into(),
        url: "https://exemplo.invalid/login".into(),
        username: "usuario.ficticio".into(),
        password: SecretUpdate::Set(Zeroizing::new("S3nha-Fict1cia!".into())),
        notes: "notas ficticias".into(),
        tags: vec!["infra".into()],
        favorite: false,
        fields: vec![FieldInput {
            id: None,
            name: "API".into(),
            secret: true,
            value: SecretUpdate::Set(Zeroizing::new("api-ficticia".into())),
        }],
    }
}

pub fn new_vault(dir: &std::path::Path) -> OpenVault {
    OpenVault::create(dir, pw(PW), kdf(), &OsRandom).unwrap()
}

pub fn now() -> i64 {
    1_763_856_000_000
}
