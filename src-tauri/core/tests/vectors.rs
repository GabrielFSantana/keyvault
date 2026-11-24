#![allow(clippy::unwrap_used)]
//! Vetor de integração estável v1 (docs/format.md §12). Material fictício injetado por um RNG
//! determinístico de teste. Verificado de forma independente por tools/vectors/verify_vector.py.

use keyvault_core::crypto::{KdfParams, sha256};
use keyvault_core::envelope::{self, EnvelopeKind, SealRequest};
use keyvault_core::model::{CustomField, Entry, Settings, Snapshot};
use keyvault_core::rng::testing::ScriptedRandom;
use keyvault_core::secret::MasterPassword;

pub const PASSWORD: &str = "senha de teste fictícia 🔐 não use";

fn seq(start: u8) -> [u8; 16] {
    core::array::from_fn(|i| start + i as u8)
}

fn vector_snapshot() -> Snapshot {
    Snapshot {
        vault_id: seq(0x40),
        revision: 1,
        settings: Settings { auto_lock_minutes: 5, clipboard_seconds: 20, lock_on_blur: true },
        entries: vec![Entry {
            id: seq(0x50),
            created_at_ms: 1_763_856_000_000,
            updated_at_ms: 1_763_856_000_000,
            favorite: true,
            title: "Exemplo n8n".into(),
            url: "https://n8n.exemplo.invalid".into(),
            username: "usuario.ficticio".into(),
            password: "S3nh@-Fict1cia".into(),
            notes: "linha 1\nlinha 2".into(),
            tags: vec!["infra".into(), "teste".into()],
            fields: vec![CustomField { id: seq(0x60), secret: true, name: "API key".into(), value: "chave-ficticia-123".into() }],
        }],
    }
}

/// SHA-256 do envelope esperado (fixado após a primeira execução e conferido em Python).
const EXPECTED_SHA256: &str = "235a289c469e817419203e3e188251638d2bce5dd1b20d709fe4c09347fffcce";

#[test]
fn integration_vector_v1() {
    let rnd: Vec<u8> = (0u8..64).collect(); // DEK = 00..1f, salt = 20..3f
    let rng = ScriptedRandom::new(&rnd);
    let pw = MasterPassword::for_tests(PASSWORD);
    let env =
        envelope::seal(&SealRequest { password: &pw, kdf: KdfParams::INITIAL, kind: EnvelopeKind::VaultSlot }, &vector_snapshot(), &rng)
            .unwrap();
    let digest = hex::encode(sha256(&env));
    let out = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/vectors/vector_v1.hex");
    std::fs::create_dir_all(out.parent().unwrap()).unwrap();
    std::fs::write(&out, hex::encode(&env)).unwrap();
    println!("len={} sha256={digest}", env.len());
    // Reabre com a senha correta e confere o conteúdo.
    let (h, s) = envelope::open(&pw, &env, EnvelopeKind::VaultSlot).unwrap();
    assert_eq!(h.salt.to_vec(), (0x20u8..0x40).collect::<Vec<_>>());
    assert_eq!(s.entries[0].fields[0].value, "chave-ficticia-123");
    if EXPECTED_SHA256 != "PENDENTE" {
        assert_eq!(digest, EXPECTED_SHA256, "o vetor de integração mudou: formato não é estável");
    }
}
