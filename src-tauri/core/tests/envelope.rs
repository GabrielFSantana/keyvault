#![allow(clippy::unwrap_used)]
//! Envelope: roundtrip, senha errada, adulteração de cada campo, troca wrapper/payload entre cofres e
//! revisões, confusão de contexto (banco × backup) e limites de KDF antes da derivação.

mod common;
use common::*;

use keyvault_core::envelope::{self, EnvelopeKind, HEADER_LEN, SealRequest};
use keyvault_core::rng::OsRandom;
use keyvault_core::{CoreError, FormatError};

fn seal(vault: u8, rev: u64, kind: EnvelopeKind) -> Vec<u8> {
    let p = pw(PW);
    let snap = sample_snapshot([vault; 16], rev, 2);
    envelope::seal(&SealRequest { password: &p, kdf: kdf(), kind }, &snap, &OsRandom).unwrap()
}

fn open(env: &[u8]) -> Result<(), CoreError> {
    envelope::open(&pw(PW), env, EnvelopeKind::VaultSlot).map(|_| ())
}

#[test]
fn roundtrip_and_wrong_password() {
    let env = seal(7, 3, EnvelopeKind::VaultSlot);
    let (h, s) = envelope::open(&pw(PW), &env, EnvelopeKind::VaultSlot).unwrap();
    assert_eq!(h.revision, 3);
    assert_eq!(s.entries.len(), 2);
    assert_eq!(s.entries[0].password, "senha-ficticia");
    assert!(matches!(envelope::open(&pw(PW2), &env, EnvelopeKind::VaultSlot), Err(CoreError::Authentication)));
    // Senha que difere só por normalização/espaço também falha (bytes exatos).
    assert!(matches!(envelope::open(&pw(&format!("{PW} ")), &env, EnvelopeKind::VaultSlot), Err(CoreError::Authentication)));
}

#[test]
fn two_seals_of_same_snapshot_differ_completely() {
    let a = seal(7, 3, EnvelopeKind::VaultSlot);
    let b = seal(7, 3, EnvelopeKind::VaultSlot);
    assert_ne!(a[58..90], b[58..90], "salt repetido");
    assert_ne!(a[HEADER_LEN..HEADER_LEN + 48], b[HEADER_LEN..HEADER_LEN + 48]);
    assert_ne!(a[HEADER_LEN + 48..], b[HEADER_LEN + 48..]);
}

/// Faixas de bytes do envelope e resultado esperado da alteração de um bit.
#[test]
fn tamper_every_header_byte_and_regions() {
    let env = seal(9, 5, EnvelopeKind::VaultSlot);
    // Cada byte do cabeçalho: falha estrutural (antes da KDF) ou de autenticação; nunca sucesso.
    std::thread::scope(|s| {
        let handles: Vec<_> = (0..HEADER_LEN)
            .map(|i| {
                let env = env.clone();
                s.spawn(move || {
                    let mut t = env;
                    t[i] ^= 0x01;
                    let r = open(&t);
                    assert!(matches!(r, Err(CoreError::Format(_)) | Err(CoreError::Authentication)), "byte {i} do cabeçalho: {r:?}");
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
    });
    // Wrapper (DEK cifrada + tag), payload, tag final e primeiro byte do payload.
    for i in [HEADER_LEN, HEADER_LEN + 31, HEADER_LEN + 32, HEADER_LEN + 47, HEADER_LEN + 48, env.len() - 17, env.len() - 16, env.len() - 1]
    {
        let mut t = env.clone();
        t[i] ^= 0x80;
        assert!(matches!(open(&t), Err(CoreError::Authentication)), "offset {i}");
    }
}

#[test]
fn salt_nonce_and_length_changes_fail() {
    let env = seal(9, 5, EnvelopeKind::VaultSlot);
    // salt (offset 58..90) → autenticação
    let mut t = env.clone();
    t[60] ^= 0xff;
    assert!(matches!(open(&t), Err(CoreError::Authentication)));
    // nonces não-zero → rejeitados estruturalmente
    for off in [92, 103, 104, 115] {
        let mut t = env.clone();
        t[off] = 1;
        assert!(matches!(open(&t), Err(CoreError::Format(FormatError::Nonce))));
    }
    // truncado / sobrando / comprimento declarado alterado
    assert!(matches!(open(&env[..env.len() - 1]), Err(CoreError::Format(_))));
    let mut longer = env.clone();
    longer.push(0);
    assert!(matches!(open(&longer), Err(CoreError::Format(FormatError::TrailingBytes))));
    let mut t = env.clone();
    t[124] = t[124].wrapping_add(1);
    assert!(matches!(open(&t), Err(CoreError::Format(_))));
    assert!(matches!(open(&env[..10]), Err(CoreError::Format(FormatError::EnvelopeSize))));
    assert!(matches!(open(&[]), Err(CoreError::Format(FormatError::EnvelopeSize))));
}

#[test]
fn swap_wrapper_and_payload_between_vaults_and_revisions() {
    let a = seal(1, 1, EnvelopeKind::VaultSlot);
    let b = seal(2, 1, EnvelopeKind::VaultSlot); // outro cofre, mesma revisão, mesma senha
    let a2 = seal(1, 2, EnvelopeKind::VaultSlot); // mesmo cofre, revisão seguinte
    let parts = |e: &[u8]| (e[..HEADER_LEN].to_vec(), e[HEADER_LEN..HEADER_LEN + 48].to_vec(), e[HEADER_LEN + 48..].to_vec());
    let (ha, wa, ca) = parts(&a);
    let (hb, wb, cb) = parts(&b);
    let (ha2, wa2, ca2) = parts(&a2);
    let cat = |h: &[u8], w: &[u8], c: &[u8]| [h, w, c].concat();
    let mut executed = 0;
    for (name, forged) in [
        ("wrapper de B em A", cat(&ha, &wb, &ca)),
        ("payload de B em A", cat(&ha, &wa, &cb)),
        ("cabeçalho de B", cat(&hb, &wa, &ca)),
        ("wrapper da rev2 na rev1", cat(&ha, &wa2, &ca)),
        ("payload da rev2 na rev1", cat(&ha, &wa, &ca2)),
        ("cabeçalho rev2 com corpo rev1", cat(&ha2, &wa, &ca)),
    ] {
        if forged.len() != a.len() && forged.len() != b.len() && forged.len() != a2.len() {
            continue;
        }
        let r = open(&forged);
        assert!(matches!(r, Err(CoreError::Authentication) | Err(CoreError::Format(_))), "{name}: {r:?}");
        executed += 1;
    }
    assert_eq!(executed, 6, "todas as combinações devem ter o mesmo comprimento e ser testadas");
}

#[test]
fn kind_confusion_rejected_before_kdf() {
    let backup = seal(3, 1, EnvelopeKind::Backup);
    let vault = seal(3, 1, EnvelopeKind::VaultSlot);
    let t = std::time::Instant::now();
    assert!(matches!(open(&backup), Err(CoreError::Format(FormatError::Kind))));
    assert!(matches!(envelope::open(&pw(PW), &vault, EnvelopeKind::Backup), Err(CoreError::Format(FormatError::Kind))));
    assert!(t.elapsed().as_millis() < 50, "rejeição deveria ocorrer antes da KDF");
}

#[test]
fn hostile_kdf_params_rejected_without_derivation() {
    let env = seal(4, 1, EnvelopeKind::VaultSlot);
    let set_u32 = |e: &mut Vec<u8>, off: usize, v: u32| e[off..off + 4].copy_from_slice(&v.to_le_bytes());
    for (off, v) in [
        (40usize, 4 * 1024 * 1024u32),
        (40, 65_535),
        (40, u32::MAX),
        (44, 2),
        (44, 11),
        (44, u32::MAX),
        (48, 0),
        (48, 5),
        (36, 0x10),
        (52, 64),
    ] {
        let mut t = env.clone();
        set_u32(&mut t, off, v);
        let start = std::time::Instant::now();
        assert!(matches!(open(&t), Err(CoreError::Format(FormatError::KdfParams))), "off {off} v {v}");
        assert!(start.elapsed().as_millis() < 50);
    }
}

#[test]
fn payload_context_mismatch_detected_after_auth() {
    // Envelope válido cujo payload interno tem vault_id diferente do cabeçalho só pode ser produzido
    // por quem tem a chave; o parser ainda assim verifica (defesa em profundidade).
    use keyvault_core::payload;
    let snap = sample_snapshot([5; 16], 2, 1);
    let bytes = payload::encode(&snap).unwrap();
    assert!(matches!(payload::decode(&bytes, &[6; 16], 2), Err(CoreError::Format(FormatError::PayloadContext))));
    assert!(matches!(payload::decode(&bytes, &[5; 16], 3), Err(CoreError::Format(FormatError::PayloadContext))));
    assert!(payload::decode(&bytes, &[5; 16], 2).is_ok());
}
