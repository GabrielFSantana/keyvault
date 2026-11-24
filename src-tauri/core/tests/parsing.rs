#![allow(clippy::unwrap_used)]
//! Parser hostil: fuzzing por propriedades (proptest) e por mutação determinística do cabeçalho e do
//! payload. Exige: nenhum pânico, nenhuma alocação desproporcional, nenhuma liberação parcial.

mod common;
use common::*;

use keyvault_core::envelope::{EnvelopeKind, HEADER_LEN, Header, SealRequest};
use keyvault_core::payload;
use keyvault_core::rng::{OsRandom, SecureRandom};
use keyvault_core::{CoreError, FormatError, envelope};
use proptest::prelude::*;

fn valid_payload() -> Vec<u8> {
    payload::encode(&sample_snapshot([9; 16], 4, 3)).unwrap().to_vec()
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 20_000, ..ProptestConfig::default() })]

    #[test]
    fn header_parse_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..400)) {
        let _ = Header::parse(&bytes, EnvelopeKind::VaultSlot);
        let _ = Header::parse(&bytes, EnvelopeKind::Backup);
    }

    #[test]
    fn payload_decode_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let _ = payload::decode(&bytes, &[9; 16], 4);
    }

    #[test]
    fn payload_mutations_never_panic(pos in 0usize..10_000, val in any::<u8>(), cut in 0usize..10_000) {
        let mut p = valid_payload();
        let i = pos % p.len();
        p[i] = val;
        let _ = payload::decode(&p, &[9; 16], 4);
        let c = cut % p.len();
        let _ = payload::decode(&p[..c], &[9; 16], 4);
    }
}

#[test]
fn deterministic_mutation_fuzz_payload() {
    // 200.000 mutações (flips, sobrescritas de u32 de comprimento, truncamentos e inserções).
    let base = valid_payload();
    let mut ok_unchanged = 0;
    for round in 0..200_000u32 {
        let mut p = base.clone();
        let mut r = [0u8; 8];
        OsRandom.fill(&mut r).unwrap();
        let pos = u32::from_le_bytes([r[0], r[1], r[2], r[3]]) as usize % p.len();
        match round % 4 {
            0 => p[pos] ^= 1 << (r[4] % 8),
            1 => {
                let end = (pos + 4).min(p.len());
                let v = u32::from_le_bytes([r[4], r[5], r[6], r[7]]).to_le_bytes();
                p[pos..end].copy_from_slice(&v[..end - pos]);
            }
            2 => p.truncate(pos),
            _ => p.insert(pos, r[4]),
        }
        if let Ok(s) = payload::decode(&p, &[9; 16], 4) {
            // Uma mutação aceita precisa produzir um snapshot totalmente válido e re-serializável.
            s.validate().unwrap();
            let re = payload::encode(&s).unwrap();
            assert_eq!(&re[..], &p[..], "serialização não canônica aceita");
            ok_unchanged += 1;
        }
    }
    println!("mutações aceitas (válidas e canônicas): {ok_unchanged}");
}

#[test]
fn huge_counts_rejected_without_allocation() {
    let mut p = valid_payload();
    // entry_count no offset 34: 10.000 com buffer pequeno → Truncated (não reserva 10.000 entradas).
    p[34..38].copy_from_slice(&10_000u32.to_le_bytes());
    assert!(matches!(payload::decode(&p, &[9; 16], 4), Err(CoreError::Format(FormatError::Truncated))));
    p[34..38].copy_from_slice(&10_001u32.to_le_bytes());
    assert!(matches!(payload::decode(&p, &[9; 16], 4), Err(CoreError::Format(FormatError::Count))));
    p[34..38].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(payload::decode(&p, &[9; 16], 4), Err(CoreError::Format(FormatError::Count))));
    // Comprimento de string gigante.
    let mut q = valid_payload();
    // primeira entrada começa em 38; título em 38+33 = 71.
    q[71..75].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(payload::decode(&q, &[9; 16], 4), Err(CoreError::Format(FormatError::FieldTooLong))));
    q[71..75].copy_from_slice(&(1024 * 1024u32).to_le_bytes());
    assert!(matches!(payload::decode(&q, &[9; 16], 4), Err(CoreError::Format(FormatError::Truncated))));
}

#[test]
fn invalid_utf8_bool_reserved_and_trailing() {
    let base = valid_payload();
    let mut p = base.clone();
    p[75] = 0xff; // primeiro byte do título
    assert!(matches!(payload::decode(&p, &[9; 16], 4), Err(CoreError::Format(FormatError::Utf8))));
    let mut p = base.clone();
    p[32] = 2; // lock_on_blur
    assert!(matches!(payload::decode(&p, &[9; 16], 4), Err(CoreError::Format(FormatError::Bool))));
    let mut p = base.clone();
    p[33] = 1; // reservado
    assert!(matches!(payload::decode(&p, &[9; 16], 4), Err(CoreError::Format(FormatError::Reserved))));
    let mut p = base.clone();
    p.push(0);
    assert!(matches!(payload::decode(&p, &[9; 16], 4), Err(CoreError::Format(FormatError::TrailingBytes))));
    let mut p = base.clone();
    p[28..30].copy_from_slice(&31u16.to_le_bytes()); // auto_lock 31 min
    assert!(matches!(payload::decode(&p, &[9; 16], 4), Err(CoreError::Format(FormatError::Settings))));
}

#[test]
fn duplicate_ids_rejected() {
    let mut s = sample_snapshot([9; 16], 4, 2);
    s.entries[1].id = s.entries[0].id;
    assert!(payload::encode(&s).is_err());
    // Forjar duplicata diretamente nos bytes: copia o id da 1ª entrada para a 2ª.
    let ok = sample_snapshot([9; 16], 4, 2);
    let mut p = payload::encode(&ok).unwrap().to_vec();
    let first = 38;
    let second = p.windows(16).position(|w| w == [2u8; 16]).unwrap();
    let id1: Vec<u8> = p[first..first + 16].to_vec();
    p[second..second + 16].copy_from_slice(&id1);
    assert!(matches!(payload::decode(&p, &[9; 16], 4), Err(CoreError::Format(FormatError::Identifier))));
}

#[test]
fn oversized_payload_and_envelope_limits() {
    // Payload > 32 MiB é rejeitado antes de cifrar.
    let mut s = sample_snapshot([9; 16], 1, 0);
    for i in 0..40u32 {
        let mut e = sample_entry(1, "grande");
        e.id = [0; 16];
        e.id[..4].copy_from_slice(&(i + 1).to_le_bytes());
        e.fields.clear();
        e.notes = "x".repeat(1024 * 1024);
        s.entries.push(e);
    }
    let p = pw(PW);
    let r = envelope::seal(&SealRequest { password: &p, kdf: kdf(), kind: EnvelopeKind::VaultSlot }, &s, &OsRandom);
    assert!(matches!(r, Err(CoreError::Format(FormatError::PayloadTooLarge))));
    // Envelope > 64 MiB é rejeitado pelo tamanho, sem parsing.
    let big = vec![0u8; 64 * 1024 * 1024 + 1];
    assert!(matches!(Header::parse(&big, EnvelopeKind::VaultSlot), Err(CoreError::Format(FormatError::EnvelopeSize))));
    // data_ciphertext_len acima do limite do payload.
    let env = envelope::seal(
        &SealRequest { password: &p, kdf: kdf(), kind: EnvelopeKind::VaultSlot },
        &sample_snapshot([9; 16], 1, 1),
        &OsRandom,
    )
    .unwrap();
    let mut t = env.clone();
    t[124..132].copy_from_slice(&(32u64 * 1024 * 1024 + 17).to_le_bytes());
    assert!(matches!(Header::parse(&t, EnvelopeKind::VaultSlot), Err(CoreError::Format(FormatError::CiphertextLen))));
    t[124..132].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(matches!(Header::parse(&t, EnvelopeKind::VaultSlot), Err(CoreError::Format(FormatError::CiphertextLen))));
    assert_eq!(HEADER_LEN, 132);
}

#[test]
fn full_envelope_mutation_sample_fails_closed() {
    // Amostra de mutações no envelope completo (cada uma pode exigir KDF real): nunca sucesso.
    let p = pw(PW);
    let env = envelope::seal(
        &SealRequest { password: &p, kdf: kdf(), kind: EnvelopeKind::VaultSlot },
        &sample_snapshot([9; 16], 1, 2),
        &OsRandom,
    )
    .unwrap();
    std::thread::scope(|s| {
        for t in 0..8 {
            let env = env.clone();
            s.spawn(move || {
                let p = pw(PW);
                for k in 0..6 {
                    let mut m = env.clone();
                    let mut r = [0u8; 4];
                    OsRandom.fill(&mut r).unwrap();
                    let pos = (u32::from_le_bytes(r) as usize + t * 31 + k) % m.len();
                    m[pos] ^= 0x04;
                    let res = envelope::open(&p, &m, EnvelopeKind::VaultSlot);
                    assert!(res.is_err(), "mutação no offset {pos} aceita");
                }
            });
        }
    });
}
