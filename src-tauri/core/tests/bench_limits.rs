#![allow(clippy::unwrap_used)]
//! Benchmark no limite suportado: 10.000 entradas com payload próximo de 32 MiB. Mede salvar
//! (envelope novo + commit), desbloquear (KDF + autenticação + parsing) e pesquisar. Executar com:
//! `cargo test -p keyvault-core --test bench_limits -- --ignored --nocapture`
//! (perfil de teste: dependências criptográficas otimizadas, código do núcleo sem otimização).

mod common;
use common::*;

use std::time::Instant;

use keyvault_core::crypto::KdfParams;
use keyvault_core::model::{CustomField, Entry, Snapshot};
use keyvault_core::rng::OsRandom;
use keyvault_core::service::{self, OpenVault};

#[test]
#[ignore = "benchmark demorado"]
fn bench_10k_entries_near_32mib() {
    let dir = tempfile::tempdir().unwrap();
    let (kdf, kdf_ms) = service::calibrate_kdf(&mut service::measure_kdf).unwrap();
    println!("KDF calibrada: m={} KiB t={} p={} ({} ms)", kdf.m_cost_kib, kdf.t_cost, kdf.p_cost, kdf_ms.as_millis());
    let v = OpenVault::create(dir.path(), pw(PW), kdf, &OsRandom).unwrap();
    // Monta 10.000 entradas (~3,2 KB cada ≈ 32 MB de payload) diretamente e salva via restauração de
    // backup para medir o caminho completo com dados no limite.
    let mut snap = Snapshot::new_empty(v.vault_id());
    snap.revision = v.revision();
    for i in 0..10_000u32 {
        let mut id = [0u8; 16];
        id[..4].copy_from_slice(&(i + 1).to_le_bytes());
        id[15] = 1;
        snap.entries.push(Entry {
            id,
            created_at_ms: 1_700_000_000_000,
            updated_at_ms: 1_700_000_000_000,
            favorite: i % 10 == 0,
            title: format!("Serviço fictício {i}"),
            url: format!("https://servico{i}.exemplo.invalid"),
            username: format!("usuario{i}"),
            password: "S3nha-Fict1cia-".repeat(2),
            notes: "n".repeat(3_000),
            tags: vec!["infra".into(), format!("t{}", i % 50)],
            fields: vec![CustomField { id: [7; 16], secret: true, name: "token".into(), value: "v".repeat(64) }],
        });
    }
    let payload_len = keyvault_core::payload::encoded_len(&snap).unwrap();
    println!("payload: {} bytes ({:.1} MiB)", payload_len, payload_len as f64 / 1048576.0);
    assert!(payload_len <= 32 * 1024 * 1024);

    let t = Instant::now();
    let blob = keyvault_core::envelope::seal(
        &keyvault_core::envelope::SealRequest { password: &pw(PW), kdf, kind: keyvault_core::envelope::EnvelopeKind::Backup },
        &snap,
        &OsRandom,
    )
    .unwrap();
    println!("selar envelope (KDF+serialização+AES-GCM): {} ms", t.elapsed().as_millis());
    let t = Instant::now();
    let ins = service::inspect_backup(&blob, &pw(PW)).unwrap();
    println!("abrir envelope (KDF+autenticação+parsing): {} ms", t.elapsed().as_millis());
    let t = Instant::now();
    let restored = service::restore_as_new_vault(dir.path(), ins, pw(PW2), kdf, &OsRandom).unwrap();
    println!("restaurar como cofre novo (envelope novo + SQLite): {} ms", t.elapsed().as_millis());
    let path = restored.path();
    restored.close();
    v.close();

    let t = Instant::now();
    let mut v = OpenVault::unlock(&path, pw(PW2)).unwrap();
    println!("desbloquear 10.000 entradas: {} ms", t.elapsed().as_millis());
    let t = Instant::now();
    let hits = v.list("servico9999", false);
    println!("pesquisa em memória (10.000): {} ms, {} resultado(s)", t.elapsed().as_millis(), hits.len());
    assert_eq!(hits.len(), 1);
    let t = Instant::now();
    v.save_entry(input("mais uma"), &OsRandom, now()).unwrap_err(); // limite de 10.000 entradas
    println!("salvar acima do limite é rejeitado: {} ms", t.elapsed().as_millis());
    let id = v.list("", false)[0].id;
    let t = Instant::now();
    v.delete_entry(&id, &OsRandom).unwrap();
    println!("salvar (exclusão, envelope novo de ~32 MiB + commit): {} ms", t.elapsed().as_millis());
    let _ = KdfParams::INITIAL;
}
