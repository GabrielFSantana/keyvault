#![allow(clippy::unwrap_used)]
//! Persistência: falhas antes/depois do commit, escritas concorrentes (revisão esperada), segundo
//! processo (trava), morte do processo durante gravações (TerminateProcess), disco cheio
//! (SQLITE_FULL via max_page_count) e permissão negada (DACL real), escrita atômica de backup.

mod common;
use common::*;

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

use keyvault_core::CoreError;
use keyvault_core::envelope::{self, EnvelopeKind, SealRequest};
use keyvault_core::fsutil::{self, testing::FsFault};
use keyvault_core::rng::OsRandom;
use keyvault_core::service::OpenVault;
use keyvault_core::storage::{self, VaultStore};

/// Lê a saída do filho até encontrar `marker` (o libtest imprime linhas antes).
fn wait_for(out: &mut impl BufRead, marker: &str) -> bool {
    let mut line = String::new();
    loop {
        line.clear();
        if out.read_line(&mut line).unwrap() == 0 {
            return false;
        }
        if line.contains(marker) {
            return true;
        }
    }
}

fn child(test: &str, envs: &[(&str, String)]) -> Command {
    let mut c = Command::new(std::env::current_exe().unwrap());
    c.args(["--exact", test, "--ignored", "--nocapture", "--test-threads=1"]);
    for (k, v) in envs {
        c.env(k, v);
    }
    c.stdout(Stdio::piped()).stdin(Stdio::piped()).stderr(Stdio::null());
    c
}

/// Processo-filho: abre o cofre, anuncia "LOCKED" e mantém a trava até o stdin fechar.
#[test]
#[ignore = "executado como processo-filho"]
fn child_hold_vault() {
    let path = std::env::var("KV_DB").unwrap();
    let v = OpenVault::unlock(std::path::Path::new(&path), pw(PW)).unwrap();
    println!("LOCKED");
    let mut s = String::new();
    let _ = std::io::stdin().read_line(&mut s);
    drop(v);
}

/// Processo-filho: grava continuamente entradas numeradas até ser morto.
#[test]
#[ignore = "executado como processo-filho"]
fn child_write_forever() {
    let path = std::env::var("KV_DB").unwrap();
    let mut v = OpenVault::unlock(std::path::Path::new(&path), pw(PW)).unwrap();
    println!("READY");
    loop {
        let n = v.entry_count();
        v.save_entry(input(&format!("item {n}")), &OsRandom, now()).unwrap();
    }
}

#[test]
fn second_process_is_blocked_while_vault_open() {
    let dir = tempfile::tempdir().unwrap();
    let v = new_vault(dir.path());
    let path = v.path();
    v.close();
    let mut ch = child("child_hold_vault", &[("KV_DB", path.display().to_string())]).spawn().unwrap();
    let mut out = BufReader::new(ch.stdout.take().unwrap());
    assert!(wait_for(&mut out, "LOCKED"), "filho não abriu o cofre");
    // Este processo não consegue abrir o mesmo cofre (nem por caminho alternativo com "./").
    assert!(matches!(OpenVault::unlock(&path, pw(PW)), Err(CoreError::VaultBusy)));
    let alt = path.parent().unwrap().join(".").join(path.file_name().unwrap());
    assert!(matches!(VaultStore::open(&alt), Err(CoreError::VaultBusy)));
    drop(ch.stdin.take());
    ch.wait().unwrap();
    assert!(OpenVault::unlock(&path, pw(PW)).is_ok());
}

#[test]
fn kill_during_writes_always_recovers_complete_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let v = new_vault(dir.path());
    let path = v.path();
    v.close();
    let mut last_rev = 1;
    for round in 0..8u64 {
        let mut ch = child("child_write_forever", &[("KV_DB", path.display().to_string())]).spawn().unwrap();
        let mut out = BufReader::new(ch.stdout.take().unwrap());
        assert!(wait_for(&mut out, "READY"));
        // Mata em instantes variados (KDF ~0,2–1 s por gravação).
        std::thread::sleep(std::time::Duration::from_millis(250 + round * 170));
        ch.kill().unwrap(); // TerminateProcess
        ch.wait().unwrap();
        let v = OpenVault::unlock(&path, pw(PW)).unwrap();
        let rev = v.revision();
        assert!(rev >= last_rev, "revisão regrediu");
        // Snapshot completo e coerente: N entradas = revisão - 1, títulos "item 0..N-1".
        assert_eq!(v.entry_count() as u64, rev - 1);
        let titles: Vec<String> = v.list("", false).into_iter().map(|e| e.title).collect();
        for i in 0..v.entry_count() {
            assert!(titles.contains(&format!("item {i}")));
        }
        last_rev = rev;
        v.close();
    }
    assert!(last_rev > 1, "nenhuma gravação concluída durante o teste");
    println!("revisão final após 8 mortes: {last_rev}");
}

#[test]
fn concurrent_writers_rejected_by_expected_revision() {
    let dir = tempfile::tempdir().unwrap();
    let mut v = new_vault(dir.path());
    let p = pw(PW);
    // Um envelope "concorrente" para a mesma revisão esperada.
    let mut snap = keyvault_core::model::Snapshot::new_empty(v.vault_id());
    snap.revision = v.revision() + 1;
    let env = envelope::seal(&SealRequest { password: &p, kdf: kdf(), kind: EnvelopeKind::VaultSlot }, &snap, &OsRandom).unwrap();
    v.save_entry(input("vence"), &OsRandom, now()).unwrap();
    // O commit concorrente com revisão esperada antiga é rejeitado.
    assert!(matches!(v.store_for_tests().commit(1, &env), Err(CoreError::RevisionConflict)));
    // Revisão nova inconsistente com a esperada também.
    assert!(matches!(v.store_for_tests().commit(2, &env), Err(CoreError::RevisionConflict)));
    assert_eq!(v.entry_count(), 1);
    // Duas threads disputando o mesmo cofre via mutex (modelo da aplicação): serializa sem perda.
    let shared = std::sync::Mutex::new(v);
    std::thread::scope(|s| {
        for t in 0..4 {
            let shared = &shared;
            s.spawn(move || {
                for k in 0..2 {
                    shared.lock().unwrap().save_entry(input(&format!("t{t}-{k}")), &OsRandom, now()).unwrap();
                }
            });
        }
    });
    let v = shared.into_inner().unwrap();
    assert_eq!(v.entry_count(), 9);
    assert_eq!(v.revision(), 10);
}

#[test]
fn disk_full_preserves_previous_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let mut v = new_vault(dir.path());
    v.save_entry(input("antes"), &OsRandom, now()).unwrap();
    let rev = v.revision();
    let pages: i64 = v.store_for_tests().connection_for_tests().query_row("PRAGMA page_count", [], |r| r.get(0)).unwrap();
    v.store_for_tests().connection_for_tests().query_row(&format!("PRAGMA max_page_count = {pages}"), [], |_| Ok(())).unwrap();
    let mut big = input("grande");
    big.notes = "z".repeat(900_000);
    let r = v.save_entry(big, &OsRandom, now());
    assert!(matches!(r, Err(CoreError::StorageFull)), "{r:?}");
    assert_eq!(v.revision(), rev);
    v.store_for_tests().connection_for_tests().query_row("PRAGMA max_page_count = 1073741823", [], |_| Ok(())).unwrap();
    let path = v.path();
    v.close();
    let v = OpenVault::unlock(&path, pw(PW)).unwrap();
    assert_eq!(v.revision(), rev);
    assert_eq!(v.entry_count(), 1);
}

#[cfg(windows)]
#[test]
fn permission_denied_is_reported_and_data_preserved() {
    let dir = tempfile::tempdir().unwrap();
    let v = new_vault(dir.path());
    let path = v.path();
    v.close();
    fsutil::testing::deny_all(&path).unwrap();
    let r = OpenVault::unlock(&path, pw(PW));
    assert!(matches!(r, Err(CoreError::PermissionDenied)), "{r:?}");
    // O dono ainda pode restaurar a ACL (direito implícito WRITE_DAC) e o cofre está intacto.
    fsutil::restrict_to_current_user(&path).unwrap();
    assert!(OpenVault::unlock(&path, pw(PW)).is_ok());
    // Diretório de destino de backup sem permissão.
    let denied = dir.path().join("negado");
    std::fs::create_dir(&denied).unwrap();
    fsutil::testing::deny_all(&denied).unwrap();
    let r = fsutil::write_file_atomically(&denied.join("b.keyvault"), b"x", false, false, &OsRandom);
    assert!(matches!(r, Err(CoreError::PermissionDenied)), "{r:?}");
    fsutil::restrict_to_current_user(&denied).unwrap();
}

#[test]
fn atomic_backup_write_failures_preserve_destination() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("cofre.keyvault");
    std::fs::write(&dest, b"backup anterior").unwrap();
    for fault in [FsFault::Write, FsFault::Publish] {
        fsutil::testing::set(Some(fault));
        let r = fsutil::write_file_atomically(&dest, b"novo", true, true, &OsRandom);
        assert!(matches!(r, Err(CoreError::InjectedFault)));
        assert_eq!(std::fs::read(&dest).unwrap(), b"backup anterior");
        let leftovers: Vec<_> =
            std::fs::read_dir(dir.path()).unwrap().flatten().filter(|e| e.file_name().to_string_lossy().ends_with(".tmp")).collect();
        assert!(leftovers.is_empty(), "temporário não removido");
    }
    // Destino existente sem confirmação: não sobrescreve.
    assert!(matches!(fsutil::write_file_atomically(&dest, b"novo", false, true, &OsRandom), Err(CoreError::AlreadyExists)));
    // Com confirmação: substitui atomicamente.
    fsutil::write_file_atomically(&dest, b"novo", true, true, &OsRandom).unwrap();
    assert_eq!(std::fs::read(&dest).unwrap(), b"novo");
}

#[test]
fn schema_tampering_and_partial_creations() {
    let dir = tempfile::tempdir().unwrap();
    let v = new_vault(dir.path());
    let path = v.path();
    v.close();
    // Tabela extra → schema rejeitado (não confiamos em bancos alterados).
    {
        let c = rusqlite::Connection::open(&path).unwrap();
        c.execute_batch("CREATE TABLE extra(x)").unwrap();
    }
    assert!(matches!(OpenVault::unlock(&path, pw(PW)), Err(CoreError::Schema)));
    // Restos ".partial" de criações interrompidas são ignorados/removidos na listagem.
    std::fs::write(dir.path().join("00112233445566778899aabbccddeeff.kvdb.partial"), b"lixo").unwrap();
    let list = storage::list_vaults(dir.path()).unwrap();
    assert_eq!(list.len(), 1);
    assert!(!dir.path().join("00112233445566778899aabbccddeeff.kvdb.partial").exists());
}
