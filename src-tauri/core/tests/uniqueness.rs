#![allow(clippy::unwrap_used)]
//! Unicidade de chave/nonce com instrumentação de teste (dados fictícios): salvar, retry após falha,
//! falha antes/depois do commit, backup, restauração, troca de senha e migração geram chaves novas;
//! RNG com falha aborta sem gravar.

mod common;
use common::*;

use std::collections::HashSet;

use keyvault_core::CoreError;
use keyvault_core::crypto::KdfParams;
use keyvault_core::crypto::instrument::{self, Purpose};
use keyvault_core::rng::OsRandom;
use keyvault_core::rng::testing::{FailAfter, FailingRandom};
use keyvault_core::service::{self, OpenVault};
use keyvault_core::storage::testing::{DbFault, set as set_db_fault};

fn assert_all_unique(uses: &[instrument::Use]) {
    let mut keys = HashSet::new();
    for u in uses {
        assert_eq!(u.nonce, [0u8; 12]);
        assert!(keys.insert(u.key_fingerprint), "chave reutilizada em {:?}", u.purpose);
    }
}

#[test]
fn every_operation_uses_fresh_keys() {
    let dir = tempfile::tempdir().unwrap();
    instrument::take();
    let mut v = new_vault(dir.path()); // criação
    let id = v.save_entry(input("A"), &OsRandom, now()).unwrap();
    v.save_entry(input("B"), &OsRandom, now()).unwrap();

    // Retry após falha antes do commit (rollback): duas tentativas → dois pares de chaves novos.
    set_db_fault(Some(DbFault::BeforeCommit));
    assert!(matches!(v.save_entry(input("C"), &OsRandom, now()), Err(CoreError::InjectedFault)));
    assert_eq!(v.entry_count(), 2, "estado visível não muda sem commit");
    v.save_entry(input("C"), &OsRandom, now()).unwrap();

    // Falha reportada após COMMIT durável: o serviço reconhece o próprio envelope persistido.
    set_db_fault(Some(DbFault::AfterCommit));
    v.save_entry(input("D"), &OsRandom, now()).unwrap();
    assert_eq!(v.entry_count(), 4);

    let backup1 = v.export_backup(&OsRandom).unwrap();
    let _backup2 = v.export_backup(&OsRandom).unwrap();
    v.delete_entry(&id, &OsRandom).unwrap();
    v.change_password(&pw(PW), pw(PW2), &OsRandom).unwrap();
    v.migrate_kdf(KdfParams { m_cost_kib: 65_536, t_cost: 4, p_cost: 4 }, &OsRandom).unwrap();
    v.update_settings(keyvault_core::model::Settings { auto_lock_minutes: 10, clipboard_seconds: 30, lock_on_blur: false }, &OsRandom)
        .unwrap();

    // Restauração do backup em cofre novo.
    let inspected = service::inspect_backup(&backup1, &pw(PW)).unwrap();
    let restored = service::restore_as_new_vault(dir.path(), inspected, pw("senha nova do restaurado 789"), kdf(), &OsRandom).unwrap();

    let uses = instrument::take();
    // criação + A + B + C(falha) + C + D + 2 backups + exclusão + troca + migração + preferências +
    // restauração = 13 envelopes → 13 cifragens de snapshot e 13 wrappings.
    let snaps = uses.iter().filter(|u| u.purpose == Purpose::Snapshot).count();
    let wraps = uses.iter().filter(|u| u.purpose == Purpose::Wrap).count();
    assert_eq!((snaps, wraps), (13, 13));
    assert_all_unique(&uses);
    drop(restored);
    v.close();
}

#[test]
fn reopen_after_unlock_never_reuses_recovered_keys() {
    let dir = tempfile::tempdir().unwrap();
    let mut v = new_vault(dir.path());
    v.save_entry(input("A"), &OsRandom, now()).unwrap();
    let path = v.path();
    v.close();
    instrument::take();
    let mut v = OpenVault::unlock(&path, pw(PW)).unwrap();
    assert!(instrument::take().is_empty(), "abrir não pode cifrar");
    v.save_entry(input("B"), &OsRandom, now()).unwrap();
    let uses = instrument::take();
    assert_eq!(uses.len(), 2);
    assert_all_unique(&uses);
}

#[test]
fn rng_failure_aborts_without_writing() {
    let dir = tempfile::tempdir().unwrap();
    assert!(matches!(OpenVault::create(dir.path(), pw(PW), kdf(), &FailingRandom), Err(CoreError::Rng)));
    assert!(keyvault_core::storage::list_vaults(dir.path()).unwrap().is_empty());

    let mut v = new_vault(dir.path());
    v.save_entry(input("A"), &OsRandom, now()).unwrap();
    let rev = v.revision();
    let path = v.path();
    // Falha no 1º, 2º, 3º e 4º pedido ao RNG (ids, DEK, salt).
    for n in 0..4 {
        let r = v.save_entry(input("B"), &FailAfter::new(n), now());
        assert!(matches!(r, Err(CoreError::Rng)), "n={n}: {r:?}");
        assert_eq!(v.revision(), rev);
    }
    assert!(matches!(v.export_backup(&FailingRandom), Err(CoreError::Rng)));
    assert!(matches!(v.change_password(&pw(PW), pw(PW2), &FailingRandom), Err(CoreError::Rng)));
    v.close();
    let v = OpenVault::unlock(&path, pw(PW)).unwrap();
    assert_eq!(v.revision(), rev);
    assert_eq!(v.entry_count(), 1);
}
