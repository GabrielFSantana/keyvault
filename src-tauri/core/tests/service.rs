#![allow(clippy::unwrap_used)]
//! Fluxos do serviço: CRUD, pesquisa, segredos fora da listagem, troca de senha, backup/restauração.

mod common;
use common::*;

use keyvault_core::rng::OsRandom;
use keyvault_core::service::{self, EntryInput, FieldInput, OpenVault, SecretRef, SecretUpdate};
use keyvault_core::{CoreError, Field};

#[test]
fn crud_search_and_secret_separation() {
    let dir = tempfile::tempdir().unwrap();
    let mut v = new_vault(dir.path());
    let id = v.save_entry(input("GitHub pessoal"), &OsRandom, now()).unwrap();
    let mut i2 = input("Docker Hub");
    i2.favorite = true;
    i2.tags = vec![" containers ".into(), "containers".into(), "".into()];
    let id2 = v.save_entry(i2, &OsRandom, now()).unwrap();

    let list = v.list("", false);
    assert_eq!(list.iter().map(|e| e.title.as_str()).collect::<Vec<_>>(), ["Docker Hub", "GitHub pessoal"]);
    assert_eq!(v.list("", true).len(), 1);
    assert_eq!(v.list("github", false).len(), 1);
    assert_eq!(v.list("CONTAINERS", false).len(), 1);
    assert_eq!(v.list("notas ficticias", false).len(), 2);
    assert_eq!(v.list("exemplo.invalid/login", false).len(), 2);
    assert_eq!(v.list("usuario.ficticio", false).len(), 2);
    // Pesquisa nunca inclui senhas nem valores secretos.
    assert_eq!(v.list("S3nha-Fict1cia", false).len(), 0);
    assert_eq!(v.list("api-ficticia", false).len(), 0);

    let d = v.detail(&id2).unwrap();
    assert_eq!(d.tags, vec!["containers".to_string()]);
    assert!(d.has_password);
    assert!(d.fields[0].secret && d.fields[0].value.is_none() && d.fields[0].has_value);
    assert_eq!(v.secret(&id2, SecretRef::Password).unwrap().as_str(), "S3nha-Fict1cia!");
    assert_eq!(v.secret(&id2, SecretRef::Field(d.fields[0].id)).unwrap().as_str(), "api-ficticia");

    let edit = EntryInput {
        id: Some(id2),
        title: "Docker Hub (org)".into(),
        url: d.url.clone(),
        username: d.username.clone(),
        password: SecretUpdate::Keep,
        notes: d.notes.clone(),
        tags: d.tags.clone(),
        favorite: false,
        fields: vec![FieldInput { id: Some(d.fields[0].id), name: "API".into(), secret: true, value: SecretUpdate::Keep }],
    };
    v.save_entry(edit, &OsRandom, now() + 1000).unwrap();
    let d2 = v.detail(&id2).unwrap();
    assert_eq!(d2.title, "Docker Hub (org)");
    assert_eq!(d2.created_at_ms, d.created_at_ms);
    assert_eq!(d2.updated_at_ms, now() + 1000);
    assert_eq!(v.secret(&id2, SecretRef::Password).unwrap().as_str(), "S3nha-Fict1cia!");
    assert_eq!(v.secret(&id2, SecretRef::Field(d.fields[0].id)).unwrap().as_str(), "api-ficticia");

    let bad = input("   ");
    assert!(matches!(v.save_entry(bad, &OsRandom, now()), Err(CoreError::Validation(Field::Title))));
    let mut bad = input("x");
    bad.id = Some([0xEE; 16]);
    assert!(matches!(v.save_entry(bad, &OsRandom, now()), Err(CoreError::NotFound)));
    let mut bad = input("x");
    bad.notes = "n".repeat(1024 * 1024 + 1);
    assert!(matches!(v.save_entry(bad, &OsRandom, now()), Err(CoreError::Validation(Field::Notes))));
    let mut bad = input("x");
    bad.tags = (0..101).map(|i| format!("t{i}")).collect();
    assert!(matches!(v.save_entry(bad, &OsRandom, now()), Err(CoreError::Validation(Field::Tags))));
    let mut bad = input("x");
    bad.fields = vec![FieldInput { id: None, name: "novo".into(), secret: true, value: SecretUpdate::Keep }];
    assert!(matches!(v.save_entry(bad, &OsRandom, now()), Err(CoreError::Validation(Field::CustomFieldValue))));

    v.delete_entry(&id, &OsRandom).unwrap();
    assert!(matches!(v.detail(&id), Err(CoreError::NotFound)));
    assert!(matches!(v.delete_entry(&id, &OsRandom), Err(CoreError::NotFound)));

    let rev = v.revision();
    let path = v.path();
    v.close();
    let v = OpenVault::unlock(&path, pw(PW)).unwrap();
    assert_eq!(v.revision(), rev);
    assert_eq!(v.entry_count(), 1);
    assert_eq!(v.secret(&id2, SecretRef::Password).unwrap().as_str(), "S3nha-Fict1cia!");
}

#[test]
fn change_password_requires_current_and_old_backups_keep_old_password() {
    let dir = tempfile::tempdir().unwrap();
    let mut v = new_vault(dir.path());
    v.save_entry(input("A"), &OsRandom, now()).unwrap();
    let old_backup = v.export_backup(&OsRandom).unwrap();
    assert!(matches!(v.change_password(&pw("senha atual errada 000"), pw(PW2), &OsRandom), Err(CoreError::Authentication)));
    v.change_password(&pw(PW), pw(PW2), &OsRandom).unwrap();
    let path = v.path();
    v.close();
    assert!(matches!(OpenVault::unlock(&path, pw(PW)), Err(CoreError::Authentication)));
    let v = OpenVault::unlock(&path, pw(PW2)).unwrap();
    // Backup antigo continua abrindo SOMENTE com a senha antiga (não há revogação).
    assert!(matches!(service::inspect_backup(&old_backup, &pw(PW2)), Err(CoreError::Authentication)));
    assert_eq!(service::inspect_backup(&old_backup, &pw(PW)).unwrap().entry_count(), 1);
    v.close();
}

#[test]
fn backup_restore_creates_independent_vault() {
    let dir = tempfile::tempdir().unwrap();
    let mut v = new_vault(dir.path());
    let id = v.save_entry(input("Original"), &OsRandom, now()).unwrap();
    let blob = v.export_backup(&OsRandom).unwrap();
    let original_path = v.path();
    v.close();
    let original_bytes_before = std::fs::read(&original_path).unwrap();
    let v = OpenVault::unlock(&original_path, pw(PW)).unwrap();

    assert!(service::precheck_backup(&blob).is_ok());
    for off in [0usize, 50, 140, 200, blob.len() - 1] {
        let mut t = blob.clone();
        t[off] ^= 0x10;
        assert!(service::precheck_backup(&t).is_err() || service::inspect_backup(&t, &pw(PW)).is_err(), "off {off}");
    }
    assert!(matches!(service::inspect_backup(&blob, &pw(PW2)), Err(CoreError::Authentication)));
    let ins = service::inspect_backup(&blob, &pw(PW)).unwrap();
    assert_eq!(ins.entry_count(), 1);
    let new_pw = "senha do cofre restaurado 2026";
    let restored = service::restore_as_new_vault(dir.path(), ins, pw(new_pw), kdf(), &OsRandom).unwrap();
    assert_ne!(restored.vault_id(), v.vault_id());
    assert_eq!(restored.revision(), 1);
    assert_eq!(restored.secret(&id, SecretRef::Password).unwrap().as_str(), "S3nha-Fict1cia!");
    let rpath = restored.path();
    restored.close();
    v.close();
    assert_eq!(std::fs::read(&original_path).unwrap(), original_bytes_before, "cofre original modificado");
    assert!(OpenVault::unlock(&original_path, pw(PW)).is_ok());
    assert!(matches!(OpenVault::unlock(&rpath, pw(PW)), Err(CoreError::Authentication)));
    assert!(OpenVault::unlock(&rpath, pw(new_pw)).is_ok());
    // Envelope do banco não é aceito como backup (contexto autenticado no cabeçalho).
    let conn = rusqlite::Connection::open(&original_path).unwrap();
    let slot: Vec<u8> = conn.query_row("SELECT envelope FROM vault_state WHERE slot=1", [], |r| r.get(0)).unwrap();
    assert!(service::precheck_backup(&slot).is_err());
}

#[test]
fn calibration_never_goes_below_floor() {
    let (p, _) = service::calibrate_kdf(&mut |_| Ok(std::time::Duration::from_millis(100))).unwrap();
    assert!(p.m_cost_kib >= 65_536 && p.t_cost >= 3 && p.p_cost == 4);
    assert!(p.m_cost_kib <= 262_144 && p.t_cost <= 10);
    let (p2, _) = service::calibrate_kdf(&mut |_| Ok(std::time::Duration::from_millis(5000))).unwrap();
    assert_eq!(p2, keyvault_core::crypto::KdfParams::INITIAL);
    let (real, t) = service::calibrate_kdf(&mut service::measure_kdf).unwrap();
    println!("calibracao: m={} KiB t={} p={} -> {} ms", real.m_cost_kib, real.t_cost, real.p_cost, t.as_millis());
}
