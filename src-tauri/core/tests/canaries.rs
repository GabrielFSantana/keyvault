#![allow(clippy::unwrap_used)]
//! Confidencialidade: canários distintos em TODOS os campos de negócio; busca em UTF-8 e UTF-16LE (e
//! bytes crus de ids/datas) no SQLite, WAL, SHM, backup e temporários do diretório após CRUD, backup,
//! troca de senha e migração. Ausência de canário é evidência adicional, não prova criptográfica.

mod common;
use common::*;

use std::path::Path;

use keyvault_core::crypto::KdfParams;
use keyvault_core::fsutil;
use keyvault_core::rng::OsRandom;
use keyvault_core::service::{self, EntryInput, FieldInput, SecretUpdate};
use zeroize::Zeroizing;

const CANARIES: &[&str] = &[
    "CANARIO-TITULO-7f3a",
    "CANARIO-URL-91bc",
    "CANARIO-USUARIO-44de",
    "CANARIO-SENHA-0a1b",
    "CANARIO-NOTAS-5c6d",
    "CANARIO-TAG-e8f9",
    "CANARIO-CAMPO-NOME-1234",
    "CANARIO-CAMPO-VALOR-5678",
    "CANARIO-CAMPO-SECRETO-9abc",
];

fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

fn scan_dir(dir: &Path, needles: &[Vec<u8>]) -> Vec<String> {
    let mut hits = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            let Ok(bytes) = std::fs::read(&p) else { continue };
            for n in needles {
                if bytes.windows(n.len()).any(|w| w == n.as_slice()) {
                    hits.push(format!("{} contém {:?}", p.display(), String::from_utf8_lossy(n)));
                }
            }
        }
    }
    hits
}

#[test]
fn no_canary_in_any_persisted_file() {
    let dir = tempfile::tempdir().unwrap();
    let vaults = dir.path().join("vaults");
    let backups = dir.path().join("backups");
    std::fs::create_dir_all(&backups).unwrap();
    let mut v = service::OpenVault::create(&vaults, pw(PW), kdf(), &OsRandom).unwrap();
    let id = v
        .save_entry(
            EntryInput {
                id: None,
                title: CANARIES[0].into(),
                url: CANARIES[1].into(),
                username: CANARIES[2].into(),
                password: SecretUpdate::Set(Zeroizing::new(CANARIES[3].into())),
                notes: CANARIES[4].into(),
                tags: vec![CANARIES[5].into()],
                favorite: true,
                fields: vec![
                    FieldInput {
                        id: None,
                        name: CANARIES[6].into(),
                        secret: false,
                        value: SecretUpdate::Set(Zeroizing::new(CANARIES[7].into())),
                    },
                    FieldInput {
                        id: None,
                        name: "segredo".into(),
                        secret: true,
                        value: SecretUpdate::Set(Zeroizing::new(CANARIES[8].into())),
                    },
                ],
            },
            &OsRandom,
            1_234_567_890_123,
        )
        .unwrap();
    // CRUD adicional, backup, troca de senha e migração.
    for i in 0..5 {
        v.save_entry(input(&format!("{}-{i}", CANARIES[0])), &OsRandom, now()).unwrap();
    }
    let detail = v.detail(&id).unwrap();
    let field_ids: Vec<[u8; 16]> = detail.fields.iter().map(|f| f.id).collect();
    let backup = v.export_backup(&OsRandom).unwrap();
    fsutil::write_file_atomically(&backups.join("teste.keyvault"), &backup, false, true, &OsRandom).unwrap();
    v.change_password(&pw(PW), pw(PW2), &OsRandom).unwrap();
    v.migrate_kdf(KdfParams { m_cost_kib: 65_536, t_cost: 4, p_cost: 4 }, &OsRandom).unwrap();

    let mut needles: Vec<Vec<u8>> = Vec::new();
    for c in CANARIES {
        needles.push(c.as_bytes().to_vec());
        needles.push(utf16le(c));
    }
    needles.push(id.to_vec()); // id da entrada (bytes crus)
    needles.push(fsutil::hex_lower(&id).into_bytes());
    for f in &field_ids {
        needles.push(f.to_vec());
    }
    needles.push(1_234_567_890_123i64.to_le_bytes().to_vec()); // data de criação
    needles.push(PW.as_bytes().to_vec());
    needles.push(PW2.as_bytes().to_vec());
    needles.push(utf16le(PW2));

    // Com o cofre aberto (WAL/SHM presentes) ...
    let hits = scan_dir(dir.path(), &needles);
    assert!(hits.is_empty(), "{hits:#?}");
    let files: Vec<String> = std::fs::read_dir(&vaults).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    println!("arquivos verificados (aberto): {files:?}");
    assert!(files.iter().any(|f| f.ends_with("-wal")), "esperava WAL presente durante o teste");
    // ... e após fechar.
    v.close();
    let hits = scan_dir(dir.path(), &needles);
    assert!(hits.is_empty(), "{hits:#?}");
    // Controle positivo: o scanner encontra o canário quando ele está em claro.
    std::fs::write(dir.path().join("controle.txt"), CANARIES[3]).unwrap();
    assert_eq!(scan_dir(dir.path(), &needles).len(), 1);
}
