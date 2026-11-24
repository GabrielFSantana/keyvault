#![allow(clippy::unwrap_used)]
//! Fronteira IPC com a autoridade ACL REAL gerada de `capabilities/main.json` + `build.rs`
//! (runtime mock do Tauri, sem WebView2). Verifica: comandos próprios só da janela "main" e de origem
//! local; plugins/core não concedidos negados; DTOs estritos (sem caminhos arbitrários); estado,
//! geração e IDs validados no Rust; XSS armazenado como texto.

use serde_json::{Value, json};
use tauri::ipc::{CallbackFn, InvokeBody};
use tauri::test::{INVOKE_KEY, MockRuntime, get_ipc_response, mock_builder};
use tauri::webview::InvokeRequest;
use tauri::{Manager, WebviewUrl, WebviewWindow, WebviewWindowBuilder};

use keyvault_lib::commands::AppCtx;

const LOCAL: &str = "http://localhost:1420/";

fn app() -> (tauri::App<MockRuntime>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let session = keyvault_lib::make_session(dir.path().join("vaults"));
    let app = mock_builder().invoke_handler(keyvault_lib::keyvault_handlers!()).build(tauri::generate_context!()).unwrap();
    app.manage(AppCtx { session, os_integration: false });
    (app, dir)
}

fn window(app: &tauri::App<MockRuntime>, label: &str) -> WebviewWindow<MockRuntime> {
    WebviewWindowBuilder::new(app, label, WebviewUrl::default()).build().unwrap()
}

fn call(w: &WebviewWindow<MockRuntime>, cmd: &str, body: Value, url: &str) -> Result<Value, Value> {
    get_ipc_response(
        w,
        InvokeRequest {
            cmd: cmd.into(),
            callback: CallbackFn(0),
            error: CallbackFn(1),
            url: url.parse().unwrap(),
            body: InvokeBody::Json(body),
            headers: Default::default(),
            invoke_key: INVOKE_KEY.to_string(),
        },
    )
    .map(|b| b.deserialize::<Value>().unwrap())
}

fn code(r: &Result<Value, Value>) -> String {
    match r {
        Err(v) => v.get("code").and_then(Value::as_str).map(str::to_owned).unwrap_or_else(|| v.to_string()),
        Ok(v) => format!("OK {v}"),
    }
}

#[test]
fn acl_allows_main_local_and_denies_everything_else() {
    let (app, _dir) = app();
    let main = window(&app, "main");
    let st = call(&main, "vault_status", json!({}), LOCAL).unwrap();
    assert_eq!(st["phase"], "uninitialized");

    // Outra janela (mesma origem): negada pela ACL (capability só vale para "main").
    let other = window(&app, "outra");
    let r = call(&other, "vault_status", json!({}), LOCAL);
    assert!(r.is_err(), "janela não autorizada executou comando: {r:?}");
    println!("janela 'outra': {}", code(&r));

    // Origem remota na janela principal: negada.
    for url in ["https://evil.example/", "http://tauri.localhost.evil.example/", "http://192.168.0.10:1420/"] {
        let r = call(&main, "vault_status", json!({}), url);
        assert!(r.is_err(), "origem remota {url} aceita: {r:?}");
    }

    // Plugins e comandos core não concedidos (shell, http, fs, clipboard, dialog, updater, opener,
    // devtools, janela, emit) e comandos inexistentes.
    for cmd in [
        "plugin:shell|execute",
        "plugin:shell|open",
        "plugin:http|fetch",
        "plugin:fs|read_file",
        "plugin:fs|write_file",
        "plugin:clipboard-manager|read_text",
        "plugin:dialog|open",
        "plugin:updater|check",
        "plugin:opener|open_url",
        "plugin:webview|internal_toggle_devtools",
        "plugin:window|close",
        "plugin:event|emit",
        "plugin:path|resolve_directory",
        "execute_sql",
        "read_file",
        "eval",
    ] {
        let r = call(&main, cmd, json!({}), LOCAL);
        assert!(r.is_err(), "{cmd} não foi negado: {r:?}");
    }
}

#[test]
fn sensitive_commands_require_unlocked_session_and_strict_dtos() {
    let (app, _dir) = app();
    let main = window(&app, "main");
    // Sem sessão.
    for (cmd, body) in [
        ("entries_list", json!({"session": 1, "favoritesOnly": false})),
        ("entry_get", json!({"session": 1, "id": "00112233445566778899aabbccddeeff"})),
        ("entry_reveal_secret", json!({"session": 1, "id": "00112233445566778899aabbccddeeff", "secret": {"kind": "password"}})),
        ("entry_copy_secret", json!({"session": 1, "id": "00112233445566778899aabbccddeeff", "secret": {"kind": "password"}})),
        (
            "password_generate",
            json!({"session": 1, "options": {"length": 24, "lowercase": true, "uppercase": true, "digits": true, "symbols": true, "excludeAmbiguous": false}}),
        ),
        ("backup_export", json!({"session": 1})),
    ] {
        let r = call(&main, cmd, body, LOCAL);
        assert_eq!(code(&r), "locked", "{cmd}");
    }
    // DTO estrito: campo extra (ex.: caminho arbitrário) é rejeitado na desserialização.
    let r = call(&main, "backup_restore", json!({"request": {"step": "select", "path": "C:\\Windows\\System32\\config\\SAM"}}), LOCAL);
    assert!(r.is_err());
    let r = call(&main, "backup_restore", json!({"request": {"step": "inspect", "token": "x", "password": "p", "path": "C:\\x"}}), LOCAL);
    assert!(r.is_err());
    // Token inválido: nenhuma restauração pendente.
    let r = call(
        &main,
        "backup_restore",
        json!({"request": {"step": "inspect", "token": "0000000000000000", "password": "senha qualquer ficticia"}}),
        LOCAL,
    );
    assert_eq!(code(&r), "invalid_state");
    // Desbloqueio de id inválido.
    let r = call(&main, "vault_unlock", json!({"vaultId": "../../etc/passwd", "password": "x"}), LOCAL);
    assert_eq!(code(&r), "validation");
}

#[test]
fn full_ipc_flow_generation_and_xss_as_text() {
    let (app, _dir) = app();
    let main = window(&app, "main");
    let pw = "senha mestra ficticia do teste IPC";
    // Confirmação diferente.
    let r = call(&main, "vault_create", json!({"password": pw, "confirmation": "outra"}), LOCAL);
    assert_eq!(code(&r), "validation");
    // Curta demais.
    let r = call(&main, "vault_create", json!({"password": "curta", "confirmation": "curta"}), LOCAL);
    assert_eq!(code(&r), "validation");
    let st = call(&main, "vault_create", json!({"password": pw, "confirmation": pw}), LOCAL).unwrap();
    assert_eq!(st["phase"], "unlocked");
    let g = st["generation"].as_u64().unwrap();
    let vault_id = st["selectedVaultId"].as_str().unwrap().to_owned();
    println!("KDF calibrado: {}", st["kdf"]);

    let xss = "<img src=x onerror=alert(1)><script>alert(2)</script>";
    let saved = call(
        &main,
        "entry_save",
        json!({"session": g, "entry": {
            "id": null, "title": xss, "url": "javascript:alert(3)", "username": "u", "notes": xss,
            "password": {"kind": "set", "value": "senha-ficticia-ipc"}, "tags": ["t"], "favorite": true,
            "fields": [{"id": null, "name": "token", "secret": true, "value": {"kind": "set", "value": "segredo-campo"}}]
        }}),
        LOCAL,
    )
    .unwrap();
    let id = saved["id"].as_str().unwrap().to_owned();
    // Campo extra no DTO de entrada é rejeitado.
    let r = call(
        &main,
        "entry_save",
        json!({"session": g, "entry": {"id": null, "title": "a", "url": "", "username": "", "notes": "", "password": {"kind": "keep"}, "tags": [], "favorite": false, "fields": [], "html": "<b>"}}),
        LOCAL,
    );
    assert!(r.is_err());

    let list = call(&main, "entries_list", json!({"session": g, "favoritesOnly": false}), LOCAL).unwrap();
    assert_eq!(list["entries"][0]["title"], xss, "texto deve voltar exatamente como dado");
    assert!(list["entries"][0].get("password").is_none());
    let detail = call(&main, "entry_get", json!({"session": g, "id": id}), LOCAL).unwrap();
    assert!(detail.get("password").is_none(), "entry_get não pode conter senha");
    assert_eq!(detail["hasPassword"], true);
    assert!(detail["fields"][0]["value"].is_null(), "campo secreto omitido");
    let field_id = detail["fields"][0]["id"].as_str().unwrap().to_owned();
    // Pesquisa não alcança segredos.
    let s = call(&main, "entries_search", json!({"session": g, "query": "senha-ficticia-ipc", "favoritesOnly": false}), LOCAL).unwrap();
    assert_eq!(s["entries"].as_array().unwrap().len(), 0);
    let rev = call(&main, "entry_reveal_secret", json!({"session": g, "id": id, "secret": {"kind": "field", "fieldId": field_id}}), LOCAL)
        .unwrap();
    assert_eq!(rev["value"], "segredo-campo");
    assert_eq!(rev["expiresInMs"], 15000);
    // ID inválido.
    let r = call(&main, "entry_get", json!({"session": g, "id": "zz"}), LOCAL);
    assert_eq!(code(&r), "validation");
    // Geração antiga/incorreta.
    let r = call(&main, "entries_list", json!({"session": g + 1, "favoritesOnly": false}), LOCAL);
    assert_eq!(code(&r), "stale_session");

    // Bloqueio: tudo com a geração antiga falha; desbloqueio cria nova geração.
    let st = call(&main, "vault_lock", json!({}), LOCAL).unwrap();
    assert_eq!(st["phase"], "locked");
    assert!(st["settings"].is_null() && st["entryCount"].is_null());
    let r = call(&main, "entry_reveal_secret", json!({"session": g, "id": id, "secret": {"kind": "password"}}), LOCAL);
    assert_eq!(code(&r), "locked");
    // Senha errada: mensagem genérica e atraso progressivo.
    let r = call(&main, "vault_unlock", json!({"vaultId": vault_id, "password": "senha errada ficticia"}), LOCAL);
    assert_eq!(code(&r), "authentication_failed");
    let r = call(&main, "vault_unlock", json!({"vaultId": vault_id, "password": pw}), LOCAL);
    assert_eq!(code(&r), "too_many_attempts");
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let st = call(&main, "vault_unlock", json!({"vaultId": vault_id, "password": pw}), LOCAL).unwrap();
    let g2 = st["generation"].as_u64().unwrap();
    assert!(g2 > g);
    let r = call(&main, "entries_list", json!({"session": g, "favoritesOnly": false}), LOCAL);
    assert_eq!(code(&r), "stale_session", "resposta/comando da sessão antiga não pode repovoar a UI");
    assert!(call(&main, "entries_list", json!({"session": g2, "favoritesOnly": false}), LOCAL).is_ok());
}

#[test]
fn lock_during_slow_operation_discards_late_result() {
    let (app, _dir) = app();
    let main = window(&app, "main");
    let pw = "senha mestra ficticia do teste tardio";
    let st = call(&main, "vault_create", json!({"password": pw, "confirmation": pw}), LOCAL).unwrap();
    let g = st["generation"].as_u64().unwrap();
    // Salvamento (KDF + commit) em outra thread e bloqueio concorrente.
    let w2 = main.clone();
    let saver = std::thread::spawn(move || {
        call(
            &w2,
            "entry_save",
            json!({"session": g, "entry": {"id": null, "title": "tardia", "url": "", "username": "", "notes": "", "password": {"kind": "keep"}, "tags": [], "favorite": false, "fields": []}}),
            LOCAL,
        )
    });
    std::thread::sleep(std::time::Duration::from_millis(30));
    let st = call(&main, "vault_lock", json!({}), LOCAL).unwrap();
    assert_eq!(st["phase"], "locked");
    let r = saver.join().unwrap();
    // Ou o salvamento terminou antes do bloqueio, ou o resultado tardio foi descartado.
    println!("resultado do salvamento concorrente: {}", code(&r));
    if let Err(e) = &r {
        assert_eq!(e["code"], "locked");
    }
    // Nenhum dado é acessível após o bloqueio.
    let r = call(&main, "entries_list", json!({"session": g, "favoritesOnly": false}), LOCAL);
    assert_eq!(code(&r), "locked");
}
