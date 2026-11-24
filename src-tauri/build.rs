// Registra os comandos próprios no manifesto ACL do Tauri. Com `AppManifest::commands`, cada comando
// passa a exigir permissão explícita (`allow-<comando>`) concedida por capability; registrar o
// handler NÃO basta para permitir a chamada.
const COMMANDS: &[&str] = &[
    "vault_status",
    "vault_create",
    "vault_unlock",
    "vault_lock",
    "entries_list",
    "entry_get",
    "entry_save",
    "entry_delete",
    "entries_search",
    "password_generate",
    "entry_reveal_secret",
    "entry_copy_secret",
    "vault_change_password",
    "backup_export",
    "backup_restore",
    "session_activity",
    "vault_settings_update",
];

fn main() {
    // Binários de teste não recebem o manifesto do app; sem Common Controls v6 o carregamento falha
    // com STATUS_ENTRYPOINT_NOT_FOUND. Embute o mesmo manifesto apenas nos alvos de teste (MSVC).
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("windows-test-manifest.xml");
        println!("cargo:rerun-if-changed={}", manifest.display());
        println!("cargo:rustc-link-arg-tests=/MANIFEST:EMBED");
        println!("cargo:rustc-link-arg-tests=/MANIFESTINPUT:{}", manifest.display());
    }
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(tauri_build::AppManifest::new().commands(COMMANDS)))
        .expect("falha no build do Tauri");
}
