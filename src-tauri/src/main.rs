// Sem console em builds de release no Windows.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    keyvault_lib::run();
}
