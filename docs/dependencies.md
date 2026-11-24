# Inventário de dependências

Gerado por `python -I tools/inventory.py` a partir de `Cargo.lock` e `package-lock.json`.

## Rust — dependências diretas (versões fixadas com `=`)

| Crate do workspace | Dependência | Requisito | Tipo |
| --- | --- | --- | --- |
| keyvault | keyvault-core | `*` | normal |
| keyvault | rfd | `=0.18.0` | normal |
| keyvault | serde | `=1.0.229` | normal |
| keyvault | serde_json | `=1.0.154` | normal |
| keyvault | tauri | `=2.12.7` | dev |
| keyvault | tauri | `=2.12.7` | normal |
| keyvault | tauri-build | `=2.7.6` | build |
| keyvault | tauri-plugin-single-instance | `=2.5.5` | normal |
| keyvault | tempfile | `=3.27.0` | dev |
| keyvault | webview2-com | `=0.39.1` | normal |
| keyvault | windows-core | `=0.62.2` | normal |
| keyvault | windows-sys | `=0.61.2` | normal |
| keyvault | zeroize | `=1.9.2` | normal |
| keyvault-core | aes-gcm | `=0.11.1` | normal |
| keyvault-core | argon2 | `=0.6.0` | normal |
| keyvault-core | getrandom | `=0.4.3` | normal |
| keyvault-core | hex | `=0.4.3` | dev |
| keyvault-core | keyvault-core | `*` | dev |
| keyvault-core | proptest | `=1.12.0` | dev |
| keyvault-core | rusqlite | `=0.43.0` | normal |
| keyvault-core | sha2 | `=0.11.1` | normal |
| keyvault-core | subtle | `=2.6.1` | normal |
| keyvault-core | tempfile | `=3.27.0` | dev |
| keyvault-core | thiserror | `=2.0.21` | normal |
| keyvault-core | windows-sys | `=0.61.2` | normal |
| keyvault-core | zeroize | `=1.9.2` | normal |

Total de crates resolvidas para `x86_64-pc-windows-msvc` (fora do workspace): **292**.

### Licenças (Rust, transitivas)

| Licença | Crates |
| --- | ---: |
| MIT OR Apache-2.0 | 140 |
| MIT | 47 |
| Apache-2.0 OR MIT | 38 |
| Unicode-3.0 | 18 |
| Unlicense OR MIT | 12 |
| MIT/Apache-2.0 | 11 |
| MPL-2.0 | 5 |
| BSD-3-Clause | 3 |
| Zlib | 2 |
| Unlicense/MIT | 2 |
| Apache-2.0 | 2 |
| MIT OR Apache-2.0 OR Zlib | 2 |
| MIT OR Zlib OR Apache-2.0 | 2 |
| CC0-1.0 OR MIT-0 OR Apache-2.0 | 1 |
| BSD-3-Clause AND MIT | 1 |
| Zlib OR Apache-2.0 OR MIT | 1 |
| BSD-3-Clause/MIT | 1 |
| (MIT OR Apache-2.0) AND Unicode-3.0 | 1 |
| Apache-2.0 AND MIT | 1 |
| Apache-2.0 / MIT | 1 |
| 0BSD OR MIT OR Apache-2.0 | 1 |

## npm — dependências diretas

| Seção | Pacote | Versão | Licença |
| --- | --- | --- | --- |
| dependencies | @tauri-apps/api | `2.12.5` | Apache-2.0 OR MIT |
| dependencies | class-variance-authority | `0.7.1` | Apache-2.0 |
| dependencies | clsx | `2.1.1` | MIT |
| dependencies | lucide-react | `1.78.0` | ISC |
| dependencies | radix-ui | `1.8.1` | MIT |
| dependencies | react | `19.3.1` | MIT |
| dependencies | react-dom | `19.3.1` | MIT |
| dependencies | tailwind-merge | `3.7.1` | MIT |
| devDependencies | @eslint/js | `10.0.1` | MIT |
| devDependencies | @tailwindcss/vite | `4.3.5` | MIT |
| devDependencies | @tauri-apps/cli | `2.12.6` | Apache-2.0 OR MIT |
| devDependencies | @testing-library/jest-dom | `8.0.0` | MIT |
| devDependencies | @testing-library/react | `16.3.3` | MIT |
| devDependencies | @testing-library/user-event | `14.6.13` | MIT |
| devDependencies | @types/node | `26.6.6` | MIT |
| devDependencies | @types/react | `19.3.0` | MIT |
| devDependencies | @types/react-dom | `19.3.0` | MIT |
| devDependencies | @vitejs/plugin-react | `6.3.0` | MIT |
| devDependencies | axe-core | `4.14.1` | MPL-2.0 |
| devDependencies | eslint | `10.15.0` | MIT |
| devDependencies | eslint-plugin-react-hooks | `7.1.1` | MIT |
| devDependencies | globals | `17.14.0` | MIT |
| devDependencies | jsdom | `31.0.1` | MIT |
| devDependencies | playwright-core | `1.65.1` | Apache-2.0 |
| devDependencies | prettier | `3.10.1` | MIT |
| devDependencies | tailwindcss | `4.3.5` | MIT |
| devDependencies | tw-animate-css | `1.4.0` | MIT |
| devDependencies | typescript | `6.0.3` | Apache-2.0 |
| devDependencies | typescript-eslint | `8.74.0` | MIT |
| devDependencies | vite | `8.3.8` | MIT |
| devDependencies | vitest | `5.1.1` | MIT |

Total de pacotes no `package-lock.json`: **376**.

### Licenças (npm, todos os pacotes do lockfile)

| Licença | Pacotes |
| --- | ---: |
| MIT | 300 |
| Apache-2.0 | 20 |
| Apache-2.0 OR MIT | 13 |
| MPL-2.0 | 13 |
| ISC | 12 |
| BSD-2-Clause | 8 |
| BlueOak-1.0.0 | 4 |
| BSD-3-Clause | 3 |
| 0BSD | 2 |
| CC-BY-4.0 | 1 |
