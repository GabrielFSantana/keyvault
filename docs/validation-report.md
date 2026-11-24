# KeyVault 0.1.0 — relatório de validação

Data: 23/11/2026. Executado pelo próprio implementador (assistente de IA) nesta máquina. **Não é revisão
independente** e não autoriza uso com senhas reais; a revisão de segurança independente exigida pela
especificação para lançamento permanece pendente.

## 1. Plataforma e versões

| Item | Versão |
| --- | --- |
| SO | Windows 11 Home Single Language 10.0.26300 (x64), Intel Core i9-14900HX, 31,7 GB RAM |
| WebView2 Runtime | 157.0.4341.60 |
| Rust | rustc 1.100.0 (0ef1bc386 2026-11-09), cargo 1.100.0, alvo `x86_64-pc-windows-msvc` |
| MSVC | Build Tools 2026 18.12.1 (MSVC 14.52.37025), Windows SDK 10.0.26100.0 |
| Node/npm | 24.18.0 / 11.16.0 |
| Tauri | tauri 2.12.7, tauri-build 2.7.6, @tauri-apps/cli 2.12.6, @tauri-apps/api 2.12.5, tauri-plugin-single-instance 2.5.5, webview2-com 0.39.1 |
| Cripto | argon2 0.6.0, aes-gcm 0.11.1 (aead 0.6.1), sha2 0.11.1, getrandom 0.4.3, zeroize 1.9.2, subtle 2.6.1 |
| Persistência | rusqlite 0.43.0 (SQLite 3.54.1 embutido) |
| Frontend | React 19.3.1, TypeScript 6.0.3 (TS 7 não é suportado pelo typescript-eslint 8.74), Vite 8.3.8, Tailwind 4.3.5, shadcn CLI 4.23.0 (new-york, radix-ui 1.8.1), Vitest 5.1.1 |
| Lockfiles | `src-tauri/Cargo.lock`, `package-lock.json`; inventário em [dependencies.md](dependencies.md) |

Toolchain instalada nesta sessão com autorização do usuário: Rustup 1.29.3 e VS Build Tools 2026 via
`winget` (fontes oficiais, hash verificado pelo winget).

## 2. Comandos executados e resultados (rodada final)

Log integral: [evidence/checks.log](evidence/checks.log).

| Comando | Resultado |
| --- | --- |
| `npm run format:check` | OK |
| `npm run lint` (ESLint 10 + typescript-eslint strictTypeChecked + regras de segurança) | OK, 0 problemas |
| `npm run typecheck` (strict, `exactOptionalPropertyTypes`, `noUncheckedIndexedAccess`) | OK |
| `npm test` (Vitest + Testing Library) | 8/8 aprovados |
| `npm audit` | 0 vulnerabilidades |
| `cargo fmt --all --check` | OK |
| `cargo clippy --workspace --all-targets` | 0 avisos, 0 erros |
| `cargo test --workspace` | **53 aprovados**, 0 falhas (núcleo 42, app 11); 4 ignorados por desenho (2 processos-filho auxiliares, clipboard real e benchmark — os dois últimos executados abaixo) |
| `cargo test -p keyvault --lib clipboard -- --ignored` | 1/1 aprovado (clipboard REAL do Windows) |
| `cargo test -p keyvault-core --test bench_limits -- --ignored` | 1/1 aprovado (§4) |
| `cargo audit` (1.563 avisos RustSec, 515 crates) | 0 vulnerabilidades; 6 avisos (5 unmaintained, 1 unsound) em crates GTK/D-Bus (`glib`, `zbus_names`, `zvariant*`) e em `proc-macro-error`/`chrono` puxados pelo Tauri; GTK/D-Bus não compilam no alvo Windows |
| `cargo deny check` (alvo Windows) | advisories ok, bans ok, licenses ok, sources ok |
| `python -I tools/vectors/verify_vector.py` (argon2-cffi 25.1.0 + cryptography 50.0.2) | envelope reconstruído independentemente **idêntico byte a byte** (SHA-256 `235a289c…fcce`) |
| `npx tauri build` | OK: release com LTO, NSIS 2,26 MiB, MSI 3,12 MiB; `dist/` sem source maps |
| `KeyVault_0.1.0_x64-setup.exe /S` | instalado em `%LOCALAPPDATA%\KeyVault` |
| `e2e\run-e2e.ps1` (app instalado) | **67/67 verificações aprovadas**; 0 canários em 159 arquivos ([e2e.log](evidence/e2e.log), [results.json](evidence/results.json), [post-scan.json](evidence/post-scan.json)) |
| `e2e\run-os-events.ps1 -Mode lock` | APROVADO: bloqueado 510 ms após `LockWorkStation`, motivo `osLock`; geração antiga recusada |
| `e2e\run-os-events.ps1 -Mode suspend` | APROVADO: suspensão real (Kernel-Power 42 às 22:09:21, retomada 22:09:23); cofre bloqueado, motivo `osLock` (o Windows bloqueou a sessão antes de entregar `PBT_APMSUSPEND`) ([os-events.log](evidence/os-events.log)) |

SHA-256 do build final (não assinado — `Get-AuthenticodeSignature`: `NotSigned`):

```
ecb5db75ce3419ce0d0e74bf7165a5e40ef99cece29cfcd9e847e7de38e5ffb4  KeyVault_0.1.0_x64-setup.exe
3dbc506842ee26e31c1f3da3b19e4482c9b2869553b33a5035b981a4a62c2f75  KeyVault_0.1.0_x64_pt-BR.msi
edb28e792b4c04abcda329fa4342242bf1795cd22107d65cfcd18a7eacaac09b  keyvault.exe (instalado via NSIS)
```

O `keyvault.exe` em `target/release` difere do instalado porque o bundler grava o tipo de pacote no
executável antes de gerar cada instalador.

## 3. Destaques das evidências

- **Vetores oficiais**: Argon2id RFC 9106 §5.3; AES-256-GCM casos 13–16 e CAVP, com payload vazio, AAD,
  tag/AAD errada e tag truncada.
- **Adulteração**: flip em cada um dos 132 bytes do cabeçalho, wrapper, payload, tag, salt, nonces e
  comprimentos → sempre falha fechada; troca de wrapper/payload/cabeçalho entre cofres e revisões falha;
  parâmetros KDF hostis rejeitados em < 50 ms, sem derivação.
- **Unicidade**: 13 envelopes (criação, saves, retry após falha antes do commit, falha após commit,
  2 backups, exclusão, troca de senha, migração de KDF, preferências, restauração) → 26 chaves distintas;
  abrir não cifra; RNG falhando em qualquer dos 4 primeiros pedidos aborta sem gravar.
- **Crash**: 8 mortes por `TerminateProcess` durante gravações contínuas → sempre snapshot completo.
- **CSP efetiva no build instalado** ([csp.txt](evidence/csp.txt)): `eval`, `new Function`, `setTimeout`
  com string, `<script>`/`<style>` inline injetados e `fetch`/imagem/WebSocket remotos bloqueados.
  Observação de método: `eval` executado via depurador CDP (`Runtime.callFunctionOn`) ignora a CSP por
  desenho do Chromium; a sonda foi refeita no contexto da página (`allowUnsafeEvalBlockedByCSP: false`).
- **IPC no WebView2 real**: 9 comandos proibidos (fs, shell, http, clipboard, dialog, opener, window,
  devtools, `execute_sql`) negados pela ACL; no runtime mock, janela "outra" e origens remotas negadas.
- **Clipboard**: formatos de exclusão de histórico/nuvem presentes; limpo após 20 s; conteúdo novo
  preservado.
- **Sessão**: inatividade de 1 min imposta pelo backend no app instalado, sem interação.
- **Acessibilidade**: axe-core 4.14.1 (WCAG 2 A/AA) sem violações na tela de bloqueio e no detalhe;
  navegação por Tab com foco visível.
- **Armazenamento do WebView**: localStorage, sessionStorage, IndexedDB, Cache, Service Workers e cookies = 0.

## 4. Benchmarks no limite

Perfil de teste (dependências cripto otimizadas, núcleo sem otimização). Payload 31,1 MiB, 10.000
entradas, Argon2id m = 256 MiB, t = 9, p = 4 (≈ 840 ms):

| Operação | Tempo |
| --- | ---: |
| Selar envelope | 2,9 s |
| Abrir envelope (KDF + autenticação + parsing) | 3,0 s |
| Desbloquear cofre de 10.000 entradas | 3,0 s |
| Salvar (envelope novo ~32 MiB + commit) | 3,2 s |
| Pesquisa em memória | 28 ms |

App instalado com 1 entrada: criar cofre ≈ 2,4 s (inclui calibração), desbloquear ≈ 2,4 s.

## 5. Falhas encontradas e corrigidas durante a validação

1. Variantes unitárias de enums com tag interna no serde ignoravam campos extras → `{}` (DTOs estritos).
2. Bloqueio por foco disparava com o **diálogo nativo do próprio app** aberto → o diálogo não conta como
   perda de foco (a inatividade continua valendo).
3. Confirmação da restauração sumia (tela remontada) → status atualizado só ao fechar a confirmação.
4. `<dl>` com separador (violação axe `definition-list`) → listas separadas.
5. Faltava oferecer backup logo após criar o cofre (§2 da especificação) → adicionado.
6. Banco com schema inválido mostrava mensagem diferente → agora usa a mensagem genérica.
7. Binários de teste Tauri falhavam com `STATUS_ENTRYPOINT_NOT_FOUND` → manifesto Common Controls v6 só
   nos alvos de teste.

Durante a depuração do E2E, dois backups **fictícios** (234 bytes, cofre vazio) foram gravados por engano
em `Documentos` (OneDrive) pelo nome padrão do diálogo; foram identificados e removidos na mesma sessão.

## 6. Achados abertos e limitações

1. **Rede do runtime WebView2**: no app instalado, ocioso, o processo browser `msedgewebview2.exe` (filho do
   app) abre 2 conexões TCP/443 a um IPv6 da Microsoft (certificado `outlook.com`/`*.office.com`/`*.live.com`)
   ao iniciar, em todas as execuções medidas ([network.log](evidence/network.log)). Não vêm do código do app
   nem da página (net-log do Chromium mostra só `tauri.localhost`/`ipc.localhost`; CSP bloqueia rede da
   página) e persistiram com todas as flags e configurações de redução. Serviço exato não identificado
   (requer ETW/pktmon com administrador). **Critério de aceite correspondente: pendente/decisão de risco.**
2. **Suspensão**: bloqueio após suspensão real comprovado, mas o primeiro evento recebido foi o bloqueio de
   sessão; o ramo `PBT_APMSUSPEND` isolado só tem teste de mapeamento (isolá-lo exigiria alterar a
   configuração "exigir entrada ao acordar", que não alteramos).
3. **Troca de usuário / logoff reais**: não executados (só mapeamento dos códigos WTS).
4. **Leitor de tela** (Narrador/NVDA): não executado.
5. **Fuzzing guiado por cobertura** (cargo-fuzz): não executado; usados proptest (60.000 casos) e 200.000
   mutações determinísticas.
6. **Disco cheio e queda de energia reais**: simulados (`SQLITE_FULL`, morte do processo); falta de espaço
   no destino do backup só com falhas injetadas.
7. **Smart App Control** ativo bloqueou esporadicamente binários de teste recém-compilados (contornado
   recompilando). Instaladores não assinados podem ser bloqueados em outras máquinas.
8. **Assinatura de código**: não realizada; instruções em [security.md §9](security.md). Build reproduzível
   não comprovado.
9. **macOS/Linux**: não testados nem suportados (clipboard e eventos de SO só no Windows nesta versão).
10. **Revisão de segurança independente**: não realizada — requisito de lançamento.

## 7. Critérios de aceite (KEYVAULT.md §12)

| Critério | Situação |
| --- | --- |
| Build de produção Windows offline com a stack exigida; versões e lockfiles | **Atendido** (ver 6.1 sobre o runtime WebView2) |
| Criar, desbloquear, CRUD, pesquisar, gerar, revelar/copiar, bloquear, trocar senha, backup e restore | **Atendido** |
| Todos os campos de negócio no snapshot cifrado; só metadados técnicos públicos | **Atendido** |
| Envelope/AAD byte a byte, vetores estáveis, sem reutilização chave/nonce | **Atendido** |
| Senha errada/adulteração falha fechada, sem resultado parcial | **Atendido** |
| Limites de parser/KDF, transações, concorrência e falhas de energia | **Atendido nos testes definidos**; queda de energia real e fuzzing guiado por cobertura pendentes |
| Bloqueio/expiração no Rust; resultados de sessão encerrada não reaparecem | **Atendido** (unitário, IPC, E2E, bloqueio e suspensão reais) |
| IPC com allowlist testada, CSP efetiva, sem APIs genéricas perigosas | **Atendido** |
| Backup autenticado, independente, restaurável em novo cofre; perda de senha explicada | **Atendido** |
| Nenhum segredo em logs/storage/temporários; nenhuma telemetria ou rede do app | Segredos: **atendido**. Rede: **pendente** (6.1) |
| Checks de compilação, lint, tipos, testes, dependências e revisão de segurança | Automáticos **atendidos**; **revisão independente pendente** |

**Conclusão:** desenvolvimento concluído e verificado nos termos acima. **Não** há autorização para uso com
senhas reais: dependem da revisão independente, da decisão sobre a rede do WebView2 e da assinatura.
