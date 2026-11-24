# KeyVault — testes

Matriz da seção 11 de KEYVAULT.md → onde está cada evidência e como executar. Resultados reais da
execução desta entrega estão em [validation-report.md](validation-report.md). Todos os testes usam
**somente dados fictícios**. Mocks são usados apenas nos testes de componentes da UI; não substituem os
testes nativos de filesystem, ACL, clipboard, sessão e WebView.

## Como executar

```powershell
# Frontend
npm run format:check; npm run lint; npm run typecheck; npm test

# Rust (na pasta src-tauri)
cargo fmt --all --check
cargo clippy --workspace --all-targets
cargo test --workspace                      # núcleo + app (IPC/ACL com runtime mock)
cargo test -p keyvault --lib clipboard -- --ignored   # clipboard REAL do Windows (altera a área de transferência)
cargo audit; cargo deny check

# Vetor de integração verificado de forma independente (Python: argon2-cffi + cryptography)
python -I tools/vectors/verify_vector.py tools/vectors/vector_v1.hex

# Build de produção + E2E no app INSTALADO (CDP do WebView2, monitor de rede, varredura de canários)
npm run tauri build
src-tauri\target\release\bundle\nsis\KeyVault_0.1.0_x64-setup.exe /S
powershell -ExecutionPolicy Bypass -File e2e\run-e2e.ps1
```

O E2E recusa rodar se já existirem cofres em `%LOCALAPPDATA%\com.keyvault.desktop\vaults`. A porta de
depuração do WebView2 é habilitada **somente** pelo script de teste (variável
`WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS`), nunca no app distribuído.

> Ambiente: o Windows desta máquina tem o **Smart App Control** ativo, que bloqueou esporadicamente
> binários de teste recém-compilados (`os error 4551`). Recompilar o alvo (mudança trivial) contornou o
> bloqueio; nenhuma verificação foi desativada.

## Matriz

| Área (§11) | Evidência automatizada | Arquivo |
| --- | --- | --- |
| Primitivas | Argon2id RFC 9106 §5.3; AES-256-GCM casos 13–16 (McGrew–Viega/NIST) e CAVP, com AAD, payload vazio, tag/AAD errada e tag truncada | `src-tauri/core/tests/primitives.rs` |
| Envelope | Roundtrip; senha errada (inclusive diferença de 1 espaço); flip em **cada um dos 132 bytes** do cabeçalho; wrapper, payload, tag; salt; nonces; comprimentos; truncado/sobrando; troca de wrapper/payload/cabeçalho entre cofres e revisões; confusão banco×backup antes da KDF; parâmetros KDF hostis rejeitados sem derivação; contexto do payload | `core/tests/envelope.rs` |
| Vetor de integração | Envelope determinístico fixado por SHA-256; reconstruído byte a byte em Python independente | `core/tests/vectors.rs`, `tools/vectors/verify_vector.py` |
| Unicidade | Instrumentação de teste (feature `test-instrumentation`, proibida em release por `compile_error!`): criação, salvar, retry após falha antes do commit, falha após commit, 2 backups, exclusão, troca de senha, migração de KDF, preferências e restauração → 13 envelopes, 26 chaves distintas, nonce zero; abrir não cifra; RNG com falha (1º–4º pedido) aborta sem gravar | `core/tests/uniqueness.rs` |
| Parsing | proptest (20.000 casos × 3 propriedades) em cabeçalho/payload; 200.000 mutações determinísticas do payload (aceitas só se canônicas); contagens gigantes sem alocação; UTF-8, bool, reservado, sobra; ids duplicados; payload > 32 MiB e envelope > 64 MiB; amostra de mutações no envelope completo | `core/tests/parsing.rs` |
| Persistência | Falha antes/depois do COMMIT; 8 mortes do processo (`TerminateProcess`) durante gravações contínuas sempre recuperam snapshot completo; revisão esperada e 4 threads concorrentes; segundo processo bloqueado (também por caminho alternativo); disco cheio (`SQLITE_FULL` via `max_page_count`); permissão negada (DACL real vazia); escrita atômica de backup com falhas injetadas; schema adulterado; restos `.partial` | `core/tests/persistence.rs` |
| Confidencialidade | Canários em todos os campos (+ ids, data, senhas mestras) buscados em UTF-8/UTF-16LE no SQLite, WAL, SHM, `.lock` e backup após CRUD, backup, troca de senha e migração (com WAL presente e após fechar), com controle positivo; no E2E, varredura do diretório de dados, perfil WebView2, backups e `%TEMP%` | `core/tests/canaries.rs`, `e2e/run-e2e.ps1` |
| Sessão | Prazo expirado bloqueia no backend sem timer da UI; geração antiga rejeitada; bloqueio durante operação descarta resultado tardio; atividade com rate limit não revive sessão; foco 30 s; atraso progressivo; IPC: bloqueio concorrente a um salvamento; E2E: inatividade de 1 min no app instalado | `src-tauri/src/session.rs`, `src-tauri/tests/ipc_acl.rs`, `e2e/run.mjs` |
| Clipboard | Clipboard REAL do Windows: cópia, expiração, preservação de conteúdo novo do usuário (inclusive conteúdo idêntico recopiado); E2E: formatos de exclusão de histórico/nuvem presentes, limpeza após 20 s, preservação | `src-tauri/src/clipboard.rs`, `e2e/run.mjs` |
| IPC/UI | ACL real (runtime mock): janela não autorizada, origens remotas, plugins/core/inexistentes negados; DTOs estritos (campo `path` extra rejeitado); IDs inválidos; sessão ausente; XSS como texto. E2E no WebView2 real: 9 comandos proibidos negados pela ACL; CSP efetiva (cabeçalho e bloqueio de eval/Function/timer-string/script e style inline/fetch/img/WebSocket remotos); axe-core WCAG 2 A/AA; navegação por Tab | `tests/ipc_acl.rs`, `e2e/run.mjs` |
| UI (componentes) | Vitest + Testing Library com backend IPC simulado: regras da senha mestra (colagem, espaços, Unicode), mensagem genérica e atraso, XSS inerte, revelação ≤ 15 s e remascarar no blur, cópia sem receber segredo, bloqueio desmonta a UI, respostas de sessão antiga descartadas, erro `locked` volta ao bloqueio, nenhum uso de storage | `src/App.test.tsx` |
| Backup | Roundtrip independente; senha antiga após troca; corrupção em várias regiões; restauração não altera bytes do cofre atual; destino existente/sem confirmação; falhas de escrita/publicação; E2E: diálogo nativo, backup com senha antiga, restauração com nova senha | `core/tests/service.rs`, `persistence.rs`, `e2e/run.mjs` |
| Rede | E2E com monitor de conexões TCP/UDP de `keyvault.exe` e filhos durante todos os fluxos + net-log do Chromium em execução diagnóstica | `e2e/netmon.ps1`, `e2e/run-e2e.ps1` |
| UX | Fluxos completos no app instalado (criar, desbloquear, CRUD, pesquisa, gerar, revelar/copiar, bloquear, trocar senha, backup, restaurar), teclado, axe-core | `e2e/run.mjs` |

## Testes reais do sistema operacional (exigem autorização de quem usa a máquina)

```powershell
powershell -ExecutionPolicy Bypass -File e2e\run-os-events.ps1 -Mode lock      # bloqueia a sessão do Windows
powershell -ExecutionPolicy Bypass -File e2e\run-os-events.ps1 -Mode suspend   # suspende o computador
```

Exigem diretório de dados sem cofres (o script cria um cofre fictício). Benchmark no limite:
`cargo test -p keyvault-core --test bench_limits -- --ignored --nocapture`.

## Não executado / pendente

- Troca de usuário e logoff reais (apenas mapeamento dos códigos WTS testado).
- Evidência real isolada do ramo `PBT_APMSUSPEND` (na suspensão real, o bloqueio de sessão chegou primeiro).
- Leitor de tela (Narrador/NVDA): apenas axe-core e rótulos.
- Fuzzing guiado por cobertura (cargo-fuzz/libFuzzer): usados proptest + mutação.
- Disco cheio de volume real e queda de energia real (simulados); falta de espaço no destino do backup.
- macOS/Linux (não homologados).
