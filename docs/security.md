# KeyVault — segurança da implementação

Implementação 0.1.0 da especificação KEYVAULT.md 1.0. **Desenvolvimento concluído não significa autorização
para guardar senhas reais**: a revisão de segurança independente exigida para lançamento não foi feita e
não pode ser autodeclarada.

## 1. Criptografia

- **Bibliotecas** (RustCrypto, versões exatas): `argon2 =0.6.0`, `aes-gcm =0.11.1` (`aead 0.6.1`),
  `sha2 =0.11.1`, `getrandom =0.4.3`, `zeroize =1.9.2`, `subtle =2.6.1`. Nenhuma primitiva própria.
- **Fluxo**: senha (bytes UTF-8 exatos) → Argon2id v0x13 (salt novo de 32 bytes) → KEK → embrulha uma DEK
  nova de 32 bytes → DEK cifra o snapshot. Layout byte a byte, AAD e vetores em [format.md](format.md).
- **Uso único de chaves**: tipos `FreshDek`/`FreshKek` (só cifram, uma vez, consumidos por valor) e
  `OpeningKek`/`OpenedDek` (só decifram). Não existe API para cifrar com chave recuperada nem para derivar
  KEK com salt fornecido externamente. Nonce de 96 bits zero apenas por isso.
- **Cada** commit, retry, backup, restauração, migração de KDF, troca de senha e alteração de preferências
  chama `envelope::seal`, que obtém DEK e salt novos do CSPRNG. Teste instrumentado: 13 envelopes →
  26 chaves distintas (docs/testing.md).
- **CSPRNG**: somente `getrandom` (no Windows, `ProcessPrng`). Falha → `CoreError::Rng`, operação abortada
  antes de produzir/persistir qualquer coisa.
- **KDF**: perfil inicial m = 65.536 KiB, t = 3, p = 4; calibração (sem nunca baixar o piso) sobe memória e
  depois iterações até ~500–1.500 ms; faixas aceitas m 65.536–262.144 KiB, t 3–10, p 1–4, validadas antes
  de alocar. Medido neste equipamento: m = 262.144 KiB, t = 8, p = 4 ≈ 761 ms. O crate `argon2` roda as
  vias sequencialmente (sem a feature `parallel`).
- **Salvamento exige KDF**: como cada envelope tem salt novo, salvar custa uma derivação (~0,8 s aqui).
  Não há autosave por tecla; salvar é ação explícita. A KDF roda em `spawn_blocking`, com no máximo uma
  KDF ativa por vez (`kdf_gate`), sem bloquear a UI.

### Exposição documentada da senha mestra

Para derivar KEKs novas a cada salvamento, a senha mestra fica num buffer `Zeroizing<Vec<u8>>` dentro do
processo Rust **enquanto o cofre está desbloqueado**, e é zerada ao bloquear. Quem lê a memória do processo
desbloqueado obtém a senha. A KEK nunca é guardada como substituto. A senha nunca é persistida e não há
hash verificador independente. Cópias transitórias fora do nosso controle: string do JavaScript (não
zeroizável), corpo JSON do IPC do Tauri e strings intermediárias do `serde_json`.

## 2. Persistência

- Diretório: `%LOCALAPPDATA%\com.keyvault.desktop\vaults\` (não-roaming; não é pasta temporária nem
  sincronizada por padrão). DACL protegida com uma única ACE (SID do usuário atual, controle total,
  herdável).
- Arquivos: `<vault_id>.kvdb` (+ `-wal`, `-shm`) e `<vault_id>.kvdb.lock` (vazio; trava exclusiva).
- Schema: `vault_state(slot INTEGER PRIMARY KEY CHECK(slot = 1), envelope BLOB NOT NULL)`,
  `user_version = 1`. Qualquer outro objeto no schema → banco rejeitado.
- PRAGMAs: `journal_mode=WAL`, `synchronous=FULL` (verificado = 2), `temp_store=MEMORY`,
  `secure_delete=ON`, `trusted_schema=OFF`, `cell_size_check=ON`. SQL sempre parametrizado.
- Commit: `BEGIN IMMEDIATE` → lê o cabeçalho público atual → compara revisão esperada → `UPDATE` do slot →
  `COMMIT` → só então o estado em memória muda. "Commit com status incerto" (erro após o COMMIT) é resolvido
  comparando o envelope persistido byte a byte.
- Criação/restauração: banco escrito em `.partial`, `COMMIT`, checkpoint, fechamento e
  `MoveFileExW(MOVEFILE_WRITE_THROUGH)` sem substituir. Restos `.partial` (nunca publicados) são removidos
  na listagem. Nunca truncamos um banco publicado.
- `secure_delete` é defesa adicional; **não** há promessa de apagamento em SSD.

## 3. Sessão (imposta no Rust)

Estados `Uninitialized, Locked, Unlocking, Unlocked, Locking, Error`. Cada comando sensível recebe a geração
que a UI conhece; o Rust verifica estado, geração e prazo (`Instant`, monotônico) antes; depois da operação,
verifica de novo e descarta o resultado se a sessão mudou. O bloqueio incrementa a geração **antes** de
esperar a operação em andamento, então nenhum resultado tardio sai.

| Gatilho | Implementação |
| --- | --- |
| Manual | `vault_lock` / Ctrl+L |
| Inatividade (padrão 5 min, 1–30) | Prazo verificado em todo comando e por tick de 1 s; atividade só de `keydown`/`pointerdown`/`wheel` confiáveis, limitada (UI 15 s, Rust 5 s) |
| Fora de foco 30 s (padrão ativo) | `WindowEvent::Focused` no Rust + tick. Enquanto um diálogo nativo do próprio app (salvar/abrir backup) está aberto, a perda de foco para ele não conta; ao fechar, a contagem recomeça. A inatividade continua valendo |
| Bloqueio de sessão do Windows | `WM_WTSSESSION_CHANGE`/`WTS_SESSION_LOCK` |
| Troca de usuário | `WTS_CONSOLE_DISCONNECT` / `WTS_REMOTE_DISCONNECT` |
| Suspensão | `WM_POWERBROADCAST`/`PBT_APMSUSPEND` (+ `RegisterSuspendResumeNotification`) |
| Logoff/desligamento | `WTS_SESSION_LOGOFF`, `WM_QUERYENDSESSION`, `WM_ENDSESSION` |
| Fechar app | `CloseRequested`, `Destroyed`, `RunEvent::Exit(Requested)` |

Ao bloquear: o `OpenVault` (senha, snapshot) é descartado e zerado, o clipboard próprio é limpo se ainda for
nosso, restaurações pendentes são descartadas (exceto quando o próprio bloqueio vem da restauração), a UI
recebe `kv://session-locked` e desmonta a árvore do cofre (estado React descartado; sem garantia de
zeroização no heap JS). Ao retomar, a senha é sempre exigida.

Tentativas erradas: mensagem única "Não foi possível desbloquear: senha incorreta ou cofre inválido";
atraso progressivo em memória 1, 2, 4, 8, 16, 30 s (máx.) — não protege contra ataque offline e não
sobrevive a reinício.

## 4. IPC — allowlist de comandos

Todos verificam no Rust: rótulo da janela = `main` e URL da webview com origem local
(`http(s)://tauri.localhost`, `tauri://localhost`; em debug também `http://localhost:1420`). Além disso, a
ACL do Tauri (capability `main`, `local: true`, `windows: ["main"]`, permissões `allow-<comando>` geradas
por `AppManifest::commands` no `build.rs`) nega chamadas de outras janelas/origens antes de chegar ao
comando. Registrar o handler **não** concede acesso: sem a permissão na capability a chamada é negada.

DTOs com `deny_unknown_fields`; IDs são 32 hex minúsculos não-zero. Erros: `{ code, field?, retryAfterMs? }`
sem dados do usuário. "S" = exige sessão `Unlocked` + geração atual (`session`).

| Comando | Entrada | Estados | Saída | Limites / erros principais |
| --- | --- | --- | --- | --- |
| `vault_status` | — | todos | `Status` (fase, geração, ids de cofres, preferências/contagem/KDF só se desbloqueado) | aplica prazo expirado |
| `vault_create` | `password`, `confirmation` | `Uninitialized` | `Status` | 15 chars–1.024 bytes; confirmação; `invalid_state` |
| `vault_unlock` | `vaultId`, `password` | `Locked` | `Status` | `authentication_failed` (genérico) + `retryAfterMs`; `too_many_attempts`; `vault_busy`; `locked` se bloqueado durante a KDF |
| `vault_lock` | — | todos | `Status` | idempotente |
| `session_activity` | `session` | S | `bool` | rate limit 5 s; não revive sessão expirada |
| `entries_list` | `session`, `favoritesOnly` | S | `{generation, entries[id,title,username,favorite,updatedAtMs]}` | — |
| `entries_search` | `session`, `query`, `favoritesOnly` | S | idem | query ≤ 1.024 bytes; busca em título/URL/usuário/tags/notas, nunca segredos |
| `entry_get` | `session`, `id` | S | detalhe **sem** senha e sem valores de campos secretos (`hasPassword`, `hasValue`) | `not_found` |
| `entry_save` | `session`, `entry` (senha/segredos como `keep`/`set`/`clear`) | S | `{generation,id,revision}` | limites de campo/tags/campos; `storage_full`; `revision_conflict` |
| `entry_delete` | `session`, `id` | S | revisão | `not_found` |
| `password_generate` | `session`, `options` | S | `{generation,password}` | 16–128; ≥ 1 classe |
| `entry_reveal_secret` | `session`, `id`, `secret` | S | `{generation,value,expiresInMs:15000}` | — |
| `entry_copy_secret` | `session`, `id`, `secret` | S | `{generation,clearsInMs}` (segredo **não** volta ao JS) | `clipboard_unavailable` |
| `vault_change_password` | `session`, `current`, `newPassword`, `confirmation` | S | `Status` | senha atual (tempo constante) + atraso; regras da nova senha |
| `vault_settings_update` | `session`, `settings` | S | `Status` | auto-lock 1–30 min; clipboard 5–60 s |
| `backup_export` | `session` | S | `{saved,fileName}` (só o nome) | destino só via diálogo nativo do Rust |
| `backup_restore` | `request` = `select {}` / `inspect{token,password}` / `commit{token,password,confirmation}` / `cancel{token}` | qualquer (independe da sessão) | etapa | arquivo ≤ 64 MiB, cabeçalho antes da KDF, autenticação completa antes da contagem; token de 64 bits; validade 10 min |

**Desvios declarados em relação à lista da especificação**: (1) `vault_settings_update` foi adicionado,
porque a especificação exige prazo configurável (1–30 min) e a opção de bloqueio por foco, e não havia
comando para isso; (2) o campo `envelope_kind` (autenticado) foi adicionado ao cabeçalho para separar
contexto banco × backup (reforço, não enfraquecimento).

Não existem comandos de SQL, shell, leitura/escrita de arquivo arbitrário, HTTP, abertura de URL, eval ou
recuperação de chave. Nenhum plugin com comandos de frontend está registrado (o single-instance não expõe
comandos); diálogos usam `rfd` diretamente no Rust.

## 5. WebView, CSP e frontend

CSP de produção (`tauri.conf.json`, o Tauri adiciona hashes/nonces dos próprios scripts):

```
default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self';
connect-src ipc: http://ipc.localhost; object-src 'none'; base-uri 'none'; frame-src 'none';
form-action 'none'
```

Configurações do WebView2 aplicadas pelo Rust ao criar a janela (`harden_webview`): autosave de senhas e
autofill do navegador **desativados**, atalhos do navegador (F5, Ctrl+P, Ctrl+F…) desativados, barra de
status, menu de contexto padrão e páginas de erro embutidas desativados, verificação de reputação
(SmartScreen) desativada e devtools desativadas no release.

`devCsp` (somente `tauri dev`) adiciona `'unsafe-inline'` em estilos e o servidor Vite/HMR. A CSP efetiva do
build instalado foi verificada (docs/validation-report.md). Outras medidas: `withGlobalTauri: false`,
`freezePrototype: true`, janela `incognito: true` (perfil WebView2 em modo InPrivate), sem drag-and-drop,
sem zoom por atalho, menu de contexto bloqueado, devtools ausentes no release (não é barreira de
segurança), sem source maps, sem fontes/CDNs remotos, argumentos do WebView2 que desativam SmartScreen,
rede em segundo plano, atualização de componentes, sync e pings.

No React: nenhum `dangerouslySetInnerHTML`/`innerHTML` (regra de lint), URLs exibidas como texto,
nenhum uso de `localStorage`/`sessionStorage`/`IndexedDB`/service workers/`fetch`/`WebSocket`/clipboard
(proibidos por lint). Segredos nunca em `aria-label`, `title`, título da janela ou notificações (rótulos
usam o nome do campo, não o valor).

## 6. Backup e restauração

Backup = envelope novo (`envelope_kind = 2`), DEK/salt/KEK novos, senha atual; temporário privado no mesmo
diretório (`create_new`, ACL restrita quando o sistema de arquivos suporta), `fsync`, publicação atômica
(`MoveFileExW` com `WRITE_THROUGH`); falha remove o temporário e preserva o destino anterior. Sobrescrita só
quando confirmada no diálogo do Windows. Restauração: cabeçalho/tamanho antes da KDF → senha do backup →
autenticação + validação completa → contagem → senha nova confirmada → cofre novo (novo `vault_id`,
revisão 1). O cofre atual nunca é sobrescrito. Backups antigos continuam abrindo com a senha antiga; não há
revogação nem prova de que um backup é o mais recente.

## 7. Privacidade, rede e logs

Sem telemetria, analytics, crash reporting, updater, pings, licença, CDNs ou requisições de rede do app em
runtime: o código Rust não tem cliente de rede e a página não consegue fazer requisições (CSP
`connect-src` restrito ao IPC; `fetch`/imagem/WebSocket remotos bloqueados e medidos no build instalado).

**Achado medido (WebView2 Runtime, não o código do app):** no app instalado, em configuração de produção e
ocioso, o **processo browser do WebView2** (`msedgewebview2.exe`, filho do `keyvault.exe`) abre 2 conexões
TCP/443 para um endereço IPv6 da Microsoft logo na inicialização; o certificado apresentado por esse
endereço é de `outlook.com`/`*.office.com`/`*.live.com`. Essas conexões **não** aparecem no net-log do
Chromium (que mostra só `tauri.localhost`/`ipc.localhost`), não passam pela CSP e persistiram com
`--disable-background-networking`, `--disable-component-update`, `--disable-domain-reliability`,
`--disable-sync`, `--no-pings`, SmartScreen desativado e as configurações acima. O serviço exato não foi
identificado (exige rastreamento com privilégio de administrador, não executado). Não enviamos dados do
cofre a esse canal (o processo browser não recebe o conteúdo do cofre além do que a página renderiza), mas
**não é possível afirmar ausência total de rede do processo do app enquanto ele usa o WebView2**. Opções
para quem exige zero rede: bloquear a saída por firewall/políticas de rede do Windows para o runtime do
WebView2 (afeta outros apps que usam o mesmo runtime) ou investigar com rastreamento ETW/pktmon antes da
revisão independente. O app não grava logs em produção; erros são códigos estáveis sem dados do usuário, caminhos
completos, parâmetros IPC, consultas, senha ou material criptográfico. O app não gera dumps.

## 8. Sem recuperação

Não há recuperação de senha. Não há proteção garantida contra malware ativo no mesmo usuário. Não há
detecção confiável de replay de um cofre antigo completo.

## 9. Distribuição assinada (pendente — instruções)

Nesta entrega os instaladores **não estão assinados**. Para distribuir:

1. Obter certificado de assinatura de código (OV/EV ou Azure Trusted Signing).
2. Configurar `bundle.windows.certificateThumbprint`, `digestAlgorithm: "sha256"` e `timestampUrl`
   (ou `signCommand` para Trusted Signing) em `src-tauri/tauri.conf.json`.
3. `npm ci && npx tauri build` em máquina limpa a partir dos lockfiles; registrar versões das toolchains.
4. Verificar com `Get-AuthenticodeSignature` e publicar SHA-256 dos instaladores (ver relatório).
5. Não alegar build reproduzível sem comprovar reprodução bit a bit.
