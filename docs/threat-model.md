# KeyVault — modelo de ameaças

Baseado em KEYVAULT.md §3 (especificação 1.0) e no comportamento implementado em `keyvault-core` 0.1.0 e
no app Tauri 0.1.0. Este documento não é uma certificação; a revisão de segurança independente exigida
para uso com credenciais reais **não ocorreu**.

## 1. Ativos

| Ativo | Onde existe |
| --- | --- |
| Senha mestra | Teclado → WebView (string JS) → IPC → buffer zeroizável no Rust enquanto desbloqueado |
| KEK / DEK | Somente no Rust, durante uma operação (tipos de uso único, zerados no drop) |
| Campos das credenciais e preferências | Snapshot no Rust enquanto desbloqueado; envelope cifrado em disco |
| Consultas de pesquisa | Rust (em memória) e estado React |
| Clipboard | Área de transferência do SO após cópia explícita |
| Backups `.keyvault` | Arquivos escolhidos pelo usuário |

## 2. Fronteiras de confiança

1. **Disco × memória** — em disco só existem: banco SQLite com o envelope (cabeçalho público + ciphertext),
   WAL/SHM com páginas do mesmo envelope, arquivo `.lock` vazio, backups (envelopes) e o perfil do WebView2.
2. **WebView × Rust** — IPC com allowlist de 17 comandos de domínio, capability única para a janela `main`
   e origem local, verificação de janela/origem no Rust, DTOs estritos.
3. **Cofre × arquivo importado** — backup tratado como hostil: tamanho e cabeçalho validados antes da KDF,
   autenticação completa antes de qualquer uso, restauração sempre em cofre novo.
4. **App × sistema operacional** — eventos de bloqueio/suspensão/troca de usuário; clipboard; ACL de arquivos.
5. **Distribuição × instalação** — instaladores NSIS/MSI; assinatura **não** realizada nesta entrega.

## 3. Ameaças e mitigações implementadas

| Ameaça | Mitigação implementada | Limite residual |
| --- | --- | --- |
| Cópia do SQLite/WAL/SHM/backup com app bloqueado | AES-256-GCM sobre todo o conteúdo de negócio; Argon2id calibrado (≥ 64 MiB, t ≥ 3, p = 4; neste equipamento 256 MiB, t = 8, ≈0,76 s) | Senha fraca continua vulnerável a ataque offline |
| Alteração de ciphertext, cabeçalho, troca entre cofres/revisões | Tags GCM completas; AAD = domínio + cabeçalho canônico (+ SHA-256 do payload no wrapper); `envelope_kind` autenticado; parser estrito; contexto do payload comparado com o cabeçalho | — |
| Replay de banco/backup antigo completo | Revisão pública e datas apenas informativas | **Não detectável** sem estado externo confiável |
| Reutilização de nonce/chave (falha, retry, restore, cópia do banco) | DEK e salt novos a cada envelope; KEK nova por salt; tipos de uso único na API; chave recuperada só decifra; RNG com falha aborta | Condicionado à qualidade do CSPRNG do SO |
| XSS / WebView comprometida | Nenhum HTML de usuário renderizado (React texto; lint proíbe `dangerouslySetInnerHTML`/`innerHTML`); CSP restritiva; sem navegação remota; IPC mínimo | Frontend comprometido durante o desbloqueio pode capturar a senha digitada e os dados que a UI pode pedir (inclusive revelar/copiar segredos) — a allowlist reduz a superfície, não prova gesto humano |
| Outro usuário local | DACL protegida somente com o SID do usuário (diretório de cofres e arquivos), sem plaintext persistente | Administrador e malware do mesmo usuário não são isolados |
| Clipboard e tela | Cópia só por ação explícita, no Rust; formatos de exclusão do histórico/nuvem do Windows; limpeza após 20 s (5–60) apenas se a sequência do clipboard não mudou, feita com o clipboard aberto (sem corrida com outros escritores); revelação ≤ 15 s; remascarar ao perder foco | Histórico/sincronização podem ignorar a solicitação; gerenciadores de clipboard, capturas de tela e câmeras podem reter cópias |
| Arquivo malicioso / DoS | Limites antes de alocar/derivar: arquivo ≤ 64 MiB, payload ≤ 32 MiB, contagens vs. bytes restantes, faixas de KDF, profundidade fixa 4; uma KDF ativa por vez | Um arquivo dentro dos limites ainda custa uma KDF (até ~0,8–1,5 s) por tentativa de senha |
| Segundo processo / escrita concorrente | Plugin single-instance; trava exclusiva por cofre (`<id>.kvdb.lock`); revisão esperada em `BEGIN IMMEDIATE` | Cópias do arquivo por outros programas não são impedidas |
| Queda de energia/crash | WAL + `synchronous=FULL`; commit atômico do slot; criação/restauração em `.partial` + rename atômico | SSD/firmware que mente sobre flush está fora do controle do app |
| Dependência/instalador adulterado | Versões exatas no `Cargo.toml`/`package.json`, `Cargo.lock`/`package-lock.json`, auditorias | Assinatura de distribuição pendente (ver docs/security.md §9) |
| Rede/telemetria | Rust sem cliente de rede; CSP bloqueia rede da página; sem updater/telemetria/CDNs; flags do WebView2 reduzem rede de fundo | **Medido**: o runtime WebView2 (processo browser filho do app) abre 2 conexões TCP/443 a um endpoint da Microsoft (*.office.com/*.live.com) na inicialização, fora do controle da CSP — ver docs/security.md §7 |
| Sessão aberta indefinidamente | Prazo monotônico no Rust (padrão 5 min, 1–30), verificado em todo comando sensível e por um tick de 1 s; bloqueio após 30 s fora de foco (padrão ativo); bloqueio em bloqueio de sessão do Windows, suspensão, troca de usuário, logoff/desligamento e fechamento | Testes de suspensão real dependem de execução manual (docs/testing.md) |
| Respostas antigas repovoando a UI | Geração da sessão incrementada no bloqueio/desbloqueio; comandos exigem a geração atual; resultado descartado se a geração mudou durante a operação; UI ignora respostas de outra geração e desmonta a árvore do cofre ao bloquear | — |

## 4. Fora da proteção garantida

Keylogger, SO comprometido, acesso administrativo, injeção no processo, leitura de memória enquanto
desbloqueado (a senha mestra fica em memória por exigência do protocolo), câmera/observação, coerção,
perda física sem backup, indisponibilidade causada por exclusão, e apagamento seguro em SSD. Zeroização é
melhor esforço: strings do JavaScript, buffers internos do serde/IPC do Tauri, cópias feitas pelo sistema,
swap/arquivo de paginação e crash dumps impedem garantia de apagamento.

## 5. Metadados públicos (vazam por design)

`magic`, versões, `suite_id`, `vault_id`, `revision`, parâmetros KDF, salt, nonces (zero), comprimentos,
`envelope_kind`; nome do arquivo (`<vault_id>.kvdb`), número de arquivos, tamanho aproximado, datas de
modificação, frequência de escrita e cabeçalhos/estrutura do SQLite. O app **não** afirma que todo o arquivo
SQLite é cifrado.
