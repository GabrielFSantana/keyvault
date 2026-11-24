# KeyVault — especificação técnica

Versão da especificação: 1.0 · 23/11/2026 · Status: projeto para implementação, sem código de aplicativo.

## 1. Objetivo e escopo

Aplicativo desktop pessoal, offline, para guardar credenciais de n8n, GitHub, Docker, contas e outros serviços. O usuário desbloqueia um cofre local usando uma senha mestra. Interface em português brasileiro. Windows é a primeira plataforma homologada; macOS e Linux só serão declarados suportados após testes próprios.

Stack obrigatória: Tauri 2, Rust, React, TypeScript em modo strict, Vite, Tailwind CSS, shadcn/ui e SQLite. Argon2id para derivação de chave; AES-256-GCM para criptografia autenticada. Não criar servidor, conta online, sincronização, extensão de navegador, preenchimento automático, biometria, recuperação remota, anexos ou exportação em texto claro no MVP.

Requisitos normativos usam DEVE, NÃO DEVE e PODE. Decisões criptográficas abaixo são requisitos, não exemplos intercambiáveis. A implementação exige revisão de segurança antes de uso com credenciais reais; não deve anunciar certificação ou segurança absoluta.

## 2. Experiência e funcionalidades

- Primeiro uso: criar cofre, explicar perda irreversível da senha, confirmar senha mestra e oferecer backup criptografado.
- Senha mestra: mínimo de 15 caracteres Unicode, permitir espaços e colagem, sem regras artificiais de composição. Máximo de 1.024 bytes UTF-8, comunicado na interface. Usar os bytes exatos, sem trim, normalização ou truncamento silencioso. Não persistir senha nem hash verificador independente.
- CRUD de credenciais com título, URL, usuário, senha, notas, tags, favorito, campos personalizados e datas de criação/alteração. Campos personalizados têm nome, valor e indicação de segredo.
- Listagem mostra título/usuário somente desbloqueada; senha e segredos ficam mascarados. Pesquisa local em título, URL, usuário, tags e notas, com filtro de favoritos. Pesquisa não inclui senhas nem valores secretos.
- Gerador no Rust com CSPRNG: padrão de 24 caracteres; comprimento configurável de 16 a 128, classes configuráveis e opção de excluir caracteres ambíguos. Amostragem sem viés e garantia das classes selecionadas; rejeitar opções impossíveis.
- Revelar segredo apenas por ação explícita, por até 15 segundos; remascarar ao perder foco, navegar ou bloquear. Copiar sem devolver segredo ao JavaScript quando possível.
- Excluir com confirmação; sem lixeira no MVP. Explicar que backups antigos e retenção física do armazenamento podem manter versões anteriores.
- Alterar senha mestra, criar backup, restaurar como cofre independente e bloquear manualmente. Sem recuperação se a senha correspondente for perdida.
- Acessibilidade: teclado completo, foco visível, rótulos, contraste AA, mensagens sem depender só de cor. Nunca incluir segredos em atributos de acessibilidade, títulos de janela ou notificações.

## 3. Threat model

### Ativos e fronteiras

Ativos: senha mestra, chaves, todos os campos das credenciais, consultas, clipboard e backups. Fronteiras: disco versus memória; WebView versus Rust; cofre versus arquivo importado; aplicativo versus sistema operacional; distribuição versus instalação.

| Ameaça | Mitigação e limite |
| --- | --- |
| Cópia do SQLite, WAL, SHM ou backup com app bloqueado | Todos os dados do usuário são AEAD; Argon2id encarece ataques offline. Senha fraca continua vulnerável. |
| Alteração de ciphertext, cabeçalho ou troca entre cofres | Tags GCM, AAD contextual, parser estrito e validação do conteúdo. Falhar sem liberar dados parciais. |
| Replay de backup ou banco antigo completo | Não há prevenção confiável offline sem estado externo confiável. Revisões e datas informam, mas não provam atualidade. |
| Reutilização de nonce após falha, restore ou cópia do banco | Uma nova DEK aleatória por snapshot e uso único de nonce por chave; nunca continuar escrevendo com chave recuperada. |
| XSS ou WebView comprometida | Conteúdo como texto, CSP, nenhuma navegação remota, IPC mínimo. Frontend comprometido durante desbloqueio ainda pode capturar a senha e dados acessíveis. |
| Leitura indevida por outro usuário local | Permissões privadas nos arquivos, sem plaintext persistente. Administrador/root e malware no mesmo usuário não são isolados por essas medidas. |
| Clipboard e observação da tela | Expiração, mascaramento e bloqueio; histórico/sincronização de clipboard, capturas e outros processos podem reter cópias. |
| Arquivo malicioso / DoS | Limites de tamanho, profundidade, KDF, quantidade e concorrência antes de alocar ou derivar. |
| Dependência ou instalador adulterado | Lockfiles, revisão, auditoria de dependências, assinatura de distribuição e builds rastreáveis. |

Fora da proteção garantida: keylogger, SO comprometido, acesso administrativo, injeção no processo, leitura de memória enquanto desbloqueado, câmera, coerção, perda física sem backup e indisponibilidade causada por exclusão. Zeroização é melhor esforço: JavaScript, cópias do sistema, swap e crash dumps impedem garantia de apagamento total. O aplicativo não promete apagamento seguro em SSD.

## 4. Arquitetura e responsabilidades

React renderiza telas e mantém apenas o mínimo necessário para a interação. Nunca acessa SQLite, arquivos, criptografia ou APIs genéricas de sistema. Não usar localStorage, sessionStorage, IndexedDB, caches de service worker ou persistência de estado com dados do cofre.

Rust concentra KDF, AEAD, RNG, banco, validação, sessão, busca, gerador, clipboard e backups. Módulos sugeridos: crypto, format, storage, session, vault_service, backup, clipboard, commands e errors. Camada de domínio independente de Tauri permite testes sem WebView.

Dependências candidatas: crates RustCrypto argon2 e aes-gcm, getrandom/rand com fonte do SO, zeroize/secrecy, rusqlite e serde com parser binário adequado. Verificar APIs, versões estáveis e manutenção no início; fixar versões resolvidas em Cargo.lock e lockfile JavaScript. Não inventar primitivas, fallback criptográfico nem RNG próprio.

## 5. Formato e envelope encryption

### Decisão de armazenamento

MVP usa um snapshot completo criptografado, em vez de linhas pesquisáveis. Todos os campos de negócio são serializados juntos e criptografados: títulos, URLs, usuários, senhas, notas, tags, favoritos, nomes/valores de campos personalizados, identificadores de entradas e timestamps. Isso evita índices de pesquisa em claro e divergências de autenticação entre registros.

Metadados técnicos ficam públicos: magic, versões, algoritmos, parâmetros KDF, salt, nonces, comprimentos, identificador aleatório do cofre, revisão e envelopes. Número de arquivos, tamanho aproximado, frequência de escrita e cabeçalhos SQLite também vazam. Não prometer que literalmente todos os bytes do arquivo são secretos.

### Chaves e parâmetros

- AES-256-GCM: chave de 32 bytes, nonce de 12 bytes, tag completa de 16 bytes; nunca truncar tag.
- Argon2id versão 0x13: salt aleatório de 32 bytes e saída de 32 bytes para KEK. Perfil inicial m=65.536 KiB, t=3, p=4. Registrar o custo real; calibrar para aproximadamente 500–1.500 ms no dispositivo, sem baixar o piso de memória ou iterações. Permitir t=3..10 e m=65.536..262.144 KiB, p=1..4; valores fora disso exigem migração explícita futura, não execução arbitrária de arquivo recebido.
- Fonte de aleatoriedade exclusivamente CSPRNG do SO; qualquer falha aborta a operação sem persistir resultado incompleto.
- A senha só deriva a KEK. A KEK cifra uma DEK aleatória de 32 bytes. A DEK cifra o snapshot: este é o envelope encryption do projeto.

### Nonce único, inclusive após rollback

Em CADA commit, criar uma DEK nova de 256 bits e usá-la para EXATAMENTE UMA operação AES-GCM do snapshot, com nonce de 12 bytes zero. Nunca reutilizar a DEK para outra criptografia, retry, backup, migração ou edição; uma falha descarta a chave. O nonce fixo só é permitido porque a chave é de uso único. Não usar um nonce fixo com chave persistente.

Em CADA envelope, gerar salt Argon2id novo, derivando uma KEK nova, e usá-la para EXATAMENTE UMA operação GCM de wrapping da DEK, também com nonce zero. Nunca reutilizar KEK recuperada para novo wrapping. Separar os domínios snapshot e wrapping na AAD. A unicidade é condicionada à qualidade do CSPRNG e à improbabilidade de repetição de chaves/salts; falha de RNG é fatal. Não usar contador persistente recuperável de backup como única defesa.

Consequência deliberada: cada salvamento exige nova derivação Argon2id. A senha mestra permanece em buffer protegido no Rust enquanto desbloqueado para permitir isso; documentar esse custo e exposição. Não armazenar a KEK como substituto para a senha e não reutilizar salt para ganhar desempenho. Executar KDF em worker limitado, sem bloquear UI. O MVP não faz autosave por tecla; salva por ação explícita.

### Codificação e AAD

Usar formato binário versionado e determinístico, com inteiros de tamanho e endianness definidos, comprimentos explícitos e sem campos duplicados. Documentar byte a byte em docs/format.md antes de implementar; JSON não canônico não pode ser AAD por concatenação informal.

Definir H como cabeçalho canônico contendo magic KVLT, format_version=1, schema_version=1, suite_id, vault_id aleatório de 16 bytes, revision u64, parâmetros KDF completos, salt, nonces e comprimentos esperados.

1. Payload interno contém vault_id, revision e coleção completa; validar igualdade com H após autenticação.
2. data_ciphertext = GCM(DEK, nonce_data, payload, AAD = domínio UTF-8 `KeyVault/snapshot/v1` com comprimento + H).
3. wrapped_dek = GCM(KEK, nonce_wrap, DEK, AAD = domínio `KeyVault/wrap/v1` com comprimento + H + SHA-256(data_ciphertext)).
4. Envelope final: H, wrapped_dek de 48 bytes e data_ciphertext com tag. Hash serve para vincular ciphertext ao envelope, não substitui autenticação.

Calcular comprimentos antes da criptografia. Não incluir o próprio wrapped_dek em H. Todos os parâmetros públicos são autenticados por AAD; antes de autenticar, tratá-los como hostis e validar limites. Descriptografar wrapper, depois payload, sem expor bytes até validar ambas as tags e o schema. Não usar resultados parciais de APIs de streaming.

Limites MVP: arquivo de até 64 MiB; payload de até 32 MiB; até 10.000 entradas; texto de até 1 MiB por campo, 100 tags/entrada, 100 campos personalizados/entrada, profundidade estrutural máxima 16. Validar também o tamanho agregado. Sem compressão no MVP. Uma única mensagem pequena por DEK evita atingir limites de volume de GCM.

## 6. SQLite e durabilidade

Schema público mínimo: vault_state(slot INTEGER PRIMARY KEY CHECK(slot=1), envelope BLOB NOT NULL). user_version contém apenas versão técnica do banco. Não armazenar dados de negócio em outras tabelas, índices, FTS, nomes de arquivo ou logs.

SQLite não é considerado cifrado por inteiro: somente o envelope guarda dados privados. SQL parametrizado; journal_mode=WAL, synchronous=FULL, temp_store=MEMORY, permissões privadas e conexão única de escrita. WAL, SHM e journal recebem somente envelope/ciphertext. secure_delete pode ser defesa adicional, sem promessa de apagar SSD.

Fluxo salvar: serializar snapshot candidato; gerar envelope totalmente novo; transação substitui slot=1; commit; somente então atualizar estado visível como salvo. Falha preserva snapshot anterior e permite tentar novamente com novas chaves. UI indica mudanças não salvas. Serializar mutações sob mutex/ator e usar revisão esperada para rejeitar gravação obsoleta. Apenas uma instância por cofre; bloquear segundo processo, inclusive via caminho alternativo quando identificável.

Crash antes ou depois do commit deve recuperar versão anterior ou nova completa. Nunca truncar banco para recuperar erro. Arquivos no diretório privado de dados da aplicação, ACL restrita no Windows e modo 0700/0600 quando aplicável. Não colocar em diretório temporário ou pasta sincronizada por padrão.

Troca de senha: exigir senha atual e confirmação da nova; gerar snapshot e envelope novos sob a nova senha, commit atômico. Após commit, trocar buffer da senha em memória. Backups e páginas antigas podem continuar abrindo com senha antiga; mudança não revoga cópias existentes.

## 7. Sessão, bloqueio e memória

Estados: Uninitialized, Locked, Unlocking, Unlocked, Locking e Error. Toda operação verifica estado e geração da sessão no Rust. Bloqueio incrementa geração, impede novos comandos sensíveis, cancela trabalhos pendentes e impede respostas antigas de repovoar UI.

Padrão de inatividade: 5 minutos, configurável de 1 a 30 minutos. Deadline monotônico no backend; eventos de atividade limitados a interações reais da janela e com rate limit. Verificar expiração antes de todo comando sensível. Bloquear ao bloquear sessão do SO, suspender, trocar usuário e fechar app. Ao retomar, sempre exigir senha. Perda de foco remascara imediatamente; opção para bloquear após 30 segundos fora de foco, ativada por padrão. Integrações de SO precisam de testes reais; não alegar cobertura sem implementação.

Ao bloquear: remover chave, senha, snapshot, resultados de pesquisa, formulários e segredos revelados; limpar clipboard próprio quando ainda contém o mesmo conteúdo. Backend guarda buffers zeroizáveis, evita clones e elimina intermediários; não serializa chaves para frontend. React limpa estado e desmonta componentes; não há garantia de zeroização no heap JavaScript.

Clipboard: ação explícita, padrão 20 segundos e máximo 60. Antes de limpar, verificar se ainda contém exatamente o conteúdo copiado; não apagar conteúdo novo do usuário. Comparação e escrita também têm janela de corrida do SO; não garantir atomicidade inexistente. Não registrar conteúdo nem hashes persistentes. Falhas de limpeza são exibidas sem o segredo. Explicar limitação do histórico e da sincronização do SO.

Tentativas erradas: erro externo genérico “Não foi possível desbloquear: senha incorreta ou cofre inválido”; atraso progressivo em memória, limitado a 30 segundos, sem apagar cofre. Limitar uma KDF ativa. Isso não impede brute force offline nem sobrevive como defesa confiável a reinício.

## 8. IPC e WebView restritos

Expor somente comandos tipados de domínio: vault_status, vault_create, vault_unlock, vault_lock, entries_list, entry_get, entry_save, entry_delete, entries_search, password_generate, entry_reveal_secret, entry_copy_secret, vault_change_password, backup_export, backup_restore e session_activity. Documentar DTO, estados permitidos, limites e erros de cada um. entry_get omite senha e campos secretos; revelação é separada e temporária. DTOs de listagem contêm só campos necessários.

Não expor executar SQL, ler arquivo arbitrário, executar shell, abrir URL arbitrária, eval, HTTP genérico ou recuperar chave. Comandos de segredo exigem sessão ativa e identificador válido; origem/janela é verificada no Rust. Um frontend comprometido pode invocar comandos autorizados: a allowlist reduz superfície, não comprova gesto humano.

Tauri 2: capabilities limitadas à janela local principal; negar por padrão, sem remote URLs e sem wildcard amplo. Registrar explicitamente permissões dos comandos próprios via manifesto/ACL Tauri e testar invocações negadas. Plugins de shell, HTTP, updater, filesystem genérico e clipboard no frontend ficam ausentes. Diálogos de backup são disparados pelo Rust; aceitar somente destinos escolhidos por diálogo da operação, com escopo efêmero e sem caminho arbitrário enviado pelo JS.

CSP de produção: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; object-src 'none'; base-uri 'none'; frame-src 'none'; form-action 'none'; connect-src restrito aos endpoints IPC locais exatos exigidos pelo Tauri na plataforma. Validar esses endpoints na documentação vigente e no build real. Proibir unsafe-eval, scripts remotos e liberações amplas. Se biblioteca exigir estilos inline, resolver integração ou registrar exceção mínima revisada, sem enfraquecer scripts. Dev server/HMR só no desenvolvimento.

Sem HTML cru, dangerouslySetInnerHTML, Markdown com HTML ativo, conteúdo remoto, webfonts remotas ou navegação externa. URLs são dados exibidos como texto no MVP. Desativar devtools e mapas de fonte distribuídos em produção, sem tratar isso como barreira de segurança.

## 9. Backups autenticados e restauração

Formato .keyvault: o mesmo envelope versionado completo, independente do SQLite. Backup é um novo snapshot cifrado com nova DEK e novo salt/KEK, sob a senha mestra atual; nunca copiar banco aberto ou arquivos WAL isolados. Exportar somente após confirmar que não há alterações não salvas ou concluir seu salvamento. Não oferecer backup em claro.

Escrever arquivo temporário privado no mesmo volume, sincronizar e publicar por rename atômico quando suportado. Não sobrescrever destino existente sem confirmação; limpar temporário em falhas. Em plataformas sem garantia equivalente, documentar comportamento e preservar destino anterior. Nenhum plaintext em disco temporário.

Restaurar valida tamanho e cabeçalho antes da KDF, pede a senha do backup, autentica todo envelope, valida payload e somente então permite revisão de contagem e confirmação. Cria novo cofre em destino novo, com novo vault_id, revisão inicial, nova DEK, novo salt e senha nova confirmada. Nunca substituir o cofre atual no MVP. Não importar parcialmente dados inválidos; falha deixa origem e destino anterior intactos.

Backup antigo exige senha usada na sua criação. Não há revogação, recuperação de senha ou prova criptográfica de que é o backup mais recente. Usuário deve manter cópias em mídia separada e testar restauração. Não exibir conteúdo antes de autenticar.

## 10. Privacidade, erros e distribuição

Zero telemetria: sem analytics, crash reporting remoto, pings de versão, licença, updater, fontes/CDNs ou requisições do aplicativo em runtime. Instalação de dependências durante desenvolvimento é separada do runtime. Recursos de rede próprios do SO/WebView não devem ser atribuídos ao app sem medição; documentar limitações e minimizar configuração que os ativa.

Logs de produção só códigos de operação/erro sem dados do usuário, caminhos completos, parâmetros IPC, queries, entradas, senha ou material criptográfico. Não capturar dumps com segredos por iniciativa do app. Não enviar logs automaticamente. Erros de validação podem identificar o campo, nunca reproduzir seu conteúdo. Tratar entradas importadas como hostis, inclusive mensagens e nomes.

Assinar instaladores destinados à distribuição; registrar versões, checksums e processo de build. Auditoria cargo/npm e análise de licenças; vulnerabilidade relevante sem correção bloqueia release ou exige decisão documentada de risco antes de distribuir. Não prometer build reproduzível sem comprová-lo.

## 11. Plano de testes obrigatório

| Área | Evidência exigida |
| --- | --- |
| Primitivas | Vetores oficiais Argon2id e AES-GCM, incluindo AAD, tag errada e payload vazio; bibliotecas mantidas, sem implementação própria. |
| Envelope | Roundtrip e senha errada; alteração de cada campo do cabeçalho, salt, nonce, DEK cifrada, payload, tag e comprimento; trocar wrapper/payload entre cofres e revisões falha. |
| Unicidade | Instrumentar pares chave/nonce apenas em testes com dados artificiais: salvar, retry, crash, restore, backup, troca de senha e migração geram novas chaves. Chave de uso único não pode ser reutilizada pela API. RNG com falha deve abortar. |
| Parsing | Fuzzing de cabeçalhos e payloads; arquivos truncados, duplicados, desconhecidos, oversized, overflow e parâmetros KDF hostis falham sem panic, alocação excessiva ou liberação parcial. |
| Persistência | Kill/fault injection antes e depois do commit; duas escritas concorrentes; segundo processo; disco cheio e falta de permissão. Sempre preservar versão completa válida. |
| Confidencialidade | Inserir canários distintos em TODOS os campos; procurar UTF-8/UTF-16 no SQLite, WAL, SHM, temporários, backup, logs e armazenamento WebView após CRUD, backup e migração. Ausência de canário é evidência adicional, não prova criptográfica. |
| Sessão | Expiração no backend mesmo sem timer JS; bloqueio durante KDF/escrita/revelação; resposta IPC tardia descartada; suspensão e bloqueio reais do Windows; clipboard novo preservado. |
| IPC/UI | Comandos negados de janela não autorizada, caminho arbitrário rejeitado, sessão ausente, IDs inválidos, carga XSS exibida como texto, CSP efetiva no build de produção. |
| Backup | Roundtrip independente, senha antiga após troca, corrupção em qualquer parte, cancelamento, falta de espaço, destino existente e restauração que não modifica cofre atual. |
| Rede | Executar build instalado em ambiente isolado monitorado: criar, desbloquear, editar, gerar, pesquisar e fazer backup sem chamadas de rede originadas pelo aplicativo. |
| UX | Fluxos completos, teclado, leitor de tela, foco, máscara, colagem, mensagens, recuperação de erro e dados não salvos. |

Usar testes unitários e integração Rust; Vitest/Testing Library para componentes e fluxo de estado; E2E no desktop para fronteiras nativas. Registrar comandos, plataforma, versões e resultados reais. Mocks não substituem testes de suspensão, filesystem, ACL ou WebView. CI sem credenciais reais. Benchmarks medem desbloqueio, salvamento e pesquisa no limite suportado; sem relaxar criptografia para cumprir metas.

## 12. Critérios de aceite e entregas

- [ ] Build de produção Windows executa offline com a stack exigida; versões e lockfiles registrados.
- [ ] Criar, desbloquear, CRUD, pesquisar, gerar, revelar/copiar, bloquear, trocar senha, backup e restore funcionam com erros tratados.
- [ ] Todos os campos de negócio estão dentro do snapshot cifrado; só metadados técnicos explicitamente listados permanecem públicos.
- [ ] Envelope e AAD documentados byte a byte, com vetores de integração estáveis; nenhuma reutilização de chave/nonce nos cenários testados.
- [ ] Senha errada ou qualquer adulteração falha fechada; nenhum resultado parcial é exibido ou persistido como válido.
- [ ] Limites de parser/KDF, transações, concorrência e falhas de energia passam nos testes definidos.
- [ ] Bloqueio e expiração são impostos pelo Rust; resultados de sessão encerrada não reaparecem.
- [ ] IPC tem allowlist testada, CSP efetiva e ausência de APIs genéricas perigosas.
- [ ] Backup é autenticado, independente e restaurável em novo cofre; fluxo de perda de senha é explicado.
- [ ] Nenhum segredo em logs, storage do frontend ou arquivos temporários; nenhuma telemetria ou rede do app em runtime.
- [ ] Checks de compilação, lint, tipos, testes, dependências e revisão de segurança concluídos; limitações e falhas remanescentes documentadas sem alegações falsas.

Entregar código modular, README com instalação/build e uso, docs/format.md, docs/threat-model.md, docs/security.md, docs/testing.md, procedimento de backup/restauração, inventário de dependências e relatório de validação. Dados de demonstração exclusivamente fictícios. Revisão independente antes de guardar segredos de produção é requisito de lançamento, não substituída por uma declaração do implementador.

## 13. Referências técnicas

Consultadas em 23/11/2026. Validar APIs atuais antes da implementação. Os limites, o formato de snapshot e o protocolo de backup acima são decisões deste projeto; não são um padrão publicado nem certificação.

- RFC 9106, Argon2: https://www.rfc-editor.org/rfc/rfc9106.html
- Tauri 2, fronteiras e segurança: https://v2.tauri.app/security/
- Tauri 2, capabilities e escopo: https://v2.tauri.app/security/capabilities/
- Tauri 2, configuração: https://v2.tauri.app/reference/config/
- Libsodium, cuidados com AES-GCM e unicidade de nonce: https://doc.libsodium.org/secret-key_cryptography/aead/aes-256-gcm

A referência Libsodium sustenta cuidados operacionais; a implementação Rust deve usar a biblioteca Rust selecionada e seus vetores/documentação, sem assumir que APIs Libsodium existem em RustCrypto.
