# KeyVault — formato binário do envelope (v1)

Status: normativo para a implementação `keyvault-core` 0.1.0. Este documento foi escrito **antes**
da camada criptográfica e deriva das seções 5, 6 e 9 de `KEYVAULT.md` (especificação 1.0).
Ele é uma decisão de projeto do KeyVault, não um padrão publicado.

## 1. Convenções

- Todos os inteiros são **little-endian**, sem sinal, salvo indicação (`i64` = complemento de dois LE).
- `bytes[n]` = sequência de exatamente `n` bytes.
- `str` = `u32` com o comprimento em bytes seguido de exatamente esse número de bytes UTF-8 válidos
  (sem terminador, sem BOM, sem normalização). Comprimento máximo: 1.048.576 bytes (1 MiB).
- `bool` = `u8` com valor `0` ou `1`; qualquer outro valor é inválido.
- `||` = concatenação.
- Nenhum campo é opcional, nenhum campo é repetido, não há campos desconhecidos tolerados e não há
  bytes sobrando no fim de nenhuma estrutura. Qualquer violação é erro fatal de parsing.
- A codificação é determinística: um mesmo valor lógico tem uma única serialização.

## 2. Primitivas e parâmetros (suite_id = 1)

| Item | Valor |
| --- | --- |
| KDF | Argon2id, versão `0x13` (RFC 9106), sem `secret` e sem `associated data` do Argon2 |
| Entrada da KDF | bytes UTF-8 exatos da senha mestra (sem trim, normalização ou truncamento) |
| Salt | 32 bytes do CSPRNG do sistema operacional, novo a cada envelope |
| Saída da KDF | 32 bytes = KEK |
| AEAD | AES-256-GCM, chave 32 bytes, nonce 12 bytes, tag 16 bytes (nunca truncada) |
| DEK | 32 bytes do CSPRNG do sistema operacional, nova a cada envelope |
| Hash de vinculação | SHA-256 |

Limites aceitos de KDF (validados **antes** de alocar memória ou derivar):

| Parâmetro | Mínimo | Máximo | Padrão inicial |
| --- | --- | --- | --- |
| `m_cost` (KiB) | 65.536 | 262.144 | 65.536 |
| `t_cost` | 3 | 10 | 3 |
| `p_cost` | 1 | 4 | 4 |
| saída | 32 | 32 | 32 |

Valores fora dessas faixas são rejeitados (`KdfParamsOutOfRange`) sem executar a KDF. Ampliações
futuras exigem nova versão de formato/migração explícita.

## 3. Cabeçalho canônico `H` (132 bytes)

| Offset | Tamanho | Campo | Valor/restrição |
| ---: | ---: | --- | --- |
| 0 | 4 | `magic` | ASCII `KVLT` = `4B 56 4C 54` |
| 4 | 2 | `format_version` | `1` |
| 6 | 2 | `schema_version` | `1` |
| 8 | 2 | `suite_id` | `1` (Argon2id-0x13 / AES-256-GCM / SHA-256) |
| 10 | 2 | `header_len` | `132` |
| 12 | 16 | `vault_id` | aleatório; não pode ser todo zero |
| 28 | 8 | `revision` | `u64`, `1 ≤ revision ≤ 2^63-1` |
| 36 | 4 | `kdf_version` | `0x13` |
| 40 | 4 | `kdf_m_cost_kib` | 65.536..262.144 |
| 44 | 4 | `kdf_t_cost` | 3..10 |
| 48 | 4 | `kdf_p_cost` | 1..4 |
| 52 | 4 | `kdf_output_len` | `32` |
| 56 | 2 | `salt_len` | `32` |
| 58 | 32 | `salt` | aleatório |
| 90 | 2 | `nonce_len` | `12` |
| 92 | 12 | `nonce_wrap` | 12 bytes zero (ver §6) |
| 104 | 12 | `nonce_data` | 12 bytes zero (ver §6) |
| 116 | 2 | `tag_len` | `16` |
| 118 | 2 | `envelope_kind` | `1` = slot do banco (`vault_state`), `2` = backup `.keyvault` |
| 120 | 4 | `wrapped_dek_len` | `48` (32 da DEK + 16 de tag) |
| 124 | 8 | `data_ciphertext_len` | `16 + len(payload)`; `16 ≤ x ≤ 33.554.448` |

`envelope_kind` é autenticado (está em `H`) e separa o contexto de uso: o banco só aceita `1` e a
restauração só aceita `2`. Um envelope de backup copiado para o banco (ou vice-versa) falha antes da
KDF.

`H` **não** contém `wrapped_dek` nem o ciphertext; contém apenas seus comprimentos esperados, que são
calculados antes de qualquer criptografia.

## 4. Envelope completo

```
envelope = H (132) || wrapped_dek (48) || data_ciphertext (data_ciphertext_len)
```

- `wrapped_dek = AES-256-GCM-Enc(KEK, nonce_wrap, DEK, AAD_wrap)` = 32 bytes de ciphertext || 16 de tag.
- `data_ciphertext = AES-256-GCM-Enc(DEK, nonce_data, payload, AAD_snapshot)` = ciphertext || tag de 16.
- Tamanho total exato: `180 + data_ciphertext_len`. Bytes faltando ou sobrando são inválidos.
- Tamanho máximo do arquivo/blob aceito antes do parsing: 67.108.864 bytes (64 MiB). Na prática o
  limite do payload (32 MiB) produz envelopes de no máximo 33.554.628 bytes.

## 5. AAD e separação de domínios

```
D_snapshot = "KeyVault/snapshot/v1"   (UTF-8, 20 bytes)
D_wrap     = "KeyVault/wrap/v1"       (UTF-8, 16 bytes)

AAD_snapshot = u16le(20) || D_snapshot || H
AAD_wrap     = u16le(16) || D_wrap     || H || SHA-256(data_ciphertext)
```

`SHA-256(data_ciphertext)` é calculado sobre o `data_ciphertext` completo **incluindo a tag**. O hash
vincula o wrapper ao payload específico (impede trocar o wrapper de um envelope pelo de outro com o
mesmo `H`); não substitui a autenticação GCM do payload.

Tamanhos: `AAD_snapshot` = 154 bytes; `AAD_wrap` = 182 bytes.

## 6. Unicidade de chave/nonce

O nonce de 96 bits zero só é permitido porque **cada chave participa de exatamente uma cifragem GCM**:

- Em cada envelope (commit, retry, backup, restauração, migração, troca de senha) gera-se uma DEK nova
  de 256 bits e um salt novo de 256 bits; a KEK é derivada desse salt novo.
- A DEK cifra uma única mensagem (o payload). A KEK cifra uma única mensagem (a DEK).
- Uma DEK/KEK recuperada na abertura de um envelope só pode **decifrar**; a API não oferece cifragem com
  chave recuperada (tipos distintos `FreshDek`/`FreshKek` × `OpenedDek`/`OpeningKek`, consumidos por valor).
- Qualquer falha descarta (zera) as chaves; nova tentativa gera material novo.
- Falha do CSPRNG aborta a operação sem produzir nem persistir envelope.
- A unicidade é probabilística e condicionada à qualidade do CSPRNG do SO (colisão de DEK de 256 bits
  ou de par (senha, salt de 256 bits) é desprezível).

O parser exige `nonce_wrap` e `nonce_data` iguais a zero na versão 1.

## 7. Payload (texto claro, existe somente na memória do processo Rust)

```
payload =
  payload_magic      bytes[4]  = ASCII "KVP1"
  vault_id           bytes[16]       (DEVE ser igual a H.vault_id)
  revision           u64             (DEVE ser igual a H.revision)
  auto_lock_minutes  u16             1..30   (padrão 5)
  clipboard_seconds  u16             5..60   (padrão 20)
  lock_on_blur       bool            (padrão 1)
  reserved           u8              = 0
  entry_count        u32             0..10.000
  entries            entry[entry_count]

entry =
  entry_id           bytes[16]       aleatório, não-zero, único no cofre
  created_at_ms      i64             0..253.402.300.799.999 (Unix ms, UTC)
  updated_at_ms      i64             created_at_ms..253.402.300.799.999
  favorite           bool
  title              str             1 a 1 MiB bytes
  url                str             0 a 1 MiB
  username           str             0 a 1 MiB
  password           str             0 a 1 MiB
  notes              str             0 a 1 MiB
  tag_count          u16             0..100
  tags               str[tag_count]  cada 1 a 1 MiB, sem duplicatas exatas
  field_count        u16             0..100
  fields             field[field_count]

field =
  field_id           bytes[16]       aleatório, não-zero, único dentro da entrada
  secret             bool
  name               str             1 a 1 MiB
  value              str             0 a 1 MiB
```

Regras adicionais:

- `len(payload) ≤ 33.554.432` (32 MiB), validado na serialização (antes de cifrar) e no parsing
  (`data_ciphertext_len - 16`).
- Profundidade estrutural: payload → entry → field → str = 4 (limite normativo: 16).
- Contagens são validadas contra o limite **e** contra os bytes restantes (cada `entry` ocupa pelo menos
  58 bytes, cada tag 5, cada `field` 26; o cabeçalho do payload tem 38 bytes) antes de reservar
  memória.
- Todos os campos de negócio (títulos, URLs, usuários, senhas, notas, tags, favoritos, ids de entradas e
  campos, datas, nomes/valores de campos personalizados) e as preferências do cofre existem **somente**
  dentro do payload cifrado.

## 8. Algoritmo de escrita

1. Validar e serializar o snapshot candidato em buffer zeroizável (`P`). Abortar se exceder limites.
2. Ler 32 bytes do CSPRNG para a DEK e 32 bytes para o salt. Falha → abortar.
3. Montar `H` com `data_ciphertext_len = len(P) + 16`, `wrapped_dek_len = 48` e o `envelope_kind`.
4. `KEK = Argon2id(senha, salt, m, t, p, 32)`.
5. `C = GCM-Enc(DEK, 0^96, P, AAD_snapshot)`; a DEK não cifra mais nada.
6. `W = GCM-Enc(KEK, 0^96, DEK, AAD_wrap)`, com `SHA-256(C)`; a KEK é descartada.
7. `envelope = H || W || C`. Zerar `P`, DEK e KEK.

## 9. Algoritmo de leitura (falha fechada)

1. Rejeitar blobs maiores que 64 MiB ou menores que 196 bytes (132 + 48 + 16).
2. Validar `H` campo a campo (magic, versões, suite, `header_len`, `envelope_kind` esperado, faixas de
   KDF, comprimentos fixos, nonces zero, `data_ciphertext_len` e tamanho total exato).
3. Derivar a KEK com os parâmetros já validados (no máximo uma KDF ativa por processo na aplicação).
4. Calcular `SHA-256(C)`; decifrar `W` com `AAD_wrap`. Falha → erro genérico de autenticação.
5. Decifrar `C` com a DEK recuperada e `AAD_snapshot`. A API não-streaming verifica a tag antes de
   devolver qualquer byte. Falha → erro genérico de autenticação.
6. Fazer o parsing estrito do payload e comparar `vault_id`/`revision` com `H`. Falha → erro de conteúdo.
7. Só então o snapshot é entregue ao serviço. Nenhum resultado parcial é exposto em nenhum passo.

Externamente, senha incorreta e cofre adulterado produzem a mesma mensagem:
“Não foi possível desbloquear: senha incorreta ou cofre inválido”.

## 10. Armazenamento SQLite

```sql
CREATE TABLE vault_state(slot INTEGER PRIMARY KEY CHECK(slot = 1), envelope BLOB NOT NULL);
PRAGMA user_version = 1;
```

Apenas o envelope com `envelope_kind = 1` é gravado. Commit: `BEGIN IMMEDIATE`, ler o cabeçalho público
do envelope atual e comparar `revision` com a revisão esperada, `INSERT OR REPLACE` do novo envelope
(revisão esperada + 1), `COMMIT`. `journal_mode=WAL`, `synchronous=FULL`, `temp_store=MEMORY`,
`secure_delete=ON`.

## 11. Backup `.keyvault`

O arquivo de backup é exatamente um envelope com `envelope_kind = 2`, gerado com DEK, salt e KEK novos
sob a senha mestra atual. Mesmo `vault_id` e `revision` do cofre de origem (são metadados públicos). A
restauração cria um cofre novo com novo `vault_id`, `revision = 1`, `envelope_kind = 1`, DEK/salt/KEK
novos e senha nova confirmada.

## 12. Vetores de integração

Os vetores abaixo usam material **fictício** injetado por uma fonte de aleatoriedade determinística
disponível apenas em testes. São verificados pelo teste `integration_vector_v1` em
`src-tauri/core/tests/vectors.rs` e, de forma independente, por `tools/vectors/verify_vector.py`
(Python `cryptography` + `argon2-cffi`).

Entradas:

- senha: UTF-8 de `"senha de teste fictícia 🔐 não use"`
- sequência de aleatoriedade: DEK = bytes `0x00..0x1f`; salt = bytes `0x20..0x3f`
- `vault_id` = `0x40..0x4f`; `revision` = 1; KDF m=65.536, t=3, p=4; `envelope_kind` = 1
- payload: `auto_lock_minutes=5`, `clipboard_seconds=20`, `lock_on_blur=1`, uma entrada:
  - `entry_id` = `0x50..0x5f`, `created_at_ms` = `updated_at_ms` = 1.763.856.000.000, `favorite=1`
  - título `"Exemplo n8n"`, URL `"https://n8n.exemplo.invalid"`, usuário `"usuario.ficticio"`,
    senha `"S3nh@-Fict1cia"`, notas `"linha 1\nlinha 2"`, tags `["infra","teste"]`
  - campo `field_id` = `0x60..0x6f`, `secret=1`, nome `"API key"`, valor `"chave-ficticia-123"`

Resultados esperados:

<!-- VECTOR-START -->
- comprimento do envelope: 442 bytes (`data_ciphertext_len` = 262; payload = 246 bytes)
- KEK (Argon2id): `dd4c500a62fa32554412cc0665000ecf21213b6062264da8111ca6185713e803`
- SHA-256 do envelope: `235a289c469e817419203e3e188251638d2bce5dd1b20d709fe4c09347fffcce`
- envelope completo (hex), também em `tools/vectors/vector_v1.hex`:

```
4b564c540100010001008400404142434445464748494a4b4c4d4e4f01000000
0000000013000000000001000300000004000000200000002000202122232425
262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f0c0000000000
0000000000000000000000000000000000000000100001003000000006010000
000000008b7428c0c64ac96f7a23f1eacb473a25680d3eed481619f16a6935b8
e46223e4d037a82d0928d1c9d3c23f937760fd6a45eae5eff56dc1fe4cedef72
5065dbd29e0e181c2981602f809eb383c0ff49564f5fe7bc2af2e857619025a0
97993117f35c1dbb272e46015218a5274a604e40ebc1a40b91d151e9d389d382
6e4125e9317a16f718c65e4134a67c378a2fa28af87e203f427189d17c141658
ec0ad3335adc3e028c6c119cd067548f055652ed50d8ffef9f406c107368d8fb
40f4b55449186039b7c9b7d7e463185d6e666e8e560cac4439cdd1e3eceed9b6
1c38e8d635ed52c184a6bca704990940a460670f16d0e043ea7eff5647c960df
432b36c07c4526f30cc87dd45420badd0634948239347c8886a1a9896e577472
0b0fb90e11092af1f9bfd2ce6661f00577cad8abc1b205468b9f
```

Verificação independente executada: `python -I tools/vectors/verify_vector.py tools/vectors/vector_v1.hex`
→ "OK: envelope reconstruído independentemente é idêntico ao do Rust".
<!-- VECTOR-END -->
