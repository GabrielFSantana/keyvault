// Gera as capturas de tela do README a partir do app INSTALADO, com dados 100% fictícios.
// Uso: powershell -ExecutionPolicy Bypass -File e2e\run-screenshots.ps1 (diretório de dados sem cofres).
import fs from "node:fs";
import path from "node:path";
import { chromium } from "playwright-core";

const OUT = path.resolve("docs/screenshots");
fs.mkdirSync(OUT, { recursive: true });
const PW = "uma frase longa e ficticia para a demonstracao";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const browser = await chromium.connectOverCDP(`http://127.0.0.1:${process.env.KV_CDP_PORT ?? "9336"}`);
const page = browser
  .contexts()
  .flatMap((c) => c.pages())
  .find((p) => p.url().includes("tauri.localhost"));
page.setDefaultTimeout(60_000);
const cdp = await page.context().newCDPSession(page);
await cdp.send("Emulation.setFocusEmulationEnabled", { enabled: true });
const shot = async (name) => {
  await sleep(400);
  await page.screenshot({ path: path.join(OUT, `${name}.png`) });
  console.log("captura", name);
};
const inv = (cmd, args = {}) =>
  page.evaluate(([c, a]) => window.__TAURI_INTERNALS__.invoke(c, a), [cmd, args]);

// 1) Primeiro uso
await page.getByRole("button", { name: "Criar cofre" }).waitFor();
await page.getByLabel("Senha mestra", { exact: true }).fill(PW);
await page.getByLabel("Confirmar senha mestra", { exact: true }).fill(PW);
await page.getByRole("checkbox").check();
await shot("01-criar-cofre");
await page.getByRole("button", { name: "Criar cofre" }).click();
await page.getByText("Cofre criado. Fazer um backup criptografado agora?").waitFor();
await shot("02-oferta-de-backup");
await page.getByRole("button", { name: "Depois" }).click();

// Dados fictícios via IPC (mesmos comandos usados pela UI).
const st = await inv("vault_status");
const g = st.generation;
const set = (value) => ({ kind: "set", value });
const entries = [
  [
    "n8n (produção)",
    "https://n8n.exemplo.com",
    "automacao@exemplo.com",
    "Instância de automações.\nToken em campo secreto.",
    ["infra", "automacao"],
    true,
    [
      ["API key", true, "n8n_api_ficticia_0123456789"],
      ["Região", false, "sa-east-1"],
    ],
  ],
  [
    "GitHub",
    "https://github.com/login",
    "dev-exemplo",
    "Conta de desenvolvimento.",
    ["dev"],
    true,
    [["Token pessoal", true, "ghp_ficticio_abcdef123456"]],
  ],
  [
    "Docker Hub",
    "https://hub.docker.com",
    "dev-exemplo",
    "Registro de imagens.",
    ["infra", "containers"],
    false,
    [],
  ],
  [
    "Servidor VPS",
    "ssh://203.0.113.10",
    "root",
    "IP de documentação (RFC 5737).",
    ["infra", "servidor"],
    false,
    [["Porta SSH", false, "2222"]],
  ],
  [
    "Banco de dados — staging",
    "postgres://db.staging.exemplo.com",
    "app_staging",
    "Somente leitura para relatórios.",
    ["dados"],
    false,
    [],
  ],
  ["E-mail pessoal", "https://mail.exemplo.com", "fulano@exemplo.com", "", ["pessoal"], false, []],
];
for (const [title, url, username, notes, tags, favorite, fields] of entries) {
  await inv("entry_save", {
    session: g,
    entry: {
      id: null,
      title,
      url,
      username,
      password: set(`Senh@-Ficticia-${title.length}x!`),
      notes,
      tags,
      favorite,
      fields: fields.map(([name, secret, value]) => ({ id: null, name, secret, value: set(value) })),
    },
  });
}
await page.reload();
await page.getByRole("button", { name: "Nova entrada" }).waitFor();

// 3) Lista + detalhe com segredos mascarados
const nav = page.getByRole("navigation", { name: "Entradas" });
await nav.getByText("n8n (produção)").click();
await page.getByRole("button", { name: "Editar" }).waitFor();
await shot("03-cofre-detalhe");

// 4) Segredo revelado temporariamente (≤ 15 s)
await page.getByRole("button", { name: "Revelar API key" }).click();
await page.getByText("n8n_api_ficticia_0123456789").waitFor();
await shot("04-segredo-revelado");

// 5) Pesquisa
await page.getByLabel("Pesquisar em título, URL, usuário, tags e notas").fill("infra");
await sleep(500);
await shot("05-pesquisa");
await page.getByLabel("Pesquisar em título, URL, usuário, tags e notas").fill("");

// 6) Editor com gerador de senhas
await nav.getByText("GitHub").click();
await page.getByRole("button", { name: "Editar" }).click();
await page.getByRole("button", { name: "Opções do gerador" }).click();
await page.getByRole("button", { name: "Gerar" }).first().click();
await page.getByRole("button", { name: "Mostrar" }).first().click();
await shot("06-editor-e-gerador");
await page.getByRole("button", { name: "Cancelar", exact: true }).last().click();
const discard = page.getByRole("button", { name: "Descartar" });
if (await discard.isVisible().catch(() => false)) await discard.click();

// 7) Configurações e segurança
await page.getByRole("button", { name: "Configurações" }).click();
await page.getByRole("heading", { name: "Configurações e segurança" }).waitFor();
await shot("07-configuracoes");
await page.keyboard.press("Escape");

// 8) Tela de bloqueio
await page.getByRole("button", { name: "Bloquear" }).click();
await page.getByRole("button", { name: "Desbloquear" }).waitFor();
await shot("08-bloqueado");

// 9) Restauração como novo cofre
await page.getByRole("button", { name: /Restaurar backup/ }).click();
await page.getByRole("button", { name: "Escolher arquivo…" }).waitFor();
await shot("09-restaurar-backup");

await browser.close();
