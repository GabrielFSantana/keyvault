// E2E do aplicativo INSTALADO (build de produção) via Chrome DevTools Protocol do WebView2.
// Somente dados fictícios. Uso: ver docs/testing.md (e2e/run-e2e.ps1 prepara tudo).
import { execFileSync, spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { chromium } from "playwright-core";

const PORT = process.env.KV_CDP_PORT ?? "9333";
const OUT = process.env.KV_E2E_OUT ?? path.resolve("e2e-out");
fs.mkdirSync(OUT, { recursive: true });

export const CANARIES = {
  title: "CANARIO-E2E-TITULO-a1",
  username: "CANARIO-E2E-USUARIO-b2",
  password: "CANARIO-E2E-SENHA-c3",
  url: "CANARIO-E2E-URL-d4",
  notes: "CANARIO-E2E-NOTAS-e5",
  tag: "CANARIO-E2E-TAG-f6",
  fieldName: "CANARIO-E2E-CAMPO-g7",
  fieldValue: "CANARIO-E2E-SEGREDO-h8",
};
const XSS = '<img src=x onerror="window.__xss=1"><script>window.__xss=2</script>';
const PW1 = "senha mestra e2e ficticia numero um";
const PW2 = "senha mestra e2e ficticia numero dois";
const PW_RESTORED = "senha do cofre restaurado e2e ficticia";

const results = [];
function check(name, ok, detail = "") {
  results.push({ name, ok: !!ok, detail: String(detail).slice(0, 400) });
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail ? ` — ${String(detail).slice(0, 200)}` : ""}`);
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function ps(script) {
  return execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], {
    encoding: "utf8",
  }).trim();
}
function clipboardText() {
  return ps("$t = Get-Clipboard -Raw; if ($null -eq $t) { '<<vazio>>' } else { $t }");
}
function dialog(title, file) {
  return spawn(
    "powershell.exe",
    [
      "-NoProfile",
      "-ExecutionPolicy",
      "Bypass",
      "-File",
      path.resolve("e2e/dialog.ps1"),
      "-Title",
      title,
      "-Path",
      file,
    ],
    { stdio: "pipe" },
  );
}

const browser = await chromium.connectOverCDP(`http://127.0.0.1:${PORT}`);
const page = browser
  .contexts()
  .flatMap((c) => c.pages())
  .find((p) => p.url().includes("tauri.localhost"));
if (!page) throw new Error("página do KeyVault não encontrada via CDP");
page.setDefaultTimeout(30_000);
const violations = [];
await page.exposeBinding("__kvRecordViolation", (_s, v) => violations.push(v)).catch(() => undefined);

// ---------------------------------------------------------------------------------------------
// 1) Origem, CSP efetiva no build de produção e superfície do IPC no WebView2 real
check(
  "origem local do app (http://tauri.localhost)",
  page.url().startsWith("http://tauri.localhost/"),
  page.url(),
);
const cdp = await page.context().newCDPSession(page);
await cdp.send("Network.enable");
// A automação não garante foco do SO na janela; a página só revela segredos com foco (document.hasFocus).
await cdp.send("Emulation.setFocusEmulationEnabled", { enabled: true });
let cspHeader = null;
cdp.on("Network.responseReceived", (e) => {
  if (e.type === "Document")
    cspHeader =
      e.response.headers["Content-Security-Policy"] ?? e.response.headers["content-security-policy"] ?? null;
});
await page.reload();
await page.waitForLoadState("domcontentloaded");
await sleep(500);
check("cabeçalho CSP presente no documento", !!cspHeader, cspHeader);
for (const d of [
  "default-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "frame-src 'none'",
  "form-action 'none'",
  "connect-src ipc: http://ipc.localhost",
]) {
  check(`CSP contém ${d}`, cspHeader?.includes(d), "");
}
check(
  "CSP sem unsafe-eval/unsafe-inline em script-src",
  cspHeader && !/script-src[^;]*unsafe-(eval|inline)/.test(cspHeader),
  cspHeader,
);
fs.writeFileSync(path.join(OUT, "csp.txt"), String(cspHeader));

const cspProbe = await page.evaluate(async () => {
  const out = {};
  const seen = [];
  document.addEventListener("securitypolicyviolation", (e) =>
    seen.push(`${e.violatedDirective} ${e.blockedURI}`),
  );
  try {
    out.eval = String((0, eval)("1+1"));
  } catch (e) {
    out.eval = `bloqueado:${e.name}`;
  }
  try {
    out.fn = String(new Function("return 2")());
  } catch (e) {
    out.fn = `bloqueado:${e.name}`;
  }
  const s = document.createElement("script");
  s.textContent = "window.__inlineRan = true";
  document.head.appendChild(s);
  const st = document.createElement("style");
  st.textContent = "#kvprobe{color:rgb(1, 2, 3)}";
  document.head.appendChild(st);
  const d = document.createElement("div");
  d.id = "kvprobe";
  document.body.appendChild(d);
  out.inlineStyle = getComputedStyle(d).color;
  d.remove();
  out.inlineScript = window.__inlineRan === true;
  out.fetch = await fetch("https://example.com/").then(
    () => "permitido",
    (e) => `bloqueado:${e.name}`,
  );
  out.img = await new Promise((r) => {
    const i = new Image();
    i.onload = () => r("carregou");
    i.onerror = () => r("bloqueado");
    i.src = "https://example.com/x.png";
  });
  out.ws = await new Promise((r) => {
    try {
      const w = new WebSocket("wss://example.com/");
      w.onerror = () => r("bloqueado");
      w.onopen = () => r("conectou");
    } catch (e) {
      r(`bloqueado:${e.name}`);
    }
  });
  out.globalTauri = typeof window.__TAURI__;
  await new Promise((r) => setTimeout(r, 300));
  out.violations = seen;
  return out;
});
fs.writeFileSync(path.join(OUT, "csp-probe.json"), JSON.stringify(cspProbe, null, 2));
// page.evaluate usa Runtime.callFunctionOn, que por padrão IGNORA a CSP para eval (privilégio do depurador);
// por isso eval é testado com allowUnsafeEvalBlockedByCSP=false e por timer com string (contexto da página).
const evalRes = await cdp.send("Runtime.evaluate", {
  expression: "(0, eval)('1+1')",
  allowUnsafeEvalBlockedByCSP: false,
});
const fnRes = await cdp.send("Runtime.evaluate", {
  expression: "new Function('return 2')()",
  allowUnsafeEvalBlockedByCSP: false,
});
check(
  "CSP bloqueia eval (contexto da página)",
  !!evalRes.exceptionDetails,
  JSON.stringify(evalRes.exceptionDetails?.exception?.description ?? evalRes.result).slice(0, 120),
);
check(
  "CSP bloqueia new Function (contexto da página)",
  !!fnRes.exceptionDetails,
  JSON.stringify(fnRes.exceptionDetails?.exception?.description ?? fnRes.result).slice(0, 120),
);
const timerStr = await page.evaluate(
  () =>
    new Promise((r) => {
      window.__strTimer = false;
      try {
        setTimeout("window.__strTimer = true", 0);
      } catch {
        /* bloqueado */
      }
      setTimeout(() => r(window.__strTimer), 200);
    }),
);
check("CSP bloqueia setTimeout com string", timerStr === false, String(timerStr));
check(
  "observação: eval via depurador CDP ignora CSP por desenho do Chromium",
  true,
  `callFunctionOn retornou ${cspProbe.eval}`,
);
check("CSP bloqueia script inline injetado", cspProbe.inlineScript === false, "");
check("CSP bloqueia <style> inline injetado", cspProbe.inlineStyle !== "rgb(1, 2, 3)", cspProbe.inlineStyle);
check("CSP bloqueia fetch remoto", cspProbe.fetch.startsWith("bloqueado"), cspProbe.fetch);
check("CSP bloqueia imagem remota", cspProbe.img === "bloqueado", cspProbe.img);
check("CSP bloqueia WebSocket remoto", String(cspProbe.ws).startsWith("bloqueado"), cspProbe.ws);
check(
  "window.__TAURI__ ausente (withGlobalTauri=false)",
  cspProbe.globalTauri === "undefined",
  cspProbe.globalTauri,
);
check(
  "eventos securitypolicyviolation registrados",
  cspProbe.violations.length >= 3,
  cspProbe.violations.join(" | "),
);

const ipcProbe = await page.evaluate(async () => {
  const inv = window.__TAURI_INTERNALS__?.invoke;
  if (!inv) return { error: "sem __TAURI_INTERNALS__" };
  const out = {};
  for (const cmd of [
    "plugin:fs|read_file",
    "plugin:shell|execute",
    "plugin:http|fetch",
    "plugin:clipboard-manager|read_text",
    "plugin:dialog|open",
    "plugin:opener|open_url",
    "plugin:window|close",
    "plugin:webview|internal_toggle_devtools",
    "execute_sql",
  ]) {
    out[cmd] = await inv(cmd, {}).then(
      () => "PERMITIDO",
      (e) => `negado: ${typeof e === "string" ? e.slice(0, 80) : JSON.stringify(e).slice(0, 80)}`,
    );
  }
  out.status = await inv("vault_status", {}).then(
    (s) => s.phase,
    (e) => `erro ${JSON.stringify(e)}`,
  );
  return out;
});
fs.writeFileSync(path.join(OUT, "ipc-probe.json"), JSON.stringify(ipcProbe, null, 2));
for (const [k, v] of Object.entries(ipcProbe)) {
  if (k === "status")
    check("vault_status permitido para a janela principal", v === "uninitialized" || v === "locked", v);
  else check(`IPC nega ${k} no WebView2 real`, String(v).startsWith("negado"), v);
}

// ---------------------------------------------------------------------------------------------
try {
  // 2) Primeiro uso: criar cofre
  await page.getByLabel("Senha mestra", { exact: true }).fill(PW1);
  await page.getByLabel("Confirmar senha mestra", { exact: true }).fill(PW1);
  await page.getByRole("checkbox").check();
  let t0 = Date.now();
  await page.getByRole("button", { name: "Criar cofre" }).click();
  // O diálogo modal de oferta de backup oculta o restante da UI da árvore de acessibilidade.
  await page.getByText("Cofre criado. Fazer um backup criptografado agora?").waitFor({ timeout: 60_000 });
  check("cofre criado e desbloqueado", true, `${Date.now() - t0} ms (inclui calibração do Argon2id)`);
  check("backup oferecido logo após criar o cofre", true);
  await page.getByRole("button", { name: "Depois" }).click();
  await page.getByRole("button", { name: "Nova entrada" }).waitFor();

  // 3) Nova entrada com canários em todos os campos + XSS
  await page.getByRole("button", { name: "Nova entrada" }).click();
  await page.getByLabel("Título (obrigatório)", { exact: true }).fill(`${CANARIES.title} ${XSS}`);
  await page.getByLabel("Usuário", { exact: true }).fill(CANARIES.username);
  await page.getByRole("button", { name: "Definir" }).first().click();
  await page.getByLabel("Senha", { exact: true }).fill(CANARIES.password);
  await page
    .getByLabel("URL (exibida somente como texto)", { exact: true })
    .fill(`${CANARIES.url} javascript:window.__xss=3`);
  await page.getByLabel("Notas", { exact: true }).fill(`${CANARIES.notes}\n${XSS}`);
  await page.getByLabel("Tags", { exact: true }).fill(`${CANARIES.tag}, infra`);
  await page.getByRole("button", { name: "Adicionar campo" }).click();
  await page.getByLabel("Nome do campo 1", { exact: true }).fill(CANARIES.fieldName);
  await page.getByRole("switch", { name: "Segredo" }).click();
  await page.getByLabel("Valor do campo 1", { exact: true }).fill(CANARIES.fieldValue);
  t0 = Date.now();
  await page.getByRole("button", { name: "Salvar", exact: true }).click();
  await page.getByRole("button", { name: "Editar" }).waitFor();
  check("entrada salva (KDF + commit)", true, `${Date.now() - t0} ms`);
  const xss = await page.evaluate(() => ({
    flag: window.__xss,
    imgs: document.querySelectorAll("main img").length,
    scripts: document.querySelectorAll("main script").length,
    links: document.querySelectorAll("main a").length,
  }));
  check(
    "XSS armazenado é exibido como texto inerte",
    xss.flag === undefined && xss.imgs === 0 && xss.scripts === 0 && xss.links === 0,
    JSON.stringify(xss),
  );

  // 4) Pesquisa
  const search = page.getByLabel("Pesquisar em título, URL, usuário, tags e notas", { exact: true });
  await search.fill(CANARIES.username);
  await sleep(500);
  check(
    "pesquisa encontra por usuário",
    (await page.getByRole("navigation", { name: "Entradas" }).getByRole("button").count()) === 1,
  );
  await search.fill(CANARIES.password);
  await sleep(500);
  check("pesquisa NÃO encontra pela senha", await page.getByText("Nenhuma entrada encontrada.").isVisible());
  await search.fill(CANARIES.fieldValue);
  await sleep(500);
  check(
    "pesquisa NÃO encontra por valor secreto",
    await page.getByText("Nenhuma entrada encontrada.").isVisible(),
  );
  await search.fill("");
  await sleep(400);

  // 5) Revelação temporária (15 s) e mascaramento
  await page.getByRole("button", { name: "Revelar Senha" }).click();
  check(
    "revelar mostra a senha",
    await page
      .getByText(CANARIES.password, { exact: true })
      .waitFor({ timeout: 5000 })
      .then(
        () => true,
        () => false,
      ),
  );
  const inAttrs = await page.evaluate(
    (c) =>
      [...document.querySelectorAll("*")].some((el) => [...el.attributes].some((a) => a.value.includes(c))),
    CANARIES.password,
  );
  check("segredo revelado não aparece em atributos", !inAttrs);
  check("título da janela não contém segredos", (await page.title()) === "KeyVault", await page.title());
  await sleep(15_500);
  check("revelação expira em 15 s", !(await page.getByText(CANARIES.password, { exact: true }).isVisible()));

  // 6) Clipboard: cópia no Rust, limpeza após 20 s, preservação de conteúdo novo do usuário
  await page.getByRole("button", { name: "Copiar Senha" }).click();
  await sleep(500);
  check("cópia coloca a senha no clipboard", clipboardText() === CANARIES.password);
  const formats = ps(
    "Add-Type -AssemblyName System.Windows.Forms; ([System.Windows.Forms.Clipboard]::GetDataObject().GetFormats()) -join ','",
  );
  check(
    "clipboard marcado para exclusão do histórico/nuvem",
    formats.includes("ExcludeClipboardContentFromMonitorProcessing") &&
      formats.includes("CanIncludeInClipboardHistory"),
    formats,
  );
  await sleep(21_000);
  check("clipboard limpo após 20 s", clipboardText() !== CANARIES.password, clipboardText());
  await page.getByRole("button", { name: "Copiar Senha" }).click();
  await sleep(500);
  ps("Set-Clipboard -Value 'texto novo do usuario e2e'");
  await sleep(21_000);
  check(
    "conteúdo novo do usuário preservado",
    clipboardText() === "texto novo do usuario e2e",
    clipboardText(),
  );

  // 7) Gerador
  await page.getByRole("button", { name: "Editar" }).click();
  await page.getByRole("button", { name: "Gerar" }).first().click();
  // Após "Gerar", o campo vira <input> com o valor gerado (espera a re-renderização).
  await page.waitForFunction(() =>
    [...document.querySelectorAll("label")].some(
      (l) => l.textContent === "Senha" && document.getElementById(l.htmlFor)?.tagName === "INPUT",
    ),
  );
  const gen = await page.getByLabel("Senha", { exact: true }).inputValue();
  check("gerador produz 24 caracteres", [...gen].length === 24, `${[...gen].length}`);
  await page.getByRole("button", { name: "Cancelar", exact: true }).last().click();
  const discard = page.getByRole("button", { name: "Descartar" });
  if (await discard.isVisible().catch(() => false)) await discard.click();

  // 8) Bloqueio manual, senha errada, desbloqueio
  await page.getByRole("button", { name: "Bloquear" }).click();
  await page.getByRole("button", { name: "Desbloquear" }).waitFor();
  check(
    "bloqueio manual remove o conteúdo da tela",
    !(await page
      .getByText(CANARIES.username)
      .isVisible()
      .catch(() => false)),
  );
  await page.getByLabel("Senha mestra", { exact: true }).fill("senha errada qualquer e2e");
  await page.getByRole("button", { name: "Desbloquear" }).click();
  check(
    "senha errada: mensagem genérica",
    await page
      .getByText("Não foi possível desbloquear: senha incorreta ou cofre inválido")
      .waitFor()
      .then(() => true),
  );
  await sleep(1500);
  await page.getByLabel("Senha mestra", { exact: true }).fill(PW1);
  t0 = Date.now();
  await page.getByRole("button", { name: "Desbloquear" }).click();
  await page.getByRole("button", { name: "Nova entrada" }).waitFor();
  check("desbloqueio com senha correta", true, `${Date.now() - t0} ms`);

  // 9) Backup (diálogo nativo do Rust) — feito com a senha 1
  const backupPath = path.join(OUT, "backup-e2e.keyvault");
  fs.rmSync(backupPath, { force: true });
  await page.getByRole("button", { name: "Configurações" }).click();
  let dlg = dialog("Salvar backup criptografado do KeyVault", backupPath);
  await page.getByRole("button", { name: "Salvar backup…" }).click();
  await page.getByText(/Backup criptografado salvo/).waitFor({ timeout: 60_000 });
  const bk = fs.readFileSync(backupPath);
  check(
    "backup gravado com magic KVLT e envelope_kind=2",
    bk.subarray(0, 4).toString() === "KVLT" && bk.readUInt16LE(118) === 2,
    `${bk.length} bytes`,
  );
  check("diálogo nativo preenchido", true, String(dlg.pid));

  // 10) Troca de senha
  await page.getByLabel("Senha atual", { exact: true }).fill(PW1);
  await page.getByLabel("Nova senha mestra", { exact: true }).fill(PW2);
  await page.getByLabel("Confirmar nova senha mestra", { exact: true }).fill(PW2);
  await page.getByRole("button", { name: "Alterar senha mestra" }).click();
  await page.getByText(/Senha mestra alterada/).waitFor({ timeout: 60_000 });
  check("troca de senha concluída", true);
  await page.keyboard.press("Escape");

  // 11) Bloquear, senha antiga falha, nova funciona
  await page.getByRole("button", { name: "Bloquear" }).click();
  await page.getByLabel("Senha mestra", { exact: true }).fill(PW1);
  await page.getByRole("button", { name: "Desbloquear" }).click();
  check(
    "senha antiga não abre o cofre após troca",
    await page
      .getByText("Não foi possível desbloquear")
      .waitFor()
      .then(() => true),
  );
  await sleep(2500);
  await page.getByLabel("Senha mestra", { exact: true }).fill(PW2);
  await page.getByRole("button", { name: "Desbloquear" }).click();
  await page.getByRole("button", { name: "Nova entrada" }).waitFor();
  check("senha nova abre o cofre", true);
  await page.getByRole("button", { name: "Bloquear" }).click();

  // 12) Restauração do backup (senha antiga do backup) como cofre novo
  await page.getByRole("button", { name: /Restaurar backup/ }).click();
  dlg = dialog("Escolher backup do KeyVault", backupPath);
  await page.getByRole("button", { name: "Escolher arquivo…" }).click();
  await page.getByLabel("Senha do backup", { exact: true }).waitFor();
  await page.getByLabel("Senha do backup", { exact: true }).fill(PW2);
  await page.getByRole("button", { name: "Verificar backup" }).click();
  check(
    "backup NÃO abre com a senha nova (feito com a antiga)",
    await page
      .getByText("Não foi possível desbloquear")
      .waitFor()
      .then(() => true),
  );
  await sleep(2500);
  await page.getByLabel("Senha do backup", { exact: true }).fill(PW1);
  await page.getByRole("button", { name: "Verificar backup" }).click();
  await page.getByText(/Backup autenticado e válido: 1 entradas/).waitFor({ timeout: 60_000 });
  check("backup autenticado com a senha da época", true);
  await page.getByLabel("Nova senha mestra", { exact: true }).fill(PW_RESTORED);
  await page.getByLabel("Confirmar nova senha mestra", { exact: true }).fill(PW_RESTORED);
  await page.getByRole("button", { name: "Criar novo cofre" }).click();
  await page.getByText(/Novo cofre criado com 1 entradas/).waitFor({ timeout: 60_000 });
  check("confirmação da restauração exibida", true);
  await page.getByRole("button", { name: "Fechar", exact: true }).first().click();
  await page.getByRole("radio").nth(1).waitFor();
  check(
    "aviso indica o cofre restaurado selecionado",
    await page.getByText("Backup restaurado como novo cofre. Desbloqueie-o com a nova senha.").isVisible(),
  );
  const radios = await page.getByRole("radio").count();
  check("dois cofres disponíveis após restauração", radios === 2, `${radios}`);
  await page.getByLabel("Senha mestra", { exact: true }).fill(PW_RESTORED);
  await page.getByRole("button", { name: "Desbloquear" }).click();
  await page.getByRole("button", { name: "Nova entrada" }).waitFor();
  check(
    "cofre restaurado abre com a senha nova e contém a entrada",
    await page
      .getByRole("navigation", { name: "Entradas" })
      .getByText(CANARIES.title)
      .waitFor({ timeout: 10_000 })
      .then(
        () => true,
        () => false,
      ),
  );
  await page.getByRole("button", { name: "Bloquear" }).click();

  // 13) Bloqueio por inatividade imposto pelo Rust (1 min, sem nenhuma interação)
  await page.getByRole("radio").first().check();
  const firstLabel = await page.getByRole("radio").first().getAttribute("id");
  await page.getByLabel("Senha mestra", { exact: true }).fill(PW2);
  await page.getByRole("button", { name: "Desbloquear" }).click();
  let unlocked = await page
    .getByRole("button", { name: "Nova entrada" })
    .waitFor({ timeout: 30_000 })
    .then(
      () => true,
      () => false,
    );
  if (!unlocked) {
    // O primeiro rádio pode ser o cofre restaurado; tenta a outra senha.
    await page.getByLabel("Senha mestra", { exact: true }).fill(PW_RESTORED);
    await sleep(2500);
    await page.getByRole("button", { name: "Desbloquear" }).click();
    unlocked = await page
      .getByRole("button", { name: "Nova entrada" })
      .waitFor({ timeout: 30_000 })
      .then(
        () => true,
        () => false,
      );
  }
  check("desbloqueio para teste de inatividade", unlocked, firstLabel);
  await page.getByRole("button", { name: "Configurações" }).click();
  await page.getByLabel("Bloquear após inatividade (minutos, 1 a 30)", { exact: true }).fill("1");
  await page.getByRole("button", { name: "Salvar preferências" }).click();
  await page.getByText("Preferências salvas.").waitFor({ timeout: 60_000 });
  await page.keyboard.press("Escape");
  t0 = Date.now();
  await page.getByText("Cofre bloqueado por inatividade.").waitFor({ timeout: 90_000 });
  check(
    "bloqueio por inatividade (1 min) no backend",
    true,
    `${Math.round((Date.now() - t0) / 1000)} s após a última interação`,
  );

  // 14) Acessibilidade automatizada (axe-core) na tela de bloqueio e no cofre
  const axeSrc = fs.readFileSync(path.resolve("node_modules/axe-core/axe.min.js"), "utf8");
  async function axe(label) {
    await page.evaluate(axeSrc);
    const r = await page.evaluate(async () => {
      const res = await window.axe.run(document, { runOnly: ["wcag2a", "wcag2aa"] });
      return res.violations.map((v) => `${v.id}(${v.nodes.length})`);
    });
    fs.writeFileSync(path.join(OUT, `axe-${label}.json`), JSON.stringify(r, null, 2));
    check(`axe-core WCAG 2 A/AA sem violações: ${label}`, r.length === 0, r.join(", "));
  }
  await axe("tela-de-bloqueio");
  // Navegação por teclado: Tab chega ao campo de senha e ao botão com foco visível.
  await page.keyboard.press("Tab");
  const focusInfo = [];
  for (let i = 0; i < 8; i++) {
    focusInfo.push(
      await page.evaluate(() => {
        const a = document.activeElement;
        const cs = a ? getComputedStyle(a) : null;
        return `${a?.tagName}:${a?.getAttribute("aria-label") ?? a?.textContent?.slice(0, 20)}:${cs?.outlineStyle}`;
      }),
    );
    await page.keyboard.press("Tab");
  }
  check(
    "navegação por Tab percorre controles com foco visível",
    focusInfo.some((f) => f.startsWith("INPUT")) && focusInfo.some((f) => f.startsWith("BUTTON")),
    focusInfo.join(" | "),
  );
  await page.getByLabel("Senha mestra", { exact: true }).fill(PW2);
  await page.keyboard.press("Enter");
  unlocked = await page
    .getByRole("button", { name: "Nova entrada" })
    .waitFor({ timeout: 30_000 })
    .then(
      () => true,
      () => false,
    );
  if (!unlocked) {
    await sleep(2500);
    await page.getByLabel("Senha mestra", { exact: true }).fill(PW_RESTORED);
    await page.keyboard.press("Enter");
    await page.getByRole("button", { name: "Nova entrada" }).waitFor({ timeout: 30_000 });
  }
  await page.getByRole("navigation", { name: "Entradas" }).getByRole("button").first().click();
  await page.getByRole("button", { name: "Editar" }).waitFor();
  await axe("cofre-detalhe");
  await page.keyboard.press("Control+l");
  await page.getByRole("button", { name: "Desbloquear" }).waitFor();
  check("atalho Ctrl+L bloqueia", true);

  // 15) Armazenamento do WebView vazio
  const storage = await page.evaluate(async () => ({
    local: localStorage.length,
    session: sessionStorage.length,
    idb: (await indexedDB.databases?.())?.length ?? 0,
    caches: (await caches.keys()).length,
    sw: (await navigator.serviceWorker?.getRegistrations?.())?.length ?? 0,
    cookies: document.cookie.length,
  }));
  check(
    "nenhum armazenamento do navegador em uso",
    Object.values(storage).every((v) => v === 0),
    JSON.stringify(storage),
  );
} catch (err) {
  check(
    "fluxo E2E executado até o fim",
    false,
    String(err?.message ?? err)
      .split(/\r?\n/)
      .slice(0, 6)
      .join(" | "),
  );
  await page.screenshot({ path: path.join(OUT, "falha.png") }).catch(() => undefined);
}
fs.writeFileSync(path.join(OUT, "results.json"), JSON.stringify({ results, violations }, null, 2));
const failed = results.filter((r) => !r.ok);
console.log(`\nTOTAL ${results.length} verificações, ${failed.length} falhas`);
await browser.close().catch(() => undefined);
process.exit(failed.length ? 1 : 0);
