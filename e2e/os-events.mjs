// Teste REAL de integração com o Windows no app instalado: bloqueio de sessão (LockWorkStation) e
// suspensão (SetSuspendState). Verifica pelo IPC que o Rust bloqueou o cofre com o motivo correto.
// Somente dados fictícios. Requer o app aberto com CDP (ver e2e/run-os-events.ps1).
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { chromium } from "playwright-core";

const OUT = process.env.KV_E2E_OUT ?? path.resolve("e2e-out");
const PW = "senha mestra ficticia do teste de SO";
const mode = process.argv[2] ?? "lock"; // lock | suspend
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const log = (m) => {
  const line = `${new Date().toISOString()} ${m}`;
  console.log(line);
  fs.appendFileSync(path.join(OUT, "os-events.log"), `${line}\n`);
};

let browser = await chromium.connectOverCDP(`http://127.0.0.1:${process.env.KV_CDP_PORT ?? "9333"}`);
let page = browser
  .contexts()
  .flatMap((c) => c.pages())
  .find((p) => p.url().includes("tauri.localhost"));
// A suspensão derruba a conexão CDP; reconecta e repete a chamada.
async function reconnect() {
  for (let i = 0; i < 60; i++) {
    try {
      browser = await chromium.connectOverCDP(`http://127.0.0.1:${process.env.KV_CDP_PORT ?? "9333"}`);
      page = browser
        .contexts()
        .flatMap((c) => c.pages())
        .find((p) => p.url().includes("tauri.localhost"));
      if (page) return;
    } catch {
      /* tenta de novo */
    }
    await sleep(1000);
  }
  throw new Error("não reconectou ao CDP");
}
const invRaw = (cmd, args = {}) =>
  page.evaluate(
    ([c, a]) =>
      window.__TAURI_INTERNALS__.invoke(c, a).then(
        (r) => ({ ok: r }),
        (e) => ({ err: e }),
      ),
    [cmd, args],
  );

const inv = async (cmd, args = {}) => {
  try {
    return await invRaw(cmd, args);
  } catch {
    log(`conexão CDP perdida em ${cmd}; reconectando`);
    await reconnect();
    return invRaw(cmd, args);
  }
};

let st = (await inv("vault_status")).ok;
if (st.phase === "uninitialized") st = (await inv("vault_create", { password: PW, confirmation: PW })).ok;
else if (st.phase === "locked")
  st = (await inv("vault_unlock", { vaultId: st.selectedVaultId, password: PW })).ok;
log(`antes: fase=${st.phase} geração=${st.generation}`);
if (st.phase !== "unlocked") throw new Error("não foi possível desbloquear o cofre fictício");

if (mode === "lock") {
  log("executando LockWorkStation (desbloqueie o Windows quando quiser)");
  execFileSync("rundll32.exe", ["user32.dll,LockWorkStation"]);
} else {
  log("executando SetSuspendState(Suspend) — acorde o PC para continuar");
  execFileSync("powershell.exe", [
    "-NoProfile",
    "-Command",
    "Add-Type -AssemblyName System.Windows.Forms; [void][System.Windows.Forms.Application]::SetSuspendState([System.Windows.Forms.PowerState]::Suspend, $false, $false)",
  ]);
}
const t0 = Date.now();
let after = null;
for (let i = 0; i < 600; i++) {
  after = (await inv("vault_status")).ok;
  if (after.phase !== "unlocked") break;
  await sleep(500);
}
log(
  `depois: fase=${after.phase} motivo=${after.lastLockReason} geração=${after.generation} (${Date.now() - t0} ms após o comando)`,
);
// Na suspensão, o Windows pode bloquear a sessão antes de notificar a suspensão; o primeiro evento
// recebido define o motivo. Ambos provam bloqueio real; o relatório registra qual ocorreu.
const expected = mode === "lock" ? ["osLock"] : ["suspend", "osLock"];
const ok =
  after.phase === "locked" && expected.includes(after.lastLockReason) && after.generation > st.generation;
// Comando com a geração antiga é recusado.
const stale = await inv("entries_list", { session: st.generation, favoritesOnly: false });
log(`comando com geração antiga: ${JSON.stringify(stale.err ?? stale.ok)}`);
log(`${ok ? "PASS" : "FAIL"} bloqueio por ${mode} (esperado ${expected})`);
await browser.close();
process.exit(ok ? 0 : 1);
