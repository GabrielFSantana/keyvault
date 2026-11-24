// Diagnóstico de rede: executa somente a sonda de CSP (fetch/img/WebSocket remotos) via CDP.
import { chromium } from "playwright-core";
const browser = await chromium.connectOverCDP(`http://127.0.0.1:${process.env.KV_CDP_PORT ?? "9333"}`);
const page = browser
  .contexts()
  .flatMap((c) => c.pages())
  .find((p) => p.url().includes("tauri.localhost"));
const r = await page.evaluate(async () => {
  const out = {};
  out.fetch = await fetch("https://example.com/").then(
    () => "permitido",
    (e) => `bloqueado:${e.name}`,
  );
  out.img = await new Promise((res) => {
    const i = new Image();
    i.onload = () => res("carregou");
    i.onerror = () => res("bloqueado");
    i.src = "https://example.com/x.png";
  });
  return out;
});
console.log(JSON.stringify(r));
await browser.close();
