"""Gera docs/dependencies.md: dependências diretas (Rust e npm), totais transitivos e licenças.

Uso (na raiz): python -I tools/inventory.py
Requer `cargo` no PATH e `node_modules` instalado (npm ci).
"""

import collections
import json
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parent.parent
TAURI = ROOT / "src-tauri"

meta = json.loads(
    subprocess.check_output(
        ["cargo", "metadata", "--format-version", "1", "--locked", "--filter-platform", "x86_64-pc-windows-msvc"],
        cwd=TAURI,
    )
)
pkgs = {p["id"]: p for p in meta["packages"]}
resolved = {n["id"] for n in meta["resolve"]["nodes"]}
workspace = set(meta["workspace_members"])
direct = []
for wid in workspace:
    p = pkgs[wid]
    for d in p["dependencies"]:
        direct.append((p["name"], d["name"], d["req"], d.get("kind") or "normal"))

lic_count = collections.Counter(pkgs[i].get("license") or "(sem campo)" for i in resolved if i not in workspace)

pkg = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
lock = json.loads((ROOT / "package-lock.json").read_text(encoding="utf-8"))
npm_lic = collections.Counter()
npm_rows = []
for path, info in lock["packages"].items():
    if not path:
        continue
    npm_lic[info.get("license", "(sem campo)")] += 1
for section in ("dependencies", "devDependencies"):
    for name, ver in pkg.get(section, {}).items():
        info = lock["packages"].get(f"node_modules/{name}", {})
        npm_rows.append((section, name, ver, info.get("license", "?")))

out = ["# Inventário de dependências", "", "Gerado por `python -I tools/inventory.py` a partir de `Cargo.lock` e `package-lock.json`.", ""]
out += ["## Rust — dependências diretas (versões fixadas com `=`)", "", "| Crate do workspace | Dependência | Requisito | Tipo |", "| --- | --- | --- | --- |"]
for a, b, c, k in sorted(direct):
    out.append(f"| {a} | {b} | `{c}` | {k} |")
out += ["", f"Total de crates resolvidas para `x86_64-pc-windows-msvc` (fora do workspace): **{len(resolved - workspace)}**.", ""]
out += ["### Licenças (Rust, transitivas)", "", "| Licença | Crates |", "| --- | ---: |"]
for l, n in lic_count.most_common():
    out.append(f"| {l} | {n} |")
out += ["", "## npm — dependências diretas", "", "| Seção | Pacote | Versão | Licença |", "| --- | --- | --- | --- |"]
for s, n, v, l in sorted(npm_rows):
    out.append(f"| {s} | {n} | `{v}` | {l} |")
out += ["", f"Total de pacotes no `package-lock.json`: **{sum(npm_lic.values())}**.", "", "### Licenças (npm, todos os pacotes do lockfile)", "", "| Licença | Pacotes |", "| --- | ---: |"]
for l, n in npm_lic.most_common():
    out.append(f"| {l} | {n} |")
(ROOT / "docs" / "dependencies.md").write_text("\n".join(out) + "\n", encoding="utf-8")
print("ok", len(resolved - workspace), sum(npm_lic.values()))
