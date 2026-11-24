# Orquestra o E2E do app INSTALADO: monitor de rede, inicialização com CDP do WebView2, testes
# (e2e/run.mjs), fechamento e varredura de canários. Somente dados fictícios.
# ATENÇÃO: usa o diretório real de dados (%LOCALAPPDATA%\com.keyvault.desktop) e recusa rodar se já houver
# cofres nele. Altera a área de transferência durante o teste.
param(
  [string]$Exe = "$env:LOCALAPPDATA\KeyVault\keyvault.exe",
  [string]$Out = (Join-Path $PSScriptRoot "..\e2e-out"),
  [int]$Port = 9333
)
$ErrorActionPreference = "Stop"
$data = Join-Path $env:LOCALAPPDATA "com.keyvault.desktop"
if (Test-Path (Join-Path $data "vaults\*.kvdb")) { throw "Já existem cofres em $data; o E2E não roda sobre dados existentes." }
New-Item -ItemType Directory -Force $Out | Out-Null
$Out = (Resolve-Path $Out).Path
$net = Join-Path $Out "network.log"; $stop = Join-Path $Out "netmon.stop"
Remove-Item -Force -ErrorAction SilentlyContinue $net, $stop
$started = Get-Date

$mon = Start-Process powershell.exe -PassThru -WindowStyle Hidden -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", (Join-Path $PSScriptRoot "netmon.ps1"), "-OutFile", $net, "-StopFile", $stop)

# Mesmos argumentos de endurecimento do tauri.conf.json + porta de depuração SOMENTE para o teste.
$env:WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS = "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection --disable-background-networking --disable-component-update --disable-domain-reliability --disable-sync --no-pings --remote-debugging-port=$Port --remote-debugging-address=127.0.0.1"
$app = Start-Process $Exe -PassThru
Remove-Item Env:\WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS
$ok = $false
for ($i = 0; $i -lt 60 -and -not $ok; $i++) {
  try { Invoke-RestMethod "http://127.0.0.1:$Port/json/version" -TimeoutSec 2 | Out-Null; $ok = $true } catch { Start-Sleep -Milliseconds 500 }
}
if (-not $ok) { throw "CDP do WebView2 não respondeu" }

$env:KV_CDP_PORT = "$Port"; $env:KV_E2E_OUT = $Out
Push-Location (Join-Path $PSScriptRoot "..")
$ErrorActionPreference = "Continue"
cmd /c "node e2e/run.mjs > `"$(Join-Path $Out 'e2e.log')`" 2>&1"
$e2eExit = $LASTEXITCODE
Get-Content (Join-Path $Out "e2e.log")
Pop-Location

# Fechamento normal (dispara bloqueio/limpeza no Rust) e parada do monitor.
$null = $app.CloseMainWindow()
if (-not $app.WaitForExit(15000)) { Stop-Process -Id $app.Id -Force }
Start-Sleep -Seconds 1
New-Item -ItemType File $stop | Out-Null
$mon.WaitForExit(10000) | Out-Null

# Varredura de canários (UTF-8 e UTF-16LE) em dados do app, perfil WebView2, saída do E2E (backups) e
# arquivos de %TEMP% modificados durante o teste.
$canaries = @("CANARIO-E2E-TITULO-a1", "CANARIO-E2E-USUARIO-b2", "CANARIO-E2E-SENHA-c3", "CANARIO-E2E-URL-d4", "CANARIO-E2E-NOTAS-e5", "CANARIO-E2E-TAG-f6", "CANARIO-E2E-CAMPO-g7", "CANARIO-E2E-SEGREDO-h8", "senha mestra e2e ficticia")
$needles = foreach ($c in $canaries) { ,[Text.Encoding]::UTF8.GetBytes($c); ,[Text.Encoding]::Unicode.GetBytes($c) }
function Find-Bytes([byte[]]$hay, [byte[]]$n) {
  for ($i = [Array]::IndexOf($hay, $n[0]); $i -ge 0 -and $i -le $hay.Length - $n.Length; $i = [Array]::IndexOf($hay, $n[0], $i + 1)) {
    $m = $true; for ($j = 1; $j -lt $n.Length; $j++) { if ($hay[$i + $j] -ne $n[$j]) { $m = $false; break } }
    if ($m) { return $true }
  }
  return $false
}
$files = @()
$files += Get-ChildItem -Recurse -Force -File $data -ErrorAction SilentlyContinue
$files += Get-ChildItem -Force -File $Out -Filter *.keyvault -ErrorAction SilentlyContinue
$files += Get-ChildItem -Recurse -Force -File $env:TEMP -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge $started -and $_.Length -lt 64MB -and $_.FullName -notlike "*\claude\*" }
$hits = @()
foreach ($f in $files) {
  try { $bytes = [IO.File]::ReadAllBytes($f.FullName) } catch { continue }
  foreach ($n in $needles) { if (Find-Bytes $bytes $n) { $hits += "$($f.FullName): $([Text.Encoding]::UTF8.GetString($n))" ; break } }
}
$report = [ordered]@{
  e2eExit = $e2eExit
  filesScanned = $files.Count
  canaryHits = $hits
  dataFiles = (Get-ChildItem -Recurse -Force -File $data | ForEach-Object { "$($_.FullName.Substring($data.Length)) ($($_.Length) B)" })
  network = (Get-Content $net -ErrorAction SilentlyContinue)
}
$report | ConvertTo-Json -Depth 4 | Set-Content -Encoding utf8 (Join-Path $Out "post-scan.json")
Write-Output "ARQUIVOS VARRIDOS: $($files.Count); ACHADOS DE CANÁRIO: $($hits.Count)"
$hits | ForEach-Object { Write-Output "  CANARIO: $_" }
Write-Output "REDE (não-loopback/UDP):"; Get-Content $net -ErrorAction SilentlyContinue | ForEach-Object { Write-Output "  $_" }
exit $e2eExit
