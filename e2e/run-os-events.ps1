# Abre o app instalado com CDP e executa os testes reais de bloqueio (lock) e suspensão (suspend).
param([ValidateSet("lock", "suspend")][string]$Mode = "lock", [int]$Port = 9334)
$out = (Resolve-Path (Join-Path $PSScriptRoot "..\e2e-out")).Path
$env:WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS = "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection --disable-background-networking --disable-component-update --disable-domain-reliability --disable-sync --no-pings --remote-debugging-port=$Port --remote-debugging-address=127.0.0.1"
$app = Start-Process "$env:LOCALAPPDATA\KeyVault\keyvault.exe" -PassThru
Remove-Item Env:\WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS
for ($i = 0; $i -lt 60; $i++) { try { Invoke-RestMethod "http://127.0.0.1:$Port/json/version" -TimeoutSec 2 | Out-Null; break } catch { Start-Sleep -Milliseconds 500 } }
$env:KV_CDP_PORT = "$Port"; $env:KV_E2E_OUT = $out
Push-Location (Join-Path $PSScriptRoot "..")
$ErrorActionPreference = "Continue"
cmd /c "node e2e/os-events.mjs $Mode 2>&1"
$code = $LASTEXITCODE
Pop-Location
$null = $app.CloseMainWindow(); if (-not $app.WaitForExit(15000)) { Stop-Process -Id $app.Id -Force }
exit $code
