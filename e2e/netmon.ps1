# Monitora conexões TCP (IPv4/IPv6) e sockets UDP do processo do KeyVault e de seus filhos (WebView2)
# até existir o arquivo de parada. Usa `netstat -ano` (rápido) a cada ~100 ms e recalcula a árvore de
# processos a cada 1 s. Registra endereços remotos que não sejam loopback e qualquer socket UDP.
param([Parameter(Mandatory)][string]$OutFile, [Parameter(Mandatory)][string]$StopFile, [string]$ProcName = "keyvault")
$seen = @{}; $samples = 0; $tree = $null; $treeAt = [datetime]::MinValue
function Get-Tree([int]$root) {
  $all = Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId
  $ids = New-Object System.Collections.Generic.HashSet[int]; [void]$ids.Add($root); $changed = $true
  while ($changed) { $changed = $false; foreach ($p in $all) { if ($ids.Contains([int]$p.ParentProcessId) -and $ids.Add([int]$p.ProcessId)) { $changed = $true } } }
  return $ids
}
function Test-Loopback([string]$addr) { return $addr -match '^(127\.|\[::1\]|0\.0\.0\.0|\[::\]|\*)' }
while (-not (Test-Path $StopFile)) {
  $p = Get-Process -Name $ProcName -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($p) {
    if (((Get-Date) - $treeAt).TotalMilliseconds -gt 1000) { $tree = Get-Tree $p.Id; $treeAt = Get-Date }
    $samples++
    foreach ($line in (netstat -ano)) {
      $f = ($line.Trim() -split '\s+')
      if ($f.Count -ge 4 -and $f[0] -eq 'TCP' -and $f.Count -ge 5) {
        $procId = [int]$f[4]
        if ($tree.Contains($procId) -and -not (Test-Loopback $f[2])) {
          $k = "TCP pid=$procId $($f[1]) -> $($f[2]) $($f[3])"
          if (-not $seen.ContainsKey($k)) { $seen[$k] = 1; Add-Content $OutFile "$((Get-Date).ToString('o')) $k" }
        }
      } elseif ($f.Count -ge 4 -and $f[0] -eq 'UDP') {
        $procId = [int]$f[-1]
        if ($tree.Contains($procId)) {
          $k = "UDP pid=$procId $($f[1])"
          if (-not $seen.ContainsKey($k)) { $seen[$k] = 1; Add-Content $OutFile "$((Get-Date).ToString('o')) $k" }
        }
      }
    }
  }
  Start-Sleep -Milliseconds 100
}
Add-Content $OutFile "SAMPLES $samples"
