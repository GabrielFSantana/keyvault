# Preenche um diálogo nativo de arquivo (Salvar/Abrir) do KeyVault. Somente testes E2E.
# Localiza o diálogo via UI Automation (no UIA ele é filho da janela "Tauri Window"), ativa-o e digita o
# caminho completo + Enter no campo de nome (foco padrão do diálogo). Recusa digitar se não confirmar que
# a janela ativa é o diálogo esperado, para nunca enviar teclas a outro programa.
param([Parameter(Mandatory)][string]$Title, [Parameter(Mandatory)][string]$Path, [int]$TimeoutSec = 30)
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes, System.Windows.Forms
Add-Type -Namespace KvE2E -Name U32 -MemberDefinition @"
[DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
[DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
"@
$AE = [System.Windows.Automation.AutomationElement]
$scope = [System.Windows.Automation.TreeScope]
$cond = New-Object System.Windows.Automation.PropertyCondition($AE::NameProperty, $Title)
$ownerCond = New-Object System.Windows.Automation.PropertyCondition($AE::ClassNameProperty, "Tauri Window")
$deadline = (Get-Date).AddSeconds($TimeoutSec)
$win = $null
while (-not $win -and (Get-Date) -lt $deadline) {
  foreach ($owner in $AE::RootElement.FindAll($scope::Children, $ownerCond)) {
    $win = $owner.FindFirst($scope::Children, $cond)
    if ($win) { break }
  }
  if (-not $win) { Start-Sleep -Milliseconds 250 }
}
if (-not $win) { Write-Output "DIALOG_NOT_FOUND"; exit 2 }
$hwnd = [IntPtr]$win.Current.NativeWindowHandle
for ($i = 0; $i -lt 20 -and [KvE2E.U32]::GetForegroundWindow() -ne $hwnd; $i++) {
  [void][KvE2E.U32]::SetForegroundWindow($hwnd)
  Start-Sleep -Milliseconds 150
}
if ([KvE2E.U32]::GetForegroundWindow() -ne $hwnd) { Write-Output "NOT_FOREGROUND"; exit 3 }
Start-Sleep -Milliseconds 300
# Seleciona o conteúdo do campo de nome (foco padrão) e digita o caminho absoluto.
[System.Windows.Forms.SendKeys]::SendWait("^a")
[System.Windows.Forms.SendKeys]::SendWait($Path)
Start-Sleep -Milliseconds 200
if ([KvE2E.U32]::GetForegroundWindow() -ne $hwnd) { Write-Output "LOST_FOREGROUND"; exit 4 }
[System.Windows.Forms.SendKeys]::SendWait("{ENTER}")
Write-Output "OK"
