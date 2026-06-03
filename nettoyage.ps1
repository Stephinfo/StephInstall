Set-ExecutionPolicy Unrestricted -Force -Scope Process

# ── Tuer le processus MultInstall avant toute suppression ──────────────────────
$multInstallProcs = Get-CimInstance Win32_Process |
    Where-Object { $_.Name -eq 'powershell.exe' -and $_.CommandLine -like '*MultInstall*' }

foreach ($proc in $multInstallProcs) {
    Write-Host "Arrêt MultInstall (PID $($proc.ProcessId))..."
    Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
}
if ($multInstallProcs) { Start-Sleep -Seconds 2 }
# ───────────────────────────────────────────────────────────────────────────────

$DownloadPathUser = Join-Path -Path ([System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::UserProfile)) -ChildPath 'Downloads'
$DesktopPathUser = [Environment]::GetFolderPath("Desktop")
$DesktopPathPublic = Join-Path -Path $env:PUBLIC -ChildPath 'Desktop'

# ── Nettoyage %TEMP% : tous les fichiers déposés par MultInstall ────────────────
$TempDir = $env:TEMP

# Fichiers nommés explicitement
$multInstallTempNames = @(
    "logfile.txt", "nettoyage.ps1", "racc.zip", "maj.ps1", "audit.ps1",
    "QB.exe", "QuickBoost.exe", "OOAPB.exe", "bb.exe", "fb.exe",
    "W10DEB.exe", "SIW.exe", "wrc.exe", "wt.exe", "Dism++.exe",
    "wd.exe", "mi2.exe", "WRT.exe", "Wtool.exe", "Nettoyer-disque.cmd",
    "win10deb.exe", "theme.deskthemepack", "BloatyNosy.zip"
)
foreach ($name in $multInstallTempNames) {
    $p = Join-Path $TempDir $name
    if (Test-Path $p) { Remove-Item $p -Force -ErrorAction SilentlyContinue; Write-Host "Supprimé : $p" }
}

# Dossiers déposés dans %TEMP%
foreach ($dir in @("fb", "W10DEB", "SIW", "ODT", "QuickBoost", "BloatyNosy")) {
    $p = Join-Path $TempDir $dir
    if (Test-Path $p) { Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue; Write-Host "Supprimé : $p" }
}

# Fichiers winget stdout/stderr (pattern)
Get-Item "$TempDir\winget_stdout_*.txt", "$TempDir\winget_stderr_*.txt" `
         -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
Write-Host "Fichiers winget temporaires nettoyés."
# ────────────────────────────────────────────────────────────────────────────────

$pathsToDelete = @(
    "$DesktopPathUser\DriversCloud_Install",
    "$DownloadPathUser\MultInstall.exe",
    "$DownloadPathUser\MI.exe",
    "$DownloadPathUser\App",
    # Anciens emplacements C:\ (compatibilité versions précédentes)
    "c:\OOAPB.exe", "c:\bb.exe", "C:\fb.exe", "C:\fb",
    "c:\W10DEB.exe", "c:\W10DEB", "c:\SIW.exe", "c:\SIW",
    "c:\wrc.exe", "c:\wt.exe", "c:\Dism++.exe", "c:\QB.exe",
    "c:\wd.exe", "c:\QuickBoost.exe", "c:\ODT", "c:\mi2.exe",
    "c:\WRT.exe", "c:\Wtool.exe", "c:\Wtools v1.0.2.4", "c:\Nettoyer-disque.cmd", "C:\temp",
    "c:\Windows_Repair_Toolbox",
    "C:\Users\USER\Desktop\Copieur",
    "c:\Users\USER\Desktop\Copieur.exe"
)

$pathsToDelete | ForEach-Object {
    if (Test-Path $_) {
        Remove-Item $_ -Recurse -Force
        Write-Host "Supprimé : $_"
    } else {
        Write-Host "Le chemin n'existe pas : $_"
    }
}

Write-Host "Appuyez sur une touche pour fermer la fenêtre..."
[Console]::ReadKey($true) | Out-Null
[Console]::WriteLine("Fermeture de la fenêtre...")
Start-Sleep -Seconds 2
Stop-Process -Id $PID