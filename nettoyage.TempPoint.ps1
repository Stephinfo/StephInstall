Set-ExecutionPolicy Unrestricted -Force -Scope Process

$DownloadPathUser = Join-Path -Path ([System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::UserProfile)) -ChildPath 'Downloads'
$DesktopPathUser = [Environment]::GetFolderPath("Desktop")
$DesktopPathPublic = Join-Path -Path $env:PUBLIC -ChildPath 'Desktop'

$pathsToDelete = @(
    "$DesktopPathUser\DriversCloud_Install",
    "$DownloadPathUser\MultInstall.exe",
    "$DownloadPathUser\MI.exe",
    "c:\OOAPB.exe",
    "$DownloadPathUser\App",
    "C:\temp",
    "c:\bb.exe",
    "C:\fb.exe",
    "C:\fb",
    "c:\W10DEB.exe",
    "c:\W10DEB",
    "c:\SIW.exe",
    "c:\SIW",
    "c:\wrc.exe",
    "c:\wt.exe",
    "c:\Dism++.exe",
    "c:\QB.exe",
    "c:\wd.exe",
	"c:\QuickBoost.exe",
	"c:\ODT",
    "c:\mi2.exe",
    "c:\WRT.exe",
    "c:\Wtool.exe",
    "c:\Wtools v1.0.2.4",
	"c:\Nettoyer-disque.cmd",
	"C:\Users\USER\Desktop\Copieur",
	"c:\Users\USER\Desktop\Copieur.exe",
	"C:\Users\USER\Desktop\Copieur.exe",
	"c:\Windows_Repair_Toolbox"
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