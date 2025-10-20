Set-ExecutionPolicy Unrestricted -Force -Scope Process

$DownloadPathUser = Join-Path -Path ([System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::UserProfile)) -ChildPath 'Downloads'
$DesktopPathUser = [Environment]::GetFolderPath("Desktop")
$DesktopPathPublic = Join-Path -Path $env:PUBLIC -ChildPath 'Desktop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$pathsToDelete = @(
    "$DesktopPathUser\DriversCloud_Install",
	"$DownloadPathUser\MultInstall.exe",
	"$DownloadPathUser\OptignoreList",
	"$DownloadPathUser\service.conf.lock",
	"$DownloadPathUser\system.conf.lock",
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
	"$DesktopPathUser\Copieur",
	"$DesktopPathUser\Copieur.exe",
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
# Suppression des profils WiFi
Write-Host "`n=== Suppression des profils WiFi ===" -ForegroundColor Cyan
$wifiProfilesToDelete = @("WIFI_ipv4", "GUEST")

foreach ($profile in $wifiProfilesToDelete)
{
	try
	{
		# Vérifier si le profil existe
		$existingProfiles = netsh wlan show profiles | Select-String "$profile"
		
		if ($existingProfiles)
		{
			netsh wlan delete profile name="$profile" 2>$null
			if ($LASTEXITCODE -eq 0)
			{
				Write-Host "✓ Profil WiFi supprimé : $profile" -ForegroundColor Green
			}
			else
			{
				Write-Host "⚠ Erreur lors de la suppression de : $profile" -ForegroundColor Yellow
			}
		}
		else
		{
			Write-Host "○ Profil WiFi non trouvé : $profile" -ForegroundColor Gray
		}
	}
	catch
	{
		Write-Host "⚠ Impossible de supprimer : $profile - $_" -ForegroundColor Yellow
	}
}
Write-Host "Appuyez sur une touche pour fermer la fenêtre..."
[Console]::ReadKey($true) | Out-Null
[Console]::WriteLine("Fermeture de la fenêtre...")
Start-Sleep -Seconds 2
Stop-Process -Id $PID