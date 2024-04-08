
Set-ExecutionPolicy Unrestricted -Force -Scope Process

$DownloadPathUser = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::UserProfile) + '\Downloads'
$DesktopPathUser = [Environment]::GetFolderPath("Desktop")
$DesktopPathPublic = "$env:PUBLIC\Desktop"
Start-Sleep -Seconds 2 # Attendez 2 secondes 
$pathsToDelete = "$DesktopPathUser\DriversCloud_Install",
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
"c:\WRT.exe",
"c:\Wtool.exe",
"c:\Wtools v1.0.2.4",
"c:\Nettoyer-disque.cmd",
"c:\Windows_Repair_Toolbox"

foreach ($path in $pathsToDelete)
{
	if (Test-Path $path)
	{
		# Suppression des fichiers
		if ((Get-Item $path) -is [System.IO.FileInfo])
		{
			Remove-Item $path -Force
			Write-Host "Fichier supprimé: $path"
		}
		# Suppression des dossiers
		elseif ((Get-Item $path) -is [System.IO.DirectoryInfo])
		{
			Remove-Item $path -Recurse -Force
			Write-Host "Dossier supprimé: $path"
		}
	}
	else
	{
		Write-Host "Path does not exist: $path"
	}
}

Read-Host "Appuyez sur une touche pour fermer la fenêtre"
Stop-Process -Id $PID
