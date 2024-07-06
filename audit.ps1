Add-Type -AssemblyName System.Windows.Forms
				[System.Windows.Forms.Application]::EnableVisualStyles()
				
				$global:outputFile = "C:\temp\AuditSecurite.txt"
				
				function Initialize-MainForm
				{
					$mainForm = New-Object System.Windows.Forms.Form
					$mainForm.Text = 'Audit de sécurité'
					$mainForm.Width = 300
					$mainForm.Height = 150
					$mainForm.StartPosition = 'CenterScreen'
					
					# Enlever la barre de titre
					$mainForm.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::None
					
					# Générer une couleur aléatoire
					$random = New-Object System.Random
					$randomColor = [System.Drawing.Color]::FromArgb($random.Next(256), $random.Next(256), $random.Next(256))
					$mainForm.BackColor = $randomColor
					
					$auditButton = New-Object System.Windows.Forms.Button
					$auditButton.Location = New-Object System.Drawing.Point(50, 30)
					$auditButton.Size = New-Object System.Drawing.Size(200, 30)
					$auditButton.Text = "Lancer l'audit"
					$auditButton.Add_Click({
							$checkForm = Create-CheckForm
							$checkForm.ShowDialog()
						})
					
					$journauxButton = New-Object System.Windows.Forms.Button
					$journauxButton.Location = New-Object System.Drawing.Point(50, 70)
					$journauxButton.Size = New-Object System.Drawing.Size(200, 30)
					$journauxButton.Text = "Journaux Windows"
					$journauxButton.Add_Click({
							Show-WindowsLogs
							[System.Windows.Forms.MessageBox]::Show("Journaux extraits. Le fichier va s'ouvrir dans le Bloc-notes.")
							Start-Process notepad.exe -ArgumentList $global:outputFile
						})
					
					$mainForm.Controls.Add($auditButton)
					$mainForm.Controls.Add($journauxButton)
					
					# Permettre de déplacer la fenêtre sans barre de titre
					$mainForm.Add_MouseDown({
							if ($_.Button -eq [System.Windows.Forms.MouseButtons]::Left)
							{
								$mainForm.Capture = $false
								$msg = [System.Windows.Forms.Message]::Create($mainForm.Handle, 0xA1, 0x2, 0)
								[System.Windows.Forms.Application]::DoEvents()
							}
						})
					
					return $mainForm
				}
				
				function Create-CheckForm
				{
					$checkForm = New-Object System.Windows.Forms.Form
					$checkForm.Text = 'Sélection des vérifications'
					$checkForm.Width = 500
					$checkForm.Height = 500
					$checkForm.StartPosition = 'CenterScreen'
					
					$checklistBox = New-Object System.Windows.Forms.CheckedListBox
					$checklistBox.Location = New-Object System.Drawing.Point(20, 20)
					$checklistBox.Size = New-Object System.Drawing.Size(450, 400)
					$checklistBox.CheckOnClick = $true
					
					$checks = @(
						"Pare-feu", "Ports", "Utilisateurs et groupes", "Services",
						"UAC", "Antivirus", "Programmes de démarrage", "Espace disque",
						"Temps d'activité", "Processus", "Mises à jour Windows",
						"Configuration réseau", "Partages réseau", "Politiques de mot de passe",
						"Logiciels installés", "BitLocker", "Tâches planifiées",
						"Événements de sécurité", "Règles de pare-feu", "Services tiers",
						"Configuration PowerShell", "Hyperviseur", "BIOS/UEFI"
					)
					
					foreach ($check in $checks)
					{
						$checklistBox.Items.Add($check, $true)
					}
					
					$checkForm.Controls.Add($checklistBox)
					
					$startButton = New-Object System.Windows.Forms.Button
					$startButton.Location = New-Object System.Drawing.Point(20, 430)
					$startButton.Size = New-Object System.Drawing.Size(450, 30)
					$startButton.Text = "Démarrer l'audit"
					$startButton.Add_Click({
							$selectedChecks = $checklistBox.CheckedItems
							Start-SecurityAudit -Checks $selectedChecks
							[System.Windows.Forms.MessageBox]::Show("Audit terminé. Le fichier va s'ouvrir dans le Bloc-notes.")
							Start-Process notepad.exe -ArgumentList $global:outputFile
							$checkForm.Close()
						})
					
					$checkForm.Controls.Add($startButton)
					
					return $checkForm
				}
				
				function Start-SecurityAudit
				{
					param ([string[]]$Checks)
					
					Ensure-OutputFileReady
					"========================= AUDIT DE SÉCURITÉ =========================" | Out-File -FilePath $global:outputFile -Force
					
					$totalChecks = $Checks.Count
					$currentCheck = 0
					
					foreach ($check in $Checks)
					{
						$currentCheck++
						$progressBar.Value = ($currentCheck / $totalChecks) * 100
						
						Add-Section $check
						switch ($check)
						{
							"Pare-feu" { Check-Firewall | Out-File -FilePath $global:outputFile -Append }
							"Ports" { Check-OpenPorts | Out-File -FilePath $global:outputFile -Append }
							"Utilisateurs et groupes" { Check-UsersAndGroups | Out-File -FilePath $global:outputFile -Append }
							"Services" { Check-Services | Out-File -FilePath $global:outputFile -Append }
							"UAC" { Check-UAC | Out-File -FilePath $global:outputFile -Append }
							"Antivirus" { Check-Antivirus | Out-File -FilePath $global:outputFile -Append }
							"Programmes de démarrage" { Check-StartupPrograms | Out-File -FilePath $global:outputFile -Append }
							"Espace disque" { Check-DiskSpace | Out-File -FilePath $global:outputFile -Append }
							"Temps d'activité" { Check-SystemUptime | Out-File -FilePath $global:outputFile -Append }
							"Processus" { Check-TopProcesses | Out-File -FilePath $global:outputFile -Append }
							"Mises à jour Windows" { Check-WindowsUpdates | Out-File -FilePath $global:outputFile -Append }
							"Configuration réseau" { Check-NetworkConfiguration | Out-File -FilePath $global:outputFile -Append }
							"Partages réseau" { Check-NetworkShares | Out-File -FilePath $global:outputFile -Append }
							
							"Logiciels installés" { Check-InstalledSoftware | Out-File -FilePath $global:outputFile -Append }
							"BitLocker" { Check-BitLockerStatus | Out-File -FilePath $global:outputFile -Append }
							"Tâches planifiées" { Check-ScheduledTasks | Out-File -FilePath $global:outputFile -Append }
							"Événements de sécurité" { Check-SecurityEvents | Out-File -FilePath $global:outputFile -Append }
							"Règles de pare-feu" { Check-FirewallRules | Out-File -FilePath $global:outputFile -Append }
							"Services tiers" { Check-ThirdPartyServices | Out-File -FilePath $global:outputFile -Append }
							"Configuration PowerShell" { Check-PowerShellConfiguration | Out-File -FilePath $global:outputFile -Append }
							"Hyperviseur" { Check-HyperVisorStatus | Out-File -FilePath $global:outputFile -Append }
							"BIOS/UEFI" { Check-BiosInfo | Out-File -FilePath $global:outputFile -Append }
						}
					}
					
					"=" * 70 | Out-File -FilePath $global:outputFile -Append
					"FIN DE L'AUDIT" | Out-File -FilePath $global:outputFile -Append
					"=" * 70 | Out-File -FilePath $global:outputFile -Append
				}
				
				function Add-Section
				{
					param ([string]$title)
					"`n" + "=" * 70 | Out-File -FilePath $global:outputFile -Append
					$title | Out-File -FilePath $global:outputFile -Append
					"=" * 70 + "`n" | Out-File -FilePath $global:outputFile -Append
				}
				
				
				function Check-Firewall
				{
					$output = ""
					$firewallProfiles = Get-NetFirewallProfile -Profile Domain, Public, Private
					foreach ($profile in $firewallProfiles)
					{
						$status = if ($profile.Enabled) { "Activé" }
						else { "Désactivé" }
						$output += "Profil $($profile.Name): $status`n"
					}
					$output += "`n"
					return $output
				}
				
				function Check-OpenPorts
				{
					$output = ""
					$openPorts = Get-NetTCPConnection | Where-Object { $_.State -eq "Listen" } |
					Group-Object -Property LocalPort |
					Sort-Object -Property Name
					
					$output += "Ports ouverts :`n"
					foreach ($port in $openPorts)
					{
						$output += "Port $($port.Name): $($port.Count) connexion(s)`n"
					}
					
					$suspiciousPorts = @(135, 139, 445, 3389)
					$suspiciousOpenPorts = $openPorts | Where-Object { $_.Name -in $suspiciousPorts }
					
					if ($suspiciousOpenPorts)
					{
						$output += "`nATTENTION! Ports suspects ouverts : $($suspiciousOpenPorts.Name -join ', ')`n"
					}
					else
					{
						$output += "`nAucun port suspect n'a été trouvé ouvert.`n"
					}
					
					$output += "`n"
					return $output
				}
				
				function Check-UsersAndGroups
				{
					$output = ""
					$userAccounts = Get-WmiObject -Class Win32_UserAccount
					$output += "Comptes d'utilisateurs :`n"
					foreach ($user in $userAccounts)
					{
						$output += "Nom: $($user.Name), FullName: $($user.FullName), Activé: $(!$user.Disabled), "
						$output += "Mot de passe modifiable: $($user.PasswordChangeable), "
						$output += "Mot de passe expire: $($user.PasswordExpires), "
						$output += "Mot de passe requis: $($user.PasswordRequired)`n"
					}
					$output += "`n"
					return $output
				}
				
				function Check-Services
				{
					$output = ""
					$inactiveServices = Get-Service | Where-Object { $_.StartType -eq 'Automatic' -and $_.Status -ne 'Running' }
					$output += "Services inactifs :`n"
					foreach ($service in $inactiveServices)
					{
						$output += "Nom: $($service.Name), DisplayName: $($service.DisplayName), Status: $($service.Status), StartType: $($service.StartType)`n"
					}
					$output += "`n"
					return $output
				}
				
				function Check-UAC
				{
					$UACStatus = (Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System").EnableLUA
					$output = "État de UAC : " + ('Désactivé', 'Activé')[$UACStatus] + "`n`n"
					return $output
				}
				
				function Check-Antivirus
				{
					$output = ""
					$defender = Get-MpComputerStatus
					
					if ($defender.AntivirusEnabled)
					{
						$output += "Windows Defender est actif.`n"
					}
					else
					{
						$output += "Windows Defender est inactif ou un autre Antivirus est présent.`n"
					}
					
					$antivirusMessage = if ($defender.AntivirusSignatureLastUpdated -lt (Get-Date).AddDays(-2))
					{
						"Windows Defender n'est pas à jour"
					}
					else
					{
						"Windows Defender est à jour"
					}
					$output += "État de l'antivirus : $antivirusMessage`n"
					$output += "Dernière mise à jour des signatures : $($defender.AntivirusSignatureLastUpdated)`n"
					
					$mbamService = Get-Service -Name MBAMService -ErrorAction SilentlyContinue
					if ($mbamService)
					{
						$output += "Le service Malwarebytes est $($mbamService.Status).`n"
					}
					else
					{
						$output += "Le service Malwarebytes n'est pas installé.`n"
					}
					
					$mbamProcess = Get-Process -Name mbam* -ErrorAction SilentlyContinue
					if ($mbamProcess)
					{
						$output += "Le processus Malwarebytes est en cours d'exécution.`n"
					}
					else
					{
						$output += "Le processus Malwarebytes n'est pas en cours d'exécution.`n"
					}
					
					$output += "`n"
					return $output
				}
				
				function Check-StartupPrograms
				{
					$output = ""
					$startupPrograms = Get-CimInstance -ClassName Win32_StartupCommand
					$output += "Programmes de démarrage :`n"
					foreach ($program in $startupPrograms)
					{
						$output += "Nom: $($program.Name)`n"
						$output += "Commande: $($program.Command)`n"
						$output += "Utilisateur: $($program.User)`n"
						$output += "Emplacement: $($program.Location)`n"
						$output += "-" * 50 + "`n"
					}
					$output += "`n"
					return $output
				}
				
				function Check-DiskSpace
				{
					$output = ""
					$disk = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'"
					$freeSpace = [math]::Round(($disk.FreeSpace / 1GB), 2)
					$totalSpace = [math]::Round(($disk.Size / 1GB), 2)
					$usedSpace = $totalSpace - $freeSpace
					$percentUsed = [math]::Round(($usedSpace / $totalSpace) * 100, 2)
					
					$output += "Espace disque sur C: :`n"
					$output += "Total : ${totalSpace}GB`n"
					$output += "Utilisé : ${usedSpace}GB (${percentUsed}%)`n"
					$output += "Disponible : ${freeSpace}GB`n`n"
					return $output
				}
				
				function Check-SystemUptime
				{
					$output = ""
					$os = Get-WmiObject Win32_OperatingSystem
					$uptime = (Get-Date) - $os.ConvertToDateTime($os.LastBootUpTime)
					$output += "Temps d'activité du système : $($uptime.Days) jours, $($uptime.Hours) heures, $($uptime.Minutes) minutes`n"
					$output += "Dernier démarrage : $($os.ConvertToDateTime($os.LastBootUpTime))`n`n"
					return $output
				}
				
				function Check-TopProcesses
				{
					$output = ""
					$topCPU = Get-Process | Sort-Object -Property CPU -Descending | Select-Object -First 5
					$output += "Top 5 des processus par utilisation du CPU :`n"
					foreach ($proc in $topCPU)
					{
						$output += "$($proc.Name): $([math]::Round($proc.CPU, 2)) s CPU, $([math]::Round($proc.WorkingSet64 / 1MB, 2)) MB Mémoire`n"
					}
					
					$output += "`nTop 5 des processus par utilisation de la mémoire :`n"
					$topMemory = Get-Process | Sort-Object -Property WorkingSet64 -Descending | Select-Object -First 5
					foreach ($proc in $topMemory)
					{
						$output += "$($proc.Name): $([math]::Round($proc.WorkingSet64 / 1MB, 2)) MB Mémoire, $([math]::Round($proc.CPU, 2)) s CPU`n"
					}
					
					$output += "`n"
					return $output
				}
				function Check-WindowsUpdates
				{
					$output = ""
					$updateSession = New-Object -ComObject Microsoft.Update.Session
					$updateSearcher = $updateSession.CreateUpdateSearcher()
					
					$lastInstallDate = (Get-WmiObject -Class Win32_QuickFixEngineering | Sort-Object -Property InstalledOn -Descending | Select-Object -First 1).InstalledOn
					$output += "Dernière mise à jour installée : $lastInstallDate`n"
					
					$pendingUpdates = $updateSearcher.Search("IsInstalled=0 and Type='Software'").Updates
					$output += "Nombre de mises à jour en attente : $($pendingUpdates.Count)`n"
					
					if ($pendingUpdates.Count -gt 0)
					{
						$output += "Mises à jour en attente :`n"
						foreach ($update in $pendingUpdates)
						{
							$output += " - $($update.Title)`n"
						}
					}
					
					$output += "`n"
					return $output
				}
				
				function Check-NetworkConfiguration
				{
					$output = ""
					$networkAdapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
					
					foreach ($adapter in $networkAdapters)
					{
						$output += "Adaptateur : $($adapter.Description)`n"
						$output += "Adresse IP : $($adapter.IPAddress -join ', ')`n"
						$output += "Masque de sous-réseau : $($adapter.IPSubnet -join ', ')`n"
						$output += "Passerelle par défaut : $($adapter.DefaultIPGateway -join ', ')`n"
						$output += "Serveurs DNS : $($adapter.DNSServerSearchOrder -join ', ')`n`n"
					}
					
					$vpnConnections = Get-VpnConnection
					if ($vpnConnections)
					{
						$output += "Connexions VPN :`n"
						foreach ($vpn in $vpnConnections)
						{
							$output += " - $($vpn.Name) : $($vpn.ConnectionStatus)`n"
						}
					}
					else
					{
						$output += "Aucune connexion VPN configurée.`n"
					}
					
					return $output
				}
				
				function Check-NetworkShares
				{
					$output = ""
					$shares = Get-WmiObject Win32_Share
					
					foreach ($share in $shares)
					{
						$output += "Nom du partage : $($share.Name)`n"
						$output += "Chemin : $($share.Path)`n"
						$output += "Description : $($share.Description)`n"
						
						$acl = Get-Acl $share.Path
						$output += "Permissions :`n"
						foreach ($access in $acl.Access)
						{
							$output += " - $($access.IdentityReference) : $($access.FileSystemRights)`n"
						}
						$output += "`n"
					}
					
					return $output
				}
				
				
				function Check-InstalledSoftware
				{
					$output = ""
					$software = Get-WmiObject -Class Win32_Product | Select-Object Name, Version
					
					foreach ($app in $software)
					{
						$output += "$($app.Name) - Version : $($app.Version)`n"
					}
					
					return $output
				}
				
				function Check-BitLockerStatus
				{
					$output = ""
					$bitlockerVolumes = Get-BitLockerVolume
					
					foreach ($volume in $bitlockerVolumes)
					{
						$output += "Lecteur : $($volume.MountPoint)`n"
						$output += "État de chiffrement : $($volume.VolumeStatus)`n"
						$output += "Pourcentage chiffré : $($volume.EncryptionPercentage)%`n`n"
					}
					
					return $output
				}
				
				function Check-ScheduledTasks
				{
					$output = ""
					$tasks = Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' }
					
					foreach ($task in $tasks)
					{
						$output += "Nom de la tâche : $($task.TaskName)`n"
						$output += "État : $($task.State)`n"
						$output += "Prochaine exécution : $($task.NextRunTime)`n`n"
					}
					
					return $output
				}
				
				function Check-SecurityEvents
				{
					$output = ""
					$failedLogins = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; ID = 4625 } -MaxEvents 10 -ErrorAction SilentlyContinue
					$adminGroupChanges = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; ID = 4732, 4733 } -MaxEvents 10 -ErrorAction SilentlyContinue
					
					$output += "10 dernières tentatives de connexion échouées :`n"
					foreach ($event in $failedLogins)
					{
						$output += " - $($event.TimeCreated) : $($event.Message)`n"
					}
					
					$output += "`n10 dernières modifications du groupe Administrateurs :`n"
					foreach ($event in $adminGroupChanges)
					{
						$output += " - $($event.TimeCreated) : $($event.Message)`n"
					}
					
					return $output
				}
				
				function Check-FirewallRules
				{
					$output = ""
					$rules = Get-NetFirewallRule | Where-Object { $_.Enabled -eq 'True' } | Select-Object Name, Direction, Action
					
					$output += "Règles de pare-feu actives :`n"
					foreach ($rule in $rules)
					{
						$output += " - $($rule.Name) : Direction=$($rule.Direction), Action=$($rule.Action)`n"
					}
					
					return $output
				}
				
				function Check-ThirdPartyServices
				{
					$output = ""
					$services = Get-WmiObject Win32_Service | Where-Object { $_.StartMode -eq 'Auto' -and $_.State -eq 'Running' -and $_.PathName -notlike '*\Windows\*' }
					
					$output += "Services tiers en cours d'exécution :`n"
					foreach ($service in $services)
					{
						$output += " - $($service.DisplayName) ($($service.Name))`n"
						$output += "   Chemin : $($service.PathName)`n"
					}
					
					return $output
				}
				
				function Check-PowerShellConfiguration
				{
					$output = ""
					$psVersion = $PSVersionTable.PSVersion
					$output += "Version de PowerShell : $($psVersion.Major).$($psVersion.Minor)`n"
					
					$transcriptionEnabled = (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription -ErrorAction SilentlyContinue).EnableTranscripting
					$output += "Journalisation des transcriptions : $(if ($transcriptionEnabled -eq 1) { 'Activée' }
						else { 'Désactivée' })`n"
					
					$scriptBlockLogging = (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging
					$output += "Journalisation des blocs de script : $(if ($scriptBlockLogging -eq 1) { 'Activée' }
						else { 'Désactivée' })`n"
					
					return $output
				}
				
				function Check-HyperVisorStatus
				{
					$output = ""
					$hyperV = Get-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V-All -Online
					$output += "État de Hyper-V : $($hyperV.State)`n"
					
					$virtualizationEnabled = (Get-WmiObject Win32_ComputerSystem).HypervisorPresent
					$output += "Virtualisation basée sur l'hyperviseur : $(if ($virtualizationEnabled) { 'Activée' }
						else { 'Désactivée' })`n"
					
					return $output
				}
				Add-Type -AssemblyName System.Windows.Forms
				[System.Windows.Forms.Application]::EnableVisualStyles()
				
				$global:outputFile = "C:\temp\AuditSecurite.txt"
				
				function Ensure-OutputFileReady
				{
					if (-not (Test-Path -Path "C:\temp"))
					{
						New-Item -ItemType Directory -Force -Path "C:\temp"
					}
					if (Test-Path -Path $global:outputFile)
					{
						Remove-Item -Path $global:outputFile -Force
					}
				}
				
				function Initialize-MainForm
				{
					$mainForm = New-Object System.Windows.Forms.Form
					$mainForm.Text = 'Audit de sécurité'
					$mainForm.Width = 300
					$mainForm.Height = 150
					
					$auditButton = New-Object System.Windows.Forms.Button
					$auditButton.Location = New-Object System.Drawing.Point(50, 30)
					$auditButton.Size = New-Object System.Drawing.Size(200, 30)
					$auditButton.Text = "Lancer l'audit"
					$auditButton.Add_Click({
							Start-SecurityAudit
							[System.Windows.Forms.MessageBox]::Show("Audit terminé. Le fichier va s'ouvrir dans le Bloc-notes.")
							Start-Process notepad.exe -ArgumentList $global:outputFile
						})
					
					$journauxButton = New-Object System.Windows.Forms.Button
					$journauxButton.Location = New-Object System.Drawing.Point(50, 70)
					$journauxButton.Size = New-Object System.Drawing.Size(200, 30)
					$journauxButton.Text = "Journaux Windows"
					$journauxButton.Add_Click({
							Show-WindowsLogs
							[System.Windows.Forms.MessageBox]::Show("Journaux extraits. Le fichier va s'ouvrir dans le Bloc-notes.")
							Start-Process notepad.exe -ArgumentList $global:outputFile
						})
					
					$mainForm.Controls.Add($auditButton)
					$mainForm.Controls.Add($journauxButton)
					
					return $mainForm
				}
				
				function Start-SecurityAudit
				{
					Ensure-OutputFileReady
					
					"========================= AUDIT DE SÉCURITÉ =========================" | Out-File -FilePath $global:outputFile -Force
					
					function Add-Section
					{
						param ([string]$title)
						"`n" + "=" * 70 | Out-File -FilePath $global:outputFile -Append
						$title | Out-File -FilePath $global:outputFile -Append
						"=" * 70 + "`n" | Out-File -FilePath $global:outputFile -Append
					}
					
					Add-Section "PARE-FEU"
					Check-Firewall | Out-File -FilePath $global:outputFile -Append
					
					Add-Section "PORTS"
					Check-OpenPorts | Out-File -FilePath $global:outputFile -Append
					
					Add-Section "UTILISATEURS ET GROUPES"
					Check-UsersAndGroups | Out-File -FilePath $global:outputFile -Append
					
					Add-Section "SERVICES"
					Check-Services | Out-File -FilePath $global:outputFile -Append
					
					Add-Section "CONTRÔLE DE COMPTE D'UTILISATEUR (UAC)"
					Check-UAC | Out-File -FilePath $global:outputFile -Append
					
					Add-Section "ANTIVIRUS"
					Check-Antivirus | Out-File -FilePath $global:outputFile -Append
					
					Add-Section "PROGRAMMES DE DÉMARRAGE"
					Check-StartupPrograms | Out-File -FilePath $global:outputFile -Append
					
					Add-Section "ESPACE DISQUE"
					Check-DiskSpace | Out-File -FilePath $global:outputFile -Append
					
					Add-Section "TEMPS D'ACTIVITÉ DU SYSTÈME"
					Check-SystemUptime | Out-File -FilePath $global:outputFile -Append
					
					Add-Section "PROCESSUS LES PLUS CONSOMMATEURS"
					Check-TopProcesses | Out-File -FilePath $global:outputFile -Append
					
					Add-Section "MISES À JOUR WINDOWS"
					Check-WindowsUpdates | Out-File -FilePath $global:outputFile -Append
					
					Add-Section "CONFIGURATION RÉSEAU"
					Check-NetworkConfiguration | Out-File -FilePath $global:outputFile -Append
					
					Add-Section "PARTAGES RÉSEAU"
					Check-NetworkShares | Out-File -FilePath $global:outputFile -Append
					
					Add-Section "LOGICIELS INSTALLÉS"
					Check-InstalledSoftware | Out-File -FilePath $global:outputFile -Append
					
					Add-Section "ÉTAT DE BITLOCKER"
					Check-BitLockerStatus | Out-File -FilePath $global:outputFile -Append
					
					Add-Section "TÂCHES PLANIFIÉES"
					Check-ScheduledTasks | Out-File -FilePath $global:outputFile -Append
					
					Add-Section "ÉVÉNEMENTS DE SÉCURITÉ SPÉCIFIQUES"
					Check-SecurityEvents | Out-File -FilePath $global:outputFile -Append
					
					Add-Section "CONFIGURATION DU PARE-FEU"
					Check-FirewallRules | Out-File -FilePath $global:outputFile -Append
					
					Add-Section "SERVICES TIERS"
					Check-ThirdPartyServices | Out-File -FilePath $global:outputFile -Append
					
					Add-Section "CONFIGURATION POWERSHELL"
					Check-PowerShellConfiguration | Out-File -FilePath $global:outputFile -Append
					
					Add-Section "VIRTUALISATION BASÉE SUR L'HYPERVISEUR"
					Check-HyperVisorStatus | Out-File -FilePath $global:outputFile -Append
					
					Add-Section "INFORMATIONS BIOS/UEFI"
					Check-BiosInfo | Out-File -FilePath $global:outputFile -Append
					
					"`n" + "=" * 70 | Out-File -FilePath $global:outputFile -Append
					"FIN DE L'AUDIT" | Out-File -FilePath $global:outputFile -Append
					"=" * 70 | Out-File -FilePath $global:outputFile -Append
				}
				
				function Check-Firewall
				{
					$output = ""
					$firewallProfiles = Get-NetFirewallProfile -Profile Domain, Public, Private
					foreach ($profile in $firewallProfiles)
					{
						$status = if ($profile.Enabled) { "Activé" }
						else { "Désactivé" }
						$output += "Profil $($profile.Name): $status`n"
					}
					$output += "`n"
					return $output
				}
				
				function Check-OpenPorts
				{
					$output = ""
					$openPorts = Get-NetTCPConnection | Where-Object { $_.State -eq "Listen" } |
					Group-Object -Property LocalPort |
					Sort-Object -Property Name
					
					$output += "Ports ouverts :`n"
					foreach ($port in $openPorts)
					{
						$output += "Port $($port.Name): $($port.Count) connexion(s)`n"
					}
					
					$suspiciousPorts = @(135, 139, 445, 3389)
					$suspiciousOpenPorts = $openPorts | Where-Object { $_.Name -in $suspiciousPorts }
					
					if ($suspiciousOpenPorts)
					{
						$output += "`nATTENTION! Ports suspects ouverts : $($suspiciousOpenPorts.Name -join ', ')`n"
					}
					else
					{
						$output += "`nAucun port suspect n'a été trouvé ouvert.`n"
					}
					
					$output += "`n"
					return $output
				}
				
				function Check-UsersAndGroups
				{
					$output = ""
					$userAccounts = Get-WmiObject -Class Win32_UserAccount
					$output += "Comptes d'utilisateurs :`n"
					foreach ($user in $userAccounts)
					{
						$output += "Nom: $($user.Name), FullName: $($user.FullName), Activé: $(!$user.Disabled), "
						$output += "Mot de passe modifiable: $($user.PasswordChangeable), "
						$output += "Mot de passe expire: $($user.PasswordExpires), "
						$output += "Mot de passe requis: $($user.PasswordRequired)`n"
					}
					$output += "`n"
					return $output
				}
				
				function Check-Services
				{
					$output = ""
					$inactiveServices = Get-Service | Where-Object { $_.StartType -eq 'Automatic' -and $_.Status -ne 'Running' }
					$output += "Services inactifs :`n"
					foreach ($service in $inactiveServices)
					{
						$output += "Nom: $($service.Name), DisplayName: $($service.DisplayName), Status: $($service.Status), StartType: $($service.StartType)`n"
					}
					$output += "`n"
					return $output
				}
				
				function Check-UAC
				{
					$UACStatus = (Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System").EnableLUA
					$output = "État de UAC : " + ('Désactivé', 'Activé')[$UACStatus] + "`n`n"
					return $output
				}
				
				function Check-Antivirus
				{
					$output = ""
					$defender = Get-MpComputerStatus
					
					if ($defender.AntivirusEnabled)
					{
						$output += "Windows Defender est actif.`n"
					}
					else
					{
						$output += "Windows Defender est inactif ou un autre Antivirus est présent.`n"
					}
					
					$antivirusMessage = if ($defender.AntivirusSignatureLastUpdated -lt (Get-Date).AddDays(-2))
					{
						"Windows Defender n'est pas à jour"
					}
					else
					{
						"Windows Defender est à jour"
					}
					$output += "État de l'antivirus : $antivirusMessage`n"
					$output += "Dernière mise à jour des signatures : $($defender.AntivirusSignatureLastUpdated)`n"
					
					$mbamService = Get-Service -Name MBAMService -ErrorAction SilentlyContinue
					if ($mbamService)
					{
						$output += "Le service Malwarebytes est $($mbamService.Status).`n"
					}
					else
					{
						$output += "Le service Malwarebytes n'est pas installé.`n"
					}
					
					$mbamProcess = Get-Process -Name mbam* -ErrorAction SilentlyContinue
					if ($mbamProcess)
					{
						$output += "Le processus Malwarebytes est en cours d'exécution.`n"
					}
					else
					{
						$output += "Le processus Malwarebytes n'est pas en cours d'exécution.`n"
					}
					
					$output += "`n"
					return $output
				}
				
				function Check-StartupPrograms
				{
					$output = ""
					$startupPrograms = Get-CimInstance -ClassName Win32_StartupCommand
					$output += "Programmes de démarrage :`n"
					foreach ($program in $startupPrograms)
					{
						$output += "Nom: $($program.Name)`n"
						$output += "Commande: $($program.Command)`n"
						$output += "Utilisateur: $($program.User)`n"
						$output += "Emplacement: $($program.Location)`n"
						$output += "-" * 50 + "`n"
					}
					$output += "`n"
					return $output
				}
				
				function Check-DiskSpace
				{
					$output = ""
					$disk = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'"
					$freeSpace = [math]::Round(($disk.FreeSpace / 1GB), 2)
					$totalSpace = [math]::Round(($disk.Size / 1GB), 2)
					$usedSpace = $totalSpace - $freeSpace
					$percentUsed = [math]::Round(($usedSpace / $totalSpace) * 100, 2)
					
					$output += "Espace disque sur C: :`n"
					$output += "Total : ${totalSpace}GB`n"
					$output += "Utilisé : ${usedSpace}GB (${percentUsed}%)`n"
					$output += "Disponible : ${freeSpace}GB`n`n"
					return $output
				}
				
				function Check-SystemUptime
				{
					$output = ""
					$os = Get-WmiObject Win32_OperatingSystem
					$uptime = (Get-Date) - $os.ConvertToDateTime($os.LastBootUpTime)
					$output += "Temps d'activité du système : $($uptime.Days) jours, $($uptime.Hours) heures, $($uptime.Minutes) minutes`n"
					$output += "Dernier démarrage : $($os.ConvertToDateTime($os.LastBootUpTime))`n`n"
					return $output
				}
				
				function Check-TopProcesses
				{
					$output = ""
					$topCPU = Get-Process | Sort-Object -Property CPU -Descending | Select-Object -First 5
					$output += "Top 5 des processus par utilisation du CPU :`n"
					foreach ($proc in $topCPU)
					{
						$output += "$($proc.Name): $([math]::Round($proc.CPU, 2)) s CPU, $([math]::Round($proc.WorkingSet64 / 1MB, 2)) MB Mémoire`n"
					}
					
					$output += "`nTop 5 des processus par utilisation de la mémoire :`n"
					$topMemory = Get-Process | Sort-Object -Property WorkingSet64 -Descending | Select-Object -First 5
					foreach ($proc in $topMemory)
					{
						$output += "$($proc.Name): $([math]::Round($proc.WorkingSet64 / 1MB, 2)) MB Mémoire, $([math]::Round($proc.CPU, 2)) s CPU`n"
					}
					
					$output += "`n"
					return $output
				}
				
				function Check-WindowsUpdates
				{
					$output = ""
					try
					{
						$updateSession = New-Object -ComObject Microsoft.Update.Session
						$updateSearcher = $updateSession.CreateUpdateSearcher()
						
						$lastInstallDate = (Get-WmiObject -Class Win32_QuickFixEngineering | Sort-Object -Property InstalledOn -Descending | Select-Object -First 1).InstalledOn
						$output += "Dernière mise à jour installée : $lastInstallDate`n"
						
						$pendingUpdates = $updateSearcher.Search("IsInstalled=0 and Type='Software'").Updates
						$output += "Nombre de mises à jour en attente : $($pendingUpdates.Count)`n"
						
						if ($pendingUpdates.Count -gt 0)
						{
							$output += "Mises à jour en attente :`n"
							foreach ($update in $pendingUpdates)
							{
								$output += " - $($update.Title)`n"
							}
						}
					}
					catch
					{
						$output += "Impossible de vérifier les mises à jour Windows : $($_.Exception.Message)`n"
					}
					
					$output += "`n"
					return $output
				}
				function Check-NetworkConfiguration
				{
					$output = ""
					$networkAdapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
					
					foreach ($adapter in $networkAdapters)
					{
						$output += "Adaptateur : $($adapter.Description)`n"
						$output += "Adresse IP : $($adapter.IPAddress -join ', ')`n"
						$output += "Masque de sous-réseau : $($adapter.IPSubnet -join ', ')`n"
						$output += "Passerelle par défaut : $($adapter.DefaultIPGateway -join ', ')`n"
						$output += "Serveurs DNS : $($adapter.DNSServerSearchOrder -join ', ')`n`n"
					}
					
					$vpnConnections = Get-VpnConnection -ErrorAction SilentlyContinue
					if ($vpnConnections)
					{
						$output += "Connexions VPN :`n"
						foreach ($vpn in $vpnConnections)
						{
							$output += " - $($vpn.Name) : $($vpn.ConnectionStatus)`n"
						}
					}
					else
					{
						$output += "Aucune connexion VPN configurée ou impossible d'obtenir les informations VPN.`n"
					}
					
					return $output
				}
				
				function Check-NetworkShares
				{
					$output = ""
					$shares = Get-WmiObject Win32_Share
					
					foreach ($share in $shares)
					{
						$output += "Nom du partage : $($share.Name)`n"
						$output += "Chemin : $($share.Path)`n"
						$output += "Description : $($share.Description)`n"
						
						if (![string]::IsNullOrEmpty($share.Path) -and (Test-Path $share.Path))
						{
							try
							{
								$acl = Get-Acl $share.Path
								$output += "Permissions :`n"
								foreach ($access in $acl.Access)
								{
									$output += " - $($access.IdentityReference) : $($access.FileSystemRights)`n"
								}
							}
							catch
							{
								$output += "Impossible d'obtenir les permissions pour ce partage.`n"
							}
						}
						else
						{
							$output += "Impossible d'obtenir les permissions pour ce partage (chemin invalide ou inaccessible).`n"
						}
						$output += "`n"
					}
					
					return $output
				}
				
				
				function Check-InstalledSoftware
				{
					$output = ""
					$software = Get-WmiObject -Class Win32_Product | Select-Object Name, Version
					
					foreach ($app in $software)
					{
						$output += "$($app.Name) - Version : $($app.Version)`n"
					}
					
					return $output
				}
				
				function Check-BitLockerStatus
				{
					$output = ""
					if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)
					{
						$bitlockerVolumes = Get-BitLockerVolume
						
						foreach ($volume in $bitlockerVolumes)
						{
							$output += "Lecteur : $($volume.MountPoint)`n"
							$output += "État de chiffrement : $($volume.VolumeStatus)`n"
							$output += "Pourcentage chiffré : $($volume.EncryptionPercentage)%`n`n"
						}
					}
					else
					{
						$output += "La commande Get-BitLockerVolume n'est pas disponible sur ce système.`n"
					}
					
					return $output
				}
				
				function Check-ScheduledTasks
				{
					$output = ""
					$tasks = Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' }
					
					foreach ($task in $tasks)
					{
						$output += "Nom de la tâche : $($task.TaskName)`n"
						$output += "État : $($task.State)`n"
						$output += "Prochaine exécution : $($task.NextRunTime)`n`n"
					}
					
					return $output
				}
				
				function Check-SecurityEvents
				{
					$output = ""
					$failedLogins = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; ID = 4625 } -MaxEvents 10 -ErrorAction SilentlyContinue
					$adminGroupChanges = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; ID = 4732, 4733 } -MaxEvents 10 -ErrorAction SilentlyContinue
					
					$output += "10 dernières tentatives de connexion échouées :`n"
					foreach ($event in $failedLogins)
					{
						$output += " - $($event.TimeCreated) : $($event.Message)`n"
					}
					
					$output += "`n10 dernières modifications du groupe Administrateurs :`n"
					foreach ($event in $adminGroupChanges)
					{
						$output += " - $($event.TimeCreated) : $($event.Message)`n"
					}
					
					return $output
				}
				
				function Check-FirewallRules
				{
					$output = ""
					$rules = Get-NetFirewallRule | Where-Object { $_.Enabled -eq 'True' } | Select-Object Name, Direction, Action
					
					$output += "Règles de pare-feu actives :`n"
					foreach ($rule in $rules)
					{
						$output += " - $($rule.Name) : Direction=$($rule.Direction), Action=$($rule.Action)`n"
					}
					
					return $output
				}
				
				function Check-ThirdPartyServices
				{
					$output = ""
					$services = Get-WmiObject Win32_Service | Where-Object { $_.StartMode -eq 'Auto' -and $_.State -eq 'Running' -and $_.PathName -notlike '*\Windows\*' }
					
					$output += "Services tiers en cours d'exécution :`n"
					foreach ($service in $services)
					{
						$output += " - $($service.DisplayName) ($($service.Name))`n"
						$output += "   Chemin : $($service.PathName)`n"
					}
					
					return $output
				}
				
				function Check-PowerShellConfiguration
				{
					$output = ""
					$psVersion = $PSVersionTable.PSVersion
					$output += "Version de PowerShell : $($psVersion.Major).$($psVersion.Minor)`n"
					
					$transcriptionEnabled = (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription -ErrorAction SilentlyContinue).EnableTranscripting
					$output += "Journalisation des transcriptions : $(if ($transcriptionEnabled -eq 1) { 'Activée' }
						else { 'Désactivée' })`n"
					
					$scriptBlockLogging = (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging
					$output += "Journalisation des blocs de script : $(if ($scriptBlockLogging -eq 1) { 'Activée' }
						else { 'Désactivée' })`n"
					
					return $output
				}
				
				function Check-HyperVisorStatus
				{
					$output = ""
					$hyperV = Get-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V-All -Online -ErrorAction SilentlyContinue
					if ($hyperV)
					{
						$output += "État de Hyper-V : $($hyperV.State)`n"
					}
					else
					{
						$output += "Impossible de déterminer l'état de Hyper-V.`n"
					}
					
					$virtualizationEnabled = (Get-WmiObject Win32_ComputerSystem).HypervisorPresent
					$output += "Virtualisation basée sur l'hyperviseur : $(if ($virtualizationEnabled) { 'Activée' }
						else { 'Désactivée' })`n"
					
					return $output
				}
				
				function Check-BiosInfo
				{
					$output = ""
					$bios = Get-WmiObject Win32_BIOS
					$output += "Fabricant du BIOS : $($bios.Manufacturer)`n"
					$output += "Version du BIOS : $($bios.SMBIOSBIOSVersion)`n"
					$output += "Date de sortie du BIOS : $($bios.ReleaseDate)`n"
					
					$secureBootStatus = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
					if ($null -ne $secureBootStatus)
					{
						$output += "État de Secure Boot : $(if ($secureBootStatus) { 'Activé' }
							else { 'Désactivé' })`n"
					}
					else
					{
						$output += "Impossible de déterminer l'état de Secure Boot.`n"
					}
					
					return $output
				}
				
				function Show-WindowsLogs
				{
					Ensure-OutputFileReady
					$output = "========================= JOURNAUX WINDOWS =========================`n`n"
					
					function ListEventsForLog
					{
						param ([string]$logName)
						
						$output += "=" * 70 + "`n"
						$output += "JOURNAL : $logName`n"
						$output += "=" * 70 + "`n`n"
						
						function ListEvents
						{
							param (
								[System.Collections.Generic.List[PSObject]]$events,
								[string]$eventType
							)
							
							if ($events.Count -gt 0)
							{
								$output += "$eventType trouvés : $($events.Count)`n`n"
								$uniqueEvents = $events | Group-Object -Property Message | ForEach-Object { $_.Group[0] }
								foreach ($event in $uniqueEvents)
								{
									$output += "Date/Heure : $($event.TimeCreated)`n"
									$output += "ID : $($event.Id)`n"
									$output += "Message : $($event.Message)`n"
									$output += "-" * 50 + "`n"
								}
							}
							else
							{
								$output += "Aucun $eventType trouvé.`n`n"
							}
							return $output
						}
						
						$criticalFilterXml = "<QueryList><Query Id='0' Path='$logName'><Select Path='$logName'>*[System[(Level=1)]]</Select></Query></QueryList>"
						$warningFilterXml = "<QueryList><Query Id='0' Path='$logName'><Select Path='$logName'>*[System[(Level=3)]]</Select></Query></QueryList>"
						
						$criticalErrors = Get-WinEvent -FilterXml $criticalFilterXml -ErrorAction SilentlyContinue
						$warnings = Get-WinEvent -FilterXml $warningFilterXml -ErrorAction SilentlyContinue
						
						$output = ListEvents -events $criticalErrors -eventType "Erreurs critiques"
						$output = ListEvents -events $warnings -eventType "Avertissements"
						
						$output += "`n"
						return $output
					}
					
					$output += ListEventsForLog -logName "System"
					$output += ListEventsForLog -logName "Security"
					$output += ListEventsForLog -logName "Application"
					
					$output += "=" * 70 + "`n"
					$output += "FIN DES JOURNAUX`n"
					$output += "=" * 70 + "`n"
					
					$output | Out-File -FilePath $global:outputFile
				}
				
				$mainForm, $progressBar = Initialize-MainForm
				[void]$mainForm.ShowDialog()