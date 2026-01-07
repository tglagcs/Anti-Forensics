Clear-Host
Write-Host ""
Write-Host "===== Anti-Forensics by @lag_cs =====" -ForegroundColor Cyan
Write-Host ""

Function Start-AntiForensics {
    [CmdletBinding(SupportsShouldProcess = $true)]
    Param([String[]]$Additional)

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'SilentlyContinue'
    $WarningPreference = 'SilentlyContinue'

    # ==== ELEVATION CHECK ====
    $IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $IsAdmin) {
        Write-Host "Requesting Administrator privileges..." -ForegroundColor Yellow
        Start-Process pwsh -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
        exit
    }

    # ==== LOGGING SETUP ====
    Clear-Host
    Write-Host ""
    Write-Host "===== Anti-Forensics Enhanced by @lag_cs =====" -ForegroundColor Cyan
    Write-Host ""
    
    do {
        $logChoice = Read-Host "Do you want to write logs? (yes/no)"
        $logChoice = $logChoice.Trim().ToLower()
    } while ($logChoice -notin @("yes","y","no","n",""))
    
    $EnableLogging = ($logChoice -in @("yes","y"))
    $LogFile = $null
    
    if ($EnableLogging) {
        $ScriptDir = Split-Path -Parent $PSCommandPath
        $LogFile = Join-Path $ScriptDir "AntiForensics.log"
        Remove-Item -Path $LogFile -ErrorAction SilentlyContinue
        "Anti-Forensics log started at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Out-File -FilePath $LogFile -Encoding UTF8
        Write-Host "[!] Warning: Logging creates its own forensic artifacts!" -ForegroundColor Red
    }

    # Logging helper function
    function Write-Log {
        param([string]$Message)
        if ($EnableLogging) {
            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message" | Out-File -Append -FilePath $LogFile -Encoding UTF8
        }
    }

    # --- Helper: Take ownership ---
    function Invoke-TakeOwnership {
        param([Parameter(Mandatory)][string]$Path)
        if (Test-Path -LiteralPath $Path) {
            Write-Log "Taking ownership: $Path"
            & takeown.exe /F $Path /A /R /D Y 2>$null | Out-Null
            & icacls.exe $Path /inheritance:e /grant '*S-1-5-32-544:F' /T /Q /C 2>$null | Out-Null
        }
    }

    # --- Helper: Remove items ---
	function Remove-Items {
		[CmdletBinding(SupportsShouldProcess)]
		param(
			[Parameter(ValueFromPipeline, Mandatory)][string[]]$Path,
			[switch]$ForceOwnership,
			[switch]$PreserveStructure
		)
		
		process {
			foreach ($p in $Path) {
				# Process registry paths
				if ($p -match '^(HKLM|HKCU|HKCR|HKU):') {
					if (Test-Path -LiteralPath $p) {
						if ($PSCmdlet.ShouldProcess($p, 'Remove registry item')) {
							Write-Log "Deleting registry: $p"
							try {
								Remove-Item -Path $p -Recurse -Force -ErrorAction Stop
							} catch {
								Get-ChildItem -LiteralPath $p -Force -ErrorAction SilentlyContinue | ForEach-Object {
									try { Remove-Item -Path $_.PSPath -Recurse -Force -ErrorAction Stop } catch {}
								}
							}
						}
					}
					continue
				}

				# Process file system paths
				# FIXED: safer path existence check
				$pathExists = $false
				if ($p -match '[\*\?\[\]]') {
					# For paths with wildcards, check via Get-ChildItem
					$items = @(Get-ChildItem -Path $p -ErrorAction SilentlyContinue)
					$pathExists = ($items.Count -gt 0)
				} else {
					# For regular paths, use Test-Path
					$pathExists = Test-Path -LiteralPath $p -ErrorAction SilentlyContinue
				}
				
				if ($pathExists) {
					Get-ChildItem -LiteralPath $p -Force -ErrorAction SilentlyContinue | ForEach-Object {
						$item = $_.FullName
						if ($PSCmdlet.ShouldProcess($item, 'Remove file system item')) {
							Write-Log "Deleting: $item"
							try {
								Remove-Item -LiteralPath $item -Recurse -Force -ErrorAction Stop
							} catch {
								if ($ForceOwnership) {
									Invoke-TakeOwnership -Path $item
									Remove-Item -LiteralPath $item -Recurse -Force -ErrorAction SilentlyContinue
								}
							}
						}
					}
					
					if ($PreserveStructure) {
						try {
							Get-ChildItem -LiteralPath $p -Force -ErrorAction SilentlyContinue | 
								Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
						} catch {}
					}
				}
			}
		}
	}

    # --- Consolidated cleanup function ---
	function Clean-Paths {
		param(
			[string[]]$Paths,
			[switch]$ForceOwnership,
			[switch]$RecreateDirectory,
			[switch]$PreserveStructure
		)
		
		foreach ($path in $Paths) {
			try {
				# Check if path contains wildcards
				if ($path -match '[\*\?\[\]]') {
					# Path contains wildcards - process via Get-ChildItem
					$items = @(Get-ChildItem -Path $path -ErrorAction SilentlyContinue)
					if ($items.Count -gt 0) {
						foreach ($item in $items) {
							$item.FullName | Remove-Items -ForceOwnership:$ForceOwnership -PreserveStructure:$PreserveStructure
						}
					} else {
						# If Get-ChildItem found no files, but path might be a directory with *
						# Example: "C:\Windows\Temp\*" - directory exists but no files
						$dirPath = $path -replace '[\*\?].*$', ''
						if ($dirPath -ne $path -and (Test-Path -LiteralPath $dirPath -ErrorAction SilentlyContinue)) {
							$dirPath | Remove-Items -ForceOwnership:$ForceOwnership -PreserveStructure:$PreserveStructure
						}
					}
				} else {
					# Regular path without wildcards
					if (Test-Path -LiteralPath $path) {
						$path | Remove-Items -ForceOwnership:$ForceOwnership -PreserveStructure:$PreserveStructure
						if ($RecreateDirectory) {
							try {
								New-Item -Path $path -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
							} catch {}
						}
					}
				}
			} catch {
				Write-Log "Error in Clean-Paths for '$path': $_"
			}
		}
	}

    # --- Explorer handling ---
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $autoRestartValue = $null
    
    try { 
        $autoRestartValue = (Get-ItemProperty -Path $regPath -Name AutoRestartShell -ErrorAction Stop).AutoRestartShell 
    } catch {}
    
    # ==== MAIN CLEANUP ====
    try {
        # Stop Explorer
        Get-Process explorer -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500
        
        if ($PSCmdlet.ShouldProcess($regPath, 'Disable AutoRestartShell')) {
            Set-ItemProperty -Path $regPath -Name AutoRestartShell -Value 0 -Force
        }
        
        if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Anti-Forensics Cleanup')) { return }
        
        Write-Host "[1/8] Clearing Event Logs..." -ForegroundColor Yellow
        # === Event Logs ===
        $eventLogs = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | Where-Object { $_.IsEnabled -and $_.RecordCount -gt 0 }
        foreach ($log in $eventLogs) {
            Write-Log "Clearing Event Log: $($log.LogName)"
            try {
                wevtutil.exe cl $log.LogName 2>$null | Out-Null
            } catch {
                try {
                    [Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog($log.LogName)
                } catch {}
            }
        }

        Write-Host "[2/8] Removing Shadow Copies..." -ForegroundColor Yellow
        # === Shadow Copies ===
        try {
            vssadmin.exe delete shadows /all /quiet 2>$null | Out-Null
            Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue | ForEach-Object {
                Write-Log "Deleting Shadow Copy ID: $($_.ID)"
                $_.Delete()
            }
        } catch {}

        Write-Host "[3/8] Clearing System Artifacts..." -ForegroundColor Yellow
        # === ShimCache / Amcache ===
        Clean-Paths -Paths @(
            "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"
            "C:\Windows\AppCompat\Programs\Amcache.hve*"
            "C:\Windows\AppCompat\Programs\RecentFileCache.bcf"
        ) -ForceOwnership

        # === BAM / DAM ===
        Clean-Paths -Paths @(
            "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
            "HKLM:\SYSTEM\CurrentControlSet\Services\dam\State\UserSettings"
        ) -ForceOwnership

        # === Windows Defender History ===
        Clean-Paths -Paths @(
            "C:\ProgramData\Microsoft\Windows Defender\Scans\History\*"
            "C:\ProgramData\Microsoft\Windows Defender\Support\*"
        ) -ForceOwnership

        Write-Host "[4/8] Clearing User Activity Traces..." -ForegroundColor Yellow
        # === MRU / Recent / Jump Lists ===
        Clean-Paths -Paths @(
            "$Env:APPDATA\Microsoft\Windows\Recent\*"
            "$Env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations\*"
            "$Env:APPDATA\Microsoft\Windows\Recent\CustomDestinations\*"
            "$Env:LOCALAPPDATA\Microsoft\Windows\Explorer\*"
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery"
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32"
        ) -ForceOwnership

        # === PowerShell History + WER ===
        Clean-Paths -Paths @(
            "$Env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\*"
            "$Env:LOCALAPPDATA\Microsoft\Windows\WER\ReportQueue\*"
            "$Env:LOCALAPPDATA\Microsoft\Windows\WER\ReportArchive\*"
            "$Env:PROGRAMDATA\Microsoft\Windows\WER\ReportQueue\*"
            "$Env:PROGRAMDATA\Microsoft\Windows\WER\ReportArchive\*"
        ) -ForceOwnership

        Write-Host "[5/8] Clearing Recycle Bin and SRUM..." -ForegroundColor Yellow
        # === Recycle Bin ===
        Get-PSDrive -PSProvider FileSystem | ForEach-Object {
			if ($_.Root) {
				$driveRoot = $_.Root.TrimEnd('\')
				# Using backtick to escape $
				$recyclePath = "${driveRoot}\`$Recycle.Bin"
				
				if (Test-Path -LiteralPath $recyclePath) {
					Write-Log "Clearing Recycle Bin at: $recyclePath"
					Clean-Paths -Paths $recyclePath -ForceOwnership -PreserveStructure
				}
			}
		}

        # === SRU (SRUM) ===
        try {
            Stop-Service -Name DPS -Force -ErrorAction SilentlyContinue
            Stop-Service -Name PcaSvc -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
            
            Clean-Paths -Paths @(
                "C:\Windows\System32\sru\SRUDB.dat"
                "C:\Windows\System32\sru\*.log"
                "C:\Windows\System32\sru\*.chk"
            ) -ForceOwnership
        } finally {
            Start-Service -Name DPS -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            Start-Service -Name PcaSvc -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        }

        Write-Host "[6/8] Clearing Timeline and Recall..." -ForegroundColor Yellow
        # === Timeline (ActivitiesCache.db) ===
        Get-ChildItem "${Env:SystemDrive}\Users\*\AppData\Local\ConnectedDevicesPlatform\*\ActivitiesCache.db*" -Force -ErrorAction SilentlyContinue |
            ForEach-Object { $_.FullName } | Remove-Items -ForceOwnership

        # === Windows Recall (AI Timeline) ===
		if ([System.Environment]::OSVersion.Version.Build -ge 26000) {
			$recallPaths = @(
				"$Env:LOCALAPPDATA\Packages\Microsoft.Windows.Recall*"
				"$Env:LOCALAPPDATA\Packages\Microsoft.Windows.Ai.DataStore*"
				"$Env:LOCALAPPDATA\Microsoft\Windows\Recall"
				"$Env:LOCALAPPDATA\CoreAIPlatform*"
				# FIXED: escaping $ in environment variables
				"${Env:SystemDrive}\Users\*\AppData\Local\CoreAIPlatform*\UKP\*\*.db"
				"${Env:SystemDrive}\Users\*\AppData\Local\Microsoft\Windows\Recall\ImageStore\*"
			)

			foreach ($recallPath in $recallPaths) {
				# For paths with wildcards, use Get-ChildItem directly
				if ($recallPath -match '[\*\?]') {
					Get-ChildItem -Path $recallPath -Force -ErrorAction SilentlyContinue |
						Where-Object { 
							$_.FullName -like "*\ImageStore\*" -or 
							$_.FullName -like "*\ukg.db*" -or
							$_.FullName -like "*\.sidb" -or
							$_.FullName -like "*\*.mspc" -or
							$_.FullName -like "*\Recall*.db"
						} |
						ForEach-Object { $_.FullName } | Remove-Items -ForceOwnership
				} elseif (Test-Path -LiteralPath $recallPath) {
					Clean-Paths -Paths $recallPath -ForceOwnership
				}
			}
		}

        # === Notification artifacts ===
        Clean-Paths -Paths @(
            "$Env:LOCALAPPDATA\Microsoft\Windows\Notifications\wpndatabase.*"
            "$Env:LOCALAPPDATA\Microsoft\Windows\Notifications\*.db"
        ) -ForceOwnership

        Write-Host "[7/8] Clearing Caches and Temporary Files..." -ForegroundColor Yellow
        # === Thumbcache + IconCache + DNS ===
        Clean-Paths -Paths @(
            "$Env:LOCALAPPDATA\Microsoft\Windows\Explorer\thumbcache*.db"
            "$Env:LOCALAPPDATA\Microsoft\Windows\Explorer\IconCache*.db"
            "$Env:LOCALAPPDATA\Microsoft\Windows\Explorer\iconcache_*.db"
        ) -ForceOwnership
        
        ipconfig /flushdns 2>$null | Out-Null
        nbtstat -R 2>$null | Out-Null

        # === USN Journal + LastAccess ===
        fsutil usn deletejournal /d C: 2>$null | Out-Null
        fsutil behavior set disablelastaccess 1 2>$null | Out-Null

        # === Temp folders & Prefetch ===
        $TempPaths = @(
            "$Env:SystemRoot\Prefetch\*"
            "$Env:SystemRoot\Temp\*"
            "$Env:TEMP\*"
            "$Env:LOCALAPPDATA\Temp\*"
            "$Env:USERPROFILE\AppData\LocalLow\Temp\*"
            "C:\Windows\Logs\*"
            "C:\Windows\SoftwareDistribution\Download\*"
        )
        
        Clean-Paths -Paths $TempPaths -ForceOwnership -RecreateDirectory

        # === UserAssist + ShellBags + FeatureUsage ===
        Clean-Paths -Paths @(
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
            "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell"
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage"
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"
        ) -ForceOwnership

        Write-Host "[8/8] Final Cleanup..." -ForegroundColor Yellow
        # === Junk files cleanup ===
        $JunkExtensions = @("*.tmp", "*.log", "*._mp", "*.gid", "*.chk", "*.old", "*.bak", "*.dmp", "*.etl", "*.evtx")
        foreach ($ext in $JunkExtensions) {
            Get-ChildItem -Path "C:\" -Filter $ext -Recurse -Depth 2 -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -notlike "*\`$Recycle.Bin\*" -and $_.FullName -notlike "*\System Volume Information\*" } |
                ForEach-Object { $_.FullName } | Remove-Items -ForceOwnership
        }

        # === Program Compatibility Assistant (PCA) ===
        Clean-Paths -Paths @("C:\Windows\AppCompat\pca\*") -ForceOwnership -RecreateDirectory

        # === Clear Windows Error Reporting Settings ===
        reg delete "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /f 2>$null | Out-Null
        
        Write-Log "Anti-Forensics cleanup completed at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        Write-Host "[✓] Cleanup completed successfully!" -ForegroundColor Green
    }
    catch {
        Write-Host "[!] Error during cleanup: $_" -ForegroundColor Red
        Write-Log "ERROR: $_"
    }
    finally {
        # Restore explorer
        try {
            if ($null -ne $autoRestartValue) {
                Set-ItemProperty -Path $regPath -Name AutoRestartShell -Value $autoRestartValue -Force
            } else {
                Set-ItemProperty -Path $regPath -Name AutoRestartShell -Value 1 -Force
            }
            
            # Give time for restoration
            Start-Sleep -Seconds 1
            Start-Process explorer.exe -WindowStyle Hidden
            Start-Sleep -Seconds 2
        } catch {
            # If restoration fails, start explorer manually
            Start-Process explorer.exe
        }
    }
}

# Start cleanup
Start-AntiForensics

Write-Host ""
Write-Host "===== Cleanup Finished =====" -ForegroundColor Green
if ($EnableLogging) {
    Write-Host "[!] Log saved to: $LogFile" -ForegroundColor Yellow
    Write-Host "[!] Remember to delete the log file if stealth is required!" -ForegroundColor Red
}

Write-Host ""
Read-Host "Press Enter to exit"