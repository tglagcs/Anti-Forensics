# Anti-Forensics

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://mit-license.org/) ![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg) ![Windows](https://img.shields.io/badge/Windows-10%2F11-green.svg)

> ⚠️ **Warning**  
> This script is intended **strictly for educational and research purposes**.  
> Unauthorized use on systems you do not own or have permission to test is illegal and may result in criminal liability.  
> The author and contributors take no responsibility for any misuse or resulting consequences.

## 📝 Description
A PowerShell script designed to remove Windows forensic artifacts commonly used in digital forensics to reconstruct user activity.  
The script covers a wide range of artifacts and is relevant as of 2026.

## 🧐 Intended Use Cases
- Studying OPSEC principles and digital traces in Windows systems
- Educational and research activities in DFIR
- Validation of detection and incident response procedures
- Analysis of the persistence and resilience of Windows forensic artifacts

## ⚙ Core Features
1. Automatically restarts itself with administrative privileges if launched without them.
2. Prompts the user whether to generate a log file upon completion.
3. Terminates `explorer.exe` and temporarily disables shell auto-restart to avoid interference during cleanup.
4. Cleans key forensic artifacts, including:
	- **Event Logs** — Complete clearing of all Windows event logs (Application, Security, System, etc.) using `wevtutil` and CIM, removing records of user activity, logons, and errors.
	- **Shadow Copies (VSS)** — Removal of all Volume Shadow Copies via `vssadmin` and CIM to prevent recovery of previous file versions.
	- **ShimCache / AppCompatCache & Amcache** — Cleanup of registry keys and files storing application execution history (AppCompatCache, `Amcache.hve`, `RecentFileCache.bcf`).
	- **BAM / DAM** — Removal of registry keys containing application execution history (Background Activity Moderator / Desktop Activity Moderator).
	- **MRU, Recent Files, Jump Lists** — Cleanup of recently opened files, documents, folders, Automatic/Custom Destinations, and related registry keys (`RunMRU`, `WordWheelQuery`, `RecentDocs`, `ComDlg32`).
	- **PowerShell History, WER (Windows Error Reporting)** — Deletion of PowerShell command history (PSReadLine) and application/system crash reports (`ReportQueue`, `ReportArchive`).
	- **Recycle Bin** — Full cleanup of the Recycle Bin across all drives, including hidden `$Recycle.Bin` directories (preserving directory structure).
	- **SRUM (System Resource Usage Monitor)** — Stops related services and removes `SRUDB.dat` and logs containing resource usage, application execution, and network activity data.
	- **ActivitiesCache.db (Windows Timeline)** — Removal of user activity databases containing chronological records of application and file usage.
	- **Windows Recall** — Cleanup of Windows Recall data (AI screenshots and semantic database on Copilot+ PCs, introduced in 2025): removal of screenshots from `ImageStore`, `ukg.db` databases (OCR text and URLs), and related `.sidb` files  
	  (path: `C:\Users\%username%\AppData\Local\CoreAIPlatform.00\UKP\{GUID}\`).
	- **Notification Artifacts** — Cleanup of the Windows notification database (`wpndatabase.db` and related files) containing toast notification content, timestamps, and sources (emails, messages, system events).
	- **Thumbcache / IconCache, DNS Cache** — Removal of thumbnail and icon caches, flushing DNS cache (`ipconfig /flushdns`) and NetBIOS cache (`nbtstat`).
	- **USN Journal** — Deletion of the NTFS USN Change Journal on the system drive.
	- **LastAccess Timestamps** — Disables file last access time updates (`fsutil behavior set disablelastaccess 1`).
	- **Temp / Prefetch** — Aggressive cleanup of temporary directories and Prefetch files (with directory recreation), removing evidence of application execution.
	- **UserAssist, ShellBags, FeatureUsage** — Cleanup of registry data related to executed programs, Explorer navigation, typed paths, and Windows feature usage.
	- **Junk Files** — Additional cleanup of temporary and junk files by extension (`*.tmp`, `*.log`, `*.bak`, etc.) on drive `C:` (limited depth).
	- **PCA (Program Compatibility Assistant)** — Cleanup of files in `C:\Windows\AppCompat\pca` with directory recreation.
5. Restarts `explorer.exe` upon completion.

## 🚀 Execution
In PowerShell:
```powershell
& '.\Anti-Forensics.ps1'
```

---
**Community feedback and suggestions are welcome** 🤗🐢

**Author: [@lag_cs](https://t.me/lag_cs)** 🐱‍💻  
**Special thanks: ChatGPT, Grok, DeepSeek** 🤖

**Tags:** #anti-forensics #windows-forensics #powershell #dfir #redteam #windows-recall #recallwipers #opsec #artifactswipe #timestomping #shadowcopies #eventlogs #amcache #shimcache #srum #prefetch #blueteam #purpleteam #incident-response #windows-security
