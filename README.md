# Notepad++ Detection & Remediation Scripts
This folder contains two scripts used for Notepad++ compliance detection and remediation.

## 1) `Notepad++ (Detection).ps1`
### Purpose
Detects whether Notepad++ is installed and whether the installed version is compliant.

### What it checks
- Installation presence (registry, common install paths, and PATH lookup)
- Installed version
- Install path
- Last used timestamp (from Prefetch)
- Install date (registry `InstallDate` or registry key last write time fallback)
- Install method:
  - Intune
  - Scoop
  - Chocolatey
  - Winget
  - MSI Installer
  - EXE Installer
  - Portable
  - Unknown

### Output behavior
When installed, emits one semicolon-delimited line with details such as version, install path, last used, and install method.

### Exit codes
- `0` = Compliant (not installed OR installed and version is at/above minimum)
- `1` = Non-compliant (installed but version is below minimum, or version parse failure)

### Minimum version in script
- Hardcoded as `8.9.1` in current detection logic.

---

## 2) `Notepad++ Update User Prompt (Remediation).ps1`
### Purpose
Remediates vulnerable Notepad++ installations by uninstalling and/or upgrading to latest GitHub release with optional user deferrals.

### High-level flow
1. Pull latest Notepad++ x64 installer from GitHub Releases API.
2. Detect installed version and uninstall metadata.
3. If app is not installed or already current, exit success.
4. Check usage via Prefetch:
   - If unused for threshold (default 180 days), silent uninstall path.
5. If app is in use and process is running, show WPF prompt with up to 2 deferrals.
6. Upgrade decision logic:
   - If uninstall registry key **and** uninstall executable exist: uninstall first, then install latest.
   - If both are missing: verify `notepad++.exe`; if outdated, install latest over top.
   - If uninstall metadata is incomplete: install latest over top.
7. Verify installation and return status.

### Key defaults
- Log file: `C:\Temp\NPP_Update.log`
- Unused threshold: `180` days
- Max deferrals: `2`
- Requires admin rights (`#Requires -RunAsAdministrator`)

### Exit codes
- `0` = Success/compliant end state
- `1` = Remediation failure/critical error

---

## Notes
- Detection script minimum version is currently static (`8.9.1`), while remediation script dynamically tracks latest GitHub release.
- If you want both scripts aligned to the same version source, update detection to use the same GitHub release lookup pattern.
