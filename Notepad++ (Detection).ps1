<#
.SYNOPSIS
    Detects Notepad++ installation details including version, last usage, and installation method.
.DESCRIPTION
    This script checks for Notepad++ installation and reports:
    - Installed version
    - Last used timestamp (based on Windows Prefetch data)
    - Installation method (MSI, EXE installer, Chocolatey, Winget, Scoop, or Portable)
.EXAMPLE
    .\Get-NotepadPlusPlusInfo.ps1
#>

[CmdletBinding()]
param()

# Add P/Invoke for registry key timestamp
Add-Type @"
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public class RegKeyInfo {
    [DllImport("advapi32.dll", EntryPoint = "RegQueryInfoKey", SetLastError = true)]
    private static extern int RegQueryInfoKey(
        SafeRegistryHandle hKey,
        IntPtr lpClass,
        IntPtr lpcchClass,
        IntPtr lpReserved,
        IntPtr lpcSubKeys,
        IntPtr lpcbMaxSubKeyLen,
        IntPtr lpcbMaxClassLen,
        IntPtr lpcValues,
        IntPtr lpcbMaxValueNameLen,
        IntPtr lpcbMaxValueLen,
        IntPtr lpcbSecurityDescriptor,
        out long lpftLastWriteTime);

    public static DateTime? GetLastWriteTime(Microsoft.Win32.RegistryKey key) {
        long timestamp;
        var handle = key.Handle;
        int result = RegQueryInfoKey(handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
            IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
            IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out timestamp);
        if (result == 0) {
            return DateTime.FromFileTime(timestamp);
        }
        return null;
    }
}
"@ -ErrorAction SilentlyContinue

function Get-NotepadPlusPlusInfo {
    $result = [PSCustomObject]@{
        IsInstalled       = $false
        Version           = $null
        InstallPath       = $null
        LastUsed          = $null
        InstallMethod     = $null
        InstallDate       = $null
        IntuneAppName     = $null
    }

    # Registry paths to check (64-bit and 32-bit)
    $registryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    # Search registry for Notepad++
    $nppRegistry = $null
    foreach ($path in $registryPaths) {
        $nppRegistry = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -like "*Notepad++*" } |
            Select-Object -First 1
        if ($nppRegistry) { break }
    }

    # Common installation paths to check
    $commonPaths = @(
        "$env:ProgramFiles\Notepad++\notepad++.exe",
        "${env:ProgramFiles(x86)}\Notepad++\notepad++.exe",
        "$env:LOCALAPPDATA\Notepad++\notepad++.exe",
        "$env:ChocolateyInstall\lib\notepadplusplus\tools\notepad++.exe"
    )

    # Check Scoop installation
    $scoopPath = "$env:USERPROFILE\scoop\apps\notepadplusplus\current\notepad++.exe"
    $commonPaths += $scoopPath

    # Find the executable
    $exePath = $null
    
    if ($nppRegistry -and $nppRegistry.InstallLocation) {
        $possibleExe = Join-Path $nppRegistry.InstallLocation "notepad++.exe"
        if (Test-Path $possibleExe) {
            $exePath = $possibleExe
        }
    }

    if (-not $exePath) {
        foreach ($path in $commonPaths) {
            if (Test-Path $path) {
                $exePath = $path
                break
            }
        }
    }

    # Also check PATH
    if (-not $exePath) {
        $cmd = Get-Command notepad++ -ErrorAction SilentlyContinue
        if ($cmd) { $exePath = $cmd.Source }
    }

    if (-not $exePath -and -not $nppRegistry) {
        Write-Warning "Notepad++ does not appear to be installed."
        return $result
    }

    $result.IsInstalled = $true

    # Get version
    if ($nppRegistry -and $nppRegistry.DisplayVersion) {
        $result.Version = $nppRegistry.DisplayVersion
    }
    elseif ($exePath -and (Test-Path $exePath)) {
        $result.Version = (Get-Item $exePath).VersionInfo.ProductVersion
    }

    # Get install path
    if ($exePath) {
        $result.InstallPath = Split-Path $exePath -Parent
    }
    elseif ($nppRegistry -and $nppRegistry.InstallLocation) {
        $result.InstallPath = $nppRegistry.InstallLocation
    }

    # Get last used time from Prefetch (more reliable than LastAccessTime)
    $prefetchPath = "$env:SystemRoot\Prefetch"
    if (Test-Path $prefetchPath) {
        $prefetchFile = Get-ChildItem -Path $prefetchPath -Filter "NOTEPAD++*.pf" -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($prefetchFile) {
            $result.LastUsed = $prefetchFile.LastWriteTime
        }
    }

    # Get install date from registry (same source as appwiz.cpl)
    if ($nppRegistry -and $nppRegistry.InstallDate) {
        try {
            $result.InstallDate = [DateTime]::ParseExact($nppRegistry.InstallDate, "yyyyMMdd", $null)
        }
        catch {
            $result.InstallDate = $nppRegistry.InstallDate
        }
    }
    elseif ($nppRegistry) {
        # Fallback to registry key's LastWriteTime (what appwiz.cpl uses)
        try {
            $keyPath = $nppRegistry.PSPath -replace '^Microsoft\.PowerShell\.Core\\Registry::',''
            $hive, $subPath = $keyPath -split '\\', 2
            $regHive = switch ($hive) {
                'HKEY_LOCAL_MACHINE' { [Microsoft.Win32.Registry]::LocalMachine }
                'HKEY_CURRENT_USER'  { [Microsoft.Win32.Registry]::CurrentUser }
            }
            $key = $regHive.OpenSubKey($subPath)
            if ($key) {
                $result.InstallDate = [RegKeyInfo]::GetLastWriteTime($key)
                $key.Close()
            }
        }
        catch {
            # Unable to retrieve LastWriteTime
        }
    }

    # Determine installation method
    $result.InstallMethod = Get-InstallMethod -RegistryEntry $nppRegistry -ExePath $exePath
    
    # Add Intune app name if applicable
    if ($script:IntuneInfo) {
        $result.IntuneAppName = $script:IntuneInfo.AppName
    }

    return $result
}

function Get-IntuneAppInfo {
    param([string]$AppName = "Notepad++")
    
    # Check Intune Win32 app registry
    $intuneBasePath = "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps"
    
    if (-not (Test-Path $intuneBasePath)) {
        return $null
    }
    
    # Iterate through user GUIDs and app GUIDs
    $userKeys = Get-ChildItem -Path $intuneBasePath -ErrorAction SilentlyContinue
    foreach ($userKey in $userKeys) {
        $appKeys = Get-ChildItem -Path $userKey.PSPath -ErrorAction SilentlyContinue
        foreach ($appKey in $appKeys) {
            $appInfo = Get-ItemProperty -Path $appKey.PSPath -ErrorAction SilentlyContinue
            
            # Check if this app matches Notepad++
            if ($appInfo) {
                # Try to get the app name from various possible properties
                $intuneAppName = $appInfo.DisplayName
                if (-not $intuneAppName) {
                    # Check the Result property which may contain JSON with app info
                    if ($appInfo.Result) {
                        try {
                            $resultJson = $appInfo.Result | ConvertFrom-Json -ErrorAction SilentlyContinue
                            if ($resultJson.DisplayName) {
                                $intuneAppName = $resultJson.DisplayName
                            }
                        } catch {}
                    }
                }
                
                # Check if this relates to Notepad++
                if ($intuneAppName -like "*$AppName*") {
                    return @{
                        AppName = $intuneAppName
                        AppId = $appKey.PSChildName
                    }
                }
            }
        }
    }
    
    # Also check the GRS (Global Reporting Status) for app names
    $grsPath = "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\SideCarPolicies\StatusServiceReports"
    if (Test-Path $grsPath) {
        $reports = Get-ChildItem -Path $grsPath -Recurse -ErrorAction SilentlyContinue
        foreach ($report in $reports) {
            $reportData = Get-ItemProperty -Path $report.PSPath -ErrorAction SilentlyContinue
            if ($reportData.Data) {
                try {
                    $data = $reportData.Data | ConvertFrom-Json -ErrorAction SilentlyContinue
                    if ($data.AppName -like "*$AppName*" -or $data.Name -like "*$AppName*") {
                        return @{
                            AppName = if ($data.AppName) { $data.AppName } else { $data.Name }
                            AppId = $report.PSChildName
                        }
                    }
                } catch {}
            }
        }
    }
    
    return $null
}

function Get-InstallMethod {
    param(
        $RegistryEntry,
        [string]$ExePath
    )
    
    $script:IntuneInfo = $null

    # Check for Intune first
    $intuneApp = Get-IntuneAppInfo -AppName "Notepad++"
    if ($intuneApp) {
        $script:IntuneInfo = $intuneApp
        return "Intune"
    }

    # Check for Scoop (path-based, very reliable)
    if ($ExePath -like "*\scoop\*") {
        return "Scoop"
    }

    # Check for Chocolatey (has its own package tracking)
    if ($env:ChocolateyInstall -and (Get-Command choco -ErrorAction SilentlyContinue)) {
        $chocoList = choco list notepadplusplus --local-only 2>$null
        if ($chocoList -match "notepadplusplus") {
            return "Chocolatey"
        }
    }

    # Check Scoop list if command exists
    if (Get-Command scoop -ErrorAction SilentlyContinue) {
        $scoopApps = scoop list 2>$null
        if ($scoopApps -match "notepadplusplus") {
            return "Scoop"
        }
    }

    # Check winget - only if Source column shows "winget" (meaning winget actually installed it)
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        $wingetOutput = winget list --id "Notepad++.Notepad++" --exact 2>$null
        if ($LASTEXITCODE -eq 0 -and $wingetOutput) {
            # Parse output to check if Source column contains "winget"
            $lines = $wingetOutput -split "`n" | Where-Object { $_ -match "Notepad\+\+" }
            foreach ($line in $lines) {
                if ($line -match "\s+winget\s*$") {
                    return "Winget"
                }
            }
        }
    }

    # Check registry for MSI or EXE installer
    if ($RegistryEntry) {
        if ($RegistryEntry.PSChildName -match "^\{[A-F0-9-]+\}$") {
            return "MSI Installer"
        }
        
        if ($RegistryEntry.UninstallString) {
            if ($RegistryEntry.UninstallString -match "msiexec") {
                return "MSI Installer"
            }
            if ($RegistryEntry.UninstallString -match "uninstall\.exe") {
                return "EXE Installer"
            }
        }
    }

    # Check if it's a portable installation (no uninstaller, local folder)
    if ($ExePath) {
        $installDir = Split-Path $ExePath -Parent
        $hasUninstaller = Test-Path (Join-Path $installDir "uninstall.exe")
        
        if (-not $hasUninstaller -and -not $RegistryEntry) {
            return "Portable"
        }
    }

    return "Unknown"
}

# Run and display results
$info = Get-NotepadPlusPlusInfo

$minimumVersion = [version]"8.9.1"

if ($info.IsInstalled) {
    # Output for Intune remediation logs
    $output = @(
        "Notepad++ Detected"
        "Version: $($info.Version)"
        "Install Path: $($info.InstallPath)"
        "Last Used: $($info.LastUsed)"
        "Install Method: $($info.InstallMethod)"
    )
    if ($info.InstallDate) {
        $output += "Install Date: $($info.InstallDate)"
    }
    if ($info.IntuneAppName) {
        $output += "Intune App Name: $($info.IntuneAppName)"
    }
    
    Write-Output ($output -join "; ")
    
    # Check if version is below minimum
    try {
        $installedVersion = [version]$info.Version
        if ($installedVersion -lt $minimumVersion) {
            exit 1  # Non-compliant - outdated version
        }
    }
    catch {
        # Unable to parse version, treat as non-compliant
        exit 1
    }
    
    exit 0  # Compliant - installed and up to date
}
else {
    Write-Output "Notepad++ is not installed"
    exit 0  # Compliant - not installed
}