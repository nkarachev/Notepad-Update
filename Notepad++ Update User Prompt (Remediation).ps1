<#
.SYNOPSIS
    Notepad++ Security Remediation Script
    
.DESCRIPTION
    Detects, uninstalls, and optionally updates Notepad++ to remediate security vulnerabilities.
    If app unused for 6 months: SILENT uninstall (no prompt).
    If app used within 6 months and running: prompts user with deferral options (up to 2 deferrals).
    
.NOTES
    Author: Systems Engineering Team
    Version: 1.1
    Requires: PowerShell 5.1+, Windows 64-bit, Administrator privileges
#>

#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$LogPath = "C:\Temp\NPP_Update.log",
    [int]$UnusedDaysThreshold = 180,
    [int]$MaxDeferrals = 2
)

# Fetch the latest release from GitHub API
$release = Invoke-RestMethod -Uri "https://api.github.com/repos/notepad-plus-plus/notepad-plus-plus/releases/latest" -Headers @{ "User-Agent" = "PowerShell" }
$latestVersionString = $release.tag_name -replace '^v', ''
$MinimumVersion = [version]$latestVersionString
$LatestInstallerUrl = $release.assets | Where-Object { $_.name -like "npp.*.Installer.x64.exe" } | Select-Object -ExpandProperty browser_download_url
if (-not $LatestInstallerUrl) {
    throw "Could not find x64 installer in the latest release assets."
}

# Load required assemblies for WPF dialog
try {
    Add-Type -AssemblyName PresentationCore, PresentationFramework, WindowsBase, System.Windows.Forms
    [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
    [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing") | Out-Null
}
catch {
    Write-Warning 'Failed to load Windows Presentation Framework assemblies.'
}

# Initialize logging
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info','Warning','Error','Success')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Ensure log directory exists
    $logDir = Split-Path -Path $LogPath -Parent
    if (-not (Test-Path -Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    }
    
    Add-Content -Path $LogPath -Value $logMessage
    Write-Host $logMessage
}

# Phase 1: Detection & Pre-Checks
function Test-NotepadPlusPlusRunning {
    try {
        $process = Get-Process -Name "notepad++" -ErrorAction SilentlyContinue
        if ($process) {
            Write-Log "Notepad++ process is running" -Level Warning
            return $true
        }
        Write-Log "No Notepad++ process detected" -Level Info
        return $false
    }
    catch {
        Write-Log "Error checking process: $_" -Level Error
        return $true  # Fail safe - assume running if we can't check
    }
}

function Get-NotepadPlusPlusVersion {
    try {
        # Check the direct known registry key first (most reliable)
        $directPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Notepad++"
        if (Test-Path -Path $directPath) {
            $regKey = Get-ItemProperty -Path $directPath -ErrorAction SilentlyContinue
            if ($regKey -and $regKey.DisplayVersion) {
                Write-Log "Found Notepad++ version: $($regKey.DisplayVersion) at $directPath" -Level Info
                return @{
                    Version = [version]$regKey.DisplayVersion
                    UninstallString = $regKey.UninstallString
                    InstallLocation = $regKey.InstallLocation
                    RegistryPath = $directPath
                }
            }
        }
        
        # Fallback: Search both 64-bit and 32-bit registry paths by DisplayName
        $regPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        )
        
        foreach ($basePath in $regPaths) {
            if (-not (Test-Path -Path $basePath)) {
                continue
            }
            
            $subKeys = Get-ChildItem -Path $basePath -ErrorAction SilentlyContinue
            foreach ($subKey in $subKeys) {
                $regKey = Get-ItemProperty -Path $subKey.PSPath -ErrorAction SilentlyContinue
                if ($regKey.DisplayName -like "*Notepad++*" -and $regKey.DisplayVersion) {
                    Write-Log "Found Notepad++ version: $($regKey.DisplayVersion) at $($subKey.PSPath)" -Level Info
                    return @{
                        Version = [version]$regKey.DisplayVersion
                        UninstallString = $regKey.UninstallString
                        InstallLocation = $regKey.InstallLocation
                        RegistryPath = $subKey.PSPath
                    }
                }
            }
        }
        
        # Final fallback: Check the installation folder directly (some installs have no registry keys)
        $exePath = "C:\Program Files\Notepad++\notepad++.exe"
        if (Test-Path -Path $exePath) {
            $fileVersion = (Get-Item $exePath).VersionInfo.FileVersion
            if ($fileVersion) {
                Write-Log "Found Notepad++ via file system: version $fileVersion at $exePath (no registry key)" -Level Warning
                return @{
                    Version = [version]$fileVersion
                    UninstallString = '"C:\Program Files\Notepad++\uninstall.exe"'
                    InstallLocation = 'C:\Program Files\Notepad++'
                    RegistryPath = $null
                }
            }
        }
        
        Write-Log "Notepad++ not found in registry or file system" -Level Info
        return $null
    }
    catch {
        Write-Log "Error retrieving version from registry: $_" -Level Error
        return $null
    }
}

function Test-NotepadPlusPlusUsage {
    try {
        # Check Prefetch folder for evidence of application execution
        $prefetchPath = "C:\Windows\Prefetch\NOTEPAD++.EXE-*.pf"
        $prefetchFiles = Get-ChildItem -Path $prefetchPath -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        
        if (-not $prefetchFiles) {
            Write-Log "No Prefetch file found - application has never been run" -Level Info
            return $false
        }
        
        $daysSinceUsed = (New-TimeSpan -Start $prefetchFiles.LastWriteTime -End (Get-Date)).Days
        Write-Log "Prefetch file last modified: $($prefetchFiles.LastWriteTime) ($daysSinceUsed days ago)" -Level Info
        
        if ($daysSinceUsed -ge $UnusedDaysThreshold) {
            Write-Log "Application has NOT been used in the last $UnusedDaysThreshold days (last use: $daysSinceUsed days ago)" -Level Info
            return $false
        }
        else {
            Write-Log "Application has been used within the last $UnusedDaysThreshold days (last use: $daysSinceUsed days ago)" -Level Info
            return $true
        }
    }
    catch {
        Write-Log "Error checking usage: $_" -Level Error
        return $true  # Fail safe - assume used if we can't check
    }
}

# Phase 2: User Interaction - WPF Dialog Helper
Function New-WPFDialog() {
    Param(
        [Parameter(Mandatory = $True, HelpMessage = 'XaML Data defining a GUI', Position = 1)]
        [string]$XamlData
    )

    [xml]$xmlWPF = $XamlData
    $XaMLReader = New-Object System.Collections.Hashtable
    $XaMLReader.Add('UI', ([Windows.Markup.XamlReader]::Load((new-object -TypeName System.Xml.XmlNodeReader -ArgumentList $xmlWPF))))

    $Elements = $xmlWPF.SelectNodes('//*[@Name]')
    ForEach ( $Element in $Elements ) {
        $VarName = $Element.Name
        $VarValue = $XaMLReader.UI.FindName($Element.Name)
        $XaMLReader.Add($VarName, $VarValue)
    }

    return $XaMLReader
}

Function Show-UpdateNotificationDialog() {
    Param(
        [Parameter(Mandatory = $True)]
        [string]$DialogTitle,
        [Parameter(Mandatory = $True)]
        [string]$H1,
        [Parameter(Mandatory = $True)]
        [string]$DialogLine1,
        [Parameter(Mandatory = $False)]
        [string]$DialogLine2,
        [Parameter(Mandatory = $False)]
        [string]$DialogLine3,
        [Parameter(Mandatory = $False)]
        [string]$DialogRemindMeText,
        [Parameter(Mandatory = $False)]
        [string]$CancelText,
        [Parameter(Mandatory = $True)]
        [string]$ConfirmText,
        [Parameter(Mandatory = $false)]
        [int]$Timeout,
        [Parameter(Mandatory = $false)]
        [boolean]$DisplayWarningText,
        [Parameter(Mandatory = $false)]
        [switch]$Beep
    )

    [string]$Base64Image = "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"

    $bitmap = New-Object System.Windows.Media.Imaging.BitmapImage 
    $bitmap.BeginInit() 
    $bitmap.StreamSource = [System.IO.MemoryStream][System.Convert]::FromBase64String($Base64Image) 
    $bitmap.EndInit()
    $bitmap.Freeze()

    $Dialog = New-WPFDialog -XamlData @'
    <Window
    x:Class="System.Windows.Window"
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
    xmlns:local="clr-namespace:errordialogXaML"
    Name="MainWindow"
    Title="__DIALOGTITLE__"
    ResizeMode="NoResize"
    SizeToContent="WidthAndHeight"
    Width="640"
    MinWidth="640"
    MaxWidth="640"
    Height="372"
    MinHeight="372"
    WindowStyle="None"
    AllowsTransparency="True"
    Background="Transparent"
    Padding="20"
    Margin="0"
    ShowInTaskbar="False">
    <Window.Resources>
        <SolidColorBrush x:Key="Button.Static.Background" Color="#FFFBFBFB"/>
        <SolidColorBrush x:Key="Button.Static.Border" Color="#FFCCCCCC"/>
        <SolidColorBrush x:Key="Button.MouseOver.Background" Color="#FFF3F3F3"/>
        <SolidColorBrush x:Key="Button.MouseOver.Border" Color="#FFCCCCCC"/>
        <SolidColorBrush x:Key="Button.Pressed.Background" Color="#FFF3F3F3"/>
        <SolidColorBrush x:Key="Button.Pressed.Border" Color="#FFDFDFDF"/>
        <SolidColorBrush x:Key="Button.Disabled.Background" Color="#FFF4F4F4"/>
        <SolidColorBrush x:Key="Button.Disabled.Border" Color="#FFADB2B5"/>
        <SolidColorBrush x:Key="Button.Default.Foreground" Color="White"/>
        <SolidColorBrush x:Key="Button.Default.Background" Color="#FF000000"/>
        <SolidColorBrush x:Key="Button.Default.Border" Color="#FF000000"/>
        <SolidColorBrush x:Key="Button.Default.MouseOver.Background" Color="#FF000000"/>
        <SolidColorBrush x:Key="Button.Default.Pressed.Background" Color="#FF000000"/>
        <SolidColorBrush x:Key="Button.Disabled.Foreground" Color="#FF838383"/>
        <Style x:Key="FlatButton" TargetType="{x:Type Button}">
            <Setter Property="Background" Value="{StaticResource Button.Static.Background}"/>
            <Setter Property="BorderBrush" Value="{StaticResource Button.Static.Border}"/>
            <Setter Property="Foreground" Value="{DynamicResource {x:Static SystemColors.ControlTextBrushKey}}"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Border.CornerRadius" Value="4"/>
            <Setter Property="HorizontalContentAlignment" Value="Center"/>
            <Setter Property="VerticalContentAlignment" Value="Center"/>
            <Setter Property="Padding" Value="12,4,12,4"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="{x:Type Button}">
                        <Border x:Name="border" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}" Background="{TemplateBinding Background}" SnapsToDevicePixels="true" CornerRadius="{TemplateBinding Border.CornerRadius}">
                            <ContentPresenter x:Name="contentPresenter" Focusable="False" HorizontalAlignment="{TemplateBinding HorizontalContentAlignment}" Margin="{TemplateBinding Padding}" RecognizesAccessKey="True" SnapsToDevicePixels="{TemplateBinding SnapsToDevicePixels}" VerticalAlignment="{TemplateBinding VerticalContentAlignment}"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsDefault" Value="true">
                                <Setter Property="BorderBrush" TargetName="border" Value="{StaticResource Button.Default.Border}"/>
                                <Setter Property="Background" TargetName="border" Value="{StaticResource Button.Default.Background}"/>
                                <Setter Property="TextElement.Foreground" TargetName="contentPresenter" Value="{StaticResource Button.Default.Foreground}"/>
                            </Trigger>
                            <Trigger Property="IsMouseOver" Value="true">
                                <Setter Property="BorderBrush" TargetName="border" Value="{StaticResource Button.MouseOver.Border}"/>
                                <Setter Property="Background" TargetName="border" Value="{StaticResource Button.MouseOver.Background}"/>
                            </Trigger>
                            <MultiTrigger>
                                <MultiTrigger.Conditions>
                                    <Condition Property="IsDefault" Value="true" />
                                    <Condition Property="IsMouseOver" Value="true" />
                                </MultiTrigger.Conditions>
                                <MultiTrigger.Setters>      
                                    <Setter Property="Background" TargetName="border" Value="{StaticResource Button.Default.MouseOver.Background}" />
                                    <Setter Property="Opacity" TargetName="border" Value="0.85"/>
                                </MultiTrigger.Setters>      
                            </MultiTrigger>
                            <Trigger Property="IsPressed" Value="true">
                                <Setter Property="BorderBrush" TargetName="border" Value="{StaticResource Button.Pressed.Border}"/>
                                <Setter Property="Background" TargetName="border" Value="{StaticResource Button.Pressed.Background}"/>
                                <Setter Property="TextElement.Foreground" TargetName="contentPresenter" Value="#FF4B4B4B"/>
                            </Trigger>
                            <MultiTrigger>
                                <MultiTrigger.Conditions>
                                    <Condition Property="IsDefault" Value="true" />
                                    <Condition Property="IsPressed" Value="true" />
                                </MultiTrigger.Conditions>
                                <MultiTrigger.Setters>      
                                    <Setter Property="Background" TargetName="border" Value="{StaticResource Button.Default.Pressed.Background}"/>
                                    <Setter Property="BorderBrush" TargetName="border" Value="{StaticResource Button.Pressed.Border}"/>
                                    <Setter Property="TextElement.Foreground" TargetName="contentPresenter" Value="#FFFFFFFF"/>
                                    <Setter Property="Opacity" TargetName="border" Value="0.85"/>
                                </MultiTrigger.Setters>      
                            </MultiTrigger>
                            <Trigger Property="IsEnabled" Value="false">
                                <Setter Property="Background" TargetName="border" Value="{StaticResource Button.Disabled.Background}"/>
                                <Setter Property="BorderBrush" TargetName="border" Value="{StaticResource Button.Disabled.Border}"/>
                                <Setter Property="TextElement.Foreground" TargetName="contentPresenter" Value="{StaticResource Button.Disabled.Foreground}"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
    </Window.Resources>
    <Border BorderThickness="1" BorderBrush="#FFADBDC8" CornerRadius="10" Background="White">
    <Grid>
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto" />
            <RowDefinition Height="*" />
        </Grid.RowDefinitions>    
            <Grid Margin="40,24,24,0" >
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="8*" />
                    <ColumnDefinition Width="2*" />
                </Grid.ColumnDefinitions>
                <TextBlock Grid.Column="0" Name="DialogTitle" Text="__DIALOGTITLE__" TextWrapping="WrapWithOverflow" HorizontalAlignment="Left" VerticalAlignment="Top" FontFamily="Segoe UI" FontSize="14" Opacity="0.6063" FontWeight="DemiBold" Width="280" />
                <Image Grid.Column="1" Name="GoToResolveIcon" Height="65" Width="130"></Image>
            </Grid>
            <DockPanel Margin="40,0,40,0" Grid.Row="1">
                <TextBlock DockPanel.Dock="Top" Name="H1" Text="__H1__" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="0" FontSize="28" FontFamily="Segoe UI" FontWeight="DemiBold" />
                <TextBlock DockPanel.Dock="Top" Name="DialogLine1" Text="__DIALOGTEXT__" TextWrapping="Wrap" TextAlignment="Justify" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="0,16,0,0" FontFamily="Segoe UI" FontSize="14" />
                <TextBlock DockPanel.Dock="Top" Name="DialogLine2" Text="__DIALOGTEXT2__" TextWrapping="Wrap" TextAlignment="Justify" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="0" FontFamily="Segoe UI" FontSize="14" />
                <TextBlock DockPanel.Dock="Top" Name="DialogLine3" Text="__DIALOGTEXT3__" TextWrapping="Wrap" TextAlignment="Justify" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="0" FontFamily="Segoe UI" FontSize="14" />
                <Grid DockPanel.Dock="Top">
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="6*" />
                        <ColumnDefinition Width="4*" />
                    </Grid.ColumnDefinitions>                
                    <DockPanel>
                        <TextBlock DockPanel.Dock="Top" Name="DialogRemindMeText" Text="__DIALOGTEXT4__" TextWrapping="Wrap" TextAlignment="Justify" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="0, 16, 0, 0" FontSize="14" />
                        <ComboBox Name="DalayOptions" DockPanel.Dock="Top" FontSize="14" SelectedIndex="0" Margin="0,10,0,0">
                            <ComboBoxItem Tag="15">15 minutes</ComboBoxItem>
                            <ComboBoxItem Tag="60">1 hour</ComboBoxItem>
                            <ComboBoxItem Tag="180">3 hours</ComboBoxItem>
                        </ComboBox>
                    </DockPanel>
                </Grid>
                <DockPanel DockPanel.Dock="Top" Name="WarningSection">
                    <TextBlock DockPanel.Dock="Top" Text="You must update this application based on a configured policy." TextWrapping="Wrap" TextAlignment="Justify" HorizontalAlignment="Left" VerticalAlignment="Top" FontSize="12" Foreground="#FFC42B1C" />
                    <TextBlock DockPanel.Dock="Top" Text="The application will be updated after the selected time." TextWrapping="Wrap" TextAlignment="Justify" HorizontalAlignment="Left" VerticalAlignment="Top" FontSize="12" Foreground="#FFC42B1C" />
                </DockPanel>
                <Grid DockPanel.Dock="Bottom" VerticalAlignment="Bottom" Margin="0,24,0,24">
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="2.7*" />
                        <ColumnDefinition Width="4.6*" />
                        <ColumnDefinition Width="2.7*" />
                    </Grid.ColumnDefinitions>
                    <Button Name="CancelButton" Grid.Column="0" Content="__CANCELTEXT__" Visibility="Hidden" Padding="16,4,16,4" Style="{DynamicResource FlatButton}" FontSize="14" FontFamily="Segoe UI" FontWeight="DemiBold" />
                    <Button Name="ConfirmButton" Grid.Column="2" Content="__CONFIRMTEXT__" Padding="16,4,16,4" IsDefault="True" Style="{DynamicResource FlatButton}" FontSize="14" FontFamily="Segoe UI" FontWeight="DemiBold" />
                </Grid>
            </DockPanel>
        </Grid>
    </Border>
</Window>
'@
    $Dialog.MainWindow.TopMost = $True
    $Dialog.DialogTitle.Text = $DialogTitle
    $Dialog.H1.Text = $H1
    $Dialog.DialogLine1.Text = $DialogLine1
    $Dialog.DialogLine2.Text = $DialogLine2
    $Dialog.DialogLine3.Text = $DialogLine3
    $Dialog.DialogRemindMeText.Text = $DialogRemindMeText
    $Dialog.CancelButton.Content = $CancelText
    $Dialog.ConfirmButton.Content = $ConfirmText
    $Dialog.GoToResolveIcon.Source = $bitmap
    $Dialog.WarningSection.Visibility = [System.Windows.Visibility]::Collapsed 
    if ($DisplayWarningText -eq $True) {
        $Dialog.WarningSection.Visibility = [System.Windows.Visibility]::Visible
    }

    $DesktopWorkingArea = [System.Windows.SystemParameters]::WorkArea
    $Dialog.MainWindow.Left = $DesktopWorkingArea.Width - $Dialog.MainWindow.Width
    $Dialog.MainWindow.Top = $DesktopWorkingArea.Height - $Dialog.MainWindow.Height - 180

    $Dialog.MainWindow.Add_Closed({
        if ($DispatcherTimer) {
            $DispatcherTimer.Stop()
        }
    })

    $Dialog.MainWindow.Add_MouseDown({
        if ($_.ChangedButton -eq 'Left') {
            $this.DragMove()
        }
    })

    if ($CancelText) {
        $Dialog.CancelButton.Visibility = 'Visible'
    }

    $Dialog.Add('Result', [System.Windows.Forms.DialogResult]::Cancel)

    $Dialog.ConfirmButton.Add_Click({
        $Dialog.Result = [System.Windows.Forms.DialogResult]::OK
        $Dialog.UI.Close()
    })

    $Dialog.CancelButton.Add_Click({
        $Dialog.Result = [System.Windows.Forms.DialogResult]::Cancel
        $Dialog.UI.Close()
    })

    $Dialog.UI.Add_ContentRendered({
        if ($Beep) {
            [System.Media.SystemSounds]::Exclamation.play()
        }
    })

    if ($Timeout) {
        $Stopwatch = New-object System.Diagnostics.Stopwatch
        $TimerCode = {
            If ($Stopwatch.Elapsed.TotalSeconds -ge $Timeout) {
                $Stopwatch.Stop()
                $Dialog.Result = [System.Windows.Forms.DialogResult]::Cancel
                $Dialog.UI.Close()
            }
        }
    
        $DispatcherTimer = New-Object -TypeName System.Windows.Threading.DispatcherTimer
        $DispatcherTimer.Interval = [TimeSpan]::FromSeconds(1)
        $DispatcherTimer.Add_Tick($TimerCode)
        $Stopwatch.Start()
        $DispatcherTimer.Start()
    }      

    $Dialog.UI.Dispatcher.InvokeAsync{ $Dialog.UI.ShowDialog() }.Wait() | Out-Null

    return @{
        DialogResult = $Dialog.Result
        SnoozePeriod = $Dialog.DalayOptions.SelectedValue.Tag
    }
}

# Show update prompt with deferral options
function Show-UpdatePrompt {
    param(
        [int]$RemainingDeferrals
    )
    
    $firstNotification = $true
    $currentDeferrals = $RemainingDeferrals
    
    do {
        $DialogRemindMeText = switch ($currentDeferrals) { 1 { 'Update in:' } default { 'Remind me again in:' } }
        $CancelText = switch ($currentDeferrals) { 1 { 'No, update later' } default { 'No, remind me later' } }
        
        if ($firstNotification) {
            $NotificationDisplayTimeout = 4 * 60 * 60 - 15 * 60  # 4 hours minus 15 mins
            $firstNotification = $false
        } else {
            $NotificationDisplayTimeout = 15 * 60  # 15 mins
        }

        $Notification = Show-UpdateNotificationDialog `
            -DialogTitle 'Managed action by Technical Services, Nikolay.Karachev@prometric.com' `
            -H1 'Notepad++ Update Required' `
            -DialogLine1 "Your version of Notepad++ is outdated and must be updated." `
            -DialogLine2 'A security update is available and required by your Security Department.' `
            -DialogLine3 'Please close Notepad++ and click Yes to proceed.' `
            -DialogRemindMeText $DialogRemindMeText `
            -ConfirmText 'Yes, update now' `
            -CancelText $CancelText `
            -Timeout $NotificationDisplayTimeout `
            -DisplayWarningText ($currentDeferrals -eq 1) `
            -Beep

        if ($Notification.DialogResult -eq 'OK') {
            Write-Log "User selected: Yes, update now" -Level Info
            if (Test-NotepadPlusPlusRunning) {
                Write-Log "Forcing Notepad++ to close before update" -Level Info
                Stop-Process -Name "notepad++" -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
            }
            return "Upgrade"
        } else {
            Write-Log "User deferred update for $($Notification.SnoozePeriod) minutes. Deferrals remaining: $($currentDeferrals - 1)" -Level Info
            Start-Sleep -Seconds ([int]$Notification.SnoozePeriod * 60)
        }

        $currentDeferrals = $currentDeferrals - 1
    } until ($currentDeferrals -le 0)
    
    Write-Log "All deferrals exhausted. Proceeding with update." -Level Info
    if (Test-NotepadPlusPlusRunning) {
        Write-Log "Forcing Notepad++ to close before update" -Level Info
        Stop-Process -Name "notepad++" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }
    return "Upgrade"
}

# Phase 3: Execution Logic
function Uninstall-NotepadPlusPlus {
    param(
        [string]$UninstallString,
        [string]$InstallLocation
    )
    
    try {
        Write-Log "Starting Notepad++ uninstallation" -Level Info
        
        if ([string]::IsNullOrEmpty($UninstallString)) {
            Write-Log "No uninstall string found in registry" -Level Warning
            return $false
        }
        
        # Detect if this is an MSI or EXE uninstaller
        if ($UninstallString -match 'MsiExec') {
            # MSI uninstaller
            Write-Log "Detected MSI installer" -Level Info
            
            # Extract the GUID and fix /I to /X for uninstall
            if ($UninstallString -match '\{[A-F0-9-]+\}') {
                $productCode = $matches[0]
                $uninstallCmd = "MsiExec.exe"
                $uninstallArgs = "/X$productCode /qn /norestart"
            }
            else {
                # Fallback: just replace /I with /X and add silent flags
                $uninstallCmd = "MsiExec.exe"
                $uninstallArgs = ($UninstallString -replace 'MsiExec\.exe\s*', '' -replace '/I', '/X') + " /qn /norestart"
            }
        }
        else {
            # EXE uninstaller (NSIS or other)
            Write-Log "Detected EXE installer" -Level Info
            
            if ($UninstallString -match '^"([^"]+)"(.*)$') {
                $uninstallCmd = $matches[1]
                $uninstallArgs = $matches[2].Trim()
            }
            else {
                $uninstallCmd = $UninstallString
                $uninstallArgs = ""
            }
            
            # Add /S for silent uninstall if not present
            if ($uninstallArgs -notmatch '/S') {
                $uninstallArgs = "/S $uninstallArgs".Trim()
            }
        }
        
        Write-Log "Executing: $uninstallCmd $uninstallArgs" -Level Info
        $processInfo = Start-Process -FilePath $uninstallCmd -ArgumentList $uninstallArgs -Wait -PassThru -WindowStyle Hidden
        
        if ($processInfo.ExitCode -eq 0) {
            Write-Log "Uninstaller completed successfully (Exit Code: 0)" -Level Success
        }
        else {
            Write-Log "Uninstaller completed with exit code: $($processInfo.ExitCode)" -Level Warning
        }
        
        return $true
    }
    catch {
        Write-Log "Error during uninstallation: $_" -Level Error
        return $false
    }
}

function Install-NotepadPlusPlus {
    param(
        [string]$InstallerUrl
    )
    
    try {
        Write-Log "Starting Notepad++ installation from: $InstallerUrl" -Level Info
        
        $installerPath = "$env:TEMP\npp_installer.exe"
        Invoke-WebRequest -Uri $InstallerUrl -OutFile $installerPath
        
        Write-Log "Running silent install" -Level Info
        Start-Process -FilePath $installerPath -ArgumentList '/S', '/D=C:\Program Files\Notepad++' -Wait -NoNewWindow
        Remove-Item $installerPath -Force
        
        # Verify installation via registry
        $installed = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Notepad++" -ErrorAction SilentlyContinue
        if ($installed -and $installed.DisplayVersion) {
            Write-Log "Installed: $($installed.DisplayName) v$($installed.DisplayVersion)" -Level Success
            return $true
        }
        
        # Fallback: verify via file system if no registry key
        $exePath = "C:\Program Files\Notepad++\notepad++.exe"
        if (Test-Path -Path $exePath) {
            $fileVersion = (Get-Item $exePath).VersionInfo.FileVersion
            Write-Log "Installation verified via file system: version $fileVersion" -Level Success
            return $true
        }
        
        Write-Log "Installation could not be verified" -Level Warning
        return $false
    }
    catch {
        Write-Log "Error during installation: $_" -Level Error
        if (Test-Path $installerPath) { Remove-Item $installerPath -Force }
        return $false
    }
}

# Main Execution
function Main {
    Write-Log "========== Notepad++ Security Remediation Script Started ==========" -Level Info
    Write-Log "Minimum required version: $MinimumVersion" -Level Info
    Write-Log "Unused threshold: $UnusedDaysThreshold days" -Level Info
    
    try {
        # Phase 1: Detection & Pre-Checks
        
        # Step 1: Check version
        $versionInfo = Get-NotepadPlusPlusVersion
        
        if (-not $versionInfo) {
            Write-Log "Notepad++ not installed on this system" -Level Info
            exit 0
        }
        
        if ($versionInfo.Version -ge $MinimumVersion) {
            Write-Log "Version current (Installed: $($versionInfo.Version), Required: $MinimumVersion)" -Level Success
            exit 0
        }
        
        Write-Log "Vulnerable version detected: $($versionInfo.Version) (Required: $MinimumVersion or higher)" -Level Warning
        
        # Step 2: Check usage - if unused for 6 months, perform silent uninstall
        $isUsed = Test-NotepadPlusPlusUsage
        
        if (-not $isUsed) {
            Write-Log "Application unused for $UnusedDaysThreshold+ days. Performing silent uninstall." -Level Info
            $uninstallResult = Uninstall-NotepadPlusPlus -UninstallString $versionInfo.UninstallString -InstallLocation $versionInfo.InstallLocation
            
            if ($uninstallResult) {
                Write-Log "Silent uninstall completed successfully" -Level Success
            }
            else {
                Write-Log "Silent uninstall encountered errors" -Level Error
            }
            exit 0
        }
        
        # Phase 2: Application is in use - check if running and prompt with deferrals
        if (Test-NotepadPlusPlusRunning) {
            Write-Log "Notepad++ is currently running. Prompting user with $MaxDeferrals deferral(s) allowed." -Level Info
            $userChoice = Show-UpdatePrompt -RemainingDeferrals $MaxDeferrals
        }
        else {
            Write-Log "Notepad++ is not currently running. Proceeding with upgrade." -Level Info
        }
        
        # Step 4: App is outdated and recently used — silent upgrade
        Write-Log "Application is outdated and recently used. Performing silent upgrade." -Level Info
        
        # Gather uninstall key/exe state
        $hasRegistryUninstallEntry = $false
        if ($versionInfo.RegistryPath) {
            $hasRegistryUninstallEntry = $true
        }
        
        $uninstallExePath = $null
        if ($versionInfo.UninstallString) {
            if ($versionInfo.UninstallString -match '^"([^"]+)"') {
                $uninstallExePath = $matches[1]
            }
            else {
                $uninstallExePath = ($versionInfo.UninstallString -split '\s+')[0]
            }
        }
        
        $hasUninstallExe = $false
        if ($uninstallExePath -and (Test-Path -Path $uninstallExePath)) {
            $hasUninstallExe = $true
        }
        
        if ($hasRegistryUninstallEntry -and $hasUninstallExe) {
            $uninstallResult = Uninstall-NotepadPlusPlus -UninstallString $versionInfo.UninstallString -InstallLocation $versionInfo.InstallLocation
            if (-not $uninstallResult) {
                Write-Log "Uninstall failed. Aborting upgrade." -Level Error
                exit 1
            }
        }
        elseif (-not $hasRegistryUninstallEntry -and -not $hasUninstallExe) {
            Write-Log "No uninstall registry key and no uninstall.exe found. Verifying notepad++.exe before install-over-top." -Level Warning
            
            $installedExePath = "C:\Program Files\Notepad++\notepad++.exe"
            if (-not (Test-Path -Path $installedExePath)) {
                Write-Log "notepad++.exe not found at $installedExePath. Cannot continue upgrade." -Level Error
                exit 1
            }
            
            $installedExeVersionRaw = (Get-Item -Path $installedExePath).VersionInfo.FileVersion
            Write-Log "Found notepad++.exe at $installedExePath (Version: $installedExeVersionRaw)" -Level Info
            
            if ($versionInfo.Version -ge $MinimumVersion) {
                Write-Log "notepad++.exe version is already compliant. No upgrade needed." -Level Success
                exit 0
            }
            
            Write-Log "notepad++.exe is below minimum version. Installing latest version over existing installation." -Level Warning
        }
        else {
            Write-Log "Uninstall data is incomplete (Registry key: $hasRegistryUninstallEntry, uninstall.exe: $hasUninstallExe). Installing latest version over existing installation." -Level Warning
        }
        
        $installResult = Install-NotepadPlusPlus -InstallerUrl $LatestInstallerUrl
        if ($installResult) {
            Write-Log "Upgrade completed successfully" -Level Success
            exit 0
        }
        else {
            Write-Log "Upgrade failed" -Level Error
            exit 1
        }
         
    }
    catch {
        Write-Log "Critical error in main execution: $_" -Level Error
        Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level Error
        exit 1
    }
    finally {
        Write-Log "========== Notepad++ Security Remediation Script Finished ==========" -Level Info
    }
}

# Execute main function
Main
