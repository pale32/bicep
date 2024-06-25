<#
.SYNOPSIS
    Installs and configures post-deployment applications and settings for Azure VMs.

.NOTES
    Owner: 
    Date: June 2024
    Version: 1.0
#>

Set-ExecutionPolicy RemoteSigned -Scope Process -Force
function Disable-IEEnhancedSecurityConfiguration {
    $registryPath = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components"

    Get-ChildItem -Path $registryPath | ForEach-Object {
        $itemProperty = Get-ItemProperty -Path $_.PSPath -Name ComponentID -ErrorAction SilentlyContinue
        if ($Null -ne $itemProperty -and $itemProperty.ComponentID -match "IEHardenUser|IEHardenAdmin") {
            Set-ItemProperty -Path $_.PSPath -Name IsInstalled -Value 0 -ErrorAction SilentlyContinue
        }
    }
}


function Set-Hardening {
    $registrySettings = @(
        @{
            # Turn On security signature on shared services communications
            Path  = "HKLM:\System\CurrentControlSet\Services\LanManWorkstation\Parameters"
            Name  = "RequireSecuritySignature"
            Type  = "DWORD"
            Value = 1
        },
        @{
            # Turn On security signature on shared services communications
            Path  = "HKLM:\System\CurrentControlSet\Services\LanManWorkstation\Parameters"
            Name  = "EnableSecuritySignature"
            Type  = "DWORD"
            Value = 1
        },
        @{
            # Set RestrictAnonymous for Local-Security-Authority (LSA)
            Path  = "HKLM:\System\CurrentControlSet\Control\Lsa"
            Name  = "RestrictAnonymous"
            Type  = "DWORD"
            Value = 1
        },
        @{
            # Set RestrictAnonymousSam for Local-Security-Authority (LSA)
            Path  = "HKLM:\System\CurrentControlSet\Control\Lsa"
            Name  = "RestrictAnonymousSam"
            Type  = "DWORD"
            Value = 1
        },
        @{
            # Disable Autorun commands
            Path  = "Registry::HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
            Name  = "NoDriveTypeAutoRun"
            Type  = "DWORD"
            Value = 255
        },
        @{
            # Disable Autorun commands
            Path  = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
            Name  = "NoDriveTypeAutoRun"
            Type  = "DWORD"
            Value = 255
        },
        @{
            # Disable Cached Logons
            Path  = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
            Name  = "CachedLogonsCount"
            Type  = "String"
            Value = "0"
        }
    )

    function Set-RegistryProperty {
        param (
            [string]$Path,
            [string]$Name,
            [string]$Type,
            $Value
        )

        if (Test-Path $Path) {
            $currentValue = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
            if (-not $currentValue) {
                New-ItemProperty -Path $Path -Name $Name -PropertyType $Type -Value $Value -Force -ErrorAction SilentlyContinue
            }
            else {
                Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -ErrorAction SilentlyContinue
            }
        }
        else {
            New-Item -Path (Split-Path $Path) -Name (Split-Path -Leaf $Path) -Force -ErrorAction SilentlyContinue
            New-ItemProperty -Path $Path -Name $Name -PropertyType $Type -Value $Value -Force -ErrorAction SilentlyContinue
        }
    }

    foreach ($setting in $registrySettings) {
        Set-RegistryProperty -Path $setting.Path -Name $setting.Name -Type $setting.Type -Value $setting.Value
    }
}

function Disable-GuestAccount {
    if ((Get-WmiObject Win32_UserAccount -Filter "LocalAccount=True AND Name='Guest'" | Where-Object { $_.Disabled -eq $false })) {
        Disable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    }
}

function Rename-AdminUsername {
    $currentUsername = ($((Get-LocalGroupMember -Group "Administrators" | Where-Object { $_.PrincipalSource -eq "Local" -and $_.ObjectClass -eq "User" }).Name) -split '\\')[1]
    $computerName = $env:COMPUTERNAME -replace '-', ''
    if ($currentUsername -notlike "#Admin_$computerName") {
        $newUsername = "#Admin_$computerName"
        $user = Get-LocalUser -Name $currentUsername
        $user | Rename-LocalUser -NewName $newUsername
    }
}

function Set-RegionalSettings {
    Set-WinUILanguageOverride -Language en-AU
    Set-WinUserLanguageList -LanguageList (New-WinUserLanguageList -Language en-AU) -Force
    Set-TimeZone -Name 'AUS Eastern Standard Time'
    Set-WinSystemLocale -SystemLocale en-AU
    Set-WinHomeLocation -GeoId 12
}

function Set-AURegion {
    Set-ItemProperty -Path 'HKCU:\Control Panel\International' -Name 'Locale' -Value '00000C09'
    Set-ItemProperty -Path 'HKCU:\Control Panel\International' -Name 'LocaleName' -Value 'en-AU'
    Set-ItemProperty -Path 'HKCU:\Control Panel\International' -Name 'sLanguage' -Value 'ENA'
    Set-ItemProperty -Path 'HKCU:\Control Panel\International\Geo' -Name 'Name' -Value 'AU'
    Set-ItemProperty -Path 'HKCU:\Control Panel\International\Geo' -Name 'Nation' -Value '12'
    Set-ItemProperty -Path 'HKCU:\Control Panel\International\User Profile' -Name 'Languages' -Value 'en-AU'
    New-ItemProperty -Path 'HKCU:\Control Panel\International\User Profile\en-AU' -Name '00000C09' -PropertyType 'DWord' -Value 1 -Force
    Remove-Item -Path 'HKCU:\Control Panel\International\User Profile\en-US' -ErrorAction SilentlyContinue
}


function Install-Pwsh7 {
    Invoke-Expression "& { $(Invoke-RestMethod 'https://aka.ms/install-powershell.ps1') } -useMSI -Quiet -EnablePSRemoting"
    if (Test-Path -Path install-powershell.ps1) {
        Remove-Item -Path install-powershell.ps1
    }
}

function Install-Chrome {
    $chromeUrl = "https://dl.google.com/tag/s/dl/chrome/install/googlechromestandaloneenterprise64.msi"
    $chromePath = "$env:TEMP\googlechromestandaloneenterprise64.msi"
    Invoke-WebRequest -Uri $chromeUrl -OutFile $chromePath
    Start-Process msiexec.exe -ArgumentList "/i `"$chromePath`" /quiet /norestart" -Wait
    if (Test-Path -Path $chromePath) {
        Remove-Item -Path $chromePath
    }
}

Disable-IEEnhancedSecurityConfiguration # IEESC Off
Set-Hardening # Qualys compliance ## Configure Registry Settings
Disable-GuestAccount # Disable the Guest Account
#Rename-AdminUsername # Rename the Local Admin Account
#Set-RegionalSettings # Set Regional Settings
#Set-AURegion # Set Regional Settings
#Install-Pwsh7 # Download and install Powershell 7 (pwsh)
#Install-Chrome # Download and install Google Chrome
