<#
.SYNOPSIS
    This PowerShell script ensures that Windows 10 must be configured to prevent Windows apps from being activated by voice while the system is locked.
.NOTES
    Author          : Horacio Flores
    LinkedIn        : linkedin.com/in/horacio-flores-19599121b/
    GitHub          : github.com/horacioxf
    Date Created    : 2025-07-21
    Last Modified   : 2025-07-21
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000365

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-CC-000365.ps1 
#>

# Define registry path and value names
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
$voiceValueName = "LetAppsActivateWithVoice"
$voiceAboveLockValueName = "LetAppsActivateWithVoiceAboveLock"

# Check if LetAppsActivateWithVoice exists and is set to 2
$voiceValue = Get-ItemProperty -Path $regPath -Name $voiceValueName -ErrorAction SilentlyContinue

if ($null -ne $voiceValue -and $voiceValue.$voiceValueName -eq 2) {
    Write-Output "Policy 'Let Windows apps activate with voice' is already set to Force Deny. No action required."
} else {
    # Set LetAppsActivateWithVoiceAboveLock to 2 (Force Deny)
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }

    Set-ItemProperty -Path $regPath -Name $voiceAboveLockValueName -Value 2 -Type DWord
    Write-Output "Policy 'Let Windows apps activate with voice while the system is locked' set to Force Deny."
}
