<#
.SYNOPSIS
    This PowerShell script ensures that users are prompted for a password on resume from sleep (on battery).
.NOTES
    Author          : Horacio Flores
    LinkedIn        : linkedin.com/in/horacio-flores-19599121b/
    GitHub          : github.com/horacioxf
    Date Created    : 2025-07-21
    Last Modified   : 2025-07-21
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000145

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-CC-000145.ps1 
#>

# Define registry path and value name
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\"
$valueName = "DCSettingIndex"

# Create the registry path if it doesn't exist
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the value to 1
Set-ItemProperty -Path $regPath -Name $valueName -Value 1 -Type DWord
