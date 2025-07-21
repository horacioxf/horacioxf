<#
.SYNOPSIS
    This PowerShell script ensures convenience PIN for Windows 10 is disabled.

.NOTES
    Author          : Horacio Flores
    LinkedIn        : linkedin.com/in/horacio-flores-19599121b/
    GitHub          : github.com/horacioxf
    Date Created    : 2025-07-21
    Last Modified   : 2025-07-21
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000370

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-CC-000370.ps1 
#>

# Define registry path and value name
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
$valueName = "AllowDomainPINLogon"

# Create the registry path if it doesn't exist
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the value to 0 (disabled)
Set-ItemProperty -Path $regPath -Name $valueName -Value 0 -Type DWord

Write-Output "Convenience PIN sign-in has been disabled."
