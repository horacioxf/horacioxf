<#
.SYNOPSIS
    This PowerShell script ensures that the maximum size of the Windows Application event log is at least 32768 KB (32 MB).

.NOTES
    Author          : Horacio Flores
    LinkedIn        : linkedin.com/in/horacio-flores-19599121b/
    GitHub          : github.com/horacioxf
    Date Created    : 2025-07-21
    Last Modified   : 2025-07-21
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AU-000500

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-AU-000500.ps1 
#>

# Define the registry key path
$regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'

# Create the key if it does not exist
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the MaxSize value to 0x8000 (32768 decimal)
Set-ItemProperty -Path $regPath -Name 'MaxSize' -Value 0x8000 -Type DWord

Write-Host "MaxSize set to 0x8000 (32768) under $regPath"
