<#
.SYNOPSIS
    This PowerShell script ensures that connections to non-domain networks when connected to a domain authenticated network are blocked.

.NOTES
    Author          : Horacio Flores
    LinkedIn        : linkedin.com/in/horacio-flores-19599121b/
    GitHub          : github.com/horacioxf
    Date Created    : 2025-07-21
    Last Modified   : 2025-07-21
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000060

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-CC-000060.ps1 
#>

# Define registry path and value
$regPath  = 'HKLM:\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'
$regName  = 'fBlockNonDomain'
$regValue = 1

# Create the key if it doesn't exist
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the policy value
Set-ItemProperty -Path $regPath -Name $regName -Value $regValue -Type DWord

Write-Output "Policy 'Prohibit connection to non-domain networks when connected to domain authenticated network' has been enabled."
