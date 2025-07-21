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
    STIG-ID         : WN10-AC-000010

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-AC-000010.ps1 
#>

# Set Account Lockout Threshold to 3 invalid logon attempts
$lockoutThreshold = 3

if ($lockoutThreshold -le 0) {
    Write-Error "Invalid threshold value: must be greater than 0."
    exit 1
}

Write-Host "Setting Account lockout threshold to $lockoutThreshold invalid logon attempts..." -ForegroundColor Cyan

# Apply the setting using `net accounts`
net accounts /lockoutthreshold:$lockoutThreshold

if ($LASTEXITCODE -eq 0) {
    Write-Host "Account lockout threshold successfully set to $lockoutThreshold." -ForegroundColor Green
} else {
    Write-Error "Failed to set Account lockout threshold."
    exit 1
}

# Optionally verify the setting
Write-Host "`nCurrent account lockout policy:"
net accounts
