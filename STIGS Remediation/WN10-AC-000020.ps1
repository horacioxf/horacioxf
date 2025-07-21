<#
.SYNOPSIS
    This PowerShell script ensures that the password history is configured to 24 passwords remembered.
.NOTES
    Author          : Horacio Flores
    LinkedIn        : linkedin.com/in/horacio-flores-19599121b/
    GitHub          : github.com/horacioxf
    Date Created    : 2025-07-21
    Last Modified   : 2025-07-21
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AC-000020

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-AC-000020.ps1 
#>

# Run as Administrator

# Set Enforce password history to 24
Write-Host "Setting 'Enforce password history' to 24" -ForegroundColor Cyan

# Use net accounts to set the password history
net accounts /uniquepw:24

# Show current password policy
Write-Host "`nCurrent Password Policy:" -ForegroundColor Green
net accounts
