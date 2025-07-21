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
    PS C:\> .\WN10-AC-000005.ps1 
#>
# Desired value — change to 0 if you want admin unlock only
$LockoutDuration = 15  # minutes — use 0 for admin unlock

# Check current settings
Write-Output "Current Account Lockout Policy:"
net accounts

# Set account lockout duration
Write-Output "Setting Account lockout duration to $LockoutDuration minutes..."
net accounts /lockoutduration:$LockoutDuration

# Verify settings
Write-Output "Updated Account Lockout Policy:"
net accounts
