<#
.SYNOPSIS
    This PowerShell script ensures that accounts are configured to require password expiration.
.NOTES
    Author          : Horacio Flores
    LinkedIn        : linkedin.com/in/horacio-flores-19599121b/
    GitHub          : github.com/horacioxf
    Date Created    : 2025-07-21
    Last Modified   : 2025-07-21
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         :WN10-00-000090

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-00-000090.ps1 
#>

# Run this script in an elevated (Administrator) PowerShell session.

# Get all enabled, local, non-built-in user accounts
$users = Get-LocalUser | Where-Object {
    $_.Enabled -eq $true -and
    $_.Name -ne "Administrator" -and
    $_.Name -ne "Guest"
}

foreach ($user in $users) {
    Write-Host "Configuring user: $($user.Name)"
    # Set PasswordNeverExpires to $false
    Set-LocalUser -Name $user.Name -PasswordNeverExpires:$false
}

Write-Host "Password expiration policy applied to all active local accounts."
