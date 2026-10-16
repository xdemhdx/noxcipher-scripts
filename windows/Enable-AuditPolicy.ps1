<#
.SYNOPSIS
    Turn on the Windows audit policy and logging that detections actually need.
.DESCRIPTION
    NoxCipher Scripts | https://scripts.noxcipher.site | MIT

    Backs up the current audit policy, then:
      - enables advanced audit subcategories (logon, process creation, account
        and group changes, policy changes, privilege use, and more)
      - forces subcategory settings to override legacy category policy
      - logs the full command line in event 4688
      - turns on PowerShell script block logging (event 4104)
      - raises the Security log to 1 GB so events aren't overwritten

    Profiles:
      baseline  what most Sentinel/Defender detections rely on
      verbose   baseline plus process termination, file share access, firewall
                rule changes, PnP devices and directory service changes (higher volume)

    Domain Group Policy can override these local settings at the next refresh.
    Subcategory names are English; on a non-English OS, set them by GUID instead.
    Run as Administrator. Supports -WhatIf.
.PARAMETER Profile
    baseline (default) or verbose.
.EXAMPLE
    .\Enable-AuditPolicy.ps1 -WhatIf
.EXAMPLE
    .\Enable-AuditPolicy.ps1 -Profile verbose
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Alias('Profile')][ValidateSet('baseline', 'verbose')][string]$AuditProfile = 'baseline'
)

$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSEdition -eq 'Core' -and -not $IsWindows) { throw 'This script runs on Windows only.' }

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw 'Run this from an elevated (Administrator) PowerShell.' }

# Subcategory -> setting (S = success, F = failure, SF = both)
$baseline = [ordered]@{
    'Credential Validation'               = 'SF'
    'Kerberos Authentication Service'     = 'SF'
    'Kerberos Service Ticket Operations'  = 'SF'
    'Computer Account Management'         = 'S'
    'Security Group Management'           = 'S'
    'User Account Management'             = 'SF'
    'Other Account Management Events'     = 'S'
    'Process Creation'                    = 'S'
    'Logon'                               = 'SF'
    'Logoff'                              = 'S'
    'Account Lockout'                     = 'F'
    'Special Logon'                       = 'S'
    'Other Logon/Logoff Events'           = 'SF'
    'Audit Policy Change'                 = 'SF'
    'Authentication Policy Change'        = 'S'
    'Sensitive Privilege Use'             = 'SF'
    'Security System Extension'           = 'S'
    'System Integrity'                    = 'SF'
    'Security State Change'               = 'S'
    'Other Object Access Events'          = 'SF'
    'Removable Storage'                   = 'SF'
}
$verboseExtra = [ordered]@{
    'Process Termination'                 = 'S'
    'File Share'                          = 'SF'
    'Detailed File Share'                 = 'F'
    'MPSSVC Rule-Level Policy Change'     = 'SF'
    'Other Policy Change Events'          = 'F'
    'Plug and Play Events'                = 'S'
    'Directory Service Changes'           = 'S'
    'Directory Service Access'            = 'SF'
}
$plan = [ordered]@{}
$baseline.GetEnumerator() | ForEach-Object { $plan[$_.Key] = $_.Value }
if ($AuditProfile -eq 'verbose') { $verboseExtra.GetEnumerator() | ForEach-Object { $plan[$_.Key] = $_.Value } }

# 1. Backup
$backup = Join-Path $env:TEMP ("auditpol-backup-{0:yyyyMMdd-HHmmss}.csv" -f (Get-Date))
if ($PSCmdlet.ShouldProcess('audit policy', "back up to $backup")) {
    auditpol /backup /file:"$backup" | Out-Null
    Write-Host "Backup: $backup  (restore with: auditpol /restore /file:`"$backup`")" -ForegroundColor DarkGray
}

# 2. Subcategories
$failed = @()
foreach ($e in $plan.GetEnumerator()) {
    $s = if ($e.Value -match 'S') { 'enable' } else { 'disable' }
    $f = if ($e.Value -match 'F') { 'enable' } else { 'disable' }
    if ($PSCmdlet.ShouldProcess($e.Key, "success:$s failure:$f")) {
        $out = auditpol /set /subcategory:"$($e.Key)" /success:$s /failure:$f 2>&1
        if ($LASTEXITCODE -ne 0) { $failed += $e.Key; Write-Warning "$($e.Key): $out" }
        else { Write-Host ("  {0,-38} {1}" -f $e.Key, $e.Value) }
    }
}

# 3. Registry settings
function Set-Reg($Path, $Name, $Value) {
    if ($PSCmdlet.ShouldProcess("$Path\$Name", "set to $Value")) {
        if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
    }
}
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'SCENoApplyLegacyAuditPolicy' 1
Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled' 1
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' 1
Write-Host '  Command line in 4688, script block logging (4104), subcategory override: on'

# 4. Security log size (1 GB)
if ($PSCmdlet.ShouldProcess('Security event log', 'set maximum size to 1 GB')) {
    wevtutil sl Security /ms:1073741824
    Write-Host '  Security log max size: 1 GB'
}

Write-Host ''
if ($failed.Count) { Write-Warning ("Couldn't set: " + ($failed -join ', ') + '. On a non-English OS, use subcategory GUIDs (auditpol /list /subcategory:* /v).') }
Write-Host "Audit profile '$AuditProfile' applied." -ForegroundColor Green
Write-Host 'Check with: auditpol /get /category:*   |   gpresult /h report.html (to spot GPO overrides)' -ForegroundColor DarkGray
