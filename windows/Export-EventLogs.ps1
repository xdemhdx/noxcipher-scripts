<#
.SYNOPSIS
    Collect Windows event logs and live triage data into one timestamped zip for incident response.
.DESCRIPTION
    NoxCipher Scripts | https://scripts.noxcipher.site | MIT

    Exports these logs (only the lookback window) as .evtx: Security, System,
    Application, Sysmon, PowerShell (Operational and classic), Defender,
    Task Scheduler, RDP session manager and WMI activity. Adds host info,
    logged-on users, running processes with paths and hashes, network
    connections, services and scheduled tasks. Hashes every file (SHA-256),
    then zips the lot. Logs that don't exist on the machine are skipped.

    Run as Administrator (needed for the Security log).
.PARAMETER Hours
    Lookback window in hours. Default 24.
.PARAMETER OutPath
    Destination folder. Default: your TEMP folder.
.EXAMPLE
    .\Export-EventLogs.ps1 -Hours 48 -OutPath D:\IR
#>
param(
    [ValidateRange(1, 8760)][int]$Hours = 24,
    [string]$OutPath = $env:TEMP
)

$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSEdition -eq 'Core' -and -not $IsWindows) { throw 'This script runs on Windows only.' }
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw 'Run this from an elevated (Administrator) PowerShell.' }

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$name = "IR-$($env:COMPUTERNAME)-$stamp"
$dir = Join-Path $OutPath $name
$logDir = Join-Path $dir 'logs'
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$ms = [int64]$Hours * 3600 * 1000
$xpath = "*[System[TimeCreated[timediff(@SystemTime) <= $ms]]]"

$logs = @(
    'Security', 'System', 'Application',
    'Microsoft-Windows-Sysmon/Operational',
    'Microsoft-Windows-PowerShell/Operational', 'Windows PowerShell',
    'Microsoft-Windows-Windows Defender/Operational',
    'Microsoft-Windows-TaskScheduler/Operational',
    'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
    'Microsoft-Windows-WMI-Activity/Operational'
)

Write-Host "Exporting the last $Hours hour(s) of event logs to $dir" -ForegroundColor Cyan
foreach ($l in $logs) {
    $exists = $null -ne (Get-WinEvent -ListLog $l -ErrorAction SilentlyContinue)
    if (-not $exists) { Write-Host ("  skip  {0} (not present)" -f $l) -ForegroundColor DarkGray; continue }
    $file = Join-Path $logDir (($l -replace '[\\/ ]', '_') + '.evtx')
    wevtutil epl "$l" "$file" "/q:$xpath" 2>$null
    if ($LASTEXITCODE -eq 0) { Write-Host ("  ok    {0}" -f $l) } else { Write-Warning "Couldn't export $l" }
}

Write-Host 'Collecting triage data...' -ForegroundColor Cyan
$t = Join-Path $dir 'triage'
New-Item -ItemType Directory -Force -Path $t | Out-Null
Get-ComputerInfo -ErrorAction SilentlyContinue | Out-File (Join-Path $t 'computerinfo.txt')
(quser 2>$null) | Out-File (Join-Path $t 'logged-on-users.txt')
Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, CreationDate |
    Export-Csv (Join-Path $t 'processes.csv') -NoTypeInformation
Get-Process | Where-Object Path | Select-Object -Unique Path | ForEach-Object {
    $h = Get-FileHash -Algorithm SHA256 -Path $_.Path -ErrorAction SilentlyContinue
    if ($h) { [pscustomobject]@{ Path = $_.Path; SHA256 = $h.Hash } }
} | Export-Csv (Join-Path $t 'process-hashes.csv') -NoTypeInformation
Get-NetTCPConnection -ErrorAction SilentlyContinue | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess,
    @{ n = 'Process'; e = { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name } } |
    Export-Csv (Join-Path $t 'tcp-connections.csv') -NoTypeInformation
Get-CimInstance Win32_Service | Select-Object Name, DisplayName, State, StartMode, PathName, StartName |
    Export-Csv (Join-Path $t 'services.csv') -NoTypeInformation
Get-ScheduledTask -ErrorAction SilentlyContinue | Select-Object TaskPath, TaskName, State,
    @{ n = 'Actions'; e = { ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | ' } } |
    Export-Csv (Join-Path $t 'scheduled-tasks.csv') -NoTypeInformation
ipconfig /all | Out-File (Join-Path $t 'ipconfig.txt')
Get-DnsClientCache -ErrorAction SilentlyContinue | Export-Csv (Join-Path $t 'dns-cache.csv') -NoTypeInformation

# Hash manifest
Get-ChildItem -Path $dir -Recurse -File | ForEach-Object {
    [pscustomobject]@{ File = $_.FullName.Substring($dir.Length + 1); Bytes = $_.Length; SHA256 = (Get-FileHash $_.FullName -Algorithm SHA256).Hash }
} | Export-Csv (Join-Path $dir 'manifest-sha256.csv') -NoTypeInformation

$zip = "$dir.zip"
Compress-Archive -Path (Join-Path $dir '*') -DestinationPath $zip -CompressionLevel Optimal -Force
$zipHash = (Get-FileHash $zip -Algorithm SHA256).Hash
Remove-Item -Recurse -Force $dir

Write-Host ''
Write-Host "Collection: $zip" -ForegroundColor Green
Write-Host "SHA-256:    $zipHash"
Write-Host 'Record the hash with the time and your name for chain of custody.' -ForegroundColor DarkGray
