<#
.SYNOPSIS
    Defender AV, tamper protection, ASR rules and MDE onboarding state in one view.
.DESCRIPTION
    NoxCipher Scripts | https://scripts.noxcipher.site | MIT

    Shows antivirus mode and health, signature age, real-time and tamper
    protection, cloud protection, every configured Attack Surface Reduction rule
    with its mode (Block, Audit, Warn, Off), and whether the device is onboarded
    to Microsoft Defender for Endpoint with the Sense service running.
.PARAMETER Json
    Output JSON instead of tables (for scripts and remote collection).
.EXAMPLE
    .\Get-DefenderStatus.ps1
.EXAMPLE
    Invoke-Command -ComputerName srv01 -FilePath .\Get-DefenderStatus.ps1 -ArgumentList $true
#>
param([switch]$Json)

$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSEdition -eq 'Core' -and -not $IsWindows) { throw 'This script runs on Windows only.' }

# ASR rule GUIDs (Microsoft ASR rules reference)
$asrNames = @{
    '56a863a9-875e-4185-98a7-b882c64b5ce5' = 'Block abuse of exploited vulnerable signed drivers'
    '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c' = 'Block Adobe Reader from creating child processes'
    'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = 'Block all Office applications from creating child processes'
    '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 'Block credential stealing from LSASS'
    'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = 'Block executable content from email client and webmail'
    '01443614-cd74-433a-b99e-2ecdc07bfc25' = 'Block executables unless they meet prevalence, age or trusted list criteria'
    '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = 'Block execution of potentially obfuscated scripts'
    'd3e037e1-3eb8-44c8-a917-57927947596d' = 'Block JavaScript or VBScript from launching downloaded executable content'
    '3b576869-a4ec-4529-8536-b80a7769e899' = 'Block Office applications from creating executable content'
    '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' = 'Block Office applications from injecting code into other processes'
    '26190899-1602-49e8-8b27-eb1d0a1ce869' = 'Block Office communication application from creating child processes'
    'e6db77e5-3df2-4cf1-b95a-636979351e5b' = 'Block persistence through WMI event subscription'
    'd1e49aac-8f56-4280-b9ba-993a6d77406c' = 'Block process creations from PSExec and WMI commands'
    '33ddedf1-c6e0-47cb-833e-de6133960387' = 'Block rebooting machine in Safe Mode'
    'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' = 'Block untrusted and unsigned processes that run from USB'
    'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb' = 'Block use of copied or impersonated system tools'
    'a8f5898e-1dc8-49a9-9878-85004b8a61e6' = 'Block Webshell creation for Servers'
    '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' = 'Block Win32 API calls from Office macros'
    'c1db55ab-c21a-4637-bb3f-a12568109d35' = 'Use advanced protection against ransomware'
}
$asrMode = @{ 0 = 'Off'; 1 = 'Block'; 2 = 'Audit'; 5 = 'Not configured'; 6 = 'Warn' }

if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) { throw 'Defender cmdlets not found (Defender not installed, or a third-party AV is the primary).' }
$s = Get-MpComputerStatus
$p = Get-MpPreference

$av = [ordered]@{
    Computer                  = $env:COMPUTERNAME
    RunningMode               = $s.AMRunningMode
    AntivirusEnabled          = $s.AntivirusEnabled
    RealTimeProtection        = $s.RealTimeProtectionEnabled
    TamperProtected           = $s.IsTamperProtected
    BehaviorMonitor           = $s.BehaviorMonitorEnabled
    CloudProtection           = if ($p.MAPSReporting -gt 0) { 'On' } else { 'Off' }
    EngineVersion             = $s.AMEngineVersion
    SignatureVersion          = $s.AntivirusSignatureVersion
    SignatureAgeDays          = $s.AntivirusSignatureAge
    LastQuickScan             = $s.QuickScanEndTime
}

$asr = @()
$ids = @($p.AttackSurfaceReductionRules_Ids); $acts = @($p.AttackSurfaceReductionRules_Actions)
for ($i = 0; $i -lt $ids.Count; $i++) {
    if (-not $ids[$i]) { continue }
    $id = $ids[$i].ToString().ToLower()
    $asr += [pscustomobject]@{
        Rule = if ($asrNames.ContainsKey($id)) { $asrNames[$id] } else { "Unknown rule $id" }
        Mode = if ($asrMode.ContainsKey([int]$acts[$i])) { $asrMode[[int]$acts[$i]] } else { "Value $($acts[$i])" }
        Id   = $id
    }
}

$sense = Get-Service -Name Sense -ErrorAction SilentlyContinue
$onb = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status' -Name OnboardingState -ErrorAction SilentlyContinue).OnboardingState
$mde = [ordered]@{
    Onboarded    = ($onb -eq 1)
    SenseService = if ($sense) { "$($sense.Status)" } else { 'Not installed' }
    OrgId        = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status' -Name OrgId -ErrorAction SilentlyContinue).OrgId
}

$issues = @()
if (-not $s.RealTimeProtectionEnabled) { $issues += 'Real-time protection is off' }
if (-not $s.IsTamperProtected) { $issues += 'Tamper protection is off' }
if ($s.AntivirusSignatureAge -gt 3) { $issues += "Signatures are $($s.AntivirusSignatureAge) days old" }
if ($s.AMRunningMode -ne 'Normal') { $issues += "AV running mode is '$($s.AMRunningMode)' (passive or EDR block mode?)" }
if (-not $mde.Onboarded) { $issues += 'Not onboarded to Defender for Endpoint' }
if ($mde.Onboarded -and $mde.SenseService -ne 'Running') { $issues += 'Onboarded, but the Sense service is not running' }
if ($asr.Count -eq 0) { $issues += 'No ASR rules configured' }

if ($Json) {
    [ordered]@{ antivirus = $av; asrRules = $asr; mde = $mde; issues = $issues } | ConvertTo-Json -Depth 5
    return
}

Write-Host "`nAntivirus" -ForegroundColor Cyan
[pscustomobject]$av | Format-List | Out-Host
Write-Host "Attack Surface Reduction ($($asr.Count) configured)" -ForegroundColor Cyan
if ($asr.Count) { $asr | Sort-Object Mode, Rule | Format-Table Mode, Rule -AutoSize | Out-Host } else { Write-Host '  none' }
Write-Host "Defender for Endpoint" -ForegroundColor Cyan
[pscustomobject]$mde | Format-List | Out-Host
if ($issues.Count) { Write-Host 'Issues:' -ForegroundColor Yellow; $issues | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow } }
else { Write-Host 'No issues found.' -ForegroundColor Green }
