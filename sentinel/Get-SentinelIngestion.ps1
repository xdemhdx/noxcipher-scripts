<#
.SYNOPSIS
    Billable GB per table for a Log Analytics / Sentinel workspace, sorted by cost driver.
.DESCRIPTION
    NoxCipher Scripts | https://scripts.noxcipher.site | MIT

    Queries the Usage table for billable data over the lookback window and shows,
    per table: total GB, average GB per day and share of the total. Uses your
    current Az context (run Connect-AzAccount first). Needs the Az.Accounts and
    Az.OperationalInsights modules and Log Analytics Reader on the workspace.
.PARAMETER WorkspaceId
    The workspace ID (GUID), from the workspace Overview page.
.PARAMETER Days
    Lookback in days. Default 7.
.PARAMETER Csv
    Optional path to also export the results as CSV.
.EXAMPLE
    .\Get-SentinelIngestion.ps1 -WorkspaceId 00000000-0000-0000-0000-000000000000 -Days 30 -Csv .\usage.csv
#>
param(
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-fA-F-]{36}$')][string]$WorkspaceId,
    [ValidateRange(1, 90)][int]$Days = 7,
    [string]$Csv
)

$ErrorActionPreference = 'Stop'

foreach ($m in 'Az.Accounts', 'Az.OperationalInsights') {
    if (-not (Get-Module -ListAvailable -Name $m)) {
        throw "Module $m is missing. Install it with: Install-Module $m -Scope CurrentUser"
    }
}
Import-Module Az.Accounts, Az.OperationalInsights -ErrorAction Stop
if (-not (Get-AzContext)) { throw 'No Azure context. Run Connect-AzAccount first.' }

$query = @"
Usage
| where TimeGenerated > ago($($Days)d)
| where IsBillable == true
| summarize BillableGB = round(sum(Quantity) / 1000.0, 3) by DataType, Solution
| extend AvgGBPerDay = round(BillableGB / $Days, 3)
| sort by BillableGB desc
"@

Write-Host "Querying billable usage for the last $Days day(s)..." -ForegroundColor DarkGray
$result = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceId -Query $query -Timespan (New-TimeSpan -Days ($Days + 1))
$rows = @($result.Results)
if ($rows.Count -eq 0) { Write-Warning 'No billable usage returned. Check the workspace ID and your permissions.'; return }

$total = ($rows | Measure-Object -Property BillableGB -Sum).Sum
$report = foreach ($r in $rows) {
    [pscustomobject]@{
        Table       = $r.DataType
        Solution    = $r.Solution
        BillableGB  = [double]$r.BillableGB
        AvgGBPerDay = [double]$r.AvgGBPerDay
        SharePct    = if ($total -gt 0) { [math]::Round(([double]$r.BillableGB / $total) * 100, 1) } else { 0 }
    }
}

$report | Format-Table -AutoSize | Out-Host
Write-Host ("Total: {0:N2} GB over {1} day(s), about {2:N2} GB/day" -f $total, $Days, ($total / $Days)) -ForegroundColor Green
$top = $report | Select-Object -First 3
Write-Host ("Top drivers: " + (($top | ForEach-Object { "$($_.Table) ($($_.SharePct)%)" }) -join ', ')) -ForegroundColor Cyan

if ($Csv) {
    $report | Export-Csv -Path $Csv -NoTypeInformation -Encoding UTF8
    Write-Host "Exported to $Csv" -ForegroundColor DarkGray
}
