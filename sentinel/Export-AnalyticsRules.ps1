<#
.SYNOPSIS
    Export every Microsoft Sentinel analytics rule in a workspace to deployable ARM templates.
.DESCRIPTION
    NoxCipher Scripts | https://scripts.noxcipher.site | MIT

    Lists all alert rules through the Microsoft.SecurityInsights REST API and
    writes one ARM template per rule (read-only properties removed, workspace as
    a parameter), named by kind and display name, plus an index.csv with ID,
    severity, tactics and enabled state. Good for detection-as-code, backups
    before content hub updates, and copying rules between tenants.

    Uses your current Az context (Connect-AzAccount). Needs Az.Accounts and
    Microsoft Sentinel Reader on the workspace.
.PARAMETER ResourceGroup
    Resource group of the Sentinel workspace.
.PARAMETER Workspace
    Log Analytics workspace name.
.PARAMETER OutDir
    Output folder. Default .\rules
.PARAMETER SubscriptionId
    Optional. Defaults to the subscription of the current Az context.
.EXAMPLE
    .\Export-AnalyticsRules.ps1 -ResourceGroup rg-soc -Workspace law-soc
.EXAMPLE
    Deploy one exported rule to another workspace:
    New-AzResourceGroupDeployment -ResourceGroupName rg-other -TemplateFile .\rules\Scheduled_My-Rule.json -workspace law-other
#>
param(
    [Parameter(Mandatory = $true)][string]$ResourceGroup,
    [Parameter(Mandatory = $true)][string]$Workspace,
    [string]$OutDir = './rules',
    [string]$SubscriptionId
)

$ErrorActionPreference = 'Stop'
$ApiVersion = '2024-03-01'

if (-not (Get-Module -ListAvailable -Name Az.Accounts)) { throw 'Module Az.Accounts is missing. Install-Module Az.Accounts -Scope CurrentUser' }
Import-Module Az.Accounts -ErrorAction Stop
$ctx = Get-AzContext
if (-not $ctx) { throw 'No Azure context. Run Connect-AzAccount first.' }
if (-not $SubscriptionId) { $SubscriptionId = $ctx.Subscription.Id }

$base = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$Workspace/providers/Microsoft.SecurityInsights/alertRules"
$path = "$($base)?api-version=$ApiVersion"
$rules = New-Object System.Collections.Generic.List[object]

do {
    $resp = Invoke-AzRestMethod -Method GET -Path $path
    if ($resp.StatusCode -ne 200) { throw "API returned $($resp.StatusCode): $($resp.Content)" }
    $page = $resp.Content | ConvertFrom-Json
    foreach ($r in $page.value) { $rules.Add($r) }
    $path = if ($page.nextLink) { ([uri]$page.nextLink).PathAndQuery } else { $null }
} while ($path)

if ($rules.Count -eq 0) { Write-Warning 'No analytics rules found.'; return }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$readOnly = 'lastModifiedUtc', 'createdTimeUtc', 'lastModifiedTimeUtc', 'etag'
$index = foreach ($r in $rules) {
    $props = $r.properties | Select-Object * -ExcludeProperty $readOnly
    $name = if ($r.properties.displayName) { $r.properties.displayName } else { $r.name }
    $safe = ($name -replace '[^A-Za-z0-9 _.-]', '' -replace '\s+', '-').Trim('-')
    if ($safe.Length -gt 80) { $safe = $safe.Substring(0, 80) }
    $file = Join-Path $OutDir ("{0}_{1}.json" -f $r.kind, $safe)
    if (Test-Path $file) { $file = Join-Path $OutDir ("{0}_{1}_{2}.json" -f $r.kind, $safe, $r.name.Substring(0, 8)) }

    $template = [ordered]@{
        '$schema'      = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'
        contentVersion = '1.0.0.0'
        parameters     = @{ workspace = @{ type = 'string' } }
        resources      = @(
            [ordered]@{
                type       = 'Microsoft.OperationalInsights/workspaces/providers/alertRules'
                apiVersion = $ApiVersion
                name       = "[concat(parameters('workspace'), '/Microsoft.SecurityInsights/', '$($r.name)')]"
                kind       = $r.kind
                properties = $props
            }
        )
    }
    $template | ConvertTo-Json -Depth 30 | Set-Content -Path $file -Encoding UTF8

    [pscustomobject]@{
        Name     = $name
        Kind     = $r.kind
        Enabled  = $r.properties.enabled
        Severity = $r.properties.severity
        Tactics  = ($r.properties.tactics -join ';')
        RuleId   = $r.name
        File     = Split-Path $file -Leaf
    }
}

$index | Sort-Object Kind, Name | Export-Csv -Path (Join-Path $OutDir 'index.csv') -NoTypeInformation -Encoding UTF8
$index | Group-Object Kind | ForEach-Object { Write-Host ("{0,-24} {1}" -f $_.Name, $_.Count) }
Write-Host "Exported $($rules.Count) rule(s) to $((Resolve-Path $OutDir).Path)" -ForegroundColor Green
Write-Host 'Fusion, ML and Microsoft Security rules are exported too; they can only be deployed where the matching product exists.' -ForegroundColor DarkGray
