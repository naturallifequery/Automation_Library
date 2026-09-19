#requires -Version 5.1
<#
.SYNOPSIS
    Creates a read-only Conditional Access coverage matrix as JSON and management HTML.

.DESCRIPTION
    Reads Conditional Access policies, named locations and authentication strength
    policies from Microsoft Graph v1.0. It normalises each policy into a scenario
    row, then reports pragmatic findings for gaps, overlaps, broad exclusions,
    possible contradictions and emergency-access account coverage.

    The script writes machine-readable JSON and, by default, a self-contained
    management HTML report with summary cards, findings and a searchable matrix.

    The script does not create, update or delete Microsoft Entra configuration.

.PARAMETER OutputPath
    Path for the JSON report. A timestamped file in C:\temp is used by default.

.PARAMETER HtmlOutputPath
    Optional path for the management HTML report. By default, the HTML file is
    written beside the JSON report with the same base filename.

.PARAMETER SkipHtmlReport
    Writes only the JSON report. The management HTML report is created by default.

.PARAMETER EmergencyAccessAccountObjectId
    One or more emergency-access user object IDs. Supplying these IDs enables the
    account-level exclusion checks. Microsoft recommends at least two accounts.

.PARAMETER EmergencyAccessGroupObjectId
    Optional emergency-access security group object ID. Supplying this ID enables
    checks that restrictive policies exclude the dedicated group.

.PARAMETER TenantId
    Optional tenant ID or verified domain passed to Connect-MgGraph.

.PARAMETER UseDeviceCode
    Uses device-code authentication instead of the default interactive browser.

.PARAMETER SkipAuthenticationStrengthInventory
    Skips the separate authentication-strength inventory call. Authentication
    strengths embedded in Conditional Access policies still appear in the matrix.

.PARAMETER IncludeRawPolicies
    Adds the complete Graph policy objects to the JSON report. This can make the
    report substantially larger.

.PARAMETER NoDisconnect
    Keeps the Microsoft Graph session connected when the script finishes.

.PARAMETER PassThru
    Returns the report object to the PowerShell pipeline as well as writing JSON.

.EXAMPLE
    .\Invoke-ConditionalAccessCoverageMatrix.ps1 -Verbose

.EXAMPLE
    .\Invoke-ConditionalAccessCoverageMatrix.ps1 `
        -EmergencyAccessAccountObjectId 'GUID-1','GUID-2' `
        -EmergencyAccessGroupObjectId 'GROUP-GUID' `
        -OutputPath C:\Reports\CA-Coverage.json -Verbose

.EXAMPLE
    .\Invoke-ConditionalAccessCoverageMatrix.ps1 `
        -OutputPath C:\Reports\CA-Coverage.json `
        -HtmlOutputPath C:\Reports\CA-Coverage-Management.html -Verbose

.NOTES
    Version: 1.1.1
    Required module: Microsoft.Graph.Authentication
    Delegated Graph scope used by default: Policy.Read.All
    Recommended PowerShell: PowerShell 7; compatible with Windows PowerShell 5.1.
    PowerShell-native arrays are used to avoid Windows PowerShell 5.1 generic
    collection binder errors such as "Argument types do not match".
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = (Join-Path -Path 'C:\temp' -ChildPath ("ConditionalAccess-Coverage-{0}.json" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))),

    [Parameter()]
    [string]$HtmlOutputPath,

    [Parameter()]
    [switch]$SkipHtmlReport,

    [Parameter()]
    [ValidateScript({ $_ -match '^[0-9a-fA-F-]{36}$' })]
    [string[]]$EmergencyAccessAccountObjectId = @(),

    [Parameter()]
    [ValidateScript({ $_ -match '^[0-9a-fA-F-]{36}$' })]
    [string]$EmergencyAccessGroupObjectId,

    [Parameter()]
    [string]$TenantId,

    [Parameter()]
    [switch]$UseDeviceCode,

    [Parameter()]
    [switch]$SkipAuthenticationStrengthInventory,

    [Parameter()]
    [switch]$IncludeRawPolicies,

    [Parameter()]
    [switch]$NoDisconnect,

    [Parameter()]
    [switch]$PassThru
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:ToolName = 'Conditional Access Coverage Matrix'
$script:ToolVersion = '1.1.1'
$script:GraphBaseUri = 'https://graph.microsoft.com/v1.0'
$script:Diagnostics = @()
$script:ConnectedByScript = $false

function Add-Diagnostic {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Information','Warning','Error')]
        [string]$Level,

        [Parameter(Mandatory)]
        [string]$Stage,

        [Parameter(Mandatory)]
        [string]$Message,

        [Parameter()]
        [string]$Detail
    )

    $entry = [pscustomobject][ordered]@{
        TimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
        Level        = $Level
        Stage        = $Stage
        Message      = $Message
        Detail       = $Detail
    }
    $script:Diagnostics += $entry

    if ($Level -eq 'Warning') { Write-Warning $Message }
    elseif ($Level -eq 'Error') { Write-Warning ("ERROR: {0}" -f $Message) }
    else { Write-Verbose ("[{0}] {1}" -f $Stage, $Message) }
}

function Get-Array {
    [CmdletBinding()]
    param([Parameter()][AllowNull()]$Value)

    if ($null -eq $Value) { return @() }
    return @($Value)
}

function Get-PropertyValue {
    [CmdletBinding()]
    param(
        [Parameter()][AllowNull()]$Object,
        [Parameter(Mandatory)][string]$Name,
        [Parameter()][AllowNull()]$Default = $null
    )

    if ($null -eq $Object) { return $Default }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $Default }
    return $property.Value
}

function Join-DisplayValue {
    [CmdletBinding()]
    param(
        [Parameter()][AllowNull()]$Value,
        [Parameter()][string]$EmptyText = 'Any'
    )

    $items = @(Get-Array -Value $Value | Where-Object { $null -ne $_ -and [string]$_ -ne '' })
    if ($items.Count -eq 0) { return $EmptyText }
    return ($items -join ', ')
}

function Test-ContainsValue {
    [CmdletBinding()]
    param(
        [Parameter()][AllowNull()]$Collection,
        [Parameter(Mandatory)][string]$Value
    )

    foreach ($item in @(Get-Array -Value $Collection)) {
        if ([string]::Equals([string]$item, $Value, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

function Get-SortedUniqueStrings {
    [CmdletBinding()]
    param([Parameter()][AllowNull()]$Value)

    return @(Get-Array -Value $Value | ForEach-Object { [string]$_ } | Where-Object { $_ } | Sort-Object -Unique)
}

function ConvertTo-StableListText {
    [CmdletBinding()]
    param([Parameter()][AllowNull()]$Value)

    $items = @(Get-SortedUniqueStrings -Value $Value)
    if ($items.Count -eq 0) { return '*' }
    return ($items -join '|').ToLowerInvariant()
}

function Invoke-GraphGetAll {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$Stage,
        [Parameter()][ValidateRange(1,10)][int]$MaxAttempts = 4
    )

    $allItems = @()
    $nextUri = $Uri

    while ($nextUri) {
        $attempt = 0
        $completed = $false
        while (-not $completed) {
            $attempt++
            try {
                Write-Verbose ("GET {0}" -f $nextUri)
                $response = Invoke-MgGraphRequest -Method GET -Uri $nextUri -OutputType PSObject
                $completed = $true
            }
            catch {
                $message = $_.Exception.Message
                $isRetryable = $message -match '(429|Too Many Requests|5\d\d|temporar|timeout)'
                if ($isRetryable -and $attempt -lt $MaxAttempts) {
                    $delay = [math]::Min([math]::Pow(2, $attempt), 30)
                    Add-Diagnostic -Level Warning -Stage $Stage -Message ("Graph request failed temporarily. Retry {0} of {1} in {2} seconds." -f $attempt, $MaxAttempts, $delay) -Detail $message
                    Start-Sleep -Seconds $delay
                }
                else {
                    throw ("{0} failed after {1} attempt(s). {2}" -f $Stage, $attempt, $message)
                }
            }
        }

        $valueProperty = $response.PSObject.Properties['value']
        if ($null -ne $valueProperty) {
            foreach ($item in @(Get-Array -Value $response.value)) { $allItems += $item }
        }
        else {
            $allItems += $response
        }

        $nextProperty = $response.PSObject.Properties['@odata.nextLink']
        if ($null -ne $nextProperty -and $nextProperty.Value) {
            $nextUri = [string]$nextProperty.Value
        }
        else {
            $nextUri = $null
        }
    }

    return @($allItems)
}

function Resolve-LocationList {
    [CmdletBinding()]
    param(
        [Parameter()][AllowNull()]$Ids,
        [Parameter(Mandatory)][hashtable]$LocationMap
    )

    $resolved = @()
    foreach ($id in @(Get-Array -Value $Ids)) {
        $text = [string]$id
        if ($text -eq 'All') { $resolved += 'All locations' }
        elseif ($text -eq 'AllTrusted') { $resolved += 'All trusted locations' }
        elseif ($LocationMap.ContainsKey($text)) { $resolved += ("{0} [{1}]" -f $LocationMap[$text], $text) }
        else { $resolved += $text }
    }
    return @($resolved)
}

function Format-GrantControls {
    [CmdletBinding()]
    param([Parameter()][AllowNull()]$GrantControls)

    if ($null -eq $GrantControls) { return 'None' }
    $controls = @()
    foreach ($item in @(Get-Array -Value (Get-PropertyValue -Object $GrantControls -Name 'builtInControls' -Default @()))) {
        $controls += [string]$item
    }
    $strength = Get-PropertyValue -Object $GrantControls -Name 'authenticationStrength'
    if ($null -ne $strength) {
        $strengthName = Get-PropertyValue -Object $strength -Name 'displayName' -Default (Get-PropertyValue -Object $strength -Name 'id' -Default 'Unknown')
        $controls += ("authenticationStrength:{0}" -f $strengthName)
    }
    foreach ($term in @(Get-Array -Value (Get-PropertyValue -Object $GrantControls -Name 'termsOfUse' -Default @()))) {
        $controls += ("termsOfUse:{0}" -f $term)
    }
    if ($controls.Count -eq 0) { return 'None' }
    $operator = [string](Get-PropertyValue -Object $GrantControls -Name 'operator' -Default 'OR')
    return (@($controls) -join (" {0} " -f $operator.ToUpperInvariant()))
}

function Format-SessionControls {
    [CmdletBinding()]
    param([Parameter()][AllowNull()]$SessionControls)

    if ($null -eq $SessionControls) { return 'None' }
    $values = @()

    $signInFrequency = Get-PropertyValue -Object $SessionControls -Name 'signInFrequency'
    if ($null -ne $signInFrequency -and (Get-PropertyValue -Object $signInFrequency -Name 'isEnabled' -Default $false)) {
        $interval = Get-PropertyValue -Object $signInFrequency -Name 'frequencyInterval'
        if ($interval -eq 'everyTime') { $values += 'Sign-in frequency: every time' }
        else {
            $frequencyValue = Get-PropertyValue -Object $signInFrequency -Name 'value' -Default '?'
            $frequencyType = Get-PropertyValue -Object $signInFrequency -Name 'type' -Default 'unknown'
            $values += ("Sign-in frequency: {0} {1}" -f $frequencyValue, $frequencyType)
        }
    }

    $persistentBrowser = Get-PropertyValue -Object $SessionControls -Name 'persistentBrowser'
    if ($null -ne $persistentBrowser -and (Get-PropertyValue -Object $persistentBrowser -Name 'isEnabled' -Default $false)) {
        $mode = Get-PropertyValue -Object $persistentBrowser -Name 'mode' -Default 'configured'
        $values += ("Persistent browser: {0}" -f $mode)
    }

    $appRestrictions = Get-PropertyValue -Object $SessionControls -Name 'applicationEnforcedRestrictions'
    if ($null -ne $appRestrictions -and (Get-PropertyValue -Object $appRestrictions -Name 'isEnabled' -Default $false)) {
        $values += 'Application-enforced restrictions'
    }

    $cloudAppSecurity = Get-PropertyValue -Object $SessionControls -Name 'cloudAppSecurity'
    if ($null -ne $cloudAppSecurity -and (Get-PropertyValue -Object $cloudAppSecurity -Name 'isEnabled' -Default $false)) {
        $cloudType = Get-PropertyValue -Object $cloudAppSecurity -Name 'cloudAppSecurityType' -Default 'configured'
        $values += ("Defender for Cloud Apps: {0}" -f $cloudType)
    }

    $continuous = Get-PropertyValue -Object $SessionControls -Name 'continuousAccessEvaluation'
    if ($null -ne $continuous -and (Get-PropertyValue -Object $continuous -Name 'mode')) {
        $values += ("Continuous access evaluation: {0}" -f (Get-PropertyValue -Object $continuous -Name 'mode'))
    }

    $tokenProtection = Get-PropertyValue -Object $SessionControls -Name 'secureSignInSession'
    if ($null -ne $tokenProtection -and (Get-PropertyValue -Object $tokenProtection -Name 'isEnabled' -Default $false)) {
        $values += 'Token protection'
    }

    if ($values.Count -eq 0) { return 'None' }
    return (@($values) -join '; ')
}

function ConvertTo-HtmlText {
    [CmdletBinding()]
    param([Parameter()][AllowNull()]$Value)

    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function New-ConditionalAccessHtmlReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Report,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Path
    )

    $htmlParts = @()
    $title = ConvertTo-HtmlText -Value $Report.Tool.Name
    $tenant = ConvertTo-HtmlText -Value $Report.Run.TenantId
    $account = ConvertTo-HtmlText -Value $Report.Run.Account
    $completed = ConvertTo-HtmlText -Value $Report.Run.CompletedUtc
    $version = ConvertTo-HtmlText -Value $Report.Tool.Version
    $criticalCount = [int]$Report.Summary.FindingsBySeverity.Critical
    $highCount = [int]$Report.Summary.FindingsBySeverity.High
    $mediumCount = [int]$Report.Summary.FindingsBySeverity.Medium
    $attentionCount = $criticalCount + $highCount

    if ($criticalCount -gt 0) {
        $attentionClass = 'critical'
        $attentionTitle = 'Immediate review required'
        $attentionText = '{0} critical and {1} high-severity findings need management attention.' -f $criticalCount, $highCount
    }
    elseif ($highCount -gt 0) {
        $attentionClass = 'high'
        $attentionTitle = 'Priority review required'
        $attentionText = '{0} high-severity findings need management attention.' -f $highCount
    }
    elseif ($mediumCount -gt 0) {
        $attentionClass = 'medium'
        $attentionTitle = 'Review recommended'
        $attentionText = '{0} medium-severity findings should be reviewed and assigned.' -f $mediumCount
    }
    else {
        $attentionClass = 'clear'
        $attentionTitle = 'No priority findings detected'
        $attentionText = 'The configured checks did not detect any Critical, High or Medium findings.'
    }

    $htmlParts += @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>$title</title>
<style>
:root{--black:#111214;--charcoal:#202226;--panel:#292c31;--line:#3c4047;--silver:#c8ccd2;--muted:#949aa3;--gold:#c8a24a;--gold-soft:#f5edda;--white:#f7f8fa;--critical:#c73737;--high:#e06b32;--medium:#d6a11f;--low:#4387c7;--info:#737b87;--green:#2f9b68}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:#f2f3f5;color:#202226;font-family:Segoe UI,Arial,sans-serif;line-height:1.45}
.topbar{background:linear-gradient(135deg,var(--black),#26282d);color:var(--white);padding:34px 5vw 30px;border-bottom:4px solid var(--gold)}
.brand{color:var(--gold);font-size:13px;font-weight:800;letter-spacing:.14em;text-transform:uppercase}.topbar h1{font-size:clamp(28px,4vw,46px);margin:7px 0 5px;letter-spacing:-.03em}.subtitle{color:var(--silver);font-size:17px;max-width:900px}.meta{display:flex;flex-wrap:wrap;gap:10px 24px;margin-top:20px;color:#dfe1e5;font-size:13px}.meta strong{color:var(--gold)}
.nav{position:sticky;top:0;z-index:10;background:#fff;border-bottom:1px solid #d9dce1;padding:10px 5vw;display:flex;gap:9px;flex-wrap:wrap}.nav a{color:#333;text-decoration:none;font-size:13px;font-weight:700;padding:7px 10px;border-radius:5px}.nav a:hover{background:var(--gold-soft)}
.container{max-width:1680px;margin:0 auto;padding:28px 4vw 60px}.section{margin-top:28px}.section h2{font-size:24px;margin:0 0 14px;border-left:5px solid var(--gold);padding-left:12px}.section-note{color:#656b74;margin:-7px 0 16px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px}.card{background:#fff;border:1px solid #dde0e4;border-radius:9px;padding:18px;box-shadow:0 3px 12px rgba(0,0,0,.04)}.card .label{color:#656b74;font-size:12px;font-weight:800;text-transform:uppercase;letter-spacing:.06em}.card .value{font-size:32px;font-weight:800;margin-top:4px}.card.gold{border-top:4px solid var(--gold)}.card.critical{border-top:4px solid var(--critical)}.card.high{border-top:4px solid var(--high)}.card.medium{border-top:4px solid var(--medium)}
.attention{margin-top:16px;border-radius:8px;padding:17px 19px;background:#fff;border-left:7px solid var(--info);box-shadow:0 3px 12px rgba(0,0,0,.04)}.attention.critical{border-color:var(--critical);background:#fff0f0}.attention.high{border-color:var(--high);background:#fff4ed}.attention.medium{border-color:var(--medium);background:#fff9e8}.attention.clear{border-color:var(--green);background:#edf9f3}.attention h3{margin:0 0 4px;font-size:18px}.attention p{margin:0}
.toolbar{display:flex;gap:10px;flex-wrap:wrap;margin:0 0 12px}.toolbar input,.toolbar select{background:#fff;border:1px solid #cfd3d9;border-radius:6px;padding:10px 12px;font:inherit;min-width:190px}.toolbar input{flex:1;min-width:260px}
.table-shell{overflow:auto;background:#fff;border:1px solid #d7dae0;border-radius:8px;box-shadow:0 3px 12px rgba(0,0,0,.04)}table{width:100%;border-collapse:collapse;font-size:13px}th{position:sticky;top:0;background:var(--charcoal);color:#fff;text-align:left;padding:11px 10px;white-space:nowrap;z-index:1}td{padding:10px;border-bottom:1px solid #e5e7ea;vertical-align:top}tbody tr:nth-child(even){background:#fafafa}tbody tr:hover{background:#fff8e7}.matrix{min-width:1800px}.findings{min-width:1050px}.muted{color:#747b85}.nowrap{white-space:nowrap}
.badge{display:inline-block;padding:4px 8px;border-radius:999px;font-size:11px;font-weight:800;white-space:nowrap}.badge.enabled,.badge.clear{background:#dff4e9;color:#176542}.badge.report{background:#fff1c9;color:#765600}.badge.disabled{background:#eceef1;color:#575d66}.badge.critical{background:#f9dcdc;color:#8d1d1d}.badge.high{background:#fde4d7;color:#9a3c14}.badge.medium{background:#fff0bd;color:#735400}.badge.low{background:#dfeefa;color:#1b5d92}.badge.information{background:#e8eaed;color:#525963}
.finding-title{font-weight:800;margin-bottom:4px}.recommendation{border-left:3px solid var(--gold);padding-left:9px}.two-col{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:14px}.note-card{background:#fff;border:1px solid #dde0e4;border-radius:8px;padding:16px}.note-card h3{margin:0 0 8px}.note-card ul{margin:0;padding-left:20px}.footer{background:var(--black);color:#aeb3bb;padding:20px 5vw;font-size:12px}.footer strong{color:var(--gold)}
@media(max-width:700px){.topbar{padding:26px 22px}.container{padding:20px 14px 45px}.nav{padding:8px 12px}.card .value{font-size:27px}}
@media print{body{background:#fff}.nav,.toolbar{display:none}.topbar{padding:20px 28px}.container{max-width:none;padding:18px}.card,.attention,.table-shell{box-shadow:none}.table-shell{overflow:visible}.matrix,.findings{min-width:0;font-size:8px}th{position:static}.section{break-inside:avoid}.footer{background:#fff;color:#555;border-top:1px solid #aaa}}
</style>
</head>
<body>
<header class="topbar">
  <div class="brand">RuleRivet</div>
  <h1>Conditional Access Coverage Matrix</h1>
  <div class="subtitle">Management view of policy coverage, priority risks, exclusions, authentication requirements and session controls.</div>
  <div class="meta"><span><strong>Tenant:</strong> $tenant</span><span><strong>Account:</strong> $account</span><span><strong>Completed:</strong> $completed</span><span><strong>Version:</strong> $version</span></div>
</header>
<nav class="nav"><a href="#summary">Executive summary</a><a href="#findings">Findings</a><a href="#matrix">Coverage matrix</a><a href="#interpretation">Interpretation</a></nav>
<main class="container">
<section class="section" id="summary">
  <h2>Executive summary</h2>
  <div class="cards">
    <div class="card gold"><div class="label">Policies</div><div class="value">$($Report.Summary.PolicyCount)</div></div>
    <div class="card"><div class="label">Enabled</div><div class="value">$($Report.Summary.EnabledPolicyCount)</div></div>
    <div class="card"><div class="label">Report-only</div><div class="value">$($Report.Summary.ReportOnlyPolicyCount)</div></div>
    <div class="card"><div class="label">Disabled</div><div class="value">$($Report.Summary.DisabledPolicyCount)</div></div>
    <div class="card critical"><div class="label">Critical</div><div class="value">$criticalCount</div></div>
    <div class="card high"><div class="label">High</div><div class="value">$highCount</div></div>
    <div class="card medium"><div class="label">Medium</div><div class="value">$mediumCount</div></div>
    <div class="card"><div class="label">Priority findings</div><div class="value">$attentionCount</div></div>
  </div>
  <div class="attention $attentionClass"><h3>$(ConvertTo-HtmlText $attentionTitle)</h3><p>$(ConvertTo-HtmlText $attentionText)</p></div>
</section>
<section class="section" id="findings">
  <h2>Findings requiring review</h2>
  <p class="section-note">These are configuration observations. Validate impact with policy owners and the Conditional Access What If tool before making changes.</p>
  <div class="toolbar"><input id="findingSearch" type="search" placeholder="Search findings..." oninput="filterFindings()"><select id="findingSeverity" onchange="filterFindings()"><option value="">All severities</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option><option>Information</option></select></div>
  <div class="table-shell"><table class="findings" id="findingsTable"><thead><tr><th>Severity</th><th>Category</th><th>Finding</th><th>Evidence</th><th>Recommended management action</th></tr></thead><tbody>
"@

    $findings = @($Report.Findings)
    if ($findings.Count -eq 0) {
        $htmlParts += '<tr><td colspan="5"><span class="badge clear">Clear</span> No findings were generated.</td></tr>'
    }
    else {
        foreach ($finding in $findings) {
            $severity = ConvertTo-HtmlText -Value $finding.Severity
            $severityClass = ([string]$finding.Severity).ToLowerInvariant()
            $category = ConvertTo-HtmlText -Value $finding.Category
            $findingTitle = ConvertTo-HtmlText -Value $finding.Title
            $evidence = ConvertTo-HtmlText -Value $finding.Evidence
            $recommendation = ConvertTo-HtmlText -Value $finding.Recommendation
            $htmlParts += ('<tr data-finding-row data-severity="{0}"><td><span class="badge {1}">{0}</span></td><td>{2}</td><td><div class="finding-title">{3}</div><span class="muted">{4}</span></td><td>{5}</td><td><div class="recommendation">{6}</div></td></tr>' -f $severity, $severityClass, $category, $findingTitle, (ConvertTo-HtmlText -Value $finding.FindingId), $evidence, $recommendation)
        }
    }

    $htmlParts += @'
  </tbody></table></div>
</section>
<section class="section" id="matrix">
  <h2>Conditional Access visual matrix</h2>
  <p class="section-note">Each row is one policy. Use the filters to isolate enforced, report-only or disabled coverage.</p>
  <div class="toolbar"><input id="policySearch" type="search" placeholder="Search policies, scopes or controls..." oninput="filterPolicies()"><select id="policyState" onchange="filterPolicies()"><option value="">All policy states</option><option value="enabled">Enabled</option><option value="enabledForReportingButNotEnforced">Report-only</option><option value="disabled">Disabled</option></select></div>
  <div class="table-shell"><table class="matrix" id="policyTable"><thead><tr><th>State</th><th>Policy</th><th>Users and roles</th><th>Applications</th><th>Platforms</th><th>Locations</th><th>Client apps</th><th>Authentication</th><th>Grant controls</th><th>Session controls</th><th>Exclusions</th></tr></thead><tbody>
'@

    foreach ($policy in @($Report.ScenarioMatrix)) {
        switch ([string]$policy.State) {
            'enabled' { $stateLabel = 'Enabled'; $stateClass = 'enabled' }
            'enabledForReportingButNotEnforced' { $stateLabel = 'Report-only'; $stateClass = 'report' }
            'disabled' { $stateLabel = 'Disabled'; $stateClass = 'disabled' }
            default { $stateLabel = [string]$policy.State; $stateClass = 'disabled' }
        }
        $htmlParts += ('<tr data-policy-row data-state="{0}"><td><span class="badge {1}">{2}</span></td><td><div class="finding-title">{3}</div><span class="muted">{4}</span></td><td>{5}</td><td>{6}</td><td>{7}</td><td>{8}</td><td>{9}</td><td>{10}</td><td>{11}</td><td>{12}</td><td>{13}</td></tr>' -f
            (ConvertTo-HtmlText -Value $policy.State),
            $stateClass,
            (ConvertTo-HtmlText -Value $stateLabel),
            (ConvertTo-HtmlText -Value $policy.PolicyName),
            (ConvertTo-HtmlText -Value $policy.PolicyId),
            (ConvertTo-HtmlText -Value $policy.Users),
            (ConvertTo-HtmlText -Value $policy.Applications),
            (ConvertTo-HtmlText -Value $policy.Platforms),
            (ConvertTo-HtmlText -Value $policy.Locations),
            (ConvertTo-HtmlText -Value $policy.ClientAppTypes),
            (ConvertTo-HtmlText -Value $policy.AuthenticationStrength),
            (ConvertTo-HtmlText -Value $policy.GrantControls),
            (ConvertTo-HtmlText -Value $policy.SessionControls),
            (ConvertTo-HtmlText -Value $policy.Exclusions))
    }

    $htmlParts += @"
  </tbody></table></div>
</section>
<section class="section" id="interpretation">
  <h2>Interpretation and governance</h2>
  <div class="two-col">
    <div class="note-card"><h3>Emergency access</h3><p>Account IDs supplied: <strong>$($Report.EmergencyAccessAssessment.AccountObjectIdsSupplied.Count)</strong></p><p>Emergency group supplied: <strong>$([bool]$Report.EmergencyAccessAssessment.GroupObjectIdSupplied)</strong></p><p class="muted">$(ConvertTo-HtmlText -Value $Report.EmergencyAccessAssessment.ImportantLimitation)</p></div>
    <div class="note-card"><h3>Inventory</h3><p>Named locations: <strong>$($Report.Summary.NamedLocationCount)</strong></p><p>Authentication strengths: <strong>$($Report.Summary.AuthenticationStrengthCount)</strong></p><p class="muted">Use the JSON report for the complete machine-readable inventory and raw arrays.</p></div>
    <div class="note-card"><h3>Important boundaries</h3><ul>
"@
    foreach ($note in @($Report.AnalysisNotes)) {
        $htmlParts += ('<li>{0}</li>' -f (ConvertTo-HtmlText -Value $note))
    }
    $htmlParts += @'
    </ul></div>
    <div class="note-card"><h3>Management review sequence</h3><ol><li>Assign Critical and High findings.</li><li>Confirm policy intent with owners.</li><li>Validate exclusions and emergency access.</li><li>Test proposed changes in report-only mode.</li><li>Use peer review, change control and rollback planning.</li></ol></div>
  </div>
</section>
</main>
<footer class="footer"><strong>RuleRivet</strong> · Conditional Access Coverage Matrix · Read-only configuration analysis</footer>
<script>
function filterPolicies(){const q=document.getElementById('policySearch').value.toLowerCase();const state=document.getElementById('policyState').value;document.querySelectorAll('[data-policy-row]').forEach(function(row){const text=row.innerText.toLowerCase();const okText=!q||text.indexOf(q)!==-1;const okState=!state||row.dataset.state===state;row.style.display=okText&&okState?'':'none';});}
function filterFindings(){const q=document.getElementById('findingSearch').value.toLowerCase();const severity=document.getElementById('findingSeverity').value;document.querySelectorAll('[data-finding-row]').forEach(function(row){const text=row.innerText.toLowerCase();const okText=!q||text.indexOf(q)!==-1;const okSeverity=!severity||row.dataset.severity===severity;row.style.display=okText&&okSeverity?'':'none';});}
</script>
</body>
</html>
'@

    $parentPath = Split-Path -Path $Path -Parent
    if ($parentPath -and -not (Test-Path -LiteralPath $parentPath)) {
        New-Item -ItemType Directory -Path $parentPath -Force | Out-Null
    }
    [System.IO.File]::WriteAllText($Path, ($htmlParts -join [Environment]::NewLine), (New-Object System.Text.UTF8Encoding($false)))
    return (Resolve-Path -LiteralPath $Path).Path
}

function Test-PolicyRestrictsAccess {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Policy)

    if ([string](Get-PropertyValue -Object $Policy -Name 'State') -ne 'enabled') { return $false }
    if ([string](Get-PropertyValue -Object $Policy -Name 'GrantControls') -ne 'None') { return $true }
    if ([string](Get-PropertyValue -Object $Policy -Name 'SessionControls') -ne 'None') { return $true }
    return $false
}

function New-Finding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][ValidateSet('Critical','High','Medium','Low','Information')][string]$Severity,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Evidence,
        [Parameter(Mandatory)][string]$Recommendation,
        [Parameter()][string[]]$PolicyIds = @(),
        [Parameter()][ValidateSet('High','Medium','Low')][string]$Confidence = 'High'
    )

    return [pscustomobject][ordered]@{
        FindingId     = $null
        Category      = $Category
        Severity      = $Severity
        Title         = $Title
        Evidence      = $Evidence
        Recommendation = $Recommendation
        PolicyIds     = @($PolicyIds)
        Confidence    = $Confidence
    }
}

function ConvertTo-ScenarioRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Policy,
        [Parameter(Mandatory)][hashtable]$LocationMap
    )

    $conditions = Get-PropertyValue -Object $Policy -Name 'conditions'
    $users = Get-PropertyValue -Object $conditions -Name 'users'
    $applications = Get-PropertyValue -Object $conditions -Name 'applications'
    $platforms = Get-PropertyValue -Object $conditions -Name 'platforms'
    $locations = Get-PropertyValue -Object $conditions -Name 'locations'
    $devices = Get-PropertyValue -Object $conditions -Name 'devices'
    $grantControls = Get-PropertyValue -Object $Policy -Name 'grantControls'
    $sessionControls = Get-PropertyValue -Object $Policy -Name 'sessionControls'

    $includeUsers = @(Get-Array -Value (Get-PropertyValue -Object $users -Name 'includeUsers' -Default @()))
    $excludeUsers = @(Get-Array -Value (Get-PropertyValue -Object $users -Name 'excludeUsers' -Default @()))
    $includeGroups = @(Get-Array -Value (Get-PropertyValue -Object $users -Name 'includeGroups' -Default @()))
    $excludeGroups = @(Get-Array -Value (Get-PropertyValue -Object $users -Name 'excludeGroups' -Default @()))
    $includeRoles = @(Get-Array -Value (Get-PropertyValue -Object $users -Name 'includeRoles' -Default @()))
    $excludeRoles = @(Get-Array -Value (Get-PropertyValue -Object $users -Name 'excludeRoles' -Default @()))
    $includeApps = @(Get-Array -Value (Get-PropertyValue -Object $applications -Name 'includeApplications' -Default @()))
    $excludeApps = @(Get-Array -Value (Get-PropertyValue -Object $applications -Name 'excludeApplications' -Default @()))
    $includePlatforms = @(Get-Array -Value (Get-PropertyValue -Object $platforms -Name 'includePlatforms' -Default @()))
    $excludePlatforms = @(Get-Array -Value (Get-PropertyValue -Object $platforms -Name 'excludePlatforms' -Default @()))
    $includeLocations = @(Get-Array -Value (Get-PropertyValue -Object $locations -Name 'includeLocations' -Default @()))
    $excludeLocations = @(Get-Array -Value (Get-PropertyValue -Object $locations -Name 'excludeLocations' -Default @()))
    $clientApps = @(Get-Array -Value (Get-PropertyValue -Object $conditions -Name 'clientAppTypes' -Default @()))
    $builtInControls = @(Get-Array -Value (Get-PropertyValue -Object $grantControls -Name 'builtInControls' -Default @()))
    $authenticationStrength = Get-PropertyValue -Object $grantControls -Name 'authenticationStrength'
    $deviceFilter = Get-PropertyValue -Object $devices -Name 'deviceFilter'
    $applicationFilter = Get-PropertyValue -Object $applications -Name 'applicationFilter'

    $userParts = @()
    if ($includeUsers.Count -gt 0) { $userParts += ("Users: {0}" -f (Join-DisplayValue $includeUsers)) }
    if ($includeGroups.Count -gt 0) { $userParts += ("Groups: {0}" -f (Join-DisplayValue $includeGroups)) }
    if ($includeRoles.Count -gt 0) { $userParts += ("Roles: {0}" -f (Join-DisplayValue $includeRoles)) }
    if ($null -ne (Get-PropertyValue -Object $users -Name 'includeGuestsOrExternalUsers')) { $userParts += 'Guests/external users: configured' }
    if ($userParts.Count -eq 0) { $userParts += 'No user target' }

    $excludeParts = @()
    if ($excludeUsers.Count -gt 0) { $excludeParts += ("Users: {0}" -f (Join-DisplayValue $excludeUsers)) }
    if ($excludeGroups.Count -gt 0) { $excludeParts += ("Groups: {0}" -f (Join-DisplayValue $excludeGroups)) }
    if ($excludeRoles.Count -gt 0) { $excludeParts += ("Roles: {0}" -f (Join-DisplayValue $excludeRoles)) }
    if ($excludeApps.Count -gt 0) { $excludeParts += ("Apps: {0}" -f (Join-DisplayValue $excludeApps)) }
    if ($excludePlatforms.Count -gt 0) { $excludeParts += ("Platforms: {0}" -f (Join-DisplayValue $excludePlatforms)) }
    if ($excludeLocations.Count -gt 0) { $excludeParts += ("Locations: {0}" -f (Join-DisplayValue (Resolve-LocationList -Ids $excludeLocations -LocationMap $LocationMap))) }
    if ($excludeParts.Count -eq 0) { $excludeParts += 'None' }

    $scenarioSignature = @(
        ("U={0}" -f (ConvertTo-StableListText $includeUsers)),
        ("G={0}" -f (ConvertTo-StableListText $includeGroups)),
        ("R={0}" -f (ConvertTo-StableListText $includeRoles)),
        ("A={0}" -f (ConvertTo-StableListText $includeApps)),
        ("P={0}" -f (ConvertTo-StableListText $includePlatforms)),
        ("L={0}" -f (ConvertTo-StableListText $includeLocations)),
        ("C={0}" -f (ConvertTo-StableListText $clientApps)),
        ("UR={0}" -f (ConvertTo-StableListText (Get-PropertyValue -Object $conditions -Name 'userRiskLevels' -Default @()))),
        ("SR={0}" -f (ConvertTo-StableListText (Get-PropertyValue -Object $conditions -Name 'signInRiskLevels' -Default @()))),
        ("DF={0}" -f ([string](Get-PropertyValue -Object $deviceFilter -Name 'rule' -Default '*'))),
        ("AF={0}" -f ([string](Get-PropertyValue -Object $applicationFilter -Name 'rule' -Default '*')))
    ) -join ';'

    return [pscustomobject][ordered]@{
        PolicyId               = [string](Get-PropertyValue -Object $Policy -Name 'id')
        PolicyName             = [string](Get-PropertyValue -Object $Policy -Name 'displayName')
        State                  = [string](Get-PropertyValue -Object $Policy -Name 'state')
        CreatedDateTime        = Get-PropertyValue -Object $Policy -Name 'createdDateTime'
        ModifiedDateTime       = Get-PropertyValue -Object $Policy -Name 'modifiedDateTime'
        Users                  = (@($userParts) -join '; ')
        Applications           = Join-DisplayValue -Value $includeApps -EmptyText 'No application target'
        UserActions            = Join-DisplayValue -Value (Get-PropertyValue -Object $applications -Name 'includeUserActions' -Default @()) -EmptyText 'None'
        AuthenticationContexts = Join-DisplayValue -Value (Get-PropertyValue -Object $applications -Name 'includeAuthenticationContextClassReferences' -Default @()) -EmptyText 'None'
        Platforms              = Join-DisplayValue -Value $includePlatforms
        Locations              = Join-DisplayValue -Value (Resolve-LocationList -Ids $includeLocations -LocationMap $LocationMap)
        ClientAppTypes         = Join-DisplayValue -Value $clientApps
        ClientAppTypesRaw      = @($clientApps)
        UserRiskLevels         = Join-DisplayValue -Value (Get-PropertyValue -Object $conditions -Name 'userRiskLevels' -Default @())
        SignInRiskLevels       = Join-DisplayValue -Value (Get-PropertyValue -Object $conditions -Name 'signInRiskLevels' -Default @())
        ServicePrincipalRiskLevels = Join-DisplayValue -Value (Get-PropertyValue -Object $conditions -Name 'servicePrincipalRiskLevels' -Default @())
        DeviceFilter           = if ($null -eq $deviceFilter) { 'None' } else { "{0}: {1}" -f (Get-PropertyValue -Object $deviceFilter -Name 'mode' -Default 'configured'), (Get-PropertyValue -Object $deviceFilter -Name 'rule' -Default '') }
        ApplicationFilter      = if ($null -eq $applicationFilter) { 'None' } else { "{0}: {1}" -f (Get-PropertyValue -Object $applicationFilter -Name 'mode' -Default 'configured'), (Get-PropertyValue -Object $applicationFilter -Name 'rule' -Default '') }
        AuthenticationStrength = if ($null -eq $authenticationStrength) { 'None' } else { [string](Get-PropertyValue -Object $authenticationStrength -Name 'displayName' -Default (Get-PropertyValue -Object $authenticationStrength -Name 'id' -Default 'Configured')) }
        GrantControls          = Format-GrantControls -GrantControls $grantControls
        SessionControls        = Format-SessionControls -SessionControls $sessionControls
        Exclusions             = (@($excludeParts) -join '; ')
        IncludeUsers           = @($includeUsers)
        ExcludeUsers           = @($excludeUsers)
        IncludeGroups          = @($includeGroups)
        ExcludeGroups          = @($excludeGroups)
        IncludeRoles           = @($includeRoles)
        ExcludeRoles           = @($excludeRoles)
        IncludeApplications    = @($includeApps)
        ExcludeApplications    = @($excludeApps)
        IncludePlatforms       = @($includePlatforms)
        ExcludePlatforms       = @($excludePlatforms)
        IncludeLocations       = @($includeLocations)
        ExcludeLocations       = @($excludeLocations)
        BuiltInGrantControls   = @($builtInControls)
        ScenarioSignature      = $scenarioSignature
    }
}

function Get-CoverageFindings {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Matrix,
        [Parameter()][string[]]$EmergencyAccountIds = @(),
        [Parameter()][string]$EmergencyGroupId
    )

    $findings = @()
    $enabled = @($Matrix | Where-Object { $_.State -eq 'enabled' })
    $reportOnly = @($Matrix | Where-Object { $_.State -eq 'enabledForReportingButNotEnforced' })

    if ($enabled.Count -eq 0) {
        $findings += (New-Finding -Category 'Gap' -Severity Critical -Title 'No enabled Conditional Access policies were found' -Evidence ("{0} report-only and {1} disabled policy rows were read." -f $reportOnly.Count, (@($Matrix | Where-Object State -eq 'disabled')).Count) -Recommendation 'Confirm the tenant and permissions, then enable a tested baseline through the normal change process.')
    }

    $allUserAllApp = @($enabled | Where-Object {
        (Test-ContainsValue $_.IncludeUsers 'All') -and
        (Test-ContainsValue $_.IncludeApplications 'All')
    })
    if ($allUserAllApp.Count -eq 0) {
        $findings += (New-Finding -Category 'Gap' -Severity High -Title 'No enabled broad all-users and all-apps baseline was detected' -Evidence 'No enabled policy includes both the All users token and the All applications token.' -Recommendation 'Review whether the intended baseline is split across scoped policies. If it is not, design and test a broad baseline with controlled exclusions.' -Confidence Medium)
    }

    $mfaPolicies = @($enabled | Where-Object {
        (Test-ContainsValue $_.BuiltInGrantControls 'mfa') -or $_.AuthenticationStrength -ne 'None'
    })
    if ($mfaPolicies.Count -eq 0) {
        $findings += (New-Finding -Category 'Gap' -Severity High -Title 'No enabled MFA or authentication-strength control was detected' -Evidence 'No enabled policy uses the mfa built-in grant control or an authentication strength.' -Recommendation 'Confirm whether MFA is enforced by Conditional Access. Design and test an appropriate authentication control if it is absent.')
    }

    $legacyBlock = @($enabled | Where-Object {
        (Test-ContainsValue $_.BuiltInGrantControls 'block') -and
        ((Test-ContainsValue $_.ClientAppTypesRaw 'exchangeActiveSync') -or
         (Test-ContainsValue $_.ClientAppTypesRaw 'other') -or
         (Test-ContainsValue $_.ClientAppTypesRaw 'otherClients'))
    })
    if ($legacyBlock.Count -eq 0) {
        $findings += (New-Finding -Category 'Gap' -Severity High -Title 'No enabled legacy-authentication block was detected' -Evidence 'No enabled block policy targets Exchange ActiveSync, other, or otherClients client app types.' -Recommendation 'Confirm the tenant does not rely on legacy authentication. Create a report-only block policy, review sign-in impact, then enable it.' -Confidence Medium)
    }

    $adminMfa = @($mfaPolicies | Where-Object { $_.IncludeRoles.Count -gt 0 })
    if ($adminMfa.Count -eq 0) {
        $findings += (New-Finding -Category 'Gap' -Severity High -Title 'No enabled administrator-role MFA policy was detected' -Evidence 'No enabled MFA or authentication-strength policy includes directory role template IDs.' -Recommendation 'Confirm whether privileged users are covered through an all-users policy. If not, design a dedicated privileged-role policy.' -Confidence Medium)
    }

    foreach ($policy in $enabled) {
        $totalExclusions = $policy.ExcludeUsers.Count + $policy.ExcludeGroups.Count + $policy.ExcludeRoles.Count + $policy.ExcludeApplications.Count + $policy.ExcludePlatforms.Count + $policy.ExcludeLocations.Count
        if ($totalExclusions -ge 5) {
            $findings += (New-Finding -Category 'BroadExclusion' -Severity Medium -Title ("Policy has a large exclusion surface: {0}" -f $policy.PolicyName) -Evidence ("The policy contains {0} direct exclusion entries across users, groups, roles, applications, platforms and locations." -f $totalExclusions) -Recommendation 'Review every exclusion, its owner and expiry date. Prefer narrowly scoped, time-bound exception groups.' -PolicyIds @($policy.PolicyId) -Confidence High)
        }
        if ((Test-ContainsValue $policy.ExcludeApplications 'All') -or (Test-ContainsValue $policy.ExcludeUsers 'All')) {
            $findings += (New-Finding -Category 'Contradiction' -Severity High -Title ("Policy contains an All exclusion token: {0}" -f $policy.PolicyName) -Evidence 'The policy excludes All users or All applications, which can make the intended scope ineffective or misleading.' -Recommendation 'Review the policy scope in the Entra admin center and correct the include and exclude design.' -PolicyIds @($policy.PolicyId) -Confidence High)
        }
    }

    $signatureGroups = @($enabled | Group-Object -Property ScenarioSignature | Where-Object Count -gt 1)
    foreach ($group in $signatureGroups) {
        $policies = @($group.Group)
        $policyNames = @($policies | ForEach-Object PolicyName)
        $findings += (New-Finding -Category 'Overlap' -Severity Medium -Title 'Multiple enabled policies have the same normalised scenario scope' -Evidence ("Policies: {0}. Their normalised include scope, risks, filters and client types match; exclusions and controls can still differ." -f ($policyNames -join '; ')) -Recommendation 'Confirm that the split is intentional. Document control composition and remove redundant policies after impact testing.' -PolicyIds @($policies | ForEach-Object PolicyId) -Confidence High)

        $hasBlock = @($policies | Where-Object { Test-ContainsValue $_.BuiltInGrantControls 'block' }).Count -gt 0
        $hasGrant = @($policies | Where-Object { $_.BuiltInGrantControls.Count -gt 0 -and -not (Test-ContainsValue $_.BuiltInGrantControls 'block') }).Count -gt 0
        if ($hasBlock -and $hasGrant) {
            $findings += (New-Finding -Category 'Contradiction' -Severity High -Title 'Equivalent enabled scopes contain both block and grant controls' -Evidence ("Policies with the same normalised scenario include both a block policy and a non-block grant policy: {0}. When multiple policies apply, a block result takes precedence." -f ($policyNames -join '; ')) -Recommendation 'Check exclusions and filters, then consolidate or clearly separate the scopes so the effective result is unambiguous.' -PolicyIds @($policies | ForEach-Object PolicyId) -Confidence High)
        }

        $persistentModes = @($policies | ForEach-Object { if ($_.SessionControls -match 'Persistent browser: ([^;]+)') { $matches[1] } } | Sort-Object -Unique)
        if ($persistentModes.Count -gt 1) {
            $findings += (New-Finding -Category 'Contradiction' -Severity Medium -Title 'Equivalent enabled scopes configure different persistent-browser modes' -Evidence ("The same normalised scenario includes these modes: {0}." -f ($persistentModes -join ', ')) -Recommendation 'Review effective session behavior and align the policies unless the difference is intentional.' -PolicyIds @($policies | ForEach-Object PolicyId) -Confidence High)
        }
    }

    if ($EmergencyAccountIds.Count -eq 0 -and -not $EmergencyGroupId) {
        $findings += (New-Finding -Category 'EmergencyAccess' -Severity Medium -Title 'Emergency-access coverage was not fully validated' -Evidence 'No emergency-access account object IDs or emergency-access group object ID were supplied to the script.' -Recommendation 'Re-run with at least two emergency-access account object IDs and, if used, the dedicated emergency-access group object ID.' -Confidence High)
    }
    else {
        if ($EmergencyAccountIds.Count -lt 2) {
            $findings += (New-Finding -Category 'EmergencyAccess' -Severity High -Title 'Fewer than two emergency-access account IDs were supplied' -Evidence ("The script received {0} emergency-access account object ID(s)." -f $EmergencyAccountIds.Count) -Recommendation 'Microsoft recommends at least two cloud-only emergency-access accounts for redundancy.' -Confidence High)
        }

        foreach ($accountId in $EmergencyAccountIds) {
            $affectingPolicies = @()
            foreach ($policy in $enabled) {
                if (-not (Test-PolicyRestrictsAccess -Policy $policy)) { continue }
                $directlyIncluded = Test-ContainsValue $policy.IncludeUsers $accountId
                $allUsers = Test-ContainsValue $policy.IncludeUsers 'All'
                $directlyExcluded = Test-ContainsValue $policy.ExcludeUsers $accountId
                $groupExcluded = $false
                if ($EmergencyGroupId) { $groupExcluded = Test-ContainsValue $policy.ExcludeGroups $EmergencyGroupId }
                if (($allUsers -or $directlyIncluded) -and -not $directlyExcluded -and -not $groupExcluded) {
                    $affectingPolicies += $policy
                }
            }
            foreach ($policy in @($affectingPolicies)) {
                $findings += (New-Finding -Category 'EmergencyAccess' -Severity Critical -Title ("Emergency-access account may be restricted by {0}" -f $policy.PolicyName) -Evidence ("Account object ID {0} is directly included or falls under All users and is not directly excluded{1}. Group membership is not expanded by this script." -f $accountId, $(if ($EmergencyGroupId) { ' through the supplied emergency-access group' } else { '' })) -Recommendation 'Validate the account and group membership, then exclude the emergency-access identity from this restrictive policy if that matches the approved design.' -PolicyIds @($policy.PolicyId) -Confidence Medium)
            }
        }

        if ($EmergencyGroupId) {
            foreach ($policy in $enabled) {
                if ((Test-PolicyRestrictsAccess -Policy $policy) -and (Test-ContainsValue $policy.IncludeUsers 'All') -and -not (Test-ContainsValue $policy.ExcludeGroups $EmergencyGroupId)) {
                    $findings += (New-Finding -Category 'EmergencyAccess' -Severity High -Title ("Emergency-access group is not excluded from restrictive all-user policy: {0}" -f $policy.PolicyName) -Evidence ("The supplied emergency-access group ID {0} is not in the policy's excluded groups." -f $EmergencyGroupId) -Recommendation 'Confirm whether the policy is intended to restrict emergency access. If not, add the approved emergency-access group exclusion through change control.' -PolicyIds @($policy.PolicyId) -Confidence High)
                }
            }
        }
    }

    $order = @{ Critical = 1; High = 2; Medium = 3; Low = 4; Information = 5 }
    $sorted = @($findings | Sort-Object @{ Expression = { $order[$_.Severity] } }, Category, Title)
    for ($index = 0; $index -lt $sorted.Count; $index++) {
        $sorted[$index].FindingId = 'CA-{0:d3}' -f ($index + 1)
    }
    return $sorted
}

function Get-SeverityCounts {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object[]]$Findings)

    $result = [ordered]@{ Critical = 0; High = 0; Medium = 0; Low = 0; Information = 0 }
    foreach ($finding in $Findings) {
        if ($result.Contains($finding.Severity)) { $result[$finding.Severity]++ }
    }
    return [pscustomobject]$result
}

$report = $null
$runStarted = (Get-Date).ToUniversalTime()

try {
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        throw 'Microsoft.Graph.Authentication is not installed. Run: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser'
    }
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

    $context = Get-MgContext
    if ($null -eq $context) {
        $connectParameters = @{ Scopes = @('Policy.Read.All'); ContextScope = 'Process'; NoWelcome = $true; ErrorAction = 'Stop' }
        if ($TenantId) { $connectParameters['TenantId'] = $TenantId }
        if ($UseDeviceCode) { $connectParameters['UseDeviceAuthentication'] = $true }
        Write-Verbose 'Connecting to Microsoft Graph with delegated Policy.Read.All permission.'
        Connect-MgGraph @connectParameters | Out-Null
        $script:ConnectedByScript = $true
        $context = Get-MgContext
    }
    elseif (-not (Test-ContainsValue $context.Scopes 'Policy.Read.All')) {
        throw 'The current Microsoft Graph context does not include Policy.Read.All. Disconnect and reconnect with the required scope, or run this script in a fresh PowerShell process.'
    }

    Add-Diagnostic -Level Information -Stage 'Authentication' -Message ("Connected to tenant {0} as {1}." -f $context.TenantId, $context.Account)

    $policies = @(Invoke-GraphGetAll -Uri ("{0}/identity/conditionalAccess/policies" -f $script:GraphBaseUri) -Stage 'ReadPolicies')
    $namedLocations = @(Invoke-GraphGetAll -Uri ("{0}/identity/conditionalAccess/namedLocations" -f $script:GraphBaseUri) -Stage 'ReadNamedLocations')
    $authenticationStrengths = @()
    if (-not $SkipAuthenticationStrengthInventory) {
        try {
            $authenticationStrengths = @(Invoke-GraphGetAll -Uri ("{0}/policies/authenticationStrengthPolicies" -f $script:GraphBaseUri) -Stage 'ReadAuthenticationStrengths')
        }
        catch {
            Add-Diagnostic -Level Warning -Stage 'ReadAuthenticationStrengths' -Message 'Authentication-strength inventory could not be read. Policy-embedded strength names will still be reported.' -Detail $_.Exception.Message
        }
    }

    $locationMap = @{}
    foreach ($location in $namedLocations) {
        $locationMap[[string]$location.id] = [string]$location.displayName
    }

    $matrix = @()
    foreach ($policy in $policies) {
        try {
            $matrix += (ConvertTo-ScenarioRow -Policy $policy -LocationMap $locationMap)
        }
        catch {
            Add-Diagnostic -Level Error -Stage 'NormalisePolicy' -Message ("Policy could not be normalised: {0}" -f (Get-PropertyValue -Object $policy -Name 'displayName' -Default (Get-PropertyValue -Object $policy -Name 'id' -Default 'Unknown'))) -Detail $_.Exception.Message
        }
    }

    $matrixArray = @($matrix | Sort-Object PolicyName)
    $findings = @(Get-CoverageFindings -Matrix $matrixArray -EmergencyAccountIds $EmergencyAccessAccountObjectId -EmergencyGroupId $EmergencyAccessGroupObjectId)
    $severityCounts = Get-SeverityCounts -Findings $findings

    $locationInventory = @($namedLocations | ForEach-Object {
        [pscustomobject][ordered]@{
            Id = [string]$_.id
            DisplayName = [string]$_.displayName
            Type = [string](Get-PropertyValue -Object $_ -Name '@odata.type' -Default 'namedLocation')
            IsTrusted = Get-PropertyValue -Object $_ -Name 'isTrusted'
            CountriesAndRegions = @(Get-Array -Value (Get-PropertyValue -Object $_ -Name 'countriesAndRegions' -Default @()))
            IpRanges = @((Get-Array -Value (Get-PropertyValue -Object $_ -Name 'ipRanges' -Default @())) | ForEach-Object { Get-PropertyValue -Object $_ -Name 'cidrAddress' })
        }
    })

    $strengthInventory = @($authenticationStrengths | ForEach-Object {
        [pscustomobject][ordered]@{
            Id = [string]$_.id
            DisplayName = [string](Get-PropertyValue -Object $_ -Name 'displayName' -Default (Get-PropertyValue -Object $_ -Name 'policyName' -Default 'Unknown'))
            PolicyType = [string](Get-PropertyValue -Object $_ -Name 'policyType')
            RequirementsSatisfied = [string](Get-PropertyValue -Object $_ -Name 'requirementsSatisfied')
            AllowedCombinations = @(Get-Array -Value (Get-PropertyValue -Object $_ -Name 'allowedCombinations' -Default @()))
        }
    })

    if (-not $HtmlOutputPath) {
        $HtmlOutputPath = [System.IO.Path]::ChangeExtension($OutputPath, '.html')
    }
    $jsonFullPath = [System.IO.Path]::GetFullPath($OutputPath)
    $htmlFullPath = [System.IO.Path]::GetFullPath($HtmlOutputPath)

    $reportData = [ordered]@{
        SchemaVersion = '1.0'
        Tool = [ordered]@{
            Name = $script:ToolName
            Version = $script:ToolVersion
            ReadOnly = $true
            GraphApiVersion = 'v1.0'
        }
        Run = [ordered]@{
            StartedUtc = $runStarted.ToString('o')
            CompletedUtc = (Get-Date).ToUniversalTime().ToString('o')
            TenantId = [string]$context.TenantId
            Account = [string]$context.Account
            PowerShellVersion = $PSVersionTable.PSVersion.ToString()
            ComputerName = [Environment]::MachineName
            Parameters = [ordered]@{
                EmergencyAccessAccountCount = $EmergencyAccessAccountObjectId.Count
                EmergencyAccessGroupSupplied = [bool]$EmergencyAccessGroupObjectId
                AuthenticationStrengthInventorySkipped = [bool]$SkipAuthenticationStrengthInventory
                RawPoliciesIncluded = [bool]$IncludeRawPolicies
                HtmlReportSkipped = [bool]$SkipHtmlReport
            }
        }
        Outputs = [ordered]@{
            JsonPath = $jsonFullPath
            HtmlPath = if ($SkipHtmlReport) { $null } else { $htmlFullPath }
        }
        Summary = [ordered]@{
            PolicyCount = $matrixArray.Count
            EnabledPolicyCount = @($matrixArray | Where-Object State -eq 'enabled').Count
            ReportOnlyPolicyCount = @($matrixArray | Where-Object State -eq 'enabledForReportingButNotEnforced').Count
            DisabledPolicyCount = @($matrixArray | Where-Object State -eq 'disabled').Count
            NamedLocationCount = $locationInventory.Count
            AuthenticationStrengthCount = $strengthInventory.Count
            FindingCount = $findings.Count
            FindingsBySeverity = $severityCounts
        }
        ScenarioMatrix = $matrixArray
        Findings = $findings
        Inventory = [ordered]@{
            NamedLocations = $locationInventory
            AuthenticationStrengths = $strengthInventory
        }
        EmergencyAccessAssessment = [ordered]@{
            AccountObjectIdsSupplied = @($EmergencyAccessAccountObjectId)
            GroupObjectIdSupplied = $EmergencyAccessGroupObjectId
            ImportantLimitation = 'The script does not expand group membership. Supply account IDs and the dedicated emergency-access group ID for the strongest available check.'
        }
        Diagnostics = @($script:Diagnostics)
        AnalysisNotes = @(
            'This is a static configuration analysis, not a sign-in simulation.',
            'A gap finding means the expected pattern was not detected; it does not prove that access is unprotected.',
            'Overlap checks compare normalised include scope, risks and filters. Exclusions and controls are reported separately.',
            'Microsoft Entra evaluates all applicable enabled policies. A block control takes precedence when applicable.',
            'Report-only and disabled policies are listed in the matrix but are not treated as enforced coverage.'
        )
    }
    if ($IncludeRawPolicies) { $reportData['RawPolicies'] = $policies }
    $report = [pscustomobject]$reportData

    $resolvedHtmlPath = $null
    if (-not $SkipHtmlReport) {
        try {
            $resolvedHtmlPath = New-ConditionalAccessHtmlReport -Report $report -Path $HtmlOutputPath
        }
        catch {
            Add-Diagnostic -Level Warning -Stage 'WriteHtmlReport' -Message 'The JSON analysis completed, but the management HTML report could not be written.' -Detail $_.Exception.Message
            $report.Diagnostics = @($script:Diagnostics)
        }
    }

    $parentPath = Split-Path -Path $OutputPath -Parent
    if ($parentPath -and -not (Test-Path -LiteralPath $parentPath)) {
        New-Item -ItemType Directory -Path $parentPath -Force | Out-Null
    }
    $json = $report | ConvertTo-Json -Depth 30
    [System.IO.File]::WriteAllText($OutputPath, $json, (New-Object System.Text.UTF8Encoding($false)))

    Write-Host ''
    Write-Host $script:ToolName -ForegroundColor Cyan
    Write-Host ("Policies: {0} total, {1} enabled, {2} report-only, {3} disabled" -f $report.Summary.PolicyCount, $report.Summary.EnabledPolicyCount, $report.Summary.ReportOnlyPolicyCount, $report.Summary.DisabledPolicyCount)
    Write-Host ("Findings: {0} critical, {1} high, {2} medium, {3} low" -f $severityCounts.Critical, $severityCounts.High, $severityCounts.Medium, $severityCounts.Low)
    Write-Host ("JSON: {0}" -f (Resolve-Path -LiteralPath $OutputPath).Path) -ForegroundColor Green
    if ($resolvedHtmlPath) { Write-Host ("HTML: {0}" -f $resolvedHtmlPath) -ForegroundColor Green }

    if ($PassThru) { Write-Output $report }
}
catch {
    Add-Diagnostic -Level Error -Stage 'Fatal' -Message 'The Conditional Access analysis did not complete.' -Detail $_.Exception.Message
    $failure = [pscustomobject][ordered]@{
        SchemaVersion = '1.0'
        Tool = [ordered]@{ Name = $script:ToolName; Version = $script:ToolVersion; ReadOnly = $true }
        Run = [ordered]@{ StartedUtc = $runStarted.ToString('o'); FailedUtc = (Get-Date).ToUniversalTime().ToString('o') }
        Status = 'Failed'
        Error = $_.Exception.Message
        Diagnostics = @($script:Diagnostics)
    }
    try {
        $parentPath = Split-Path -Path $OutputPath -Parent
        if ($parentPath -and -not (Test-Path -LiteralPath $parentPath)) { New-Item -ItemType Directory -Path $parentPath -Force | Out-Null }
        [System.IO.File]::WriteAllText($OutputPath, ($failure | ConvertTo-Json -Depth 10), (New-Object System.Text.UTF8Encoding($false)))
        Write-Warning ("A failure report was written to {0}" -f $OutputPath)
    }
    catch {
        Write-Warning 'The failure report could not be written.'
    }
    throw
}
finally {
    if ($script:ConnectedByScript -and -not $NoDisconnect) {
        try { Disconnect-MgGraph | Out-Null } catch { Write-Verbose 'Microsoft Graph disconnect failed; the process-scoped session will end with this PowerShell process.' }
    }
}
