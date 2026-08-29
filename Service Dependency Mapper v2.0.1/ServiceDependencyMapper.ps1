#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$OutputFolder = (Join-Path $PSScriptRoot 'Reports'),
    [switch]$NoGui,
    [switch]$RunningServicesOnly,
    [switch]$OpenReport
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:SdmVersion = '2.0.1'

function ConvertTo-SdmHtmlText {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Protect-SdmText {
    param([AllowNull()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return $Text }
    $protected = $Text
    foreach ($pattern in @(
        '(?i)(password|pwd|passwd)\s*[:=]\s*([^\s;]+)',
        '(?i)(token|secret|api[_-]?key)\s*[:=]\s*([^\s;]+)',
        '(?i)((?:--?|/)(?:password|pwd|token|secret|api[_-]?key))\s+([^\s;]+)'
    )) {
        $protected = [regex]::Replace($protected, $pattern, '$1=<redacted>')
    }
    return $protected
}

function Test-SdmAdministrator {
    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Format-SdmEndpoint {
    param(
        [AllowNull()][string]$Address,
        [int]$Port
    )

    if ($Address -match ':') { return "[$Address]:$Port" }
    return "$Address`:$Port"
}

function Get-SdmServiceInventory {
    param([switch]$RunningOnly)

    $controllers = @{}
    foreach ($controller in @(Get-Service -ErrorAction SilentlyContinue)) {
        $controllers[[string]$controller.Name] = $controller
    }

    $cimServices = @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)
    $items = foreach ($service in @($cimServices | Sort-Object DisplayName, Name)) {
        if ($RunningOnly -and [string]$service.State -ne 'Running') { continue }

        $dependencies = @()
        $dependents = @()
        if ($controllers.ContainsKey([string]$service.Name)) {
            try {
                $dependencies = @($controllers[[string]$service.Name].ServicesDependedOn |
                    ForEach-Object { [string]$_.Name } |
                    Sort-Object -Unique)
            }
            catch { $dependencies = @() }
            try {
                $dependents = @($controllers[[string]$service.Name].DependentServices |
                    ForEach-Object { [string]$_.Name } |
                    Sort-Object -Unique)
            }
            catch { $dependents = @() }
        }

        [pscustomobject]@{
            Name         = [string]$service.Name
            DisplayName  = [string]$service.DisplayName
            State        = [string]$service.State
            StartMode    = [string]$service.StartMode
            StartName    = [string]$service.StartName
            ProcessId    = [int]$service.ProcessId
            PathName     = Protect-SdmText ([string]$service.PathName)
            Description  = [string]$service.Description
            Dependencies = @($dependencies)
            Dependents   = @($dependents)
        }
    }

    return @($items)
}

function Get-SdmNetworkSnapshot {
    $warnings = @()
    $connections = @()
    $localAddresses = @('127.0.0.1', '::1')

    if (-not (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue)) {
        $warnings += 'Get-NetTCPConnection is unavailable. The report contains service-control dependencies but no TCP relationships.'
        return [pscustomobject]@{
            Connections   = @()
            LocalAddresses = @($localAddresses)
            Warnings      = @($warnings)
        }
    }

    try {
        $connections = @(Get-NetTCPConnection -ErrorAction Stop)
    }
    catch {
        $warnings += "TCP collection failed: $($_.Exception.Message)"
    }

    try {
        if (Get-Command Get-NetIPAddress -ErrorAction SilentlyContinue) {
            $localAddresses += @(Get-NetIPAddress -AddressFamily @('IPv4', 'IPv6') -ErrorAction Stop |
                Where-Object { $_.IPAddress } |
                ForEach-Object { [string]$_.IPAddress })
        }
        else {
            $localAddresses += @([System.Net.Dns]::GetHostAddresses($env:COMPUTERNAME) |
                ForEach-Object { $_.IPAddressToString })
        }
    }
    catch {
        $warnings += 'Local IP enumeration was incomplete; loopback addresses are still recognised.'
    }

    return [pscustomobject]@{
        Connections    = @($connections)
        LocalAddresses = @($localAddresses | Where-Object { $_ } | Sort-Object -Unique)
        Warnings       = @($warnings)
    }
}

function New-SdmRelationships {
    param(
        [Parameter(Mandatory)][object[]]$Services,
        [Parameter(Mandatory)][object]$NetworkSnapshot
    )

    $serviceIndex = @{}
    $pidServices = @{}
    foreach ($service in $Services) {
        $serviceIndex[[string]$service.Name] = $service
        if ([int]$service.ProcessId -gt 0) {
            $serviceProcessId = [int]$service.ProcessId
            if (-not $pidServices.ContainsKey($serviceProcessId)) { $pidServices[$serviceProcessId] = @() }
            $pidServices[$serviceProcessId] = @($pidServices[$serviceProcessId]) + @([string]$service.Name)
        }
    }

    $listenerByPort = @{}
    foreach ($connection in @($NetworkSnapshot.Connections | Where-Object { [string]$_.State -eq 'Listen' })) {
        $port = [int]$connection.LocalPort
        if (-not $listenerByPort.ContainsKey($port)) { $listenerByPort[$port] = @() }
        $listenerByPort[$port] = @($listenerByPort[$port]) + @($connection)
    }

    $relationshipIndex = @{}
    $relationships = New-Object System.Collections.ArrayList

    function Add-Relationship {
        param(
            [string]$SourceName,
            [string]$SourceDisplay,
            [string]$TargetKey,
            [string]$TargetDisplay,
            [string]$TargetKind,
            [string]$Relationship,
            [ValidateSet('out', 'in')][string]$Direction,
            [string]$Evidence,
            [string]$Confidence
        )

        $key = "$SourceName|$Relationship|$TargetKey|$Direction"
        if ($relationshipIndex.ContainsKey($key)) { return }
        $relationshipIndex[$key] = $true
        $null = $relationships.Add([pscustomobject]@{
            SourceName     = $SourceName
            SourceDisplay  = $SourceDisplay
            TargetKey      = $TargetKey
            TargetDisplay  = $TargetDisplay
            TargetKind     = $TargetKind
            Relationship   = $Relationship
            Direction      = $Direction
            Evidence       = $Evidence
            Confidence     = $Confidence
        })
    }

    foreach ($service in $Services) {
        $sourceDisplay = if ([string]::IsNullOrWhiteSpace([string]$service.DisplayName)) { [string]$service.Name } else { [string]$service.DisplayName }

        foreach ($dependencyName in @($service.Dependencies)) {
            $targetDisplay = [string]$dependencyName
            if ($serviceIndex.ContainsKey([string]$dependencyName)) {
                $targetService = $serviceIndex[[string]$dependencyName]
                $targetDisplay = if ($targetService.DisplayName) { [string]$targetService.DisplayName } else { [string]$targetService.Name }
            }
            Add-Relationship -SourceName $service.Name -SourceDisplay $sourceDisplay -TargetKey "service:$dependencyName" -TargetDisplay $targetDisplay -TargetKind 'Service' -Relationship 'Declared dependency' -Direction 'out' -Evidence "$($service.Name) declares $dependencyName through the Windows Service Control Manager." -Confidence 'Declared'
        }

        foreach ($dependentName in @($service.Dependents)) {
            $targetDisplay = [string]$dependentName
            if ($serviceIndex.ContainsKey([string]$dependentName)) {
                $targetService = $serviceIndex[[string]$dependentName]
                $targetDisplay = if ($targetService.DisplayName) { [string]$targetService.DisplayName } else { [string]$targetService.Name }
            }
            Add-Relationship -SourceName $service.Name -SourceDisplay $sourceDisplay -TargetKey "service:$dependentName" -TargetDisplay $targetDisplay -TargetKind 'Service' -Relationship 'Dependent service' -Direction 'in' -Evidence "$dependentName declares $($service.Name) as a service dependency." -Confidence 'Declared'
        }
    }

    $localAddressIndex = @{}
    foreach ($address in @($NetworkSnapshot.LocalAddresses)) { $localAddressIndex[[string]$address] = $true }

    foreach ($connection in @($NetworkSnapshot.Connections)) {
        $ownerPid = [int]$connection.OwningProcess
        if (-not $pidServices.ContainsKey($ownerPid)) { continue }

        $ownerServiceNames = @($pidServices[$ownerPid])
        $confidence = if ($ownerServiceNames.Count -gt 1) { "Shared PID ($($ownerServiceNames.Count) services)" } else { 'Direct PID' }

        foreach ($sourceName in $ownerServiceNames) {
            if (-not $serviceIndex.ContainsKey([string]$sourceName)) { continue }
            $sourceService = $serviceIndex[[string]$sourceName]
            $sourceDisplay = if ($sourceService.DisplayName) { [string]$sourceService.DisplayName } else { [string]$sourceService.Name }

            if ([string]$connection.State -eq 'Listen') {
                $endpoint = Format-SdmEndpoint -Address ([string]$connection.LocalAddress) -Port ([int]$connection.LocalPort)
                Add-Relationship -SourceName $sourceName -SourceDisplay $sourceDisplay -TargetKey "listener:$endpoint" -TargetDisplay $endpoint -TargetKind 'Listener' -Relationship 'Listening port' -Direction 'out' -Evidence "PID $ownerPid was listening on TCP $endpoint during the scan." -Confidence $confidence
                continue
            }

            if ([string]$connection.State -eq 'Bound' -or [int]$connection.RemotePort -le 0) { continue }
            $remoteAddress = [string]$connection.RemoteAddress
            $remotePort = [int]$connection.RemotePort
            $matchedLocalService = $false

            if ($localAddressIndex.ContainsKey($remoteAddress) -and $listenerByPort.ContainsKey($remotePort)) {
                foreach ($listener in @($listenerByPort[$remotePort])) {
                    $targetPid = [int]$listener.OwningProcess
                    if (-not $pidServices.ContainsKey($targetPid)) { continue }
                    foreach ($targetServiceName in @($pidServices[$targetPid])) {
                        if (-not $serviceIndex.ContainsKey([string]$targetServiceName)) { continue }
                        $targetService = $serviceIndex[[string]$targetServiceName]
                        $targetDisplay = if ($targetService.DisplayName) { [string]$targetService.DisplayName } else { [string]$targetService.Name }
                        $endpoint = Format-SdmEndpoint -Address $remoteAddress -Port $remotePort
                        Add-Relationship -SourceName $sourceName -SourceDisplay $sourceDisplay -TargetKey "service:$targetServiceName" -TargetDisplay $targetDisplay -TargetKind 'Service' -Relationship 'Observed local TCP' -Direction 'out' -Evidence "PID $ownerPid connected to local TCP $endpoint, listened to by PID $targetPid." -Confidence $confidence
                        $matchedLocalService = $true
                    }
                }
            }

            if (-not $matchedLocalService) {
                $endpoint = Format-SdmEndpoint -Address $remoteAddress -Port $remotePort
                Add-Relationship -SourceName $sourceName -SourceDisplay $sourceDisplay -TargetKey "endpoint:$endpoint" -TargetDisplay $endpoint -TargetKind 'Endpoint' -Relationship 'Outbound TCP' -Direction 'out' -Evidence "PID $ownerPid had a $($connection.State) TCP connection to $endpoint during the scan." -Confidence $confidence
            }
        }
    }

    return @($relationships.ToArray())
}

function New-SdmHtmlReport {
    param(
        [Parameter(Mandatory)][object[]]$Services,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Relationships,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Warnings,
        [Parameter(Mandatory)][string]$ReportPath,
        [Parameter(Mandatory)][datetime]$Started,
        [Parameter(Mandatory)][bool]$IsAdministrator,
        [Parameter(Mandatory)][bool]$RunningOnly
    )

    $finished = Get-Date
    $computerName = $env:COMPUTERNAME
    $scanTime = $finished.ToString('yyyy-MM-dd HH:mm:ss')
    $duration = [math]::Round(($finished - $Started).TotalSeconds, 2)
    $runningCount = @($Services | Where-Object { $_.State -eq 'Running' }).Count
    $stoppedCount = @($Services | Where-Object { $_.State -ne 'Running' }).Count
    $declaredCount = @($Relationships | Where-Object { $_.Relationship -eq 'Declared dependency' }).Count
    $listenerCount = @($Relationships | Where-Object { $_.Relationship -eq 'Listening port' }).Count
    $outboundCount = @($Relationships | Where-Object { $_.Relationship -in @('Outbound TCP', 'Observed local TCP') }).Count

    $serviceRows = foreach ($service in $Services) {
        $stateClass = if ($service.State -eq 'Running') { 'ok' } else { 'muted' }
        $dependencies = if (@($service.Dependencies).Count) { @($service.Dependencies) -join ', ' } else { 'None declared' }
        $pathName = if ($service.PathName) { [string]$service.PathName } else { '' }
        $searchText = "$($service.Name) $($service.DisplayName) $($service.State) $($service.StartMode) $($service.StartName) $pathName"
        @"
<tr data-search="$(ConvertTo-SdmHtmlText $searchText)">
  <td><strong>$(ConvertTo-SdmHtmlText $service.DisplayName)</strong><span class="sub">$(ConvertTo-SdmHtmlText $service.Name)</span></td>
  <td><span class="badge $stateClass">$(ConvertTo-SdmHtmlText $service.State)</span></td>
  <td>$(ConvertTo-SdmHtmlText $service.StartMode)</td>
  <td>$(ConvertTo-SdmHtmlText $service.StartName)</td>
  <td>$(ConvertTo-SdmHtmlText $service.ProcessId)</td>
  <td>$(ConvertTo-SdmHtmlText $dependencies)</td>
  <td class="path">$(ConvertTo-SdmHtmlText $pathName)</td>
</tr>
"@
    }

    $relationshipRows = foreach ($relationship in @($Relationships | Sort-Object SourceDisplay, Relationship, TargetDisplay)) {
        $directionText = switch ($relationship.Relationship) {
            'Declared dependency' { 'Depends on' }
            'Dependent service'   { 'Used by' }
            'Listening port'      { 'Listens on' }
            'Observed local TCP'  { 'Connects locally to' }
            default               { 'Connects to' }
        }
        $typeClass = switch ($relationship.TargetKind) {
            'Service'  { 'service' }
            'Listener' { 'listener' }
            default    { 'endpoint' }
        }
        $searchText = "$($relationship.SourceName) $($relationship.SourceDisplay) $($relationship.TargetDisplay) $($relationship.Relationship) $($relationship.Evidence)"
        @"
<tr class="relationship-row" data-search="$(ConvertTo-SdmHtmlText $searchText)" data-source="$(ConvertTo-SdmHtmlText $relationship.SourceName)" data-source-label="$(ConvertTo-SdmHtmlText $relationship.SourceDisplay)" data-target="$(ConvertTo-SdmHtmlText $relationship.TargetDisplay)" data-kind="$(ConvertTo-SdmHtmlText $relationship.TargetKind)" data-direction="$(ConvertTo-SdmHtmlText $relationship.Direction)" data-relationship="$(ConvertTo-SdmHtmlText $relationship.Relationship)" data-evidence="$(ConvertTo-SdmHtmlText $relationship.Evidence)">
  <td><strong>$(ConvertTo-SdmHtmlText $relationship.SourceDisplay)</strong><span class="sub">$(ConvertTo-SdmHtmlText $relationship.SourceName)</span></td>
  <td>$(ConvertTo-SdmHtmlText $directionText)</td>
  <td><span class="badge $typeClass">$(ConvertTo-SdmHtmlText $relationship.TargetDisplay)</span></td>
  <td>$(ConvertTo-SdmHtmlText $relationship.Relationship)</td>
  <td>$(ConvertTo-SdmHtmlText $relationship.Confidence)</td>
  <td>$(ConvertTo-SdmHtmlText $relationship.Evidence)</td>
</tr>
"@
    }

    $relationshipCounts = @{}
    foreach ($relationship in $Relationships) {
        $name = [string]$relationship.SourceName
        if (-not $relationshipCounts.ContainsKey($name)) { $relationshipCounts[$name] = 0 }
        $relationshipCounts[$name] = [int]$relationshipCounts[$name] + 1
    }
    $defaultService = @($relationshipCounts.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1 -ExpandProperty Key)
    if ($defaultService.Count) { $defaultServiceName = [string]$defaultService[0] }
    elseif ($Services.Count) { $defaultServiceName = [string]$Services[0].Name }
    else { $defaultServiceName = '' }

    $serviceOptions = foreach ($service in $Services) {
        $selected = if ([string]$service.Name -eq $defaultServiceName) { ' selected' } else { '' }
        $count = if ($relationshipCounts.ContainsKey([string]$service.Name)) { [int]$relationshipCounts[[string]$service.Name] } else { 0 }
        $label = if ($service.DisplayName) { "$($service.DisplayName) [$($service.Name)] - $count relationship(s)" } else { "$($service.Name) - $count relationship(s)" }
        '<option value="{0}"{1}>{2}</option>' -f (ConvertTo-SdmHtmlText $service.Name), $selected, (ConvertTo-SdmHtmlText $label)
    }

    $warningItems = @(
        'The scan is point-in-time. A connection not seen during this run may still be required at another time.',
        'Services sharing one process ID also share its observed TCP evidence; review those relationships before making changes.',
        'This report is discovery evidence, not automatic approval to stop a service or block an endpoint.'
    ) + @($Warnings)
    $warningHtml = foreach ($warning in $warningItems | Select-Object -Unique) {
        "<li>$(ConvertTo-SdmHtmlText $warning)</li>"
    }

    $adminText = if ($IsAdministrator) { 'Administrator' } else { 'Standard user - some details may be incomplete' }
    $scopeText = if ($RunningOnly) { 'Running services only' } else { 'All installed services' }

    $template = @'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:">
<title>__TITLE__</title>
<style>
:root{--bg:#08111f;--panel:#0f1d30;--panel2:#13243a;--line:#27405f;--text:#edf5ff;--muted:#9db0c7;--cyan:#35d6c2;--blue:#60a5fa;--green:#4ade80;--orange:#fb923c;--purple:#c084fc;--red:#fb7185}
*{box-sizing:border-box}body{margin:0;background:linear-gradient(145deg,#07101d,#0c1b2e 55%,#08111f);color:var(--text);font:14px/1.5 "Segoe UI",Arial,sans-serif}
.wrap{max-width:1500px;margin:auto;padding:28px}.hero{display:flex;justify-content:space-between;gap:24px;align-items:flex-start;margin-bottom:22px}.eyebrow{color:var(--cyan);font-weight:700;letter-spacing:.14em;text-transform:uppercase}.hero h1{font-size:34px;line-height:1.15;margin:5px 0 8px}.hero p{color:var(--muted);margin:0}.actions{display:flex;gap:8px}.button{border:1px solid var(--line);background:var(--panel2);color:var(--text);padding:9px 14px;border-radius:8px;cursor:pointer}.button:hover{border-color:var(--cyan)}
.cards{display:grid;grid-template-columns:repeat(5,minmax(130px,1fr));gap:12px;margin:18px 0}.card,.panel{background:rgba(15,29,48,.94);border:1px solid var(--line);border-radius:12px;box-shadow:0 12px 28px rgba(0,0,0,.2)}.card{padding:16px}.card .number{font-size:28px;font-weight:700;color:var(--cyan)}.card .label{color:var(--muted)}
.panel{padding:18px;margin:15px 0}.panel h2{margin:0 0 5px;font-size:20px}.panel .intro{color:var(--muted);margin:0 0 14px}.meta{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}.pill{border:1px solid var(--line);background:#0b1728;color:var(--muted);border-radius:999px;padding:5px 10px}
.warnings{margin:10px 0 0;padding-left:20px;color:#f8d59a}.toolbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:12px 0}.toolbar label{font-weight:600}.toolbar input,.toolbar select{background:#081524;color:var(--text);border:1px solid var(--line);border-radius:8px;padding:9px 11px;min-width:280px}.toolbar input{flex:1}
.graph-shell{background:#071423;border:1px solid var(--line);border-radius:10px;overflow:auto}.graph-note{padding:8px 12px;color:var(--muted);border-bottom:1px solid var(--line)}svg{display:block;width:100%;min-width:860px;height:auto}.edge{stroke:#59708e;stroke-width:1.6;opacity:.8;marker-end:url(#arrow)}.node-box{stroke-width:2}.node-service{fill:#172c4a;stroke:var(--blue)}.node-listener{fill:#123625;stroke:var(--green)}.node-endpoint{fill:#3a2516;stroke:var(--orange)}.node-center{fill:#123a3c;stroke:var(--cyan);stroke-width:3}.node-label{fill:var(--text);font-size:13px;font-weight:600;text-anchor:middle}.node-sub{fill:var(--muted);font-size:10px;text-anchor:middle}.edge-label{fill:#b8c8dc;font-size:9px;text-anchor:middle}.legend{display:flex;gap:16px;flex-wrap:wrap;margin:10px 0;color:var(--muted)}.legend span:before{content:"";display:inline-block;width:10px;height:10px;border-radius:3px;margin-right:6px}.l-service:before{background:var(--blue)}.l-listener:before{background:var(--green)}.l-endpoint:before{background:var(--orange)}
.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:9px}table{width:100%;border-collapse:collapse;min-width:1000px}th{position:sticky;top:0;background:#142740;color:#cfe0f5;text-align:left;padding:10px;border-bottom:1px solid var(--line)}td{padding:9px 10px;border-bottom:1px solid #1c324d;vertical-align:top}tbody tr:hover{background:#12243a}.sub{display:block;color:var(--muted);font-size:12px}.path{font-family:Consolas,monospace;font-size:12px;max-width:440px;word-break:break-word}.badge{display:inline-block;padding:3px 7px;border-radius:999px;border:1px solid var(--line);white-space:nowrap}.badge.ok,.badge.listener{color:var(--green);border-color:#235d3d}.badge.muted{color:var(--muted)}.badge.service{color:var(--blue);border-color:#315b8a}.badge.endpoint{color:var(--orange);border-color:#774321}.empty{color:var(--muted);padding:22px;text-align:center}.footer{color:var(--muted);text-align:center;padding:18px}
@media(max-width:900px){.cards{grid-template-columns:repeat(2,1fr)}.hero{display:block}.actions{margin-top:14px}.wrap{padding:16px}}@media print{body{background:#fff;color:#111}.wrap{max-width:none}.panel,.card{box-shadow:none;background:#fff;border-color:#ccc}.actions,.toolbar input{display:none}.graph-shell{overflow:visible}.hero p,.intro,.sub,.pill,.footer{color:#444}th{position:static;background:#eee;color:#111}td{border-color:#ddd}.node-label{fill:#111}.node-sub,.edge-label{fill:#333}}
</style>
</head>
<body>
<main class="wrap">
  <header class="hero">
    <div><div class="eyebrow">Local service dependency scan</div><h1>__COMPUTER__</h1><p>Windows services, declared service dependencies, listening ports and current outbound TCP relationships.</p><div class="meta"><span class="pill">Tool __VERSION__</span><span class="pill">__SCANTIME__</span><span class="pill">__DURATION__ seconds</span><span class="pill">__ADMIN__</span><span class="pill">__SCOPE__</span></div></div>
    <div class="actions"><button class="button" onclick="window.print()">Print / Save PDF</button></div>
  </header>

  <section class="cards">
    <div class="card"><div class="number">__TOTAL__</div><div class="label">Services scanned</div></div>
    <div class="card"><div class="number">__RUNNING__</div><div class="label">Running</div></div>
    <div class="card"><div class="number">__DECLARED__</div><div class="label">Declared dependencies</div></div>
    <div class="card"><div class="number">__LISTENERS__</div><div class="label">Service listeners</div></div>
    <div class="card"><div class="number">__OUTBOUND__</div><div class="label">Observed TCP dependencies</div></div>
  </section>

  <section class="panel"><h2>Read this first</h2><p class="intro">The scanner is read-only and ran directly on this computer. It did not use WinRM or contact a management server.</p><ul class="warnings">__WARNINGS__</ul></section>

  <section class="panel">
    <h2>Interactive dependency map</h2><p class="intro">Choose a service to see what it declares, listens on, currently connects to, and which services declare it as a dependency. Hover a node for the evidence.</p>
    <div class="toolbar"><label for="servicePicker">Focus service</label><select id="servicePicker">__SERVICE_OPTIONS__</select><span id="graphCount" class="pill"></span></div>
    <div class="legend"><span class="l-service">Service</span><span class="l-listener">Listener</span><span class="l-endpoint">Remote endpoint</span></div>
    <div class="graph-shell"><div id="graphMessage" class="graph-note"></div><svg id="dependencyGraph" viewBox="0 0 1100 700" role="img" aria-label="Selected service dependency map"><defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto"><path d="M0,0 L0,6 L8,3 z" fill="#7d94af"></path></marker></defs><g id="graphEdges"></g><g id="graphNodes"></g></svg></div>
  </section>

  <section class="panel"><h2>Service inventory</h2><p class="intro">Search by service, account, state, dependency or executable path.</p><div class="toolbar"><input id="serviceSearch" type="search" placeholder="Filter services..."><span id="serviceVisible" class="pill"></span></div><div class="table-wrap"><table id="serviceTable"><thead><tr><th>Service</th><th>State</th><th>Start mode</th><th>Account</th><th>PID</th><th>Declared dependencies</th><th>Binary path</th></tr></thead><tbody>__SERVICE_ROWS__</tbody></table></div></section>

  <section class="panel"><h2>Dependency evidence</h2><p class="intro">Every graph edge is listed here. Shared-PID network ownership is marked so it can be reviewed manually.</p><div class="toolbar"><input id="relationshipSearch" type="search" placeholder="Filter dependencies and endpoints..."><span id="relationshipVisible" class="pill"></span></div><div class="table-wrap"><table id="relationshipTable"><thead><tr><th>Service</th><th>Direction</th><th>Target</th><th>Relationship</th><th>Confidence</th><th>Evidence</th></tr></thead><tbody>__RELATIONSHIP_ROWS__</tbody></table></div></section>

  <div class="footer">Generated locally by Service Dependency Mapper v__VERSION__. No external resources or internet connection are used.</div>
</main>
<script>
(function(){
  'use strict';
  const NS='http://www.w3.org/2000/svg';
  const picker=document.getElementById('servicePicker');
  const graph=document.getElementById('dependencyGraph');
  const edgeLayer=document.getElementById('graphEdges');
  const nodeLayer=document.getElementById('graphNodes');
  const graphMessage=document.getElementById('graphMessage');
  const graphCount=document.getElementById('graphCount');
  const relationshipRows=Array.from(document.querySelectorAll('#relationshipTable tbody tr'));

  function svgElement(name,attributes){
    const item=document.createElementNS(NS,name);
    Object.keys(attributes||{}).forEach(key=>item.setAttribute(key,attributes[key]));
    return item;
  }
  function shortened(value,max){return value.length>max?value.slice(0,max-1)+'…':value;}
  function nodeClass(kind){return kind==='Service'?'node-service':kind==='Listener'?'node-listener':'node-endpoint';}
  function addText(parent,x,y,text,className){const t=svgElement('text',{x:x,y:y,class:className});t.textContent=text;parent.appendChild(t);}
  function addNode(x,y,label,sub,kind,evidence,isCenter){
    const group=svgElement('g',{});const width=isCenter?220:164;const height=isCenter?68:56;
    const rect=svgElement('rect',{x:x-width/2,y:y-height/2,width:width,height:height,rx:10,class:isCenter?'node-center':'node-box '+nodeClass(kind)});
    group.appendChild(rect);addText(group,x,y-3,shortened(label,isCenter?31:23),'node-label');addText(group,x,y+16,shortened(sub,isCenter?34:27),'node-sub');
    const title=svgElement('title',{});title.textContent=evidence||label;group.appendChild(title);nodeLayer.appendChild(group);
  }
  function renderGraph(){
    edgeLayer.textContent='';nodeLayer.textContent='';
    const source=picker.value;const sourceLabel=picker.options.length?picker.options[picker.selectedIndex].text.replace(/ - \d+ relationship\(s\)$/,''):source;
    const all=relationshipRows.filter(row=>row.dataset.source===source);const rows=all.slice(0,22);const cx=550,cy=350;
    addNode(cx,cy,sourceLabel,source,'Service','Selected local Windows service',true);
    if(!rows.length){graphMessage.textContent='No declared or observed relationships were found for this service during the scan.';graphCount.textContent='0 relationships';return;}
    graphMessage.textContent=all.length>rows.length?'Showing 22 of '+all.length+' relationships. The evidence table contains the complete set.':'Hover a node to read the captured evidence.';
    graphCount.textContent=all.length+' relationship'+(all.length===1?'':'s');
    rows.forEach((row,index)=>{
      const innerCount=Math.min(rows.length,8);let radius,slot,total;
      if(index<innerCount){radius=175;slot=index;total=innerCount;}else{radius=292;slot=index-innerCount;total=rows.length-innerCount;}
      const angle=(-Math.PI/2)+(Math.PI*2*slot/Math.max(total,1));const x=cx+Math.cos(angle)*radius;const y=cy+Math.sin(angle)*radius;
      const line=row.dataset.direction==='in'?svgElement('line',{x1:x,y1:y,x2:cx,y2:cy,class:'edge'}):svgElement('line',{x1:cx,y1:cy,x2:x,y2:y,class:'edge'});
      edgeLayer.appendChild(line);const mx=(cx+x)/2,my=(cy+y)/2;addText(edgeLayer,mx,my-5,shortened(row.dataset.relationship,22),'edge-label');
      addNode(x,y,row.dataset.target,row.dataset.relationship,row.dataset.kind,row.dataset.evidence,false);
    });
  }
  function attachFilter(inputId,tableId,countId){
    const input=document.getElementById(inputId),rows=Array.from(document.querySelectorAll('#'+tableId+' tbody tr')),count=document.getElementById(countId);
    function apply(){const term=input.value.trim().toLowerCase();let visible=0;rows.forEach(row=>{const show=!term||(row.dataset.search||row.textContent).toLowerCase().includes(term);row.style.display=show?'':'none';if(show)visible++;});count.textContent=visible+' of '+rows.length;}
    input.addEventListener('input',apply);apply();
  }
  picker.addEventListener('change',renderGraph);attachFilter('serviceSearch','serviceTable','serviceVisible');attachFilter('relationshipSearch','relationshipTable','relationshipVisible');renderGraph();
})();
</script>
</body>
</html>
'@

    $replacements = [ordered]@{
        '__TITLE__'             = ConvertTo-SdmHtmlText "Service Dependency Report - $computerName"
        '__COMPUTER__'          = ConvertTo-SdmHtmlText $computerName
        '__VERSION__'           = ConvertTo-SdmHtmlText $script:SdmVersion
        '__SCANTIME__'          = ConvertTo-SdmHtmlText $scanTime
        '__DURATION__'          = ConvertTo-SdmHtmlText $duration
        '__ADMIN__'             = ConvertTo-SdmHtmlText $adminText
        '__SCOPE__'             = ConvertTo-SdmHtmlText $scopeText
        '__TOTAL__'             = ConvertTo-SdmHtmlText $Services.Count
        '__RUNNING__'           = ConvertTo-SdmHtmlText $runningCount
        '__STOPPED__'           = ConvertTo-SdmHtmlText $stoppedCount
        '__DECLARED__'          = ConvertTo-SdmHtmlText $declaredCount
        '__LISTENERS__'         = ConvertTo-SdmHtmlText $listenerCount
        '__OUTBOUND__'          = ConvertTo-SdmHtmlText $outboundCount
        '__WARNINGS__'          = @($warningHtml) -join [Environment]::NewLine
        '__SERVICE_OPTIONS__'   = @($serviceOptions) -join [Environment]::NewLine
        '__SERVICE_ROWS__'      = @($serviceRows) -join [Environment]::NewLine
        '__RELATIONSHIP_ROWS__' = @($relationshipRows) -join [Environment]::NewLine
    }
    foreach ($placeholder in $replacements.Keys) {
        $template = $template.Replace([string]$placeholder, [string]$replacements[$placeholder])
    }

    [System.IO.File]::WriteAllText($ReportPath, $template, (New-Object System.Text.UTF8Encoding($false)))
}

function Invoke-SdmLocalScan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Destination,
        [switch]$RunningOnly,
        [switch]$OpenWhenComplete
    )

    $started = Get-Date
    $warnings = @()
    $isAdministrator = Test-SdmAdministrator
    if (-not $isAdministrator) {
        $warnings += 'PowerShell was not running as Administrator. The report was created, but some service paths or TCP ownership details may be incomplete.'
    }

    $resolvedDestination = [System.IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($Destination.Trim([char]'"')))
    if (-not (Test-Path -LiteralPath $resolvedDestination -PathType Container)) {
        $null = New-Item -Path $resolvedDestination -ItemType Directory -Force
    }

    Write-Progress -Activity 'Service Dependency Mapper' -Status 'Reading local Windows services...' -PercentComplete 15
    $services = @(Get-SdmServiceInventory -RunningOnly:$RunningOnly)
    if ($services.Count -eq 0) { throw 'No Windows services were returned. Try running PowerShell as Administrator.' }

    Write-Progress -Activity 'Service Dependency Mapper' -Status 'Reading current local TCP state...' -PercentComplete 45
    $network = Get-SdmNetworkSnapshot
    $warnings += @($network.Warnings)

    Write-Progress -Activity 'Service Dependency Mapper' -Status 'Correlating service relationships...' -PercentComplete 70
    $relationships = @(New-SdmRelationships -Services $services -NetworkSnapshot $network)

    $sharedPidCount = @($relationships | Where-Object { $_.Confidence -like 'Shared PID*' }).Count
    if ($sharedPidCount -gt 0) {
        $warnings += "$sharedPidCount network relationship(s) belong to a process hosting multiple services and therefore require manual attribution review."
    }

    $timestamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $safeComputer = $env:COMPUTERNAME -replace '[^A-Za-z0-9_.-]', '_'
    $reportPath = Join-Path $resolvedDestination "Service-Dependency-Report-$safeComputer-$timestamp.html"

    Write-Progress -Activity 'Service Dependency Mapper' -Status 'Building the offline HTML report...' -PercentComplete 88
    New-SdmHtmlReport -Services $services -Relationships $relationships -Warnings @($warnings) -ReportPath $reportPath -Started $started -IsAdministrator $isAdministrator -RunningOnly ([bool]$RunningOnly)
    Write-Progress -Activity 'Service Dependency Mapper' -Completed

    $result = [pscustomobject]@{
        ComputerName      = $env:COMPUTERNAME
        ReportPath        = $reportPath
        Services          = $services.Count
        RunningServices   = @($services | Where-Object { $_.State -eq 'Running' }).Count
        Relationships     = $relationships.Count
        WarningCount      = @($warnings).Count
        DurationSeconds   = [math]::Round(((Get-Date) - $started).TotalSeconds, 2)
        RanAsAdministrator = $isAdministrator
    }

    if ($OpenWhenComplete) { Start-Process -FilePath $reportPath }
    return $result
}

function Show-SdmWinFormsMenu {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [System.Windows.Forms.Application]::EnableVisualStyles()

    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Service Dependency Mapper v2'
    $form.Size = New-Object System.Drawing.Size(720, 470)
    $form.MinimumSize = New-Object System.Drawing.Size(680, 440)
    $form.StartPosition = 'CenterScreen'
    $form.BackColor = [System.Drawing.Color]::FromArgb(9, 20, 35)
    $form.ForeColor = [System.Drawing.Color]::FromArgb(235, 244, 255)
    $form.Font = New-Object System.Drawing.Font('Segoe UI', 9)

    $title = New-Object System.Windows.Forms.Label
    $title.Text = 'Service Dependency Mapper'
    $title.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 22)
    $title.ForeColor = [System.Drawing.Color]::FromArgb(53, 214, 194)
    $title.AutoSize = $true
    $title.Location = New-Object System.Drawing.Point(24, 20)
    $form.Controls.Add($title)

    $subtitle = New-Object System.Windows.Forms.Label
    $subtitle.Text = "Local read-only scan of $env:COMPUTERNAME - no WinRM, agent or installation"
    $subtitle.ForeColor = [System.Drawing.Color]::FromArgb(157, 176, 199)
    $subtitle.AutoSize = $true
    $subtitle.Location = New-Object System.Drawing.Point(27, 62)
    $form.Controls.Add($subtitle)

    $info = New-Object System.Windows.Forms.Label
    $info.Text = "This scan reads Windows services, declared dependencies and current TCP ownership.`r`nIt creates one self-contained HTML report and does not change services or firewall rules."
    $info.ForeColor = [System.Drawing.Color]::FromArgb(205, 219, 235)
    $info.Location = New-Object System.Drawing.Point(27, 96)
    $info.Size = New-Object System.Drawing.Size(650, 52)
    $form.Controls.Add($info)

    $outputLabel = New-Object System.Windows.Forms.Label
    $outputLabel.Text = 'Report folder'
    $outputLabel.AutoSize = $true
    $outputLabel.Location = New-Object System.Drawing.Point(27, 164)
    $form.Controls.Add($outputLabel)

    $outputBox = New-Object System.Windows.Forms.TextBox
    $outputBox.Text = $OutputFolder
    $outputBox.Location = New-Object System.Drawing.Point(27, 187)
    $outputBox.Size = New-Object System.Drawing.Size(560, 25)
    $outputBox.Anchor = 'Top,Left,Right'
    $outputBox.BackColor = [System.Drawing.Color]::FromArgb(7, 16, 29)
    $outputBox.ForeColor = [System.Drawing.Color]::White
    $form.Controls.Add($outputBox)

    $browseButton = New-Object System.Windows.Forms.Button
    $browseButton.Text = 'Browse'
    $browseButton.Location = New-Object System.Drawing.Point(598, 184)
    $browseButton.Size = New-Object System.Drawing.Size(88, 30)
    $browseButton.Anchor = 'Top,Right'
    $form.Controls.Add($browseButton)

    $includeStoppedCheck = New-Object System.Windows.Forms.CheckBox
    $includeStoppedCheck.Text = 'Include stopped services (recommended for a complete map)'
    $includeStoppedCheck.Checked = -not [bool]$RunningServicesOnly
    $includeStoppedCheck.AutoSize = $true
    $includeStoppedCheck.Location = New-Object System.Drawing.Point(28, 235)
    $form.Controls.Add($includeStoppedCheck)

    $openCheck = New-Object System.Windows.Forms.CheckBox
    $openCheck.Text = 'Open the HTML report when the scan finishes'
    $openCheck.Checked = $true
    $openCheck.AutoSize = $true
    $openCheck.Location = New-Object System.Drawing.Point(28, 266)
    $form.Controls.Add($openCheck)

    $adminStatus = New-Object System.Windows.Forms.Label
    $adminStatus.Text = if (Test-SdmAdministrator) { 'Administrator check: PASS' } else { 'Administrator check: WARNING - report may contain partial details' }
    $adminStatus.ForeColor = if (Test-SdmAdministrator) { [System.Drawing.Color]::FromArgb(74, 222, 128) } else { [System.Drawing.Color]::FromArgb(251, 191, 36) }
    $adminStatus.AutoSize = $true
    $adminStatus.Location = New-Object System.Drawing.Point(28, 302)
    $form.Controls.Add($adminStatus)

    $progress = New-Object System.Windows.Forms.ProgressBar
    $progress.Location = New-Object System.Drawing.Point(28, 332)
    $progress.Size = New-Object System.Drawing.Size(658, 7)
    $progress.Anchor = 'Top,Left,Right'
    $form.Controls.Add($progress)

    $status = New-Object System.Windows.Forms.Label
    $status.Text = 'Ready to scan this computer.'
    $status.ForeColor = [System.Drawing.Color]::FromArgb(157, 176, 199)
    $status.Location = New-Object System.Drawing.Point(28, 352)
    $status.Size = New-Object System.Drawing.Size(658, 32)
    $status.Anchor = 'Top,Left,Right'
    $form.Controls.Add($status)

    $scanButton = New-Object System.Windows.Forms.Button
    $scanButton.Text = 'Scan this computer'
    $scanButton.Location = New-Object System.Drawing.Point(28, 390)
    $scanButton.Size = New-Object System.Drawing.Size(170, 34)
    $scanButton.BackColor = [System.Drawing.Color]::FromArgb(19, 58, 62)
    $scanButton.ForeColor = [System.Drawing.Color]::White
    $form.Controls.Add($scanButton)

    $openButton = New-Object System.Windows.Forms.Button
    $openButton.Text = 'Open last report'
    $openButton.Location = New-Object System.Drawing.Point(208, 390)
    $openButton.Size = New-Object System.Drawing.Size(145, 34)
    $openButton.Enabled = $false
    $form.Controls.Add($openButton)

    $closeButton = New-Object System.Windows.Forms.Button
    $closeButton.Text = 'Close'
    $closeButton.Location = New-Object System.Drawing.Point(576, 390)
    $closeButton.Size = New-Object System.Drawing.Size(110, 34)
    $closeButton.Anchor = 'Top,Right'
    $form.Controls.Add($closeButton)

    $script:lastSdmReport = $null

    $browseButton.Add_Click({
        $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
        $dialog.Description = 'Choose where the HTML report will be saved'
        if (Test-Path -LiteralPath $outputBox.Text -PathType Container) { $dialog.SelectedPath = $outputBox.Text }
        if ($dialog.ShowDialog() -eq 'OK') { $outputBox.Text = $dialog.SelectedPath }
        $dialog.Dispose()
    })

    $scanButton.Add_Click({
        if ([string]::IsNullOrWhiteSpace($outputBox.Text)) {
            [System.Windows.Forms.MessageBox]::Show('Choose a report folder.', 'Output folder', 'OK', 'Warning') | Out-Null
            return
        }
        $scanButton.Enabled = $false
        $browseButton.Enabled = $false
        $progress.Style = 'Marquee'
        $status.Text = 'Scanning local Windows services and current TCP state...'
        $form.UseWaitCursor = $true
        [System.Windows.Forms.Application]::DoEvents()
        try {
            $result = Invoke-SdmLocalScan -Destination $outputBox.Text.Trim() -RunningOnly:(-not $includeStoppedCheck.Checked) -OpenWhenComplete:$openCheck.Checked
            $script:lastSdmReport = [string]$result.ReportPath
            $openButton.Enabled = $true
            $status.Text = "Complete: $($result.Services) services and $($result.Relationships) relationships."
            [System.Windows.Forms.MessageBox]::Show("Scan complete.`r`n`r`nReport: $($result.ReportPath)", 'Service Dependency Mapper', 'OK', 'Information') | Out-Null
        }
        catch {
            $status.Text = 'The scan failed. Review the message and try again as Administrator.'
            [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Scan failed', 'OK', 'Error') | Out-Null
        }
        finally {
            $form.UseWaitCursor = $false
            $progress.Style = 'Continuous'
            $progress.Value = 0
            $scanButton.Enabled = $true
            $browseButton.Enabled = $true
        }
    })

    $openButton.Add_Click({
        if ($script:lastSdmReport -and (Test-Path -LiteralPath $script:lastSdmReport -PathType Leaf)) {
            Start-Process -FilePath $script:lastSdmReport
        }
    })
    $closeButton.Add_Click({ $form.Close() })
    $form.AcceptButton = $scanButton
    [void]$form.ShowDialog()
    $form.Dispose()
}

if ($NoGui) {
    $result = Invoke-SdmLocalScan -Destination $OutputFolder -RunningOnly:$RunningServicesOnly -OpenWhenComplete:$OpenReport
    Write-Host ''
    Write-Host 'SERVICE DEPENDENCY SCAN COMPLETE' -ForegroundColor Green
    Write-Host "Computer:      $($result.ComputerName)"
    Write-Host "Services:      $($result.Services)"
    Write-Host "Relationships: $($result.Relationships)"
    Write-Host "Warnings:      $($result.WarningCount)"
    Write-Host "Report:        $($result.ReportPath)"
    Write-Host "Duration:      $($result.DurationSeconds) seconds"
    $result
}
else {
    try {
        Show-SdmWinFormsMenu
    }
    catch {
        Write-Warning "The WinForms menu could not start: $($_.Exception.Message)"
        Write-Host 'Running the local scan in console mode instead.' -ForegroundColor Yellow
        $result = Invoke-SdmLocalScan -Destination $OutputFolder -RunningOnly:$RunningServicesOnly -OpenWhenComplete:$OpenReport
        Write-Host "Report: $($result.ReportPath)" -ForegroundColor Green
        $result
    }
}
