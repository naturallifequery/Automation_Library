#requires -Version 5.1
<#
.SYNOPSIS
    Creates a read-only Windows Server triage report.

.DESCRIPTION
    Collects a consistent operational snapshot from one or more Windows servers
    and writes an HTML dashboard, CSV summary, JSON evidence files, and a run log.

    The script does not restart services, delete files, install software, or
    change configuration on the local or remote computer.

.PARAMETER ComputerName
    One or more Windows computer names. The default is localhost.

.PARAMETER ComputerListPath
    Path to a CSV containing ComputerName and optional Environment and Owner
    columns.

.PARAMETER Credential
    Optional credential used for remote PowerShell sessions. Credentials are
    held in memory and are not written to the output.

.PARAMETER ConfigPath
    Path to the JSON configuration file.

.PARAMETER OutputPath
    Parent directory for timestamped report folders.

.PARAMETER UseSSL
    Uses HTTPS for PowerShell remoting.

.PARAMETER SkipPing
    Skips the informational ICMP connectivity test. A failed ping never prevents
    the script from attempting PowerShell remoting.

.PARAMETER OpenReport
    Opens the HTML report after collection completes.

.EXAMPLE
    .\Invoke-ServerTriage.ps1 -ComputerName localhost -OpenReport

.EXAMPLE
    .\Invoke-ServerTriage.ps1 -ComputerName APP-SRV-01,SQL-SRV-01

.EXAMPLE
    $cred = Get-Credential
    .\Invoke-ServerTriage.ps1 -ComputerListPath .\Config\servers.example.csv -Credential $cred

.NOTES
    Project: Server Triage Pack
    Version: 1.0.0
    License: MIT
#>

[CmdletBinding(DefaultParameterSetName = 'ByName')]
param(
    [Parameter(ParameterSetName = 'ByName')]
    [ValidateNotNullOrEmpty()]
    [string[]]$ComputerName = @('localhost'),

    [Parameter(Mandatory = $true, ParameterSetName = 'ByCsv')]
    [ValidateNotNullOrEmpty()]
    [string]$ComputerListPath,

    [Parameter()]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'Config\triage.config.json'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = (Join-Path $PSScriptRoot 'Output'),

    [Parameter()]
    [switch]$UseSSL,

    [Parameter()]
    [switch]$SkipPing,

    [Parameter()]
    [switch]$OpenReport
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:PackVersion = '1.0.0'
$script:StartedAt = Get-Date
$script:RunId = $script:StartedAt.ToString('yyyyMMdd-HHmmss')
$script:RunDirectory = $null
$script:LogPath = $null
$script:SelectedParameterSet = $PSCmdlet.ParameterSetName

function Write-TriageLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter()]
        [ValidateSet('INFO', 'WARN', 'ERROR')]
        [string]$Level = 'INFO'
    )

    $line = '{0} [{1}] {2}' -f (Get-Date).ToString('s'), $Level, $Message
    Write-Host $line

    if ($script:LogPath) {
        Add-Content -LiteralPath $script:LogPath -Value $line -Encoding UTF8
    }
}

function ConvertTo-HtmlText {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return ''
    }

    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Get-StatusRank {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Status
    )

    switch ($Status) {
        'Critical'    { return 4 }
        'Unreachable' { return 4 }
        'Warning'     { return 3 }
        'Healthy'     { return 2 }
        default       { return 1 }
    }
}

function Get-StatusBadgeHtml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Status
    )

    $safeStatus = ConvertTo-HtmlText $Status
    $className = $Status.ToLowerInvariant()
    if ($className -notin @('healthy', 'warning', 'critical', 'unreachable', 'info')) {
        $className = 'info'
    }

    return '<span class="badge {0}">{1}</span>' -f $className, $safeStatus
}

function Assert-TriageConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Config
    )

    $requiredProperties = @(
        'EventLookbackHours',
        'MaxEventsPerLog',
        'EventLogs',
        'EventLevels',
        'DiskWarningPercentFree',
        'DiskCriticalPercentFree',
        'MemoryWarningPercentFree',
        'UptimeWarningDays',
        'PatchWarningAgeDays',
        'PatchCriticalAgeDays',
        'RequiredServices',
        'ExcludedAutomaticServices',
        'CollectListeningPorts',
        'MaxListeningPorts'
    )

    foreach ($name in $requiredProperties) {
        if ($null -eq $Config.PSObject.Properties[$name]) {
            throw "Configuration property '$name' is missing."
        }
    }

    if ([int]$Config.DiskCriticalPercentFree -ge [int]$Config.DiskWarningPercentFree) {
        throw 'DiskCriticalPercentFree must be lower than DiskWarningPercentFree.'
    }

    if ([int]$Config.PatchCriticalAgeDays -le [int]$Config.PatchWarningAgeDays) {
        throw 'PatchCriticalAgeDays must be greater than PatchWarningAgeDays.'
    }

    if ([int]$Config.EventLookbackHours -lt 1 -or [int]$Config.MaxEventsPerLog -lt 1) {
        throw 'EventLookbackHours and MaxEventsPerLog must both be at least 1.'
    }
}

function Get-TriageTargets {
    [CmdletBinding()]
    param()

    $targets = @()

    if ($script:SelectedParameterSet -eq 'ByCsv') {
        if (-not (Test-Path -LiteralPath $ComputerListPath -PathType Leaf)) {
            throw "Computer list not found: $ComputerListPath"
        }

        $rows = @(Import-Csv -LiteralPath $ComputerListPath)
        if ($rows.Count -eq 0) {
            throw "Computer list is empty: $ComputerListPath"
        }

        if ($null -eq $rows[0].PSObject.Properties['ComputerName']) {
            throw "Computer list must contain a 'ComputerName' column."
        }

        foreach ($row in $rows) {
            if ([string]::IsNullOrWhiteSpace([string]$row.ComputerName)) {
                continue
            }

            $environment = ''
            $owner = ''
            if ($row.PSObject.Properties['Environment']) {
                $environment = [string]$row.Environment
            }
            if ($row.PSObject.Properties['Owner']) {
                $owner = [string]$row.Owner
            }

            $targets += [pscustomobject]@{
                ComputerName = ([string]$row.ComputerName).Trim()
                Environment  = $environment.Trim()
                Owner        = $owner.Trim()
            }
        }
    }
    else {
        foreach ($name in $ComputerName) {
            if ([string]::IsNullOrWhiteSpace($name)) {
                continue
            }

            $targets += [pscustomobject]@{
                ComputerName = $name.Trim()
                Environment  = ''
                Owner        = ''
            }
        }
    }

    $deduplicated = @(
        $targets |
            Group-Object -Property { $_.ComputerName.ToLowerInvariant() } |
            ForEach-Object { $_.Group[0] }
    )

    if ($deduplicated.Count -eq 0) {
        throw 'No valid computer names were supplied.'
    }

    return $deduplicated
}

function Test-IsLocalTarget {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $localNames = @('.', 'localhost', '127.0.0.1', '::1', $env:COMPUTERNAME)
    try {
        $localNames += [System.Net.Dns]::GetHostEntry('').HostName
    }
    catch {
        # The short computer name is sufficient if DNS lookup is unavailable.
    }

    return $localNames -contains $Name
}

$collectorScript = {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$CollectorConfig
    )

    Set-StrictMode -Version 2.0
    $ErrorActionPreference = 'Stop'
    $collectionErrors = New-Object System.Collections.Generic.List[string]
    $collectedAt = Get-Date

    function Add-CollectionError {
        param([string]$Area, [string]$Message)
        [void]$collectionErrors.Add(('{0}: {1}' -f $Area, $Message))
    }

    $os = $null
    $computerSystem = $null
    $processors = @()
    $systemInfo = $null
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
        $processors = @(Get-CimInstance -ClassName Win32_Processor)

        $totalMemoryGB = [math]::Round(([double]$os.TotalVisibleMemorySize / 1MB), 2)
        $freeMemoryGB = [math]::Round(([double]$os.FreePhysicalMemory / 1MB), 2)
        $memoryUsedPercent = 0
        if ($totalMemoryGB -gt 0) {
            $memoryUsedPercent = [math]::Round((($totalMemoryGB - $freeMemoryGB) / $totalMemoryGB) * 100, 1)
        }

        $cpuLoadValues = @($processors | Where-Object { $null -ne $_.LoadPercentage } | ForEach-Object { [double]$_.LoadPercentage })
        $cpuLoadPercent = $null
        if ($cpuLoadValues.Count -gt 0) {
            $cpuLoadPercent = [math]::Round(($cpuLoadValues | Measure-Object -Average).Average, 1)
        }

        $timeZoneName = 'Unavailable'
        try {
            $timeZoneCommand = Get-Command -Name Get-TimeZone -ErrorAction SilentlyContinue
            if ($timeZoneCommand) {
                $timeZoneName = [string](Get-TimeZone).Id
            }
            else {
                $timeZoneName = [string](Get-CimInstance -ClassName Win32_TimeZone).Caption
            }
        }
        catch {
            Add-CollectionError -Area 'Time zone' -Message $_.Exception.Message
        }

        $uptime = New-TimeSpan -Start ([datetime]$os.LastBootUpTime) -End $collectedAt
        $systemInfo = [pscustomobject]@{
            ComputerName       = [string]$env:COMPUTERNAME
            Domain             = [string]$computerSystem.Domain
            Manufacturer       = [string]$computerSystem.Manufacturer
            Model              = [string]$computerSystem.Model
            OperatingSystem    = [string]$os.Caption
            Version            = [string]$os.Version
            BuildNumber        = [string]$os.BuildNumber
            LastBootTime       = [datetime]$os.LastBootUpTime
            UptimeDays         = [math]::Round($uptime.TotalDays, 1)
            CpuLogicalCount    = [int]$computerSystem.NumberOfLogicalProcessors
            CpuLoadPercent     = $cpuLoadPercent
            TotalMemoryGB      = $totalMemoryGB
            FreeMemoryGB       = $freeMemoryGB
            MemoryUsedPercent  = $memoryUsedPercent
            TimeZone           = $timeZoneName
            PowerShellVersion  = [string]$PSVersionTable.PSVersion
        }
    }
    catch {
        Add-CollectionError -Area 'System information' -Message $_.Exception.Message
    }

    $disks = @()
    try {
        $disks = @(
            Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' |
                Sort-Object -Property DeviceID |
                ForEach-Object {
                    $sizeGB = [math]::Round(([double]$_.Size / 1GB), 2)
                    $freeGB = [math]::Round(([double]$_.FreeSpace / 1GB), 2)
                    $percentFree = 0
                    if ($sizeGB -gt 0) {
                        $percentFree = [math]::Round(($freeGB / $sizeGB) * 100, 1)
                    }

                    $status = 'Healthy'
                    if ($percentFree -le [int]$CollectorConfig.DiskCriticalPercentFree) {
                        $status = 'Critical'
                    }
                    elseif ($percentFree -le [int]$CollectorConfig.DiskWarningPercentFree) {
                        $status = 'Warning'
                    }

                    [pscustomobject]@{
                        Drive       = [string]$_.DeviceID
                        VolumeName  = [string]$_.VolumeName
                        SizeGB      = $sizeGB
                        FreeGB      = $freeGB
                        PercentFree = $percentFree
                        Status      = $status
                    }
                }
        )
    }
    catch {
        Add-CollectionError -Area 'Disk information' -Message $_.Exception.Message
    }

    $requiredServices = @()
    try {
        foreach ($serviceName in @($CollectorConfig.RequiredServices)) {
            try {
                $service = Get-Service -Name ([string]$serviceName) -ErrorAction Stop
                $requiredServices += [pscustomobject]@{
                    Name        = [string]$service.Name
                    DisplayName = [string]$service.DisplayName
                    Status      = [string]$service.Status
                    Found       = $true
                }
            }
            catch {
                $requiredServices += [pscustomobject]@{
                    Name        = [string]$serviceName
                    DisplayName = [string]$serviceName
                    Status      = 'NotFound'
                    Found       = $false
                }
            }
        }
    }
    catch {
        Add-CollectionError -Area 'Required services' -Message $_.Exception.Message
    }

    $automaticServicesStopped = @()
    try {
        $excludedServices = @($CollectorConfig.ExcludedAutomaticServices | ForEach-Object { ([string]$_).ToLowerInvariant() })
        $automaticServicesStopped = @(
            Get-CimInstance -ClassName Win32_Service |
                Where-Object {
                    $_.StartMode -eq 'Auto' -and
                    $_.State -ne 'Running' -and
                    $excludedServices -notcontains ([string]$_.Name).ToLowerInvariant()
                } |
                Sort-Object -Property Name |
                Select-Object -Property Name, DisplayName, State, StartMode, StartName
        )
    }
    catch {
        Add-CollectionError -Area 'Automatic services' -Message $_.Exception.Message
    }

    $eventRecords = @()
    try {
        $eventStart = $collectedAt.AddHours(-1 * [int]$CollectorConfig.EventLookbackHours)
        foreach ($logName in @($CollectorConfig.EventLogs)) {
            try {
                $filter = @{
                    LogName   = [string]$logName
                    Level     = @($CollectorConfig.EventLevels | ForEach-Object { [int]$_ })
                    StartTime = $eventStart
                }

                $events = @(
                    Get-WinEvent -FilterHashtable $filter -MaxEvents ([int]$CollectorConfig.MaxEventsPerLog) -ErrorAction Stop
                )

                foreach ($event in $events) {
                    $message = [string]$event.Message
                    $message = ($message -replace '[\r\n]+', ' ').Trim()
                    if ($message.Length -gt 360) {
                        $message = $message.Substring(0, 360) + '...'
                    }

                    $eventRecords += [pscustomobject]@{
                        LogName      = [string]$logName
                        TimeCreated  = [datetime]$event.TimeCreated
                        Level        = [string]$event.LevelDisplayName
                        Id           = [int]$event.Id
                        ProviderName = [string]$event.ProviderName
                        Message      = $message
                    }
                }
            }
            catch {
                Add-CollectionError -Area ("Event log '{0}'" -f $logName) -Message $_.Exception.Message
            }
        }
    }
    catch {
        Add-CollectionError -Area 'Event logs' -Message $_.Exception.Message
    }

    $hotfixes = @()
    $lastPatchDate = $null
    try {
        $hotfixes = @(
            Get-HotFix -ErrorAction Stop |
                Where-Object { $null -ne $_.InstalledOn } |
                Sort-Object -Property InstalledOn -Descending |
                Select-Object -First 10 -Property HotFixID, Description, InstalledBy, InstalledOn
        )

        if ($hotfixes.Count -gt 0 -and $null -ne $hotfixes[0].InstalledOn) {
            $lastPatchDate = [datetime]$hotfixes[0].InstalledOn
        }
    }
    catch {
        Add-CollectionError -Area 'Installed updates' -Message $_.Exception.Message
    }

    $pendingRebootReasons = New-Object System.Collections.Generic.List[string]
    try {
        if (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
            [void]$pendingRebootReasons.Add('Component Based Servicing')
        }
        if (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
            [void]$pendingRebootReasons.Add('Windows Update')
        }

        $sessionManager = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
        if ($null -ne $sessionManager -and $sessionManager.PSObject.Properties['PendingFileRenameOperations']) {
            [void]$pendingRebootReasons.Add('Pending file rename operations')
        }
    }
    catch {
        Add-CollectionError -Area 'Pending reboot checks' -Message $_.Exception.Message
    }

    $networkAdapters = @()
    try {
        $networkAdapters = @(
            Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' |
                ForEach-Object {
                    [pscustomobject]@{
                        Description = [string]$_.Description
                        DHCPEnabled = [bool]$_.DHCPEnabled
                        IPAddresses = (@($_.IPAddress) -join ', ')
                        Gateways    = (@($_.DefaultIPGateway) -join ', ')
                        DnsServers  = (@($_.DNSServerSearchOrder) -join ', ')
                        MacAddress  = [string]$_.MACAddress
                    }
                }
        )
    }
    catch {
        Add-CollectionError -Area 'Network adapters' -Message $_.Exception.Message
    }

    $firewallProfiles = @()
    try {
        if (Get-Command -Name Get-NetFirewallProfile -ErrorAction SilentlyContinue) {
            $firewallProfiles = @(
                Get-NetFirewallProfile |
                    Sort-Object -Property Name |
                    Select-Object -Property Name, Enabled, DefaultInboundAction, DefaultOutboundAction
            )
        }
    }
    catch {
        Add-CollectionError -Area 'Firewall profiles' -Message $_.Exception.Message
    }

    $listeningPorts = @()
    if ([bool]$CollectorConfig.CollectListeningPorts) {
        try {
            if (Get-Command -Name Get-NetTCPConnection -ErrorAction SilentlyContinue) {
                $connections = @(
                    Get-NetTCPConnection -State Listen -ErrorAction Stop |
                        Sort-Object -Property LocalPort, LocalAddress |
                        Select-Object -First ([int]$CollectorConfig.MaxListeningPorts)
                )

                $processNames = @{}
                foreach ($processId in @($connections.OwningProcess | Select-Object -Unique)) {
                    try {
                        $processNames[[int]$processId] = [string](Get-Process -Id $processId -ErrorAction Stop).ProcessName
                    }
                    catch {
                        $processNames[[int]$processId] = 'Unknown'
                    }
                }

                $listeningPorts = @(
                    foreach ($connection in $connections) {
                        [pscustomobject]@{
                            LocalAddress = [string]$connection.LocalAddress
                            LocalPort    = [int]$connection.LocalPort
                            ProcessId    = [int]$connection.OwningProcess
                            ProcessName  = [string]$processNames[[int]$connection.OwningProcess]
                        }
                    }
                )
            }
        }
        catch {
            Add-CollectionError -Area 'Listening ports' -Message $_.Exception.Message
        }
    }

    [pscustomobject]@{
        CollectedAt              = $collectedAt
        SystemInfo               = $systemInfo
        Disks                    = @($disks)
        RequiredServices         = @($requiredServices)
        AutomaticServicesStopped = @($automaticServicesStopped)
        Events                   = @($eventRecords | Sort-Object -Property TimeCreated -Descending)
        Hotfixes                 = @($hotfixes)
        LastPatchDate            = $lastPatchDate
        PendingReboot            = ($pendingRebootReasons.Count -gt 0)
        PendingRebootReasons     = @($pendingRebootReasons)
        NetworkAdapters          = @($networkAdapters)
        FirewallProfiles         = @($firewallProfiles)
        ListeningPorts           = @($listeningPorts)
        CollectionErrors         = @($collectionErrors)
    }
}

function Get-TriageAssessment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Result,

        [Parameter(Mandatory = $true)]
        [psobject]$Config
    )

    $findings = New-Object System.Collections.Generic.List[object]

    foreach ($disk in @($Result.Disks)) {
        if ($disk.Status -eq 'Critical') {
            [void]$findings.Add([pscustomobject]@{
                Severity = 'Critical'
                Category = 'Disk'
                Message  = ('{0} has only {1}% free ({2} GB).' -f $disk.Drive, $disk.PercentFree, $disk.FreeGB)
            })
        }
        elseif ($disk.Status -eq 'Warning') {
            [void]$findings.Add([pscustomobject]@{
                Severity = 'Warning'
                Category = 'Disk'
                Message  = ('{0} has {1}% free ({2} GB).' -f $disk.Drive, $disk.PercentFree, $disk.FreeGB)
            })
        }
    }

    foreach ($service in @($Result.RequiredServices)) {
        if (-not $service.Found) {
            [void]$findings.Add([pscustomobject]@{
                Severity = 'Critical'
                Category = 'Service'
                Message  = ("Required service '{0}' was not found." -f $service.Name)
            })
        }
        elseif ($service.Status -ne 'Running') {
            [void]$findings.Add([pscustomobject]@{
                Severity = 'Critical'
                Category = 'Service'
                Message  = ("Required service '{0}' is {1}." -f $service.Name, $service.Status)
            })
        }
    }

    if (@($Result.AutomaticServicesStopped).Count -gt 0) {
        [void]$findings.Add([pscustomobject]@{
            Severity = 'Warning'
            Category = 'Service'
            Message  = ('{0} automatic service(s) are not running. Review for trigger-start or intentionally stopped services.' -f @($Result.AutomaticServicesStopped).Count)
        })
    }

    if ($Result.PendingReboot) {
        [void]$findings.Add([pscustomobject]@{
            Severity = 'Warning'
            Category = 'Patching'
            Message  = ('A restart is pending: {0}.' -f (@($Result.PendingRebootReasons) -join ', '))
        })
    }

    if ($null -ne $Result.LastPatchDate) {
        $patchAge = [math]::Floor(((Get-Date) - [datetime]$Result.LastPatchDate).TotalDays)
        if ($patchAge -ge [int]$Config.PatchCriticalAgeDays) {
            [void]$findings.Add([pscustomobject]@{
                Severity = 'Critical'
                Category = 'Patching'
                Message  = ("Latest detected update is $patchAge days old.")
            })
        }
        elseif ($patchAge -ge [int]$Config.PatchWarningAgeDays) {
            [void]$findings.Add([pscustomobject]@{
                Severity = 'Warning'
                Category = 'Patching'
                Message  = ("Latest detected update is $patchAge days old.")
            })
        }
    }
    else {
        [void]$findings.Add([pscustomobject]@{
            Severity = 'Info'
            Category = 'Patching'
            Message  = 'No dated hotfix was returned. Confirm patch state using the organisation patch-management platform.'
        })
    }

    if ($null -ne $Result.SystemInfo) {
        $memoryFreePercent = 100 - [double]$Result.SystemInfo.MemoryUsedPercent
        if ($memoryFreePercent -le [int]$Config.MemoryWarningPercentFree) {
            [void]$findings.Add([pscustomobject]@{
                Severity = 'Warning'
                Category = 'Memory'
                Message  = ('Point-in-time free memory is {0}%.' -f [math]::Round($memoryFreePercent, 1))
            })
        }

        if ([double]$Result.SystemInfo.UptimeDays -ge [int]$Config.UptimeWarningDays) {
            [void]$findings.Add([pscustomobject]@{
                Severity = 'Warning'
                Category = 'Uptime'
                Message  = ('Server uptime is {0} days. Check the maintenance and reboot history.' -f $Result.SystemInfo.UptimeDays)
            })
        }
    }
    else {
        [void]$findings.Add([pscustomobject]@{
            Severity = 'Critical'
            Category = 'Collection'
            Message  = 'Core system information could not be collected. Review the collection notes and permissions.'
        })
    }

    if (@($Result.Events).Count -gt 0) {
        [void]$findings.Add([pscustomobject]@{
            Severity = 'Warning'
            Category = 'Events'
            Message  = ('{0} critical or error event(s) were returned for the configured lookback window.' -f @($Result.Events).Count)
        })
    }

    if (@($Result.CollectionErrors).Count -gt 0) {
        [void]$findings.Add([pscustomobject]@{
            Severity = 'Info'
            Category = 'Collection'
            Message  = ('{0} section(s) could not be collected. See collection notes.' -f @($Result.CollectionErrors).Count)
        })
    }

    $status = 'Healthy'
    foreach ($finding in $findings) {
        if ((Get-StatusRank -Status $finding.Severity) -gt (Get-StatusRank -Status $status)) {
            $status = $finding.Severity
        }
    }

    [pscustomobject]@{
        Status   = $status
        Findings = $findings.ToArray()
    }
}

function Add-Cell {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Text.StringBuilder]$Builder,

        [AllowNull()]
        [object]$Value,

        [switch]$Header
    )

    $tag = 'td'
    if ($Header) {
        $tag = 'th'
    }
    [void]$Builder.AppendFormat('<{0}>{1}</{0}>', $tag, (ConvertTo-HtmlText $Value))
}

function New-TriageHtmlReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Results,

        [Parameter(Mandatory = $true)]
        [psobject]$Config,

        [Parameter(Mandatory = $true)]
        [string]$Destination
    )

    $healthyCount = @($Results | Where-Object { $_.Status -eq 'Healthy' }).Count
    $warningCount = @($Results | Where-Object { $_.Status -eq 'Warning' }).Count
    $criticalCount = @($Results | Where-Object { $_.Status -eq 'Critical' }).Count
    $unreachableCount = @($Results | Where-Object { $_.Status -eq 'Unreachable' }).Count

    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append(@'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Server Triage Report</title>
<style>
:root{--ink:#172126;--muted:#647178;--paper:#f4f6f3;--card:#fff;--line:#dce3df;--green:#2f7d62;--green-bg:#e4f3ec;--amber:#a56500;--amber-bg:#fff2d8;--red:#b13a3a;--red-bg:#fde7e5;--blue:#315f75;--blue-bg:#e7f0f5;--shadow:0 8px 24px rgba(23,33,38,.08)}
*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:14px/1.5 "Segoe UI",Arial,sans-serif}main{max-width:1200px;margin:0 auto;padding:28px}.hero{background:linear-gradient(135deg,#172126,#315f75);color:white;border-radius:18px;padding:30px;box-shadow:var(--shadow)}.eyebrow{text-transform:uppercase;letter-spacing:.16em;font-size:11px;font-weight:700;color:#c8ddcf}.hero h1{margin:7px 0 4px;font-size:34px;line-height:1.1}.hero p{margin:0;color:#dbe5e9}.summary-grid{display:grid;grid-template-columns:repeat(5,minmax(120px,1fr));gap:14px;margin:20px 0}.metric,.server{background:var(--card);border:1px solid var(--line);border-radius:14px;box-shadow:var(--shadow)}.metric{padding:16px}.metric .number{font-size:28px;font-weight:800}.metric .label{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em}.server{margin:18px 0;overflow:hidden}.server-header{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;padding:20px 22px;border-bottom:1px solid var(--line)}.server-header h2{margin:0;font-size:22px}.server-header p{margin:3px 0 0;color:var(--muted)}.content{padding:20px 22px}.facts{display:grid;grid-template-columns:repeat(4,minmax(130px,1fr));gap:10px;margin-bottom:18px}.fact{background:#f8faf9;border:1px solid var(--line);border-radius:10px;padding:10px}.fact strong{display:block;font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}.fact span{font-size:15px;font-weight:600}.badge{display:inline-block;border-radius:999px;padding:5px 10px;font-size:12px;font-weight:800}.healthy{color:var(--green);background:var(--green-bg)}.warning{color:var(--amber);background:var(--amber-bg)}.critical,.unreachable{color:var(--red);background:var(--red-bg)}.info{color:var(--blue);background:var(--blue-bg)}table{width:100%;border-collapse:collapse;margin:10px 0 18px;font-size:13px}th{text-align:left;background:#eef2f0;color:#405057}th,td{border:1px solid var(--line);padding:8px;vertical-align:top}h3{font-size:16px;margin:20px 0 8px}.finding{display:flex;gap:10px;align-items:flex-start;border-bottom:1px solid var(--line);padding:9px 0}.finding:last-child{border:0}details{border-top:1px solid var(--line);padding:10px 0}summary{cursor:pointer;font-weight:700}.muted{color:var(--muted)}.empty{color:var(--muted);font-style:italic}.footer{padding:22px 0;color:var(--muted);font-size:12px;text-align:center}@media(max-width:800px){main{padding:12px}.summary-grid,.facts{grid-template-columns:repeat(2,1fr)}.hero h1{font-size:27px}.server-header{flex-direction:column}table{display:block;overflow-x:auto}}
@media print{body{background:white}main{max-width:none;padding:0}.hero,.metric,.server{box-shadow:none}.server{break-inside:avoid}details>summary{display:none}details>*{display:block!important}}
</style>
</head>
<body><main>
'@)

    [void]$builder.Append('<section class="hero">')
    [void]$builder.Append('<div class="eyebrow">Read-only operational snapshot</div>')
    [void]$builder.Append('<h1>Server Triage Report</h1>')
    [void]$builder.AppendFormat('<p>Run {0} | Generated {1} | Pack version {2}</p>', (ConvertTo-HtmlText $script:RunId), (ConvertTo-HtmlText (Get-Date -Format 'yyyy-MM-dd HH:mm:ss K')), (ConvertTo-HtmlText $script:PackVersion))
    [void]$builder.Append('</section>')

    [void]$builder.Append('<section class="summary-grid">')
    foreach ($metric in @(
        @('Targets', $Results.Count),
        @('Healthy', $healthyCount),
        @('Warnings', $warningCount),
        @('Critical', $criticalCount),
        @('Unreachable', $unreachableCount)
    )) {
        [void]$builder.AppendFormat('<div class="metric"><div class="number">{0}</div><div class="label">{1}</div></div>', (ConvertTo-HtmlText $metric[1]), (ConvertTo-HtmlText $metric[0]))
    }
    [void]$builder.Append('</section>')

    foreach ($result in $Results) {
        [void]$builder.Append('<article class="server">')
        [void]$builder.Append('<header class="server-header"><div>')
        [void]$builder.AppendFormat('<h2>{0}</h2>', (ConvertTo-HtmlText $result.ComputerName))
        [void]$builder.AppendFormat('<p>{0}{1}</p>', (ConvertTo-HtmlText $result.Environment), $(if ($result.Owner) { ' | Owner: ' + (ConvertTo-HtmlText $result.Owner) } else { '' }))
        [void]$builder.Append('</div>')
        [void]$builder.Append((Get-StatusBadgeHtml -Status $result.Status))
        [void]$builder.Append('</header><div class="content">')

        if ($result.Status -eq 'Unreachable') {
            [void]$builder.AppendFormat('<p><strong>Collection failed:</strong> {0}</p>', (ConvertTo-HtmlText $result.Error))
            [void]$builder.Append('</div></article>')
            continue
        }

        $system = $result.SystemInfo
        if ($null -eq $system) {
            [void]$builder.Append('<p><strong>Core system information was unavailable.</strong> Review the assessment and collection notes below.</p>')
            $system = [pscustomobject]@{
                OperatingSystem   = 'Unavailable'
                BuildNumber       = ''
                UptimeDays        = ''
                CpuLoadPercent    = $null
                MemoryUsedPercent = ''
                TotalMemoryGB     = ''
                Domain            = ''
            }
        }
        [void]$builder.Append('<div class="facts">')
        foreach ($fact in @(
            @('OS', ('{0} ({1})' -f $system.OperatingSystem, $system.BuildNumber)),
            @('Uptime', ('{0} days' -f $system.UptimeDays)),
            @('CPU load', $(if ($null -eq $system.CpuLoadPercent) { 'Unavailable' } else { '{0}%' -f $system.CpuLoadPercent })),
            @('Memory used', ('{0}% of {1} GB' -f $system.MemoryUsedPercent, $system.TotalMemoryGB)),
            @('Last patch', $(if ($null -eq $result.LastPatchDate) { 'Unavailable' } else { ([datetime]$result.LastPatchDate).ToString('yyyy-MM-dd') })),
            @('Pending reboot', $(if ($result.PendingReboot) { 'Yes' } else { 'No' })),
            @('Domain', $system.Domain),
            @('Collected', ([datetime]$result.CollectedAt).ToString('yyyy-MM-dd HH:mm:ss'))
        )) {
            [void]$builder.AppendFormat('<div class="fact"><strong>{0}</strong><span>{1}</span></div>', (ConvertTo-HtmlText $fact[0]), (ConvertTo-HtmlText $fact[1]))
        }
        [void]$builder.Append('</div>')

        [void]$builder.Append('<h3>Assessment</h3>')
        if (@($result.Findings).Count -eq 0) {
            [void]$builder.Append('<p class="empty">No findings crossed the configured thresholds.</p>')
        }
        else {
            foreach ($finding in @($result.Findings)) {
                [void]$builder.Append('<div class="finding">')
                [void]$builder.Append((Get-StatusBadgeHtml -Status $finding.Severity))
                [void]$builder.AppendFormat('<div><strong>{0}</strong><br>{1}</div>', (ConvertTo-HtmlText $finding.Category), (ConvertTo-HtmlText $finding.Message))
                [void]$builder.Append('</div>')
            }
        }

        [void]$builder.Append('<h3>Fixed disks</h3><table><thead><tr>')
        foreach ($heading in @('Drive', 'Volume', 'Size GB', 'Free GB', 'Free %', 'Status')) {
            Add-Cell -Builder $builder -Value $heading -Header
        }
        [void]$builder.Append('</tr></thead><tbody>')
        foreach ($disk in @($result.Disks)) {
            [void]$builder.Append('<tr>')
            foreach ($value in @($disk.Drive, $disk.VolumeName, $disk.SizeGB, $disk.FreeGB, $disk.PercentFree)) {
                Add-Cell -Builder $builder -Value $value
            }
            [void]$builder.AppendFormat('<td>{0}</td>', (Get-StatusBadgeHtml -Status $disk.Status))
            [void]$builder.Append('</tr>')
        }
        [void]$builder.Append('</tbody></table>')

        [void]$builder.Append('<details open><summary>Required services</summary><table><thead><tr>')
        foreach ($heading in @('Name', 'Display name', 'Status')) {
            Add-Cell -Builder $builder -Value $heading -Header
        }
        [void]$builder.Append('</tr></thead><tbody>')
        foreach ($service in @($result.RequiredServices)) {
            [void]$builder.Append('<tr>')
            Add-Cell -Builder $builder -Value $service.Name
            Add-Cell -Builder $builder -Value $service.DisplayName
            Add-Cell -Builder $builder -Value $service.Status
            [void]$builder.Append('</tr>')
        }
        [void]$builder.Append('</tbody></table></details>')

        [void]$builder.Append('<details><summary>Automatic services not running (')
        [void]$builder.Append(@($result.AutomaticServicesStopped).Count)
        [void]$builder.Append(')</summary>')
        if (@($result.AutomaticServicesStopped).Count -eq 0) {
            [void]$builder.Append('<p class="empty">None returned.</p>')
        }
        else {
            [void]$builder.Append('<table><thead><tr>')
            foreach ($heading in @('Name', 'Display name', 'State', 'Run as')) {
                Add-Cell -Builder $builder -Value $heading -Header
            }
            [void]$builder.Append('</tr></thead><tbody>')
            foreach ($service in @($result.AutomaticServicesStopped)) {
                [void]$builder.Append('<tr>')
                foreach ($value in @($service.Name, $service.DisplayName, $service.State, $service.StartName)) {
                    Add-Cell -Builder $builder -Value $value
                }
                [void]$builder.Append('</tr>')
            }
            [void]$builder.Append('</tbody></table>')
        }
        [void]$builder.Append('</details>')

        [void]$builder.AppendFormat('<details><summary>Critical and error events ({0})</summary>', @($result.Events).Count)
        if (@($result.Events).Count -eq 0) {
            [void]$builder.Append('<p class="empty">No matching events returned.</p>')
        }
        else {
            [void]$builder.Append('<table><thead><tr>')
            foreach ($heading in @('Time', 'Log', 'Level', 'ID', 'Provider', 'Message')) {
                Add-Cell -Builder $builder -Value $heading -Header
            }
            [void]$builder.Append('</tr></thead><tbody>')
            foreach ($event in @($result.Events)) {
                [void]$builder.Append('<tr>')
                foreach ($value in @(([datetime]$event.TimeCreated).ToString('yyyy-MM-dd HH:mm:ss'), $event.LogName, $event.Level, $event.Id, $event.ProviderName, $event.Message)) {
                    Add-Cell -Builder $builder -Value $value
                }
                [void]$builder.Append('</tr>')
            }
            [void]$builder.Append('</tbody></table>')
        }
        [void]$builder.Append('</details>')

        [void]$builder.AppendFormat('<details><summary>Recent dated hotfixes ({0})</summary>', @($result.Hotfixes).Count)
        if (@($result.Hotfixes).Count -gt 0) {
            [void]$builder.Append('<table><thead><tr>')
            foreach ($heading in @('Hotfix', 'Description', 'Installed by', 'Installed on')) {
                Add-Cell -Builder $builder -Value $heading -Header
            }
            [void]$builder.Append('</tr></thead><tbody>')
            foreach ($hotfix in @($result.Hotfixes)) {
                [void]$builder.Append('<tr>')
                foreach ($value in @($hotfix.HotFixID, $hotfix.Description, $hotfix.InstalledBy, $hotfix.InstalledOn)) {
                    Add-Cell -Builder $builder -Value $value
                }
                [void]$builder.Append('</tr>')
            }
            [void]$builder.Append('</tbody></table>')
        }
        else {
            [void]$builder.Append('<p class="empty">No dated hotfix records returned.</p>')
        }
        [void]$builder.Append('</details>')

        [void]$builder.AppendFormat('<details><summary>Network adapters ({0})</summary>', @($result.NetworkAdapters).Count)
        if (@($result.NetworkAdapters).Count -gt 0) {
            [void]$builder.Append('<table><thead><tr>')
            foreach ($heading in @('Adapter', 'IP addresses', 'Gateways', 'DNS servers', 'DHCP', 'MAC')) {
                Add-Cell -Builder $builder -Value $heading -Header
            }
            [void]$builder.Append('</tr></thead><tbody>')
            foreach ($adapter in @($result.NetworkAdapters)) {
                [void]$builder.Append('<tr>')
                foreach ($value in @($adapter.Description, $adapter.IPAddresses, $adapter.Gateways, $adapter.DnsServers, $adapter.DHCPEnabled, $adapter.MacAddress)) {
                    Add-Cell -Builder $builder -Value $value
                }
                [void]$builder.Append('</tr>')
            }
            [void]$builder.Append('</tbody></table>')
        }
        [void]$builder.Append('</details>')

        [void]$builder.AppendFormat('<details><summary>Windows Firewall profiles ({0})</summary>', @($result.FirewallProfiles).Count)
        if (@($result.FirewallProfiles).Count -gt 0) {
            [void]$builder.Append('<table><thead><tr>')
            foreach ($heading in @('Profile', 'Enabled', 'Default inbound', 'Default outbound')) {
                Add-Cell -Builder $builder -Value $heading -Header
            }
            [void]$builder.Append('</tr></thead><tbody>')
            foreach ($profile in @($result.FirewallProfiles)) {
                [void]$builder.Append('<tr>')
                foreach ($value in @($profile.Name, $profile.Enabled, $profile.DefaultInboundAction, $profile.DefaultOutboundAction)) {
                    Add-Cell -Builder $builder -Value $value
                }
                [void]$builder.Append('</tr>')
            }
            [void]$builder.Append('</tbody></table>')
        }
        else {
            [void]$builder.Append('<p class="empty">No firewall profile data returned.</p>')
        }
        [void]$builder.Append('</details>')

        [void]$builder.AppendFormat('<details><summary>Listening ports ({0})</summary>', @($result.ListeningPorts).Count)
        if (@($result.ListeningPorts).Count -gt 0) {
            [void]$builder.Append('<table><thead><tr>')
            foreach ($heading in @('Address', 'Port', 'Process ID', 'Process')) {
                Add-Cell -Builder $builder -Value $heading -Header
            }
            [void]$builder.Append('</tr></thead><tbody>')
            foreach ($port in @($result.ListeningPorts)) {
                [void]$builder.Append('<tr>')
                foreach ($value in @($port.LocalAddress, $port.LocalPort, $port.ProcessId, $port.ProcessName)) {
                    Add-Cell -Builder $builder -Value $value
                }
                [void]$builder.Append('</tr>')
            }
            [void]$builder.Append('</tbody></table>')
        }
        [void]$builder.Append('</details>')

        [void]$builder.AppendFormat('<details><summary>Collection notes ({0})</summary>', @($result.CollectionErrors).Count)
        if (@($result.CollectionErrors).Count -eq 0) {
            [void]$builder.Append('<p class="empty">All requested sections completed.</p>')
        }
        else {
            [void]$builder.Append('<ul>')
            foreach ($collectionError in @($result.CollectionErrors)) {
                [void]$builder.AppendFormat('<li>{0}</li>', (ConvertTo-HtmlText $collectionError))
            }
            [void]$builder.Append('</ul>')
        }
        [void]$builder.Append('</details>')
        [void]$builder.Append('</div></article>')
    }

    [void]$builder.AppendFormat('<div class="footer">Read-only Server Triage Pack {0}. Thresholds are indicators, not incident conclusions. Validate findings before taking action.</div>', (ConvertTo-HtmlText $script:PackVersion))
    [void]$builder.Append('</main></body></html>')

    Set-Content -LiteralPath $Destination -Value $builder.ToString() -Encoding UTF8
}

try {
    $isWindows = [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
    if (-not $isWindows) {
        throw 'Server Triage Pack must be launched from Windows because it uses Windows PowerShell remoting and Windows management cmdlets.'
    }

    if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
        throw "Configuration file not found: $ConfigPath"
    }

    $config = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-TriageConfig -Config $config

    $targets = @(Get-TriageTargets)
    if (-not (Test-Path -LiteralPath $OutputPath -PathType Container)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    $script:RunDirectory = Join-Path $OutputPath ("Run_{0}" -f $script:RunId)
    New-Item -ItemType Directory -Path $script:RunDirectory -Force | Out-Null
    $jsonDirectory = Join-Path $script:RunDirectory 'json'
    New-Item -ItemType Directory -Path $jsonDirectory -Force | Out-Null
    $script:LogPath = Join-Path $script:RunDirectory 'triage-run.log'

    Write-TriageLog -Message ("Server Triage Pack {0} started for {1} target(s)." -f $script:PackVersion, $targets.Count)
    Write-TriageLog -Message 'Collection is read-only. No remediation actions are included.'

    $results = New-Object System.Collections.Generic.List[object]
    foreach ($target in $targets) {
        $name = [string]$target.ComputerName
        Write-TriageLog -Message ("Collecting from {0}." -f $name)

        $pingResult = $null
        if (-not $SkipPing -and -not (Test-IsLocalTarget -Name $name)) {
            try {
                $pingResult = [bool](Test-Connection -ComputerName $name -Count 1 -Quiet -ErrorAction Stop)
            }
            catch {
                $pingResult = $false
            }

            if (-not $pingResult) {
                Write-TriageLog -Level 'WARN' -Message ("{0} did not answer ICMP. Remoting will still be attempted." -f $name)
            }
        }

        try {
            if (Test-IsLocalTarget -Name $name) {
                $rawResult = & $collectorScript $config
            }
            else {
                $invokeParameters = @{
                    ComputerName = $name
                    ScriptBlock  = $collectorScript
                    ArgumentList = @($config)
                    ErrorAction  = 'Stop'
                }
                if ($Credential) {
                    $invokeParameters.Credential = $Credential
                }
                if ($UseSSL) {
                    $invokeParameters.UseSSL = $true
                }

                $rawResult = Invoke-Command @invokeParameters
            }

            $assessment = Get-TriageAssessment -Result $rawResult -Config $config
            $result = [pscustomobject]@{
                ComputerName            = $name
                Environment             = [string]$target.Environment
                Owner                   = [string]$target.Owner
                PingResponded            = $pingResult
                Status                   = [string]$assessment.Status
                Findings                 = @($assessment.Findings)
                CollectedAt              = $rawResult.CollectedAt
                SystemInfo               = $rawResult.SystemInfo
                Disks                    = @($rawResult.Disks)
                RequiredServices         = @($rawResult.RequiredServices)
                AutomaticServicesStopped = @($rawResult.AutomaticServicesStopped)
                Events                   = @($rawResult.Events)
                Hotfixes                 = @($rawResult.Hotfixes)
                LastPatchDate            = $rawResult.LastPatchDate
                PendingReboot            = [bool]$rawResult.PendingReboot
                PendingRebootReasons     = @($rawResult.PendingRebootReasons)
                NetworkAdapters          = @($rawResult.NetworkAdapters)
                FirewallProfiles         = @($rawResult.FirewallProfiles)
                ListeningPorts           = @($rawResult.ListeningPorts)
                CollectionErrors         = @($rawResult.CollectionErrors)
                Error                    = $null
            }

            [void]$results.Add($result)
            $hostJsonPath = Join-Path $jsonDirectory ("{0}.json" -f ($name -replace '[^a-zA-Z0-9._-]', '_'))
            $result | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $hostJsonPath -Encoding UTF8
            Write-TriageLog -Message ("{0} completed with status {1}." -f $name, $result.Status)
        }
        catch {
            $message = $_.Exception.Message
            Write-TriageLog -Level 'ERROR' -Message ("{0} collection failed: {1}" -f $name, $message)
            $failedResult = [pscustomobject]@{
                ComputerName            = $name
                Environment             = [string]$target.Environment
                Owner                   = [string]$target.Owner
                PingResponded            = $pingResult
                Status                   = 'Unreachable'
                Findings                 = @()
                CollectedAt              = Get-Date
                SystemInfo               = $null
                Disks                    = @()
                RequiredServices         = @()
                AutomaticServicesStopped = @()
                Events                   = @()
                Hotfixes                 = @()
                LastPatchDate            = $null
                PendingReboot            = $false
                PendingRebootReasons     = @()
                NetworkAdapters          = @()
                FirewallProfiles         = @()
                ListeningPorts           = @()
                CollectionErrors         = @()
                Error                    = $message
            }
            [void]$results.Add($failedResult)
            $hostJsonPath = Join-Path $jsonDirectory ("{0}.json" -f ($name -replace '[^a-zA-Z0-9._-]', '_'))
            $failedResult | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $hostJsonPath -Encoding UTF8
        }
    }

    $orderedResults = @($results | Sort-Object -Property @{ Expression = { Get-StatusRank -Status $_.Status }; Descending = $true }, ComputerName)
    $htmlPath = Join-Path $script:RunDirectory 'Server-Triage-Report.html'
    New-TriageHtmlReport -Results $orderedResults -Config $config -Destination $htmlPath

    $summaryPath = Join-Path $script:RunDirectory 'Server-Triage-Summary.csv'
    $summaryRows = @(
        foreach ($result in $orderedResults) {
            [pscustomobject]@{
                ComputerName             = $result.ComputerName
                Environment              = $result.Environment
                Owner                    = $result.Owner
                Status                   = $result.Status
                CollectedAt              = $result.CollectedAt
                OperatingSystem          = $(if ($null -eq $result.SystemInfo) { '' } else { $result.SystemInfo.OperatingSystem })
                BuildNumber              = $(if ($null -eq $result.SystemInfo) { '' } else { $result.SystemInfo.BuildNumber })
                UptimeDays               = $(if ($null -eq $result.SystemInfo) { '' } else { $result.SystemInfo.UptimeDays })
                CpuLoadPercent           = $(if ($null -eq $result.SystemInfo) { '' } else { $result.SystemInfo.CpuLoadPercent })
                MemoryUsedPercent        = $(if ($null -eq $result.SystemInfo) { '' } else { $result.SystemInfo.MemoryUsedPercent })
                LowestDiskFreePercent    = $(if (@($result.Disks).Count -eq 0) { '' } else { (@($result.Disks.PercentFree) | Measure-Object -Minimum).Minimum })
                LastPatchDate            = $result.LastPatchDate
                PendingReboot            = $result.PendingReboot
                RequiredServicesStopped  = @($result.RequiredServices | Where-Object { $_.Status -ne 'Running' }).Count
                AutomaticServicesStopped = @($result.AutomaticServicesStopped).Count
                MatchingEvents           = @($result.Events).Count
                Findings                 = @($result.Findings).Count
                Error                    = $result.Error
            }
        }
    )
    $summaryRows | Export-Csv -LiteralPath $summaryPath -NoTypeInformation -Encoding UTF8

    $manifestPath = Join-Path $script:RunDirectory 'run-manifest.json'
    [pscustomobject]@{
        ProjectVersion = $script:PackVersion
        RunId          = $script:RunId
        StartedAt      = $script:StartedAt
        CompletedAt    = Get-Date
        LaunchedBy     = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        LaunchComputer = $env:COMPUTERNAME
        Targets        = @($targets.ComputerName)
        Config         = $config
        OutputFiles    = @('Server-Triage-Report.html', 'Server-Triage-Summary.csv', 'triage-run.log', 'run-manifest.json', 'json\<computer>.json')
    } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

    Write-TriageLog -Message ("Report created: {0}" -f $htmlPath)
    Write-TriageLog -Message ("Summary created: {0}" -f $summaryPath)

    if ($OpenReport) {
        Start-Process -FilePath $htmlPath
    }

    [pscustomobject]@{
        RunDirectory = $script:RunDirectory
        HtmlReport   = $htmlPath
        CsvSummary   = $summaryPath
        Log          = $script:LogPath
        Targets      = $orderedResults.Count
        Healthy      = @($orderedResults | Where-Object { $_.Status -eq 'Healthy' }).Count
        Warning      = @($orderedResults | Where-Object { $_.Status -eq 'Warning' }).Count
        Critical     = @($orderedResults | Where-Object { $_.Status -eq 'Critical' }).Count
        Unreachable  = @($orderedResults | Where-Object { $_.Status -eq 'Unreachable' }).Count
    }
}
catch {
    if ($script:LogPath) {
        Write-TriageLog -Level 'ERROR' -Message $_.Exception.Message
    }
    else {
        Write-Error $_.Exception.Message
    }
    exit 1
}


if (Test-Path $htmlPath) {
    Start-Process $htmlPath
}