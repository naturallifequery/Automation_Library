#requires -Version 5.1
#requires -RunAsAdministrator

<#
.SYNOPSIS
    Interactive, read-only Hyper-V health check for elevated PowerShell ISE.

.DESCRIPTION
    Prompts for a VM name, expected managing user, VM folder, event lookback
    and report folder. It checks Hyper-V, VMMS, VM registration, storage,
    permissions, networking and recent errors, then creates an HTML report.

    The script never starts, stops, restarts, imports, removes or reconfigures
    a VM or service. It never edits ACLs, Windows features, boot settings or
    networking. Its only persistent output is the HTML report.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:Findings = @()
$script:ErrorsFound = @()

function Add-Finding {
    param(
        [ValidateSet('Critical','Warning','Info','Pass')][string]$Severity,
        [string]$Area,
        [string]$Finding,
        [string]$Evidence,
        [string]$Advice
    )
    $script:Findings += [pscustomobject]@{
        Severity = $Severity
        Area = $Area
        Finding = $Finding
        Evidence = $Evidence
        Advice = $Advice
    }
}

function Add-CollectionError {
    param([string]$Area, [System.Management.Automation.ErrorRecord]$Record)
    $script:ErrorsFound += [pscustomobject]@{
        Area = $Area
        Error = $Record.Exception.Message
    }
}

function Get-SafeValue {
    param([object]$Object, [string]$Property, $Default = $null)
    if ($null -eq $Object) { return $Default }
    $item = $Object.PSObject.Properties[$Property]
    if ($null -eq $item -or $null -eq $item.Value) { return $Default }
    return $item.Value
}

function Format-Bytes {
    param($Bytes)
    if ($null -eq $Bytes) { return 'Unknown' }
    $value = [double]$Bytes
    if ($value -ge 1TB) { return ('{0:N2} TB' -f ($value / 1TB)) }
    if ($value -ge 1GB) { return ('{0:N2} GB' -f ($value / 1GB)) }
    if ($value -ge 1MB) { return ('{0:N2} MB' -f ($value / 1MB)) }
    return ('{0:N0} bytes' -f $value)
}

function Read-RequiredValue {
    param([string]$Prompt, [string]$DefaultValue)
    do {
        if ([string]::IsNullOrWhiteSpace($DefaultValue)) {
            $answer = Read-Host $Prompt
        }
        else {
            $answer = Read-Host ("{0} [{1}]" -f $Prompt, $DefaultValue)
            if ([string]::IsNullOrWhiteSpace($answer)) { $answer = $DefaultValue }
        }
        if (-not [string]::IsNullOrWhiteSpace($answer)) { return $answer.Trim() }
        Write-Host 'A value is required.' -ForegroundColor Yellow
    } while ($true)
}

function Test-AccountMatch {
    param([string]$Member, [string]$Expected)
    if ([string]::IsNullOrWhiteSpace($Member) -or
        [string]::IsNullOrWhiteSpace($Expected)) { return $false }
    if ($Member -ieq $Expected) { return $true }
    $memberLeaf = ($Member -split '\\')[-1]
    $expectedLeaf = (($Expected -split '\\')[-1] -split '@')[0]
    return $memberLeaf -ieq $expectedLeaf
}

function Convert-ToTable {
    param([object[]]$Data, [string[]]$Properties, [string]$EmptyText = 'No data returned.')
    if ($null -eq $Data -or @($Data).Count -eq 0) {
        return ('<p class="empty">{0}</p>' -f [System.Net.WebUtility]::HtmlEncode($EmptyText))
    }
    return (($Data | Select-Object $Properties | ConvertTo-Html -Fragment) -join [Environment]::NewLine)
}

function Get-PendingRestart {
    $reasons = @()
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
        $reasons += 'Component Based Servicing'
    }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
        $reasons += 'Windows Update'
    }
    return @($reasons)
}

Clear-Host
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host '   Hyper-V Interactive Health Check - READ ONLY' -ForegroundColor Cyan
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host 'This run cannot restart services or change Hyper-V.' -ForegroundColor Green
Write-Host 'Its only persistent output is one local HTML report.' -ForegroundColor Green
Write-Host ''

$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
$isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    throw 'ISE is not elevated. Close it, right-click Windows PowerShell ISE, choose Run as administrator, reopen this file and press F5.'
}

Add-Finding 'Pass' 'Execution' 'ISE is elevated' $identity.Name 'No action required.'

$moduleLoaded = $false
$registeredVMs = @()
$vmHost = $null
try {
    Import-Module Hyper-V -ErrorAction Stop
    $moduleLoaded = $true
    $registeredVMs = @(Get-VM -ErrorAction Stop)
    $vmHost = Get-VMHost -ErrorAction Stop
    Add-Finding 'Pass' 'Management tools' 'Hyper-V PowerShell loaded successfully' `
        ([string](Get-Module Hyper-V | Select-Object -First 1 -ExpandProperty Version)) `
        'No action required.'
}
catch {
    Add-Finding 'Critical' 'Management tools' 'Hyper-V management could not be queried' `
        $_.Exception.Message 'Check the Hyper-V management tools and VMMS.'
    Add-CollectionError 'Initial Hyper-V query' $_
}

if ($registeredVMs.Count -gt 0) {
    Write-Host 'VMs currently visible to Hyper-V:' -ForegroundColor Cyan
    $registeredVMs | Select-Object Name, State, Status | Format-Table -AutoSize | Out-Host
}
else {
    Write-Host 'No registered VMs were returned. Enter the expected VM name.' -ForegroundColor Yellow
}

$defaultVM = ''
if ($registeredVMs.Count -eq 1) { $defaultVM = [string]$registeredVMs[0].Name }
$vmName = Read-RequiredValue 'VM name to diagnose' $defaultVM

try { $defaultUser = [string](Get-CimInstance Win32_ComputerSystem).UserName }
catch { $defaultUser = '{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME }
$expectedUser = Read-RequiredValue 'User expected to manage Hyper-V (DOMAIN\username)' $defaultUser

$targetVM = @($registeredVMs | Where-Object Name -ieq $vmName | Select-Object -First 1)
$defaultVMFolder = ''
if ($targetVM.Count -gt 0) { $defaultVMFolder = [string]$targetVM[0].ConfigurationLocation }
elseif ($null -ne $vmHost) { $defaultVMFolder = [string]$vmHost.VirtualMachinePath }
if ([string]::IsNullOrWhiteSpace($defaultVMFolder)) {
    $defaultVMFolder = Join-Path $env:ProgramData 'Microsoft\Windows\Hyper-V'
}
$vmFolder = Read-RequiredValue 'Expected VM folder to search' $defaultVMFolder

do {
    $daysText = Read-Host 'Days of Hyper-V events to check [7]'
    if ([string]::IsNullOrWhiteSpace($daysText)) { $days = 7; $daysValid = $true }
    else {
        $days = 0
        $daysValid = [int]::TryParse($daysText, [ref]$days)
        if (-not $daysValid -or $days -lt 1 -or $days -gt 30) {
            $daysValid = $false
            Write-Host 'Enter a whole number from 1 to 30.' -ForegroundColor Yellow
        }
    }
} while (-not $daysValid)

$defaultReportFolder = [Environment]::GetFolderPath('Desktop')
if ([string]::IsNullOrWhiteSpace($defaultReportFolder)) { $defaultReportFolder = $env:TEMP }
$reportFolder = Read-RequiredValue 'Folder for the HTML report' $defaultReportFolder
if (-not (Test-Path -LiteralPath $reportFolder -PathType Container)) {
    Add-Finding 'Warning' 'Report' 'Requested report folder does not exist' $reportFolder `
        ("Using {0} instead." -f $env:TEMP)
    $reportFolder = $env:TEMP
}

Write-Host ''
Write-Host 'Collecting read-only Hyper-V data...' -ForegroundColor Cyan

$hostRows = @()
$featureRows = @()
$serviceRows = @()
$permissionRows = @()
$vmRows = @()
$diskRows = @()
$networkRows = @()
$fileRows = @()
$eventRows = @()
$vmmsState = 'Unknown'
$allDisksPresent = $true

try {
    $os = Get-CimInstance Win32_OperatingSystem
    $system = Get-CimInstance Win32_ComputerSystem
    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
    $pendingRestart = @(Get-PendingRestart)
    $launchType = 'Unknown'
    try {
        $bcd = @(& "$env:SystemRoot\System32\bcdedit.exe" /enum '{current}' 2>&1)
        $launchLine = @($bcd | Where-Object { $_ -match '^hypervisorlaunchtype\s+' } | Select-Object -First 1)
        if ($launchLine.Count -gt 0 -and $launchLine[0] -match '^hypervisorlaunchtype\s+(\S+)') {
            $launchType = $Matches[1]
        }
        elseif ($LASTEXITCODE -eq 0) { $launchType = 'Default/Auto' }
    }
    catch { Add-CollectionError 'Boot configuration' $_ }

    $hypervisorPresent = Get-SafeValue $system 'HypervisorPresent' 'Unknown'
    $hostRows += [pscustomobject]@{
        Computer = $env:COMPUTERNAME
        OperatingSystem = $os.Caption
        Version = $os.Version
        Build = $os.BuildNumber
        LastBoot = $os.LastBootUpTime
        HypervisorPresent = $hypervisorPresent
        HypervisorLaunchType = $launchType
        FirmwareVirtualization = Get-SafeValue $cpu 'VirtualizationFirmwareEnabled' 'Unknown'
        PendingRestart = if ($pendingRestart.Count) { $pendingRestart -join '; ' } else { 'No' }
        DiagnosticAccount = $identity.Name
    }
    if ($hypervisorPresent -eq $true) {
        Add-Finding 'Pass' 'Hypervisor' 'Windows reports an active hypervisor' 'HypervisorPresent=True' 'No action required.'
    }
    else {
        Add-Finding 'Critical' 'Hypervisor' 'Windows does not report an active hypervisor' `
            ("hypervisorlaunchtype={0}" -f $launchType) 'Check the feature, firmware virtualization and pending reboot.'
    }
    if ($launchType -eq 'Off') {
        Add-Finding 'Critical' 'Hypervisor' 'Hypervisor boot launch is disabled' 'hypervisorlaunchtype=Off' `
            'Raise a controlled change to correct it; this script makes no boot changes.'
    }
    if ($pendingRestart.Count) {
        Add-Finding 'Warning' 'Host' 'Windows has a pending restart' ($pendingRestart -join '; ') `
            'Complete a controlled reboot before deciding Hyper-V needs reinstalling.'
    }
}
catch { Add-CollectionError 'Host information' $_ }

try {
    if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
        $feature = Get-WindowsFeature Hyper-V
        $featureRows += [pscustomobject]@{ Source='Server role'; Name=$feature.DisplayName; State=$feature.InstallState }
        if ($feature.Installed) { Add-Finding 'Pass' 'Feature' 'Hyper-V role is installed' $feature.InstallState 'No action required.' }
        else { Add-Finding 'Critical' 'Feature' 'Hyper-V role is not installed' $feature.InstallState 'Confirm the intended host design.' }
    }
    else {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All
        $featureRows += [pscustomobject]@{ Source='Optional feature'; Name=$feature.FeatureName; State=$feature.State }
        if ([string]$feature.State -eq 'Enabled') { Add-Finding 'Pass' 'Feature' 'Hyper-V is enabled' $feature.State 'No action required.' }
        else { Add-Finding 'Critical' 'Feature' 'Hyper-V is not enabled' $feature.State 'Confirm the Windows edition and intended design.' }
    }
}
catch {
    Add-CollectionError 'Hyper-V feature' $_
    Add-Finding 'Warning' 'Feature' 'Feature state could not be confirmed' $_.Exception.Message 'Check it manually.'
}

try {
    $services = @(Get-CimInstance Win32_Service -Filter "Name='vmms' OR Name='vmcompute'")
    foreach ($service in $services) {
        $serviceRows += [pscustomobject]@{
            Name=$service.Name; DisplayName=$service.DisplayName; State=$service.State
            StartMode=$service.StartMode; Account=$service.StartName; ProcessId=$service.ProcessId
        }
    }
    $vmms = @($services | Where-Object Name -eq 'vmms' | Select-Object -First 1)
    if (-not $vmms.Count) {
        $vmmsState = 'Not found'
        Add-Finding 'Critical' 'Services' 'VMMS was not found' 'No vmms service record returned' 'Check the Hyper-V platform installation.'
    }
    else {
        $vmmsState = [string]$vmms[0].State
        if ($vmmsState -eq 'Running') {
            Add-Finding 'Pass' 'Services' 'VMMS is running' ("StartMode={0}" -f $vmms[0].StartMode) 'No action required.'
        }
        else {
            Add-Finding 'Critical' 'Services' 'VMMS is not running' ("State={0}; StartMode={1}" -f $vmmsState,$vmms[0].StartMode) `
                'Review VMMS events before starting or repairing the service.'
        }
        if ($vmms[0].StartMode -ne 'Auto') {
            Add-Finding 'Warning' 'Services' 'VMMS is not set to automatic startup' $vmms[0].StartMode `
                'Confirm the approved service configuration; this script makes no change.'
        }
    }
}
catch { Add-CollectionError 'Hyper-V services' $_ }

try {
    $hvGroup = Get-LocalGroup -SID 'S-1-5-32-578'
    $hvMembers = @(Get-LocalGroupMember -SID 'S-1-5-32-578')
    $adminGroup = Get-LocalGroup -SID 'S-1-5-32-544'
    $adminMembers = @(Get-LocalGroupMember -SID 'S-1-5-32-544')
    foreach ($member in $hvMembers) {
        $permissionRows += [pscustomobject]@{ Group=$hvGroup.Name; Member=$member.Name; Type=$member.ObjectClass }
    }
    foreach ($member in $adminMembers) {
        $permissionRows += [pscustomobject]@{ Group=$adminGroup.Name; Member=$member.Name; Type=$member.ObjectClass }
    }
    $inHvGroup = @($hvMembers | Where-Object { Test-AccountMatch $_.Name $expectedUser }).Count -gt 0
    $inAdminGroup = @($adminMembers | Where-Object { Test-AccountMatch $_.Name $expectedUser }).Count -gt 0
    if ($inHvGroup) {
        Add-Finding 'Pass' 'Permissions' 'Expected user is a direct Hyper-V Administrators member' $expectedUser `
            'Sign out and back in if membership was added recently.'
    }
    elseif ($inAdminGroup) {
        Add-Finding 'Info' 'Permissions' 'Expected user is a local Administrator, but not a direct Hyper-V Administrators member' `
            $expectedUser 'Elevated management should work; use Hyper-V Administrators for least-privilege access.'
    }
    else {
        Add-Finding 'Warning' 'Permissions' 'Expected user is not a direct member of either local management group' `
            $expectedUser 'Check approved nested domain groups and refresh the user logon token.'
    }
}
catch {
    Add-CollectionError 'Hyper-V group membership' $_
    Add-Finding 'Warning' 'Permissions' 'Local group membership could not be checked' $_.Exception.Message 'Check it manually.'
}

if (-not $targetVM.Count) {
    Add-Finding 'Critical' 'VM registration' 'Requested VM is not registered or visible' `
        ("Get-VM did not return '{0}'" -f $vmName) 'Check VMMS, storage and any discovered VMCX file before rebuilding.'
}
else {
    $vm = $targetVM[0]
    try { $checkpoints = @(Get-VMSnapshot -VM $vm) }
    catch { $checkpoints = @(); Add-CollectionError 'VM checkpoints' $_ }

    $vmRows += [pscustomobject]@{
        Name=$vm.Name; Id=$vm.Id; Visible='Yes'; State=$vm.State; Status=$vm.Status
        Generation=$vm.Generation; Version=$vm.Version
        ConfigurationLocation=$vm.ConfigurationLocation
        AutomaticStartAction=$vm.AutomaticStartAction
        AutomaticStartDelay=$vm.AutomaticStartDelay
        AutomaticStopAction=$vm.AutomaticStopAction
        Checkpoints=$checkpoints.Count
    }
    Add-Finding 'Pass' 'VM registration' 'Requested VM is registered and visible' `
        ("{0}; ID={1}; State={2}" -f $vm.Name,$vm.Id,$vm.State) `
        'If only the standard user cannot see it, focus on permissions and logon context.'

    if (-not (Test-Path -LiteralPath $vm.ConfigurationLocation)) {
        Add-Finding 'Critical' 'VM storage' 'VM configuration location is unavailable' $vm.ConfigurationLocation `
            'Check the disk, mount point, BitLocker and storage availability at boot.'
    }
    if ([string]$vm.State -match 'Critical') {
        Add-Finding 'Critical' 'VM state' 'VM is in a critical state' ("{0}; {1}" -f $vm.State,$vm.Status) `
            'Review storage, checkpoint chain and VMMS events before making changes.'
    }
    elseif ([string]$vm.State -eq 'Saved') {
        Add-Finding 'Warning' 'VM state' 'VM is in a saved state' $vm.State `
            'Investigate saved-state errors before deliberately discarding in-memory state.'
    }
    if ([string]$vm.AutomaticStartAction -eq 'Nothing') {
        Add-Finding 'Warning' 'VM startup' 'VM is configured not to start with the host' 'AutomaticStartAction=Nothing' `
            'If startup is expected, raise a controlled configuration change after diagnosis.'
    }
    if ($checkpoints.Count) {
        Add-Finding 'Info' 'Checkpoints' 'VM has checkpoints' ("{0} checkpoint(s)" -f $checkpoints.Count) `
            'Confirm they are intentional and retain the complete VHDX/AVHDX chain.'
    }

    try {
        $logicalDisks = @(Get-CimInstance Win32_LogicalDisk)
        $hardDisks = @(Get-VMHardDiskDrive -VM $vm)
        foreach ($hardDisk in $hardDisks) {
            $exists = -not [string]::IsNullOrWhiteSpace($hardDisk.Path) -and (Test-Path -LiteralPath $hardDisk.Path)
            if (-not $exists) { $allDisksPresent = $false }
            $vhd = $null
            if ($exists) {
                try { $vhd = Get-VHD -Path $hardDisk.Path }
                catch { Add-CollectionError ("VHD metadata: {0}" -f $hardDisk.Path) $_ }
            }

            $storageType = 'Unknown'; $freePercent = $null; $freeSpace = 'Unknown'; $fileSystem = 'Unknown'
            if ($hardDisk.Path -like '\\*') { $storageType = 'Network/UNC' }
            elseif (-not [string]::IsNullOrWhiteSpace($hardDisk.Path)) {
                $root = [System.IO.Path]::GetPathRoot($hardDisk.Path)
                $drive = @($logicalDisks | Where-Object DeviceID -eq $root.TrimEnd('\') | Select-Object -First 1)
                if ($drive.Count) {
                    $types = @{ 2='Removable'; 3='Fixed local'; 4='Network'; 5='Optical' }
                    $driveType = [int]$drive[0].DriveType
                    if ($types.ContainsKey($driveType)) { $storageType = $types[$driveType] }
                    else { $storageType = 'Other' }
                    $fileSystem = $drive[0].FileSystem
                    $freeSpace = Format-Bytes $drive[0].FreeSpace
                    if ([double]$drive[0].Size -gt 0) {
                        $freePercent = [math]::Round(([double]$drive[0].FreeSpace/[double]$drive[0].Size)*100,1)
                    }
                }
            }

            $parentPath = [string](Get-SafeValue $vhd 'ParentPath' '')
            $diskRows += [pscustomobject]@{
                Attached='Yes'; Controller=('{0} {1}:{2}' -f $hardDisk.ControllerType,$hardDisk.ControllerNumber,$hardDisk.ControllerLocation)
                Path=$hardDisk.Path; Exists=$exists; VHDType=Get-SafeValue $vhd 'VhdType' 'Unknown'
                FileSize=Format-Bytes (Get-SafeValue $vhd 'FileSize' $null)
                MaximumSize=Format-Bytes (Get-SafeValue $vhd 'Size' $null)
                ParentPath=$parentPath; StorageType=$storageType; FileSystem=$fileSystem
                FreeSpace=$freeSpace; FreePercent=$freePercent
            }
            if (-not $exists) {
                Add-Finding 'Critical' 'VM storage' 'Attached VM disk is missing or inaccessible' $hardDisk.Path `
                    'Check the expected volume and path. Do not create a blank disk with this filename.'
            }
            if ($parentPath -and -not (Test-Path -LiteralPath $parentPath)) {
                Add-Finding 'Critical' 'VM storage' 'Differencing disk parent is missing' `
                    ("{0} expects {1}" -f $hardDisk.Path,$parentPath) 'Preserve the chain; do not manually merge or rename it.'
            }
            if ($storageType -in @('Removable','Network','Network/UNC')) {
                Add-Finding 'Warning' 'VM storage' 'VM disk is on non-fixed storage' `
                    ("{0}: {1}" -f $hardDisk.Path,$storageType) 'Confirm it is available before VMMS starts.'
            }
            if ($null -ne $freePercent -and $freePercent -lt 10) {
                Add-Finding 'Critical' 'VM storage' 'VM volume has less than 10% free space' `
                    ("{0}% free" -f $freePercent) 'Free or extend capacity before startup, checkpoint or merge work.'
            }
        }
    }
    catch { Add-CollectionError 'VM hard disks' $_ }

    try {
        $switches = @(Get-VMSwitch)
        foreach ($adapter in @(Get-VMNetworkAdapter -VM $vm)) {
            $switchPresent = @($switches | Where-Object Name -eq $adapter.SwitchName).Count -gt 0
            $networkRows += [pscustomobject]@{
                Adapter=$adapter.Name; SwitchName=$adapter.SwitchName; SwitchPresent=$switchPresent
                Status=$adapter.Status; MacAddress=$adapter.MacAddress
                IPAddresses=@($adapter.IPAddresses) -join ', '
            }
            if ($adapter.SwitchName -and -not $switchPresent) {
                Add-Finding 'Warning' 'Networking' 'VM adapter references a missing switch' `
                    ("{0}: {1}" -f $adapter.Name,$adapter.SwitchName) 'Verify the intended switch; this does not explain lost registration.'
            }
        }
    }
    catch { Add-CollectionError 'VM networking' $_ }
}

if (Test-Path -LiteralPath $vmFolder -PathType Container) {
    try {
        $candidateFiles = @(Get-ChildItem -LiteralPath $vmFolder -File -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in @('.vmcx','.vhdx','.avhdx') })
        foreach ($file in $candidateFiles) {
            $match = 'N/A'
            if ($file.Extension -ieq '.vmcx') {
                $id = [System.IO.Path]::GetFileNameWithoutExtension($file.Name).Trim('{}')
                if ($targetVM.Count -and $id -ieq $targetVM[0].Id.ToString()) { $match = 'Matches target VM' }
                elseif (-not $targetVM.Count) { $match = 'Candidate for missing VM; verify manually' }
                else { $match = 'Different VM ID' }
            }
            $fileRows += [pscustomobject]@{
                Type=$file.Extension.TrimStart('.').ToUpperInvariant(); Path=$file.FullName
                Size=Format-Bytes $file.Length; LastWriteTime=$file.LastWriteTime; Match=$match
            }
        }
        $vmcx = @($candidateFiles | Where-Object Extension -ieq '.vmcx')
        if (-not $targetVM.Count -and $vmcx.Count) {
            Add-Finding 'Warning' 'Likely cause' 'VMCX files exist but the VM is not registered' `
                ("{0} VMCX file(s) under {1}" -f $vmcx.Count,$vmFolder) `
                'This points to registration or storage timing. Verify the correct file and backup before registration.'
        }
        elseif (-not $targetVM.Count -and -not $vmcx.Count) {
            Add-Finding 'Warning' 'Likely cause' 'VM is missing and no VMCX was found in the expected folder' $vmFolder `
                'Confirm the correct volume, path and backup before rebuilding Hyper-V.'
        }
    }
    catch { Add-CollectionError 'VM folder search' $_ }
}
else {
    Add-Finding 'Critical' 'VM storage' 'Expected VM folder is unavailable' $vmFolder `
        'Check the disk, mount point, BitLocker or approved network storage.'
}

$eventStart = (Get-Date).AddDays(-$days)
foreach ($log in @('Microsoft-Windows-Hyper-V-VMMS-Admin','Microsoft-Windows-Hyper-V-VMMS-Operational','Microsoft-Windows-Hyper-V-Worker-Admin')) {
    try {
        $events = @(Get-WinEvent -FilterHashtable @{LogName=$log;StartTime=$eventStart} -MaxEvents 250 |
            Where-Object { $_.Level -in @(2,3) } | Select-Object -First 75)
        foreach ($event in $events) {
            $message = [string]$event.Message
            if ($message.Length -gt 1000) { $message = $message.Substring(0,1000) + '...' }
            $eventRows += [pscustomobject]@{
                Time=$event.TimeCreated; Level=$event.LevelDisplayName; Log=$log
                EventId=$event.Id; Provider=$event.ProviderName; Message=$message
            }
        }
    }
    catch {
        if ($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound|NoMatchingLogsFound') {
            Add-CollectionError ("Event log: {0}" -f $log) $_
        }
    }
}

$recentErrors = @($eventRows | Where-Object Level -eq 'Error')
if ($recentErrors.Count) {
    Add-Finding 'Warning' 'Event logs' 'Recent Hyper-V errors were found' `
        ("{0} error(s) in the last {1} day(s)" -f $recentErrors.Count,$days) `
        'Correlate their timestamps with host startup and the VM disappearing.'
}
else {
    Add-Finding 'Pass' 'Event logs' 'No Hyper-V errors were returned in the selected period' `
        ("Lookback={0} day(s)" -f $days) 'Increase the lookback if the fault is older.'
}

if ($targetVM.Count -and $vmmsState -eq 'Running' -and $allDisksPresent) {
    Add-Finding 'Info' 'Likely cause' 'VM is registered, VMMS is running and attached disks resolve' $vmName `
        'If only the standard user cannot see it, permissions or the user logon token are most likely.'
}
elseif ($vmmsState -ne 'Running') {
    Add-Finding 'Critical' 'Likely cause' 'VMMS health is the first issue to resolve' $vmmsState `
        'Review service and VMMS events before considering feature removal.'
}
elseif ($targetVM.Count -and -not $allDisksPresent) {
    Add-Finding 'Critical' 'Likely cause' 'VM is registered but attached storage is unavailable' $vmName `
        'Treat this as a storage/path fault, not a Hyper-V role fault.'
}

$order = @{Critical=1;Warning=2;Info=3;Pass=4}
$sortedFindings = @($script:Findings | Sort-Object @{Expression={$order[$_.Severity]}},Area,Finding)
$criticalCount = @($script:Findings | Where-Object Severity -eq 'Critical').Count
$warningCount = @($script:Findings | Where-Object Severity -eq 'Warning').Count
$passCount = @($script:Findings | Where-Object Severity -eq 'Pass').Count
if ($criticalCount) { $overall = 'Critical findings present' }
elseif ($warningCount) { $overall = 'Attention required' }
else { $overall = 'No material issue detected' }

$inputRows = @([pscustomobject]@{
    VMName=$vmName; ExpectedUser=$expectedUser; ExpectedVMFolder=$vmFolder
    EventLookbackDays=$days; DiagnosticAccount=$identity.Name
})

$inputsHtml = Convert-ToTable $inputRows @('VMName','ExpectedUser','ExpectedVMFolder','EventLookbackDays','DiagnosticAccount')
$findingsHtml = Convert-ToTable $sortedFindings @('Severity','Area','Finding','Evidence','Advice')
$hostHtml = Convert-ToTable $hostRows @('Computer','OperatingSystem','Version','Build','LastBoot','HypervisorPresent','HypervisorLaunchType','FirmwareVirtualization','PendingRestart','DiagnosticAccount')
$featureHtml = Convert-ToTable $featureRows @('Source','Name','State')
$serviceHtml = Convert-ToTable $serviceRows @('Name','DisplayName','State','StartMode','Account','ProcessId')
$permissionHtml = Convert-ToTable $permissionRows @('Group','Member','Type') 'No local group members were returned.'
$vmHtml = Convert-ToTable $vmRows @('Name','Id','Visible','State','Status','Generation','Version','ConfigurationLocation','AutomaticStartAction','AutomaticStartDelay','AutomaticStopAction','Checkpoints') 'The requested VM was not returned by Get-VM.'
$diskHtml = Convert-ToTable $diskRows @('Attached','Controller','Path','Exists','VHDType','FileSize','MaximumSize','ParentPath','StorageType','FileSystem','FreeSpace','FreePercent') 'No attached disks were returned.'
$networkHtml = Convert-ToTable $networkRows @('Adapter','SwitchName','SwitchPresent','Status','MacAddress','IPAddresses') 'No VM network adapters were returned.'
$filesHtml = Convert-ToTable $fileRows @('Type','Path','Size','LastWriteTime','Match') 'No VMCX, VHDX or AVHDX files were found in the expected folder.'
$eventsHtml = Convert-ToTable @($eventRows | Sort-Object Time -Descending) @('Time','Level','Log','EventId','Provider','Message') 'No Hyper-V warning or error events were returned.'
$errorsHtml = Convert-ToTable $script:ErrorsFound @('Area','Error') 'All requested data sources were queried successfully.'

$computerHtml = [System.Net.WebUtility]::HtmlEncode($env:COMPUTERNAME)
$overallHtml = [System.Net.WebUtility]::HtmlEncode($overall)
$generated = Get-Date -Format 'yyyy-MM-dd HH:mm:ss K'
$fileName = 'Hyper-V-Health-{0}-{1}.html' -f $env:COMPUTERNAME,(Get-Date -Format 'yyyyMMdd-HHmmss')
$reportPath = Join-Path $reportFolder $fileName

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Hyper-V Health Report - $computerHtml</title>
<style>
body{margin:0;background:#f3f6fa;color:#172033;font-family:Segoe UI,Arial,sans-serif;font-size:14px;line-height:1.45}
header{background:#102b4e;color:white;padding:28px 5vw}header h1{margin:0 0 6px}header p{margin:3px 0;color:#d7e7fb}
main{width:min(1500px,94vw);margin:20px auto 45px}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}
.card,section{background:white;border:1px solid #dbe3ee;border-radius:8px;box-shadow:0 2px 7px rgba(16,43,78,.05)}
.card{padding:16px}.card span{display:block;color:#66758a;font-size:12px;text-transform:uppercase}.card strong{display:block;margin-top:5px;font-size:21px}
section{padding:19px;margin:14px 0}h2{margin:0 0 12px;color:#102b4e;font-size:19px}h3{color:#102b4e;font-size:15px;margin:19px 0 9px}
.notice{border-left:4px solid #039855;background:#ecfdf3;padding:11px 13px;margin:10px 0}
table{border-collapse:collapse;width:100%;display:block;overflow-x:auto}th{background:#eaf1f8;text-transform:uppercase;font-size:12px;color:#344c68}
th,td{border:1px solid #dbe3ee;padding:8px 10px;text-align:left;vertical-align:top;overflow-wrap:anywhere}tr:nth-child(even) td{background:#fafbfd}.empty{color:#66758a}
footer{text-align:center;color:#66758a;padding:18px}@media print{body{background:white}.card,section{box-shadow:none;break-inside:avoid}main{width:100%}}
</style>
</head>
<body>
<header><h1>Hyper-V Health Report</h1><p>$computerHtml</p><p>Generated $generated</p></header>
<main>
<div class="cards">
<div class="card"><span>Overall</span><strong>$overallHtml</strong></div>
<div class="card"><span>Critical</span><strong>$criticalCount</strong></div>
<div class="card"><span>Warnings</span><strong>$warningCount</strong></div>
<div class="card"><span>Passed</span><strong>$passCount</strong></div>
</div>
<section><div class="notice"><strong>Read-only diagnostic:</strong> no service was restarted; no VM, disk, ACL, feature, boot setting or network configuration was changed. This HTML file is the only persistent output.</div><h2>Inputs</h2>$inputsHtml</section>
<section><h2>Findings and advice</h2>$findingsHtml</section>
<section><h2>Host and hypervisor</h2>$hostHtml<h3>Hyper-V feature</h3>$featureHtml</section>
<section><h2>Hyper-V services</h2>$serviceHtml</section>
<section><h2>Management permissions</h2><p>The VM is registered to the host, not locked to a human administrator account.</p>$permissionHtml</section>
<section><h2>Requested VM</h2>$vmHtml<h3>Attached storage</h3>$diskHtml<h3>Networking</h3>$networkHtml</section>
<section><h2>Files in expected VM folder</h2><p>Files were only read and listed; nothing was mounted, imported, merged or renamed.</p>$filesHtml</section>
<section><h2>Recent Hyper-V warnings and errors</h2>$eventsHtml</section>
<section><h2>Collection limitations</h2>$errorsHtml</section>
<section><h2>Repair versus rebuild</h2><p>If VMMS is running and a valid VMCX exists, investigate registration, storage availability and permissions before touching the Hyper-V feature. Reinstall only after backup and after confirming that a new test VM on fixed local storage also fails across clean reboots.</p></section>
</main>
<footer>Hyper-V interactive health check</footer>
</body>
</html>
"@

try {
    Set-Content -LiteralPath $reportPath -Value $html -Encoding UTF8
}
catch {
    $firstWriteError = $_
    $reportPath = Join-Path $env:TEMP $fileName
    Set-Content -LiteralPath $reportPath -Value $html -Encoding UTF8
    Write-Warning ("Requested report folder was not writable; saved to TEMP instead. {0}" -f $firstWriteError.Exception.Message)
}

Write-Host ''
Write-Host 'Diagnostic complete.' -ForegroundColor Green
Write-Host ("Report: {0}" -f $reportPath) -ForegroundColor Green
Write-Host 'No Hyper-V or service changes were made.' -ForegroundColor Green
try { Start-Process -FilePath $reportPath }
catch { Write-Warning 'Report was created but could not be opened automatically. Use the path shown above.' }

[pscustomobject]@{
    Computer=$env:COMPUTERNAME; VM=$vmName; OverallStatus=$overall
    CriticalFindings=$criticalCount; Warnings=$warningCount; ReportPath=$reportPath
}
