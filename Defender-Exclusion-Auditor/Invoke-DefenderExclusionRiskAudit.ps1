#Requires -Version 5.1

<#
.SYNOPSIS
    Audits, plans, hardens, and rolls back Microsoft Defender Antivirus custom exclusions.

.DESCRIPTION
    Defender Exclusion Risk Auditor and Hardener v1.0 is a single-file, local-first
    PowerShell tool. Audit is the default and never changes Defender settings.

    The tool reads custom path, process, extension, and IP address exclusions,
    applies deterministic risk rules, and writes self-contained HTML, JSON, and CSV
    evidence. Plan mode creates a remediation plan. Harden mode removes only the
    exclusions selected by the operator. Rollback mode restores the exclusions in a
    saved pre-change snapshot.

    Harden and Rollback support -WhatIf, -Confirm, and explicit typed confirmation.
    Managed policy exclusions are reported but are not changed by this tool.

.PARAMETER Mode
    Audit, Plan, Harden, or Rollback. The default is Audit.

.PARAMETER OutputDirectory
    Directory for reports, plans, snapshots, and change logs. If omitted, the tool
    creates a timestamped folder under the current directory.

.PARAMETER MinimumRisk
    Minimum risk level included in Plan and Harden candidate lists. The default is High.

.PARAMETER FindingId
    One or more finding IDs to select in Harden mode. If omitted, an interactive
    selection list is shown. With -WhatIf and no IDs, all eligible candidates are used.

.PARAMETER SnapshotPath
    Snapshot JSON file to restore in Rollback mode.

.PARAMETER SkipAclAnalysis
    Skips the heuristic check for low-privilege write access to excluded paths.

.PARAMETER OpenReport
    Opens the HTML report in the default browser after the run.

.PARAMETER Force
    Skips the typed HARDEN or ROLLBACK confirmation. This does not disable
    PowerShell's -Confirm behavior. Use -Confirm:$false separately when required.

.PARAMETER AllowDifferentComputer
    Permits rollback from a snapshot made on a different computer. Use with care.

.PARAMETER SelfTest
    Runs deterministic synthetic risk-engine checks. Defender is not queried or changed.

.EXAMPLE
    .\Invoke-DefenderExclusionRiskAudit.ps1

    Runs a read-only audit and writes HTML, JSON, and CSV reports.

.EXAMPLE
    .\Invoke-DefenderExclusionRiskAudit.ps1 -Mode Plan -MinimumRisk Medium

    Creates a remediation plan for Medium, High, and Critical findings.

.EXAMPLE
    .\Invoke-DefenderExclusionRiskAudit.ps1 -Mode Harden -WhatIf

    Simulates removal of all eligible High and Critical findings without changing Defender.

.EXAMPLE
    .\Invoke-DefenderExclusionRiskAudit.ps1 -Mode Harden -FindingId DX-123456789ABC

    Prompts for confirmation and removes the selected local exclusion.

.EXAMPLE
    .\Invoke-DefenderExclusionRiskAudit.ps1 -Mode Rollback -SnapshotPath .\Snapshot-Before-Hardening.json

    Restores the custom exclusion state recorded in the snapshot.

.NOTES
    Product: Defender Exclusion Risk Auditor and Hardener
    Version: 1.0.1
    Publisher: RuleRivet
    Compatibility: Windows PowerShell 5.1 and later on supported Windows clients and servers

    Important: An exclusion can be required for application compatibility or performance.
    A high score means urgent human review, not proof that the exclusion is malicious.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [ValidateSet('Audit', 'Plan', 'Harden', 'Rollback')]
    [string]$Mode = 'Audit',

    [string]$OutputDirectory,

    [ValidateSet('Low', 'Medium', 'High', 'Critical')]
    [string]$MinimumRisk = 'High',

    [string[]]$FindingId,

    [string]$SnapshotPath,

    [switch]$SkipAclAnalysis,

    [switch]$OpenReport,

    [switch]$Force,

    [switch]$AllowDifferentComputer,

    [switch]$SelfTest
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:ToolName = 'Defender Exclusion Risk Auditor and Hardener'
$script:ToolVersion = '1.0.1'
$script:SchemaVersion = '1.0'
$script:CmdletContext = $PSCmdlet
$script:RunId = [guid]::NewGuid().Guid
$script:RunStartedUtc = (Get-Date).ToUniversalTime()
$script:CoverageNotes = New-Object System.Collections.Generic.List[string]
$script:AclAttemptCount = 0
$script:AclSuccessCount = 0
$script:SignatureAttemptCount = 0
$script:SignatureSuccessCount = 0

$script:RiskRank = @{
    Low      = 1
    Medium   = 2
    High     = 3
    Critical = 4
}

$script:DangerousExtensions = @(
    'bat', 'bin', 'cab', 'cmd', 'com', 'cpl', 'dll', 'exe', 'hta', 'inf',
    'jar', 'java', 'job', 'js', 'msi', 'ocx', 'ps1', 'py', 'reg', 'scr',
    'sys', 'tmp', 'url', 'vbe', 'vbs', 'wsf'
)

$script:ArchiveExtensions = @('7z', 'gz', 'rar', 'tar', 'zip')
$script:DocumentAndImageExtensions = @('fla', 'gif', 'jpeg', 'jpg', 'png')
$script:DangerousProcesses = @(
    'acrord32.exe', 'addinprocess.exe', 'addinprocess32.exe', 'addinutil.exe',
    'bash.exe', 'bginfo.exe', 'bitsadmin.exe', 'cdb.exe', 'cmd.exe',
    'cscript.exe', 'csi.exe', 'dbghost.exe', 'dbgsvc.exe', 'dnx.exe',
    'dotnet.exe', 'excel.exe', 'fsi.exe', 'fsianycpu.exe', 'iexplore.exe',
    'java.exe', 'kd.exe', 'lxssmanager.dll', 'msbuild.exe', 'mshta.exe',
    'ntkd.exe', 'ntsd.exe', 'outlook.exe', 'powerpnt.exe', 'powershell.exe',
    'psexec.exe', 'rcsi.exe', 'schtasks.exe', 'svchost.exe',
    'system.management.automation.dll', 'windbg.exe', 'winword.exe',
    'wmic.exe', 'wscript.exe', 'wuauclt.exe'
)

function Write-Banner {
    [CmdletBinding()]
    param()

    $line = ('=' * 78)
    Write-Host $line -ForegroundColor DarkYellow
    Write-Host ('  {0}' -f $script:ToolName) -ForegroundColor Yellow
    Write-Host ('  RuleRivet  |  Version {0}  |  Mode {1}' -f $script:ToolVersion, $Mode) -ForegroundColor Gray
    Write-Host $line -ForegroundColor DarkYellow
    Write-Host '  Audit is evidence. A risk score is a prompt for review, not proof of abuse.' -ForegroundColor DarkGray
    Write-Host ''
}

function Write-Section {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Text)

    Write-Host ''
    Write-Host ('[ {0} ]' -f $Text) -ForegroundColor Cyan
}

function Get-PropertyValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$InputObject,
        [Parameter(Mandatory = $true)][string]$Name,
        $Default = $null
    )

    if ($null -eq $InputObject) { return $Default }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) { return $Default }
    return $property.Value
}

function ConvertTo-StringArray {
    [CmdletBinding()]
    param($Value)

    if ($null -eq $Value) { return @() }

    $items = @($Value) | ForEach-Object {
        if ($null -ne $_) {
            $text = ([string]$_).Trim()
            if ($text.Length -gt 0) { $text }
        }
    }

    return @($items | Sort-Object -Unique)
}

function Test-IsAdministrator {
    [CmdletBinding()]
    param()

    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Assert-WindowsPlatform {
    [CmdletBinding()]
    param()

    if ($env:OS -ne 'Windows_NT') {
        throw 'This tool must run on Windows because it uses the Microsoft Defender PowerShell module.'
    }
}

function Assert-DefenderModule {
    [CmdletBinding()]
    param()

    if (-not (Get-Command -Name Get-MpPreference -ErrorAction SilentlyContinue)) {
        try {
            Import-Module Defender -ErrorAction Stop
        }
        catch {
            throw ('The Microsoft Defender PowerShell module is not available. {0}' -f $_.Exception.Message)
        }
    }

    foreach ($command in @('Get-MpPreference', 'Get-MpComputerStatus')) {
        if (-not (Get-Command -Name $command -ErrorAction SilentlyContinue)) {
            throw ('Required Defender command is unavailable: {0}' -f $command)
        }
    }
}

function Initialize-OutputDirectory {
    [CmdletBinding()]
    param([string]$RequestedPath)

    if ([string]::IsNullOrWhiteSpace($RequestedPath)) {
        $folderName = 'Defender-Exclusion-Audit-{0}' -f (Get-Date -Format 'yyyyMMdd-HHmmss')
        $RequestedPath = Join-Path -Path (Get-Location).Path -ChildPath $folderName
    }

    $fullPath = [IO.Path]::GetFullPath($RequestedPath)
    if (-not (Test-Path -LiteralPath $fullPath -PathType Container)) {
        New-Item -ItemType Directory -Path $fullPath -Force | Out-Null
    }

    return $fullPath
}

function Add-CoverageNote {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Message)

    if (-not $script:CoverageNotes.Contains($Message)) {
        $script:CoverageNotes.Add($Message) | Out-Null
    }
}

function Get-SystemEnvironmentMap {
    [CmdletBinding()]
    param()

    $systemRoot = if ($env:SystemRoot) { $env:SystemRoot } else { 'C:\Windows' }
    $systemDrive = if ($env:SystemDrive) { $env:SystemDrive } else { 'C:' }
    $programData = if ($env:ProgramData) { $env:ProgramData } else { Join-Path $systemDrive 'ProgramData' }
    $publicPath = if ($env:PUBLIC) { $env:PUBLIC } else { Join-Path $systemDrive 'Users\Public' }
    $programFilesX86 = ${env:ProgramFiles(x86)}
    $commonProgramFilesX86 = ${env:CommonProgramFiles(x86)}

    return @{
        'ALLUSERSPROFILE'       = $programData
        'APPDATA'               = Join-Path $systemRoot 'System32\config\systemprofile\AppData\Roaming'
        'COMMONPROGRAMFILES'    = $env:CommonProgramFiles
        'COMMONPROGRAMFILES(X86)' = $commonProgramFilesX86
        'LOCALAPPDATA'          = Join-Path $systemRoot 'System32\config\systemprofile\AppData\Local'
        'PROGRAMDATA'           = $programData
        'PROGRAMFILES'          = $env:ProgramFiles
        'PROGRAMFILES(X86)'     = $programFilesX86
        'PUBLIC'                = $publicPath
        'SYSTEMDRIVE'           = $systemDrive
        'SYSTEMROOT'            = $systemRoot
        'TEMP'                  = Join-Path $systemRoot 'TEMP'
        'TMP'                   = Join-Path $systemRoot 'TEMP'
        'USERPROFILE'           = Join-Path $systemRoot 'System32\config\systemprofile'
        'WINDIR'                = $systemRoot
    }
}

function Expand-DefenderEnvironmentPath {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Value)

    $map = Get-SystemEnvironmentMap
    $unknown = New-Object System.Collections.Generic.List[string]
    $expanded = [regex]::Replace($Value, '%([^%]+)%', {
        param($match)
        $name = $match.Groups[1].Value.ToUpperInvariant()
        if ($map.ContainsKey($name) -and -not [string]::IsNullOrWhiteSpace([string]$map[$name])) {
            return [string]$map[$name]
        }
        $unknown.Add($match.Value) | Out-Null
        return $match.Value
    })

    [pscustomobject]@{
        ExpandedValue       = $expanded
        UnknownVariables    = @($unknown.ToArray())
        ContainsEnvironment = ($Value -match '%[^%]+%')
    }
}

function Get-PathWithoutContext {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Value)

    $index = $Value.IndexOf('\:{', [StringComparison]::Ordinal)
    if ($index -ge 0) { return $Value.Substring(0, $index) }
    return $Value
}

function Get-StaticAclTarget {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Value)

    $candidate = Get-PathWithoutContext -Value $Value
    $expanded = (Expand-DefenderEnvironmentPath -Value $candidate).ExpandedValue
    $wildcardIndex = $expanded.IndexOfAny([char[]]'*?')
    if ($wildcardIndex -ge 0) {
        $prefix = $expanded.Substring(0, $wildcardIndex)
        $lastSlash = $prefix.LastIndexOf('\')
        if ($lastSlash -gt 2) { $expanded = $prefix.Substring(0, $lastSlash) }
        else { $expanded = $prefix.TrimEnd('\') + '\' }
    }

    if (Test-Path -LiteralPath $expanded -PathType Leaf) {
        return Split-Path -Path $expanded -Parent
    }

    $probe = $expanded
    while (-not [string]::IsNullOrWhiteSpace($probe) -and -not (Test-Path -LiteralPath $probe)) {
        $parent = Split-Path -Path $probe -Parent
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $probe) { break }
        $probe = $parent
    }

    if (Test-Path -LiteralPath $probe) { return $probe }
    return $null
}

function Get-LowPrivilegeWriteEvidence {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    $script:AclAttemptCount++
    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        $writeMask = [Security.AccessControl.FileSystemRights]::Write -bor
            [Security.AccessControl.FileSystemRights]::Modify -bor
            [Security.AccessControl.FileSystemRights]::FullControl -bor
            [Security.AccessControl.FileSystemRights]::CreateFiles -bor
            [Security.AccessControl.FileSystemRights]::CreateDirectories -bor
            [Security.AccessControl.FileSystemRights]::AppendData -bor
            [Security.AccessControl.FileSystemRights]::Delete -bor
            [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
            [Security.AccessControl.FileSystemRights]::TakeOwnership

        $lowPrivilegePatterns = @(
            '^Everyone$', '^BUILTIN\\Users$', '^NT AUTHORITY\\Authenticated Users$',
            '^NT AUTHORITY\\INTERACTIVE$', '^S-1-1-0$', '^S-1-5-11$', '^S-1-5-32-545$'
        )

        $matches = New-Object System.Collections.Generic.List[string]
        foreach ($rule in @($acl.Access)) {
            if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
            $identity = [string]$rule.IdentityReference.Value
            $isLowPrivilege = $false
            foreach ($pattern in $lowPrivilegePatterns) {
                if ($identity -match $pattern) { $isLowPrivilege = $true; break }
            }
            if (-not $isLowPrivilege) { continue }

            if (($rule.FileSystemRights -band $writeMask) -ne 0) {
                $matches.Add(('{0}: {1}' -f $identity, $rule.FileSystemRights)) | Out-Null
            }
        }

        $script:AclSuccessCount++
        [pscustomobject]@{
            Checked  = $true
            Writable = ($matches.Count -gt 0)
            Evidence = @($matches.ToArray())
        }
    }
    catch {
        Add-CoverageNote -Message ('ACL analysis failed for {0}: {1}' -f $Path, $_.Exception.Message)
        [pscustomobject]@{
            Checked  = $false
            Writable = $false
            Evidence = @()
        }
    }
}

function Get-SignatureEvidence {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    $script:SignatureAttemptCount++
    try {
        $signature = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        $script:SignatureSuccessCount++
        [pscustomobject]@{
            Checked = $true
            Status  = [string]$signature.Status
            Subject = if ($signature.SignerCertificate) { [string]$signature.SignerCertificate.Subject } else { $null }
        }
    }
    catch {
        Add-CoverageNote -Message ('Signature analysis failed for {0}: {1}' -f $Path, $_.Exception.Message)
        [pscustomobject]@{
            Checked = $false
            Status  = 'NotChecked'
            Subject = $null
        }
    }
}

function New-RiskSignal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$RuleId,
        [Parameter(Mandatory = $true)][string]$Title,
        [Parameter(Mandatory = $true)][int]$Points,
        [Parameter(Mandatory = $true)][string]$Detail,
        [ValidateSet('High', 'Medium', 'Low')][string]$Confidence = 'High'
    )

    [pscustomobject]@{
        RuleId     = $RuleId
        Title      = $Title
        Points     = $Points
        Detail     = $Detail
        Confidence = $Confidence
    }
}

function Get-RiskLevel {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][int]$Score)

    if ($Score -ge 80) { return 'Critical' }
    if ($Score -ge 60) { return 'High' }
    if ($Score -ge 35) { return 'Medium' }
    return 'Low'
}

function Get-StableFindingId {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Type,
        [Parameter(Mandatory = $true)][string]$Value
    )

    $bytes = [Text.Encoding]::UTF8.GetBytes(('{0}|{1}' -f $Type.ToUpperInvariant(), $Value.ToUpperInvariant()))
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash($bytes)
        $hex = -join ($hash | ForEach-Object { $_.ToString('X2') })
        return 'DX-{0}' -f $hex.Substring(0, 12)
    }
    finally {
        $sha.Dispose()
    }
}

function Get-SuggestedReplacement {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Type,
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Signals
    )

    $ruleIds = @($Signals | ForEach-Object { $_.RuleId })
    switch ($Type) {
        'Path' {
            if ($ruleIds -contains 'PATH-DRIVE-ROOT') {
                return 'Remove the drive-wide exclusion. If a verified compatibility issue exists, exclude only the exact vendor file or working folder.'
            }
            if ($ruleIds -contains 'PATH-TEMP' -or $ruleIds -contains 'PATH-USERS') {
                return 'Replace the broad user-writable location with the smallest exact application-owned subfolder, or use a contextual exclusion where supported.'
            }
            if ($ruleIds -contains 'PATH-WILDCARD') {
                return 'Replace broad wildcards with exact paths. If a wildcard is essential, limit it to one known folder level and one file pattern.'
            }
            return 'Confirm the vendor requirement, owner, review date, and exact minimum path. Prefer a file or narrow subfolder over an application root.'
        }
        'Process' {
            if ($ruleIds -contains 'PROCESS-NAME-ONLY') {
                return 'Replace the image-name entry with the full path to the trusted executable. A process exclusion affects every file that the process opens.'
            }
            return 'Prefer a contextual file or folder exclusion limited to the exact process and data path. Remove the process exclusion if no current requirement exists.'
        }
        'Extension' {
            return ('Replace the device-wide .{0} exclusion with a path-scoped file pattern, such as C:\Vendor\Data\*.{0}, when a verified requirement exists.' -f $Value.TrimStart('.'))
        }
        'IpAddress' {
            return 'Confirm the Defender feature and workload that require this entry. Replace broad ranges with the smallest exact address set, or remove the entry.'
        }
        default { return 'Validate the business requirement and reduce the exclusion to the smallest possible scope.' }
    }
}

function New-ExclusionFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Type,
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$ExpandedValue,
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Signals,
        [int]$BaseScore = 0,
        [hashtable]$Metadata
    )

    $score = $BaseScore
    foreach ($signal in $Signals) { $score += [int]$signal.Points }
    $score = [Math]::Max(0, [Math]::Min(100, $score))
    $level = Get-RiskLevel -Score $score
    $action = switch ($level) {
        'Critical' { 'Remove or replace urgently' }
        'High'     { 'Remove or narrow after validation' }
        'Medium'   { 'Review and narrow' }
        default    { 'Document and retain only if required' }
    }

    [pscustomobject][ordered]@{
        FindingId           = Get-StableFindingId -Type $Type -Value $Value
        Type                = $Type
        Value               = $Value
        ExpandedValue       = $ExpandedValue
        Source              = $Source
        Score               = $score
        RiskLevel           = $level
        RecommendedAction   = $action
        SuggestedReplacement = Get-SuggestedReplacement -Type $Type -Value $Value -Signals $Signals
        Signals             = @($Signals)
        Metadata            = if ($Metadata) { [pscustomobject]$Metadata } else { [pscustomobject]@{} }
        Managed             = ($Source -eq 'ManagedPolicy')
    }
}

function Measure-PathExclusion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Source,
        [switch]$SkipAcl
    )

    $signals = New-Object System.Collections.Generic.List[object]
    $contextFree = Get-PathWithoutContext -Value $Value
    $expansion = Expand-DefenderEnvironmentPath -Value $contextFree
    $expanded = $expansion.ExpandedValue
    $normal = $expanded.Trim().TrimEnd('\')
    $hasContext = ($Value -match '\\\:\{.+\}$')

    if ($normal -match '^[A-Za-z]:$' -or $contextFree -match '^%SYSTEMDRIVE%\\?$') {
        $signals.Add((New-RiskSignal 'PATH-DRIVE-ROOT' 'Drive root excluded' 90 'The exclusion covers an entire drive. Microsoft lists drive-root exclusions as unsafe.')) | Out-Null
    }

    if ($normal -match '^[A-Za-z]:\\Users$') {
        $signals.Add((New-RiskSignal 'PATH-USERS' 'All user profiles excluded' 70 'The exclusion covers every local user profile and common attacker-controlled locations.')) | Out-Null
    }
    elseif ($normal -match '^[A-Za-z]:\\Users\\[^\\]+(?:\\AppData\\Local(?:Low)?\\Temp)?$' -or
            $normal -match '\\Users\\Public(?:\\|$)') {
        $signals.Add((New-RiskSignal 'PATH-USER-WRITABLE' 'User-controlled location excluded' 45 'The path is normally writable by a standard user or contains user-controlled content.')) | Out-Null
    }

    if ($normal -match '(?i)(^|\\)(temp|tmp)(\\|$)' -or
        $normal -match '(?i)\\AppData\\Local(?:Low)?\\Temp(?:\\|$)') {
        $signals.Add((New-RiskSignal 'PATH-TEMP' 'Temporary location excluded' 50 'Temporary directories are common malware staging locations and should not be broadly excluded.')) | Out-Null
    }

    if ($normal -match '(?i)\\Windows\\Prefetch$' -or
        $normal -match '(?i)\\Windows\\System32\\Spool(?:\\|$)' -or
        $normal -match '(?i)\\Windows\\System32\\CatRoot2$') {
        $signals.Add((New-RiskSignal 'PATH-MS-AVOID' 'Microsoft-listed sensitive folder excluded' 55 'Microsoft specifically identifies this folder as one that should not be excluded.')) | Out-Null
    }

    if ($normal -match '(?i)^[A-Za-z]:\\Program Files(?: \(x86\))?(?:\\|$)') {
        $signals.Add((New-RiskSignal 'PATH-PROGRAM-FILES' 'Application installation path excluded' 25 'Microsoft advises against broad application program-folder exclusions. Validate the exact vendor requirement.' 'Medium')) | Out-Null
    }

    if ($Value -match '[*?]') {
        $wildcardCount = ([regex]::Matches($Value, '[*?]')).Count
        $points = if ($wildcardCount -ge 3 -or $Value -match '(?i)^[A-Za-z]:\\\*') { 35 } else { 20 }
        $signals.Add((New-RiskSignal 'PATH-WILDCARD' 'Wildcard broadens the path' $points ('The entry contains {0} wildcard character(s). Defender wildcards have path-specific matching behavior.' -f $wildcardCount))) | Out-Null
        if ($wildcardCount -gt 6) {
            $signals.Add((New-RiskSignal 'PATH-WILDCARD-LIMIT' 'More than six wildcards' 20 'Microsoft Defender supports a maximum of six wildcards in one exclusion entry.')) | Out-Null
        }
    }

    if ($expansion.UnknownVariables.Count -gt 0) {
        $signals.Add((New-RiskSignal 'PATH-UNKNOWN-VARIABLE' 'Environment variable could not be resolved' 25 ('Unresolved variable(s): {0}. Defender expands variables in the LocalSystem context.' -f ($expansion.UnknownVariables -join ', ')))) | Out-Null
    }
    elseif ($Value -match '(?i)%(APPDATA|LOCALAPPDATA|TEMP|TMP|USERPROFILE)%') {
        $signals.Add((New-RiskSignal 'PATH-SYSTEM-CONTEXT' 'Variable resolves in the LocalSystem context' 20 'This variable normally resolves to the system profile or Windows Temp for Defender, not the interactive user profile.' 'Medium')) | Out-Null
    }

    if ($normal -match '^\\\\') {
        $signals.Add((New-RiskSignal 'PATH-UNC' 'Network location excluded' 30 'The entry points to remotely controlled content. Confirm availability, ownership, and trust boundaries.')) | Out-Null
    }
    elseif ($normal -match '^[A-Za-z]:') {
        try {
            $driveName = $normal.Substring(0, 1)
            $drive = Get-PSDrive -Name $driveName -ErrorAction SilentlyContinue
            if ($drive -and $drive.DisplayRoot -match '^\\\\') {
                $signals.Add((New-RiskSignal 'PATH-MAPPED-DRIVE' 'Mapped network drive used' 35 'Microsoft advises using the actual UNC path instead of a mapped network drive.')) | Out-Null
            }
        }
        catch { }
    }

    $exists = $false
    if ($Value -notmatch '[*?]' -and $expansion.UnknownVariables.Count -eq 0) {
        $exists = Test-Path -LiteralPath $expanded
        if (-not $exists) {
            $signals.Add((New-RiskSignal 'PATH-NOT-FOUND' 'Path does not currently exist' 10 'The exclusion cannot be validated against the current file system. It might be stale or intended for removable storage.' 'Medium')) | Out-Null
        }
    }

    $aclTarget = $null
    $writable = $false
    if (-not $SkipAcl) {
        $aclTarget = Get-StaticAclTarget -Value $Value
        if ($aclTarget) {
            $aclEvidence = Get-LowPrivilegeWriteEvidence -Path $aclTarget
            if ($aclEvidence.Writable) {
                $writable = $true
                $signals.Add((New-RiskSignal 'ACL-LOW-PRIV-WRITE' 'Low-privilege write access detected' 40 ('Writable ACL on {0}: {1}' -f $aclTarget, ($aclEvidence.Evidence -join '; ')) 'Medium')) | Out-Null
            }
        }
        else {
            Add-CoverageNote -Message ('No existing ACL target could be resolved for path exclusion: {0}' -f $Value)
        }
    }

    $signatureStatus = 'NotApplicable'
    if ($exists -and (Test-Path -LiteralPath $expanded -PathType Leaf) -and $expanded -match '(?i)\.(exe|dll|sys|ocx|cpl|scr)$') {
        $signature = Get-SignatureEvidence -Path $expanded
        $signatureStatus = $signature.Status
        if ($signature.Checked -and $signature.Status -ne 'Valid') {
            $points = if ($signature.Status -eq 'HashMismatch') { 55 } else { 30 }
            $signals.Add((New-RiskSignal 'SIGNATURE-NOT-VALID' 'Executable signature is not valid' $points ('Authenticode status: {0}' -f $signature.Status))) | Out-Null
        }
    }

    $baseScore = if ($hasContext) { 0 } else { 10 }
    if ($hasContext) {
        $signals.Add((New-RiskSignal 'PATH-CONTEXTUAL' 'Contextual restriction present' 0 'The exclusion includes contextual restrictions, which can reduce scope. Syntax and business intent still require review.' 'Medium')) | Out-Null
    }

    New-ExclusionFinding -Type 'Path' -Value $Value -ExpandedValue $expanded -Source $Source -Signals ($signals.ToArray()) -BaseScore $baseScore -Metadata @{
        Exists          = $exists
        Contextual      = $hasContext
        AclTarget       = $aclTarget
        LowPrivWritable = $writable
        SignatureStatus = $signatureStatus
    }
}

function Measure-ProcessExclusion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Source,
        [switch]$SkipAcl
    )

    $signals = New-Object System.Collections.Generic.List[object]
    $expansion = Expand-DefenderEnvironmentPath -Value $Value
    $expanded = $expansion.ExpandedValue
    $leaf = [IO.Path]::GetFileName($expanded).ToLowerInvariant()
    $isFullPath = ($expanded -match '^(?i)[A-Za-z]:\\' -or $expanded -match '^\\\\')

    if (-not $isFullPath) {
        $signals.Add((New-RiskSignal 'PROCESS-NAME-ONLY' 'Process is not fully qualified' 40 'An image-name exclusion applies to every process with that name, including copies on removable media.')) | Out-Null
    }

    if ($script:DangerousProcesses -contains $leaf) {
        $signals.Add((New-RiskSignal 'PROCESS-MS-AVOID' 'Microsoft-listed process excluded' 55 ('Microsoft identifies {0} as a process that should not be excluded.' -f $leaf))) | Out-Null
    }

    if ($Value -match '[*?]') {
        $signals.Add((New-RiskSignal 'PROCESS-WILDCARD' 'Wildcard process exclusion' 30 'The wildcard can match multiple executable paths. Image-name-only process exclusions do not support wildcards.')) | Out-Null
    }

    if ($expansion.UnknownVariables.Count -gt 0) {
        $signals.Add((New-RiskSignal 'PROCESS-UNKNOWN-VARIABLE' 'Environment variable could not be resolved' 25 ('Unresolved variable(s): {0}' -f ($expansion.UnknownVariables -join ', ')))) | Out-Null
    }

    $exists = $false
    $signatureStatus = 'NotChecked'
    if ($isFullPath -and $Value -notmatch '[*?]' -and $expansion.UnknownVariables.Count -eq 0) {
        $exists = Test-Path -LiteralPath $expanded -PathType Leaf
        if ($exists) {
            $signature = Get-SignatureEvidence -Path $expanded
            $signatureStatus = $signature.Status
            if ($signature.Checked -and $signature.Status -ne 'Valid') {
                $points = if ($signature.Status -eq 'HashMismatch') { 55 } else { 30 }
                $signals.Add((New-RiskSignal 'PROCESS-SIGNATURE' 'Process signature is not valid' $points ('Authenticode status: {0}' -f $signature.Status))) | Out-Null
            }
        }
        else {
            $signals.Add((New-RiskSignal 'PROCESS-NOT-FOUND' 'Process path does not exist' 15 'The process exclusion could be stale, offline, or intended for removable storage.' 'Medium')) | Out-Null
        }
    }

    $aclTarget = $null
    $writable = $false
    if ($isFullPath -and -not $SkipAcl) {
        $aclTarget = Get-StaticAclTarget -Value $expanded
        if ($aclTarget) {
            $aclEvidence = Get-LowPrivilegeWriteEvidence -Path $aclTarget
            if ($aclEvidence.Writable) {
                $writable = $true
                $signals.Add((New-RiskSignal 'PROCESS-WRITABLE-PATH' 'Process directory is low-privilege writable' 45 ('Writable ACL on {0}: {1}' -f $aclTarget, ($aclEvidence.Evidence -join '; ')) 'Medium')) | Out-Null
            }
        }
    }

    New-ExclusionFinding -Type 'Process' -Value $Value -ExpandedValue $expanded -Source $Source -Signals ($signals.ToArray()) -BaseScore 20 -Metadata @{
        FullPath        = $isFullPath
        Exists          = $exists
        AclTarget       = $aclTarget
        LowPrivWritable = $writable
        SignatureStatus = $signatureStatus
    }
}

function Measure-ExtensionExclusion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Source
    )

    $signals = New-Object System.Collections.Generic.List[object]
    $extension = $Value.Trim().TrimStart('.').ToLowerInvariant()

    if ($extension -in @('*', '.*', '?', '.?') -or [string]::IsNullOrWhiteSpace($extension)) {
        $signals.Add((New-RiskSignal 'EXTENSION-ALL' 'All or indeterminate extensions excluded' 100 'The entry can suppress scanning across nearly all file types.')) | Out-Null
    }
    elseif ($script:DangerousExtensions -contains $extension) {
        $signals.Add((New-RiskSignal 'EXTENSION-EXECUTABLE' 'Executable or script-capable extension excluded' 65 ('Microsoft identifies .{0} as a file type that should not be excluded.' -f $extension))) | Out-Null
    }
    elseif ($script:ArchiveExtensions -contains $extension) {
        $signals.Add((New-RiskSignal 'EXTENSION-ARCHIVE' 'Archive extension excluded' 40 ('Archive files can carry nested malicious content. Microsoft advises against excluding .{0}.' -f $extension))) | Out-Null
    }
    elseif ($script:DocumentAndImageExtensions -contains $extension) {
        $signals.Add((New-RiskSignal 'EXTENSION-CONTENT' 'Document or image extension excluded globally' 25 ('The .{0} exclusion applies in every location. Microsoft advises caution because parsers can contain vulnerabilities.' -f $extension) 'Medium')) | Out-Null
    }
    else {
        $signals.Add((New-RiskSignal 'EXTENSION-GLOBAL' 'Extension excluded in every location' 15 ('The .{0} exclusion is device-wide. Confirm why a path-scoped pattern is not sufficient.' -f $extension) 'Medium')) | Out-Null
    }

    if ($extension -match '[\\/:]') {
        $signals.Add((New-RiskSignal 'EXTENSION-MALFORMED' 'Extension value contains path characters' 20 'The value does not look like a simple extension and might not behave as intended.' 'Medium')) | Out-Null
    }

    New-ExclusionFinding -Type 'Extension' -Value $Value -ExpandedValue $extension -Source $Source -Signals ($signals.ToArray()) -BaseScore 20 -Metadata @{
        NormalizedExtension = $extension
    }
}

function Measure-IpAddressExclusion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Source
    )

    $signals = New-Object System.Collections.Generic.List[object]
    $trimmed = $Value.Trim()

    if ($trimmed -in @('*', '0.0.0.0', '0.0.0.0/0', '::', '::/0')) {
        $signals.Add((New-RiskSignal 'IP-ANY' 'Any-address exclusion' 100 'The entry appears to cover all IPv4 or IPv6 addresses.')) | Out-Null
    }
    elseif ($trimmed -match '^(.+)/(\d{1,3})$') {
        $prefix = [int]$Matches[2]
        $addressText = $Matches[1]
        $parsed = $null
        $valid = [Net.IPAddress]::TryParse($addressText, [ref]$parsed)
        if (-not $valid) {
            $signals.Add((New-RiskSignal 'IP-INVALID' 'IP network is not valid' 25 'The address portion could not be parsed.' 'Medium')) | Out-Null
        }
        elseif (($parsed.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork -and $prefix -gt 32) -or
                ($parsed.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6 -and $prefix -gt 128)) {
            $signals.Add((New-RiskSignal 'IP-INVALID' 'CIDR prefix is not valid' 25 ('The /{0} prefix is outside the valid range for this address family.' -f $prefix) 'Medium')) | Out-Null
        }
        elseif (($parsed.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork -and $prefix -le 16) -or
                ($parsed.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6 -and $prefix -le 64)) {
            $signals.Add((New-RiskSignal 'IP-BROAD-RANGE' 'Broad IP network excluded' 50 ('The /{0} prefix covers a large address range.' -f $prefix))) | Out-Null
        }
        else {
            $signals.Add((New-RiskSignal 'IP-RANGE' 'IP network excluded' 25 'Confirm the feature, owner, and smallest required address range.' 'Medium')) | Out-Null
        }
    }
    else {
        $parsed = $null
        if (-not [Net.IPAddress]::TryParse($trimmed, [ref]$parsed)) {
            $signals.Add((New-RiskSignal 'IP-INVALID' 'IP address is not valid' 25 'The value could not be parsed as an IPv4 or IPv6 address.' 'Medium')) | Out-Null
        }
        else {
            $signals.Add((New-RiskSignal 'IP-SINGLE' 'IP address excluded' 15 'A single address is narrower than a range, but the requirement still needs an owner and review date.' 'Medium')) | Out-Null
        }
    }

    New-ExclusionFinding -Type 'IpAddress' -Value $Value -ExpandedValue $trimmed -Source $Source -Signals ($signals.ToArray()) -BaseScore 20 -Metadata @{}
}

function Get-PolicyExclusionSets {
    [CmdletBinding()]
    param()

    $sets = @{
        Path      = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        Extension = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        Process   = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        IpAddress = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    }

    $keyMap = @{
        Path      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths'
        Extension = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Extensions'
        Process   = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Processes'
        IpAddress = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\IpAddresses'
    }

    foreach ($type in $keyMap.Keys) {
        try {
            if (Test-Path -LiteralPath $keyMap[$type]) {
                $item = Get-ItemProperty -LiteralPath $keyMap[$type] -ErrorAction Stop
                foreach ($property in $item.PSObject.Properties) {
                    if ($property.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$') {
                        $sets[$type].Add([string]$property.Name) | Out-Null
                    }
                }
            }
        }
        catch {
            Add-CoverageNote -Message ('Managed policy source detection failed for {0}: {1}' -f $type, $_.Exception.Message)
        }
    }

    return $sets
}

function Get-ExclusionState {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Preference)

    [pscustomobject][ordered]@{
        Path      = ConvertTo-StringArray (Get-PropertyValue $Preference 'ExclusionPath' @())
        Extension = ConvertTo-StringArray (Get-PropertyValue $Preference 'ExclusionExtension' @())
        Process   = ConvertTo-StringArray (Get-PropertyValue $Preference 'ExclusionProcess' @())
        IpAddress = ConvertTo-StringArray (Get-PropertyValue $Preference 'ExclusionIpAddress' @())
    }
}

function Get-DefenderContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Preference,
        [Parameter(Mandatory = $true)]$Status
    )

    $os = $null
    try { $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop } catch { Add-CoverageNote -Message ('Operating system inventory failed: {0}' -f $_.Exception.Message) }

    $disableLocalMerge = $null
    try {
        $policy = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -ErrorAction SilentlyContinue
        if ($policy) { $disableLocalMerge = Get-PropertyValue $policy 'DisableLocalAdminMerge' $null }
    }
    catch { Add-CoverageNote -Message ('Local policy merge state could not be read: {0}' -f $_.Exception.Message) }

    [pscustomobject][ordered]@{
        ComputerName                 = $env:COMPUTERNAME
        UserName                     = [Environment]::UserName
        IsAdministrator              = Test-IsAdministrator
        OSCaption                    = if ($os) { [string]$os.Caption } else { [Environment]::OSVersion.VersionString }
        OSVersion                    = if ($os) { [string]$os.Version } else { [string][Environment]::OSVersion.Version }
        ProductType                  = if ($os) { [int]$os.ProductType } else { $null }
        DefenderAntivirusEnabled     = Get-PropertyValue $Status 'AntivirusEnabled' $null
        RealTimeProtectionEnabled    = Get-PropertyValue $Status 'RealTimeProtectionEnabled' $null
        AMRunningMode                = Get-PropertyValue $Status 'AMRunningMode' $null
        IsTamperProtected            = Get-PropertyValue $Status 'IsTamperProtected' $null
        AMProductVersion             = Get-PropertyValue $Status 'AMProductVersion' $null
        AMEngineVersion              = Get-PropertyValue $Status 'AMEngineVersion' $null
        AntivirusSignatureVersion    = Get-PropertyValue $Status 'AntivirusSignatureVersion' $null
        AntivirusSignatureLastUpdated = Get-PropertyValue $Status 'AntivirusSignatureLastUpdated' $null
        DisableLocalAdminMerge       = $disableLocalMerge
        DisableAutoExclusions        = Get-PropertyValue $Preference 'DisableAutoExclusions' $null
    }
}

function Invoke-RiskAssessment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Exclusions,
        [Parameter(Mandatory = $true)]$PolicySets,
        [switch]$SkipAcl
    )

    $findings = New-Object System.Collections.Generic.List[object]
    foreach ($value in @($Exclusions.Path)) {
        $source = if ($PolicySets.Path.Contains($value)) { 'ManagedPolicy' } else { 'LocalOrOtherManagement' }
        $findings.Add((Measure-PathExclusion -Value $value -Source $source -SkipAcl:$SkipAcl)) | Out-Null
    }
    foreach ($value in @($Exclusions.Process)) {
        $source = if ($PolicySets.Process.Contains($value)) { 'ManagedPolicy' } else { 'LocalOrOtherManagement' }
        $findings.Add((Measure-ProcessExclusion -Value $value -Source $source -SkipAcl:$SkipAcl)) | Out-Null
    }
    foreach ($value in @($Exclusions.Extension)) {
        $source = if ($PolicySets.Extension.Contains($value)) { 'ManagedPolicy' } else { 'LocalOrOtherManagement' }
        $findings.Add((Measure-ExtensionExclusion -Value $value -Source $source)) | Out-Null
    }
    foreach ($value in @($Exclusions.IpAddress)) {
        $source = if ($PolicySets.IpAddress.Contains($value)) { 'ManagedPolicy' } else { 'LocalOrOtherManagement' }
        $findings.Add((Measure-IpAddressExclusion -Value $value -Source $source)) | Out-Null
    }

    return @($findings.ToArray() | Sort-Object @{Expression = { $script:RiskRank[$_.RiskLevel] }; Descending = $true}, @{Expression = 'Score'; Descending = $true}, Type, Value)
}

function Get-RiskSummary {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()]
        [object[]]$Findings
    )

    $summary = [ordered]@{ Critical = 0; High = 0; Medium = 0; Low = 0; Total = 0 }
    foreach ($finding in @($Findings)) {
        $summary[$finding.RiskLevel]++
        $summary.Total++
    }
    [pscustomobject]$summary
}

function Test-MeetsMinimumRisk {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$RiskLevel,
        [Parameter(Mandatory = $true)][string]$Minimum
    )

    return ($script:RiskRank[$RiskLevel] -ge $script:RiskRank[$Minimum])
}

function Get-RemediationCandidates {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Findings,
        [Parameter(Mandatory = $true)][string]$Minimum
    )

    @($Findings | Where-Object {
        (Test-MeetsMinimumRisk -RiskLevel $_.RiskLevel -Minimum $Minimum) -and -not $_.Managed
    })
}

function Select-HardeningFindings {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Candidates,
        [string[]]$RequestedIds
    )

    if ($Candidates.Count -eq 0) { return @() }

    $indexed = for ($i = 0; $i -lt $Candidates.Count; $i++) {
        [pscustomobject]@{
            Index     = $i + 1
            FindingId = $Candidates[$i].FindingId
            Risk      = $Candidates[$i].RiskLevel
            Score     = $Candidates[$i].Score
            Type      = $Candidates[$i].Type
            Value     = $Candidates[$i].Value
        }
    }

    if ($RequestedIds -and $RequestedIds.Count -gt 0) {
        $selected = New-Object System.Collections.Generic.List[object]
        foreach ($id in $RequestedIds) {
            $match = @($Candidates | Where-Object { $_.FindingId -ieq $id })
            if ($match.Count -eq 0) { throw ('Finding ID was not found or is not eligible: {0}' -f $id) }
            $selected.Add($match[0]) | Out-Null
        }
        return @($selected.ToArray() | Sort-Object FindingId -Unique)
    }

    if ($WhatIfPreference) { return @($Candidates) }

    Write-Section 'Eligible hardening candidates'
    $indexed | Format-Table -AutoSize | Out-Host
    Write-Host 'Enter comma-separated index numbers or Finding IDs. Enter ALL to select all. Press Enter to cancel.' -ForegroundColor Yellow
    $response = Read-Host 'Selection'
    if ([string]::IsNullOrWhiteSpace($response)) { return @() }
    if ($response.Trim() -ieq 'ALL') { return @($Candidates) }

    $selected = New-Object System.Collections.Generic.List[object]
    foreach ($token in ($response -split ',')) {
        $item = $token.Trim()
        if ([string]::IsNullOrWhiteSpace($item)) { continue }
        $number = 0
        if ([int]::TryParse($item, [ref]$number)) {
            if ($number -lt 1 -or $number -gt $Candidates.Count) { throw ('Selection index is out of range: {0}' -f $item) }
            $selected.Add($Candidates[$number - 1]) | Out-Null
        }
        else {
            $match = @($Candidates | Where-Object { $_.FindingId -ieq $item })
            if ($match.Count -eq 0) { throw ('Finding ID was not found: {0}' -f $item) }
            $selected.Add($match[0]) | Out-Null
        }
    }
    return @($selected.ToArray() | Sort-Object FindingId -Unique)
}

function New-ExclusionSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Exclusions,
        [Parameter(Mandatory = $true)]$Context
    )

    [pscustomobject][ordered]@{
        SchemaVersion  = $script:SchemaVersion
        ToolName       = $script:ToolName
        ToolVersion    = $script:ToolVersion
        SnapshotId     = [guid]::NewGuid().Guid
        CreatedUtc     = (Get-Date).ToUniversalTime().ToString('o')
        ComputerName   = $Context.ComputerName
        OSVersion      = $Context.OSVersion
        AMProductVersion = $Context.AMProductVersion
        Exclusions     = [pscustomobject][ordered]@{
            Path      = @($Exclusions.Path)
            Extension = @($Exclusions.Extension)
            Process   = @($Exclusions.Process)
            IpAddress = @($Exclusions.IpAddress)
        }
    }
}

function Save-JsonFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$InputObject,
        [Parameter(Mandatory = $true)][string]$Path,
        [int]$Depth = 10
    )

    $json = $InputObject | ConvertTo-Json -Depth $Depth
    Set-Content -LiteralPath $Path -Value $json -Encoding UTF8
}

function Save-SnapshotWithHash {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Snapshot,
        [Parameter(Mandatory = $true)][string]$Path
    )

    Save-JsonFile -InputObject $Snapshot -Path $Path -Depth 8
    $hash = Get-FileHash -LiteralPath $Path -Algorithm SHA256
    Set-Content -LiteralPath ($Path + '.sha256') -Value ('{0}  {1}' -f $hash.Hash, [IO.Path]::GetFileName($Path)) -Encoding ASCII
    return $hash.Hash
}

function Test-SnapshotIntegrity {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    $hashPath = $Path + '.sha256'
    if (-not (Test-Path -LiteralPath $hashPath -PathType Leaf)) {
        Add-CoverageNote -Message ('Snapshot hash sidecar was not found: {0}. Validate provenance manually before rollback.' -f $hashPath)
        return 'SidecarMissing'
    }

    $hashLine = Get-Content -LiteralPath $hashPath -TotalCount 1 -Encoding ASCII
    if ($hashLine -notmatch '^([A-Fa-f0-9]{64})(?:\s|$)') {
        throw ('Snapshot hash sidecar is malformed: {0}' -f $hashPath)
    }

    $expected = $Matches[1]
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    if ($actual -ine $expected) {
        throw ('Snapshot integrity check failed. Expected SHA-256 {0}, calculated {1}.' -f $expected, $actual)
    }

    return 'Verified'
}

function Get-DefenderParameterName {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Type)

    switch ($Type) {
        'Path'      { return 'ExclusionPath' }
        'Extension' { return 'ExclusionExtension' }
        'Process'   { return 'ExclusionProcess' }
        'IpAddress' { return 'ExclusionIpAddress' }
        default     { throw ('Unsupported exclusion type: {0}' -f $Type) }
    }
}

function Test-DefenderParameterAvailable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][string]$ParameterName
    )

    $cmd = Get-Command -Name $Command -ErrorAction SilentlyContinue
    return ($cmd -and $cmd.Parameters.ContainsKey($ParameterName))
}

function Invoke-RemoveExclusion {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Finding)

    $parameterName = Get-DefenderParameterName -Type $Finding.Type
    if (-not (Test-DefenderParameterAvailable -Command 'Remove-MpPreference' -ParameterName $parameterName)) {
        throw ('Remove-MpPreference on this device does not expose -{0}.' -f $parameterName)
    }

    $parameters = @{ ErrorAction = 'Stop'; Force = $true }
    $parameters[$parameterName] = @($Finding.Value)
    Remove-MpPreference @parameters
}

function Invoke-AddExclusion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Type,
        [Parameter(Mandatory = $true)][string]$Value
    )

    $parameterName = Get-DefenderParameterName -Type $Type
    if (-not (Test-DefenderParameterAvailable -Command 'Add-MpPreference' -ParameterName $parameterName)) {
        throw ('Add-MpPreference on this device does not expose -{0}.' -f $parameterName)
    }

    $parameters = @{ ErrorAction = 'Stop'; Force = $true }
    $parameters[$parameterName] = @($Value)
    Add-MpPreference @parameters
}

function Test-ExclusionPresent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Exclusions,
        [Parameter(Mandatory = $true)][string]$Type,
        [Parameter(Mandatory = $true)][string]$Value
    )

    $values = @($Exclusions.$Type)
    return (@($values | Where-Object { $_ -ieq $Value }).Count -gt 0)
}

function Invoke-Hardening {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$SelectedFindings
    )

    $changes = New-Object System.Collections.Generic.List[object]
    foreach ($finding in $SelectedFindings) {
        $target = '{0} exclusion: {1}' -f $finding.Type, $finding.Value
        $status = 'NotRun'
        $message = $null
        $started = Get-Date
        try {
            $current = Get-ExclusionState -Preference (Get-MpPreference -ErrorAction Stop)
            if (-not (Test-ExclusionPresent -Exclusions $current -Type $finding.Type -Value $finding.Value)) {
                $status = 'AlreadyAbsent'
                $message = 'The exclusion was already absent. No change was required.'
            }
            elseif ($script:CmdletContext.ShouldProcess($target, 'Remove Microsoft Defender Antivirus exclusion')) {
                Invoke-RemoveExclusion -Finding $finding
                $after = Get-ExclusionState -Preference (Get-MpPreference -ErrorAction Stop)
                if (Test-ExclusionPresent -Exclusions $after -Type $finding.Type -Value $finding.Value) {
                    $status = 'VerificationFailed'
                    $message = 'The exclusion is still present. A managed policy or tamper protection might have reapplied or blocked the change.'
                }
                else {
                    $status = 'Removed'
                    $message = 'The exclusion was removed and the effective preference was checked.'
                }
            }
            else {
                $status = if ($WhatIfPreference) { 'WhatIf' } else { 'Declined' }
                $message = 'No Defender setting was changed.'
            }
        }
        catch {
            $status = 'Failed'
            $message = $_.Exception.Message
        }

        $changes.Add([pscustomobject][ordered]@{
            TimestampUtc = $started.ToUniversalTime().ToString('o')
            Operation    = 'Remove'
            FindingId    = $finding.FindingId
            Type         = $finding.Type
            Value        = $finding.Value
            RiskLevel    = $finding.RiskLevel
            Score        = $finding.Score
            Status       = $status
            Message      = $message
        }) | Out-Null
    }
    return @($changes.ToArray())
}

function Get-StateDifferences {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Current,
        [Parameter(Mandatory = $true)]$Desired
    )

    $differences = New-Object System.Collections.Generic.List[object]
    foreach ($type in @('Path', 'Extension', 'Process', 'IpAddress')) {
        $currentSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        $desiredSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        foreach ($value in @($Current.$type)) { $currentSet.Add([string]$value) | Out-Null }
        foreach ($value in @($Desired.$type)) { $desiredSet.Add([string]$value) | Out-Null }

        foreach ($value in @($Current.$type)) {
            if (-not $desiredSet.Contains([string]$value)) {
                $differences.Add([pscustomobject]@{ Operation = 'Remove'; Type = $type; Value = [string]$value }) | Out-Null
            }
        }
        foreach ($value in @($Desired.$type)) {
            if (-not $currentSet.Contains([string]$value)) {
                $differences.Add([pscustomobject]@{ Operation = 'Add'; Type = $type; Value = [string]$value }) | Out-Null
            }
        }
    }
    return @($differences.ToArray())
}

function Invoke-RollbackState {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$DesiredState)

    $changes = New-Object System.Collections.Generic.List[object]
    $current = Get-ExclusionState -Preference (Get-MpPreference -ErrorAction Stop)
    $differences = Get-StateDifferences -Current $current -Desired $DesiredState

    foreach ($difference in @($differences | Sort-Object @{Expression = { if ($_.Operation -eq 'Remove') { 0 } else { 1 } }})) {
        $target = '{0} exclusion: {1}' -f $difference.Type, $difference.Value
        $status = 'NotRun'
        $message = $null
        try {
            if ($script:CmdletContext.ShouldProcess($target, ('Rollback operation: {0}' -f $difference.Operation))) {
                if ($difference.Operation -eq 'Remove') {
                    $finding = [pscustomobject]@{ Type = $difference.Type; Value = $difference.Value }
                    Invoke-RemoveExclusion -Finding $finding
                }
                else {
                    Invoke-AddExclusion -Type $difference.Type -Value $difference.Value
                }
                $status = 'Applied'
                $message = 'The rollback operation completed.'
            }
            else {
                $status = if ($WhatIfPreference) { 'WhatIf' } else { 'Declined' }
                $message = 'No Defender setting was changed.'
            }
        }
        catch {
            $status = 'Failed'
            $message = $_.Exception.Message
        }

        $changes.Add([pscustomobject][ordered]@{
            TimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
            Operation    = $difference.Operation
            FindingId    = $null
            Type         = $difference.Type
            Value        = $difference.Value
            RiskLevel    = $null
            Score        = $null
            Status       = $status
            Message      = $message
        }) | Out-Null
    }

    $verified = Get-ExclusionState -Preference (Get-MpPreference -ErrorAction Stop)
    $remaining = Get-StateDifferences -Current $verified -Desired $DesiredState
    [pscustomobject]@{
        Changes              = @($changes.ToArray())
        RemainingDifferences = @($remaining)
        Verified             = ($remaining.Count -eq 0)
    }
}

function ConvertTo-FlatFinding {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Finding)

    [pscustomobject][ordered]@{
        FindingId            = $Finding.FindingId
        RiskLevel            = $Finding.RiskLevel
        Score                = $Finding.Score
        Type                 = $Finding.Type
        Value                = $Finding.Value
        ExpandedValue        = $Finding.ExpandedValue
        Source               = $Finding.Source
        Managed              = $Finding.Managed
        RiskReasons          = (@($Finding.Signals | ForEach-Object { '[{0} +{1}] {2}' -f $_.RuleId, $_.Points, $_.Title }) -join '; ')
        RecommendedAction    = $Finding.RecommendedAction
        SuggestedReplacement = $Finding.SuggestedReplacement
    }
}

function ConvertTo-HtmlEncoded {
    [CmdletBinding()]
    param($Value)

    if ($null -eq $Value) { return '' }
    return [Net.WebUtility]::HtmlEncode([string]$Value)
}

function Get-RiskCssClass {
    [CmdletBinding()]
    param([string]$RiskLevel)
    return ('risk-{0}' -f $RiskLevel.ToLowerInvariant())
}

function New-HtmlReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Report,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $before = @($Report.AuditBefore.Findings)
    $after = if ($Report.AuditAfter) { @($Report.AuditAfter.Findings) } else { @() }
    $summary = $Report.AuditBefore.Summary
    $context = $Report.Context

    $rows = New-Object Text.StringBuilder
    foreach ($finding in $before) {
        $reasonHtml = (@($finding.Signals | ForEach-Object {
            '<li><strong>{0}</strong> (+{1}) - {2}</li>' -f (ConvertTo-HtmlEncoded $_.Title), $_.Points, (ConvertTo-HtmlEncoded $_.Detail)
        }) -join '')
        [void]$rows.AppendLine(('<tr><td><span class="badge {0}">{1}</span><div class="score">{2}/100</div></td><td><strong>{3}</strong><div class="muted">{4}</div></td><td><code>{5}</code><div class="muted">{6}</div></td><td><ul>{7}</ul></td><td>{8}<div class="recommend">{9}</div></td></tr>' -f
            (Get-RiskCssClass $finding.RiskLevel),
            (ConvertTo-HtmlEncoded $finding.RiskLevel),
            $finding.Score,
            (ConvertTo-HtmlEncoded $finding.Type),
            (ConvertTo-HtmlEncoded $finding.Source),
            (ConvertTo-HtmlEncoded $finding.Value),
            (ConvertTo-HtmlEncoded $finding.FindingId),
            $reasonHtml,
            (ConvertTo-HtmlEncoded $finding.RecommendedAction),
            (ConvertTo-HtmlEncoded $finding.SuggestedReplacement)))
    }

    if ($before.Count -eq 0) {
        [void]$rows.AppendLine('<tr><td colspan="5" class="empty">No custom exclusions were returned by Get-MpPreference.</td></tr>')
    }

    $changeRows = New-Object Text.StringBuilder
    foreach ($change in @($Report.Changes)) {
        [void]$changeRows.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td><code>{3}</code></td><td>{4}</td><td>{5}</td></tr>' -f
            (ConvertTo-HtmlEncoded $change.TimestampUtc),
            (ConvertTo-HtmlEncoded $change.Operation),
            (ConvertTo-HtmlEncoded $change.Type),
            (ConvertTo-HtmlEncoded $change.Value),
            (ConvertTo-HtmlEncoded $change.Status),
            (ConvertTo-HtmlEncoded $change.Message)))
    }

    $coverageItems = @($Report.Coverage.Notes | ForEach-Object { '<li>{0}</li>' -f (ConvertTo-HtmlEncoded $_) }) -join ''
    if ([string]::IsNullOrWhiteSpace($coverageItems)) { $coverageItems = '<li>No runtime coverage gaps were recorded.</li>' }

    $afterSection = ''
    if ($Report.AuditAfter) {
        $afterSummary = $Report.AuditAfter.Summary
        $afterSection = @"
<section>
  <h2>Post change verification</h2>
  <p>The tool re-read the effective Defender preferences after the requested operations.</p>
  <div class="cards compact">
    <div class="card"><span>Remaining exclusions</span><strong>$($afterSummary.Total)</strong></div>
    <div class="card"><span>Critical</span><strong>$($afterSummary.Critical)</strong></div>
    <div class="card"><span>High</span><strong>$($afterSummary.High)</strong></div>
    <div class="card"><span>Medium</span><strong>$($afterSummary.Medium)</strong></div>
  </div>
</section>
"@
    }

    $changesSection = ''
    if (@($Report.Changes).Count -gt 0) {
        $changesSection = @"
<section>
  <h2>Change log</h2>
  <div class="table-wrap"><table><thead><tr><th>UTC time</th><th>Operation</th><th>Type</th><th>Value</th><th>Status</th><th>Message</th></tr></thead><tbody>$($changeRows.ToString())</tbody></table></div>
</section>
"@
    }

    $html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Defender Exclusion Risk Report</title>
<style>
:root{--bg:#0b0d10;--panel:#14181e;--panel2:#1a2028;--text:#edf0f3;--muted:#aab2bd;--line:#323945;--gold:#d6ad45;--critical:#ff5c6c;--high:#ff9f43;--medium:#ffd166;--low:#57d38c;--silver:#c8ced6}
*{box-sizing:border-box}body{margin:0;background:linear-gradient(135deg,#080a0d 0%,#11161d 55%,#090b0e 100%);color:var(--text);font:15px/1.55 "Segoe UI",Arial,sans-serif}main{max-width:1500px;margin:0 auto;padding:38px 28px 64px}.hero{border:1px solid var(--line);background:linear-gradient(135deg,rgba(214,173,69,.14),rgba(20,24,30,.94) 38%);padding:30px;border-radius:16px;box-shadow:0 18px 50px rgba(0,0,0,.35)}.brand{color:var(--gold);font-size:12px;letter-spacing:.18em;text-transform:uppercase;font-weight:700}h1{font-size:34px;margin:8px 0 6px;line-height:1.15}h2{font-size:22px;margin:0 0 14px;color:var(--silver)}p{color:var(--muted);max-width:980px}.meta{display:flex;flex-wrap:wrap;gap:10px;margin-top:18px}.meta span{border:1px solid var(--line);background:#0e1217;border-radius:999px;padding:6px 11px;color:var(--silver);font-size:13px}.cards{display:grid;grid-template-columns:repeat(5,minmax(130px,1fr));gap:14px;margin:22px 0}.cards.compact{grid-template-columns:repeat(4,minmax(130px,1fr))}.card{background:var(--panel);border:1px solid var(--line);border-radius:13px;padding:17px}.card span{display:block;color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.08em}.card strong{display:block;margin-top:5px;font-size:28px}section{margin-top:26px;background:rgba(20,24,30,.96);border:1px solid var(--line);border-radius:16px;padding:24px}.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:11px}table{width:100%;border-collapse:collapse;min-width:1050px;background:#101419}th{background:#1d232c;color:var(--silver);text-align:left;font-size:12px;text-transform:uppercase;letter-spacing:.06em;padding:13px;border-bottom:1px solid var(--line)}td{vertical-align:top;padding:14px 13px;border-bottom:1px solid #272e38}tr:last-child td{border-bottom:0}code{color:#f2d98d;word-break:break-all;font-family:Consolas,monospace}ul{padding-left:18px;margin:0}li{margin:0 0 7px}.badge{display:inline-block;padding:4px 9px;border-radius:999px;font-weight:700;font-size:12px;color:#090b0e}.risk-critical{background:var(--critical)}.risk-high{background:var(--high)}.risk-medium{background:var(--medium)}.risk-low{background:var(--low)}.score{font-weight:700;margin-top:7px}.muted{color:var(--muted);font-size:12px;margin-top:4px}.recommend{color:var(--muted);font-size:13px;margin-top:8px}.empty{text-align:center;color:var(--muted);padding:30px}dl{display:grid;grid-template-columns:230px 1fr;gap:8px 18px;margin:0}dt{color:var(--muted)}dd{margin:0;color:var(--text)}footer{color:#77808d;margin-top:20px;text-align:center;font-size:12px}@media(max-width:900px){.cards,.cards.compact{grid-template-columns:repeat(2,1fr)}main{padding:20px 12px}h1{font-size:27px}dl{grid-template-columns:1fr;gap:2px}dd{margin-bottom:10px}}
</style>
</head>
<body><main>
<div class="hero">
  <div class="brand">RuleRivet security automation</div>
  <h1>Defender Exclusion Risk Report</h1>
  <p>Custom Microsoft Defender Antivirus exclusions ranked by deterministic exposure signals. Validate business need and application impact before removing any exclusion.</p>
  <div class="meta"><span>Mode: $(ConvertTo-HtmlEncoded $Report.Mode)</span><span>Computer: $(ConvertTo-HtmlEncoded $context.ComputerName)</span><span>Generated: $(ConvertTo-HtmlEncoded $Report.CompletedUtc)</span><span>Run ID: $(ConvertTo-HtmlEncoded $Report.RunId)</span></div>
</div>
<div class="cards">
  <div class="card"><span>Total exclusions</span><strong>$($summary.Total)</strong></div>
  <div class="card"><span>Critical</span><strong>$($summary.Critical)</strong></div>
  <div class="card"><span>High</span><strong>$($summary.High)</strong></div>
  <div class="card"><span>Medium</span><strong>$($summary.Medium)</strong></div>
  <div class="card"><span>Low</span><strong>$($summary.Low)</strong></div>
</div>
<section>
  <h2>Host and Defender state</h2>
  <dl>
    <dt>Operating system</dt><dd>$(ConvertTo-HtmlEncoded $context.OSCaption) $(ConvertTo-HtmlEncoded $context.OSVersion)</dd>
    <dt>Administrator</dt><dd>$(ConvertTo-HtmlEncoded $context.IsAdministrator)</dd>
    <dt>Antivirus enabled</dt><dd>$(ConvertTo-HtmlEncoded $context.DefenderAntivirusEnabled)</dd>
    <dt>Real-time protection</dt><dd>$(ConvertTo-HtmlEncoded $context.RealTimeProtectionEnabled)</dd>
    <dt>Running mode</dt><dd>$(ConvertTo-HtmlEncoded $context.AMRunningMode)</dd>
    <dt>Tamper protected</dt><dd>$(ConvertTo-HtmlEncoded $context.IsTamperProtected)</dd>
    <dt>Platform version</dt><dd>$(ConvertTo-HtmlEncoded $context.AMProductVersion)</dd>
    <dt>Engine version</dt><dd>$(ConvertTo-HtmlEncoded $context.AMEngineVersion)</dd>
    <dt>Security intelligence</dt><dd>$(ConvertTo-HtmlEncoded $context.AntivirusSignatureVersion)</dd>
    <dt>Local admin merge disabled</dt><dd>$(ConvertTo-HtmlEncoded $context.DisableLocalAdminMerge)</dd>
  </dl>
</section>
<section>
  <h2>Risk findings</h2>
  <div class="table-wrap"><table><thead><tr><th>Risk</th><th>Type and source</th><th>Exclusion</th><th>Reasons</th><th>Recommendation</th></tr></thead><tbody>$($rows.ToString())</tbody></table></div>
</section>
$changesSection
$afterSection
<section>
  <h2>Coverage and interpretation</h2>
  <p>Scores are deterministic triage aids. They do not prove malicious intent and do not replace vendor guidance, change control, testing, or workload-owner approval. Built-in and automatic Windows Server role exclusions do not normally appear in the custom lists returned by Get-MpPreference.</p>
  <ul>$coverageItems</ul>
  <p>ACL analysis is heuristic. An allow entry for a low-privilege principal can raise risk even when a separate deny entry or another control changes effective access. Confirm effective permissions before remediation.</p>
</section>
<footer>$($script:ToolName) v$($script:ToolVersion) - RuleRivet</footer>
</main></body></html>
"@

    Set-Content -LiteralPath $Path -Value $html -Encoding UTF8
}

function Write-ReportFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Report,
        [Parameter(Mandatory = $true)][string]$Directory
    )

    $jsonPath = Join-Path $Directory 'Defender-Exclusion-Risk-Report.json'
    $csvPath = Join-Path $Directory 'Defender-Exclusion-Risk-Findings.csv'
    $htmlPath = Join-Path $Directory 'Defender-Exclusion-Risk-Report.html'

    Save-JsonFile -InputObject $Report -Path $jsonPath -Depth 12
    @($Report.AuditBefore.Findings | ForEach-Object { ConvertTo-FlatFinding $_ }) |
        Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
    New-HtmlReport -Report $Report -Path $htmlPath

    if ($Report.Plan) {
        $planJson = Join-Path $Directory 'Defender-Exclusion-Remediation-Plan.json'
        $planCsv = Join-Path $Directory 'Defender-Exclusion-Remediation-Plan.csv'
        Save-JsonFile -InputObject $Report.Plan -Path $planJson -Depth 10
        @($Report.Plan.Candidates | ForEach-Object { ConvertTo-FlatFinding $_ }) |
            Export-Csv -LiteralPath $planCsv -NoTypeInformation -Encoding UTF8
    }

    if (@($Report.Changes).Count -gt 0) {
        $changeJson = Join-Path $Directory 'Defender-Exclusion-Change-Log.json'
        $changeCsv = Join-Path $Directory 'Defender-Exclusion-Change-Log.csv'
        Save-JsonFile -InputObject @($Report.Changes) -Path $changeJson -Depth 8
        @($Report.Changes) | Export-Csv -LiteralPath $changeCsv -NoTypeInformation -Encoding UTF8
    }

    [pscustomobject]@{
        Html = $htmlPath
        Json = $jsonPath
        Csv  = $csvPath
    }
}

function Write-ConsoleSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Summary,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Findings
    )

    Write-Section 'Risk summary'
    Write-Host ('  Critical: {0}' -f $Summary.Critical) -ForegroundColor Red
    Write-Host ('  High:     {0}' -f $Summary.High) -ForegroundColor DarkYellow
    Write-Host ('  Medium:   {0}' -f $Summary.Medium) -ForegroundColor Yellow
    Write-Host ('  Low:      {0}' -f $Summary.Low) -ForegroundColor Green
    Write-Host ('  Total:    {0}' -f $Summary.Total) -ForegroundColor Gray

    if ($Findings.Count -gt 0) {
        Write-Section 'Highest risk exclusions'
        @($Findings | Select-Object -First 12 FindingId, RiskLevel, Score, Type, Value) | Format-Table -AutoSize -Wrap | Out-Host
    }
}

function Invoke-RiskEngineSelfTest {
    [CmdletBinding()]
    param()

    Write-Banner
    Write-Section 'Synthetic self-test'
    $tests = New-Object System.Collections.Generic.List[object]

    $cases = @(
        @{ Name = 'Drive root is Critical'; Finding = { Measure-PathExclusion -Value 'C:\' -Source 'LocalOrOtherManagement' -SkipAcl }; Expected = 'Critical' },
        @{ Name = 'PowerShell process is Critical'; Finding = { Measure-ProcessExclusion -Value 'powershell.exe' -Source 'LocalOrOtherManagement' -SkipAcl }; Expected = 'Critical' },
        @{ Name = 'Executable extension is Critical'; Finding = { Measure-ExtensionExclusion -Value '.exe' -Source 'LocalOrOtherManagement' }; Expected = 'Critical' },
        @{ Name = 'Archive extension is High'; Finding = { Measure-ExtensionExclusion -Value '.zip' -Source 'LocalOrOtherManagement' }; Expected = 'High' },
        @{ Name = 'Single IP is Medium'; Finding = { Measure-IpAddressExclusion -Value '192.0.2.10' -Source 'LocalOrOtherManagement' }; Expected = 'Medium' },
        @{ Name = 'Any IPv4 network is Critical'; Finding = { Measure-IpAddressExclusion -Value '0.0.0.0/0' -Source 'LocalOrOtherManagement' }; Expected = 'Critical' },
        @{ Name = 'Invalid IPv4 CIDR is Medium'; Finding = { Measure-IpAddressExclusion -Value '192.0.2.0/99' -Source 'LocalOrOtherManagement' }; Expected = 'Medium' }
    )

    foreach ($case in $cases) {
        try {
            $finding = & $case.Finding
            $passed = ($finding.RiskLevel -eq $case.Expected)
            $tests.Add([pscustomobject]@{
                Test     = $case.Name
                Expected = $case.Expected
                Actual   = $finding.RiskLevel
                Score    = $finding.Score
                Passed   = $passed
            }) | Out-Null
        }
        catch {
            $tests.Add([pscustomobject]@{
                Test     = $case.Name
                Expected = $case.Expected
                Actual   = 'Error'
                Score    = $null
                Passed   = $false
            }) | Out-Null
            Write-Warning ('{0} failed: {1}' -f $case.Name, $_.Exception.Message)
            if ($_.InvocationInfo.PositionMessage) {
                Write-Verbose $_.InvocationInfo.PositionMessage
            }
        }
    }

    try {
        $emptyFindings = @()
        $emptySummary = Get-RiskSummary -Findings $emptyFindings
        $emptyCandidates = @(Get-RemediationCandidates -Findings $emptyFindings -Minimum 'High')
        & { Write-ConsoleSummary -Summary $emptySummary -Findings $emptyFindings } *> $null

        $passed = ($emptySummary.Total -eq 0 -and $emptyCandidates.Count -eq 0)
        $tests.Add([pscustomobject]@{
            Test     = 'Empty findings are accepted'
            Expected = 'Pass'
            Actual   = if ($passed) { 'Pass' } else { 'Fail' }
            Score    = $null
            Passed   = $passed
        }) | Out-Null
    }
    catch {
        $tests.Add([pscustomobject]@{
            Test     = 'Empty findings are accepted'
            Expected = 'Pass'
            Actual   = 'Error'
            Score    = $null
            Passed   = $false
        }) | Out-Null
        Write-Warning $_.Exception.Message
    }

    $tests | Format-Table -AutoSize | Out-Host
    $failed = @($tests | Where-Object { -not $_.Passed })
    if ($failed.Count -gt 0) { throw ('Self-test failed: {0} test(s).' -f $failed.Count) }
    Write-Host 'All synthetic risk-engine tests passed.' -ForegroundColor Green
}

try {
    if ($SelfTest) {
        Invoke-RiskEngineSelfTest
        return
    }

    Assert-WindowsPlatform
    Assert-DefenderModule
    Write-Banner
    $OutputDirectory = Initialize-OutputDirectory -RequestedPath $OutputDirectory

    if ($Mode -in @('Harden', 'Rollback') -and -not (Test-IsAdministrator)) {
        throw ('{0} mode requires an elevated PowerShell session. Audit and Plan modes do not require elevation.' -f $Mode)
    }

    Write-Section 'Collecting Defender state'
    $preferenceBefore = Get-MpPreference -ErrorAction Stop
    $status = Get-MpComputerStatus -ErrorAction Stop
    $context = Get-DefenderContext -Preference $preferenceBefore -Status $status
    $policySets = Get-PolicyExclusionSets
    $exclusionsBefore = Get-ExclusionState -Preference $preferenceBefore
    if ($context.DisableLocalAdminMerge -eq 1) {
        foreach ($type in @('Path', 'Extension', 'Process', 'IpAddress')) {
            foreach ($value in @($exclusionsBefore.$type)) {
                $policySets[$type].Add([string]$value) | Out-Null
            }
        }
        Add-CoverageNote -Message 'Local administrator exclusion merging is disabled. Effective exclusions were treated as managed policy and were not eligible for local hardening.'
    }
    $findingsBefore = @(Invoke-RiskAssessment -Exclusions $exclusionsBefore -PolicySets $policySets -SkipAcl:$SkipAclAnalysis)
    $summaryBefore = Get-RiskSummary -Findings $findingsBefore
    Write-ConsoleSummary -Summary $summaryBefore -Findings $findingsBefore

    $plan = $null
    $changes = @()
    $auditAfter = $null
    $snapshotFile = $null
    $snapshotHash = $null
    $snapshotHashStatus = $null
    $rollbackVerification = $null

    if ($Mode -in @('Plan', 'Harden')) {
        $candidates = @(Get-RemediationCandidates -Findings $findingsBefore -Minimum $MinimumRisk)
        $managedBlocked = @($findingsBefore | Where-Object {
            $_.Managed -and (Test-MeetsMinimumRisk -RiskLevel $_.RiskLevel -Minimum $MinimumRisk)
        })
        $plan = [pscustomobject][ordered]@{
            GeneratedUtc          = (Get-Date).ToUniversalTime().ToString('o')
            MinimumRisk           = $MinimumRisk
            CandidateCount        = $candidates.Count
            ManagedPolicyBlocked  = $managedBlocked.Count
            Candidates            = @($candidates)
            ManagedPolicyFindings = @($managedBlocked)
        }

        Write-Section 'Remediation plan'
        Write-Host ('  Eligible local or other-management candidates: {0}' -f $candidates.Count) -ForegroundColor Gray
        Write-Host ('  Managed policy findings requiring source-policy change: {0}' -f $managedBlocked.Count) -ForegroundColor Gray
    }

    if ($Mode -eq 'Harden') {
        $selected = @(Select-HardeningFindings -Candidates @($plan.Candidates) -RequestedIds $FindingId)
        if ($selected.Count -eq 0) {
            Write-Warning 'No findings were selected. Defender settings were not changed.'
        }
        else {
            Write-Section 'Hardening safety gate'
            Write-Host ('Selected exclusions: {0}' -f $selected.Count) -ForegroundColor Yellow
            @($selected | Select-Object FindingId, RiskLevel, Score, Type, Value) | Format-Table -AutoSize -Wrap | Out-Host

            if (-not $Force -and -not $WhatIfPreference) {
                Write-Host 'Removing an exclusion can affect application performance or stability.' -ForegroundColor Yellow
                $typed = Read-Host 'Type HARDEN to continue'
                if ($typed -cne 'HARDEN') { throw 'Hardening cancelled. The confirmation text did not match HARDEN.' }
            }

            $snapshot = New-ExclusionSnapshot -Exclusions $exclusionsBefore -Context $context
            $snapshotFile = Join-Path $OutputDirectory 'Snapshot-Before-Hardening.json'
            $snapshotHash = Save-SnapshotWithHash -Snapshot $snapshot -Path $snapshotFile
            Write-Host ('Snapshot saved: {0}' -f $snapshotFile) -ForegroundColor Green

            $changes = Invoke-Hardening -SelectedFindings $selected
            $preferenceAfter = Get-MpPreference -ErrorAction Stop
            $exclusionsAfter = Get-ExclusionState -Preference $preferenceAfter
            $findingsAfter = @(Invoke-RiskAssessment -Exclusions $exclusionsAfter -PolicySets $policySets -SkipAcl:$SkipAclAnalysis)
            $auditAfter = [pscustomobject]@{
                Exclusions = $exclusionsAfter
                Findings   = @($findingsAfter)
                Summary    = Get-RiskSummary -Findings $findingsAfter
            }
        }
    }

    if ($Mode -eq 'Rollback') {
        if ([string]::IsNullOrWhiteSpace($SnapshotPath)) { throw 'Rollback mode requires -SnapshotPath.' }
        $resolvedSnapshot = (Resolve-Path -LiteralPath $SnapshotPath -ErrorAction Stop).Path
        $snapshotHashStatus = Test-SnapshotIntegrity -Path $resolvedSnapshot
        $snapshot = Get-Content -LiteralPath $resolvedSnapshot -Raw -Encoding UTF8 | ConvertFrom-Json
        if ((Get-PropertyValue $snapshot 'SchemaVersion' $null) -ne $script:SchemaVersion) {
            throw ('Unsupported snapshot schema. Expected {0}.' -f $script:SchemaVersion)
        }
        if (-not $snapshot.Exclusions) { throw 'The snapshot does not contain an Exclusions object.' }
        if (-not $AllowDifferentComputer -and $snapshot.ComputerName -and $snapshot.ComputerName -ine $env:COMPUTERNAME) {
            throw ('Snapshot computer {0} does not match this computer {1}. Use -AllowDifferentComputer only after validating the target.' -f $snapshot.ComputerName, $env:COMPUTERNAME)
        }

        $desiredState = [pscustomobject]@{
            Path      = ConvertTo-StringArray (Get-PropertyValue $snapshot.Exclusions 'Path' @())
            Extension = ConvertTo-StringArray (Get-PropertyValue $snapshot.Exclusions 'Extension' @())
            Process   = ConvertTo-StringArray (Get-PropertyValue $snapshot.Exclusions 'Process' @())
            IpAddress = ConvertTo-StringArray (Get-PropertyValue $snapshot.Exclusions 'IpAddress' @())
        }

        $differences = @(Get-StateDifferences -Current $exclusionsBefore -Desired $desiredState)
        Write-Section 'Rollback safety gate'
        Write-Host ('Snapshot: {0}' -f $resolvedSnapshot) -ForegroundColor Gray
        Write-Host ('Snapshot integrity: {0}' -f $snapshotHashStatus) -ForegroundColor Gray
        Write-Host ('Required operations: {0}' -f $differences.Count) -ForegroundColor Yellow
        if ($differences.Count -gt 0) { $differences | Format-Table -AutoSize -Wrap | Out-Host }

        if ($differences.Count -gt 0 -and -not $Force -and -not $WhatIfPreference) {
            Write-Host 'Rollback can re-add exclusions and reduce protection. Validate the snapshot and application requirement.' -ForegroundColor Yellow
            $typed = Read-Host 'Type ROLLBACK to continue'
            if ($typed -cne 'ROLLBACK') { throw 'Rollback cancelled. The confirmation text did not match ROLLBACK.' }
        }

        $rollbackResult = Invoke-RollbackState -DesiredState $desiredState
        $changes = @($rollbackResult.Changes)
        $rollbackVerification = [pscustomobject]@{
            Verified             = $rollbackResult.Verified
            RemainingDifferences = @($rollbackResult.RemainingDifferences)
            SnapshotPath         = $resolvedSnapshot
            SnapshotHashStatus   = $snapshotHashStatus
        }

        $preferenceAfter = Get-MpPreference -ErrorAction Stop
        $exclusionsAfter = Get-ExclusionState -Preference $preferenceAfter
        $findingsAfter = @(Invoke-RiskAssessment -Exclusions $exclusionsAfter -PolicySets $policySets -SkipAcl:$SkipAclAnalysis)
        $auditAfter = [pscustomobject]@{
            Exclusions = $exclusionsAfter
            Findings   = @($findingsAfter)
            Summary    = Get-RiskSummary -Findings $findingsAfter
        }
    }

    if ($SkipAclAnalysis) { Add-CoverageNote -Message 'ACL analysis was skipped by operator request.' }
    if ($context.ProductType -and $context.ProductType -ne 1) {
        Add-CoverageNote -Message 'Windows Server built-in and automatic role exclusions are separate from custom exclusions and normally do not appear in this report.'
    }
    Add-CoverageNote -Message 'The tool reports effective custom exclusions returned by Get-MpPreference. A management platform can reapply a setting after local remediation.'
    Add-CoverageNote -Message 'Risk scoring is deterministic and heuristic. Validate vendor support guidance, workload ownership, effective permissions, and change impact.'

    $report = [pscustomobject][ordered]@{
        SchemaVersion = $script:SchemaVersion
        ToolName      = $script:ToolName
        ToolVersion   = $script:ToolVersion
        RunId         = $script:RunId
        Mode          = $Mode
        StartedUtc    = $script:RunStartedUtc.ToString('o')
        CompletedUtc  = (Get-Date).ToUniversalTime().ToString('o')
        Context       = $context
        AuditBefore   = [pscustomobject]@{
            Exclusions = $exclusionsBefore
            Findings   = @($findingsBefore)
            Summary    = $summaryBefore
        }
        Plan          = $plan
        Changes       = @($changes)
        AuditAfter    = $auditAfter
        Snapshot      = if ($snapshotFile) { [pscustomobject]@{ Path = $snapshotFile; Sha256 = $snapshotHash } } else { $null }
        Rollback      = $rollbackVerification
        Coverage      = [pscustomobject]@{
            AclAnalysisSkipped      = [bool]$SkipAclAnalysis
            AclAttempts             = $script:AclAttemptCount
            AclSuccesses            = $script:AclSuccessCount
            SignatureAttempts       = $script:SignatureAttemptCount
            SignatureSuccesses      = $script:SignatureSuccessCount
            Notes                    = @($script:CoverageNotes.ToArray())
        }
    }

    Write-Section 'Writing evidence'
    $paths = Write-ReportFiles -Report $report -Directory $OutputDirectory
    Write-Host ('  HTML: {0}' -f $paths.Html) -ForegroundColor Green
    Write-Host ('  JSON: {0}' -f $paths.Json) -ForegroundColor Green
    Write-Host ('  CSV:  {0}' -f $paths.Csv) -ForegroundColor Green
    if ($snapshotFile) { Write-Host ('  Rollback snapshot: {0}' -f $snapshotFile) -ForegroundColor Green }

    if ($OpenReport) {
        Start-Process -FilePath $paths.Html
    }

    [pscustomobject]@{
        Mode            = $Mode
        OutputDirectory = $OutputDirectory
        HtmlReport      = $paths.Html
        JsonReport      = $paths.Json
        CsvFindings     = $paths.Csv
        SnapshotPath    = $snapshotFile
        Summary         = $summaryBefore
        Changes         = @($changes)
    }
}
catch {
    Write-Host ''
    Write-Host ('ERROR: {0}' -f $_.Exception.Message) -ForegroundColor Red
    Write-Host 'No further action was taken. Review the error, permissions, Defender management source, and report directory.' -ForegroundColor Yellow
    throw
}
