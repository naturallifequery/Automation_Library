#requires -Version 5.1

<#
.SYNOPSIS
    Audits and optionally hardens Windows Schannel TLS settings.

.DESCRIPTION
    Every run begins in read-only audit mode. Registry changes are made only
    after the operator selects Harden, answers the modern TLS prompts, and
    types the final confirmation word HARDEN.

    The script disables SSL 2.0, SSL 3.0, TLS 1.0 and TLS 1.1 for both Schannel
    client and server roles. It also disables currently enabled cipher suites
    whose names indicate NULL, RC2, RC4, DES/3DES, EXPORT, MD5 or CBC.

    TLS 1.2 can be explicitly enabled at the operator's request. TLS 1.3 is
    offered only when the detected Windows version supports Schannel TLS 1.3.

.NOTES
    Version: 1.0.1
    Run in Windows PowerShell 5.1 as Administrator for hardening mode.
    A reboot is not performed automatically.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$SchannelProtocolsPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
$CipherPolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002'
$CipherLocalRegPath = 'HKLM\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002'
$SchannelRegPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'

function Write-Section {
    param([Parameter(Mandatory = $true)][string]$Text)

    Write-Host ''
    Write-Host ('=' * 72) -ForegroundColor DarkGray
    Write-Host $Text -ForegroundColor Cyan
    Write-Host ('=' * 72) -ForegroundColor DarkGray
}

function Get-RegistryValue {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )

    try {
        $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
        [pscustomobject]@{
            Exists = $true
            Value  = $item.PSObject.Properties[$Name].Value
        }
    }
    catch {
        [pscustomobject]@{
            Exists = $false
            Value  = $null
        }
    }
}

function Get-ProtocolSetting {
    param([Parameter(Mandatory = $true)][string]$Path)

    $enabled = Get-RegistryValue -Path $Path -Name 'Enabled'
    $disabledByDefault = Get-RegistryValue -Path $Path -Name 'DisabledByDefault'

    if (-not $enabled.Exists -and -not $disabledByDefault.Exists) {
        return 'OS default'
    }

    if ($enabled.Exists -and [int64]$enabled.Value -eq 0) {
        return 'Explicitly disabled'
    }

    if ($enabled.Exists -and [int64]$enabled.Value -ne 0) {
        if ($disabledByDefault.Exists -and [int64]$disabledByDefault.Value -ne 0) {
            return 'Enabled; off by default'
        }

        return 'Explicitly enabled'
    }

    if ($disabledByDefault.Exists -and [int64]$disabledByDefault.Value -ne 0) {
        return 'Disabled by default'
    }

    return 'Available by default'
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Read-YesNo {
    param([Parameter(Mandatory = $true)][string]$Question)

    while ($true) {
        $answer = (Read-Host "$Question [Y/N]").Trim().ToUpperInvariant()
        if ($answer -eq 'Y' -or $answer -eq 'YES') { return $true }
        if ($answer -eq 'N' -or $answer -eq 'NO') { return $false }
        Write-Host 'Please enter Y or N.' -ForegroundColor Yellow
    }
}

function Get-LegacyCipherReason {
    param([Parameter(Mandatory = $true)][string]$CipherName)

    $reasons = New-Object System.Collections.Generic.List[string]

    if ($CipherName -match '(^|_)NULL(_|$)') { $reasons.Add('NULL encryption') }
    if ($CipherName -match 'RC2') { $reasons.Add('RC2') }
    if ($CipherName -match 'RC4') { $reasons.Add('RC4') }
    if ($CipherName -match '3DES|(^|_)DES(_|$)') { $reasons.Add('DES/3DES') }
    if ($CipherName -match 'EXPORT') { $reasons.Add('EXPORT grade') }
    if ($CipherName -match 'MD5') { $reasons.Add('MD5') }
    if ($CipherName -match 'CBC') { $reasons.Add('CBC mode (legacy)') }

    return ($reasons -join ', ')
}

function Set-ProtocolState {
    param(
        [Parameter(Mandatory = $true)][string]$Protocol,
        [Parameter(Mandatory = $true)][bool]$Enable
    )

    foreach ($role in @('Client', 'Server')) {
        $path = Join-Path (Join-Path $SchannelProtocolsPath $Protocol) $role
        New-Item -Path $path -Force | Out-Null

        if ($Enable) {
            New-ItemProperty -Path $path -Name 'Enabled' -PropertyType DWord -Value 1 -Force | Out-Null
            New-ItemProperty -Path $path -Name 'DisabledByDefault' -PropertyType DWord -Value 0 -Force | Out-Null
        }
        else {
            New-ItemProperty -Path $path -Name 'Enabled' -PropertyType DWord -Value 0 -Force | Out-Null
            New-ItemProperty -Path $path -Name 'DisabledByDefault' -PropertyType DWord -Value 1 -Force | Out-Null
        }
    }
}

function Export-RegistryBackup {
    param(
        [Parameter(Mandatory = $true)][string]$RegistryPath,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    & "$env:SystemRoot\System32\reg.exe" export $RegistryPath $Destination /y | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Registry backup failed for $RegistryPath. No hardening changes were attempted."
    }
}

if ($env:OS -ne 'Windows_NT') {
    Write-Error 'This script supports Windows only.'
    exit 1
}

Clear-Host
Write-Host 'Windows Schannel TLS Audit & Hardening' -ForegroundColor Cyan
Write-Host 'Version 1.0.1' -ForegroundColor DarkGray
Write-Host 'No changes have been made.' -ForegroundColor Green

try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $osName = $os.Caption
    $osBuild = [int]$os.BuildNumber
    $isServer = [int]$os.ProductType -ne 1
}
catch {
    $osName = [Environment]::OSVersion.VersionString
    $osBuild = [Environment]::OSVersion.Version.Build
    $isServer = $false
}

$tls12Supported = ($osBuild -ge 7600)
if ($isServer -and $osBuild -eq 6002) {
    $tls12Supported = $true
}

if ($isServer) {
    $tls13Supported = ($osBuild -ge 20348)
}
else {
    $tls13Supported = ($osBuild -ge 22000)
}

$ssl20Support = 'Legacy / OS-dependent'
if ($osBuild -ge 14393) {
    $ssl20Support = 'Removed by OS'
}

$tls12SupportText = 'Not detected'
if ($tls12Supported) {
    $tls12SupportText = 'Supported'
}

$tls13SupportText = 'Not supported by this OS'
if ($tls13Supported) {
    $tls13SupportText = 'Supported'
}

$protocolSupport = @{
    'SSL 2.0' = $ssl20Support
    'SSL 3.0' = 'Legacy / OS-dependent'
    'TLS 1.0' = 'Legacy / OS-dependent'
    'TLS 1.1' = 'Legacy / OS-dependent'
    'TLS 1.2' = $tls12SupportText
    'TLS 1.3' = $tls13SupportText
}

Write-Section 'System'
Write-Host "Computer : $env:COMPUTERNAME"
Write-Host "OS       : $osName"
Write-Host "Build    : $osBuild"
Write-Host "Admin    : $(Test-IsAdministrator)"

Write-Section 'Schannel protocol configuration'
$protocolRows = foreach ($protocol in @('SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1', 'TLS 1.2', 'TLS 1.3')) {
    [pscustomobject]@{
        Protocol  = $protocol
        Client    = Get-ProtocolSetting -Path (Join-Path (Join-Path $SchannelProtocolsPath $protocol) 'Client')
        Server    = Get-ProtocolSetting -Path (Join-Path (Join-Path $SchannelProtocolsPath $protocol) 'Server')
        OS_Support = $protocolSupport[$protocol]
    }
}
$protocolRows | Format-Table -AutoSize | Out-Host

Write-Host 'OS default means no explicit local Schannel setting was found.' -ForegroundColor DarkGray
Write-Host 'This does not prove that a network service is offering the protocol.' -ForegroundColor DarkGray

$cipherPolicy = Get-RegistryValue -Path $CipherPolicyPath -Name 'Functions'
$cipherPolicyConfigured = $cipherPolicy.Exists -and -not [string]::IsNullOrWhiteSpace([string]$cipherPolicy.Value)

$getCipherCommand = Get-Command -Name 'Get-TlsCipherSuite' -ErrorAction SilentlyContinue
$disableCipherCommand = Get-Command -Name 'Disable-TlsCipherSuite' -ErrorAction SilentlyContinue
$legacyCipherSuites = @()
$cipherAuditSucceeded = $false

Write-Section 'Enabled legacy or weak cipher suites'
if ($null -eq $getCipherCommand) {
    Write-Host 'The Windows TLS PowerShell cmdlets are not available on this system.' -ForegroundColor Yellow
}
else {
    try {
        $enabledCipherSuites = @(Get-TlsCipherSuite)
        $legacyCipherSuites = @(
            foreach ($suite in $enabledCipherSuites) {
                if ($null -eq $suite) {
                    continue
                }

                $nameProperty = $suite.PSObject.Properties['Name']
                if ($null -eq $nameProperty) {
                    continue
                }

                # Some Windows builds expose Name as a collection. Normalise
                # each value before passing it to a scalar string parameter.
                foreach ($nameValue in @($nameProperty.Value)) {
                    $cipherName = [Convert]::ToString($nameValue)
                    if ([string]::IsNullOrWhiteSpace($cipherName)) {
                        continue
                    }

                    $reason = Get-LegacyCipherReason -CipherName $cipherName
                    if (-not [string]::IsNullOrWhiteSpace($reason)) {
                        [pscustomobject]@{
                            Name    = $cipherName
                            Finding = $reason
                        }
                    }
                }
            }
        )
        $cipherAuditSucceeded = $true

        if ($legacyCipherSuites.Count -eq 0) {
            Write-Host 'No enabled cipher suites matched the legacy/weak rules.' -ForegroundColor Green
        }
        else {
            $legacyCipherSuites | Format-Table -AutoSize -Wrap | Out-Host
        }
    }
    catch {
        Write-Host "Cipher-suite audit failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

if ($cipherPolicyConfigured) {
    Write-Host ''
    Write-Host 'NOTICE: A Group Policy cipher suite order is configured.' -ForegroundColor Yellow
    Write-Host 'Local cipher changes may be overridden and hardening mode will be blocked.' -ForegroundColor Yellow
}

Write-Section 'Choose mode'
Write-Host '[R] Report only (default) - make no changes'
Write-Host '[H] Harden - review and confirm proposed changes'
$mode = (Read-Host 'Enter R or H').Trim().ToUpperInvariant()

if ($mode -ne 'H') {
    Write-Host ''
    Write-Host 'Report-only complete. No changes were made.' -ForegroundColor Green
    exit 0
}

if (-not (Test-IsAdministrator)) {
    Write-Host ''
    Write-Host 'Hardening cancelled: reopen Windows PowerShell as Administrator.' -ForegroundColor Red
    Write-Host 'No changes were made.' -ForegroundColor Green
    exit 1
}

if ($null -eq $getCipherCommand -or $null -eq $disableCipherCommand -or -not $cipherAuditSucceeded) {
    Write-Host ''
    Write-Host 'Hardening cancelled: TLS cipher cmdlets are unavailable or the cipher audit failed.' -ForegroundColor Red
    Write-Host 'No changes were made.' -ForegroundColor Green
    exit 1
}

if ($cipherPolicyConfigured) {
    Write-Host ''
    Write-Host 'Hardening cancelled: manage cipher suites in the detected Group Policy.' -ForegroundColor Red
    Write-Host 'No changes were made.' -ForegroundColor Green
    exit 1
}

Write-Section 'Modern TLS choices'
Write-Host 'WARNING' -ForegroundColor Red
Write-Host 'Disabling old protocols without an available modern protocol can break' -ForegroundColor Yellow
Write-Host 'web, mail, RDP, database, monitoring and application connectivity.' -ForegroundColor Yellow
Write-Host 'Test compatibility and have a maintenance/rollback plan before continuing.' -ForegroundColor Yellow
Write-Host ''

$enableTls12 = Read-YesNo -Question 'Explicitly enable TLS 1.2 for Schannel client and server roles?'
$enableTls13 = $false

if ($tls13Supported) {
    $enableTls13 = Read-YesNo -Question 'Explicitly enable TLS 1.3 for Schannel client and server roles?'
}
else {
    Write-Host 'TLS 1.3 is not offered because this Windows version does not support it in Schannel.' -ForegroundColor Yellow
}

if (-not $enableTls12 -and -not $enableTls13) {
    Write-Host ''
    Write-Host 'HIGH RISK: You chose not to explicitly enable TLS 1.2 or TLS 1.3.' -ForegroundColor Red
    Write-Host 'The script will leave their existing settings unchanged, but disabling all' -ForegroundColor Red
    Write-Host 'older protocols may leave applications without a usable protocol.' -ForegroundColor Red
}

Write-Section 'Proposed changes'
Write-Host 'Disable for Client and Server: SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1'
Write-Host "Disable enabled legacy/weak cipher suites found: $($legacyCipherSuites.Count)"

if ($enableTls12) {
    Write-Host 'TLS 1.2: explicitly enable for Client and Server' -ForegroundColor Green
}
else {
    Write-Host 'TLS 1.2: leave current setting unchanged' -ForegroundColor Yellow
}

if ($tls13Supported) {
    if ($enableTls13) {
        Write-Host 'TLS 1.3: explicitly enable for Client and Server' -ForegroundColor Green
    }
    else {
        Write-Host 'TLS 1.3: leave current setting unchanged' -ForegroundColor Yellow
    }
}
else {
    Write-Host 'TLS 1.3: unsupported; no change'
}

Write-Host ''
Write-Host 'A registry backup will be created before any hardening change.' -ForegroundColor Cyan
$confirmation = Read-Host 'Type HARDEN exactly to apply these changes; anything else cancels'

if ($confirmation -cne 'HARDEN') {
    Write-Host ''
    Write-Host 'Hardening cancelled. No changes were made.' -ForegroundColor Green
    exit 0
}

Write-Section 'Applying hardening'
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$backupDirectory = Join-Path $env:ProgramData "TLS-Hardening-Backups\$timestamp"
New-Item -Path $backupDirectory -ItemType Directory -Force | Out-Null

try {
    Export-RegistryBackup -RegistryPath $SchannelRegPath -Destination (Join-Path $backupDirectory 'SCHANNEL.reg')
    Export-RegistryBackup -RegistryPath $CipherLocalRegPath -Destination (Join-Path $backupDirectory 'CipherSuites.reg')
    Write-Host "Backup created: $backupDirectory" -ForegroundColor Green
}
catch {
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host 'Hardening stopped before registry settings were changed.' -ForegroundColor Red
    exit 1
}

$failures = New-Object System.Collections.Generic.List[string]

try {
    foreach ($legacyProtocol in @('SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1')) {
        Set-ProtocolState -Protocol $legacyProtocol -Enable $false
        Write-Host "Disabled $legacyProtocol for Client and Server."
    }

    if ($enableTls12) {
        Set-ProtocolState -Protocol 'TLS 1.2' -Enable $true
        Write-Host 'Enabled TLS 1.2 for Client and Server.'
    }

    if ($enableTls13) {
        Set-ProtocolState -Protocol 'TLS 1.3' -Enable $true
        Write-Host 'Enabled TLS 1.3 for Client and Server.'
    }
}
catch {
    $failures.Add("Protocol configuration: $($_.Exception.Message)")
}

foreach ($suite in $legacyCipherSuites) {
    try {
        Disable-TlsCipherSuite -Name $suite.Name -Confirm:$false -ErrorAction Stop
        Write-Host "Disabled cipher suite: $($suite.Name)"
    }
    catch {
        $failures.Add("Cipher suite $($suite.Name): $($_.Exception.Message)")
    }
}

Write-Section 'Result'
if ($failures.Count -eq 0) {
    Write-Host 'Hardening settings were applied successfully.' -ForegroundColor Green
}
else {
    Write-Host 'Hardening completed with one or more errors:' -ForegroundColor Yellow
    foreach ($failure in $failures) {
        Write-Host " - $failure" -ForegroundColor Yellow
    }
    Write-Host "Use the backup in $backupDirectory if rollback is required." -ForegroundColor Yellow
}

Write-Host ''
Write-Host 'Restart Windows during an approved maintenance window before validation.' -ForegroundColor Cyan
Write-Host 'Then rerun this script in Report-only mode and test every dependent service.' -ForegroundColor Cyan

if ($failures.Count -gt 0) { exit 1 }
exit 0
