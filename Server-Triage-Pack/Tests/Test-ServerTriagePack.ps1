#requires -Version 5.1
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$failures = New-Object System.Collections.Generic.List[string]

function Add-TestResult {
    param(
        [string]$Name,
        [bool]$Passed,
        [string]$Detail
    )

    if ($Passed) {
        Write-Host "[PASS] $Name" -ForegroundColor Green
    }
    else {
        Write-Host "[FAIL] $Name - $Detail" -ForegroundColor Red
        [void]$failures.Add("$Name - $Detail")
    }
}

$requiredFiles = @(
    'Invoke-ServerTriage.ps1',
    'Config\triage.config.json',
    'Config\servers.example.csv',
    'README.md',
    'LICENSE.txt'
)

foreach ($relativePath in $requiredFiles) {
    $path = Join-Path $projectRoot $relativePath
    Add-TestResult -Name "File exists: $relativePath" -Passed (Test-Path -LiteralPath $path -PathType Leaf) -Detail 'File not found'
}

$scriptPath = Join-Path $projectRoot 'Invoke-ServerTriage.ps1'
$tokens = $null
$parseErrors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)
Add-TestResult -Name 'PowerShell syntax' -Passed (@($parseErrors).Count -eq 0) -Detail ((@($parseErrors) | ForEach-Object Message) -join '; ')

$configPath = Join-Path $projectRoot 'Config\triage.config.json'
try {
    $config = Get-Content -LiteralPath $configPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $configPassed = (
        [int]$config.DiskCriticalPercentFree -lt [int]$config.DiskWarningPercentFree -and
        [int]$config.PatchCriticalAgeDays -gt [int]$config.PatchWarningAgeDays -and
        @($config.EventLogs).Count -gt 0
    )
    Add-TestResult -Name 'Configuration validity' -Passed $configPassed -Detail 'Threshold relationship or required collection list is invalid'
}
catch {
    Add-TestResult -Name 'Configuration validity' -Passed $false -Detail $_.Exception.Message
}

$csvPath = Join-Path $projectRoot 'Config\servers.example.csv'
try {
    $rows = @(Import-Csv -LiteralPath $csvPath)
    $csvPassed = $rows.Count -gt 0 -and $null -ne $rows[0].PSObject.Properties['ComputerName']
    Add-TestResult -Name 'Server-list schema' -Passed $csvPassed -Detail 'ComputerName column or sample rows are missing'
}
catch {
    Add-TestResult -Name 'Server-list schema' -Passed $false -Detail $_.Exception.Message
}

$scriptText = Get-Content -LiteralPath $scriptPath -Raw -Encoding UTF8
$prohibitedCommands = @('Restart-Service', 'Stop-Service', 'Remove-Item', 'Set-ItemProperty', 'New-ItemProperty', 'Install-Module')
foreach ($command in $prohibitedCommands) {
    $present = $scriptText -match ('(?im)^\s*' + [regex]::Escape($command) + '\b')
    Add-TestResult -Name "Read-only check: $command" -Passed (-not $present) -Detail 'A prohibited mutating command was found at the start of a code line'
}

if ($failures.Count -gt 0) {
    Write-Host ''
    Write-Host "$($failures.Count) validation check(s) failed." -ForegroundColor Red
    exit 1
}

Write-Host ''
Write-Host 'All Server Triage Pack validation checks passed.' -ForegroundColor Green
exit 0
