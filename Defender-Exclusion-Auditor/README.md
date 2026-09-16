# Defender Exclusion Risk Auditor and Hardener

> Is your antivirus exclusion list creating an attacker safe zone?

The **Defender Exclusion Risk Auditor and Hardener** is a single-file PowerShell tool from RuleRivet. It audits custom Microsoft Defender Antivirus exclusions, assigns transparent risk scores, produces evidence, and supports controlled remediation and rollback.

The default `Audit` mode is read-only. A risk score is a prompt for review, not proof of malicious activity or an instruction to remove an exclusion.

## What the tool does

- Audits path, process, extension, and IP address exclusions.
- Detects drive roots, user-writable folders, temporary paths, wildcards, broad ranges, and global file-type exclusions.
- Checks resolvable paths for low-privilege write access.
- Checks existing executable files for Authenticode signature state.
- Identifies process exclusions that use only an image name instead of a full path.
- Expands environment variables as the LocalSystem account would resolve them.
- Separates local findings from exclusions that appear to come from managed policy.
- Produces HTML, JSON, and CSV evidence.
- Creates a controlled remediation plan without changing Defender.
- Supports `-WhatIf`, `-Confirm`, stable finding IDs, snapshots, change logs, and differential rollback.

## Safety model

| Mode | Changes Defender | Purpose |
| --- | :---: | --- |
| `Audit` | No | Inventory, score, and report all visible custom exclusions. |
| `Plan` | No | Create a remediation candidate list at or above a selected risk level. |
| `Harden` | Yes | Remove only operator-selected exclusions after safety checks and confirmation. |
| `Rollback` | Yes | Compare the current state with a saved snapshot and restore the differences. |

The script does not disable tamper protection, real-time protection, automatic server exclusions, or Defender services. Managed policy findings remain visible but are not eligible for local removal.

## Requirements

- A supported Windows client or Windows Server device.
- Microsoft Defender Antivirus and the Defender PowerShell module.
- Windows PowerShell 5.1 or later.
- Read access to Defender preferences for `Audit` and `Plan`.
- An elevated PowerShell session for `Harden` and `Rollback`.
- A writable report directory.

The script has no external PowerShell module dependency.

## Quick start

1. Download `Invoke-DefenderExclusionRiskAudit.ps1`.
2. Open Windows PowerShell.
3. Change to the script directory.
4. Run the synthetic self-test:

```powershell
.\Invoke-DefenderExclusionRiskAudit.ps1 -SelfTest
```

5. Run a read-only audit:

```powershell
.\Invoke-DefenderExclusionRiskAudit.ps1 -Mode Audit -OpenReport
```

The script creates a timestamped output directory when you do not specify `-OutputDirectory`.

Do not weaken the PowerShell execution policy to run the tool. Use your organisation's approved signing and execution process.

## Common commands

### Audit only

```powershell
.\Invoke-DefenderExclusionRiskAudit.ps1 -Mode Audit
```

### Create a remediation plan

```powershell
.\Invoke-DefenderExclusionRiskAudit.ps1 -Mode Plan -MinimumRisk Medium
```

### Simulate hardening

```powershell
.\Invoke-DefenderExclusionRiskAudit.ps1 -Mode Harden -MinimumRisk High -WhatIf
```

### Harden selected findings

Run this command in an elevated PowerShell session:

```powershell
.\Invoke-DefenderExclusionRiskAudit.ps1 -Mode Harden `
    -FindingId DX-4D81A90A8F12,DX-AB883FE1427C
```

The script shows the selected entries, saves a pre-change snapshot, requests the typed word `HARDEN`, and uses PowerShell `ShouldProcess` confirmation for each removal.

### Roll back to a saved snapshot

Run this command in an elevated PowerShell session:

```powershell
.\Invoke-DefenderExclusionRiskAudit.ps1 -Mode Rollback `
    -SnapshotPath .\Snapshot-Before-Hardening.json
```

Rollback can re-add exclusions and reduce protection. Use it only when validation shows an unacceptable operational effect.

## Risk model

The risk engine uses deterministic additive rules. Each finding shows the matched rule IDs, points, explanation, and confidence. Scores are capped at 100.

| Score | Level | Review meaning |
| ---: | --- | --- |
| 80-100 | Critical | Very broad or directly dangerous protection gap. Review urgently. |
| 60-79 | High | Strong risk signals. Validate, remove, or narrow through change control. |
| 35-59 | Medium | Meaningful exposure or uncertainty. Review scope, ownership, and alternatives. |
| 0-34 | Low | Lower exposure or lower confidence. Document the requirement and review date. |

Examples of scored conditions include:

- Whole-drive and all-user-profile exclusions.
- Temporary or broadly writable folders.
- Wildcards and unresolved environment variables.
- Process image names without a full path.
- Microsoft-listed processes and file types that should not normally be excluded.
- Unsigned or invalidly signed executable files.
- Globally excluded executable, script, archive, document, or image extensions.
- Broad, any-address, or invalid IP exclusions.
- Missing files and folders that can indicate stale entries.

The score measures technical exposure. It does not measure business need, vendor support, application performance, or evidence of compromise.

## Evidence files

| File | Mode | Use |
| --- | --- | --- |
| `Defender-Exclusion-Risk-Report.html` | All | Self-contained report for human review. |
| `Defender-Exclusion-Risk-Report.json` | All | Complete structured evidence and nested risk signals. |
| `Defender-Exclusion-Risk-Findings.csv` | All | Flat finding list for Excel, tickets, and comparison. |
| `Defender-Exclusion-Remediation-Plan.json` | Plan, Harden | Eligible candidates and managed-policy findings. |
| `Defender-Exclusion-Remediation-Plan.csv` | Plan, Harden | Flat candidate list. |
| `Snapshot-Before-Hardening.json` | Harden | Exact pre-change custom exclusion state. |
| `Snapshot-Before-Hardening.json.sha256` | Harden | SHA-256 digest used for snapshot integrity checking. |
| `Defender-Exclusion-Change-Log.json` | Harden, Rollback | Detailed operation and verification record. |
| `Defender-Exclusion-Change-Log.csv` | Harden, Rollback | Flat change log for tickets and review. |

JSON is the authoritative machine-readable record. HTML is the presentation layer. CSV supports filtering and external workflow tools.

## Parameters

| Parameter | Purpose |
| --- | --- |
| `-Mode` | Selects `Audit`, `Plan`, `Harden`, or `Rollback`. Default: `Audit`. |
| `-OutputDirectory` | Sets the directory for reports, plans, snapshots, and logs. |
| `-MinimumRisk` | Sets the minimum candidate level: `Low`, `Medium`, `High`, or `Critical`. Default: `High`. |
| `-FindingId` | Selects one or more stable finding IDs for hardening. |
| `-SnapshotPath` | Selects the snapshot file for rollback. |
| `-SkipAclAnalysis` | Skips the low-privilege write-access heuristic. |
| `-OpenReport` | Opens the HTML report after the run. |
| `-Force` | Skips the typed `HARDEN` or `ROLLBACK` safety word. It does not disable `-Confirm`. |
| `-AllowDifferentComputer` | Permits rollback from a snapshot made on another computer. Use with care. |
| `-SelfTest` | Runs synthetic risk-engine checks without querying or changing Defender. |

The script also supports the common parameters `-WhatIf`, `-Confirm`, and `-Verbose`.

## Recommended hardening workflow

1. Run `Audit` and retain the JSON report.
2. Identify the application or service that requires each exclusion.
3. Confirm the current vendor guidance and system owner.
4. Consider a narrower path or a contextual exclusion.
5. Run `Plan` with the correct minimum risk.
6. Run `Harden -WhatIf`.
7. Review the proposed actions and change approval.
8. Harden only the approved finding IDs.
9. Retain the snapshot and SHA-256 file.
10. Test the workload and review Defender events.
11. Run a new audit and document the result.

## Troubleshooting

| Symptom | Likely cause | Action |
| --- | --- | --- |
| `Get-MpPreference` is unavailable | Defender is absent, disabled, unsupported, or not registered as expected. | Confirm the Windows version, Defender feature state, and module availability. |
| Access is denied in `Harden` | The session is not elevated, or a security control blocks local changes. | Run as administrator. Check tamper protection and management ownership. |
| An entry returns after removal | Group Policy, Intune, Configuration Manager, or another service reapplied it. | Change the authoritative policy. Do not loop local removal. |
| `VerificationFailed` | The effective entry remained after `Remove-MpPreference`. | Review policy source, tamper state, Defender logs, and the exact value. |
| ACL analysis fails | The path is absent, inaccessible, wildcard-only, or on unavailable storage. | Read the coverage notes and verify the location manually. |
| No exclusions are reported | The device has no custom exclusions, or management settings restrict visibility. | Confirm the expected policy and exclusion visibility configuration. |
| Rollback has remaining differences | Policy blocked or reapplied a value, or a change failed. | Review the change log. Do not assume that rollback completed. |

For additional self-test diagnostics, use:

```powershell
.\Invoke-DefenderExclusionRiskAudit.ps1 -SelfTest -Verbose
```

## Design notes

The script demonstrates several reusable PowerShell engineering patterns:

- Advanced script parameters with validation.
- Native `ShouldProcess` support.
- Structured `PSCustomObject` output.
- Stable IDs derived from SHA-256.
- Case-insensitive `HashSet` comparisons.
- Dynamic splatting for Defender parameters.
- Idempotent changes and post-change verification.
- Differential rollback instead of blind preference replacement.
- HTML encoding before report rendering.
- Windows PowerShell 5.1-compatible collection handling.

## Important limitations

- ACL analysis is a heuristic. It is not a complete Windows effective-access calculation.
- A valid Authenticode signature does not prove that software is safe.
- An unsigned internal application is not automatically malicious.
- Management-source detection cannot identify every possible management platform.
- Defender can hide or restrict local exclusion visibility.
- Harden removes exclusions. It does not automatically create a narrower replacement.
- Rollback can reduce protection by restoring an earlier exclusion.

Use the report as evidence for a technical and business review. Do not treat the score as an automatic change decision.

## References

- [Microsoft Defender Antivirus exclusions overview](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-exclusions-overview)
- [Exclusions to avoid in Microsoft Defender Antivirus and Defender for Endpoint](https://learn.microsoft.com/en-us/defender-endpoint/defender-endpoint-exclusions-common-mistakes)
- [Configure custom exclusions for Microsoft Defender Antivirus](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-exclusions-configure)
- [Microsoft Defender Antivirus exclusions on Windows Server](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-exclusions-windows-server)
- [Add-MpPreference](https://learn.microsoft.com/en-us/powershell/module/defender/add-mppreference)
- [Remove-MpPreference](https://learn.microsoft.com/en-us/powershell/module/defender/remove-mppreference)

## Release

Current release: **1.0.1**

Publisher: **RuleRivet**

The v1.0.1 release includes Windows PowerShell 5.1 collection compatibility fixes and clean-device handling for systems with no custom exclusions.
