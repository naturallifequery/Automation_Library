# Hyper-V Interactive Health Check

A simple, read-only PowerShell diagnostic tool for troubleshooting local Hyper-V hosts and virtual machines.

The script prompts for the VM and environment details, checks the most common causes of a missing or unavailable VM, and produces a clean HTML report for review or escalation.

## When to use it

Use this tool when:

- A VM disappears from Hyper-V Manager after startup.
- A VM is visible only to an elevated or different administrator account.
- The Hyper-V Virtual Machine Management service may not be starting correctly.
- VM configuration or virtual disk files may have moved or become unavailable.
- A VM is present but cannot start, has storage issues, or has lost its virtual switch.
- You need a consistent Hyper-V health report before deciding whether to repair or rebuild the setup.

## What it checks

The script collects and reports:

- Hyper-V feature and PowerShell module availability.
- Hypervisor startup configuration.
- Pending Windows reboot indicators.
- Hyper-V Virtual Machine Management (`VMMS`) service state.
- Hyper-V Host Compute (`vmcompute`) service state.
- Current administrator and Hyper-V Administrators group membership.
- VM visibility and registration on the local host.
- VM state, automatic start action and checkpoint information.
- Attached VHD/VHDX/AVHDX paths, file existence, disk type and parent disk details.
- Free space and storage information for relevant volumes.
- Virtual switch and VM network-adapter configuration.
- VM configuration and disk files under the folder supplied by the operator.
- Recent Hyper-V VMMS and worker event-log errors.
- Likely causes and practical troubleshooting recommendations.

## Safety and scope

This is a diagnostic script. It does not remediate the host or VM.

It does **not**:

- Start, stop, restart or modify a VM.
- Restart or reconfigure Hyper-V services.
- Import, export, register, mount or remove a VM.
- Change file or folder permissions.
- Enable or disable Windows features.
- Change boot, networking or execution-policy settings.

The only persistent output is the generated HTML report. The script also opens that report when collection is complete.

The expected VM folder is searched recursively. Choose the narrowest useful Hyper-V folder rather than an entire drive to limit disk activity and report noise.

## Requirements

- Windows 10/11 Pro, Enterprise or Education, or Windows Server with Hyper-V.
- Windows PowerShell 5.1.
- Hyper-V PowerShell management tools.
- An account authorised to inspect the local Hyper-V configuration.
- Windows PowerShell ISE launched with **Run as administrator**.

## Files

| File | Purpose |
| --- | --- |
| `Get-HyperVDiagnosticReport.ps1` | Interactive diagnostic and HTML report generator. |
| `README.md` | Usage, safety and interpretation guidance. |

## Running the tool

1. Download or clone the repository.
2. Right-click **Windows PowerShell ISE** and select **Run as administrator**.
3. Open `Get-HyperVDiagnosticReport.ps1`.
4. Press **F5** or select **Run Script**.
5. Enter the requested values.
6. Review the HTML report that opens when the checks finish.

If your organisation permits a temporary execution-policy override, it can be applied only to the current PowerShell process before running the script:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Do not make a permanent execution-policy change unless it is approved by your organisation.

## Interactive prompts

| Prompt | What to enter |
| --- | --- |
| VM name | The VM name expected in Hyper-V Manager, for example `Dev-VM`. |
| Expected managing user | The user or admin account expected to manage the VM, for example `DOMAIN\UserName`. |
| Expected VM folder | The folder that should contain the VM configuration or disks, for example `D:\Hyper-V`. |
| Event lookback | The number of days of recent Hyper-V events to review. |
| Report folder | The folder in which the HTML report should be saved. |

## Report output

The report is saved with a name similar to:

```text
Hyper-V-Health-COMPUTERNAME-20260905-143000.html
```

It summarises the checks, highlights warnings and failures, and includes troubleshooting advice based on the findings.

## Quick interpretation guide

| Finding | Likely direction |
| --- | --- |
| VMMS is running, the VM is registered, but the user cannot see or manage it | Check elevation, logon token and Hyper-V Administrators membership. Sign out and back in after group changes. |
| VMMS is running, configuration files exist, but the VM is not registered | Investigate storage availability, startup timing and whether the VM registration was removed. Review the event logs before importing anything. |
| The VM is visible but an attached virtual disk is missing | Confirm the storage path, drive availability and any moved or renamed VHDX files. |
| VMMS is stopped or repeatedly failing | Review service dependencies, Windows events, pending updates and the Hyper-V feature state. |
| Automatic start action is `Nothing` | The VM is not configured to start automatically with the host. This does not explain a missing registration. |
| AVHDX files or checkpoints are present | Review checkpoint health before moving, merging or attaching disks. Do not manipulate the chain without a verified backup. |
| A configured virtual switch is missing | Recreate or reassign networking only after confirming the intended host adapter and switch design. |

## Common problems

### Access is denied

Close the current session and reopen **Windows PowerShell ISE as administrator** using an approved local or domain administrator account. Confirm that the account has permission to query Hyper-V and the supplied VM folder.

### The script is blocked

Follow your organisation's PowerShell policy. If permitted, use the process-only execution-policy command shown above. This setting ends when that PowerShell process closes.

### The report is not on the Desktop

If the requested report folder is unavailable, check the path shown in the ISE output. A temporary folder may be used as a fallback.

### The expected VM folder takes a long time to scan

Cancel the run if necessary and supply a more specific folder. Avoid using a drive root such as `C:\` or `D:\` unless a broad search is genuinely required.

## Known limitations

- The script diagnoses the local Hyper-V host only.
- It reports direct local group membership; nested domain-group membership may require separate verification.
- It does not repair, import or re-register a VM.
- File discovery is limited to the folder supplied by the operator.
- Event-log availability and retention depend on the endpoint configuration.
- A clean report does not replace a verified backup or change-control process.

## Handling the report

The HTML report may contain computer names, usernames, local paths, VM names, IP or MAC information and Windows event messages. Treat it as internal administrative data and review it before sharing outside your organisation.

## Licence and support

Use the licence and support terms applied to the parent automation-library repository. Test the script in accordance with your organisation's operational and change-control requirements.
