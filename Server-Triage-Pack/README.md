# Server Triage Pack

A read-only PowerShell project that gathers a consistent Windows Server health
snapshot and turns it into a portable HTML dashboard, CSV summary, JSON evidence,
and an execution log.

The pack is designed for 2nd-line support, 3rd-line support, infrastructure
engineers, and automation specialists who want repeatable first-pass diagnostics
without opening several consoles or making changes during evidence collection.

## What it collects

- Operating system, build, domain, hardware model, PowerShell version, and time zone
- Last boot time and uptime
- Point-in-time CPU load and memory use
- Fixed-disk capacity and free-space status
- Configured critical service status
- Automatic services that are not running
- Critical and error events from selected Windows event logs
- Ten most recent dated hotfix records
- Common pending-reboot indicators
- Enabled network adapter addressing, gateway, DNS, DHCP, and MAC details
- Windows Firewall profile state
- A limited list of listening TCP ports and owning processes
- Section-level collection errors

## What it deliberately does not do

The project does not:

- Restart, stop, or reconfigure services
- Delete logs, temporary files, or other data
- Install modules or software
- Modify the registry, firewall, or remoting configuration
- Store supplied credentials
- Decide that an alert is the root cause of an incident

Thresholds highlight items for review. They are not a replacement for change
control, monitoring history, application knowledge, or engineer judgement.

## Project structure

~~~text
Server-Triage-Pack
|-- Invoke-ServerTriage.ps1
|-- Start-Local-Triage.cmd
|-- Config
|   |-- triage.config.json
|   '-- servers.example.csv
|-- Documentation
|   '-- Server_Triage_Pack_Build_and_Usage_Guide.pdf
|-- Examples
|   |-- Sample-Server-Triage-Report.html
|   |-- Sample-Server-Triage-Summary.csv
|   '-- Sample-APP-SRV-01.json
|-- Tests
|   '-- Test-ServerTriagePack.ps1
|-- Output
|-- CHANGELOG.md
|-- LICENSE.txt
'-- README.md
~~~

## Requirements

### Collection computer

- Windows 10, Windows 11, or Windows Server
- Windows PowerShell 5.1 or PowerShell 7 on Windows
- Network access to the target servers
- Permission to read the requested Windows management information
- PowerShell remoting for remote collection

No external PowerShell modules are required.

### Target servers

- Supported Windows Server version with Windows Management Instrumentation
- PowerShell remoting enabled for remote collection
- WinRM allowed through the appropriate firewall profile
- An account permitted to use the selected PowerShell session configuration

The default remoting endpoint normally permits administrators. An organisation
can instead provide a constrained endpoint or delegated read permissions.

## Five-minute local test

1. Extract the project to a controlled folder.
2. Read **Invoke-ServerTriage.ps1** before running it.
3. Open Windows PowerShell as an account allowed to read local system data.
4. Move into the project directory:

~~~powershell
Set-Location C:\Tools\Server-Triage-Pack
~~~

5. If Windows marked the downloaded files as coming from the internet, inspect
   them and then remove that mark from the scripts:

~~~powershell
Get-ChildItem -Path . -Filter *.ps1 -Recurse | Unblock-File
~~~

6. Run the validation checks:

~~~powershell
.\Tests\Test-ServerTriagePack.ps1
~~~

7. Collect from the local computer:

~~~powershell
.\Invoke-ServerTriage.ps1 -ComputerName localhost -OpenReport
~~~

You can also double-click **Start-Local-Triage.cmd**. The command file does not
bypass the effective execution policy.

## Where the results go

Each execution creates a timestamped folder:

~~~text
Output\Run_20260822-143015
|-- Server-Triage-Report.html
|-- Server-Triage-Summary.csv
|-- run-manifest.json
|-- triage-run.log
'-- json
    |-- APP-SRV-01.json
    '-- SQL-SRV-01.json
~~~

- **HTML report** - Human-readable dashboard for review or attachment to a ticket.
- **CSV summary** - One row per server for filtering, comparison, or import.
- **Host JSON** - Complete structured result for later automation.
- **Run manifest** - Run identity, targets, effective configuration, and output list.
- **Run log** - Collection sequence, warnings, and failures.

Treat the output as operational data. It can contain server names, IP addresses,
service accounts, listening ports, and event messages.

## Configure the pack

Edit **Config\triage.config.json** with a text editor. Keep a copy in source
control if the configuration is used operationally.

| Property | Default | Purpose |
| --- | ---: | --- |
| EventLookbackHours | 24 | How far back event collection looks |
| MaxEventsPerLog | 20 | Maximum returned events from each configured log |
| EventLogs | System, Application | Event logs queried |
| EventLevels | 1, 2 | Critical and Error event levels |
| DiskWarningPercentFree | 20 | Disk warning threshold |
| DiskCriticalPercentFree | 10 | Disk critical threshold |
| MemoryWarningPercentFree | 15 | Point-in-time free-memory warning |
| UptimeWarningDays | 45 | Prompts review of maintenance and reboot history |
| PatchWarningAgeDays | 35 | Warns on the latest detected dated update |
| PatchCriticalAgeDays | 60 | Critical patch-age threshold |
| RequiredServices | EventLog, WinRM, W32Time | Services treated as critical when missing or stopped |
| ExcludedAutomaticServices | See JSON | Suppresses known trigger-start or intentionally stopped services |
| CollectListeningPorts | true | Enables a bounded listener inventory |
| MaxListeningPorts | 40 | Limits listener rows per target |

### Choose required services carefully

The default list is a generic starting point. Add workload-specific services
only when they are expected on every target in that run.

~~~json
"RequiredServices": [
  "EventLog",
  "WinRM",
  "W32Time",
  "W3SVC"
]
~~~

For SQL Server or named instances, use the real Windows service name rather than
the display name. Keep separate configurations for materially different server
roles.

### Tune automatic-service exclusions

Some Windows services use trigger start. They can have an Automatic start mode
without running continuously. Review false positives and add only understood,
approved service names to **ExcludedAutomaticServices**.

Do not automatically assume that every stopped automatic service is faulty.

## Run against one remote server

First confirm the target is prepared for PowerShell remoting according to your
organisation's management standard.

~~~powershell
Test-WSMan -ComputerName APP-SRV-01
~~~

Then run:

~~~powershell
.\Invoke-ServerTriage.ps1 -ComputerName APP-SRV-01 -OpenReport
~~~

The current Windows identity is used by default.

## Use an alternate credential

Prompt securely and keep the credential only in the current process:

~~~powershell
$credential = Get-Credential
.\Invoke-ServerTriage.ps1 -ComputerName APP-SRV-01 -Credential $credential -OpenReport
~~~

Do not put passwords in the script, CSV, JSON configuration, command history, or
scheduled-task arguments.

## Run against several servers

Direct list:

~~~powershell
.\Invoke-ServerTriage.ps1 -ComputerName APP-SRV-01,SQL-SRV-01,FILE-SRV-01
~~~

CSV list:

~~~powershell
Copy-Item .\Config\servers.example.csv .\Config\servers.csv
notepad .\Config\servers.csv
.\Invoke-ServerTriage.ps1 -ComputerListPath .\Config\servers.csv -OpenReport
~~~

CSV schema:

~~~csv
ComputerName,Environment,Owner
APP-SRV-01,Production,Applications
SQL-SRV-01,Production,Database Team
FILE-SRV-01,Test,Infrastructure
~~~

Environment and Owner are optional report labels. ComputerName is required.
Duplicate computer names are removed.

## Use HTTPS remoting

When the target WinRM service has a correctly configured HTTPS listener:

~~~powershell
.\Invoke-ServerTriage.ps1 -ComputerName DMZ-SRV-01 -UseSSL -Credential (Get-Credential)
~~~

Do not weaken certificate validation to make an untrusted connection work.
Correct the certificate, name, listener, or trust configuration.

## ICMP is optional

Ping is used only as context. The script still attempts remoting when a target
does not answer ICMP.

~~~powershell
.\Invoke-ServerTriage.ps1 -ComputerListPath .\Config\servers.csv -SkipPing
~~~

## Use a different configuration

Create role-specific copies:

~~~powershell
.\Invoke-ServerTriage.ps1 -ComputerListPath .\Config\web-servers.csv -ConfigPath .\Config\web-server.config.json
~~~

Useful configuration sets include:

- Domain controllers
- IIS application servers
- SQL Server hosts
- File servers
- Management and monitoring servers
- Development or test workloads

## Use a different output location

~~~powershell
.\Invoke-ServerTriage.ps1 -ComputerName APP-SRV-01 -OutputPath C:\TriageEvidence
~~~

Use a controlled, access-restricted location. Avoid syncing operational evidence
to personal cloud storage.

## Read the health status

The overall status uses the highest applicable finding:

| Status | Meaning |
| --- | --- |
| Healthy | No configured threshold was crossed |
| Warning | Review is needed, but the result is not proof of an outage |
| Critical | A critical disk, patch-age, core collection, or required-service condition was found |
| Unreachable | The remote collection failed |

Examples of warning conditions:

- Pending reboot
- Old but not critical patch date
- Long uptime
- Low point-in-time free memory
- Returned critical or error events
- Automatic services that are not running

Examples of critical conditions:

- A required service is missing or not running
- A disk crosses the configured critical threshold
- The latest detected dated hotfix crosses the critical age
- Core system information cannot be collected

## Interpret results responsibly

The report is a triage aid, not a diagnosis.

- A CPU value is a point-in-time sample.
- Free memory is not the same as memory pressure.
- Event errors can be symptoms, expected noise, or unrelated history.
- Get-HotFix is not a universal replacement for Intune, Configuration Manager,
  WSUS, Azure Update Manager, or another patch-compliance platform.
- A stopped automatic service can be trigger-started or intentionally stopped.
- A listening port does not prove that an application is healthy.
- An unreachable result can be caused by DNS, WinRM, firewall, authentication,
  authorization, endpoint configuration, or the target being offline.

Correlate findings with monitoring, change records, application logs, and the
reported incident window.

## Common troubleshooting

### Script execution is blocked

~~~powershell
Get-ExecutionPolicy -List
Unblock-File .\Invoke-ServerTriage.ps1
Unblock-File .\Tests\Test-ServerTriagePack.ps1
~~~

Do not make a permanent organisation-wide execution-policy change just to run
this project. Follow the organisation's script signing and application-control
standards.

### WinRM cannot connect

~~~powershell
Test-WSMan -ComputerName APP-SRV-01
~~~

On a server approved to receive remote management, an administrator can run:

~~~powershell
Enable-PSRemoting -Force
~~~

This changes the target's remoting configuration and firewall rules. It is not
performed by Server Triage Pack and should follow change control.

### Access is denied

Confirm:

- The supplied account is correct
- The account is permitted to use the remote session endpoint
- UAC remote restrictions are understood
- The account can read CIM, services, event logs, registry indicators, and network data
- A constrained PowerShell endpoint is not blocking required commands

Prefer delegated read permissions or a constrained endpoint over routine use of
highly privileged accounts.

### The target does not answer ping

ICMP can be blocked while WinRM remains available. Let collection continue or
use **-SkipPing**.

### TrustedHosts prompts or workgroup targets

Kerberos normally handles authentication in a trusted Active Directory domain.
Workgroup, cross-forest, IP-address, and some DMZ scenarios require a deliberate
WinRM HTTPS or trust design.

Do not add wildcard TrustedHosts entries. Prefer a valid HTTPS listener and an
explicitly trusted certificate.

### Some report sections say unavailable

The HTML collection notes and **triage-run.log** contain the section-level error.
Common causes are missing permissions, unsupported cmdlets, disabled event logs,
or platform-specific server roles.

## Scheduled collection

Before scheduling:

1. Test interactively with the same identity.
2. Store the script and configuration in a controlled path.
3. Use a managed service account or approved automation identity.
4. Give the identity only the required remote and output permissions.
5. Protect and rotate output.
6. Monitor scheduled-task failure and report freshness.

Example action:

~~~text
Program:
powershell.exe

Arguments:
-NoLogo -NoProfile -File "C:\Tools\Server-Triage-Pack\Invoke-ServerTriage.ps1" -ComputerListPath "C:\Tools\Server-Triage-Pack\Config\servers.csv" -OutputPath "C:\TriageEvidence"
~~~

Do not use **-OpenReport** in an unattended task.

## Validate after changes

~~~powershell
.\Tests\Test-ServerTriagePack.ps1
~~~

The validation script checks:

- Required project files
- PowerShell parser errors
- Configuration threshold relationships
- CSV schema
- Absence of selected mutating commands at the start of code lines

It does not replace testing on representative Windows Server versions and roles.

## Suggested lab test cases

Use non-production systems first.

1. Healthy local Windows test host.
2. Remote host with WinRM available.
3. Unresolvable host name.
4. Host that blocks ICMP but allows WinRM.
5. Disk threshold temporarily raised in the JSON to force a warning.
6. A fictional required service name to test the missing-service path.
7. Very small event lookback and event limit.
8. Listening-port collection disabled.
9. Alternate credential with insufficient event-log permissions.
10. Output path without write permission.

Restore the standard configuration after threshold tests.

## Production hardening checklist

- Review and sign the script
- Store code and configuration in version control
- Peer review configuration changes
- Separate server-role configurations
- Use delegated or constrained remoting where practical
- Use WinRM HTTPS where the trust boundary requires it
- Protect output with appropriate NTFS permissions
- Define evidence retention and secure deletion
- Remove or mask sensitive event text before sharing externally
- Test representative server versions
- Monitor execution failures and stale reports
- Review exclusions periodically
- Document ownership and support

## Extending the project

The host JSON files make safe extensions possible without rewriting the
collector. Examples:

- Import the CSV into Power BI
- Compare two JSON runs for configuration drift
- Attach the HTML report to an ITSM incident
- Add role-specific application checks
- Publish only aggregated status to a monitoring platform
- Create an approval-gated remediation workflow as a separate project

Keep collection and remediation separate. A report should remain safe to run
during an incident.

## References

- Microsoft Learn: Enable-PSRemoting
  https://learn.microsoft.com/powershell/module/microsoft.powershell.core/enable-psremoting
- Microsoft Learn: about_Remote_Requirements
  https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_remote_requirements
- Microsoft Learn: Running Remote Commands
  https://learn.microsoft.com/powershell/scripting/security/remoting/running-remote-commands
- Microsoft Learn: Get-WinEvent
  https://learn.microsoft.com/powershell/module/microsoft.powershell.diagnostics/get-winevent
- Microsoft Learn: about_Execution_Policies
  https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_execution_policies

## License and support

Released under the MIT License. Use at your own risk. Validate it against your
environment, policies, security controls, and change-management requirements.

## AI Assistance Disclosure

Generative AI tools were used to assist with aspects of this project’s development, including code drafting, troubleshooting and documentation. All material was reviewed, edited and approved by the author, who retains responsibility for the final content.

Users should independently review and validate all code in a suitable test environment before using it in production.

Version 1.0.0 - 22 August 2026
