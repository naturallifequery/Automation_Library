# Interactive Windows TLS Audit & Hardening

A single, interactive PowerShell script that audits Windows Schannel and can optionally disable legacy protocols and cipher suites.

The default path is **report only**. The script does not write to the registry unless the operator selects hardening, answers the TLS 1.2/TLS 1.3 questions, reviews the proposed changes and types the exact confirmation word `HARDEN`.

## What it checks

- SSL 2.0 and SSL 3.0
- TLS 1.0 and TLS 1.1
- TLS 1.2 and TLS 1.3 Schannel support and local configuration
- Enabled cipher suites containing:
  - NULL encryption
  - RC2 or RC4
  - DES or 3DES
  - EXPORT-grade encryption
  - MD5
  - CBC mode
- Group Policy-managed cipher suite order

The protocol report distinguishes between:

- `Explicitly enabled`
- `Explicitly disabled`
- `OS default` — no explicit local Schannel value exists

`OS default` is deliberately not reported as enabled or disabled. Windows defaults vary by version, and an application's own TLS behaviour can also affect what is used.

## What hardening mode does

After explicit confirmation, the script:

1. Backs up the current Schannel and local cipher-suite registry configuration.
2. Disables SSL 2.0, SSL 3.0, TLS 1.0 and TLS 1.1 for both Schannel client and server roles.
3. Offers to explicitly enable TLS 1.2.
4. Offers to explicitly enable TLS 1.3 only on Windows 11 or Windows Server 2022 and later.
5. Disables the currently enabled legacy/weak cipher suites shown in the audit.
6. Never restarts the computer automatically.

Backups are stored under:

```text
C:\ProgramData\TLS-Hardening-Backups\yyyyMMdd-HHmmss\
```

## Requirements

- Windows 10/11 or Windows Server 2016 or later is recommended
- Windows PowerShell 5.1
- Local administrator rights for hardening mode
- The built-in Windows `TLS` PowerShell module for cipher-suite auditing and changes

Report-only mode does not require elevation in a typical configuration. Hardening mode checks for elevation before writing anything.

## Run it

1. Download `Invoke-TLSHardening.ps1`.
2. Open **Windows PowerShell**.
3. Change to the folder containing the script.
4. If needed, allow this script for the current PowerShell process only:

   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   ```

5. Run:

   ```powershell
   .\Invoke-TLSHardening.ps1
   ```

6. Select:
   - `R` or Enter for report-only mode
   - `H` to review hardening choices

For hardening, reopen Windows PowerShell with **Run as administrator** before starting the script.

## Safety controls

- Audit always runs before any change is offered.
- Report only is the default selection.
- Selecting hardening alone does not authorise changes.
- TLS 1.2 and supported TLS 1.3 are prompted separately.
- The final typed confirmation must be exactly `HARDEN`.
- Registry backups must complete before protocol or cipher changes begin.
- If an SSL Cipher Suite Order Group Policy is detected, hardening is blocked. Make the change in the controlling policy instead.
- The script does not reboot the endpoint.

## Important limitations

This is a **local Schannel configuration audit**, not a network vulnerability scanner.

- It does not prove which protocols an IIS site, RDP listener, mail service or other endpoint presents over the network.
- Java, OpenSSL and products with their own TLS stack may not use Schannel.
- Load balancers, reverse proxies and appliances must be tested separately.
- Disabling CBC suites is intentionally strict and may affect older applications or clients.
- A domain policy, MDM profile or security baseline can overwrite local configuration.
- A restart and application testing are required before treating the change as validated.

Test in a representative non-production environment first. For production systems, use an approved maintenance window and verify web, mail, RDP, database, monitoring, backup and line-of-business connectivity.

## Suggested validation

After the approved restart:

1. Rerun the script in report-only mode.
2. Confirm the legacy protocols show `Explicitly disabled`.
3. Confirm the selected modern protocols show `Explicitly enabled`.
4. Confirm no listed legacy/weak cipher suite remains enabled.
5. Test every service that depends on the host.
6. Use an authorised external TLS scanner where the service is network-facing.

## Microsoft references

- [Protocols in TLS/SSL (Schannel SSP)](https://learn.microsoft.com/windows/win32/secauthn/protocols-in-tls-ssl--schannel-ssp-)
- [Transport Layer Security registry settings](https://learn.microsoft.com/windows-server/security/tls/tls-registry-settings)
- [Manage TLS in Windows Server](https://learn.microsoft.com/windows-server/security/tls/manage-tls)
- [Get-TlsCipherSuite](https://learn.microsoft.com/powershell/module/tls/get-tlsciphersuite)
- [Disable-TlsCipherSuite](https://learn.microsoft.com/powershell/module/tls/disable-tlsciphersuite)

## Changelog

### 1.0.1

- Normalises cipher-suite name values returned as collections on some Windows builds, preventing `Cannot convert value to type System.String` during the audit.

## Disclaimer

Use at your own risk. Review the code, test application compatibility and follow your organisation's change-control and rollback processes before applying security changes.
