# ADCSTools

[![PowerShell Gallery Version](https://img.shields.io/powershellgallery/v/ADCSTools?label=PowerShell%20Gallery)](https://www.powershellgallery.com/packages/ADCSTools)
[![PowerShell Gallery Downloads](https://img.shields.io/powershellgallery/dt/ADCSTools?label=Downloads)](https://www.powershellgallery.com/packages/ADCSTools)
[![License](https://img.shields.io/github/license/richardhicks/adcstools?label=License)](https://github.com/richardhicks/adcstools/blob/main/LICENSE)

PowerShell module for performing administrative tasks on Microsoft Active Directory Certificate Services (AD CS) servers.

## What's New in 3.1

Version 3.1 adds a new function for organizations that publish CRLs to multiple file shares or serve them from load-balanced web servers:

- **Consistent CRL timestamps** – The new `Update-CrlDateTimeStamp` function sets the last write time and creation time of published CRL files to the `ThisUpdate` value embedded in the CRL. Because IIS derives the `ETag` and `Last-Modified` HTTP headers from the file's last write time, identical CRLs served by different web servers would otherwise return different ETags and cause unnecessary cache misses. Publication folders are discovered automatically from the CA's `CRLPublicationURLs` configuration, or specified explicitly with `-Path`. The `-RegisterScheduledTask` parameter creates a scheduled task that runs the function each time the CA publishes a CRL (security event ID 4872) and once daily as a safety net, with a summary written to the Application event log on every run.

## What's New in 3.0

Version 3.0 is a major update focused on safety, reliability, and automation. Highlights include:

- **Safer destructive operations** – Functions that modify the CA now perform pre-flight checks before making any changes. Elevation is verified where required, and CA permissions (Manage CA, Issue and Manage Certificates) are validated using the new internal `Test-IsElevated` and `Test-CaPermission` helper functions. High-impact operations require confirmation by default and fully support `-WhatIf`/`-Confirm`.
- **Hardened, automation-friendly backups** – `Backup-CertificateServicesDatabase` now stages and verifies each backup before replacing the previous one, so a failed backup never destroys the last known good copy. Remote archives are timestamped with configurable retention (`-RetentionCount`), backup folder permissions are restricted to SYSTEM and Administrators, and a new `-Password` parameter enables fully non-interactive (scheduled) backups that include private keys. Critical failures throw terminating errors so scheduled tasks and monitoring can detect them.
- **More flexible database cleanup** – `Remove-ExpiredCertificate` now accepts multiple states (including `All`), supports CSV log output (`-Csv`), organizes log files by state with copy-ready certificate thumbprints, performs a database integrity check and free disk space validation before compaction, and returns a summary object for each state processed.
- **Improved database relocation** – `Move-CertificateServicesDatabase` now auto-detects all source locations from the registry (including split database/log configurations), supports placing transaction logs on a separate volume (`-LogDestinationPath`), validates free space and destination paths up front, secures destination folder permissions, and automatically rolls back on failure.
- **Revocation reason support** – `Revoke-ValidIssuedCertificate` adds a `-Reason` parameter (default `CessationOfOperation`) and validates CA permissions before revoking, with guidance for role-separated CAs.
- **Remote administration** – The Active Directory query functions (`Get-ADCertificateTemplate`, `Get-Oid`, `Get-PublishedCertificateTemplate`) now support `-Server` and `-Credential` parameters, plus wildcard filtering by name, display name, or OID.
- **More reliable SID resolution** – `Get-Sid` now reads the current user's SID directly from the process token, eliminating ambiguous name lookups (for example, when a local and domain account share the same name). Failed lookups now raise standard PowerShell errors that scripts can catch with `-ErrorAction Stop` or `try`/`catch`, with clearer guidance when a machine SID lookup fails on a non-domain-joined computer.
- **Structured output** – Functions now emit `PSCustomObject` results to the pipeline, so output can be filtered, sorted, and exported like any other PowerShell object.

## Description

ADCSTools is a collection of PowerShell functions designed to simplify the management and administration of Microsoft Active Directory Certificate Services (AD CS). It provides tools for backing up and relocating the CA database, managing certificate templates, removing expired certificates, revoking certificates, and more.

## Installation

### PowerShell Gallery

```powershell
Install-Module -Name ADCSTools -Scope CurrentUser
```

### Manual Installation

1. Download the module files from the [GitHub repository](https://github.com/richardhicks/adcstools).
2. Copy the `ADCSTools` folder to a PowerShell module directory (e.g., `$env:USERPROFILE\Documents\PowerShell\Modules\`).
3. Import the module:

```powershell
Import-Module -Name ADCSTools
```

## Functions

| Function | Description |
|---|---|
| [Backup-CertificateServicesDatabase](#backup-certificateservicesdatabase) | Back up the CA server database and configuration information |
| [Get-ADCertificateTemplate](#get-adcertificatetemplate) | Retrieve certificate templates from Active Directory |
| [Get-Oid](#get-oid) | Retrieve information about custom OID objects in Active Directory |
| [Get-PublishedCertificateTemplate](#get-publishedcertificatetemplate) | Retrieve published certificate templates in AD CS |
| [Get-Sid](#get-sid) | Get the Security Identifier (SID) of the current user or computer |
| [Move-CertificateServicesDatabase](#move-certificateservicesdatabase) | Move the CA server database and log files to another folder or volume |
| [Remove-ExpiredCertificate](#remove-expiredcertificate) | Delete expired certificates from the CA server database |
| [Revoke-ValidIssuedCertificate](#revoke-validissuedcertificate) | Revoke all valid issued certificates on a CA server |
| [Update-CrlDateTimeStamp](#update-crldatetimestamp) | Set the timestamp of published CRL files to the CRL ThisUpdate value |

The module also includes private helper functions (`Test-IsElevated` and `Test-CaPermission`) used internally to validate elevation and CA permissions. These are not exported.

## Usage

### Backup-CertificateServicesDatabase

Back up the CA server database and additional configuration information, including registry entries, CAPolicy.inf, CSP settings, published templates, database locations, machine SID, and CA certificate thumbprint. Backups are staged and verified before the previous backup is replaced, and remote archives are timestamped with automatic retention pruning. Suitable for scheduled (non-interactive) use. Returns a summary object describing the completed backup. Supports `-WhatIf`.

> **Note:** Requires elevated (administrator) privileges.

#### Parameters

| Parameter | Type | Required | Description |
|---|---|---|---|
| `-LocalPath` | String | No | Local file path to store backup files. Permissions are restricted to SYSTEM and Administrators. Default: `C:\CaBackup` |
| `-RemotePath` | String | No | Remote file path to store the timestamped backup archive (.zip) |
| `-IncludePrivateKey` | Switch | No | Include private keys in the backup |
| `-Password` | SecureString | No | Password to protect exported private keys. Required for non-interactive (scheduled) use with `-IncludePrivateKey` |
| `-RetentionCount` | Int | No | Number of archive files to retain in the remote path. Default: 14 |

#### Examples

```powershell
# Back up the CA database to the default location
Backup-CertificateServicesDatabase

# Back up the CA database and include private keys (prompts for a password)
Backup-CertificateServicesDatabase -IncludePrivateKey

# Scheduled backup including private keys using a previously stored password
Backup-CertificateServicesDatabase -IncludePrivateKey -Password (Import-CliXml -Path C:\Secure\backup-password.xml).Password

# Back up the CA database locally and copy a compressed archive to a remote file server
Backup-CertificateServicesDatabase -LocalPath 'C:\Temp\CaBackup' -RemotePath '\\fs1.corp.example.net\pki\backup\'
```

---

### Get-ADCertificateTemplate

Retrieve certificate templates from Active Directory and return their names, display names, and OIDs. This is helpful for troubleshooting certificate enrollment issues. Supports filtering with wildcards and querying remote domains.

> **Note:** Requires the `ActiveDirectory` PowerShell module.

#### Parameters

| Parameter | Type | Required | Description |
|---|---|---|---|
| `-Name` | String | No | Template name to retrieve. Accepts wildcards and matches the template name, display name, or OID. Default: all templates |
| `-Server` | String | No | A specific domain controller or domain to query |
| `-Credential` | PSCredential | No | Alternate credentials for the Active Directory query |

#### Examples

```powershell
# Retrieve all certificate templates from Active Directory
Get-ADCertificateTemplate

# Retrieve templates matching a wildcard pattern
Get-ADCertificateTemplate -Name 'LabNdes*'

# Retrieve templates from a specific domain controller using alternate credentials
Get-ADCertificateTemplate -Server 'dc1.corp.example.net' -Credential (Get-Credential)
```

---

### Get-Oid

Retrieve information about custom OID objects in Active Directory. The function automatically detects the domain's Configuration partition and searches the Public Key Services container. Search by OID value or display name (with wildcard support), or omit the identity to return all custom OID objects.

> **Note:** Requires the `ActiveDirectory` PowerShell module.

#### Parameters

| Parameter | Type | Required | Description |
|---|---|---|---|
| `-Identity` | String | No | An OID value (dotted-decimal) or a display name (wildcards supported). Aliases: `Oid`, `DisplayName`. Default: all custom OID objects |
| `-Server` | String | No | A specific domain controller or domain to query |
| `-Credential` | PSCredential | No | Alternate credentials for the Active Directory query |

#### Examples

```powershell
# Retrieve all custom OID objects
Get-Oid

# Retrieve information about a specific OID
Get-Oid -Oid '1.3.6.1.4.1.311.21.8.2358923.5642938.1735024.6412058.9371604.213.5194392.8460315'

# Retrieve OID objects by display name using a wildcard
Get-Oid 'Enterprise*'
```

---

### Get-PublishedCertificateTemplate

Retrieve a list of certificate templates published in Active Directory Certificate Services. The output includes one object per published template with a Boolean property for each enrollment server indicating whether that server has published the template.

> **Note:** Requires the `ActiveDirectory` PowerShell module.

#### Parameters

| Parameter | Type | Required | Description |
|---|---|---|---|
| `-Server` | String | No | A specific domain controller or domain to query |
| `-Credential` | PSCredential | No | Alternate credentials for the Active Directory query |

#### Examples

```powershell
# Retrieve all published certificate templates
Get-PublishedCertificateTemplate

# Retrieve published templates from a specific domain controller using alternate credentials
Get-PublishedCertificateTemplate -Server dc1.corp.example.net -Credential (Get-Credential)
```

---

### Get-Sid

Get the Security Identifier (SID) of the current user or the local computer. The user SID is read directly from the current process token. The machine SID is the SID of the computer's domain account and requires the computer to be domain-joined. Returns an object with `Principal` and `SID` properties.

> **Note:** Retrieving the machine SID requires the computer to be domain-joined and a domain controller to be reachable.

#### Parameters

| Parameter | Type | Required | Description |
|---|---|---|---|
| `-SidType` | String | No | Type of SID to retrieve: `User` or `Machine`. Default: `User` |

#### Examples

```powershell
# Get the SID for the current user
Get-Sid -SidType User

# Get the SID for the current computer's domain account
Get-Sid -SidType Machine
```

---

### Move-CertificateServicesDatabase

Move the CA server database, transaction log, and checkpoint files to another folder or volume. Source locations are automatically detected from the certificate services registry configuration, including configurations where the database and log files are split across different volumes. Transaction logs can optionally be placed in a separate destination. The function validates free disk space and destination paths before making changes, secures destination folder permissions, and automatically rolls back if the move fails. The original files are preserved in the source location(s) so the move can be reversed if required. Supports `-WhatIf`; confirmation is required by default.

> **Note:** Requires elevated (administrator) privileges.

#### Parameters

| Parameter | Type | Required | Description |
|---|---|---|---|
| `-DestinationPath` | String | Yes | New location for the CA database. Alias: `DbPath` |
| `-LogDestinationPath` | String | No | Separate location for transaction log and checkpoint files. If omitted, all files are consolidated in `DestinationPath`. Alias: `LogPath` |

#### Examples

```powershell
# Move the CA database, log, and checkpoint files to a new volume (sources auto-detected)
Move-CertificateServicesDatabase -DestinationPath 'D:\CaDatabase\'

# Move the database and log files to separate volumes
Move-CertificateServicesDatabase -DbPath 'D:\CaDatabase\' -LogPath 'E:\CaLogs\'
```

---

### Remove-ExpiredCertificate

Delete expired certificates from the CA server database. Supports processing multiple certificate states in a single run (including `All`), filtering by certificate template OID and date, and optional CSV log output. Log files are written to a per-state subfolder with timestamped file names, and certificate thumbprints are recorded without embedded spaces so they can be copied directly from the log. If the database query for a state fails, that state is skipped with a warning and the remaining states are still processed. Optionally compact the database after cleanup — an integrity check and free disk space validation are performed first, and the Certificate Services service is always restarted. Returns a summary object for each state processed. Supports `-WhatIf`; deleting records requires confirmation by default.

> **Note:** The Certificate Services service must be installed and running.

> **Note:** Deleting records requires the Manage CA permission on the certification authority. Compacting the database requires an elevated PowerShell session. This function parses `certutil.exe` output and requires an English operating system display language.

#### Parameters

| Parameter | Type | Required | Description |
|---|---|---|---|
| `-State` | String[] | Yes | Certificate record type(s) to delete: `Denied`, `Failed`, `Issued`, `Revoked`, or `All`. Multiple values may be specified |
| `-Template` | String | No | OID of a specific certificate template to filter by |
| `-Date` | DateTime | No | Records older than this date will be deleted. Must be no later than today. Default: today |
| `-Delete` | Switch | No | Perform the actual deletion. Without this, the command runs in view-only mode |
| `-LogFilePath` | String | No | Location to store log files. Default: user's temp directory |
| `-Csv` | Switch | No | Create an additional log file in CSV format alongside the standard text log. Requires a second database query, which may increase processing time on CA servers with large databases |
| `-CompactDatabase` | Switch | No | Compact the CA database after maintenance (recommended). Only valid with `-Delete`; ignored in view-only mode. Aliases: `Compress`, `CompressDatabase` |

#### Examples

```powershell
# View all expired Denied certificates (view-only mode)
Remove-ExpiredCertificate -State Denied

# Delete all expired Failed certificates (confirmation required)
Remove-ExpiredCertificate -State Failed -Delete

# View expired Issued and Denied certificates and create CSV log files
Remove-ExpiredCertificate -State Issued, Denied -Csv

# Delete expired Revoked certificates older than a specific date
Remove-ExpiredCertificate -State Revoked -Date 12/31/2022 -Delete

# View expired Issued certificates for a specific certificate template
Remove-ExpiredCertificate -State Issued -Template '1.3.6.1.4.1.311.21.8.8823763.7881424.11597667.39223303.50834909.808.1387547.7582140'

# Delete all expired certificates of every state without prompting and compact the database
Remove-ExpiredCertificate -State All -Delete -Confirm:$false -CompactDatabase
```

---

### Revoke-ValidIssuedCertificate

Revoke all valid issued certificates on a CA server. This is commonly used when retiring a Certificate Authority. A revocation reason can be specified (default: `CessationOfOperation`). CA permissions are validated before any changes are made. Supports `-WhatIf` and `-Force` to skip confirmation.

> **Warning:** This action is irreversible. Use with caution.

> **Note:** Revoking certificates requires the Issue and Manage Certificates permission. Publishing a CRL with `-IssueCrl` also requires the Manage CA permission. On a CA with role separation enforced, run without `-IssueCrl` and publish the CRL separately as a CA administrator.

#### Parameters

| Parameter | Type | Required | Description |
|---|---|---|---|
| `-IssueCrl` | Switch | No | Issue a new Certificate Revocation List (CRL) after revocation. Alias: `Crl` |
| `-Reason` | String | No | Revocation reason: `Unspecified`, `KeyCompromise`, `CACompromise`, `AffiliationChanged`, `Superseded`, or `CessationOfOperation`. Default: `CessationOfOperation` |
| `-Force` | Switch | No | Skip the confirmation prompt |

#### Examples

```powershell
# Revoke all valid issued certificates (with confirmation prompt)
Revoke-ValidIssuedCertificate

# Revoke all valid issued certificates and issue a new CRL
Revoke-ValidIssuedCertificate -IssueCrl

# Revoke all valid issued certificates with a specific reason
Revoke-ValidIssuedCertificate -Reason CACompromise -IssueCrl

# Simulate the revocation without performing it
Revoke-ValidIssuedCertificate -WhatIf
```

### Update-CrlDateTimeStamp

Set the file system timestamp of published certificate revocation list (CRL) files to the `ThisUpdate` value embedded in the CRL. When a CA publishes CRL files to multiple file shares, or when several load-balanced web servers serve the same CRL, the last write time of each copy differs slightly. IIS derives the `ETag` and `Last-Modified` HTTP headers from the file's last write time, so identical CRLs return different ETags. Setting every copy to the signed `ThisUpdate` value makes the timestamps identical regardless of which server wrote the file. The operation is idempotent and safe to run repeatedly. Supports `-WhatIf`.

When `-Path` is omitted, publication folders are discovered from the `CRLPublicationURLs` registry value of the active CA. Only file system entries flagged for base or delta CRL publication are used. Each run writes a summary event to the Application event log using the source `Update-CrlDateTimeStamp`: event ID 1000 (Information) on success, 1001 (Warning) when a location was inaccessible or a file could not be updated, and 1002 (Error) when the run fails.

> **Note:** The scheduled task is triggered by security event ID 4872, which is only logged when success auditing is enabled for the Certification Services subcategory (`auditpol /set /subcategory:"Certification Services" /success:enable`) and the CA audit filter includes CRL publishing (`certutil -setreg CA\AuditFilter 127` followed by a restart of the CertSvc service). The task imports the module from its installation path at registration time, so run `-RegisterScheduledTask` again after the module is updated or moved. Install the module in the `AllUsers` scope so the task, which runs as SYSTEM, can load it.

#### Parameters

| Parameter | Type | Required | Description |
|---|---|---|---|
| `-Path` | String[] | No | One or more folders or CRL files to process. When omitted, publication locations are discovered from the local CA configuration |
| `-DelaySeconds` | Int | No | Seconds to wait before processing files, allowing the CA to finish writing when triggered by an event. Default: `0` |
| `-RetryCount` | Int | No | Number of times to retry a file that is locked or in use. Default: `3` |
| `-RetryDelaySeconds` | Int | No | Seconds to wait between retries. Default: `5` |
| `-RegisterScheduledTask` | Switch | No | Register a scheduled task running as SYSTEM that runs the function on security event ID 4872 and once daily. Also registers the event log source |
| `-TaskName` | String | No | Name of the scheduled task to register. Default: `Update-CrlDateTimeStamp` |

#### Examples

```powershell
# Discover CRL publication folders from the CA configuration and update timestamps
Update-CrlDateTimeStamp

# Process CRL files in specific folders without reading the CA configuration
Update-CrlDateTimeStamp -Path '\\fs1.corp.example.net\pki\', '\\fs2.corp.example.net\pki\'

# Report which files would be updated without making changes
Update-CrlDateTimeStamp -WhatIf

# Register a scheduled task that runs whenever the CA publishes a CRL
Update-CrlDateTimeStamp -RegisterScheduledTask
```

## Requirements

- Windows Server with the Active Directory Certificate Services (AD CS) role installed (for CA-specific functions).
- The `ActiveDirectory` PowerShell module (for functions that query Active Directory).
- Administrative privileges (for functions that modify CA configuration or services).
- Appropriate CA permissions (Manage CA, Issue and Manage Certificates) for functions that modify the CA database or revoke certificates.

## Author

**Richard M. Hicks** - [Richard M. Hicks Consulting, Inc.](https://www.richardhicks.com/)

- Website: [https://www.richardhicks.com/](https://www.richardhicks.com/)
- GitHub: [https://github.com/richardhicks/adcstools](https://github.com/richardhicks/adcstools)
- X: [@richardhicks](https://x.com/richardhicks)

## License

This project is licensed under the [MIT License](https://github.com/richardhicks/adcstools/blob/main/LICENSE).

## Copyright

&copy; 2024-2026 Richard M. Hicks Consulting, Inc. All rights reserved.
