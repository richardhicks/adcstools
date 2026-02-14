# ADCSTools

[![PowerShell Gallery](https://img.shields.io/badge/PowerShell%20Gallery-ADCSTools-blue)](https://github.com/richardhicks/adcstools)
[![License](https://img.shields.io/badge/License-MIT-green)](https://github.com/richardhicks/adcstools/blob/main/LICENSE)
[![Version](https://img.shields.io/badge/Version-1.9.0-brightgreen)](https://github.com/richardhicks/adcstools)

PowerShell module for performing administrative tasks on Microsoft Active Directory Certificate Services (AD CS) servers.

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
| [Get-ADCertificateTemplate](#get-adcertificatetemplate) | Retrieve all certificate templates from Active Directory |
| [Get-Oid](#get-oid) | Retrieve information about a specific custom OID object in Active Directory |
| [Get-PublishedCertificateTemplate](#get-publishedcertificatetemplate) | Retrieve published certificate templates in AD CS |
| [Get-Sid](#get-sid) | Translate a security principal's Security Identifier (SID) |
| [Move-CertificateServicesDatabase](#move-certificateservicesdatabase) | Move the CA server database to another folder or volume |
| [Remove-ExpiredCertificate](#remove-expiredcertificate) | Delete expired certificates from the CA server database |
| [Revoke-ValidIssuedCertificate](#revoke-validissuedcertificate) | Revoke all valid issued certificates on a CA server |

## Usage

### Backup-CertificateServicesDatabase

Back up the CA server database and additional configuration information, including registry entries, CAPolicy.inf, CSP settings, published templates, and database locations.

> **Note:** Requires elevated (administrator) privileges.

#### Parameters

| Parameter | Type | Required | Description |
|---|---|---|---|
| `-LocalPath` | String | No | Local file path to store backup files. Default: `C:\CaBackup` |
| `-RemotePath` | String | No | Remote file path to store the backup archive (.zip) |
| `-IncludePrivateKey` | Switch | No | Include private keys in the backup |

#### Examples

```powershell
# Back up the CA database to the default location
Backup-CertificateServicesDatabase

# Back up the CA database and include private keys
Backup-CertificateServicesDatabase -IncludePrivateKey

# Back up the CA database locally and copy a compressed archive to a remote file server
Backup-CertificateServicesDatabase -LocalPath 'C:\Temp\CaBackup' -RemotePath '\\fs1.corp.example.net\pki\backup\'
```

---

### Get-ADCertificateTemplate

Retrieve all certificate templates from Active Directory and display their names and OIDs. This is helpful for troubleshooting certificate enrollment issues.

> **Note:** Requires the `ActiveDirectory` PowerShell module.

#### Examples

```powershell
# Retrieve all certificate templates from Active Directory
Get-ADCertificateTemplate
```

---

### Get-Oid

Retrieve information about a specific custom OID object in Active Directory. The function automatically detects the domain's Configuration partition and searches the Public Key Services container.

> **Note:** Requires the `ActiveDirectory` PowerShell module.

#### Parameters

| Parameter | Type | Required | Description |
|---|---|---|---|
| `-Oid` | String | Yes | The custom OID value to search for in Active Directory |

#### Examples

```powershell
# Retrieve information about a specific OID
Get-Oid -Oid '1.3.6.1.5.5.7.3.2'
```

---

### Get-PublishedCertificateTemplate

Retrieve a list of certificate templates published in Active Directory Certificate Services. The output includes each certificate template and the enrollment servers that have published it.

> **Note:** Requires the `ActiveDirectory` PowerShell module.

#### Examples

```powershell
# Retrieve all published certificate templates
Get-PublishedCertificateTemplate
```

---

### Get-Sid

Translate a user or computer security principal to its corresponding Security Identifier (SID).

#### Parameters

| Parameter | Type | Required | Description |
|---|---|---|---|
| `-SidType` | String | No | Type of SID to translate: `User` or `Machine`. Default: `User` |

#### Examples

```powershell
# Get the SID for the current user
Get-Sid -SidType User

# Get the SID for the current computer
Get-Sid -SidType Machine
```

---

### Move-CertificateServicesDatabase

Move the CA server database to another folder or volume. The source path is automatically detected from the certificate services registry configuration. Supports `-WhatIf` for simulation.

> **Note:** Requires elevated (administrator) privileges.

#### Parameters

| Parameter | Type | Required | Description |
|---|---|---|---|
| `-SourcePath` | String | No | Current location of the CA database. Auto-detected from the registry if not specified |
| `-DestinationPath` | String | Yes | New location for the CA database |

#### Examples

```powershell
# Move the CA database to a new volume (source auto-detected)
Move-CertificateServicesDatabase -DestinationPath 'D:\CaDatabase\'

# Move the CA database with an explicit source path
Move-CertificateServicesDatabase -SourcePath 'C:\Windows\System32\CertLog\' -DestinationPath 'D:\CaDatabase\'
```

---

### Remove-ExpiredCertificate

Delete expired certificates from the CA server database. Supports filtering by certificate state, template OID, and date. Optionally compress the database after cleanup. Supports `-WhatIf` for simulation.

#### Parameters

| Parameter | Type | Required | Description |
|---|---|---|---|
| `-State` | String | Yes | Certificate record type to delete: `Denied`, `Failed`, `Issued`, or `Revoked` |
| `-Template` | String | No | OID of a specific certificate template to filter by |
| `-Date` | String | No | Records older than this date will be deleted. Format: `M/d/yyyy`. Default: today |
| `-Delete` | Switch | No | Perform the actual deletion. Without this, the command runs in view-only mode |
| `-LogFilePath` | String | No | Location to store log files. Default: user's temp directory |
| `-CompressDatabase` | Switch | No | Compress the CA database after maintenance (recommended) |

#### Examples

```powershell
# View all expired Denied certificates (view-only mode)
Remove-ExpiredCertificate -State Denied

# Delete all expired Failed certificates
Remove-ExpiredCertificate -State Failed -Delete

# View expired Issued certificates for a specific template
Remove-ExpiredCertificate -State Issued -Template '1.3.6.1.4.1.311.21.8.8823763.7881424.11597667.39223303.50834909.808.1387547.7582140'

# Delete all expired Revoked certificates before a specific date and compress the database
Remove-ExpiredCertificate -State Revoked -Date 12/31/2022 -Delete -CompressDatabase
```

---

### Revoke-ValidIssuedCertificate

Revoke all valid issued certificates on a CA server. This is commonly used when retiring a Certificate Authority. Supports `-WhatIf` for simulation and `-Force` to skip confirmation.

> **Warning:** This action is irreversible. Use with caution.

#### Parameters

| Parameter | Type | Required | Description |
|---|---|---|---|
| `-IssueCrl` | Switch | No | Issue a new Certificate Revocation List (CRL) after revocation |
| `-Force` | Switch | No | Skip the confirmation prompt |

#### Examples

```powershell
# Revoke all valid issued certificates (with confirmation prompt)
Revoke-ValidIssuedCertificate

# Revoke all valid issued certificates and issue a new CRL
Revoke-ValidIssuedCertificate -IssueCrl

# Simulate the revocation without performing it
Revoke-ValidIssuedCertificate -WhatIf

# Revoke all valid issued certificates without confirmation
Revoke-ValidIssuedCertificate -Force
```

## Requirements

- Windows Server with the Active Directory Certificate Services (AD CS) role installed (for CA-specific functions).
- The `ActiveDirectory` PowerShell module (for functions that query Active Directory).
- Administrative privileges (for functions that modify CA configuration or services).

## Author

**Richard M. Hicks** - [Richard M. Hicks Consulting, Inc.](https://www.richardhicks.com/)

- Website: [https://www.richardhicks.com/](https://www.richardhicks.com/)
- GitHub: [https://github.com/richardhicks/adcstools](https://github.com/richardhicks/adcstools)
- X: [@richardhicks](https://x.com/richardhicks)

## License

This project is licensed under the [MIT License](https://github.com/richardhicks/adcstools/blob/main/LICENSE).

## Copyright

&copy; 2025-2026 Richard M. Hicks Consulting, Inc. All rights reserved.
