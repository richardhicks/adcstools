<#

.SYNOPSIS
    Back up the CA server database and additional configuration information.

.PARAMETER LocalPath
    The local file path to store backup files. The folder is created if it does not exist and its permissions are restricted to SYSTEM and Administrators.

.PARAMETER RemotePath
    The remote file path to store the backup file archive. Archives are timestamped (cabackup_<hostname>_<yyyyMMdd-HHmmss>.zip) and older archives are removed according to the RetentionCount parameter.

.PARAMETER IncludePrivateKey
    Indicates that private keys should be included in the backup.

.PARAMETER Password
    A SecureString password used to protect exported private keys. Required for non-interactive (scheduled) use with the IncludePrivateKey parameter. If omitted in an interactive session, the operator is prompted.

.PARAMETER RetentionCount
    The number of archive files to retain in the remote path. Older archives beyond this count are deleted. The default value is 14.

.EXAMPLE
    Backup-CertificateServicesDatabase

    Running this PowerShell command will back up the local certificate services database and configuration files to the default location C:\CaBackup.

.EXAMPLE
    Backup-CertificateServicesDatabase -IncludePrivateKey

    Running this PowerShell command will back up the local certificate services database and configuration files to the default location C:\CaBackup and include private keys in the backup. The operator is prompted for a password to protect the exported keys.

.EXAMPLE
    Backup-CertificateServicesDatabase -IncludePrivateKey -Password (Import-CliXml -Path C:\Secure\backup-password.xml).Password

    Running this PowerShell command performs a backup including private keys using a password previously stored with Export-CliXml. Use this pattern for scheduled (non-interactive) backups.

.EXAMPLE
    Backup-CertificateServicesDatabase -LocalPath 'C:\Temp\CaBackup' -RemotePath '\\fs1.corp.example.net\pki\backup\'

    Running this PowerShell command will back up the local certificate services database and configuration files to C:\Temp\CaBackup and copy a compressed, timestamped archive (.zip file) to a remote file server.

.DESCRIPTION
    Use this PowerShell script to perform regular certificate services database and configuration backup. Can be scheduled with a scheduled PowerShell job or scheduled task and performed on a regular schedule. When scheduling backups that include private keys, supply the Password parameter so no interactive prompt is required.

    The database backup is written to a staging folder and verified before the previous backup is replaced, so a failed backup never destroys the last known good backup. All critical failures throw terminating errors so scheduled tasks and monitoring can detect them.

    This function depends on the private ADCSTools module functions Test-IsElevated and Get-Sid and is not intended to run standalone outside the module.

    Ensure the remote path is a share restricted to CA administrators and backup operators. Archives may contain exported private keys (password protected) and should be treated as sensitive material.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    PSCustomObject. Returns an object describing the completed backup (computer name, backup path, archive path, CA certificate thumbprint, and timestamp).

.LINK
    https://github.com/richardhicks/adcstools/blob/main/Functions/Backup-CertificateServicesDatabase.ps1

.LINK
    https://www.richardhicks.com/

.NOTES
    Version:        3.0
    Creation Date:  January 20, 2020
    Last Updated:   July 26, 2026
    Author:         Richard Hicks
    Organization:   Richard M. Hicks Consulting, Inc.
    Contact:        rich@richardhicks.com
    Website:        https://www.richardhicks.com/

#>

Function Backup-CertificateServicesDatabase {

    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject])]

    Param (

        [ValidateNotNullOrEmpty()]
        [string]$LocalPath = (Join-Path -Path $env:systemdrive -ChildPath 'CaBackup'),
        [ValidateNotNullOrEmpty()]
        [string]$RemotePath,
        [switch]$IncludePrivateKey,
        [securestring]$Password,
        [ValidateRange(1, 365)]
        [int]$RetentionCount = 14

    )

    # Require administrative privileges
    If (-Not (Test-IsElevated)) {

        Throw 'This command requires an elevated PowerShell session. Run PowerShell as an administrator and try again.'

    }

    # Variables
    $Hostname = $env:computername
    $Timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $BackupDBPath = Join-Path -Path $LocalPath -ChildPath 'Database'
    $StagingPath = Join-Path -Path $LocalPath -ChildPath 'Database_staging'

    # Confirm the overall operation (supports -WhatIf/-Confirm)
    If (-Not $PSCmdlet.ShouldProcess($Hostname, 'Back up certificate services database and configuration')) {

        Return

    }

    # Validate password when including private keys
    If ($IncludePrivateKey) {

        If ($PSBoundParameters.ContainsKey('Password')) {

            # Reject empty passwords supplied via parameter
            If ($Password.Length -eq 0) {

                Throw 'The password supplied with the Password parameter must not be empty.'

            }

        }

        Else {

            # A password prompt is not possible in a non-interactive session
            $NonInteractive = (-Not [Environment]::UserInteractive) -or ([Environment]::GetCommandLineArgs() -match '^-NonI')

            If ($NonInteractive) {

                Throw 'The Password parameter is required when using IncludePrivateKey in a non-interactive session.'

            }

            # Prompt user for password and validate
            Do {

                # Prompt user for password
                $Password = Read-Host 'Enter a password to protect the exported private key(s)' -AsSecureString
                $Password2 = Read-Host 'Confirm password' -AsSecureString

                # Reject empty passwords
                If ($Password.Length -eq 0) {

                    Write-Warning 'The password must not be empty. Please try again.'
                    $Match = $false
                    Continue

                }

                # Compare passwords case-sensitively without retaining plaintext copies
                $Bstr1 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
                $Bstr2 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password2)

                Try {

                    $Match = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($Bstr1) -ceq [Runtime.InteropServices.Marshal]::PtrToStringBSTR($Bstr2)

                }

                Finally {

                    # Zero and free the unmanaged copies of the password
                    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Bstr1)
                    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Bstr2)

                }

                # Check if passwords match
                If (-Not $Match) {

                    Write-Warning 'Passwords do not match. Please try again.'

                }

            }

            # Repeat until passwords match
            While (-Not $Match)

        }

    }

    # Create the local backup folder and restrict its permissions before any sensitive data is written
    If (-Not (Test-Path $LocalPath)) {

        Write-Verbose "Creating local backup folder $LocalPath..."
        New-Item -Path $LocalPath -ItemType Directory | Out-Null

    }

    Write-Verbose 'Restricting backup folder permissions to SYSTEM and Administrators...'
    $Acl = Get-Acl -Path $LocalPath
    $Acl.SetAccessRuleProtection($true, $false)

    ForEach ($Identity in 'NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators') {

        $Acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($Identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))

    }

    Set-Acl -Path $LocalPath -AclObject $Acl

    # Validate the remote path early so a bad target fails before the backup runs
    If ($RemotePath) {

        # Check for existing archive folder. Create if not found.
        Write-Verbose "Checking for existing archive folder `"$RemotePath`"."
        If (-Not (Test-Path $RemotePath)) {

            Try {

                Write-Verbose 'Archive path not found. Creating folder...'
                New-Item -Path $RemotePath -ItemType Directory -ErrorAction Stop | Out-Null

            }

            Catch {

                Throw "Unable to create remote archive folder `"$RemotePath`". $($_.Exception.Message)"

            }

        }

    }

    # Remove artifacts from previous runs so stale data is never archived
    Write-Verbose 'Removing artifacts from previous backups...'
    $StaleArtifacts = @('*.reg', '*.p12', 'csp.txt', 'templates.txt', 'dblocation.txt', 'sid.txt', 'cacert.txt', 'CAPolicy.inf')

    ForEach ($Artifact in $StaleArtifacts) {

        Remove-Item -Path (Join-Path -Path $LocalPath -ChildPath $Artifact) -Force -ErrorAction SilentlyContinue

    }

    If (Test-Path $StagingPath) {

        Remove-Item $StagingPath -Recurse -Force

    }

    # Backup the CA database to a staging folder so the previous backup is preserved if this backup fails
    Write-Verbose "Backing up the CA database on $Hostname..."

    Try {

        Backup-CARoleService -Path $StagingPath -DatabaseOnly -ErrorAction Stop

    }

    Catch {

        Throw "CA database backup failed. $($_.Exception.Message)"

    }

    # Verify the staged backup contains the database before replacing the previous backup
    $StagedDatabase = Join-Path -Path $StagingPath -ChildPath 'DataBase'

    If (-Not (Get-ChildItem -Path $StagedDatabase -Filter '*.edb' -ErrorAction SilentlyContinue)) {

        Throw "CA database backup completed but no database (.edb) file was found in $StagedDatabase."

    }

    # Replace the previous backup with the verified staged backup
    If (Test-Path $BackupDBPath) {

        Write-Verbose 'Deleting previous backup...'
        Remove-Item $BackupDBPath -Recurse -Force

    }

    Move-Item -Path $StagedDatabase -Destination $BackupDBPath
    Remove-Item $StagingPath -Recurse -Force

    # Backup CA certificate(s) and private key(s)
    If ($IncludePrivateKey) {

        Try {

            Backup-CARoleService -Path $LocalPath -Password $Password -KeyOnly -Force -ErrorAction Stop

        }

        Catch {

            Throw "CA private key backup failed. $($_.Exception.Message)"

        }

    }

    # Export CA configuration registry entries
    Write-Verbose 'Exporting CA registry entries...'
    $RegFile = Join-Path -Path $LocalPath -ChildPath "$Hostname.reg"
    reg.exe export 'HKLM\System\CurrentControlSet\Services\CertSvc\Configuration' $RegFile /y | Out-Null

    If ($LASTEXITCODE -ne 0) {

        Throw "CA registry export failed with exit code $LASTEXITCODE."

    }

    # Copy CAPolicy.inf
    If (Test-Path "$env:systemroot\CAPolicy.inf") {

        Write-Verbose 'Backing up CAPolicy.inf...'
        Copy-Item "$env:systemroot\CAPolicy.inf" $LocalPath

    }

    # Record existing CSP algorithm and key length
    Write-Verbose 'Recording existing CSP algorithm and key length...'
    certutil.exe -getreg 'CA\CSP\*' | Out-File -FilePath (Join-Path -Path $LocalPath -ChildPath 'csp.txt') -Encoding utf8

    If ($LASTEXITCODE -ne 0) {

        Write-Warning "certutil.exe -getreg returned exit code $LASTEXITCODE. CSP information may be incomplete."

    }

    # Record published templates
    Write-Verbose 'Recording published templates...'
    certutil.exe -catemplates | Out-File -FilePath (Join-Path -Path $LocalPath -ChildPath 'templates.txt') -Encoding utf8

    If ($LASTEXITCODE -ne 0) {

        Write-Warning "certutil.exe -catemplates returned exit code $LASTEXITCODE. Template information may be incomplete."

    }

    # Record CA database and log file locations
    Write-Verbose 'Recording CA database and log file locations...'
    $CertSvcConfigPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'
    $DbLocationFile = Join-Path -Path $LocalPath -ChildPath 'dblocation.txt'
    $DbNames = @('DBDirectory', 'DBLogDirectory', 'DBSystemDirectory', 'DBTempDirectory')

    $DbOutput = ForEach ($Name in $DbNames) {

        $Value = (Get-ItemProperty -Path $CertSvcConfigPath -Name $Name -ErrorAction SilentlyContinue).$Name
        "$Name = $Value"

    }

    $DbOutput | Out-File -FilePath $DbLocationFile -Encoding utf8

    # Record machine SID if domain-joined (useful for server migrations)
    If ((Get-CimInstance -ClassName Win32_ComputerSystem).PartOfDomain) {

        Write-Verbose 'Recording machine SID...'

        Try {

            Get-Sid -SidType Machine -ErrorAction Stop | Out-File -FilePath (Join-Path -Path $LocalPath -ChildPath 'sid.txt') -Encoding utf8

        }

        Catch {

            Write-Warning "Unable to record machine SID. $($_.Exception.Message)"

        }

    }

    # Extract CA name
    $Subject = (Get-ItemProperty -Path $CertSvcConfigPath).Active

    # Search local computer certificate store for newest CA signing certificate
    $Escaped = [regex]::Escape($Subject)
    $CaCert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Subject -match "CN=$Escaped(,|$)" -and $_.HasPrivateKey } | Sort-Object -Property NotBefore -Descending | Select-Object -First 1

    # Record current CA signing certificate thumbprint (useful for server migrations)
    If ($null -eq $CaCert) {

        Write-Warning "No certificate matching CA name `"$Subject`" was found in the local machine store. The CA certificate thumbprint was not recorded."

    }

    Else {

        $CaCert.Thumbprint | Out-File -FilePath (Join-Path -Path $LocalPath -ChildPath 'cacert.txt') -Encoding utf8

    }

    # Create archive file in remote location
    $ArchivePath = $null

    If ($RemotePath) {

        # Use a timestamped archive name so a failed run never overwrites the last known good archive
        $ArchivePath = Join-Path -Path $RemotePath -ChildPath "cabackup_${Hostname}_$Timestamp.zip"

        Write-Verbose "Creating archive file $ArchivePath..."

        Try {

            # Use ZipFile directly to avoid the Compress-Archive file size limitation in Windows PowerShell 5.1
            Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop

            If (Test-Path $ArchivePath) {

                Remove-Item $ArchivePath -Force

            }

            [System.IO.Compression.ZipFile]::CreateFromDirectory($LocalPath, $ArchivePath, [System.IO.Compression.CompressionLevel]::Optimal, $true)

        }

        Catch {

            Throw "Unable to create archive file $ArchivePath. $($_.Exception.Message)"

        }

        # Remove archives beyond the retention count
        Write-Verbose "Removing archives beyond the retention count of $RetentionCount..."
        Get-ChildItem -Path $RemotePath -Filter "cabackup_${Hostname}_*.zip" | Sort-Object -Property LastWriteTime -Descending | Select-Object -Skip $RetentionCount | Remove-Item -Force

    }

    # Return a result object describing the completed backup
    [PSCustomObject]@{

        ComputerName       = $Hostname
        BackupPath         = $LocalPath
        ArchivePath        = $ArchivePath
        CaCertThumbprint   = $CaCert.Thumbprint
        IncludedPrivateKey = [bool]$IncludePrivateKey
        Timestamp          = $Timestamp

    }

}

# SIG # Begin signature block
# MIIk6wYJKoZIhvcNAQcCoIIk3DCCJNgCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBX049aRFYUm7bo
# eoJsJrK7XCKUKespBs80e0Y98qMvyqCCH6YwggWNMIIEdaADAgECAhAOmxiO+dAt
# 5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBa
# Fw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3E
# MB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKy
# unWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsF
# xl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU1
# 5zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJB
# MtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObUR
# WBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6
# nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxB
# YKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5S
# UUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+x
# q4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIB
# NjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMC
# AYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0Nc
# Vec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnov
# Lbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65Zy
# oUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFW
# juyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPF
# mCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9z
# twGpn1eqXijiuZQwggW0MIIDnKADAgECAhAOxitIKuZQm69NGxw+uiH/MA0GCSqG
# SIb3DQEBDAUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5j
# LjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNB
# NDA5NiBTSEEzODQgMjAyMSBDQTEwHhcNMjYwNTE2MDAwMDAwWhcNMjcwODE3MjM1
# OTU5WjCBhjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNV
# BAcTDU1pc3Npb24gVmllam8xJDAiBgNVBAoTG1JpY2hhcmQgTS4gSGlja3MgQ29u
# c3VsdGluZzEkMCIGA1UEAxMbUmljaGFyZCBNLiBIaWNrcyBDb25zdWx0aW5nMFkw
# EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOooTPiege6mCA4AriPO+Xh3mymiiZ+3k
# kn31uJifB2ojzzfY7VkAVKhgj+rcVBnofnj2b8OhvAJ4YaQ2Iwuc6aOCAgMwggH/
# MB8GA1UdIwQYMBaAFGg34Ou2O/hfEYb7/mF7CIhl9E5CMB0GA1UdDgQWBBQJvGhl
# Ahwi6UKROatrFKBmPLmd5TA+BgNVHSAENzA1MDMGBmeBDAEEATApMCcGCCsGAQUF
# BwIBFhtodHRwOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwDgYDVR0PAQH/BAQDAgeA
# MBMGA1UdJQQMMAoGCCsGAQUFBwMDMIG1BgNVHR8Ega0wgaowU6BRoE+GTWh0dHA6
# Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNENvZGVTaWduaW5n
# UlNBNDA5NlNIQTM4NDIwMjFDQTEuY3JsMFOgUaBPhk1odHRwOi8vY3JsNC5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRDb2RlU2lnbmluZ1JTQTQwOTZTSEEz
# ODQyMDIxQ0ExLmNybDCBlAYIKwYBBQUHAQEEgYcwgYQwJAYIKwYBBQUHMAGGGGh0
# dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBcBggrBgEFBQcwAoZQaHR0cDovL2NhY2Vy
# dHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29kZVNpZ25pbmdSU0E0
# MDk2U0hBMzg0MjAyMUNBMS5jcnQwCQYDVR0TBAIwADANBgkqhkiG9w0BAQwFAAOC
# AgEAbaKnnRcJAMHjuWSc2PG/QhJ0jj4hQVwJIbddYDJNxPmD0cxuuorSiR9gX2nl
# ajqNI9N7Kl+FB3oheRTGh/wp4JgZMpCq0qS0zGJ/N6Js+HmVtbkFaPyYxJMXbIWq
# p9zKkoXtSXkpR6nGZnzYkn3EBcRlu4R6hIJHzM/C2PUztH/Hd4fGIryyD69iHvKx
# zotYdlHHY6+X1ACaQnuCz3TLxs3/CDKhPUXesKcISnXHmm4uCwyVdtGyl7wPuZVk
# +rfCIOeWn+XG5J7L8xwhXCPSJ5fKJ5m8/H5cICLR0I7hI4SUiybE1nG5CZ1hKhbW
# abSfNer1dHH/vSYi80YGXCej/88vZeCGQ9/rrjugsg0yN7WCPqNKjEMTYGWkrt37
# lp4cJqULS+alUbL6x1HBdoBStDE2CFmPivL7cCCtnudqCA6b3XB416/FlRo8t4Lw
# Dc2ty+RDKirWM84Zj3ANTVs5fi43rxClBQwngGdqi5TjriKHGTkEKYRIFTViy6Ie
# JDIboOkCFJU5vM7Curvh4rQnw+aM4CyjwnDwnzwcKQVZC3Iy1T4h/FvmpSgu5ouM
# wjdzaR3cSh4OPDRrfBl1YIOoZEOHcshCaHDC46t8+UyAf70BMlrB7Nj84ORTuKTi
# IlU062VzGeREc1KHJqp/S3/NtArpVUVQEgibRxQ99KJCOV8wggawMIIEmKADAgEC
# AhAIrUCyYNKcTJ9ezam9k67ZMA0GCSqGSIb3DQEBDAUAMGIxCzAJBgNVBAYTAlVT
# MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
# b20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yMTA0Mjkw
# MDAwMDBaFw0zNjA0MjgyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5E
# aWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2Rl
# IFNpZ25pbmcgUlNBNDA5NiBTSEEzODQgMjAyMSBDQTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQDVtC9C0CiteLdd1TlZG7GIQvUzjOs9gZdwxbvEhSYw
# n6SOaNhc9es0JAfhS0/TeEP0F9ce2vnS1WcaUk8OoVf8iJnBkcyBAz5NcCRks43i
# CH00fUyAVxJrQ5qZ8sU7H/Lvy0daE6ZMswEgJfMQ04uy+wjwiuCdCcBlp/qYgEk1
# hz1RGeiQIXhFLqGfLOEYwhrMxe6TSXBCMo/7xuoc82VokaJNTIIRSFJo3hC9FFdd
# 6BgTZcV/sk+FLEikVoQ11vkunKoAFdE3/hoGlMJ8yOobMubKwvSnowMOdKWvObar
# YBLj6Na59zHh3K3kGKDYwSNHR7OhD26jq22YBoMbt2pnLdK9RBqSEIGPsDsJ18eb
# MlrC/2pgVItJwZPt4bRc4G/rJvmM1bL5OBDm6s6R9b7T+2+TYTRcvJNFKIM2KmYo
# X7BzzosmJQayg9Rc9hUZTO1i4F4z8ujo7AqnsAMrkbI2eb73rQgedaZlzLvjSFDz
# d5Ea/ttQokbIYViY9XwCFjyDKK05huzUtw1T0PhH5nUwjewwk3YUpltLXXRhTT8S
# kXbev1jLchApQfDVxW0mdmgRQRNYmtwmKwH0iU1Z23jPgUo+QEdfyYFQc4UQIyFZ
# YIpkVMHMIRroOBl8ZhzNeDhFMJlP/2NPTLuqDQhTQXxYPUez+rbsjDIJAsxsPAxW
# EQIDAQABo4IBWTCCAVUwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUaDfg
# 67Y7+F8Rhvv+YXsIiGX0TkIwHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4c
# D08wDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMDMHcGCCsGAQUF
# BwEBBGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEG
# CCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRU
# cnVzdGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5k
# aWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAcBgNVHSAEFTAT
# MAcGBWeBDAEDMAgGBmeBDAEEATANBgkqhkiG9w0BAQwFAAOCAgEAOiNEPY0Idu6P
# vDqZ01bgAhql+Eg08yy25nRm95RysQDKr2wwJxMSnpBEn0v9nqN8JtU3vDpdSG2V
# 1T9J9Ce7FoFFUP2cvbaF4HZ+N3HLIvdaqpDP9ZNq4+sg0dVQeYiaiorBtr2hSBh+
# 3NiAGhEZGM1hmYFW9snjdufE5BtfQ/g+lP92OT2e1JnPSt0o618moZVYSNUa/tcn
# P/2Q0XaG3RywYFzzDaju4ImhvTnhOE7abrs2nfvlIVNaw8rpavGiPttDuDPITzgU
# kpn13c5UbdldAhQfQDN8A+KVssIhdXNSy0bYxDQcoqVLjc1vdjcshT8azibpGL6Q
# B7BDf5WIIIJw8MzK7/0pNVwfiThV9zeKiwmhywvpMRr/LhlcOXHhvpynCgbWJme3
# kuZOX956rEnPLqR0kq3bPKSchh/jwVYbKyP/j7XqiHtwa+aguv06P0WmxOgWkVKL
# QcBIhEuWTatEQOON8BUozu3xGFYHKi8QxAwIZDwzj64ojDzLj4gLDb879M4ee47v
# tevLt/B3E+bnKD+sEq6lLyJsQfmCXBVmzGwOysWGw/YmMwwHS6DTBwJqakAwSEs0
# qFEgu60bhQjiWQ1tygVQK+pKHJ6l/aCnHwZ05/LWUpD9r4VIIflXO7ScA+2GRfS0
# YW6/aOImYIbqyK+p/pQd52MbOoZWeE4wgga0MIIEnKADAgECAhANx6xXBf8hmS5A
# QyIMOkmGMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxE
# aWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMT
# GERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yNTA1MDcwMDAwMDBaFw0zODAx
# MTQyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5j
# LjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNB
# NDA5NiBTSEEyNTYgMjAyNSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
# AoICAQC0eDHTCphBcr48RsAcrHXbo0ZodLRRF51NrY0NlLWZloMsVO1DahGPNRcy
# bEKq+RuwOnPhof6pvF4uGjwjqNjfEvUi6wuim5bap+0lgloM2zX4kftn5B1IpYzT
# qpyFQ/4Bt0mAxAHeHYNnQxqXmRinvuNgxVBdJkf77S2uPoCj7GH8BLuxBG5AvftB
# dsOECS1UkxBvMgEdgkFiDNYiOTx4OtiFcMSkqTtF2hfQz3zQSku2Ws3IfDReb6e3
# mmdglTcaarps0wjUjsZvkgFkriK9tUKJm/s80FiocSk1VYLZlDwFt+cVFBURJg6z
# MUjZa/zbCclF83bRVFLeGkuAhHiGPMvSGmhgaTzVyhYn4p0+8y9oHRaQT/aofEnS
# 5xLrfxnGpTXiUOeSLsJygoLPp66bkDX1ZlAeSpQl92QOMeRxykvq6gbylsXQskBB
# BnGy3tW/AMOMCZIVNSaz7BX8VtYGqLt9MmeOreGPRdtBx3yGOP+rx3rKWDEJlIqL
# XvJWnY0v5ydPpOjL6s36czwzsucuoKs7Yk/ehb//Wx+5kMqIMRvUBDx6z1ev+7ps
# NOdgJMoiwOrUG2ZdSoQbU2rMkpLiQ6bGRinZbI4OLu9BMIFm1UUl9VnePs6BaaeE
# WvjJSjNm2qA+sdFUeEY0qVjPKOWug/G6X5uAiynM7Bu2ayBjUwIDAQABo4IBXTCC
# AVkwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU729TSunkBnx6yuKQVvYv
# 1Ensy04wHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/
# BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAkBggr
# BgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVo
# dHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0
# LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20v
# RGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjAL
# BglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggIBABfO+xaAHP4HPRF2cTC9vgvI
# tTSmf83Qh8WIGjB/T8ObXAZz8OjuhUxjaaFdleMM0lBryPTQM2qEJPe36zwbSI/m
# S83afsl3YTj+IQhQE7jU/kXjjytJgnn0hvrV6hqWGd3rLAUt6vJy9lMDPjTLxLgX
# f9r5nWMQwr8Myb9rEVKChHyfpzee5kH0F8HABBgr0UdqirZ7bowe9Vj2AIMD8liy
# rukZ2iA/wdG2th9y1IsA0QF8dTXqvcnTmpfeQh35k5zOCPmSNq1UH410ANVko43+
# Cdmu4y81hjajV/gxdEkMx1NKU4uHQcKfZxAvBAKqMVuqte69M9J6A47OvgRaPs+2
# ykgcGV00TYr2Lr3ty9qIijanrUR3anzEwlvzZiiyfTPjLbnFRsjsYg39OlV8cipD
# oq7+qNNjqFzeGxcytL5TTLL4ZaoBdqbhOhZ3ZRDUphPvSRmMThi0vw9vODRzW6Ax
# nJll38F0cuJG7uEBYTptMSbhdhGQDpOXgpIUsWTjd6xpR6oaQf/DJbg3s6KCLPAl
# Z66RzIg9sC+NJpud/v4+7RWsWCiKi9EOLLHfMR2ZyJ/+xhCx9yHbxtl5TPau1j/1
# MIDpMPx0LckTetiSuEtQvLsNz3Qbp7wGWqbIiOWCnb5WqxL3/BAPvIXKUjPSxyZs
# q8WhbaM2tszWkPZPubdcMIIG7TCCBNWgAwIBAgIQCoDvGEuN8QWC0cR2p5V0aDAN
# BgkqhkiG9w0BAQsFADBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQs
# IEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5n
# IFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMB4XDTI1MDYwNDAwMDAwMFoXDTM2MDkw
# MzIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMu
# MTswOQYDVQQDEzJEaWdpQ2VydCBTSEEyNTYgUlNBNDA5NiBUaW1lc3RhbXAgUmVz
# cG9uZGVyIDIwMjUgMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANBG
# rC0Sxp7Q6q5gVrMrV7pvUf+GcAoB38o3zBlCMGMyqJnfFNZx+wvA69HFTBdwbHwB
# SOeLpvPnZ8ZN+vo8dE2/pPvOx/Vj8TchTySA2R4QKpVD7dvNZh6wW2R6kSu9RJt/
# 4QhguSssp3qome7MrxVyfQO9sMx6ZAWjFDYOzDi8SOhPUWlLnh00Cll8pjrUcCV3
# K3E0zz09ldQ//nBZZREr4h/GI6Dxb2UoyrN0ijtUDVHRXdmncOOMA3CoB/iUSROU
# INDT98oksouTMYFOnHoRh6+86Ltc5zjPKHW5KqCvpSduSwhwUmotuQhcg9tw2YD3
# w6ySSSu+3qU8DD+nigNJFmt6LAHvH3KSuNLoZLc1Hf2JNMVL4Q1OpbybpMe46Yce
# NA0LfNsnqcnpJeItK/DhKbPxTTuGoX7wJNdoRORVbPR1VVnDuSeHVZlc4seAO+6d
# 2sC26/PQPdP51ho1zBp+xUIZkpSFA8vWdoUoHLWnqWU3dCCyFG1roSrgHjSHlq8x
# ymLnjCbSLZ49kPmk8iyyizNDIXj//cOgrY7rlRyTlaCCfw7aSUROwnu7zER6EaJ+
# AliL7ojTdS5PWPsWeupWs7NpChUk555K096V1hE0yZIXe+giAwW00aHzrDchIc2b
# Qhpp0IoKRR7YufAkprxMiXAJQ1XCmnCfgPf8+3mnAgMBAAGjggGVMIIBkTAMBgNV
# HRMBAf8EAjAAMB0GA1UdDgQWBBTkO/zyMe39/dfzkXFjGVBDz2GM6DAfBgNVHSME
# GDAWgBTvb1NK6eQGfHrK4pBW9i/USezLTjAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0l
# AQH/BAwwCgYIKwYBBQUHAwgwgZUGCCsGAQUFBwEBBIGIMIGFMCQGCCsGAQUFBzAB
# hhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXQYIKwYBBQUHMAKGUWh0dHA6Ly9j
# YWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFtcGlu
# Z1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNydDBfBgNVHR8EWDBWMFSgUqBQhk5odHRw
# Oi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBp
# bmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIw
# CwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQBlKq3xHCcEua5gQezRCESe
# Y0ByIfjk9iJP2zWLpQq1b4URGnwWBdEZD9gBq9fNaNmFj6Eh8/YmRDfxT7C0k8FU
# FqNh+tshgb4O6Lgjg8K8elC4+oWCqnU/ML9lFfim8/9yJmZSe2F8AQ/UdKFOtj7Y
# MTmqPO9mzskgiC3QYIUP2S3HQvHG1FDu+WUqW4daIqToXFE/JQ/EABgfZXLWU0zi
# TN6R3ygQBHMUBaB5bdrPbF6MRYs03h4obEMnxYOX8VBRKe1uNnzQVTeLni2nHkX/
# QqvXnNb+YkDFkxUGtMTaiLR9wjxUxu2hECZpqyU1d0IbX6Wq8/gVutDojBIFeRlq
# AcuEVT0cKsb+zJNEsuEB7O7/cuvTQasnM9AWcIQfVjnzrvwiCZ85EE8LUkqRhoS3
# Y50OHgaY7T/lwd6UArb+BOVAkg2oOvol/DJgddJ35XTxfUlQ+8Hggt8l2Yv7roan
# cJIFcbojBcxlRcGG0LIhp6GvReQGgMgYxQbV1S3CrWqZzBt1R9xJgKf47CdxVRd/
# ndUlQ05oxYy2zRWVFjF7mcr4C34Mj3ocCVccAvlKV9jEnstrniLvUxxVZE/rptb7
# IRE2lskKPIJgbaP5t2nGj/ULLi49xTcBZU8atufk+EMF/cWuiC7POGT75qaL6vdC
# vHlshtjdNXOCIUjsarfNZzGCBJswggSXAgEBMH0waTELMAkGA1UEBhMCVVMxFzAV
# BgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVk
# IEc0IENvZGUgU2lnbmluZyBSU0E0MDk2IFNIQTM4NCAyMDIxIENBMQIQDsYrSCrm
# UJuvTRscProh/zANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3AgEMMQowCKAC
# gAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsx
# DjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCAffV48hWG9cAZ0Fh2B7xuh
# 3CvsKbDLaBsod/8POP4wADALBgcqhkjOPQIBBQAERjBEAiAQZYBKo/DShxTiC1Ij
# EKi5vyW1vxQQqOmbrsGIzUEz1gIgOmAm1taOaKIEdyjh29wBGss+d/2/aShvTUQA
# HjyV9WKhggMmMIIDIgYJKoZIhvcNAQkGMYIDEzCCAw8CAQEwfTBpMQswCQYDVQQG
# EwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0
# IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0Ex
# AhAKgO8YS43xBYLRxHanlXRoMA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkD
# MQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYwNzI3MDQwMjUyWjAvBgkq
# hkiG9w0BCQQxIgQgeuIapyL2wjf8v15VIgBt1K1Y1rdm43+Jq659/Z1Q7FAwDQYJ
# KoZIhvcNAQEBBQAEggIAhp69TgRMCD+ez95i6ToyIrC7H5jeNDEJ5lBOaxoJ7GPO
# Otwk5jwLmdOPsloIGRiax83F+8Gv7XSMM/hpYNiEkEtovl0atfC5E7jgkGdlWQf3
# E68oQCfpJoiC47MpI4BK/hipuz1ysQ9MqXD38cWYvyaZlrJ0qY183FL4vOrb+Ftr
# 5XUSOoNRzj1uXWg6e+Ssx+ecjGzsao0uT1fZkWNq6VmyaENFHlEm5OySGDj9MxYp
# 5Tyes0ogp50zS95xrGguQRedzKFEmOoukfsna0Amfz7jUf3dBEHJISLIjWG5F86Z
# a07sW1bQhkougyzH5LZ9ARgKLc7Rfab5S1WMNiknXZkoAhopdDqFsof8DzBGLPbl
# YpSNPq1YVNXaGK5d75JhRKqD9EkU5pwIbDFP4UCZ/jalMJEDMNvLsvhyvVb5hbNe
# 1l12D5bpXClDbALV2QFZPs5HOxwILzMOKx8PrcGMgrbYZO9g+O7AsbjsTYefuyxO
# cngsrRlr6k4gCX9gEWJn93N6fczx8GW9hGWDm5m0naFwv0NP91HFWnZyeG5eixok
# ky76aVIllYsqIt0X4Bs1QfimWiqT7AaSQo9efCIcZLZJJBxSCMRwlOfV4DRvTWd5
# jsR7Rb1W76gqJsBV6t/G77mw0/PrTUB/fJbwICjtvJDU1UMpajxYEH6cHdzfYNg=
# SIG # End signature block
