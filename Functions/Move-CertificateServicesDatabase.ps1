<#

.SYNOPSIS
    Move the CA server database and log files to another folder or volume.

.DESCRIPTION
    By default, the certificate services database and its transaction log files are installed on the C: drive of the server. Ideally, they will be located on a separate volume to allow more room for growth. This command can be used to relocate the certificate services database and log files to another folder or volume if required.

    The current database, log, and checkpoint file locations are automatically detected from the certificate services registry configuration (DBDirectory, DBLogDirectory, DBSystemDirectory, and DBTempDirectory). Configurations where the database and log files are split across different folders or volumes are fully supported. By default, all files are consolidated in the destination path. To place the transaction log and checkpoint files in a separate location, use the LogDestinationPath parameter.

    The original database and log files are not removed from the source location(s). This is intentional and allows the move to be reversed manually if required. A readme.txt file is created in each source folder documenting the move.

    This command stops the Certificate Services service, moves the files, updates the registry, and restarts the service. Because this is a disruptive operation, confirmation is required by default. Use -Confirm:$false to suppress the confirmation prompt.

.PARAMETER DestinationPath
    The location to move the Certificate Services database. Also accepts the alias DbPath.

.PARAMETER LogDestinationPath
    The location to move the Certificate Services transaction log and checkpoint files. If not specified, the log and checkpoint files are placed in the location specified by DestinationPath. Also accepts the alias LogPath.

.EXAMPLE
    Move-CertificateServicesDatabase -DestinationPath 'D:\CaDatabase\'

    Running this PowerShell command will move the Certificate Services database, transaction log, and checkpoint files from their current locations (auto-detected from the registry) to the new location D:\CaDatabase\.

.EXAMPLE
    Move-CertificateServicesDatabase -DbPath 'D:\CaDatabase\' -LogPath 'E:\CaLogs\'

    Running this PowerShell command will move the Certificate Services database to D:\CaDatabase\ and the transaction log and checkpoint files to E:\CaLogs\.

.LINK
    https://github.com/richardhicks/adcstools/blob/main/Functions/Move-CertificateServicesDatabase.ps1

.LINK
    https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/move-certificate-server-database-log-files

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

Function Move-CertificateServicesDatabase {

    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([System.String])]

    Param (

        [Parameter(Mandatory, HelpMessage = 'Enter the full path to move the certificate services database.')]
        [ValidateNotNullOrEmpty()]
        [Alias('DbPath')]
        [string]$DestinationPath,
        [ValidateNotNullOrEmpty()]
        [Alias('LogPath')]
        [string]$LogDestinationPath

    )

    # Require administrative privileges
    If (-Not (Test-IsElevated)) {

        Throw 'This command requires an elevated PowerShell session. Run PowerShell as an administrator and try again.'

    }

    # Verify Certificate Services is installed and record the current service state
    $Service = Get-Service -Name CertSvc -ErrorAction SilentlyContinue

    If (-Not $Service) {

        Write-Error 'Certificate Services does not appear to be installed on this server.'
        Return

    }

    $ServiceWasRunning = $Service.Status -eq 'Running'
    $CertSvcConfigPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'
    $RegistryNames = @('DBDirectory', 'DBLogDirectory', 'DBSystemDirectory', 'DBTempDirectory')

    # Record the current database locations from the registry for source detection and rollback
    $OriginalValues = @{}

    ForEach ($Name in $RegistryNames) {

        $OriginalValues[$Name] = (Get-ItemProperty -Path $CertSvcConfigPath -Name $Name -ErrorAction SilentlyContinue).$Name

    }

    If ([string]::IsNullOrEmpty($OriginalValues['DBDirectory'])) {

        Write-Error 'Unable to detect the CA database location from the registry. The CA does not appear to be configured on this server.'
        Return

    }

    # Resolve source paths from the registry
    $DbSourcePath = $OriginalValues['DBDirectory'].TrimEnd('\')
    Write-Verbose "Auto-detected CA database location: $DbSourcePath"

    If ([string]::IsNullOrEmpty($OriginalValues['DBLogDirectory'])) {

        $LogSourcePath = $DbSourcePath

    }

    Else {

        $LogSourcePath = $OriginalValues['DBLogDirectory'].TrimEnd('\')
        Write-Verbose "Auto-detected CA database log location: $LogSourcePath"

    }

    If ([string]::IsNullOrEmpty($OriginalValues['DBSystemDirectory'])) {

        $SystemSourcePath = $LogSourcePath

    }

    Else {

        $SystemSourcePath = $OriginalValues['DBSystemDirectory'].TrimEnd('\')

    }

    $SourceFolders = @($DbSourcePath, $LogSourcePath, $SystemSourcePath) | Select-Object -Unique

    # Resolve destination paths. Log and checkpoint files are consolidated with the database unless LogDestinationPath is specified
    $DestinationPath = $DestinationPath.TrimEnd('\')

    If ($PSBoundParameters.ContainsKey('LogDestinationPath')) {

        $LogDestinationPath = $LogDestinationPath.TrimEnd('\')

    }

    Else {

        $LogDestinationPath = $DestinationPath

    }

    $SplitDestination = $LogDestinationPath -ne $DestinationPath
    $DestinationPaths = @($DestinationPath)

    If ($SplitDestination) {

        $DestinationPaths += $LogDestinationPath

    }

    # Verify source paths exist
    ForEach ($Path in $SourceFolders) {

        If (-Not (Test-Path -LiteralPath $Path -PathType Container)) {

            Write-Error "The source path `"$Path`" does not exist."
            Return

        }

    }

    ForEach ($Path in $DestinationPaths) {

        # Verify destination path is an absolute local path. UNC and relative paths are not supported
        If ($Path -NotMatch '^[A-Za-z]:\\.+') {

            Write-Error "The destination path `"$Path`" must be an absolute path on a local drive (for example, 'D:\CaDatabase'). UNC and relative paths are not supported."
            Return

        }

        # Verify destination path does not already exist
        If (Test-Path -LiteralPath $Path) {

            Write-Error "The destination path `"$Path`" already exists."
            Return

        }

        # Verify destination path is not located within a source path
        ForEach ($Source in $SourceFolders) {

            If (($Path + '\').StartsWith(($Source + '\'), [System.StringComparison]::OrdinalIgnoreCase)) {

                Write-Error "The destination path `"$Path`" cannot be located within the source path `"$Source`"."
                Return

            }

        }

    }

    # Identify database, transaction log, and checkpoint files to move. Transient ESE working files (tmp.edb and edbtmp.log) are excluded because the database engine removes them on clean shutdown and recreates them on service start
    $DbFiles = Get-ChildItem -LiteralPath $DbSourcePath -Filter '*.edb' -File | Where-Object { $_.Name -ne 'tmp.edb' }
    $LogFiles = Get-ChildItem -LiteralPath $LogSourcePath -Filter '*.log' -File | Where-Object { $_.Name -ne 'edbtmp.log' }
    $CheckpointFiles = Get-ChildItem -LiteralPath $SystemSourcePath -Filter '*.chk' -File

    If (-Not $DbFiles) {

        Write-Error "No certificate services database (.edb) files were found in `"$DbSourcePath`"."
        Return

    }

    # Verify sufficient free space on the destination volume(s)
    $SpaceRequired = @{}
    $DbRoot = [System.IO.Path]::GetPathRoot($DestinationPath)
    $LogRoot = [System.IO.Path]::GetPathRoot($LogDestinationPath)
    $SpaceRequired[$DbRoot] += ($DbFiles | Measure-Object -Property Length -Sum).Sum
    $SpaceRequired[$LogRoot] += ($LogFiles | Measure-Object -Property Length -Sum).Sum
    $SpaceRequired[$LogRoot] += ($CheckpointFiles | Measure-Object -Property Length -Sum).Sum

    ForEach ($Root in $SpaceRequired.Keys) {

        Try {

            $Drive = New-Object -TypeName System.IO.DriveInfo -ArgumentList $Root

            If ($Drive.DriveType -ne [System.IO.DriveType]::Fixed) {

                Write-Error "The destination volume $Root is not a local fixed drive."
                Return

            }

            If ($Drive.AvailableFreeSpace -lt $SpaceRequired[$Root]) {

                Write-Error "Insufficient free space on volume $Root. Required: $([math]::Round($SpaceRequired[$Root] / 1GB, 2)) GB. Available: $([math]::Round($Drive.AvailableFreeSpace / 1GB, 2)) GB."
                Return

            }

        }

        Catch {

            Write-Error "Unable to validate the destination volume $Root. $_"
            Return

        }

    }

    If ($SplitDestination) {

        $Action = "Move database files from '$DbSourcePath' to '$DestinationPath' and log files from '$LogSourcePath' to '$LogDestinationPath'"

    }

    Else {

        $Action = "Move database and log files from '$($SourceFolders -Join ''', ''')' to '$DestinationPath'"

    }

    If ($PSCmdlet.ShouldProcess('Certificate Services database', $Action)) {

        # Stop certificate services if running
        If ($ServiceWasRunning) {

            Write-Verbose 'Stopping the Certificate Services service...'

            Try {

                Stop-Service -Name CertSvc -ErrorAction Stop

            }

            Catch {

                Write-Error "Failed to stop the Certificate Services service. $_"
                Return

            }

        }

        Else {

            Write-Verbose 'The Certificate Services service is not currently running.'

        }

        # Re-enumerate files now that the service is stopped. The initial enumeration is performed while the service is running and may include files the database engine removes during clean shutdown
        $DbFiles = Get-ChildItem -LiteralPath $DbSourcePath -Filter '*.edb' -File | Where-Object { $_.Name -ne 'tmp.edb' }
        $LogFiles = Get-ChildItem -LiteralPath $LogSourcePath -Filter '*.log' -File | Where-Object { $_.Name -ne 'edbtmp.log' }
        $CheckpointFiles = Get-ChildItem -LiteralPath $SystemSourcePath -Filter '*.chk' -File

        # Create destination folder(s)
        $CreatedPaths = @()

        Try {

            ForEach ($Path in $DestinationPaths) {

                Write-Verbose "Creating destination folder $Path..."
                New-Item -ItemType Directory -Path $Path -ErrorAction Stop | Out-Null
                $CreatedPaths += $Path

            }

        }

        Catch {

            Write-Error "Failed to create destination folder. $_"

            ForEach ($Path in $CreatedPaths) {

                Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue

            }

            If ($ServiceWasRunning) {

                Write-Verbose 'Restarting the Certificate Services service...'
                Start-Service -Name CertSvc

            }

            Return

        }

        # Secure destination folder(s) with the permissions required by certificate services (SYSTEM and Administrators full control, inheritance disabled)
        Try {

            $SystemSid = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-18'
            $AdministratorsSid = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-32-544'

            ForEach ($Path in $CreatedPaths) {

                $Acl = Get-Acl -Path $Path
                $Acl.SetAccessRuleProtection($True, $False)

                ForEach ($Sid in @($SystemSid, $AdministratorsSid)) {

                    $Rule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $Sid, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow'
                    $Acl.AddAccessRule($Rule)

                }

                Set-Acl -Path $Path -AclObject $Acl

            }

        }

        Catch {

            Write-Warning "Failed to set permissions on the destination folder(s). Verify that SYSTEM and Administrators have full control. $_"

        }

        # Copy CA database, transaction log, and checkpoint files to new location(s)
        Try {

            Write-Verbose "Copying the Certificate Services database files from $DbSourcePath to $DestinationPath..."
            Copy-Item -LiteralPath $DbFiles.FullName -Destination $DestinationPath -ErrorAction Stop

            If ($LogFiles) {

                Write-Verbose "Copying the Certificate Services log files from $LogSourcePath to $LogDestinationPath..."
                Copy-Item -LiteralPath $LogFiles.FullName -Destination $LogDestinationPath -ErrorAction Stop

            }

            If ($CheckpointFiles) {

                Write-Verbose "Copying the Certificate Services checkpoint files from $SystemSourcePath to $LogDestinationPath..."
                Copy-Item -LiteralPath $CheckpointFiles.FullName -Destination $LogDestinationPath -ErrorAction Stop

            }

        }

        Catch {

            Write-Error "Failed to copy database files. $_"
            Write-Verbose 'Removing partially copied files...'

            ForEach ($Path in $CreatedPaths) {

                Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue

            }

            If ($ServiceWasRunning) {

                Write-Verbose 'Restarting the Certificate Services service...'
                Start-Service -Name CertSvc

            }

            Return

        }

        # Update registry settings. Database and temporary files use the database destination; log and checkpoint files use the log destination
        $RegistryUpdates = @{

            DBDirectory       = $DestinationPath
            DBTempDirectory   = $DestinationPath
            DBLogDirectory    = $LogDestinationPath
            DBSystemDirectory = $LogDestinationPath

        }

        Try {

            Write-Verbose 'Updating Certificate Services database locations in the registry...'

            ForEach ($Name in $RegistryNames) {

                Set-ItemProperty -Path $CertSvcConfigPath -Name $Name -Value $RegistryUpdates[$Name] -ErrorAction Stop

            }

        }

        Catch {

            Write-Error "Failed to update registry settings. $_"

            # Roll back registry changes
            Write-Verbose 'Rolling back registry changes...'

            ForEach ($Name in $RegistryNames) {

                Try {

                    If ($Null -ne $OriginalValues[$Name]) {

                        Set-ItemProperty -Path $CertSvcConfigPath -Name $Name -Value $OriginalValues[$Name] -ErrorAction Stop

                    }

                    Else {

                        # The value did not exist before the move and must be removed
                        Remove-ItemProperty -Path $CertSvcConfigPath -Name $Name -ErrorAction SilentlyContinue

                    }

                }

                Catch {

                    Write-Warning "Failed to restore the registry value $Name to `"$($OriginalValues[$Name])`". Restore this value manually before starting the Certificate Services service. $_"

                }

            }

            # Remove copied files
            ForEach ($Path in $CreatedPaths) {

                Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue

            }

            If ($ServiceWasRunning) {

                Write-Verbose 'Restarting the Certificate Services service...'
                Start-Service -Name CertSvc

            }

            Return

        }

        # Start the Certificate Services service if it was running prior to the move
        If ($ServiceWasRunning) {

            Write-Verbose 'Starting the Certificate Services service...'

            Try {

                Start-Service -Name CertSvc -ErrorAction Stop

            }

            Catch {

                Write-Error "The database move completed but the Certificate Services service failed to start. Review the event log for details. $_"
                Return

            }

        }

        Else {

            Write-Verbose 'The Certificate Services service was not running prior to the move and was not started.'

        }

        # Capture timestamp once for consistency
        $Timestamp = Get-Date

        If ($SplitDestination) {

            $LocationText = "The Certificate Services database has been relocated to $DestinationPath and the log files have been relocated to $LogDestinationPath."

        }

        Else {

            $LocationText = "The Certificate Services database and log files have been relocated to $DestinationPath."

        }

        # Create a readme.txt file in each original location
        $Text = @"
$LocationText
The move was performed by $env:USERDOMAIN\$env:USERNAME on $($Timestamp.ToShortDateString()) at $($Timestamp.ToShortTimeString()).
"@

        ForEach ($Path in $SourceFolders) {

            Try {

                Write-Verbose "Creating readme.txt file in $Path..."
                Set-Content -LiteralPath (Join-Path -Path $Path -ChildPath 'readme.txt') -Value $Text -ErrorAction Stop

            }

            Catch {

                Write-Warning "Failed to create readme.txt in `"$Path`". $_"

            }

        }

        Write-Output 'Certificate Services database move complete.'
        Write-Warning "The original database and log files in '$($SourceFolders -Join ''', ''')' were not removed. Manually delete these files to recover disk space."

    }

}

# SIG # Begin signature block
# MIIk6wYJKoZIhvcNAQcCoIIk3DCCJNgCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCKH1SPfhtBI3RU
# Ka8AB/dETUCrYJd4I3V6vb9W54pccqCCH6YwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# DjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBD2z4z5eCpwli7Vz5kvoEo
# is3mFqFi5QgmrElDqwSAhjALBgcqhkjOPQIBBQAERjBEAiBIxxAg4EmVl1cwaE3/
# rw9+uIZp0tO7f27XvsBnd0OpSAIgEiHOEt4Z92b+50LRjPLTKNJyc42DBPmhFK+V
# b9VraUWhggMmMIIDIgYJKoZIhvcNAQkGMYIDEzCCAw8CAQEwfTBpMQswCQYDVQQG
# EwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0
# IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0Ex
# AhAKgO8YS43xBYLRxHanlXRoMA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkD
# MQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYwNzI3MDQwMjU0WjAvBgkq
# hkiG9w0BCQQxIgQgJEG4M2Hy+Qzqxv6AtokyDrylpSqtM9j9YJXgoecPjzIwDQYJ
# KoZIhvcNAQEBBQAEggIAO+QCP/BRzCijCdoTZS89nsr3Vtl3w0mvQ4VdHlLyoYS/
# Y4II+I4Xqh/bmOErcqY6Eey4h6usMiEFMulX4zecfFZ6yx5mNVdusMrL/0KcMHC6
# uNm7K/j3p8k5aWAkpu6wY1Ldkg4nopZmZ544pSIRdknNOpNqBXUDRYKoXOLBgIO6
# 2OF2O/kjSAbUn6gcxcMwGDKNkKif23FJTWZ1lEAfu7NkaUFyAtVQUqIjEuGVXiWq
# UyMT1odGHUyewo/2Qs98LH6DbT1/4Cyd68+dR2wug1SRJi9bSyxPvxmij2c9qj4Z
# Z+cqt0KY0kRfEZ+6DMrTVLCRhC3sswB83EAk12exMZz9dIvtIdbYSlWPS7g1yLLb
# 2tiMh75fbnIr58KVXNrblTVgXMqX9yeWRXDBJDO6KmsihcCYH3tinssqOK5t2YS1
# nz2rsYoh9wxbh9FLM9UUrIifRKuV/0foJxIjmi5voyoMRGl/M7IsRQ+TyAws42+L
# vmFM4jupc1OEEh7Am+dErZMOA5s3Ch5v+e7qR2SB79k67xrcQvFmEF+ji+WTb/8B
# KNVuUlsVeBnPsrjjOh0RJUJFWYzuW+rB6+C6kbiTAc8fGA5qQurItBfO2gh8BYuX
# Fh3g/d9WOrDtOEoyVjGC07K5nBsCUX72F4nCBrTzMcn13y1DlMQTzVcoJjhGVL8=
# SIG # End signature block
