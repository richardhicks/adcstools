<#

.SYNOPSIS
    Delete expired certificates from the CA server database.

.PARAMETER State
    This parameter defines what type of certificate record to delete - Denied, Failed, Issued, or Revoked. Multiple values may be specified. Use the value 'All' to process all record types.

.PARAMETER Template
    The Object Identifier (OID) of a specific certificate template to delete database records for. Use Get-ADCertificateTemplate to retrieve the OID of a published certificate template. When multiple states are specified, the template filter applies to every state processed.

.PARAMETER Date
    Database records older than this date will be deleted. Accepts any date format valid for the current culture. The date must be no later than today. The default value is today.

.PARAMETER Delete
    Use this switch to delete records from the CA database. If this switch is not present, the command runs in view only mode and records that would be deleted are written to a log file for review. No records are deleted. Deleting records requires the Manage CA permission on the certification authority. Deleting records is a high impact operation and confirmation is required by default. Use -Confirm:$false to suppress the confirmation prompt.

.PARAMETER LogFilePath
    Specifies the location to store CA maintenance log files. The default location is C:\Users\<username>\AppData\Local\Temp\.

.PARAMETER Csv
    Use this switch to create an additional log file in CSV format alongside the standard text log file. The CSV file is written to the same location and shares the same name as the text log file with a .csv extension. Creating the CSV file requires a second CA database query, which may increase processing time on CA servers with large databases.

.PARAMETER CompactDatabase
    Use this switch to compact the CA database after performing maintenance (recommended). Compacting the database stops and restarts the Certificate Services service and requires an elevated PowerShell session. This switch is only valid when used with the -Delete parameter and is ignored in view only mode because no records are deleted.

.EXAMPLE
    Remove-ExpiredCertificate -State Denied

    Records all expired Denied certificates to a log file for review. Does not delete any records.

.EXAMPLE
    Remove-ExpiredCertificate -State Failed -Delete

    Deletes all expired Failed certificates. Confirmation is required before records are deleted. Use -Confirm:$false to suppress the confirmation prompt.

.EXAMPLE
    Remove-ExpiredCertificate -State Issued, Denied

    Records all expired Issued and Denied certificates to log files for review. Does not delete any records.

.EXAMPLE
    Remove-ExpiredCertificate -State All -Delete

    Deletes all expired Denied, Failed, Issued, and Revoked certificates. Confirmation is required before records are deleted. Use -Confirm:$false to suppress the confirmation prompt.

.EXAMPLE
    Remove-ExpiredCertificate -State Issued -Csv

    Records all expired Issued certificates to a log file for review and creates an additional log file in CSV format. Does not delete any records.

.EXAMPLE
    Remove-ExpiredCertificate -State Issued -Template '1.3.6.1.4.1.311.21.8.8823763.7881424.11597667.39223303.50834909.808.1387547.7582140'

    Records all expired Issued certificates based on the specified certificate template OID to a log file for review. Does not delete any records.

.EXAMPLE
    Remove-ExpiredCertificate -State Revoked -Date 12/31/2022 -Delete -Confirm:$false -CompactDatabase

    Deletes all expired Revoked certificates prior to December 31, 2022 without prompting for confirmation and compacts the CA database.

.EXAMPLE
    Remove-ExpiredCertificate -State Issued -Delete -WhatIf

    Displays the records that would be deleted without making any changes to the CA database.

.DESCRIPTION
    Use this command to remove expired certificates from a CA server, and optionally compact the CA database after performing maintenance.

    Deleting records requires the Manage CA permission on the certification authority. Compacting the database requires an elevated PowerShell session.

    This function parses certutil.exe output and requires an English operating system display language.

    This function depends on the private ADCSTools module functions Test-IsElevated and Test-CaPermission and is not intended to run standalone outside the module.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    PSCustomObject. A summary object for each state processed containing the state, the number of matching records, the number of records deleted, the number of records that could not be processed, the log file path, and the CSV log file path when the -Csv parameter is used.

.LINK
    https://github.com/richardhicks/adcstools/blob/main/Functions/Remove-ExpiredCertificate.ps1

.LINK
    https://vanbrenk.blogspot.com/2020/12/how-to-cleanup-expired-certificates.html

.LINK
    https://www.richardhicks.com/

.NOTES
    Version:            3.0
    Creation Date:      January 18, 2020
    Last Updated:       July 26, 2026
    Special Note:       This script adapted from original published guidance by Andre Gibel
    Original Author:    Andre Gibel
    Original Script:    https://vanbrenk.blogspot.com/2020/12/how-to-cleanup-expired-certificates.html
    Author:             Richard Hicks
    Organization:       Richard M. Hicks Consulting, Inc.
    Contact:            rich@richardhicks.com
    Website:            https://www.richardhicks.com/

#>

Function Remove-ExpiredCertificate {

    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([PSCustomObject])]

    Param (

        [Parameter(Mandatory)]
        [ValidateSet('All', 'Denied', 'Failed', 'Issued', 'Revoked')]
        [String[]]$State,
        [ValidatePattern('^\d+(\.\d+)+$')]
        [String]$Template,
        [ValidateScript({

                If ($_ -gt (Get-Date)) {

                    Throw 'The date specified is in the future. Specify a date no later than today.'

                }

                $True

            })]
        [DateTime]$Date = (Get-Date),
        [Switch]$Delete,
        [String]$LogFilePath = $env:temp,
        [Switch]$Csv,
        [Alias('Compress', 'CompressDatabase')]
        [Switch]$CompactDatabase

    )

    # Verify the Certificate Services service is present and running
    $Service = Get-Service -Name CertSvc -ErrorAction SilentlyContinue

    If (-Not $Service) {

        Throw 'Certificate Services does not appear to be installed on this server.'

    }

    If ($Service.Status -ne 'Running') {

        Throw 'The Certificate Services service is not running. Start the service and try again.'

    }

    # Deleting CA database records requires the Manage CA permission on the certification authority
    If ($Delete -and -not (Test-CaPermission -Role ManageCa)) {

        Throw 'The current user does not hold the Manage CA permission on this certification authority. Records cannot be deleted.'

    }

    # Database compaction serves no purpose in view only mode because no records are deleted
    If ($CompactDatabase -and -not $Delete) {

        Write-Warning 'The -CompactDatabase parameter has no effect in view only mode and will be ignored. Use the -Delete parameter to delete records and compact the CA database.'
        $CompactDatabase = $False

    }

    # Database compaction requires an elevated session to stop the Certificate Services service and access the database files
    If ($CompactDatabase -and -not (Test-IsElevated)) {

        Throw 'The -CompactDatabase parameter requires an elevated PowerShell session. Run PowerShell as an administrator and try again.'

    }

    # Expand 'All' to every supported state, otherwise remove duplicate values while preserving the order specified
    $SupportedStates = 'Denied', 'Failed', 'Issued', 'Revoked'

    If ($State -Contains 'All') {

        $StatesToProcess = $SupportedStates

    }

    Else {

        # Normalize each value to its canonical capitalization so output, warnings, and log file paths are consistent regardless of the casing specified
        $StatesToProcess = @($State | ForEach-Object { $CurrentValue = $_; $SupportedStates | Where-Object { $_ -eq $CurrentValue } } | Select-Object -Unique)

    }

    # Format the date for certutil.exe using the current culture so the restriction is interpreted correctly on the local system
    $RestrictDate = $Date.ToString('d', [System.Globalization.CultureInfo]::CurrentCulture)

    # All log files created during this run share the same timestamp
    $TimeStamp = Get-Date -Format 'yyyyMMdd-HHmmss'

    $OutColumns = 'Request.RequestID,Request.RequesterName,Request.SubmittedWhen,NotBefore,NotAfter,Request.Disposition,CertificateTemplate,SerialNumber,CertificateHash'

    If (-Not $Delete) {

        Write-Warning "'$($MyInvocation.MyCommand.Name)' is in view only mode. Use the -Delete parameter to delete CA database entries."

    }

    ForEach ($CurrentState in $StatesToProcess) {

        Switch ($CurrentState) {

            'Issued' {

                $Disposition = '20'
                $DateFilterField = 'NotAfter'

            }

            'Revoked' {

                $Disposition = '21'
                $DateFilterField = 'NotAfter'

            }

            'Failed' {

                $Disposition = '30'
                $DateFilterField = 'Request.SubmittedWhen'

            }

            'Denied' {

                $Disposition = '31'
                $DateFilterField = 'Request.SubmittedWhen'

            }

        }

        Write-Verbose "`$State = $CurrentState"
        Write-Verbose "`$Date = $RestrictDate"
        Write-Verbose "`$Disposition = $Disposition"

        # Create the log file folder if it doesn't already exist. -WhatIf is explicitly overridden because creating the log folder is required to record the matching entries during a -WhatIf pass
        $StateLogFolder = Join-Path -Path $LogFilePath -ChildPath $CurrentState

        If (-Not (Test-Path -LiteralPath $StateLogFolder)) {

            New-Item -Path $StateLogFolder -ItemType Directory -Force -WhatIf:$False | Out-Null

        }

        If ($Delete) {

            $CertLogFilePath = Join-Path -Path $StateLogFolder -ChildPath "RequestID-$CurrentState-Deleted-$TimeStamp.txt"

        }

        Else {

            $CertLogFilePath = Join-Path -Path $StateLogFolder -ChildPath "RequestID-$CurrentState-ViewOnly-$TimeStamp.txt"

        }

        Write-Verbose "Log file path is $CertLogFilePath."

        If ($PSBoundParameters['Template']) {

            # Select certificates matching a specific template
            $Restrict = "Certificate Template=$Template,Disposition=$Disposition,$DateFilterField<=$RestrictDate"

        }

        Else {

            # Select certificates matching any template
            $Restrict = "Disposition=$Disposition,$DateFilterField<=$RestrictDate"

        }

        Write-Verbose "Query: certutil.exe -view -restrict '$Restrict' -Out '$OutColumns'"
        & certutil.exe -view -restrict $Restrict -Out $OutColumns | Out-File -FilePath $CertLogFilePath -WhatIf:$False

        If ($LASTEXITCODE -ne 0) {

            Write-Warning "The certutil.exe database query for the $CurrentState state failed with exit code $LASTEXITCODE. Verify this server is a certification authority and the query restriction is valid. Skipping this state."
            Continue

        }

        # certutil.exe writes certificate hash values with a space between each byte. Remove the spaces so thumbprints can be copied directly from the log file
        $LogContent = Get-Content -LiteralPath $CertLogFilePath | ForEach-Object {

            If ($_ -Match '^(\s*Certificate Hash:\s*")([^"]*)(".*)$') {

                $Matches[1] + ($Matches[2] -Replace '\s', '') + $Matches[3]

            }

            Else {

                $_

            }

        }

        Set-Content -LiteralPath $CertLogFilePath -Value $LogContent -WhatIf:$False

        If ($Csv) {

            # Create an additional log file in CSV format for review and reporting. certutil.exe cannot emit both output formats in a single pass, so a second database query is required
            $CsvLogFilePath = [System.IO.Path]::ChangeExtension($CertLogFilePath, 'csv')
            Write-Verbose "CSV log file path is $CsvLogFilePath."
            Write-Verbose "Query: certutil.exe -view -restrict '$Restrict' -Out '$OutColumns' csv"
            & certutil.exe -view -restrict $Restrict -Out $OutColumns csv | Out-File -FilePath $CsvLogFilePath -WhatIf:$False

            If ($LASTEXITCODE -ne 0) {

                Write-Warning "The certutil.exe CSV database query failed with exit code $LASTEXITCODE. The CSV log file may be missing or incomplete."

            }

            Else {

                # Remove spaces from certificate hash values in the CSV log file
                $CsvRows = @(Import-Csv -LiteralPath $CsvLogFilePath)

                If ($CsvRows.Count -gt 0) {

                    ForEach ($CsvRow in $CsvRows) {

                        $CsvRow.'Certificate Hash' = $CsvRow.'Certificate Hash' -Replace '\s'

                    }

                    $CsvRows | Export-Csv -LiteralPath $CsvLogFilePath -NoTypeInformation -WhatIf:$False

                }

            }

        }

        Write-Verbose 'Processing log file...'
        $MatchingRequestIDCollection = @(Select-String -Path $CertLogFilePath -SimpleMatch 'Request ID:')

        $EntryDeletedCount = 0
        $EntryFailedCount = 0

        If ($MatchingRequestIDCollection.Count -eq 0) {

            Write-Warning "No $CurrentState entries to delete from the CA database."

        }

        Else {

            Write-Verbose "Number of matching entries in the CA database: $($MatchingRequestIDCollection.Count)."

            ForEach ($Entry in $MatchingRequestIDCollection) {

                # Extract the hexadecimal request ID from "Request ID: 0xb (11)" => "0xb"
                $ReqIDHex = $Entry.Line -Replace '(\s*Request\sID\:\s)(0x[0-9a-f]+)(.*)', '$2'

                Try {

                    $IDDec = [System.Convert]::ToInt64($ReqIDHex, 16)

                }

                Catch {

                    Write-Warning "Unable to parse the request ID from log entry '$($Entry.Line.Trim())'."
                    $EntryFailedCount++
                    Continue

                }

                If ($Delete -and $PSCmdlet.ShouldProcess("Request ID $IDDec", 'Delete CA database record')) {

                    Write-Verbose "Executing command: certutil.exe -deleterow $ReqIDHex (Request ID $IDDec)."
                    & certutil.exe -deleterow $ReqIDHex | Out-Null

                    If ($LASTEXITCODE -eq 0) {

                        $EntryDeletedCount++

                    }

                    Else {

                        Write-Warning "Failed to delete Request ID $IDDec (certutil.exe exit code $LASTEXITCODE)."
                        $EntryFailedCount++

                    }

                }

            }

            If ($Delete) {

                Write-Verbose "Number of deleted records: $EntryDeletedCount."

            }

        }

        # Output summary for this state
        [PSCustomObject]@{

            State          = $CurrentState
            EntriesMatched = $MatchingRequestIDCollection.Count
            EntriesDeleted = $EntryDeletedCount
            EntriesFailed  = $EntryFailedCount
            LogFile        = $CertLogFilePath
            CsvFile        = If ($Csv) { $CsvLogFilePath } Else { $Null }

        }

    }

    If ($CompactDatabase) {

        # Identify CA database location
        Write-Verbose 'Identifying the Certificate Services database location...'

        Try {

            $Config = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration' -ErrorAction Stop
            $DbFolder = $Config.DBDirectory
            $DbName = $Config.Active
            $DbPath = Join-Path -Path $DbFolder -ChildPath "$DbName.edb"

        }

        Catch {

            Write-Warning "Failed to identify the Certificate Services database location. $_"
            Return

        }

        Write-Verbose "The Certificate Services database location is `"$DbPath`"."

        If (-Not (Test-Path -LiteralPath $DbPath)) {

            Write-Warning "The Certificate Services database file `"$DbPath`" was not found. Database compaction will not be performed."
            Return

        }

        # Database compaction requires free space at least equal to the database size on the database volume for the temporary defragmented copy
        Try {

            $DbSize = (Get-Item -LiteralPath $DbPath -ErrorAction Stop).Length
            $DbVolume = [System.IO.Path]::GetPathRoot($DbFolder)
            $Drive = New-Object -TypeName System.IO.DriveInfo -ArgumentList $DbVolume

            If ($Drive.AvailableFreeSpace -lt $DbSize) {

                Write-Warning "Insufficient free space on volume $DbVolume to compact the database. Required: $([Math]::Round($DbSize / 1GB, 2)) GB. Available: $([Math]::Round($Drive.AvailableFreeSpace / 1GB, 2)) GB. Database compaction will not be performed."
                Return

            }

        }

        Catch {

            Write-Warning "Unable to verify free disk space on the database volume. $_"

        }

        If ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Stop the Certificate Services service and compact the CA database')) {

            # Stop certificate services service
            Write-Verbose 'Stopping the Certificate Services service...'

            Try {

                Stop-Service -Name CertSvc -ErrorAction Stop

            }

            Catch {

                Write-Warning "Failed to stop the Certificate Services service. $_"
                Return

            }

            Try {

                # Perform integrity check on the certificate services database. The check runs from the log file folder so the integrity check log file is created in a known location
                $IntegrityLogFile = Join-Path -Path $LogFilePath -ChildPath "$DbName.INTEG.RAW"
                Write-Verbose 'Performing integrity check on the Certificate Services database...'
                Push-Location -LiteralPath $LogFilePath

                Try {

                    & esentutl.exe /g $DbPath | Out-Host

                }

                Finally {

                    Pop-Location

                }

                If ($LASTEXITCODE -ne 0) {

                    Write-Warning "Database integrity check failed with exit code $LASTEXITCODE. Database compaction will not be performed."
                    Write-Warning "Review the integrity check log file located at '$IntegrityLogFile' for more information."
                    Return

                }

                Write-Verbose 'Database integrity check passed.'
                Write-Verbose "Removing integrity check log file located at '$IntegrityLogFile'..."
                Remove-Item -LiteralPath $IntegrityLogFile -ErrorAction SilentlyContinue

                # Compact certificate services database. Compaction runs from the database folder so the temporary defragmented database is created on the database volume
                Write-Verbose 'Compacting the Certificate Services database...'
                Push-Location -LiteralPath $DbFolder

                Try {

                    & esentutl.exe /d $DbPath | Out-Host

                }

                Finally {

                    Pop-Location

                }

                If ($LASTEXITCODE -ne 0) {

                    Write-Warning "Database compaction failed with exit code $LASTEXITCODE."

                }

            }

            Finally {

                # Always restart the certificate services service, even if the integrity check or compaction failed
                Write-Verbose 'Starting the Certificate Services service...'

                Try {

                    Start-Service -Name CertSvc -ErrorAction Stop

                }

                Catch {

                    Write-Warning "Failed to start the Certificate Services service. $_"

                }

            }

        }

    }

}

# SIG # Begin signature block
# MIIk7AYJKoZIhvcNAQcCoIIk3TCCJNkCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAeg9CpzO33ybiU
# N6ivtuaOOrOMb4B/3ljqlWymCVgRjaCCH6YwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# vHlshtjdNXOCIUjsarfNZzGCBJwwggSYAgEBMH0waTELMAkGA1UEBhMCVVMxFzAV
# BgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVk
# IEc0IENvZGUgU2lnbmluZyBSU0E0MDk2IFNIQTM4NCAyMDIxIENBMQIQDsYrSCrm
# UJuvTRscProh/zANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3AgEMMQowCKAC
# gAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsx
# DjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCS8LftlKZRzJYVeBRv3dm9
# tFNnTSybbrmZA+naay/JfTALBgcqhkjOPQIBBQAERzBFAiEA7yaiW40QfmxuymAi
# BJH9BRrlcdUXLnPB3DQ2+KXoab4CIFnDF4E9DLpWRBfJuuKvYLXSdFGwnvsoLJmR
# z2w6SxtXoYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMPAgEBMH0waTELMAkGA1UE
# BhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2Vy
# dCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENB
# MQIQCoDvGEuN8QWC0cR2p5V0aDANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJ
# AzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI2MDcyNzA0MDI1NVowLwYJ
# KoZIhvcNAQkEMSIEIFHaVeWedWgwZrHX9NF4T8UpLwl3WxSBX1KLO3TpikkZMA0G
# CSqGSIb3DQEBAQUABIICAJxVH90qVdM2eumo0w6DCZ7juRZxFt/weULUj3J8NWw2
# oog5hQPvOsPFEcBaeYbAeFcYdo6b6gArKLm3aCaMMYLrlmkifz/Xgykcf5VCMpPl
# lEch6MRI4IPWwdzR7RHHkxSzvnHluH4MHOV90Yfswvdf92vhKPmqFr+Y5khkW2Er
# ml9i45AZL0hzzbFvAOYRXxp12JAmCEiVzntH/sINJLZVPhjxoIoRwjj4ZoqYafmo
# Pp8HqEA8lurHUmvuzpcJBmR0jO/L4q5vbGlQ2YUWGAyzrkAdcKgotlwwy1Ge6B+4
# GSgb+EC6QTi+fjmaHKQTGfq+hG7vZqeJIxA8TTunysTmEqhAg9HoRAlmtLxkAE7k
# uMyHMWd5ZV7eQ+YJmx8/BsLVf7k5G1H2Vgxw6PPH7V37zeJhjTIhAupot0KZQJNS
# 6iZUk08MvvUfYh10z85TFhN57IqH1omBVoR3/5g8TzXsYCd7Du5Q/w3wJwKRr+tM
# BMNcNCu8/O4dkBs0oDNlMAabZHIIcC2W2m5QE80mxIdOM5GElP+C6MMLO59ZCPVg
# cgHtFZGLvWxu9CmqpQtmKnO9Pz+edIyquCPRxcZKCNDA89UJQnA5MxUU7kg6+RMN
# fYU99d8oMa/YH3PWgC3vKKDQUdwR3rBb5auvjMTbSeQ58Om6QUra8lXijQSxUU0i
# SIG # End signature block
