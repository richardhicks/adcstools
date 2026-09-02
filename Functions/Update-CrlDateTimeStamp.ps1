<#

.SYNOPSIS
    Set the file system timestamp of published certificate revocation list (CRL) files to the ThisUpdate value embedded in the CRL.

.PARAMETER Path
    One or more folders or CRL files to process. When omitted, CRL publication locations are discovered automatically from the local certification authority (CA) configuration in the registry.

.PARAMETER DelaySeconds
    The number of seconds to wait before processing files. Use this when the function is triggered by an event to allow the CA to finish writing files. The default value is 0.

.PARAMETER RetryCount
    The number of times to retry a file that is locked or in use. The default value is 3.

.PARAMETER RetryDelaySeconds
    The number of seconds to wait between retries. The default value is 5.

.PARAMETER RegisterScheduledTask
    Registers a scheduled task on the local CA server that runs this function whenever security event ID 4872 (Certificate Services published the CRL) is logged. A daily trigger is also added as a safety net. The event log source used by the function is also registered. The task imports the ADCSTools module from its current installation path, so run this command again after the module is updated or moved.

.PARAMETER TaskName
    The name of the scheduled task to register. The default value is Update-CrlDateTimeStamp.

.EXAMPLE
    Update-CrlDateTimeStamp

    Running this PowerShell command discovers CRL publication folders from the local CA configuration and sets the timestamp of each CRL file to its ThisUpdate value.

.EXAMPLE
    Update-CrlDateTimeStamp -Path '\\fs1.corp.example.net\pki\', '\\fs2.corp.example.net\pki\'

    Running this PowerShell command processes all CRL files in the specified folders without reading the local CA configuration.

.EXAMPLE
    Update-CrlDateTimeStamp -WhatIf

    Running this PowerShell command reports which CRL files would be updated without making any changes.

.EXAMPLE
    Update-CrlDateTimeStamp -RegisterScheduledTask

    Running this PowerShell command registers a scheduled task running as SYSTEM that imports the ADCSTools module and runs Update-CrlDateTimeStamp with a 5 second delay each time security event ID 4872 is logged, and once daily as a backup.

.DESCRIPTION
    When a CA publishes CRL files to multiple file shares, or when several web servers serve the same CRL, the last write time of each copy differs slightly. IIS derives the ETag and Last-Modified HTTP headers from the file's last write time, so identical CRLs served by load-balanced web servers return different ETags. This causes unnecessary cache misses and conditional request failures.

    This function sets the last write time and creation time of each CRL file to the ThisUpdate value contained in the CRL itself. Because ThisUpdate is part of the signed CRL, every copy of the same CRL receives an identical timestamp regardless of which server wrote it or when. The operation is idempotent and safe to run repeatedly.

    Publication locations are discovered from the CRLPublicationURLs registry value of the active CA. Only entries flagged for base CRL (1) or delta CRL (64) publication that refer to file system paths are used. LDAP and HTTP entries are ignored. All CRL files in each discovered folder are processed, which covers renewed CA keys and delta CRLs without special handling.

    Each run writes a single summary event to the Application event log using the source Update-CrlDateTimeStamp. Event ID 1000 (Information) is logged when the run completes without issues, event ID 1001 (Warning) when a location was not accessible or a file could not be updated, and event ID 1002 (Error) when the function terminates unexpectedly. No events are written when the WhatIf parameter is specified. The event log source is registered by the RegisterScheduledTask parameter. If the source does not exist and cannot be created, a warning is displayed and the run continues.

    Security event ID 4872 is only logged when success auditing is enabled for the Certification Services subcategory (auditpol /set /subcategory:"Certification Services" /success:enable) and the CA audit filter includes revocation and CRL publishing (certutil -setreg CA\AuditFilter 127 followed by a restart of the CertSvc service).

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    PSCustomObject. Returns an object for each CRL file processed with the file path, ThisUpdate value, previous last write time, and result.

.LINK
    https://github.com/richardhicks/adcstools/blob/main/Functions/Update-CrlDateTimeStamp.ps1

.LINK
    https://www.richardhicks.com/

.NOTES
    Version:        1.0
    Creation Date:  September 2, 2026
    Last Updated:   September 2, 2026
    Author:         Richard Hicks
    Organization:   Richard M. Hicks Consulting, Inc.
    Contact:        rich@richardhicks.com
    Website:        https://www.richardhicks.com/

#>

Function Update-CrlDateTimeStamp {

    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Update')]
    [OutputType([PSCustomObject])]

    Param (

        [Parameter(ParameterSetName = 'Update')]
        [ValidateNotNullOrEmpty()]
        [string[]]$Path,
        [Parameter(ParameterSetName = 'Update')]
        [ValidateRange(0, 300)]
        [int]$DelaySeconds = 0,
        [Parameter(ParameterSetName = 'Update')]
        [ValidateRange(0, 10)]
        [int]$RetryCount = 3,
        [Parameter(ParameterSetName = 'Update')]
        [ValidateRange(1, 60)]
        [int]$RetryDelaySeconds = 5,
        [Parameter(ParameterSetName = 'Register', Mandatory)]
        [switch]$RegisterScheduledTask,
        [Parameter(ParameterSetName = 'Register')]
        [ValidateNotNullOrEmpty()]
        [string]$TaskName = 'Update-CrlDateTimeStamp'

    )

    # Registry location of the CA configuration
    $CertSvcConfigPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'

    # CRLPublicationURLs flag bits for file publishing
    $CsUrlServerPublish = 1
    $CsUrlServerPublishDelta = 64

    # Event log source and event IDs
    $EventLogName = 'Application'
    $EventSource = 'Update-CrlDateTimeStamp'
    $EventIdCompleted = 1000
    $EventIdCompletedWithWarnings = 1001
    $EventIdFailed = 1002

    # Warnings collected during the run for the summary event
    $Issues = [System.Collections.Generic.List[string]]::new()

    # Writes a warning to the console and records it for the summary event
    Function Write-CrlTimestampWarning {

        [CmdletBinding()]

        Param (

            [string]$Message

        )

        Write-Warning $Message
        $Issues.Add($Message)

    }

    # Writes an entry to the Application event log. Failures are reported as warnings and never abort the run
    Function Write-CrlTimestampEvent {

        [CmdletBinding()]

        Param (

            [System.Diagnostics.EventLogEntryType]$EntryType,
            [int]$EventId,
            [string]$Message

        )

        If ($WhatIfPreference) {

            Write-Verbose 'Skipping event log entry (WhatIf).'
            Return

        }

        Try {

            If (-Not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {

                [System.Diagnostics.EventLog]::CreateEventSource($EventSource, $EventLogName)
                Write-Verbose "Created event log source '$EventSource' in the $EventLogName log."

            }

            [System.Diagnostics.EventLog]::WriteEntry($EventSource, $Message, $EntryType, $EventId)
            Write-Verbose "Logged event ID $EventId ($EntryType) to the $EventLogName log."

        }

        Catch {

            Write-Warning "Unable to write to the $EventLogName event log. $($_.Exception.Message)"

        }

    }

    # Reads the tag, length, and content position of the ASN.1 DER element starting at the given offset
    Function Read-Asn1Element {

        [CmdletBinding()]

        Param (

            [byte[]]$Data,
            [int]$Offset

        )

        If ($Offset -ge $Data.Length) {

            Throw 'Unexpected end of ASN.1 data.'

        }

        $Tag = $Data[$Offset]
        $Position = $Offset + 1
        $Length = [int]$Data[$Position]
        $Position++

        # Long form length
        If ($Length -band 0x80) {

            $LengthBytes = $Length -band 0x7F

            If ($LengthBytes -eq 0 -or $LengthBytes -gt 4) {

                Throw 'Unsupported ASN.1 length encoding.'

            }

            $Length = 0

            For ($i = 0; $i -lt $LengthBytes; $i++) {

                $Length = ($Length -shl 8) -bor $Data[$Position]
                $Position++

            }

        }

        If ($Position + $Length -gt $Data.Length) {

            Throw 'ASN.1 element length exceeds available data.'

        }

        Return [PSCustomObject]@{

            Tag           = $Tag
            Length        = $Length
            ContentOffset = $Position
            NextOffset    = $Position + $Length

        }

    }

    # Returns the ThisUpdate value of a DER or PEM encoded CRL file as a UTC DateTime
    Function Get-CrlThisUpdate {

        [CmdletBinding()]
        [OutputType([datetime])]

        Param (

            [string]$FilePath

        )

        $Data = [System.IO.File]::ReadAllBytes($FilePath)

        # Convert PEM encoded CRL to DER
        If ($Data.Length -gt 10 -and [System.Text.Encoding]::ASCII.GetString($Data, 0, 10) -eq '-----BEGIN') {

            $Pem = [System.Text.Encoding]::ASCII.GetString($Data)
            $Base64 = ($Pem -split "`r?`n" | Where-Object { $_ -notmatch '^-----' }) -join ''
            $Data = [System.Convert]::FromBase64String($Base64)

        }

        # CertificateList SEQUENCE
        $CertificateList = Read-Asn1Element -Data $Data -Offset 0

        If ($CertificateList.Tag -ne 0x30) {

            Throw 'File is not a DER encoded CRL.'

        }

        # TBSCertList SEQUENCE
        $TbsCertList = Read-Asn1Element -Data $Data -Offset $CertificateList.ContentOffset

        If ($TbsCertList.Tag -ne 0x30) {

            Throw 'File is not a DER encoded CRL.'

        }

        $Element = Read-Asn1Element -Data $Data -Offset $TbsCertList.ContentOffset

        # Optional version INTEGER
        If ($Element.Tag -eq 0x02) {

            $Element = Read-Asn1Element -Data $Data -Offset $Element.NextOffset

        }

        # Signature AlgorithmIdentifier SEQUENCE
        If ($Element.Tag -ne 0x30) {

            Throw 'Unexpected CRL structure (signature algorithm).'

        }

        $Element = Read-Asn1Element -Data $Data -Offset $Element.NextOffset

        # Issuer Name SEQUENCE
        If ($Element.Tag -ne 0x30) {

            Throw 'Unexpected CRL structure (issuer).'

        }

        $Element = Read-Asn1Element -Data $Data -Offset $Element.NextOffset

        # ThisUpdate Time (UTCTime or GeneralizedTime)
        $TimeString = [System.Text.Encoding]::ASCII.GetString($Data, $Element.ContentOffset, $Element.Length)

        Switch ($Element.Tag) {

            0x17 { $Format = 'yyMMddHHmmss\Z' }
            0x18 { $Format = 'yyyyMMddHHmmss\Z' }
            Default { Throw 'Unexpected CRL structure (ThisUpdate).' }

        }

        Return [datetime]::ParseExact($TimeString, $Format, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal)

    }

    # Returns the file system folders the local CA publishes CRL files to, discovered from the registry
    Function Get-CrlPublicationFolder {

        [CmdletBinding()]
        [OutputType([string])]

        Param ()

        If (-Not (Test-Path -Path $CertSvcConfigPath)) {

            Throw 'Certificate Services configuration not found in the registry. Run this function on a CA server or specify the Path parameter.'

        }

        $CaName = (Get-ItemProperty -Path $CertSvcConfigPath -Name 'Active' -ErrorAction Stop).Active
        $CaConfigPath = Join-Path -Path $CertSvcConfigPath -ChildPath $CaName
        $PublicationUrls = (Get-ItemProperty -Path $CaConfigPath -Name 'CRLPublicationURLs' -ErrorAction Stop).CRLPublicationURLs

        Write-Verbose "Active CA is '$CaName'."

        # Token values used in publication URL templates
        $SanitizedName = $CaName -replace '[\\/:*?"<>|]', '_'
        $Tokens = @{

            '%1' = [System.Net.Dns]::GetHostEntry($env:computername).HostName
            '%2' = $env:computername
            '%3' = $CaName
            '%7' = $SanitizedName

        }

        ForEach ($Entry in $PublicationUrls) {

            # Each entry is <flags>:<template>
            If ($Entry -notmatch '^(\d+):(.+)$') {

                Write-CrlTimestampWarning "Ignoring unrecognized CRLPublicationURLs entry '$Entry'."
                Continue

            }

            $Flags = [int]$Matches[1]
            $Template = $Matches[2]

            # Only locations the CA writes base or delta CRLs to
            If (($Flags -band ($CsUrlServerPublish -bor $CsUrlServerPublishDelta)) -eq 0) {

                Write-Verbose "Skipping '$Template' (not a publishing location)."
                Continue

            }

            # Only file system locations
            If ($Template -match '^(ldap|https?):') {

                Write-Verbose "Skipping '$Template' (not a file system location)."
                Continue

            }

            $FilePath = $Template

            # Convert file URL to file system path
            If ($FilePath -match '^file://(.+)$') {

                $FilePath = $Matches[1]

                If ($FilePath -match '^/*([A-Za-z]:.*)$') {

                    # file:///C:/path or file://C:\path (as written by the CA console)
                    $FilePath = $Matches[1] -replace '/', '\'

                }

                ElseIf ($FilePath -notmatch '^\\\\') {

                    # file://server/share/path
                    $FilePath = '\\' + ($FilePath -replace '/', '\')

                }

            }

            # Expand tokens that may appear in the folder portion of the template
            ForEach ($Token in $Tokens.Keys) {

                $FilePath = $FilePath.Replace($Token, $Tokens[$Token])

            }

            $Folder = Split-Path -Path $FilePath -Parent

            If ([string]::IsNullOrWhiteSpace($Folder)) {

                Write-CrlTimestampWarning "Unable to determine folder for publication entry '$Template'."
                Continue

            }

            Write-Verbose "Discovered CRL publication folder '$Folder'."
            Write-Output $Folder

        }

    }

    # Registers the event log source and a scheduled task that runs this function on security event 4872 and once daily
    Function Register-CrlTimestampTask {

        [CmdletBinding(SupportsShouldProcess)]

        Param (

            [string]$Name

        )

        # Event log source for run summaries
        If ($PSCmdlet.ShouldProcess($EventSource, "Register event log source in the $EventLogName log")) {

            If ([System.Diagnostics.EventLog]::SourceExists($EventSource)) {

                Write-Verbose "Event log source '$EventSource' already exists."

            }

            Else {

                [System.Diagnostics.EventLog]::CreateEventSource($EventSource, $EventLogName)
                Write-Verbose "Registered event log source '$EventSource' in the $EventLogName log."

            }

        }

        # The task starts a new PowerShell session on every run, so the module (or this file when used standalone) must be loaded before the function is called
        $Module = $ExecutionContext.SessionState.Module

        If ($Null -ne $Module) {

            $ManifestPath = Join-Path -Path $Module.ModuleBase -ChildPath "$($Module.Name).psd1"
            $LoadPath = If (Test-Path -Path $ManifestPath) { $ManifestPath } Else { $Module.Path }
            $LoadCommand = "Import-Module -Name '$LoadPath'"

        }

        Else {

            $LoadPath = $PSCommandPath
            $LoadCommand = ". '$LoadPath'"

        }

        $Command = "$LoadCommand; Update-CrlDateTimeStamp -DelaySeconds 5"
        $Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command `"$Command`""
        $Action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $Arguments

        # Event trigger for CRL publication (security event 4872)
        $Subscription = @'
<QueryList><Query Id="0" Path="Security"><Select Path="Security">*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and EventID=4872]]</Select></Query></QueryList>
'@

        $TriggerClass = Get-CimClass -ClassName MSFT_TaskEventTrigger -Namespace Root/Microsoft/Windows/TaskScheduler
        $EventTrigger = New-CimInstance -CimClass $TriggerClass -ClientOnly
        $EventTrigger.Subscription = $Subscription
        $EventTrigger.Enabled = $true

        # Daily trigger as a safety net
        $DailyTrigger = New-ScheduledTaskTrigger -Daily -At '3:00AM'

        $Principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $Settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -StartWhenAvailable

        If ($PSCmdlet.ShouldProcess($Name, 'Register scheduled task')) {

            Register-ScheduledTask -TaskName $Name -Action $Action -Trigger @($EventTrigger, $DailyTrigger) -Principal $Principal -Settings $Settings -Description 'Sets the timestamp of published CRL files to the CRL ThisUpdate value so ETags match across load-balanced web servers.' -Force | Out-Null
            Write-Verbose "Registered scheduled task '$Name' loading '$LoadPath'."

        }

    }

    # Register scheduled task and exit
    If ($PSCmdlet.ParameterSetName -eq 'Register') {

        Register-CrlTimestampTask -Name $TaskName
        Return

    }

    $Results = [System.Collections.Generic.List[PSCustomObject]]::new()

    Try {

        # Wait for the CA to finish writing files when triggered by an event
        If ($DelaySeconds -gt 0) {

            Write-Verbose "Waiting $DelaySeconds seconds before processing."
            Start-Sleep -Seconds $DelaySeconds

        }

        # Determine locations to process
        If ($PSBoundParameters.ContainsKey('Path')) {

            $Locations = $Path

        }

        Else {

            $Locations = @(Get-CrlPublicationFolder | Select-Object -Unique)

        }

        If ($Locations.Count -eq 0) {

            Throw 'No CRL publication locations were found.'

        }

        # Collect CRL files
        $CrlFiles = ForEach ($Location in $Locations) {

            If (-Not (Test-Path -Path $Location)) {

                Write-CrlTimestampWarning "Location '$Location' is not accessible."
                Continue

            }

            $Item = Get-Item -Path $Location

            If ($Item.PSIsContainer) {

                Get-ChildItem -Path $Location -Filter '*.crl' -File

            }

            Else {

                $Item

            }

        }

        If (-Not $CrlFiles) {

            Write-CrlTimestampWarning 'No CRL files were found.'

        }

        # Process each CRL file
        ForEach ($File in ($CrlFiles | Sort-Object -Property FullName -Unique)) {

            $Result = [PSCustomObject]@{

                Path                     = $File.FullName
                ThisUpdate               = $null
                PreviousLastWriteTimeUtc = $File.LastWriteTimeUtc
                Result                   = $null

            }

            $Attempt = 0

            While ($true) {

                Try {

                    $ThisUpdate = Get-CrlThisUpdate -FilePath $File.FullName
                    $Result.ThisUpdate = $ThisUpdate

                    If ($File.LastWriteTimeUtc -eq $ThisUpdate -and $File.CreationTimeUtc -eq $ThisUpdate) {

                        Write-Verbose "'$($File.FullName)' already has timestamp $($ThisUpdate.ToString('u'))."
                        $Result.Result = 'Unchanged'

                    }

                    ElseIf ($PSCmdlet.ShouldProcess($File.FullName, "Set timestamp to $($ThisUpdate.ToString('u'))")) {

                        $File.LastWriteTimeUtc = $ThisUpdate
                        $File.CreationTimeUtc = $ThisUpdate
                        Write-Verbose "'$($File.FullName)' timestamp set to $($ThisUpdate.ToString('u'))."
                        $Result.Result = 'Updated'

                    }

                    Else {

                        $Result.Result = 'Skipped'

                    }

                    Break

                }

                Catch [System.IO.IOException] {

                    $Attempt++

                    If ($Attempt -gt $RetryCount) {

                        Write-CrlTimestampWarning "Unable to update '$($File.FullName)' after $RetryCount retries. $($_.Exception.Message)"
                        $Result.Result = 'Failed'
                        Break

                    }

                    Write-Verbose "'$($File.FullName)' is in use. Retrying in $RetryDelaySeconds seconds (attempt $Attempt of $RetryCount)."
                    Start-Sleep -Seconds $RetryDelaySeconds

                }

                Catch {

                    Write-CrlTimestampWarning "Unable to update '$($File.FullName)'. $($_.Exception.Message)"
                    $Result.Result = 'Failed'
                    Break

                }

            }

            $Results.Add($Result)
            Write-Output $Result

        }

    }

    Catch {

        Write-CrlTimestampEvent -EntryType Error -EventId $EventIdFailed -Message "CRL timestamp update failed.`r`n`r`n$($_.Exception.Message)"
        Throw

    }

    # Write run summary to the event log
    $Updated = @($Results | Where-Object { $_.Result -eq 'Updated' })
    $Unchanged = @($Results | Where-Object { $_.Result -eq 'Unchanged' })
    $Failed = @($Results | Where-Object { $_.Result -eq 'Failed' })

    $Summary = [System.Collections.Generic.List[string]]::new()
    $Summary.Add('CRL timestamp update completed.')
    $Summary.Add('')
    $Summary.Add('Locations:')
    $Locations | ForEach-Object { $Summary.Add("  $_") }
    $Summary.Add('')
    $Summary.Add("Updated: $($Updated.Count)")
    $Updated | ForEach-Object { $Summary.Add("  $($_.Path) ($($_.ThisUpdate.ToString('u')))") }
    $Summary.Add('')
    $Summary.Add("Unchanged: $($Unchanged.Count)")
    $Unchanged | ForEach-Object { $Summary.Add("  $($_.Path)") }

    If ($Failed.Count -gt 0) {

        $Summary.Add('')
        $Summary.Add("Failed: $($Failed.Count)")
        $Failed | ForEach-Object { $Summary.Add("  $($_.Path)") }

    }

    If ($Issues.Count -gt 0) {

        $Summary.Add('')
        $Summary.Add('Warnings:')
        $Issues | ForEach-Object { $Summary.Add("  $_") }

    }

    If ($Failed.Count -gt 0 -or $Issues.Count -gt 0) {

        Write-CrlTimestampEvent -EntryType Warning -EventId $EventIdCompletedWithWarnings -Message ($Summary -join "`r`n")

    }

    Else {

        Write-CrlTimestampEvent -EntryType Information -EventId $EventIdCompleted -Message ($Summary -join "`r`n")

    }

}

# SIG # Begin signature block
# MIIk6wYJKoZIhvcNAQcCoIIk3DCCJNgCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC13jiRAEsQJo2P
# /V2tpsSApOqJdjuBccwORammya1wuqCCH6YwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# DjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDnA0uxeiJLam2LCrxjjphS
# s734GViwizNrJieCctJZ6TALBgcqhkjOPQIBBQAERjBEAiBb8wi0ccyKiwLj8V8J
# Fg+x5o0AP3S80zwa6GyCgOw1lQIgGMyGxq7KPeyrMCNPFzGzAn2OPFFhnEMZRdLT
# o5K+OkmhggMmMIIDIgYJKoZIhvcNAQkGMYIDEzCCAw8CAQEwfTBpMQswCQYDVQQG
# EwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0
# IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0Ex
# AhAKgO8YS43xBYLRxHanlXRoMA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkD
# MQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYwOTAyMjMyMjA1WjAvBgkq
# hkiG9w0BCQQxIgQgqj8kCV1ieHVxG7SXRZJumjhO7NuXdtNdc93Sr5V7Yl8wDQYJ
# KoZIhvcNAQEBBQAEggIAV+hEhOZXHYdirIpBn25h56hP9mRG16904fAsWi2jFImX
# qWS0T8QmleNAG022dttptRgRbw6J9aAgO9s4p1WwDvuEjfGeX1ldrBJbJcyD5HnG
# Ouse6oDOSnzWmj++FUiMHAU114z9e2rL39wnxLaAn+/nzztr+60Lk5mywhmbuFUe
# OHI4pTuQRqQpF49siiBCYrhXDH+xnJ92XWeZFThwxWUlBoecDu4qK3HJ2AamAmfF
# /QtPFh+jakZingBoxozzk0vi5E90PNF+bsOS7bVNhp5wYXsBi2mnIi6OBCm3LmU+
# /WatuaVMOaS4IBYfglhXbusgqTh0VdEJLhAvUJRe3Ab0yBZ6Gywt6aYP1Kd1XNIi
# //5D/Xg8B1R7thAOz4pqHcziuIN14788OJKNMaMwgCoOWweq2lxdnlKdVg34ER4S
# H+/pbGLj89Gmt5jjmUTuRKRRYM2g4lw7DhsuqCzxu+ML1LrLgGi1wV3GEpWlyn1+
# 26jujxFMZIOkqGLnILneiZ3WZ9Ab9j1HSNWvRBWfPHQSUwF+FI7av9RNfQo6LCt+
# +XbJmLYbVSvp1AEIgEfHXqsFWxqRbRVcv3h8fXYv4FgwSIH6Fkv3mRRqp9tjY5co
# dJohh5C8iTFM1ZdkAZr2w6Hl7HwsMo8guZ/SR5Tc3dGrpGx1vm8xAhvj2yhLinU=
# SIG # End signature block
