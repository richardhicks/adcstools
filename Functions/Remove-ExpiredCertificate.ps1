<#

.SYNOPSIS
    Delete expired certificates from the CA server database.

.PARAMETER State
    This parameter defines what type of certificate record to delete - Denied, Failed, Issued, or Revoked.

.PARAMETER Template
    The Object Identifier (OID) of a specific certificate template to delete database records for. Use Get-ADCertificateTemplate to retrieve the OID of a published certificate template.

.PARAMETER Date
    Database records older than this date will be deleted.

.PARAMETER Delete
    Use this switch to delete records from the CA database. If this switch is not present, the script only displays records that will be deleted, if any.

.PARAMETER LogFilePath
    Specifies the location to store CA maintenance log files. The default location is C:\Users\<username>\AppData\Local\Temp\.

.PARAMETER CompressDatabase
    Use this switch to compress the CA database after performing maintenance (recommended).

.EXAMPLE
    Remove-ExpiredCertificate -State Denied

    Displays all expired Denied certificates. Does not delete any records.

.EXAMPLE
    Remove-ExpiredCertificate -State Failed -Delete

    Deletes all expired Failed certificates.

.EXAMPLE
    Remove-ExpiredCertificate -State Issued -Template '1.3.6.1.4.1.311.21.8.8823763.7881424.11597667.39223303.50834909.808.1387547.7582140'

    Displays all expired Issued certificates based on the specified certificate template OID. Does not delete any records.

.EXAMPLE
    Remove-ExpiredCertificate -State Revoked -Date 12/31/2022 -Delete -CompressDatabase

    Deletes all expired Revoked certificates prior to December 31, 2022 and compresses the CA database.

.DESCRIPTION
    Use this command to remove expired certificates from a CA server, and optionally compress the CA database after performing maintenance.

.LINK
    https://github.com/richardhicks/adcstools/blob/main/Functions/Remove-ExpiredCertificate.ps1

.LINK
    https://vanbrenk.blogspot.com/2020/12/how-to-cleanup-expired-certificates.html

.LINK
    https://www.richardhicks.com/

.NOTES
    Version:            1.4
    Creation Date:      January 18, 2020
    Last Updated:       February 14, 2026
    Special Note:       This script adapted from original published guidance by Andre Gibel
    Original Author:    Andre Gibel
    Original Script:    https://vanbrenk.blogspot.com/2020/12/how-to-cleanup-expired-certificates.html
    Author:             Richard Hicks
    Organization:       Richard M. Hicks Consulting, Inc.
    Contact:            rich@richardhicks.com
    Website:            https://www.richardhicks.com/

#>

Function Remove-ExpiredCertificate {

    [CmdletBinding(SupportsShouldProcess)]

    Param (

        [Parameter(Mandatory)]
        [ValidateSet('Denied', 'Failed', 'Issued', 'Revoked')]
        [String]$State,
        [ValidatePattern('^([0-9\.\s])+$')]
        [String]$Template,
        [ValidatePattern('^(0?[1-9]|1[0-2])/(0?[1-9]|[12][0-9]|3[01])/([0-9]{4})$')]
        [String]$Date = (Get-Date -Format M/d/yyyy),
        [Switch]$Delete,
        [String]$LogFilePath = $env:temp,
        [Alias('Compress')]
        [Switch]$CompressDatabase

    )

    # Ensure date input is no later than today when viewing or deleting Issued certificates
    If ($State -eq 'Issued' -And (Get-Date $Date) -gt (Get-Date)) {

        Write-Warning 'The date specified is in the future. Please specify a date no later than today when viewing or deleting Issued certificates.'
        Return

    }

    $Pathmid = ''
    $DateFilterField = ''

    Switch ($State) {

        'Issued' {

            $Pathmid = 'Issued'
            $Disposition = '20'
            $DateFilterField = 'NotAfter'

        }

        'Revoked' {

            $Pathmid = 'Revoked'
            $Disposition = '21'
            $DateFilterField = 'NotAfter'

        }

        'Failed' {

            $Pathmid = 'Failed'
            $Disposition = '30'
            $DateFilterField = 'Request.SubmittedWhen'

        }

        'Denied' {

            $Pathmid = 'Denied'
            $Disposition = '31'
            $DateFilterField = 'Request.SubmittedWhen'

        }

    }

    Write-Verbose "`$Pathmid = $Pathmid"
    Write-Verbose "`$Date = $Date"
    Write-Verbose "`$Disposition = $Disposition"

    # Path of temporary file needed for further parsing (regular expression)
    # Folder structure is automatically created if it doesn't exist
    If (-Not (Test-Path $LogFilePath )) {

        New-Item -Path $LogFilePath -ItemType Directory | Out-Null

    }

    If (-Not (Test-Path "$LogFilePath\$Pathmid" )) {

        New-Item -Path $LogFilePath\$Pathmid -ItemType Directory | Out-Null

    }

    If ($Delete) {

        $CertLogFilePath = Join-Path -Path $LogFilePath -ChildPath "$Pathmid\RequestID-$Pathmid-$($Date -Replace '[\./-]', '').txt"

    }

    Else {

        Write-Warning "'Remove-ExpiredCertificates' is in view only mode. Use the -Delete parameter to delete CA database entries."
        $CertLogFilePath = Join-Path -Path $LogFilePath -ChildPath "$Pathmid\RequestID-$Pathmid-ViewOnly-$($Date -Replace '[\./-]', '').txt"

    }

    Write-Output "Log file path is $CertLogFilePath."
    Write-Verbose 'Executing the following command...'

    If ($PSBoundParameters['Template']) {

        # Select certificates matching a specific template
        Write-Verbose "Query: certutil.exe -view -restrict 'Certificate Template=$Template,Disposition=$Disposition,$DateFilterField<=$Date' -Out 'Request.RequestID,Request.RequesterName,Request.SubmittedWhen,NotBefore,NotAfter,Request.Disposition'"
        Invoke-Command -ScriptBlock { certutil.exe -view -restrict "Certificate Template=$Template,Disposition=$Disposition,$DateFilterField<=$Date" -Out 'Request.RequestID,Request.RequesterName,Request.SubmittedWhen,NotBefore,NotAfter,Request.Disposition' | Out-File $CertLogFilePath }

    }

    Else {

        # Select certificates matching any template
        Write-Verbose "Query: certutil.exe -view -restrict 'Disposition=$Disposition,$DateFilterField<=$Date' -Out 'Request.RequestID,Request.RequesterName,Request.SubmittedWhen,NotBefore,NotAfter,Request.Disposition'"
        Invoke-Command -ScriptBlock { certutil.exe -view -restrict "Disposition=$Disposition,$DateFilterField<=$Date" -Out 'Request.RequestID,Request.RequesterName,Request.SubmittedWhen,NotBefore,NotAfter,Request.Disposition' | Out-File $CertLogFilePath }

    }

    Write-Verbose 'Processing temporary file...'
    $MatchingRequestIDCollection = (Select-String -Path $CertLogFilePath -SimpleMatch "Request ID:" | Select-Object line)

    If ($Null -eq $MatchingRequestIDCollection) {

        Write-Warning 'No entries to delete from the CA database.'
        Break

    }

    Else {

        Write-Output "Number of entries to delete from CA database: $($MatchingRequestIDCollection.Count)."

    }

    # Delete expired certificates
    $EntryDeletedCount = 0

    # Filter out the HEX part of "Request ID: 0xb (11)"  => "0xb"
    $MatchingRequestIDCollection | ForEach-Object {

        $ReqIDHex = $_.Line -Replace "(\s*Request\sID\:\s)(0x[a-f|0-9]+)(.*)", '$2'

        Try {

            $IDDec = [int]$ReqIDHex
            If ($Delete) {

                Write-Output "Executing command: `"certutil.exe -deleterow $ReqIDHex`" (Request ID $IDDec)"
                & certutil.exe -deleterow $ReqIDHex

            }

            $EntryDeletedCount ++

        }

        Catch {

            Write-Output 'Error deleting CA database record.'

        }

    }

    If ($Delete) {

        Write-Output "Number of deleted records: $EntryDeletedCount."

    }

    If ($CompressDatabase) {

        # Identify CA database location
        Write-Verbose 'Identifying certificate services database location...'

        Try {

            $DbFolder = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration' -Name DBDirectory -ErrorAction Stop | Select-Object -ExpandProperty DBDirectory
            $DbName = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration' -Name Active -ErrorAction Stop | Select-Object -ExpandProperty Active
            $DbPath = Join-Path -Path $DbFolder -ChildPath "$DbName.edb"

        }

        Catch {

            Write-Warning "Failed to identify the Certificate Services database location. $_"
            Return

        }

        Write-Verbose "The Certificate Services database location is `"$DbPath`"."

        # Stop certificate services service
        Write-Verbose 'Stopping the Certificate Services service...'

        Try {

            Stop-Service -Name CertSvc -ErrorAction Stop

        }

        Catch {

            Write-Warning "Failed to stop the Certificate Services service. $_"
            Return

        }

        # Compress certificate services database
        Write-Verbose 'Compressing the Certificate Services database...'

        Try {

            Invoke-Command -ScriptBlock { esentutl.exe /d $DbPath }

            If ($LASTEXITCODE -ne 0) {

                Write-Warning "Database compression completed with exit code $LASTEXITCODE."

            }

        }

        Catch {

            Write-Warning "Failed to compress the Certificate Services database. $_"

        }

        # Start certificate services service
        Write-Verbose 'Starting the Certificate Services service...'

        Try {

            Start-Service -Name CertSvc -ErrorAction Stop

        }

        Catch {

            Write-Warning "Failed to start the Certificate Services service. $_"
            Return

        }

    }

}

# SIG # Begin signature block
# MIIf2gYJKoZIhvcNAQcCoIIfyzCCH8cCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDhZN4Y1btlyHuy
# c+P8SuULT6E4zKotWtIsKmqC/fSb6KCCGpkwggNZMIIC36ADAgECAhAPuKdAuRWN
# A1FDvFnZ8EApMAoGCCqGSM49BAMDMGExCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxE
# aWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xIDAeBgNVBAMT
# F0RpZ2lDZXJ0IEdsb2JhbCBSb290IEczMB4XDTIxMDQyOTAwMDAwMFoXDTM2MDQy
# ODIzNTk1OVowZDELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMu
# MTwwOgYDVQQDEzNEaWdpQ2VydCBHbG9iYWwgRzMgQ29kZSBTaWduaW5nIEVDQyBT
# SEEzODQgMjAyMSBDQTEwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAS7tKwnpUgNolNf
# jy6BPi9TdrgIlKKaqoqLmLWx8PwqFbu5s6UiL/1qwL3iVWhga5c0wWZTcSP8GtXK
# IA8CQKKjSlpGo5FTK5XyA+mrptOHdi/nZJ+eNVH8w2M1eHbk+HejggFXMIIBUzAS
# BgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBSbX7A2up0GrhknvcCgIsCLizh3
# 7TAfBgNVHSMEGDAWgBSz20ik+aHF2K42QcwRY2liKbxLxjAOBgNVHQ8BAf8EBAMC
# AYYwEwYDVR0lBAwwCgYIKwYBBQUHAwMwdgYIKwYBBQUHAQEEajBoMCQGCCsGAQUF
# BzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQAYIKwYBBQUHMAKGNGh0dHA6
# Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbFJvb3RHMy5jcnQw
# QgYDVR0fBDswOTA3oDWgM4YxaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lD
# ZXJ0R2xvYmFsUm9vdEczLmNybDAcBgNVHSAEFTATMAcGBWeBDAEDMAgGBmeBDAEE
# ATAKBggqhkjOPQQDAwNoADBlAjB4vUmVZXEB0EZXaGUOaKncNgjB7v3UjttAZT8N
# /5Ovwq5jhqN+y7SRWnjsBwNnB3wCMQDnnx/xB1usNMY4vLWlUM7m6jh+PnmQ5KRb
# qwIN6Af8VqZait2zULLd8vpmdJ7QFmMwggP+MIIDhKADAgECAhANSjTahpCPwBMs
# vIE3k68kMAoGCCqGSM49BAMDMGQxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdp
# Q2VydCwgSW5jLjE8MDoGA1UEAxMzRGlnaUNlcnQgR2xvYmFsIEczIENvZGUgU2ln
# bmluZyBFQ0MgU0hBMzg0IDIwMjEgQ0ExMB4XDTI0MTIwNjAwMDAwMFoXDTI3MTIy
# NDIzNTk1OVowgYYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYw
# FAYDVQQHEw1NaXNzaW9uIFZpZWpvMSQwIgYDVQQKExtSaWNoYXJkIE0uIEhpY2tz
# IENvbnN1bHRpbmcxJDAiBgNVBAMTG1JpY2hhcmQgTS4gSGlja3MgQ29uc3VsdGlu
# ZzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABFCbtcqpc7vGGM4hVM79U+7f0tKz
# o8BAGMJ/0E7JUwKJfyMJj9jsCNpp61+mBNdTwirEm/K0Vz02vak0Ftcb/3yjggHz
# MIIB7zAfBgNVHSMEGDAWgBSbX7A2up0GrhknvcCgIsCLizh37TAdBgNVHQ4EFgQU
# KIMkVkfISNUyQJ7bwvLm9sCIkxgwPgYDVR0gBDcwNTAzBgZngQwBBAEwKTAnBggr
# BgEFBQcCARYbaHR0cDovL3d3dy5kaWdpY2VydC5jb20vQ1BTMA4GA1UdDwEB/wQE
# AwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzCBqwYDVR0fBIGjMIGgME6gTKBKhkho
# dHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRHbG9iYWxHM0NvZGVTaWdu
# aW5nRUNDU0hBMzg0MjAyMUNBMS5jcmwwTqBMoEqGSGh0dHA6Ly9jcmw0LmRpZ2lj
# ZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbEczQ29kZVNpZ25pbmdFQ0NTSEEzODQyMDIx
# Q0ExLmNybDCBjgYIKwYBBQUHAQEEgYEwfzAkBggrBgEFBQcwAYYYaHR0cDovL29j
# c3AuZGlnaWNlcnQuY29tMFcGCCsGAQUFBzAChktodHRwOi8vY2FjZXJ0cy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRHbG9iYWxHM0NvZGVTaWduaW5nRUNDU0hBMzg0MjAy
# MUNBMS5jcnQwCQYDVR0TBAIwADAKBggqhkjOPQQDAwNoADBlAjBMOsBb80qx6E6S
# 2lnnHafuyY2paoDtPjcfddKaB1HKnAy7WLaEVc78xAC84iW3l6ECMQDhOPD5JHtw
# YxEH6DxVDle5pLKfuyQHiY1i0I9PrSn1plPUeZDTnYKmms1P66nBvCkwggWNMIIE
# daADAgECAhAOmxiO+dAt5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNV
# BAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdp
# Y2VydC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAe
# Fw0yMjA4MDEwMDAwMDBaFw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUw
# EwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20x
# ITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcN
# AQEBBQADggIPADCCAgoCggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC
# 4SmnPVirdprNrnsbhA3EMB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWl
# fr6fqVcWWVVyr2iTcMKyunWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1j
# KS3O7F5OyJP4IWGbNOsFxl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dP
# pzDZVu7Ke13jrclPXuU15zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3
# pC4FfYj1gj4QkXCrVYJBMtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJ
# pMLmqaBn3aQnvKFPObURWBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aa
# dMreSx7nDmOu5tTvkpI6nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXD
# j/chsrIRt7t/8tWMcCxBYKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB
# 4Q+UDCEdslQpJYls5Q5SUUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ
# 33xMdT9j7CFfxCBRa2+xq4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amy
# HeUbAgMBAAGjggE6MIIBNjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC
# 0nFdZEzfLmc/57qYrhwPTzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823I
# DzAOBgNVHQ8BAf8EBAMCAYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhho
# dHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNl
# cnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYD
# VR0fBD4wPDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0
# QXNzdXJlZElEUm9vdENBLmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcN
# AQEMBQADggEBAHCgv0NcVec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxpp
# VCLtpIh3bb0aFPQTSnovLbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6
# mouyXtTP0UNEm0Mh65ZyoUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPH
# h6jSTEAZNUZqaVSwuKFWjuyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCN
# NWAcAgPLILCsWKAOQGPFmCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg6
# 2fC2h5b9W9FcrBjDTZ9ztwGpn1eqXijiuZQwgga0MIIEnKADAgECAhANx6xXBf8h
# mS5AQyIMOkmGMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNV
# BAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yNTA1MDcwMDAwMDBaFw0z
# ODAxMTQyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
# ggIKAoICAQC0eDHTCphBcr48RsAcrHXbo0ZodLRRF51NrY0NlLWZloMsVO1DahGP
# NRcybEKq+RuwOnPhof6pvF4uGjwjqNjfEvUi6wuim5bap+0lgloM2zX4kftn5B1I
# pYzTqpyFQ/4Bt0mAxAHeHYNnQxqXmRinvuNgxVBdJkf77S2uPoCj7GH8BLuxBG5A
# vftBdsOECS1UkxBvMgEdgkFiDNYiOTx4OtiFcMSkqTtF2hfQz3zQSku2Ws3IfDRe
# b6e3mmdglTcaarps0wjUjsZvkgFkriK9tUKJm/s80FiocSk1VYLZlDwFt+cVFBUR
# Jg6zMUjZa/zbCclF83bRVFLeGkuAhHiGPMvSGmhgaTzVyhYn4p0+8y9oHRaQT/ao
# fEnS5xLrfxnGpTXiUOeSLsJygoLPp66bkDX1ZlAeSpQl92QOMeRxykvq6gbylsXQ
# skBBBnGy3tW/AMOMCZIVNSaz7BX8VtYGqLt9MmeOreGPRdtBx3yGOP+rx3rKWDEJ
# lIqLXvJWnY0v5ydPpOjL6s36czwzsucuoKs7Yk/ehb//Wx+5kMqIMRvUBDx6z1ev
# +7psNOdgJMoiwOrUG2ZdSoQbU2rMkpLiQ6bGRinZbI4OLu9BMIFm1UUl9VnePs6B
# aaeEWvjJSjNm2qA+sdFUeEY0qVjPKOWug/G6X5uAiynM7Bu2ayBjUwIDAQABo4IB
# XTCCAVkwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU729TSunkBnx6yuKQ
# VvYv1Ensy04wHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0P
# AQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAk
# BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAC
# hjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9v
# dEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEE
# AjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggIBABfO+xaAHP4HPRF2cTC9
# vgvItTSmf83Qh8WIGjB/T8ObXAZz8OjuhUxjaaFdleMM0lBryPTQM2qEJPe36zwb
# SI/mS83afsl3YTj+IQhQE7jU/kXjjytJgnn0hvrV6hqWGd3rLAUt6vJy9lMDPjTL
# xLgXf9r5nWMQwr8Myb9rEVKChHyfpzee5kH0F8HABBgr0UdqirZ7bowe9Vj2AIMD
# 8liyrukZ2iA/wdG2th9y1IsA0QF8dTXqvcnTmpfeQh35k5zOCPmSNq1UH410ANVk
# o43+Cdmu4y81hjajV/gxdEkMx1NKU4uHQcKfZxAvBAKqMVuqte69M9J6A47OvgRa
# Ps+2ykgcGV00TYr2Lr3ty9qIijanrUR3anzEwlvzZiiyfTPjLbnFRsjsYg39OlV8
# cipDoq7+qNNjqFzeGxcytL5TTLL4ZaoBdqbhOhZ3ZRDUphPvSRmMThi0vw9vODRz
# W6AxnJll38F0cuJG7uEBYTptMSbhdhGQDpOXgpIUsWTjd6xpR6oaQf/DJbg3s6KC
# LPAlZ66RzIg9sC+NJpud/v4+7RWsWCiKi9EOLLHfMR2ZyJ/+xhCx9yHbxtl5TPau
# 1j/1MIDpMPx0LckTetiSuEtQvLsNz3Qbp7wGWqbIiOWCnb5WqxL3/BAPvIXKUjPS
# xyZsq8WhbaM2tszWkPZPubdcMIIG7TCCBNWgAwIBAgIQCoDvGEuN8QWC0cR2p5V0
# aDANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNl
# cnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1w
# aW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMB4XDTI1MDYwNDAwMDAwMFoXDTM2
# MDkwMzIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJ
# bmMuMTswOQYDVQQDEzJEaWdpQ2VydCBTSEEyNTYgUlNBNDA5NiBUaW1lc3RhbXAg
# UmVzcG9uZGVyIDIwMjUgMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
# ANBGrC0Sxp7Q6q5gVrMrV7pvUf+GcAoB38o3zBlCMGMyqJnfFNZx+wvA69HFTBdw
# bHwBSOeLpvPnZ8ZN+vo8dE2/pPvOx/Vj8TchTySA2R4QKpVD7dvNZh6wW2R6kSu9
# RJt/4QhguSssp3qome7MrxVyfQO9sMx6ZAWjFDYOzDi8SOhPUWlLnh00Cll8pjrU
# cCV3K3E0zz09ldQ//nBZZREr4h/GI6Dxb2UoyrN0ijtUDVHRXdmncOOMA3CoB/iU
# SROUINDT98oksouTMYFOnHoRh6+86Ltc5zjPKHW5KqCvpSduSwhwUmotuQhcg9tw
# 2YD3w6ySSSu+3qU8DD+nigNJFmt6LAHvH3KSuNLoZLc1Hf2JNMVL4Q1OpbybpMe4
# 6YceNA0LfNsnqcnpJeItK/DhKbPxTTuGoX7wJNdoRORVbPR1VVnDuSeHVZlc4seA
# O+6d2sC26/PQPdP51ho1zBp+xUIZkpSFA8vWdoUoHLWnqWU3dCCyFG1roSrgHjSH
# lq8xymLnjCbSLZ49kPmk8iyyizNDIXj//cOgrY7rlRyTlaCCfw7aSUROwnu7zER6
# EaJ+AliL7ojTdS5PWPsWeupWs7NpChUk555K096V1hE0yZIXe+giAwW00aHzrDch
# Ic2bQhpp0IoKRR7YufAkprxMiXAJQ1XCmnCfgPf8+3mnAgMBAAGjggGVMIIBkTAM
# BgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTkO/zyMe39/dfzkXFjGVBDz2GM6DAfBgNV
# HSMEGDAWgBTvb1NK6eQGfHrK4pBW9i/USezLTjAOBgNVHQ8BAf8EBAMCB4AwFgYD
# VR0lAQH/BAwwCgYIKwYBBQUHAwgwgZUGCCsGAQUFBwEBBIGIMIGFMCQGCCsGAQUF
# BzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXQYIKwYBBQUHMAKGUWh0dHA6
# Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFt
# cGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNydDBfBgNVHR8EWDBWMFSgUqBQhk5o
# dHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3Rh
# bXBpbmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5jcmwwIAYDVR0gBBkwFzAIBgZngQwB
# BAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQBlKq3xHCcEua5gQezR
# CESeY0ByIfjk9iJP2zWLpQq1b4URGnwWBdEZD9gBq9fNaNmFj6Eh8/YmRDfxT7C0
# k8FUFqNh+tshgb4O6Lgjg8K8elC4+oWCqnU/ML9lFfim8/9yJmZSe2F8AQ/UdKFO
# tj7YMTmqPO9mzskgiC3QYIUP2S3HQvHG1FDu+WUqW4daIqToXFE/JQ/EABgfZXLW
# U0ziTN6R3ygQBHMUBaB5bdrPbF6MRYs03h4obEMnxYOX8VBRKe1uNnzQVTeLni2n
# HkX/QqvXnNb+YkDFkxUGtMTaiLR9wjxUxu2hECZpqyU1d0IbX6Wq8/gVutDojBIF
# eRlqAcuEVT0cKsb+zJNEsuEB7O7/cuvTQasnM9AWcIQfVjnzrvwiCZ85EE8LUkqR
# hoS3Y50OHgaY7T/lwd6UArb+BOVAkg2oOvol/DJgddJ35XTxfUlQ+8Hggt8l2Yv7
# roancJIFcbojBcxlRcGG0LIhp6GvReQGgMgYxQbV1S3CrWqZzBt1R9xJgKf47Cdx
# VRd/ndUlQ05oxYy2zRWVFjF7mcr4C34Mj3ocCVccAvlKV9jEnstrniLvUxxVZE/r
# ptb7IRE2lskKPIJgbaP5t2nGj/ULLi49xTcBZU8atufk+EMF/cWuiC7POGT75qaL
# 6vdCvHlshtjdNXOCIUjsarfNZzGCBJcwggSTAgEBMHgwZDELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTwwOgYDVQQDEzNEaWdpQ2VydCBHbG9i
# YWwgRzMgQ29kZSBTaWduaW5nIEVDQyBTSEEzODQgMjAyMSBDQTECEA1KNNqGkI/A
# Eyy8gTeTryQwDQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAA
# oQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4w
# DAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgyoXDeJbqH00Ok4e7H03rEscp
# 5oIX4uBaqGW1eXILFt8wCwYHKoZIzj0CAQUABEcwRQIhAP0PJl3IOjNyXrVArLfJ
# 6MLjKZNOz2Er/YSUDsZ81B6cAiA/mJ/lgDVzRJ3UNuxPNCkkK9jsd+J5nDI2wuen
# x8l25aGCAyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYT
# AlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQg
# VHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEC
# EAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMx
# CwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjAyMTQyMTUyMTVaMC8GCSqG
# SIb3DQEJBDEiBCAjVrfIh6Ghj+kByYyPoZ3tncFxVMxTp5Fnp8OivAskBDANBgkq
# hkiG9w0BAQEFAASCAgBRuXFJKM2TfINht/nhSq18RubtP35rYqcwqqiehKJ4x7IB
# 6+zegw73Uw6vd308obOncZOiDoFjjrwDh0eQF/VZZlGEj1aLzdXIybWwX86d0Vw3
# 0JjgC748Hs1bwMTad+2KMOR7dV8wMFzDp1eS8Xf4NA9qMDO3KdfQfdySOKQtFJeT
# OI2X/zWxYz77D0It8tbpSCfFq6+d68TvbnGE4LVmhhwwQovvO1bgMwsFey6yNDjd
# DAEU9WtvZjzp8SMiZuT6RWBeoyDbVJkFO7Z8sP1rv/KnuhRTs3HK+4Rzsm7pS1K+
# P7SgNoq0cGLuBj26x9p5J35kja229dTCxtCpwFO13iwYXDvrpRdkEi6RiEJtk/Zt
# 1BqfnCNVuyGn2hwWy0zXgF18VqoeLMkcuJG5QLv9XhaUrR8fR6ZEI5+ICUMZzmsm
# nG4R3zzkFJocKRwWHZ9kqSH3DGFcpqXCK9IgDXJuETxiDmZzhEDD54VikFj6vuTQ
# K1tAPSLJc6CL1gnyneK4GylzHltpsW/OBkpZl3WbGnKVpfdTDdkJKfsLCwWtSjs5
# JZr1TrFJhPOIhL00nqQBCXv0xw/rmY0ccs1kEFoNZ5bG39Duf03qupn5HpKaxzYz
# YThCvtPmKbeiKJqkuXQTWxAgiyq26Mgwr9LOW3ftsmqMNCIWCikov6hSbmxgUQ==
# SIG # End signature block
