function Get-SilverTicketDetection {
    <#
        .SYNOPSIS
            Detects Silver Ticket attack indicators by correlating service logons, Kerberos requests, and service account risk.

        .DESCRIPTION
            Performs a five-phase Silver Ticket detection audit:
            1) Service account security audit (SPN accounts, password age, privilege risk, encryption posture).
            2) Correlation of Event ID 4624 logons without matching Event ID 4769 service ticket requests.
            3) Event ID 4769 anomaly analysis (deleted users, RC4 downgrade, PAC validation failures).
            4) Computer account misuse detection and stale computer password analysis.
            5) Behavioral baseline advisory summary.

            The function returns structured output and optionally exports reports for investigations.

        .PARAMETER TargetServers
            Target servers to analyze. If omitted, servers are auto-discovered from DCs, SQL SPN hosts, and file server patterns.

        .PARAMETER ServiceTypes
            Service SPN prefixes to monitor (for example MSSQLSvc, CIFS, HTTP, LDAP, HOST).

        .PARAMETER Hours
            Number of hours to analyze from current time.

        .PARAMETER ExportPath
            Directory path where CSV reports are exported.

        .PARAMETER IncludeServiceAccountAudit
            Includes full service account audit export and remediation recommendations.

        .PARAMETER BaselineMode
            Baseline learning mode. Detections are analyzed but not promoted as actionable alerts.

        .PARAMETER Remediate
            Opens Silver Ticket remediation guidance URL when critical findings are present.

        .EXAMPLE
            Get-SilverTicketDetection

            Runs full Silver Ticket detection with server auto-discovery for the last 24 hours.

        .EXAMPLE
            Get-SilverTicketDetection -TargetServers 'SQLPROD01','SQLPROD02' -ServiceTypes 'MSSQLSvc' -Hours 168

            Focused 7-day SQL service Silver Ticket analysis.

        .EXAMPLE
            Get-SilverTicketDetection -BaselineMode -Hours 720 -ExportPath 'C:\Reports'

            Runs 30-day baseline learning mode and exports telemetry reports.

        .INPUTS
            None.

        .OUTPUTS
            [PSCustomObject]

        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Get-FunctionDisplay                    | EguibarIT.SecurityPS
                Import-MyModule                        | EguibarIT.SecurityPS
                Get-ADDomain                           | ActiveDirectory
                Get-ADDomainController                 | ActiveDirectory
                Get-ADComputer                         | ActiveDirectory
                Get-ADUser                             | ActiveDirectory
                Get-WinEvent                           | Microsoft.PowerShell.Diagnostics
                Export-Csv                             | Microsoft.PowerShell.Utility
                Start-Process                          | Microsoft.PowerShell.Management

        .NOTES
            Version:         1.0.0
            DateModified:    03/Mar/2026
            LastModifiedBy:  Vicente Rodriguez Eguibar
                vicente@eguibar.com
                EguibarIT
                http://www.eguibarit.com

        .LINK
            https://attack.mitre.org/techniques/T1558/002/

        .LINK
            https://github.com/vreguibar/EguibarIT.SecurityPS

        .COMPONENT
            EguibarIT.SecurityPS

        .ROLE
            Security Auditing

        .FUNCTIONALITY
            Detects Silver Ticket attack patterns in Kerberos service authentication flows.
    #>

    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'Medium'
    )]
    [OutputType([PSCustomObject])]

    param(
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Servers to analyze for Silver Ticket activity',
            Position = 0
        )]
        [AllowEmptyCollection()]
        [string[]]
        $TargetServers = @(),

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Service SPN prefixes to monitor',
            Position = 1
        )]
        [ValidateNotNullOrEmpty()]
        [PSDefaultValue(Help = 'Default: MSSQLSvc,CIFS,HTTP,LDAP,HOST,TERMSRV')]
        [string[]]
        $ServiceTypes = @('MSSQLSvc', 'CIFS', 'HTTP', 'LDAP', 'HOST', 'TERMSRV'),

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Number of hours to analyze in event logs',
            Position = 2
        )]
        [ValidateRange(1, 720)]
        [PSDefaultValue(Help = 'Default: 24 hours')]
        [int]
        $Hours = 24,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Directory path for CSV report exports',
            Position = 3
        )]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
                if (-not (Test-Path -Path $_ -IsValid)) {
                    throw ('Invalid export path: {0}' -f $_)
                }
                return $true
            })]
        [PSDefaultValue(Help = 'Default: C:\Reports')]
        [string]
        $ExportPath = 'C:\Reports',

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Include service account audit details and remediation recommendations',
            Position = 4
        )]
        [switch]
        $IncludeServiceAccountAudit,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Enable baseline learning mode (reduced alerting mode)',
            Position = 5
        )]
        [switch]
        $BaselineMode,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Open remediation guidance URL when critical findings exist',
            Position = 6
        )]
        [switch]
        $Remediate
    )

    begin {
        Set-StrictMode -Version Latest

        if ($null -ne $Variables -and
            $null -ne $Variables.HeaderSecurity) {

            $txt = ($Variables.HeaderSecurity -f
                (Get-Date).ToString('dd/MMM/yyyy'),
                $MyInvocation.Mycommand,
                (Get-FunctionDisplay -Hashtable $PsBoundParameters -Verbose:$false)
            )
            Write-Verbose -Message $txt
        } #end If

        try {
            Import-MyModule -Name ActiveDirectory -Force -Verbose:$VerbosePreference -ErrorAction Stop
            Write-Verbose -Message 'Active Directory module loaded successfully.'
        } catch {
            Write-Error -Message 'ActiveDirectory module is required. Install RSAT-AD-PowerShell.' -ErrorAction Stop
        } #end try-catch

        [datetime]$ScanStartTime = (Get-Date).AddHours(-$Hours)
        [datetime]$AuditTimestamp = Get-Date
        [string]$MitreTechnique = 'T1558.002'
        [string]$RemediationUrl = 'https://www.eguibarit.com/security/five-eyes-ad-attacks.html#silver-ticket'

        [System.Collections.ArrayList]$Detections = @()
        [System.Collections.ArrayList]$ServiceAccountAudit = @()
        [System.Collections.ArrayList]$MissingServiceTicket = @()
        [System.Collections.ArrayList]$ServiceTicketAnomalies = @()
        [System.Collections.ArrayList]$ComputerAccountAnomalies = @()
        [System.Collections.ArrayList]$BehaviorAdvisories = @()
        [System.Collections.ArrayList]$ExportedReports = @()

        $Domain = Get-ADDomain -ErrorAction Stop
        [string]$PdcEmulator = $Domain.PDCEmulator

        Write-Verbose -Message ('Analyzing domain {0} for the last {1} hours.' -f $Domain.DNSRoot, $Hours)

        if ($TargetServers.Count -eq 0) {
            Write-Verbose -Message 'Auto-discovering target servers.'

            $Dcs = (Get-ADDomainController -Filter * -ErrorAction Stop | Select-Object -ExpandProperty Name)
            $SqlServers = Get-ADComputer -Filter * -Properties ServicePrincipalName -ErrorAction SilentlyContinue |
                Where-Object { $_.ServicePrincipalName -like '*MSSQLSvc*' } |
                    Select-Object -ExpandProperty Name

            $FileServers = Get-ADComputer -Filter "Name -like '*FILE*' -or Name -like '*FS*'" -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty Name

            $TargetServers = @($Dcs + $SqlServers + $FileServers | Select-Object -Unique)
        } #end If

        Write-Verbose -Message ('Target server count: {0}' -f $TargetServers.Count)
    } #end Begin

    process {
        try {
            Write-Verbose -Message '[Phase 1/5] Auditing service account security posture.'

            $ServiceAccounts = Get-ADUser -Filter * -Properties ServicePrincipalName, PasswordLastSet, PasswordNeverExpires, MemberOf, msDS-SupportedEncryptionTypes -ErrorAction SilentlyContinue |
                Where-Object { $null -ne $_.ServicePrincipalName }

            foreach ($Account in $ServiceAccounts) {
                [int]$DaysOld = if ($Account.PasswordLastSet) {
                    [math]::Round(((Get-Date) - $Account.PasswordLastSet).TotalDays)
                } else {
                    999999
                }

                [bool]$IsGmsa = ($Account.ObjectClass -eq 'msDS-GroupManagedServiceAccount')
                [bool]$IsDomainAdmin = $Account.MemberOf -match 'CN=Domain Admins'
                [bool]$IsEnterpriseAdmin = $Account.MemberOf -match 'CN=Enterprise Admins'
                [bool]$IsAdministrators = $Account.MemberOf -match 'CN=Administrators'
                [bool]$DangerousGroups = ($IsDomainAdmin -or $IsEnterpriseAdmin -or $IsAdministrators)

                [int]$EncryptionTypes = if ($null -ne $Account.'msDS-SupportedEncryptionTypes') {
                    [int]$Account.'msDS-SupportedEncryptionTypes'
                } else {
                    0
                }
                [bool]$Rc4Enabled = (($EncryptionTypes -band 0x04) -eq 0x04)

                [string]$RiskLevel = if ($DangerousGroups -and $DaysOld -gt 365 -and -not $IsGmsa) {
                    'CRITICAL'
                } elseif ($DaysOld -gt 365 -and -not $IsGmsa) {
                    'HIGH'
                } elseif ($DaysOld -gt 90 -and -not $IsGmsa) {
                    'MEDIUM'
                } else {
                    'LOW'
                }

                [string]$Recommendation = if ($IsGmsa) {
                    'Already using gMSA.'
                } elseif ($DaysOld -gt 180) {
                    'URGENT: migrate to gMSA or rotate password immediately.'
                } elseif ($DaysOld -gt 90) {
                    'Migrate to gMSA within 30 days.'
                } else {
                    'Plan migration to gMSA.'
                }

                [void]$ServiceAccountAudit.Add([PSCustomObject]@{
                        SamAccountName           = $Account.SamAccountName
                        PasswordLastSet          = $Account.PasswordLastSet
                        PasswordAge_Days         = $DaysOld
                        IsGMSA                   = $IsGmsa
                        PasswordNeverExpires     = $Account.PasswordNeverExpires
                        IsDomainAdmin            = $IsDomainAdmin
                        DangerousGroupMembership = $DangerousGroups
                        RC4_Enabled              = $Rc4Enabled
                        RiskLevel                = $RiskLevel
                        SPNs                     = ($Account.ServicePrincipalName -join '; ')
                        Recommendation           = $Recommendation
                    })

                if (($RiskLevel -in @('HIGH', 'CRITICAL')) -and (-not $BaselineMode)) {
                    [void]$Detections.Add([PSCustomObject]@{
                            Timestamp       = Get-Date
                            DetectionType   = 'High-Risk Service Account'
                            Severity        = $RiskLevel
                            Domain          = $Domain.DNSRoot
                            Details         = ('Service account {0}: PasswordAge={1} days, gMSA={2}, DomainAdmin={3}, RC4={4}' -f $Account.SamAccountName, $DaysOld, $IsGmsa, $IsDomainAdmin, $Rc4Enabled)
                            Recommendation  = 'Migrate to gMSA and rotate account password if stale.'
                            MITRE_Technique = $MitreTechnique
                        })
                } #end If
            } #end ForEach

            Write-Verbose -Message '[Phase 2/5] Correlating Event ID 4624 with Event ID 4769 (missing service ticket pattern).'

            [System.Collections.ArrayList]$Event4769 = @()
            $Event4769Query = @{
                LogName   = 'Security'
                Id        = 4769
                StartTime = $ScanStartTime
            }
            $Event4769Raw = Get-WinEvent -ComputerName $PdcEmulator -FilterHashtable $Event4769Query -ErrorAction SilentlyContinue
            foreach ($EventEntry in $Event4769Raw) {
                [void]$Event4769.Add($EventEntry)
            } #end ForEach

            [hashtable]$UsersWithServiceTicket = @{}
            foreach ($EventEntry in $Event4769) {
                $Xml = [xml]$EventEntry.ToXml()
                [string]$UserName = ($Xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
                [string]$ServiceName = ($Xml.Event.EventData.Data | Where-Object { $_.Name -eq 'ServiceName' }).'#text'

                [bool]$MatchesServiceType = $false
                foreach ($SvcType in $ServiceTypes) {
                    if ($ServiceName -like ('{0}*' -f $SvcType)) {
                        $MatchesServiceType = $true
                        break
                    } #end If
                } #end ForEach
                if (-not $MatchesServiceType) {
                    continue
                } #end If

                [string]$TicketKey = ('{0}|{1}' -f $UserName, $ServiceName)
                if (-not $UsersWithServiceTicket.ContainsKey($TicketKey)) {
                    $UsersWithServiceTicket[$TicketKey] = [System.Collections.ArrayList]@()
                } #end If
                [void]$UsersWithServiceTicket[$TicketKey].Add($EventEntry.TimeCreated)
            } #end ForEach

            foreach ($Server in $TargetServers) {
                try {
                    $Event4624Query = @{
                        LogName   = 'Security'
                        Id        = 4624
                        StartTime = $ScanStartTime
                    }

                    $Event4624 = Get-WinEvent -ComputerName $Server -FilterHashtable $Event4624Query -ErrorAction SilentlyContinue |
                        Where-Object {
                            $Xml = [xml]$_.ToXml()
                            $LogonType = ($Xml.Event.EventData.Data | Where-Object { $_.Name -eq 'LogonType' }).'#text'
                            $LogonType -eq '3'
                        }

                    foreach ($LogonEvent in $Event4624) {
                        $Xml = [xml]$LogonEvent.ToXml()
                        [string]$UserName = ($Xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
                        [datetime]$LogonTime = $LogonEvent.TimeCreated
                        [string]$SourceIp = ($Xml.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'

                        if ($UserName -like '*$') {
                            continue
                        } #end If

                        [bool]$TicketFound = $false
                        foreach ($SvcType in $ServiceTypes) {
                            [string]$TicketKey = ('{0}|{1}/{2}' -f $UserName, $SvcType, $Server)
                            if ($UsersWithServiceTicket.ContainsKey($TicketKey)) {
                                foreach ($TicketTime in $UsersWithServiceTicket[$TicketKey]) {
                                    [double]$TimeDiff = ($LogonTime - $TicketTime).TotalMinutes
                                    if ($TimeDiff -ge 0 -and $TimeDiff -le 5) {
                                        $TicketFound = $true
                                        break
                                    } #end If
                                } #end ForEach
                            } #end If
                            if ($TicketFound) {
                                break
                            } #end If
                        } #end ForEach

                        if (-not $TicketFound) {
                            $AdUser = Get-ADUser -Filter { SamAccountName -eq $UserName } -ErrorAction SilentlyContinue
                            [bool]$UserExists = $null -ne $AdUser

                            [string]$Severity = if (-not $UserExists) {
                                'CRITICAL'
                            } else {
                                'HIGH'
                            }

                            [string]$ExpectedService = if ($Server -match 'SQL') {
                                'MSSQLSvc'
                            } elseif ($Server -match 'DC') {
                                'LDAP'
                            } else {
                                'CIFS'
                            }

                            [string]$Details = if (-not $UserExists) {
                                ('Logon to {0} by non-existent user {1} without KDC service ticket request.' -f $Server, $UserName)
                            } else {
                                ('Logon to {0} by {1} without preceding service ticket request.' -f $Server, $UserName)
                            }

                            [void]$MissingServiceTicket.Add([PSCustomObject]@{
                                    Timestamp       = $LogonTime
                                    Server          = $Server
                                    Username        = $UserName
                                    SourceIP        = $SourceIp
                                    ExpectedService = $ExpectedService
                                    UserExists      = $UserExists
                                    Severity        = $Severity
                                    Details         = $Details
                                })
                        } #end If
                    } #end ForEach
                } catch {
                    Write-Warning -Message ('Failed to analyze server {0}: {1}' -f $Server, $_.Exception.Message)
                } #end try-catch
            } #end ForEach

            if (-not $BaselineMode) {
                foreach ($Finding in $MissingServiceTicket) {
                    [string]$Recommendation = if (-not $Finding.UserExists) {
                        ('IMMEDIATE: rotate service account credentials on {0} and investigate source IP {1}.' -f $Finding.Server, $Finding.SourceIP)
                    } else {
                        ('Investigate user {0} and source IP {1} for Silver Ticket abuse.' -f $Finding.Username, $Finding.SourceIP)
                    }

                    [void]$Detections.Add([PSCustomObject]@{
                            Timestamp       = $Finding.Timestamp
                            DetectionType   = 'Missing Service Ticket Request'
                            Severity        = $Finding.Severity
                            Domain          = $Domain.DNSRoot
                            Details         = ('{0} Source: {1}' -f $Finding.Details, $Finding.SourceIP)
                            Recommendation  = $Recommendation
                            MITRE_Technique = $MitreTechnique
                        })
                } #end ForEach
            } #end If

            Write-Verbose -Message '[Phase 3/5] Analyzing Event ID 4769 service ticket anomalies.'

            foreach ($EventEntry in $Event4769) {
                $Xml = [xml]$EventEntry.ToXml()
                $EventData = $Xml.Event.EventData.Data

                [string]$TargetUserName = ($EventData | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
                [string]$ServiceName = ($EventData | Where-Object { $_.Name -eq 'ServiceName' }).'#text'
                [string]$TicketEncryptionType = ($EventData | Where-Object { $_.Name -eq 'TicketEncryptionType' }).'#text'
                [string]$Status = ($EventData | Where-Object { $_.Name -eq 'Status' }).'#text'
                [string]$IpAddress = ($EventData | Where-Object { $_.Name -eq 'IpAddress' }).'#text'

                [bool]$MatchesServiceType = $false
                foreach ($SvcType in $ServiceTypes) {
                    if ($ServiceName -like ('{0}*' -f $SvcType)) {
                        $MatchesServiceType = $true
                        break
                    } #end If
                } #end ForEach
                if (-not $MatchesServiceType) {
                    continue
                } #end If

                $AdUser = Get-ADUser -Filter { SamAccountName -eq $TargetUserName } -ErrorAction SilentlyContinue
                [bool]$UserExists = $null -ne $AdUser

                if ((-not $UserExists) -and ($TargetUserName -notlike '*$')) {
                    [void]$ServiceTicketAnomalies.Add([PSCustomObject]@{
                            Timestamp      = $EventEntry.TimeCreated
                            AnomalyType    = 'Service Ticket for Non-Existent User'
                            Severity       = 'CRITICAL'
                            TargetUser     = $TargetUserName
                            ServiceName    = $ServiceName
                            EncryptionType = $TicketEncryptionType
                            SourceIP       = $IpAddress
                            Details        = ('Service ticket requested for non-existent account {0}.' -f $TargetUserName)
                        })
                } #end If

                if ($TicketEncryptionType -eq '0x17') {
                    [void]$ServiceTicketAnomalies.Add([PSCustomObject]@{
                            Timestamp      = $EventEntry.TimeCreated
                            AnomalyType    = 'RC4 Encryption Downgrade'
                            Severity       = 'MEDIUM'
                            TargetUser     = $TargetUserName
                            ServiceName    = $ServiceName
                            EncryptionType = 'RC4_HMAC_MD5 (0x17)'
                            SourceIP       = $IpAddress
                            Details        = 'Service ticket uses deprecated RC4 encryption.'
                        })
                } #end If

                if ($Status -eq '0x1F') {
                    [void]$ServiceTicketAnomalies.Add([PSCustomObject]@{
                            Timestamp      = $EventEntry.TimeCreated
                            AnomalyType    = 'PAC Validation Failure'
                            Severity       = 'CRITICAL'
                            TargetUser     = $TargetUserName
                            ServiceName    = $ServiceName
                            EncryptionType = $TicketEncryptionType
                            SourceIP       = $IpAddress
                            Details        = 'PAC validation failure indicates potential forged Silver Ticket.'
                        })
                } #end If
            } #end ForEach

            if (-not $BaselineMode) {
                foreach ($Anomaly in ($ServiceTicketAnomalies | Where-Object { $_.Severity -eq 'CRITICAL' })) {
                    [void]$Detections.Add([PSCustomObject]@{
                            Timestamp       = $Anomaly.Timestamp
                            DetectionType   = 'Service Ticket Anomaly'
                            Severity        = $Anomaly.Severity
                            Domain          = $Domain.DNSRoot
                            Details         = ('{0} User={1} Service={2} Source={3}' -f $Anomaly.AnomalyType, $Anomaly.TargetUser, $Anomaly.ServiceName, $Anomaly.SourceIP)
                            Recommendation  = 'Rotate affected service credentials and validate PAC signature enforcement.'
                            MITRE_Technique = $MitreTechnique
                        })
                } #end ForEach
            } #end If

            Write-Verbose -Message '[Phase 4/5] Detecting computer account Silver Ticket indicators.'

            $StaleComputerAccounts = Get-ADComputer -Filter * -Properties PasswordLastSet -ErrorAction SilentlyContinue |
                Where-Object {
                    $null -ne $_.PasswordLastSet -and
                    ((Get-Date) - $_.PasswordLastSet).TotalDays -gt 30
                }

            foreach ($Server in $TargetServers) {
                try {
                    $Event4624 = Get-WinEvent -ComputerName $Server -FilterHashtable @{
                        LogName   = 'Security'
                        Id        = 4624
                        StartTime = $ScanStartTime
                    } -ErrorAction SilentlyContinue |
                        Where-Object {
                            $Xml = [xml]$_.ToXml()
                            $UserName = ($Xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
                            $UserName -like '*$'
                        }

                    foreach ($LogonEvent in $Event4624) {
                        $Xml = [xml]$LogonEvent.ToXml()
                        [string]$ComputerAccount = ($Xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
                        [string]$SourceIp = ($Xml.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'

                        if ($Server -match 'SQL|WEB|APP') {
                            [void]$ComputerAccountAnomalies.Add([PSCustomObject]@{
                                    Timestamp       = $LogonEvent.TimeCreated
                                    ComputerAccount = $ComputerAccount
                                    TargetServer    = $Server
                                    SourceIP        = $SourceIp
                                    Severity        = 'MEDIUM'
                                    Details         = ('Computer account {0} accessed non-standard service on {1}.' -f $ComputerAccount, $Server)
                                })
                        } #end If
                    } #end ForEach
                } catch {
                    Write-Warning -Message ('Failed to analyze computer account activity on {0}: {1}' -f $Server, $_.Exception.Message)
                } #end try-catch
            } #end ForEach

            if (-not $BaselineMode) {
                foreach ($Finding in $ComputerAccountAnomalies) {
                    [void]$Detections.Add([PSCustomObject]@{
                            Timestamp       = $Finding.Timestamp
                            DetectionType   = 'Computer Account Silver Ticket Indicator'
                            Severity        = $Finding.Severity
                            Domain          = $Domain.DNSRoot
                            Details         = ('{0} Source={1}' -f $Finding.Details, $Finding.SourceIP)
                            Recommendation  = ('Investigate why {0} accessed {1}.' -f $Finding.ComputerAccount, $Finding.TargetServer)
                            MITRE_Technique = $MitreTechnique
                        })
                } #end ForEach
            } #end If

            Write-Verbose -Message '[Phase 5/5] Behavioral baseline advisory.'
            [void]$BehaviorAdvisories.Add('Behavioral UEBA analysis requires 7-30 day baseline and SIEM integration.')
            [void]$BehaviorAdvisories.Add('Recommended platforms: Microsoft Sentinel, Splunk, or Chronicle for anomaly baselining.')

            if ($BaselineMode) {
                [void]$BehaviorAdvisories.Add('Baseline mode active: detections are informational and not treated as alert conditions.')
            } #end If

            [int]$StaleComputerCount = ($StaleComputerAccounts | Measure-Object).Count
            if ($StaleComputerCount -gt 0) {
                [void]$BehaviorAdvisories.Add(('Stale computer account passwords (>30 days): {0}' -f $StaleComputerCount))
            } #end If

        } catch {
            Write-Error -Message ('Silver Ticket detection failed: {0}' -f $_.Exception.Message) -ErrorAction Stop
        } #end try-catch
    } #end Process

    end {
        [int]$CriticalCount = ($Detections | Where-Object { $_.Severity -eq 'CRITICAL' } | Measure-Object).Count
        [int]$HighCount = ($Detections | Where-Object { $_.Severity -eq 'HIGH' } | Measure-Object).Count
        [int]$MediumCount = ($Detections | Where-Object { $_.Severity -eq 'MEDIUM' } | Measure-Object).Count

        [string[]]$RecommendedActions = @()

        if ($BaselineMode) {
            $RecommendedActions += 'Baseline mode enabled: validate trends before enabling enforcement alerts.'
        } #end If

        if ($CriticalCount -gt 0 -and -not $BaselineMode) {
            $RecommendedActions += 'IMMEDIATE: rotate affected service account passwords.'
            $RecommendedActions += 'Enable PAC validation on high-value services.'
            $RecommendedActions += 'Investigate source systems for persistence mechanisms.'
        } elseif (($HighCount -gt 0 -or $MediumCount -gt 0) -and -not $BaselineMode) {
            $RecommendedActions += 'Review suspicious service authentication paths and stale credentials.'
            $RecommendedActions += 'Migrate non-gMSA service accounts to gMSA where possible.'
        } else {
            $RecommendedActions += 'No actionable Silver Ticket indicators detected.'
        } #end If-ElseIf-Else

        if ($IncludeServiceAccountAudit) {
            $RecommendedActions += 'Prioritize service account hardening: gMSA migration, rotation cadence, and privileged group review.'
        } #end If

        if ($ExportPath) {
            if ($PSCmdlet.ShouldProcess($ExportPath, 'Export Silver Ticket detection reports')) {
                if (-not (Test-Path -Path $ExportPath -PathType Container)) {
                    New-Item -Path $ExportPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
                } #end If

                [string]$TimestampSuffix = (Get-Date -Format 'yyyyMMdd-HHmmss')
                [string]$DetectionFile = Join-Path -Path $ExportPath -ChildPath ('SilverTicket-Detections-{0}.csv' -f $TimestampSuffix)
                [string]$ServiceAuditFile = Join-Path -Path $ExportPath -ChildPath ('SilverTicket-ServiceAccountAudit-{0}.csv' -f $TimestampSuffix)
                [string]$AnomalyFile = Join-Path -Path $ExportPath -ChildPath ('SilverTicket-4769Anomalies-{0}.csv' -f $TimestampSuffix)

                if ($Detections.Count -gt 0) {
                    $Detections | Export-Csv -Path $DetectionFile -NoTypeInformation -Encoding UTF8
                    [void]$ExportedReports.Add($DetectionFile)
                } #end If

                if ($IncludeServiceAccountAudit -and $ServiceAccountAudit.Count -gt 0) {
                    $ServiceAccountAudit | Export-Csv -Path $ServiceAuditFile -NoTypeInformation -Encoding UTF8
                    [void]$ExportedReports.Add($ServiceAuditFile)
                } #end If

                if ($ServiceTicketAnomalies.Count -gt 0) {
                    $ServiceTicketAnomalies | Export-Csv -Path $AnomalyFile -NoTypeInformation -Encoding UTF8
                    [void]$ExportedReports.Add($AnomalyFile)
                } #end If
            } #end If
        } #end If

        if ($Remediate -and $CriticalCount -gt 0 -and -not $BaselineMode) {
            if ($PSCmdlet.ShouldProcess($RemediationUrl, 'Open Silver Ticket remediation guidance')) {
                Start-Process -FilePath $RemediationUrl
            } #end If
        } #end If

        [PSCustomObject]@{
            DomainName                        = $Domain.DNSRoot
            PdcEmulator                       = $PdcEmulator
            AuditTimestamp                    = $AuditTimestamp
            TimeWindowHours                   = $Hours
            BaselineMode                      = [bool]$BaselineMode
            TargetServerCount                 = $TargetServers.Count
            ServiceTypeCount                  = $ServiceTypes.Count
            TotalDetections                   = $Detections.Count
            CriticalDetections                = $CriticalCount
            HighDetections                    = $HighCount
            MediumDetections                  = $MediumCount
            HighRiskServiceAccountCount       = ($ServiceAccountAudit | Where-Object { $_.RiskLevel -in @('CRITICAL', 'HIGH') } | Measure-Object).Count
            MissingServiceTicketCount         = $MissingServiceTicket.Count
            ServiceTicketAnomalyCount         = $ServiceTicketAnomalies.Count
            ComputerAccountAnomalyCount       = $ComputerAccountAnomalies.Count
            IsSecure                          = (($CriticalCount + $HighCount) -eq 0)
            RiskLevel                         = if ($CriticalCount -gt 0) {
                'Critical'
            } elseif ($HighCount -gt 0) {
                'High'
            } elseif ($MediumCount -gt 0) {
                'Medium'
            } else {
                'Secure'
            }
            RecommendedActions                = $RecommendedActions
            BehavioralBaselineRecommendations = @($BehaviorAdvisories)
            ExportedReports                   = @($ExportedReports)
            ServiceAccountAudit               = @($ServiceAccountAudit)
            Detections                        = @($Detections)
            MissingServiceTicketFindings      = @($MissingServiceTicket)
            ServiceTicketAnomalies            = @($ServiceTicketAnomalies)
            ComputerAccountAnomalies          = @($ComputerAccountAnomalies)
        }

        if ($null -ne $Variables -and
            $null -ne $Variables.FooterSecurity) {

            $txt = ($Variables.FooterSecurity -f
                $MyInvocation.InvocationName,
                'completed Silver Ticket detection audit.'
            )
            Write-Verbose -Message $txt
        } #end If
    } #end End
} #end Function Get-SilverTicketDetection
