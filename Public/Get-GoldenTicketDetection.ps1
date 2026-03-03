function Get-GoldenTicketDetection {
    <#
        .SYNOPSIS
            Detects Golden Ticket attack indicators by correlating Kerberos and logon security events.

        .DESCRIPTION
            Performs a five-phase Golden Ticket detection audit:
            1) krbtgt password age audit across forest domains.
            2) Event ID 4768 anomaly analysis (TGT request anomalies).
            3) Correlation of Event ID 4624 logons without prior 4768 requests.
            4) Event ID 4769 service ticket anomaly analysis.
            5) Event ID 4672 privileged access outlier analysis.

            The function returns structured output suitable for automation and optionally exports reports.

        .PARAMETER DomainController
            Target domain controller for Security log analysis. If omitted, uses the PDC Emulator.

        .PARAMETER Hours
            Number of hours to analyze from the current time.

        .PARAMETER ExportPath
            Directory path used to export CSV reports.

        .PARAMETER IncludeKrbtgtRotation
            If specified, includes krbtgt rotation guidance in output recommendations.

        .PARAMETER Remediate
            If specified and critical findings exist, opens remediation guidance URL.

        .EXAMPLE
            Get-GoldenTicketDetection

            Runs the detection audit using default options.

        .EXAMPLE
            Get-GoldenTicketDetection -Hours 168 -ExportPath 'C:\Reports' -Verbose

            Scans last 7 days and exports report files to C:\Reports.

        .EXAMPLE
            $Result = Get-GoldenTicketDetection -Hours 24
            if ($Result.CriticalDetections -gt 0) {
                Write-Warning -Message ('Critical Golden Ticket indicators detected: {0}' -f $Result.CriticalDetections)
            }

            Captures output for automation workflows.

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
                Get-ADForest                           | ActiveDirectory
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
            https://attack.mitre.org/techniques/T1558/001/

        .LINK
            https://github.com/vreguibar/EguibarIT.SecurityPS

        .COMPONENT
            EguibarIT.SecurityPS

        .ROLE
            Security Auditing

        .FUNCTIONALITY
            Detects Golden Ticket attack patterns using Kerberos telemetry and account validation.
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
            HelpMessage = 'Target domain controller for Security event log analysis',
            Position = 0
        )]
        [ValidateNotNullOrEmpty()]
        [string]
        $DomainController = '',

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Number of hours to analyze in security event logs',
            Position = 1
        )]
        [ValidateRange(1, 720)]
        [PSDefaultValue(Help = 'Default: 24 hours')]
        [int]
        $Hours = 24,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Directory path to export CSV reports',
            Position = 2
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
            HelpMessage = 'Include krbtgt rotation guidance when findings require remediation',
            Position = 3
        )]
        [switch]
        $IncludeKrbtgtRotation,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Open remediation guidance URL when critical findings are present',
            Position = 4
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
        [string]$MitreTechnique = 'T1558.001'
        [string]$RemediationUrl = 'https://eguibarit.eu/security/five-eyes-ad-attacks.html#golden-ticket'

        [System.Collections.ArrayList]$Detections = @()
        [System.Collections.ArrayList]$KrbtgtAudit = @()
        [System.Collections.ArrayList]$TgtAnomalies = @()
        [System.Collections.ArrayList]$MissingTgt = @()
        [System.Collections.ArrayList]$ServiceTicketAnomalies = @()
        [System.Collections.ArrayList]$PrivilegeAnomalies = @()
        [System.Collections.ArrayList]$ExportedReports = @()

        [System.Collections.ArrayList]$Event4768 = @()

        $Domain = Get-ADDomain -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($DomainController)) {
            $DomainController = $Domain.PDCEmulator
        } #end If

        Write-Verbose -Message ('Analyzing domain {0} on DC {1} for the last {2} hours.' -f $Domain.DNSRoot, $DomainController, $Hours)
    } #end Begin

    process {
        try {
            Write-Verbose -Message '[Phase 1/5] Auditing krbtgt password age across all domains.'

            $Forest = Get-ADForest -ErrorAction Stop
            foreach ($DomainName in $Forest.Domains) {
                try {
                    $KrbtgtAccount = Get-ADUser -Identity 'krbtgt' -Server $DomainName -Properties PasswordLastSet, PasswordNeverExpires -ErrorAction Stop
                    [int]$DaysOld = [math]::Round(((Get-Date) - $KrbtgtAccount.PasswordLastSet).TotalDays)

                    [string]$RiskLevel = if ($DaysOld -gt 365) {
                        'CRITICAL'
                    } elseif ($DaysOld -gt 180) {
                        'HIGH'
                    } elseif ($DaysOld -gt 90) {
                        'MEDIUM'
                    } else {
                        'LOW'
                    }

                    [string]$Recommendation = if ($DaysOld -gt 180) {
                        'Rotate krbtgt password twice with 10+ hour delay between rotations.'
                    } elseif ($DaysOld -gt 90) {
                        'Schedule krbtgt password rotation within 30 days.'
                    } else {
                        'No immediate action required.'
                    }

                    [void]$KrbtgtAudit.Add([PSCustomObject]@{
                            Domain               = $DomainName
                            PasswordLastSet      = $KrbtgtAccount.PasswordLastSet
                            PasswordAge_Days     = $DaysOld
                            RiskLevel            = $RiskLevel
                            PasswordNeverExpires = $KrbtgtAccount.PasswordNeverExpires
                            Recommendation       = $Recommendation
                        })

                    if ($RiskLevel -in @('HIGH', 'CRITICAL')) {
                        [void]$Detections.Add([PSCustomObject]@{
                                Timestamp       = Get-Date
                                DetectionType   = 'krbtgt Password Age Violation'
                                Severity        = $RiskLevel
                                Domain          = $DomainName
                                Details         = ('krbtgt password age is {0} days (last set {1}).' -f $DaysOld, $KrbtgtAccount.PasswordLastSet)
                                Recommendation  = 'Rotate krbtgt password twice with 10+ hour replication window.'
                                MITRE_Technique = $MitreTechnique
                            })
                    } #end If
                } catch {
                    Write-Warning -Message ('Failed to query krbtgt in domain {0}: {1}' -f $DomainName, $_.Exception.Message)
                } #end try-catch
            } #end ForEach

            Write-Verbose -Message '[Phase 2/5] Analyzing Event ID 4768 TGT requests.'

            $Event4768Query = @{
                LogName   = 'Security'
                Id        = 4768
                StartTime = $ScanStartTime
            }

            $Event4768Raw = Get-WinEvent -ComputerName $DomainController -FilterHashtable $Event4768Query -ErrorAction SilentlyContinue
            foreach ($EventEntry in $Event4768Raw) {
                [void]$Event4768.Add($EventEntry)
            } #end ForEach

            foreach ($EventEntry in $Event4768) {
                $Xml = [xml]$EventEntry.ToXml()
                $EventData = $Xml.Event.EventData.Data

                [string]$TargetUserName = ($EventData | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
                [string]$TicketOptions = ($EventData | Where-Object { $_.Name -eq 'TicketOptions' }).'#text'
                [string]$TicketEncryptionType = ($EventData | Where-Object { $_.Name -eq 'TicketEncryptionType' }).'#text'
                [string]$IpAddress = ($EventData | Where-Object { $_.Name -eq 'IpAddress' }).'#text'

                $AdUser = Get-ADUser -Filter { SamAccountName -eq $TargetUserName } -ErrorAction SilentlyContinue
                [bool]$UserExists = $null -ne $AdUser

                if ((-not $UserExists) -and ($TargetUserName -notlike '*$')) {
                    [void]$TgtAnomalies.Add([PSCustomObject]@{
                            Timestamp      = $EventEntry.TimeCreated
                            AnomalyType    = 'Non-Existent User TGT Request'
                            Severity       = 'CRITICAL'
                            TargetUser     = $TargetUserName
                            EncryptionType = $TicketEncryptionType
                            SourceIP       = $IpAddress
                            TicketOptions  = $TicketOptions
                            Details        = ('TGT requested for non-existent account {0}.' -f $TargetUserName)
                        })
                } #end If

                if ($TicketEncryptionType -eq '0x17') {
                    [void]$TgtAnomalies.Add([PSCustomObject]@{
                            Timestamp      = $EventEntry.TimeCreated
                            AnomalyType    = 'RC4 Encryption Usage'
                            Severity       = 'MEDIUM'
                            TargetUser     = $TargetUserName
                            EncryptionType = 'RC4_HMAC_MD5 (0x17)'
                            SourceIP       = $IpAddress
                            TicketOptions  = $TicketOptions
                            Details        = 'TGT request used deprecated RC4 encryption.'
                        })
                } #end If
            } #end ForEach

            foreach ($Anomaly in ($TgtAnomalies | Where-Object { $_.Severity -eq 'CRITICAL' })) {
                [void]$Detections.Add([PSCustomObject]@{
                        Timestamp       = $Anomaly.Timestamp
                        DetectionType   = 'Anomalous TGT Request'
                        Severity        = $Anomaly.Severity
                        Domain          = $Domain.DNSRoot
                        Details         = ('{0} | User: {1} | Source: {2}' -f $Anomaly.Details, $Anomaly.TargetUser, $Anomaly.SourceIP)
                        Recommendation  = ('Investigate source IP {0} and account activity immediately.' -f $Anomaly.SourceIP)
                        MITRE_Technique = $MitreTechnique
                    })
            } #end ForEach

            Write-Verbose -Message '[Phase 3/5] Correlating Event ID 4624 logons without Event ID 4768 TGT requests.'

            $Event4624Query = @{
                LogName   = 'Security'
                Id        = 4624
                StartTime = $ScanStartTime
            }

            $Event4624 = Get-WinEvent -ComputerName $DomainController -FilterHashtable $Event4624Query -ErrorAction SilentlyContinue |
                Where-Object {
                    $Xml = [xml]$_.ToXml()
                    $LogonType = ($Xml.Event.EventData.Data | Where-Object { $_.Name -eq 'LogonType' }).'#text'
                    $LogonType -eq '3'
                }

            [hashtable]$UsersWithTgt = @{}
            foreach ($EventEntry in $Event4768) {
                $Xml = [xml]$EventEntry.ToXml()
                [string]$UserName = ($Xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'

                if (-not $UsersWithTgt.ContainsKey($UserName)) {
                    $UsersWithTgt[$UserName] = [System.Collections.ArrayList]@()
                } #end If
                [void]$UsersWithTgt[$UserName].Add($EventEntry.TimeCreated)
            } #end ForEach

            foreach ($LogonEvent in $Event4624) {
                $Xml = [xml]$LogonEvent.ToXml()
                [string]$UserName = ($Xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
                [datetime]$LogonTime = $LogonEvent.TimeCreated
                [string]$SourceIp = ($Xml.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'

                if ($UserName -like '*$') {
                    continue
                } #end If

                [bool]$TgtFound = $false
                if ($UsersWithTgt.ContainsKey($UserName)) {
                    foreach ($TgtTime in $UsersWithTgt[$UserName]) {
                        [double]$TimeDiff = ($LogonTime - $TgtTime).TotalMinutes
                        if ($TimeDiff -ge 0 -and $TimeDiff -le 60) {
                            $TgtFound = $true
                            break
                        } #end If
                    } #end ForEach
                } #end If

                if (-not $TgtFound) {
                    $AdUser = Get-ADUser -Filter { SamAccountName -eq $UserName } -ErrorAction SilentlyContinue
                    [bool]$UserExists = $null -ne $AdUser

                    [string]$Severity = if (-not $UserExists) {
                        'CRITICAL'
                    } else {
                        'HIGH'
                    }

                    [string]$DetailMessage = if (-not $UserExists) {
                        ('Logon for non-existent user {0} without preceding TGT request.' -f $UserName)
                    } else {
                        ('Logon for user {0} without preceding TGT request.' -f $UserName)
                    }

                    [void]$MissingTgt.Add([PSCustomObject]@{
                            Timestamp  = $LogonTime
                            Username   = $UserName
                            SourceIP   = $SourceIp
                            UserExists = $UserExists
                            Severity   = $Severity
                            Details    = $DetailMessage
                        })
                } #end If
            } #end ForEach

            foreach ($MissingEntry in $MissingTgt) {
                [string]$Recommendation = if (-not $MissingEntry.UserExists) {
                    ('IMMEDIATE: rotate krbtgt twice and investigate source IP {0}.' -f $MissingEntry.SourceIP)
                } else {
                    ('Investigate user {0} and source IP {1} for forged ticket activity.' -f $MissingEntry.Username, $MissingEntry.SourceIP)
                }

                [void]$Detections.Add([PSCustomObject]@{
                        Timestamp       = $MissingEntry.Timestamp
                        DetectionType   = 'Missing TGT Request Before Logon'
                        Severity        = $MissingEntry.Severity
                        Domain          = $Domain.DNSRoot
                        Details         = ('{0} Source: {1}' -f $MissingEntry.Details, $MissingEntry.SourceIP)
                        Recommendation  = $Recommendation
                        MITRE_Technique = $MitreTechnique
                    })
            } #end ForEach

            Write-Verbose -Message '[Phase 4/5] Analyzing Event ID 4769 service ticket anomalies.'

            $Event4769Query = @{
                LogName   = 'Security'
                Id        = 4769
                StartTime = $ScanStartTime
            }
            $Event4769 = Get-WinEvent -ComputerName $DomainController -FilterHashtable $Event4769Query -ErrorAction SilentlyContinue

            foreach ($EventEntry in $Event4769) {
                $Xml = [xml]$EventEntry.ToXml()
                $EventData = $Xml.Event.EventData.Data

                [string]$TargetUserName = ($EventData | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
                [string]$ServiceName = ($EventData | Where-Object { $_.Name -eq 'ServiceName' }).'#text'
                [string]$TicketEncryptionType = ($EventData | Where-Object { $_.Name -eq 'TicketEncryptionType' }).'#text'
                [string]$IpAddress = ($EventData | Where-Object { $_.Name -eq 'IpAddress' }).'#text'

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
            } #end ForEach

            foreach ($Anomaly in ($ServiceTicketAnomalies | Where-Object { $_.Severity -eq 'CRITICAL' })) {
                [void]$Detections.Add([PSCustomObject]@{
                        Timestamp       = $Anomaly.Timestamp
                        DetectionType   = 'Anomalous Service Ticket Request'
                        Severity        = $Anomaly.Severity
                        Domain          = $Domain.DNSRoot
                        Details         = ('{0} Service: {1} Source: {2}' -f $Anomaly.Details, $Anomaly.ServiceName, $Anomaly.SourceIP)
                        Recommendation  = 'Investigate deleted-account service ticket activity and source host immediately.'
                        MITRE_Technique = $MitreTechnique
                    })
            } #end ForEach

            Write-Verbose -Message '[Phase 5/5] Analyzing Event ID 4672 privileged access outliers.'

            $Event4672Query = @{
                LogName   = 'Security'
                Id        = 4672
                StartTime = $ScanStartTime
            }
            $Event4672 = Get-WinEvent -ComputerName $DomainController -FilterHashtable $Event4672Query -ErrorAction SilentlyContinue

            foreach ($EventEntry in $Event4672) {
                $Xml = [xml]$EventEntry.ToXml()
                [string]$UserName = ($Xml.Event.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'

                if ($UserName -like '*$' -or $UserName -eq 'SYSTEM') {
                    continue
                } #end If

                $AdUser = Get-ADUser -Filter { SamAccountName -eq $UserName } -ErrorAction SilentlyContinue
                [bool]$UserExists = $null -ne $AdUser

                if (-not $UserExists) {
                    [void]$PrivilegeAnomalies.Add([PSCustomObject]@{
                            Timestamp   = $EventEntry.TimeCreated
                            AnomalyType = 'Privileges Assigned to Non-Existent User'
                            Severity    = 'CRITICAL'
                            Username    = $UserName
                            Details     = ('Event 4672 privileges assigned to non-existent account {0}.' -f $UserName)
                        })
                } #end If
            } #end ForEach

            foreach ($Anomaly in $PrivilegeAnomalies) {
                [void]$Detections.Add([PSCustomObject]@{
                        Timestamp       = $Anomaly.Timestamp
                        DetectionType   = 'Privilege Escalation via Forged Ticket'
                        Severity        = $Anomaly.Severity
                        Domain          = $Domain.DNSRoot
                        Details         = $Anomaly.Details
                        Recommendation  = 'IMMEDIATE: rotate krbtgt twice and investigate related Kerberos events.'
                        MITRE_Technique = $MitreTechnique
                    })
            } #end ForEach

        } catch {
            Write-Error -Message ('Golden Ticket detection failed: {0}' -f $_.Exception.Message) -ErrorAction Stop
        } #end try-catch
    } #end Process

    end {
        [int]$CriticalCount = ($Detections | Where-Object { $_.Severity -eq 'CRITICAL' } | Measure-Object).Count
        [int]$HighCount = ($Detections | Where-Object { $_.Severity -eq 'HIGH' } | Measure-Object).Count
        [int]$MediumCount = ($Detections | Where-Object { $_.Severity -eq 'MEDIUM' } | Measure-Object).Count

        [string[]]$RecommendedActions = @()
        if ($CriticalCount -gt 0) {
            $RecommendedActions += 'Critical indicators detected: rotate krbtgt password twice with 10+ hour delay.'
            $RecommendedActions += 'Investigate suspicious source IP addresses and disable compromised accounts.'
            $RecommendedActions += 'Perform incident response and forensic review of Kerberos activity.'
        } elseif ($HighCount -gt 0 -or $MediumCount -gt 0) {
            $RecommendedActions += 'Investigate anomalous Kerberos events and validate account hygiene.'
            $RecommendedActions += 'Review krbtgt rotation schedule and enforce modern encryption.'
        } else {
            $RecommendedActions += 'No critical indicators detected. Continue periodic monitoring.'
        } #end If-ElseIf-Else

        if ($IncludeKrbtgtRotation) {
            $RecommendedActions += 'Use Microsoft New-KrbtgtKeys.ps1 and perform two staged rotations.'
        } #end If

        if ($ExportPath -and ($Detections.Count -gt 0 -or $KrbtgtAudit.Count -gt 0)) {
            if ($PSCmdlet.ShouldProcess($ExportPath, 'Export Golden Ticket detection reports')) {
                if (-not (Test-Path -Path $ExportPath -PathType Container)) {
                    New-Item -Path $ExportPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
                } #end If

                [string]$TimestampSuffix = (Get-Date -Format 'yyyyMMdd-HHmmss')
                [string]$DetectionFile = Join-Path -Path $ExportPath -ChildPath ('GoldenTicket-Detections-{0}.csv' -f $TimestampSuffix)
                [string]$KrbtgtFile = Join-Path -Path $ExportPath -ChildPath ('GoldenTicket-krbtgt-Audit-{0}.csv' -f $TimestampSuffix)

                if ($Detections.Count -gt 0) {
                    $Detections | Export-Csv -Path $DetectionFile -NoTypeInformation -Encoding UTF8
                    [void]$ExportedReports.Add($DetectionFile)
                } #end If

                if ($KrbtgtAudit.Count -gt 0) {
                    $KrbtgtAudit | Export-Csv -Path $KrbtgtFile -NoTypeInformation -Encoding UTF8
                    [void]$ExportedReports.Add($KrbtgtFile)
                } #end If
            } #end If
        } #end If

        if ($Remediate -and $CriticalCount -gt 0) {
            if ($PSCmdlet.ShouldProcess($RemediationUrl, 'Open Golden Ticket remediation guidance')) {
                Start-Process -FilePath $RemediationUrl
            } #end If
        } #end If

        [PSCustomObject]@{
            DomainName                 = $Domain.DNSRoot
            DomainController           = $DomainController
            AuditTimestamp             = $AuditTimestamp
            TimeWindowHours            = $Hours
            TotalDetections            = $Detections.Count
            CriticalDetections         = $CriticalCount
            HighDetections             = $HighCount
            MediumDetections           = $MediumCount
            KrbtgtCriticalOrHighCount  = ($KrbtgtAudit | Where-Object { $_.RiskLevel -in @('CRITICAL', 'HIGH') } | Measure-Object).Count
            TgtAnomalyCount            = $TgtAnomalies.Count
            MissingTgtCorrelationCount = $MissingTgt.Count
            ServiceTicketAnomalyCount  = $ServiceTicketAnomalies.Count
            PrivilegeAnomalyCount      = $PrivilegeAnomalies.Count
            IsSecure                   = (($CriticalCount + $HighCount) -eq 0)
            RiskLevel                  = if ($CriticalCount -gt 0) { 'Critical' } elseif ($HighCount -gt 0) { 'High' } elseif ($MediumCount -gt 0) { 'Medium' } else { 'Secure' }
            RecommendedActions         = $RecommendedActions
            ExportedReports            = @($ExportedReports)
            KrbtgtAudit                = @($KrbtgtAudit)
            Detections                 = @($Detections)
            TgtAnomalies               = @($TgtAnomalies)
            MissingTgtCorrelations     = @($MissingTgt)
            ServiceTicketAnomalies     = @($ServiceTicketAnomalies)
            PrivilegeAnomalies         = @($PrivilegeAnomalies)
        }

        if ($null -ne $Variables -and
            $null -ne $Variables.FooterSecurity) {

            $txt = ($Variables.FooterSecurity -f
                $MyInvocation.InvocationName,
                'completed Golden Ticket detection audit.'
            )
            Write-Verbose -Message $txt
        } #end If
    } #end End
} #end Function Get-GoldenTicketDetection
