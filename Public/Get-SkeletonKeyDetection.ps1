function Get-SkeletonKeyDetection {
    <#
        .SYNOPSIS
            Detects Skeleton Key malware indicators on domain controllers.

        .DESCRIPTION
            Performs a comprehensive five-phase Skeleton Key detection audit:

            **Phase 1 - CREDENTIAL GUARD STATUS CHECK:**
            Validates whether Credential Guard is configured and running on target domain controllers.

            **Phase 2 - LSASS MEMORY ACCESS DETECTION (SYSMON EVENT 10):**
            Detects suspicious process access to lsass.exe, including high-risk full access masks.

            **Phase 3 - SERVICE INSTALLATION EVENTS (EVENT 7045):**
            Identifies suspicious service deployment patterns associated with remote tooling and malware staging.

            **Phase 4 - AUTHENTICATION ANOMALY ANALYSIS (EVENT 4624):**
            Flags source IPs authenticating as many distinct accounts in the analysis window.

            **Phase 5 - NTLM AUDIT/ANOMALY ANALYSIS (EVENT 8004):**
            Checks NTLM auditing posture and highlights privileged account NTLM usage anomalies.

            **ATTACK VECTOR:**
            Skeleton Key patches LSASS in memory on domain controllers to create a universal password backdoor
            for domain authentication workflows.

            **MITRE ATT&CK Mapping:**
            - **T1556.001**: Modify Authentication Process - Domain Controller Authentication
            - **T1003.001**: OS Credential Dumping - LSASS Memory

            **DETECTION REQUIREMENTS:**
            - Domain Admin or equivalent read rights
            - ActiveDirectory module
            - Sysmon deployed on domain controllers for Event ID 10 visibility

        .PARAMETER OutputPath
            Directory where detection reports are exported in CSV and JSON format.
            Export respects -WhatIf and -Confirm.

        .PARAMETER DaysBack
            Number of days to analyze event logs for Skeleton Key indicators.
            Valid range is 1 to 365 days.

        .PARAMETER CheckAllDCs
            If specified, scans all domain controllers discovered in the domain.
            By default, scans current host only.

        .EXAMPLE
            Get-SkeletonKeyDetection

            Description
            -----------
            Runs Skeleton Key detection against the current host.

        .EXAMPLE
            Get-SkeletonKeyDetection -OutputPath 'C:\SkeletonKeyAudit' -DaysBack 90 -CheckAllDCs -Verbose

            Description
            -----------
            Performs comprehensive domain controller analysis and exports reports.

        .EXAMPLE
            $Result = Get-SkeletonKeyDetection -DaysBack 30 -CheckAllDCs
            if ($Result.CriticalCount -gt 0) {
                Write-Warning ('Critical Skeleton Key indicators found: {0}' -f $Result.CriticalCount)
            }

            Description
            -----------
            Integrates output in automation pipelines for incident triage.

        .INPUTS
            None. This function does not accept pipeline input.

        .OUTPUTS
            [PSCustomObject]

        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Import-MyModule                        | EguibarIT.SecurityPS
                Get-FunctionDisplay                    | EguibarIT.SecurityPS
                Get-ADDomainController                 | ActiveDirectory
                Invoke-Command                         | Microsoft.PowerShell.Core
                Get-Service                            | Microsoft.PowerShell.Management
                Get-WinEvent                           | Microsoft.PowerShell.Diagnostics
                Export-Csv                             | Microsoft.PowerShell.Utility
                ConvertTo-Json                         | Microsoft.PowerShell.Utility
                Out-File                               | Microsoft.PowerShell.Utility
                Write-Verbose                          | Microsoft.PowerShell.Utility
                Write-Warning                          | Microsoft.PowerShell.Utility
                Write-Progress                         | Microsoft.PowerShell.Utility
                Write-Error                            | Microsoft.PowerShell.Utility
                Write-Output                           | Microsoft.PowerShell.Utility

        .NOTES
            Version:         1.0.0
            DateModified:    06/Mar/2026
            LastModifiedBy:  Vicente Rodriguez Eguibar
                vicente@eguibar.com
                EguibarIT
                http://www.eguibarit.com

        .LINK
            https://attack.mitre.org/techniques/T1556/001/

        .LINK
            https://github.com/vreguibar/EguibarIT.SecurityPS

        .COMPONENT
            EguibarIT.SecurityPS

        .ROLE
            Security Auditing

        .FUNCTIONALITY
            Detects Skeleton Key malware indicators through LSASS integrity posture,
            endpoint telemetry, and authentication anomaly analysis.
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
            HelpMessage = 'Directory where detection reports are exported in CSV and JSON format',
            Position = 0
        )]
        [ValidateNotNullOrEmpty()]
        [Alias('ExportPath', 'Path')]
        [PSDefaultValue(Help = 'Default: Desktop\SkeletonKeyAudit')]
        [string]
        $OutputPath = (Join-Path -Path $env:USERPROFILE -ChildPath 'Desktop\SkeletonKeyAudit'),

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Number of days to analyze event logs for Skeleton Key indicators',
            Position = 1
        )]
        [ValidateRange(1, 365)]
        [PSDefaultValue(Help = 'Default: 30 days', Value = 30)]
        [int]
        $DaysBack = 30,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Scan all domain controllers instead of current host only',
            Position = 2
        )]
        [switch]
        $CheckAllDCs
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

        [datetime]$AuditTimestamp = Get-Date
        [datetime]$StartDate = (Get-Date).AddDays(-$DaysBack)

        [System.Collections.ArrayList]$DomainControllersToScan = @()
        [System.Collections.ArrayList]$Findings = @()
        [System.Collections.ArrayList]$RecommendedActions = @()
        [System.Collections.ArrayList]$ExportedReports = @()

        Write-Verbose -Message ('Starting Skeleton Key detection. Analysis window starts at {0}' -f $StartDate)
    } #end Begin

    process {
        try {
            if ($CheckAllDCs.IsPresent) {
                Write-Verbose -Message 'Collecting all domain controllers for scan scope.'
                $AllDcs = Get-ADDomainController -Filter * -ErrorAction Stop
                foreach ($Dc in $AllDcs) {
                    if (-not [string]::IsNullOrWhiteSpace($Dc.HostName)) {
                        [void]$DomainControllersToScan.Add($Dc.HostName)
                    } elseif (-not [string]::IsNullOrWhiteSpace($Dc.Name)) {
                        [void]$DomainControllersToScan.Add($Dc.Name)
                    } #end if-elseif
                } #end foreach
            } else {
                [void]$DomainControllersToScan.Add($env:COMPUTERNAME)
                Write-Verbose -Message ('Scanning current host only: {0}' -f $env:COMPUTERNAME)
            } #end if-else

            if ($DomainControllersToScan.Count -eq 0) {
                throw 'No domain controllers were resolved for scanning.'
            } #end if

            Write-Progress -Activity 'Skeleton Key Detection Audit' -Status 'Phase 1/5: Credential Guard status' -PercentComplete 15

            # =============================================
            # PHASE 1: CREDENTIAL GUARD STATUS CHECK
            # =============================================
            foreach ($DomainController in $DomainControllersToScan) {
                try {
                    $CredentialGuardStatus = Invoke-Command -ComputerName $DomainController -ScriptBlock {
                        $ComputerInfo = Get-ComputerInfo -Property DeviceGuardSecurityServicesConfigured, DeviceGuardSecurityServicesRunning -ErrorAction SilentlyContinue

                        [PSCustomObject]@{
                            CredentialGuardConfigured = ($ComputerInfo.DeviceGuardSecurityServicesConfigured -contains 'CredentialGuard')
                            CredentialGuardRunning    = ($ComputerInfo.DeviceGuardSecurityServicesRunning -contains 'CredentialGuard')
                        }
                    } -ErrorAction Stop

                    if (-not $CredentialGuardStatus.CredentialGuardConfigured -or
                        -not $CredentialGuardStatus.CredentialGuardRunning) {

                        [void]$Findings.Add([PSCustomObject]@{
                                PSTypeName                 = 'EguibarIT.SkeletonKeyDetection.Finding'
                                Timestamp                  = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                                FindingType                = 'Credential Guard Not Enabled'
                                RiskLevel                  = 'Critical'
                                DomainController           = $DomainController
                                EventID                    = $null
                                SourceProcess              = $null
                                SourceUser                 = $null
                                GrantedAccess              = $null
                                SourceIP                   = $null
                                UniqueUserCount            = $null
                                NTLMEventCount             = $null
                                ServiceName                = $null
                                ServicePath                = $null
                                AccountName                = $null
                                CredentialGuardConfigured  = [bool]$CredentialGuardStatus.CredentialGuardConfigured
                                CredentialGuardRunning     = [bool]$CredentialGuardStatus.CredentialGuardRunning
                                NTLMAuditingEnabled        = $null
                                Indicator                  = 'Credential Guard disabled or not running; LSASS tampering risk is elevated.'
                                Recommendation             = 'Enable Credential Guard on domain controllers and reboot to enforce protection.'
                            })
                    } #end if
                } catch {
                    Write-Warning -Message ('Failed to check Credential Guard status on {0}: {1}' -f $DomainController, $_.Exception.Message)
                } #end try-catch
            } #end foreach

            Write-Progress -Activity 'Skeleton Key Detection Audit' -Status 'Phase 2/5: Sysmon Event 10 LSASS access' -PercentComplete 35

            # =============================================
            # PHASE 2: LSASS MEMORY ACCESS DETECTION
            # =============================================
            foreach ($DomainController in $DomainControllersToScan) {
                try {
                    [System.Management.Automation.CommandInfo]$GetServiceCommand = Get-Command -Name 'Get-Service' -ErrorAction Stop

                    if ($GetServiceCommand.Parameters.ContainsKey('ComputerName')) {
                        $SysmonService = Get-Service -ComputerName $DomainController -Name 'Sysmon64' -ErrorAction SilentlyContinue
                    } elseif ($DomainController -eq $env:COMPUTERNAME) {
                        $SysmonService = Get-Service -Name 'Sysmon64' -ErrorAction SilentlyContinue
                    } else {
                        $SysmonService = Invoke-Command -ComputerName $DomainController -ScriptBlock {
                            Get-Service -Name 'Sysmon64' -ErrorAction SilentlyContinue | Select-Object -First 1 -Property Name, Status
                        } -ErrorAction SilentlyContinue
                    } #end if-elseif-else

                    if ($null -eq $SysmonService) {
                        [void]$Findings.Add([PSCustomObject]@{
                                PSTypeName                 = 'EguibarIT.SkeletonKeyDetection.Finding'
                                Timestamp                  = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                                FindingType                = 'Sysmon Not Installed'
                                RiskLevel                  = 'High'
                                DomainController           = $DomainController
                                EventID                    = $null
                                SourceProcess              = $null
                                SourceUser                 = $null
                                GrantedAccess              = $null
                                SourceIP                   = $null
                                UniqueUserCount            = $null
                                NTLMEventCount             = $null
                                ServiceName                = $null
                                ServicePath                = $null
                                AccountName                = $null
                                CredentialGuardConfigured  = $null
                                CredentialGuardRunning     = $null
                                NTLMAuditingEnabled        = $null
                                Indicator                  = 'Sysmon is not installed; LSASS process-access telemetry is unavailable.'
                                Recommendation             = 'Deploy Sysmon and monitor Event ID 10 for lsass.exe access.'
                            })
                        continue
                    } #end if

                    $Event10List = Get-WinEvent -ComputerName $DomainController -FilterHashtable @{
                        LogName   = 'Microsoft-Windows-Sysmon/Operational'
                        Id        = 10
                        StartTime = $StartDate
                    } -ErrorAction SilentlyContinue

                    foreach ($Event10 in $Event10List) {
                        [xml]$EventXml = $Event10.ToXml()

                        $TargetImage = ($EventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetImage' } | Select-Object -First 1).'#text'
                        if ([string]::IsNullOrWhiteSpace($TargetImage) -or
                            $TargetImage -notmatch 'lsass\.exe') {
                            continue
                        } #end if

                        $SourceImage = ($EventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'SourceImage' } | Select-Object -First 1).'#text'
                        $SourceUser = ($EventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'SourceUser' } | Select-Object -First 1).'#text'
                        $GrantedAccess = ($EventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'GrantedAccess' } | Select-Object -First 1).'#text'

                        [string]$RiskLevel = if ($GrantedAccess -eq '0x1FFFFF') {
                            'Critical'
                        } else {
                            'High'
                        }

                        [void]$Findings.Add([PSCustomObject]@{
                                PSTypeName                 = 'EguibarIT.SkeletonKeyDetection.Finding'
                                Timestamp                  = $Event10.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                                FindingType                = 'LSASS Memory Access'
                                RiskLevel                  = $RiskLevel
                                DomainController           = $DomainController
                                EventID                    = 10
                                SourceProcess              = $SourceImage
                                SourceUser                 = $SourceUser
                                GrantedAccess              = $GrantedAccess
                                SourceIP                   = $null
                                UniqueUserCount            = $null
                                NTLMEventCount             = $null
                                ServiceName                = $null
                                ServicePath                = $null
                                AccountName                = $null
                                CredentialGuardConfigured  = $null
                                CredentialGuardRunning     = $null
                                NTLMAuditingEnabled        = $null
                                Indicator                  = 'Process accessed LSASS memory, potentially indicating credential theft or patching activity.'
                                Recommendation             = 'Investigate source process and account immediately; isolate host if malicious tools are confirmed.'
                            })
                    } #end foreach
                } catch {
                    Write-Warning -Message ('Failed LSASS telemetry query on {0}: {1}' -f $DomainController, $_.Exception.Message)
                } #end try-catch
            } #end foreach

            Write-Progress -Activity 'Skeleton Key Detection Audit' -Status 'Phase 3/5: Service installation anomalies' -PercentComplete 55

            # =============================================
            # PHASE 3: SERVICE INSTALLATION EVENTS (7045)
            # =============================================
            foreach ($DomainController in $DomainControllersToScan) {
                try {
                    $Event7045List = Get-WinEvent -ComputerName $DomainController -FilterHashtable @{
                        LogName   = 'System'
                        Id        = 7045
                        StartTime = $StartDate
                    } -ErrorAction SilentlyContinue

                    foreach ($Event7045 in $Event7045List) {
                        [xml]$EventXml = $Event7045.ToXml()

                        $ServiceName = ($EventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'ServiceName' } | Select-Object -First 1).'#text'
                        $ImagePath = ($EventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'ImagePath' } | Select-Object -First 1).'#text'
                        $InstalledBy = ($EventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'AccountName' } | Select-Object -First 1).'#text'

                        if ($ServiceName -match 'PSEXESVC|mimikatz|lsass' -or
                            $ImagePath -match 'temp|downloads|users') {

                            [void]$Findings.Add([PSCustomObject]@{
                                    PSTypeName                 = 'EguibarIT.SkeletonKeyDetection.Finding'
                                    Timestamp                  = $Event7045.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                                    FindingType                = 'Suspicious Service Installation'
                                    RiskLevel                  = 'High'
                                    DomainController           = $DomainController
                                    EventID                    = 7045
                                    SourceProcess              = $null
                                    SourceUser                 = $null
                                    GrantedAccess              = $null
                                    SourceIP                   = $null
                                    UniqueUserCount            = $null
                                    NTLMEventCount             = $null
                                    ServiceName                = $ServiceName
                                    ServicePath                = $ImagePath
                                    AccountName                = $InstalledBy
                                    CredentialGuardConfigured  = $null
                                    CredentialGuardRunning     = $null
                                    NTLMAuditingEnabled        = $null
                                    Indicator                  = 'Suspicious service deployment pattern may indicate remote staging or malicious tooling.'
                                    Recommendation             = 'Validate service provenance and remove unauthorized services from domain controllers.'
                                })
                        } #end if
                    } #end foreach
                } catch {
                    Write-Warning -Message ('Failed Event 7045 query on {0}: {1}' -f $DomainController, $_.Exception.Message)
                } #end try-catch
            } #end foreach

            Write-Progress -Activity 'Skeleton Key Detection Audit' -Status 'Phase 4/5: Authentication anomalies' -PercentComplete 75

            # =============================================
            # PHASE 4: AUTHENTICATION ANOMALIES (4624)
            # =============================================
            foreach ($DomainController in $DomainControllersToScan) {
                try {
                    $Event4624List = Get-WinEvent -ComputerName $DomainController -FilterHashtable @{
                        LogName   = 'Security'
                        Id        = 4624
                        StartTime = $StartDate
                    } -MaxEvents 10000 -ErrorAction SilentlyContinue

                    [System.Collections.ArrayList]$ParsedLogons = @()
                    foreach ($Event4624 in $Event4624List) {
                        [xml]$EventXml = $Event4624.ToXml()

                        $TargetUser = ($EventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' } | Select-Object -First 1).'#text'
                        $IpAddress = ($EventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' } | Select-Object -First 1).'#text'

                        if ([string]::IsNullOrWhiteSpace($IpAddress) -or
                            $IpAddress -eq '-' -or
                            $IpAddress -eq '127.0.0.1') {
                            continue
                        } #end if

                        [void]$ParsedLogons.Add([PSCustomObject]@{
                                TargetUserName = $TargetUser
                                IpAddress      = $IpAddress
                            })
                    } #end foreach

                    $GroupedByIp = $ParsedLogons | Group-Object -Property IpAddress
                    foreach ($IpGroup in $GroupedByIp) {
                        $UniqueUsers = @($IpGroup.Group | Select-Object -ExpandProperty TargetUserName -Unique).Count
                        if ($UniqueUsers -ge 5) {
                            [void]$Findings.Add([PSCustomObject]@{
                                    PSTypeName                 = 'EguibarIT.SkeletonKeyDetection.Finding'
                                    Timestamp                  = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                                    FindingType                = 'Multiple Users from Single IP'
                                    RiskLevel                  = 'High'
                                    DomainController           = $DomainController
                                    EventID                    = 4624
                                    SourceProcess              = $null
                                    SourceUser                 = $null
                                    GrantedAccess              = $null
                                    SourceIP                   = $IpGroup.Name
                                    UniqueUserCount            = $UniqueUsers
                                    NTLMEventCount             = $null
                                    ServiceName                = $null
                                    ServicePath                = $null
                                    AccountName                = $null
                                    CredentialGuardConfigured  = $null
                                    CredentialGuardRunning     = $null
                                    NTLMAuditingEnabled        = $null
                                    Indicator                  = 'Single source IP authenticated as many accounts in analysis window.'
                                    Recommendation             = 'Investigate source host and account activity for potential lateral movement/backdoor abuse.'
                                })
                        } #end if
                    } #end foreach
                } catch {
                    Write-Warning -Message ('Failed Event 4624 analysis on {0}: {1}' -f $DomainController, $_.Exception.Message)
                } #end try-catch
            } #end foreach

            Write-Progress -Activity 'Skeleton Key Detection Audit' -Status 'Phase 5/5: NTLM auditing and anomalies' -PercentComplete 90

            # =============================================
            # PHASE 5: NTLM AUDITING / ANOMALIES
            # =============================================
            foreach ($DomainController in $DomainControllersToScan) {
                try {
                    $NtlmAuditEnabled = Invoke-Command -ComputerName $DomainController -ScriptBlock {
                        $AuditSetting = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'AuditReceivingNTLMTraffic' -ErrorAction SilentlyContinue
                        if ($null -eq $AuditSetting) {
                            return $false
                        }

                        return ($AuditSetting.AuditReceivingNTLMTraffic -eq 2)
                    } -ErrorAction SilentlyContinue

                    if (-not $NtlmAuditEnabled) {
                        [void]$Findings.Add([PSCustomObject]@{
                                PSTypeName                 = 'EguibarIT.SkeletonKeyDetection.Finding'
                                Timestamp                  = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                                FindingType                = 'NTLM Auditing Disabled'
                                RiskLevel                  = 'Medium'
                                DomainController           = $DomainController
                                EventID                    = $null
                                SourceProcess              = $null
                                SourceUser                 = $null
                                GrantedAccess              = $null
                                SourceIP                   = $null
                                UniqueUserCount            = $null
                                NTLMEventCount             = $null
                                ServiceName                = $null
                                ServicePath                = $null
                                AccountName                = $null
                                CredentialGuardConfigured  = $null
                                CredentialGuardRunning     = $null
                                NTLMAuditingEnabled        = $false
                                Indicator                  = 'NTLM auditing is disabled, reducing visibility for suspicious NTLM authentication.'
                                Recommendation             = 'Enable NTLM auditing and forward operational logs to monitoring systems.'
                            })
                        continue
                    } #end if

                    $NtlmEvents = Get-WinEvent -ComputerName $DomainController -LogName 'Microsoft-Windows-NTLM/Operational' -FilterXPath '*[System[EventID=8004]]' -MaxEvents 1000 -ErrorAction SilentlyContinue
                    [System.Collections.ArrayList]$ParsedNtlm = @()

                    foreach ($NtlmEvent in $NtlmEvents) {
                        [xml]$EventXml = $NtlmEvent.ToXml()
                        $UserName = ($EventXml.Event.EventData.Data | Select-Object -First 1).'#text'

                        if ([string]::IsNullOrWhiteSpace($UserName)) {
                            continue
                        } #end if

                        [void]$ParsedNtlm.Add([PSCustomObject]@{
                                UserName = $UserName
                            })
                    } #end foreach

                    $NtlmByUser = $ParsedNtlm | Group-Object -Property UserName
                    foreach ($UserGroup in $NtlmByUser) {
                        if ($UserGroup.Name -match 'admin|krbtgt|service|root') {
                            [void]$Findings.Add([PSCustomObject]@{
                                    PSTypeName                 = 'EguibarIT.SkeletonKeyDetection.Finding'
                                    Timestamp                  = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                                    FindingType                = 'Privileged Account NTLM Usage'
                                    RiskLevel                  = 'Medium'
                                    DomainController           = $DomainController
                                    EventID                    = 8004
                                    SourceProcess              = $null
                                    SourceUser                 = $null
                                    GrantedAccess              = $null
                                    SourceIP                   = $null
                                    UniqueUserCount            = $null
                                    NTLMEventCount             = $UserGroup.Count
                                    ServiceName                = $null
                                    ServicePath                = $null
                                    AccountName                = $UserGroup.Name
                                    CredentialGuardConfigured  = $null
                                    CredentialGuardRunning     = $null
                                    NTLMAuditingEnabled        = $true
                                    Indicator                  = 'Privileged account used NTLM authentication where Kerberos is typically expected.'
                                    Recommendation             = 'Investigate account and endpoint context; validate protocol hardening controls.'
                                })
                        } #end if
                    } #end foreach
                } catch {
                    Write-Warning -Message ('Failed NTLM analysis on {0}: {1}' -f $DomainController, $_.Exception.Message)
                } #end try-catch
            } #end foreach

            [int]$CriticalCount = @($Findings | Where-Object { $_.RiskLevel -eq 'Critical' }).Count
            [int]$HighCount = @($Findings | Where-Object { $_.RiskLevel -eq 'High' }).Count
            [int]$MediumCount = @($Findings | Where-Object { $_.RiskLevel -eq 'Medium' }).Count

            if ($CriticalCount -gt 0) {
                [void]$RecommendedActions.Add('IMMEDIATE: Investigate and contain critical Skeleton Key indicators on affected domain controllers.')
                [void]$RecommendedActions.Add('Reboot affected domain controllers to clear memory-resident tampering after IR validation.')
                [void]$RecommendedActions.Add('Enable Credential Guard and verify secure boot/VBS prerequisites across all domain controllers.')
            } #end if

            if ($HighCount -gt 0) {
                [void]$RecommendedActions.Add('Deploy Sysmon with robust LSASS monitoring and review suspicious service installation activity.')
                [void]$RecommendedActions.Add('Investigate source systems with multi-user authentication behavior from single IP addresses.')
            } #end if

            if ($MediumCount -gt 0) {
                [void]$RecommendedActions.Add('Enable NTLM auditing and reduce privileged NTLM usage through Kerberos-first policy hardening.')
            } #end if

            if ($Findings.Count -eq 0) {
                [void]$RecommendedActions.Add('No Skeleton Key indicators detected in current window; continue periodic monitoring and hardening checks.')
            } #end if

            if ($PSCmdlet.ShouldProcess($OutputPath, 'Export Skeleton Key detection reports')) {
                if (-not (Test-Path -Path $OutputPath)) {
                    New-Item -Path $OutputPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
                    Write-Verbose -Message ('Created output directory: {0}' -f $OutputPath)
                } #end if

                [string]$TimestampSuffix = (Get-Date -Format 'yyyyMMdd-HHmmss')
                [string]$CsvPath = Join-Path -Path $OutputPath -ChildPath ('SkeletonKey-Detection-{0}.csv' -f $TimestampSuffix)
                [string]$JsonPath = Join-Path -Path $OutputPath -ChildPath ('SkeletonKey-Detection-{0}.json' -f $TimestampSuffix)

                $Findings | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8 -Force
                $Findings | ConvertTo-Json -Depth 6 | Out-File -FilePath $JsonPath -Encoding UTF8 -Force

                [void]$ExportedReports.Add($CsvPath)
                [void]$ExportedReports.Add($JsonPath)
            } #end if

            Write-Progress -Activity 'Skeleton Key Detection Audit' -Completed

            [PSCustomObject]$Result = [PSCustomObject]@{
                PSTypeName             = 'EguibarIT.SkeletonKeyDetection'
                AuditTimestamp         = $AuditTimestamp
                AnalysisWindowDays     = $DaysBack
                DomainControllersScanned = $DomainControllersToScan.Count
                CheckedAllDomainControllers = $CheckAllDCs.IsPresent
                TotalFindings          = $Findings.Count
                CriticalCount          = $CriticalCount
                HighCount              = $HighCount
                MediumCount            = $MediumCount
                IsCompromiseLikely     = ($CriticalCount -gt 0)
                Findings               = $Findings
                RecommendedActions     = $RecommendedActions
                ExportedReports        = $ExportedReports
            }

            Write-Output -InputObject $Result
        } catch {
            Write-Error -Message ('Failed to execute Skeleton Key detection: {0}' -f $_.Exception.Message)
            throw
        } #end try-catch
    } #end Process

    end {
        if ($null -ne $Variables -and
            $null -ne $Variables.FooterSecurity) {

            $txt = ($Variables.FooterSecurity -f
                $MyInvocation.InvocationName,
                'finished auditing Skeleton Key indicators.'
            )
            Write-Verbose -Message $txt
        } #end If
    } #end End
} #end Function Get-SkeletonKeyDetection
