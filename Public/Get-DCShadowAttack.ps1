function Get-DCShadowAttack {
    <#
        .SYNOPSIS
            Detects DCShadow attack indicators by auditing rogue domain controller registration and replication anomalies.

        .DESCRIPTION
            Performs a comprehensive five-phase DCShadow detection audit:

            **Phase 1 - BASELINE DOMAIN CONTROLLERS:**
            Enumerates legitimate domain controllers and validates DC computer account placement.
            Flags computer objects with PrimaryGroupID=516 outside the Domain Controllers OU.

            **Phase 2 - ROGUE DC REGISTRATION EVENTS:**
            Analyzes Security Events 5137/5141/4742 for suspicious server object creation,
            replication partner registrations, and replication SPN assignments on non-DC accounts.

            **Phase 3 - REPLICATION METADATA ANOMALIES:**
            Audits privileged objects and AdminSDHolder replication metadata for unknown
            originating directory servers not present in the legitimate DC baseline.

            **Phase 4 - PRIVILEGED ACCOUNTS WITHOUT CREATION EVENTS:**
            Identifies privileged accounts with no corresponding Event 4720 evidence in the
            analysis window, which may indicate out-of-band object creation.

            **Phase 5 - ADMINSDHOLDER CHANGE MONITORING:**
            Detects Event 5136 modifications targeting AdminSDHolder, a common persistence vector.

            **ATTACK VECTOR:**
            DCShadow enables attackers to register rogue DC objects and replicate unauthorized
            directory changes while bypassing many conventional account-management event trails.

            **MITRE ATT&CK Mapping:**
            - **T1207:** Rogue Domain Controller
            - **T1484.001:** Domain Policy Modification - Group Policy Modification
            - **T1098:** Account Manipulation

            **DETECTION REQUIREMENTS:**
            - Domain Admin or equivalent read access to AD and Security logs on DCs
            - ActiveDirectory module available
            - Security auditing enabled for relevant Event IDs (4720, 4742, 5136, 5137, 5141)

        .PARAMETER OutputPath
            Directory path where CSV and JSON detection reports are exported.
            If omitted, results are returned to pipeline without writing files.

            The export operation respects -WhatIf and -Confirm parameters.

        .PARAMETER DaysBack
            Number of days to analyze event logs and replication metadata.
            Valid range is 1 to 365 days.

        .PARAMETER IncludeEvents
            If specified, includes raw event samples in the output object.
            This can increase memory usage and export size in large environments.

        .EXAMPLE
            Get-DCShadowAttack

            Description
            -----------
            Runs DCShadow detection with default 30-day analysis window and returns structured findings.

        .EXAMPLE
            Get-DCShadowAttack -DaysBack 90 -Verbose

            Description
            -----------
            Performs extended historical analysis and writes detailed progress information.

        .EXAMPLE
            Get-DCShadowAttack -OutputPath 'C:\SecurityAudits\DCShadow' -DaysBack 60

            Description
            -----------
            Exports findings to CSV and JSON reports in the specified directory.

        .EXAMPLE
            $Result = Get-DCShadowAttack -DaysBack 14
            if ($Result.CriticalCount -gt 0) {
                Write-Warning ('CRITICAL: {0} high-confidence DCShadow indicators found.' -f $Result.CriticalCount)
            }

            Description
            -----------
            Integrates audit results into automated triage workflows.

        .INPUTS
            None. This function does not accept pipeline input.

        .OUTPUTS
            PSCustomObject. Returns DCShadow audit summary including:
            - AuditTimestamp
            - AnalysisWindowDays
            - DomainControllerCount
            - TotalFindings
            - CriticalCount
            - HighCount
            - MediumCount
            - IsCompromiseLikely
            - Findings
            - RecommendedActions
            - ExportedReports

        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Get-ADDomainController                 | ActiveDirectory
                Get-ADComputer                         | ActiveDirectory
                Get-ADGroupMember                      | ActiveDirectory
                Get-ADUser                             | ActiveDirectory
                Get-ADRootDSE                          | ActiveDirectory
                Get-ADReplicationAttributeMetadata     | ActiveDirectory
                Get-WinEvent                           | Microsoft.PowerShell.Diagnostics
                Test-Path                              | Microsoft.PowerShell.Management
                New-Item                               | Microsoft.PowerShell.Management
                Export-Csv                             | Microsoft.PowerShell.Utility
                ConvertTo-Json                         | Microsoft.PowerShell.Utility
                Out-File                               | Microsoft.PowerShell.Utility
                Write-Verbose                          | Microsoft.PowerShell.Utility
                Write-Warning                          | Microsoft.PowerShell.Utility
                Write-Progress                         | Microsoft.PowerShell.Utility
                Write-Error                            | Microsoft.PowerShell.Utility
                Write-Output                           | Microsoft.PowerShell.Utility
                Get-FunctionDisplay                    | EguibarIT.SecurityPS

        .NOTES
            Version:         1.0.0
            DateModified:    04/Mar/2026
            LastModifiedBy:  Vicente Rodriguez Eguibar
                vicente@eguibar.com
                EguibarIT
                http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT.SecurityPS

        .LINK
            https://www.dcshadow.com/

        .COMPONENT
            EguibarIT.SecurityPS

        .ROLE
            Security Auditing

        .FUNCTIONALITY
            Detects DCShadow-related indicators by combining AD state validation,
            event log analysis, and replication metadata anomaly detection.
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
            HelpMessage = 'Directory where detection results are exported in CSV and JSON format',
            Position = 0
        )]
        [ValidateNotNullOrEmpty()]
        [Alias('ExportPath', 'Path')]
        [string]
        $OutputPath,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Number of days to analyze event logs and replication metadata',
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
            HelpMessage = 'Include raw event samples in output (large environments may produce large objects)',
            Position = 2
        )]
        [switch]
        $IncludeEvents
    )

    Begin {
        Set-StrictMode -Version Latest

        [datetime]$StartDate = (Get-Date).AddDays(-$DaysBack)
        [datetime]$AuditTimestamp = Get-Date

        [System.Collections.ArrayList]$Findings = @()
        [System.Collections.ArrayList]$RecommendedActions = @()
        [System.Collections.ArrayList]$ExportedReports = @()
        [System.Collections.ArrayList]$RawEvents = @()

        [System.Collections.ArrayList]$LegitimateDCNames = @()
        [System.Collections.ArrayList]$LegitimateDCHostNames = @()
        [System.Collections.ArrayList]$LegitimateDCs = @()

        # Display function header if variables exist
        if ($null -ne $Variables -and
            $null -ne $Variables.HeaderSecurity) {

            $txt = ($Variables.HeaderSecurity -f
                $MyInvocation.InvocationName,
                (Get-FunctionDisplay -Hashtable $PsBoundParameters -Verbose:$False)
            )
            Write-Verbose -Message $txt
        } #end if

        Write-Verbose -Message ('Starting DCShadow detection. Analysis window starts at {0}' -f $StartDate)
    } #end Begin

    Process {
        try {
            Write-Progress -Activity 'DCShadow Detection Audit' -Status 'Phase 1/5: Building DC baseline' -PercentComplete 10

            # =============================================
            # PHASE 1: BASELINE LEGITIMATE DOMAIN CONTROLLERS
            # =============================================
            try {
                Write-Verbose -Message '[Phase 1] Building baseline of legitimate domain controllers.'

                $DCList = Get-ADDomainController -Filter * -ErrorAction Stop |
                    Select-Object -Property Name, HostName, IPv4Address, Site

                foreach ($DC in $DCList) {
                    if (-not [string]::IsNullOrWhiteSpace($DC.Name)) {
                        [void]$LegitimateDCNames.Add($DC.Name)
                    } #end if

                    if (-not [string]::IsNullOrWhiteSpace($DC.HostName)) {
                        [void]$LegitimateDCHostNames.Add($DC.HostName)
                    } #end if

                    [void]$LegitimateDCs.Add($DC)
                } #end foreach

                Write-Verbose -Message ('Baseline includes {0} domain controller(s).' -f $LegitimateDCs.Count)

                $DCComputerAccounts = Get-ADComputer -Filter { PrimaryGroupID -eq 516 } -Properties DistinguishedName -ErrorAction Stop

                foreach ($DCComputer in $DCComputerAccounts) {
                    if ($DCComputer.DistinguishedName -notmatch 'OU=Domain Controllers') {
                        $RogueDCFinding = [PSCustomObject]@{
                            PSTypeName         = 'EguibarIT.DCShadowAttack.Finding'
                            Timestamp          = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                            FindingType        = 'Rogue DC Computer Account'
                            RiskLevel          = 'Critical'
                            DomainController   = $null
                            EventID            = $null
                            ObjectName         = $DCComputer.Name
                            DistinguishedName  = $DCComputer.DistinguishedName
                            OriginatingDC      = $null
                            Indicator          = 'Computer object with PrimaryGroupID=516 exists outside Domain Controllers OU'
                            Recommendation     = 'Investigate immediately and validate whether object is unauthorized or stale DCShadow artifact'
                        }

                        [void]$Findings.Add($RogueDCFinding)
                        Write-Warning -Message ('Rogue DC computer account detected: {0}' -f $DCComputer.DistinguishedName)
                    } #end if
                } #end foreach
            } catch {
                Write-Error -Message ('Failed to baseline domain controllers: {0}' -f $_.Exception.Message) -ErrorAction Stop
            } #end try-catch

            if ($LegitimateDCs.Count -eq 0) {
                Write-Error -Message 'No domain controllers found in baseline. Aborting analysis.' -ErrorAction Stop
            } #end if

            Write-Progress -Activity 'DCShadow Detection Audit' -Status 'Phase 2/5: Scanning registration events' -PercentComplete 35

            # =============================================
            # PHASE 2: MONITOR FOR ROGUE DC REGISTRATION EVENTS
            # =============================================
            foreach ($DC in $LegitimateDCs) {
                [string]$DCHost = $DC.HostName

                if ([string]::IsNullOrWhiteSpace($DCHost)) {
                    continue
                } #end if

                Write-Verbose -Message ('[Phase 2] Querying security events from {0}' -f $DCHost)

                try {
                    [hashtable]$Splat5137 = @{
                        ComputerName    = $DCHost
                        FilterHashtable = @{
                            LogName   = 'Security'
                            Id        = 5137
                            StartTime = $StartDate
                        }
                        ErrorAction     = 'SilentlyContinue'
                    }

                    $Events5137 = Get-WinEvent @Splat5137 | Where-Object { $_.Message -match 'objectClass.*server|objectClass.*nTDSDSA' }

                    foreach ($Event5137 in $Events5137) {
                        $EventXml = [xml]$Event5137.ToXml()
                        $ObjectDN = ($EventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'ObjectDN' }).'#text'
                        $ObjectClass = ($EventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'ObjectClass' }).'#text'
                        $SubjectUserName = ($EventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'

                        $Finding = [PSCustomObject]@{
                            PSTypeName        = 'EguibarIT.DCShadowAttack.Finding'
                            Timestamp         = $Event5137.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                            FindingType       = 'Server Object Creation'
                            RiskLevel         = 'High'
                            DomainController  = $DCHost
                            EventID           = 5137
                            ObjectName        = $null
                            DistinguishedName = $ObjectDN
                            OriginatingDC     = $null
                            Indicator         = 'New server/nTDSDSA object created (possible DCShadow registration step)'
                            Recommendation    = 'Validate object creation against approved DC provisioning operations'
                            SubjectUserName   = $SubjectUserName
                            ObjectClass       = $ObjectClass
                        }

                        [void]$Findings.Add($Finding)
                        if ($IncludeEvents.IsPresent) { [void]$RawEvents.Add($Event5137) }
                    } #end foreach

                    [hashtable]$Splat5141 = @{
                        ComputerName    = $DCHost
                        FilterHashtable = @{
                            LogName   = 'Security'
                            Id        = 5141
                            StartTime = $StartDate
                        }
                        ErrorAction     = 'SilentlyContinue'
                    }

                    $Events5141 = Get-WinEvent @Splat5141

                    foreach ($Event5141 in $Events5141) {
                        $EventXml = [xml]$Event5141.ToXml()
                        $ObjectDN = ($EventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'ObjectDN' }).'#text'

                        if ($ObjectDN -match 'CN=Servers,CN=') {
                            $SubjectUserName = ($EventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'

                            $Finding = [PSCustomObject]@{
                                PSTypeName        = 'EguibarIT.DCShadowAttack.Finding'
                                Timestamp         = $Event5141.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                                FindingType       = 'Replication Partner Registration'
                                RiskLevel         = 'Critical'
                                DomainController  = $DCHost
                                EventID           = 5141
                                ObjectName        = $null
                                DistinguishedName = $ObjectDN
                                OriginatingDC     = $null
                                Indicator         = 'Replication partner object created under CN=Servers (high-confidence DCShadow signal)'
                                Recommendation    = 'Immediate incident response: validate if object is rogue and isolate source'
                                SubjectUserName   = $SubjectUserName
                            }

                            [void]$Findings.Add($Finding)
                            if ($IncludeEvents.IsPresent) { [void]$RawEvents.Add($Event5141) }
                        } #end if
                    } #end foreach

                    [hashtable]$Splat4742 = @{
                        ComputerName    = $DCHost
                        FilterHashtable = @{
                            LogName   = 'Security'
                            Id        = 4742
                            StartTime = $StartDate
                        }
                        ErrorAction     = 'SilentlyContinue'
                    }

                    $Events4742 = Get-WinEvent @Splat4742

                    foreach ($Event4742 in $Events4742) {
                        $EventXml = [xml]$Event4742.ToXml()
                        $TargetAccount = ($EventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
                        $SubjectUserName = ($EventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'

                        if ($Event4742.Message -match 'ServicePrincipalNames.*(GC/|E3514235-4B06-11D1-AB04-00C04FC2DCD2/)') {
                            if ($TargetAccount -notin $LegitimateDCNames) {
                                $Finding = [PSCustomObject]@{
                                    PSTypeName        = 'EguibarIT.DCShadowAttack.Finding'
                                    Timestamp         = $Event4742.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                                    FindingType       = 'Unauthorized Replication SPN'
                                    RiskLevel         = 'Critical'
                                    DomainController  = $DCHost
                                    EventID           = 4742
                                    ObjectName        = $TargetAccount
                                    DistinguishedName = $null
                                    OriginatingDC     = $null
                                    Indicator         = 'Replication SPN registered on account not present in DC baseline'
                                    Recommendation    = 'Immediate investigation: remove unauthorized SPN and validate account compromise'
                                    SubjectUserName   = $SubjectUserName
                                }

                                [void]$Findings.Add($Finding)
                                if ($IncludeEvents.IsPresent) { [void]$RawEvents.Add($Event4742) }
                            } #end if
                        } #end if
                    } #end foreach

                } catch {
                    Write-Warning -Message ('Failed to query events from {0}: {1}' -f $DCHost, $_.Exception.Message)
                } #end try-catch
            } #end foreach

            Write-Progress -Activity 'DCShadow Detection Audit' -Status 'Phase 3/5: Auditing replication metadata' -PercentComplete 60

            # =============================================
            # PHASE 3: AUDIT AD REPLICATION METADATA FOR UNKNOWN DCs
            # =============================================
            try {
                [System.Collections.ArrayList]$CriticalObjects = @()

                [string[]]$PrivilegedGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins')
                foreach ($Group in $PrivilegedGroups) {
                    try {
                        $Members = Get-ADGroupMember -Identity $Group -Recursive -ErrorAction SilentlyContinue |
                            Where-Object { $_.objectClass -eq 'user' }

                        foreach ($Member in $Members) {
                            $ADUser = Get-ADUser -Identity $Member.SamAccountName -Properties DistinguishedName, SamAccountName -ErrorAction SilentlyContinue
                            if ($null -ne $ADUser) {
                                [void]$CriticalObjects.Add($ADUser)
                            } #end if
                        } #end foreach
                    } catch {
                        Write-Verbose -Message ('Skipping group {0}: {1}' -f $Group, $_.Exception.Message)
                    } #end try-catch
                } #end foreach

                $RootDSE = Get-ADRootDSE -ErrorAction Stop
                [string]$DomainDN = $RootDSE.defaultNamingContext
                [string]$AdminSDHolderDN = 'CN=AdminSDHolder,CN=System,{0}' -f $DomainDN

                foreach ($CriticalObject in $CriticalObjects) {
                    if ([string]::IsNullOrWhiteSpace($CriticalObject.DistinguishedName)) {
                        continue
                    } #end if

                    try {
                        $Metadata = Get-ADReplicationAttributeMetadata -Object $CriticalObject.DistinguishedName -Server $LegitimateDCs[0].HostName -ErrorAction Stop

                        foreach ($AttributeMetadata in $Metadata) {
                            $OriginatingDC = $AttributeMetadata.LastOriginatingChangeDirectoryServerIdentity

                            if ($OriginatingDC -notin $LegitimateDCNames -and $OriginatingDC -notin $LegitimateDCHostNames) {
                                $Finding = [PSCustomObject]@{
                                    PSTypeName        = 'EguibarIT.DCShadowAttack.Finding'
                                    Timestamp         = $AttributeMetadata.LastOriginatingChangeTime.ToString('yyyy-MM-dd HH:mm:ss')
                                    FindingType       = 'Unknown Originating DC in Replication Metadata'
                                    RiskLevel         = 'Critical'
                                    DomainController  = $null
                                    EventID           = $null
                                    ObjectName        = $CriticalObject.SamAccountName
                                    DistinguishedName = $CriticalObject.DistinguishedName
                                    OriginatingDC     = $OriginatingDC
                                    Indicator         = 'Privileged object attribute modified by unknown originating directory server'
                                    Recommendation    = 'Immediate forensic validation of replication source and object integrity'
                                    AttributeName     = $AttributeMetadata.AttributeName
                                    Version           = $AttributeMetadata.Version
                                }

                                [void]$Findings.Add($Finding)
                            } #end if
                        } #end foreach
                    } catch {
                        Write-Verbose -Message ('Failed metadata retrieval for {0}: {1}' -f $CriticalObject.SamAccountName, $_.Exception.Message)
                    } #end try-catch
                } #end foreach

                try {
                    $AdminMetadata = Get-ADReplicationAttributeMetadata -Object $AdminSDHolderDN -Server $LegitimateDCs[0].HostName -ErrorAction Stop

                    foreach ($AttributeMetadata in $AdminMetadata) {
                        $OriginatingDC = $AttributeMetadata.LastOriginatingChangeDirectoryServerIdentity

                        if ($OriginatingDC -notin $LegitimateDCNames -and $OriginatingDC -notin $LegitimateDCHostNames) {
                            $Finding = [PSCustomObject]@{
                                PSTypeName        = 'EguibarIT.DCShadowAttack.Finding'
                                Timestamp         = $AttributeMetadata.LastOriginatingChangeTime.ToString('yyyy-MM-dd HH:mm:ss')
                                FindingType       = 'AdminSDHolder Modified by Unknown DC'
                                RiskLevel         = 'Critical'
                                DomainController  = $null
                                EventID           = $null
                                ObjectName        = 'AdminSDHolder'
                                DistinguishedName = $AdminSDHolderDN
                                OriginatingDC     = $OriginatingDC
                                Indicator         = 'AdminSDHolder attribute changed by unknown originating directory server'
                                Recommendation    = 'Urgent remediation: validate AdminSDHolder ACL and restore known-good state'
                                AttributeName     = $AttributeMetadata.AttributeName
                            }

                            [void]$Findings.Add($Finding)
                        } #end if
                    } #end foreach
                } catch {
                    Write-Warning -Message ('Failed to audit AdminSDHolder replication metadata: {0}' -f $_.Exception.Message)
                } #end try-catch

            } catch {
                Write-Warning -Message ('Failed replication metadata audit: {0}' -f $_.Exception.Message)
            } #end try-catch

            Write-Progress -Activity 'DCShadow Detection Audit' -Status 'Phase 4/5: Checking privileged account provenance' -PercentComplete 80

            # =============================================
            # PHASE 4: DETECT PRIVILEGED ACCOUNTS WITHOUT CREATION EVENTS
            # =============================================
            try {
                [string[]]$PrivilegedGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators')
                [System.Collections.ArrayList]$PrivilegedAccounts = @()

                foreach ($Group in $PrivilegedGroups) {
                    try {
                        $Members = Get-ADGroupMember -Identity $Group -Recursive -ErrorAction SilentlyContinue |
                            Where-Object { $_.objectClass -eq 'user' }

                        foreach ($Member in $Members) {
                            if ($null -ne $Member.SamAccountName) {
                                [void]$PrivilegedAccounts.Add($Member.SamAccountName)
                            } #end if
                        } #end foreach
                    } catch {
                        Write-Verbose -Message ('Failed to enumerate group {0}: {1}' -f $Group, $_.Exception.Message)
                    } #end try-catch
                } #end foreach

                $UniquePrivilegedAccounts = $PrivilegedAccounts | Select-Object -Unique

                foreach ($AccountName in $UniquePrivilegedAccounts) {
                    $CreationEventFound = $false

                    foreach ($DC in $LegitimateDCs) {
                        try {
                            [hashtable]$Splat4720 = @{
                                ComputerName    = $DC.HostName
                                FilterHashtable = @{
                                    LogName   = 'Security'
                                    Id        = 4720
                                    StartTime = $StartDate
                                }
                                ErrorAction     = 'SilentlyContinue'
                            }

                            $CreationEvent = Get-WinEvent @Splat4720 | Where-Object {
                                $_.Message -match [regex]::Escape($AccountName)
                            } | Select-Object -First 1

                            if ($null -ne $CreationEvent) {
                                $CreationEventFound = $true
                                break
                            } #end if
                        } catch {
                            Write-Verbose -Message ('Failed 4720 query on {0}: {1}' -f $DC.HostName, $_.Exception.Message)
                        } #end try-catch
                    } #end foreach

                    if (-not $CreationEventFound) {
                        $UserDetails = Get-ADUser -Identity $AccountName -Properties whenCreated, PasswordLastSet, DistinguishedName -ErrorAction SilentlyContinue

                        if ($null -ne $UserDetails) {
                            $Finding = [PSCustomObject]@{
                                PSTypeName        = 'EguibarIT.DCShadowAttack.Finding'
                                Timestamp         = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                                FindingType       = 'Privileged Account Without Creation Event'
                                RiskLevel         = 'High'
                                DomainController  = $null
                                EventID           = 4720
                                ObjectName        = $AccountName
                                DistinguishedName = $UserDetails.DistinguishedName
                                OriginatingDC     = $null
                                Indicator         = 'Privileged account exists without matching Event 4720 in analysis window'
                                Recommendation    = 'Validate account lifecycle, retention window, and potential unauthorized object creation'
                                WhenCreated       = $UserDetails.whenCreated
                                PasswordLastSet   = $UserDetails.PasswordLastSet
                            }

                            [void]$Findings.Add($Finding)
                        } #end if
                    } #end if
                } #end foreach
            } catch {
                Write-Warning -Message ('Failed privileged account provenance analysis: {0}' -f $_.Exception.Message)
            } #end try-catch

            Write-Progress -Activity 'DCShadow Detection Audit' -Status 'Phase 5/5: Auditing AdminSDHolder changes' -PercentComplete 95

            # =============================================
            # PHASE 5: MONITOR ADMINSDHOLDER MODIFICATIONS (Event 5136)
            # =============================================
            foreach ($DC in $LegitimateDCs) {
                [string]$DCHost = $DC.HostName

                if ([string]::IsNullOrWhiteSpace($DCHost)) {
                    continue
                } #end if

                try {
                    [hashtable]$Splat5136 = @{
                        ComputerName    = $DCHost
                        FilterHashtable = @{
                            LogName   = 'Security'
                            Id        = 5136
                            StartTime = $StartDate
                        }
                        ErrorAction     = 'SilentlyContinue'
                    }

                    $AdminSDHolderEvents = Get-WinEvent @Splat5136 | Where-Object {
                        $_.Message -match 'CN=AdminSDHolder,CN=System'
                    }

                    foreach ($AdminEvent in $AdminSDHolderEvents) {
                        $EventXml = [xml]$AdminEvent.ToXml()
                        $AttributeName = ($EventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'AttributeLDAPDisplayName' }).'#text'
                        $SubjectUserName = ($EventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'

                        $Finding = [PSCustomObject]@{
                            PSTypeName        = 'EguibarIT.DCShadowAttack.Finding'
                            Timestamp         = $AdminEvent.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                            FindingType       = 'AdminSDHolder Modification'
                            RiskLevel         = 'Critical'
                            DomainController  = $DCHost
                            EventID           = 5136
                            ObjectName        = 'AdminSDHolder'
                            DistinguishedName = 'CN=AdminSDHolder,CN=System'
                            OriginatingDC     = $null
                            Indicator         = 'AdminSDHolder modified (potential persistence path associated with DCShadow tradecraft)'
                            Recommendation    = 'Validate change authorization and restore baseline ACLs if unauthorized'
                            SubjectUserName   = $SubjectUserName
                            AttributeName     = $AttributeName
                        }

                        [void]$Findings.Add($Finding)
                        if ($IncludeEvents.IsPresent) { [void]$RawEvents.Add($AdminEvent) }
                    } #end foreach
                } catch {
                    Write-Warning -Message ('Failed to query AdminSDHolder changes from {0}: {1}' -f $DCHost, $_.Exception.Message)
                } #end try-catch
            } #end foreach

            Write-Progress -Activity 'DCShadow Detection Audit' -Completed

        } catch {
            Write-Error -Message ('DCShadow detection failed: {0}' -f $_.Exception.Message)
            throw
        } #end try-catch
    } #end Process

    End {
        try {
            [int]$CriticalCount = ($Findings | Where-Object { $_.RiskLevel -eq 'Critical' }).Count
            [int]$HighCount = ($Findings | Where-Object { $_.RiskLevel -eq 'High' }).Count
            [int]$MediumCount = ($Findings | Where-Object { $_.RiskLevel -eq 'Medium' }).Count

            if ($CriticalCount -gt 0) {
                [void]$RecommendedActions.Add('IMMEDIATE: Isolate suspected rogue hosts and validate server/nTDSDSA objects under CN=Configuration')
                [void]$RecommendedActions.Add('Review and remove unauthorized replication SPNs on non-DC accounts')
                [void]$RecommendedActions.Add('Audit and restore AdminSDHolder ACLs from a known-good baseline if tampering is confirmed')
            } #end if

            if ($HighCount -gt 0) {
                [void]$RecommendedActions.Add('Investigate privileged accounts without matching creation-event evidence within retention period')
            } #end if

            if ($RecommendedActions.Count -eq 0) {
                [void]$RecommendedActions.Add('No high-confidence DCShadow indicators found. Continue continuous monitoring and periodic audits.')
            } #end if

            if ($PSBoundParameters.ContainsKey('OutputPath') -and -not [string]::IsNullOrWhiteSpace($OutputPath)) {
                if ($PSCmdlet.ShouldProcess($OutputPath, 'Export DCShadow detection reports')) {
                    if (-not (Test-Path -Path $OutputPath)) {
                        [void](New-Item -Path $OutputPath -ItemType Directory -Force)
                    } #end if

                    [string]$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
                    [string]$CsvPath = Join-Path -Path $OutputPath -ChildPath ('DCShadow-Detection-{0}.csv' -f $Stamp)
                    [string]$JsonPath = Join-Path -Path $OutputPath -ChildPath ('DCShadow-Detection-{0}.json' -f $Stamp)

                    $Findings | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
                    $Findings | ConvertTo-Json -Depth 6 | Out-File -FilePath $JsonPath -Encoding UTF8

                    [void]$ExportedReports.Add($CsvPath)
                    [void]$ExportedReports.Add($JsonPath)
                } #end if
            } #end if

            $AuditResult = [PSCustomObject]@{
                PSTypeName          = 'EguibarIT.DCShadowAttack'
                AuditTimestamp      = $AuditTimestamp
                AnalysisWindowDays  = $DaysBack
                DomainControllerCount = $LegitimateDCs.Count
                TotalFindings       = $Findings.Count
                CriticalCount       = $CriticalCount
                HighCount           = $HighCount
                MediumCount         = $MediumCount
                IsCompromiseLikely  = ($CriticalCount -gt 0)
                Findings            = $Findings
                RecommendedActions  = $RecommendedActions
                ExportedReports     = $ExportedReports
                IncludedRawEvents   = if ($IncludeEvents.IsPresent) { $RawEvents } else { $null }
            }

            Write-Output -InputObject $AuditResult

            if ($null -ne $Variables -and
                $null -ne $Variables.FooterSecurity) {

                $txt = ($Variables.FooterSecurity -f $MyInvocation.InvocationName,
                    'finished auditing DCShadow attack indicators.'
                )
                Write-Verbose -Message $txt
            } #end if

        } catch {
            Write-Error -Message ('Failed to finalize DCShadow detection results: {0}' -f $_.Exception.Message)
            throw
        } #end try-catch
    } #end End

} #end Function Get-DCShadowAttack
