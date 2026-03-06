function Get-SIDHistoryInjectionAttack {
    <#
        .SYNOPSIS
            Detects SID History injection attack indicators by auditing sidHistory, related events, replication metadata, and trust SID filtering.

        .DESCRIPTION
            Performs a comprehensive five-phase SID History injection detection audit:

            **Phase 1 - SID HISTORY ENUMERATION:**
            Enumerates user and computer accounts with non-empty sidHistory attribute.

            **Phase 2 - PRIVILEGED SID HISTORY ANALYSIS:**
            Detects privileged identities present in SID History (Domain Admins, Enterprise Admins,
            Schema Admins, Administrator) using module Well-Known SID mappings.

            **Phase 3 - EVENT 4765 ANALYSIS:**
            Queries domain controllers for Event ID 4765 (SID History Added) in the specified window.

            **Phase 4 - REPLICATION METADATA AUDIT:**
            Detects sidHistory changes originating from unknown directory server identities,
            which may indicate DCShadow or unauthorized replication behavior.

            **Phase 5 - TRUST SID FILTERING STATUS (OPTIONAL):**
            Evaluates trust SID filtering configuration when -CheckTrusts is provided.

            **ATTACK VECTOR:**
            SID History can be abused to gain privileged access without direct privileged group membership.
            This bypasses many standard membership-centric monitoring controls.

            **MITRE ATT&CK Mapping:**
            - **T1134.005**: Access Token Manipulation - SID-History Injection
            - **T1484.001**: Domain Policy Modification (related trust abuse scenarios)

            **DETECTION REQUIREMENTS:**
            - Domain Admin or equivalent read permissions
            - ActiveDirectory module available
            - Access to Security logs on domain controllers (for Event 4765)

        .PARAMETER OutputPath
            Directory where detection results are exported in CSV and JSON format.
            Export operation respects -WhatIf and -Confirm.

        .PARAMETER DaysBack
            Number of days to analyze event logs for SID History modifications.
            Valid range: 1 to 365 days. Default is 90.

        .PARAMETER CheckTrusts
            Includes trust SID filtering status checks when specified.

        .EXAMPLE
            Get-SIDHistoryInjectionAttack

            Description
            -----------
            Runs SID History injection detection using default settings.

        .EXAMPLE
            Get-SIDHistoryInjectionAttack -DaysBack 180 -CheckTrusts -Verbose

            Description
            -----------
            Performs extended analysis and includes SID filtering checks for trusts.

        .EXAMPLE
            Get-SIDHistoryInjectionAttack -OutputPath 'C:\SIDHistoryAudit' -DaysBack 30

            Description
            -----------
            Runs a 30-day analysis and exports CSV/JSON reports.

        .EXAMPLE
            $Result = Get-SIDHistoryInjectionAttack -CheckTrusts
            if ($Result.CriticalCount -gt 0) {
                Write-Warning ('Critical SID History injection indicators found: {0}' -f $Result.CriticalCount)
            }

            Description
            -----------
            Integrates the output into automated triage workflows.

        .INPUTS
            None. This function does not accept pipeline input.

        .OUTPUTS
            PSCustomObject. Returns SID History injection audit summary including:
            - AuditTimestamp
            - AnalysisWindowDays
            - UsersWithSIDHistoryCount
            - ComputersWithSIDHistoryCount
            - AccountsWithSIDHistoryCount
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
                Import-MyModule                        | EguibarIT.SecurityPS
                Get-FunctionDisplay                    | EguibarIT.SecurityPS
                Get-ADRootDSE                          | ActiveDirectory
                Get-ADDomain                           | ActiveDirectory
                Get-ADUser                             | ActiveDirectory
                Get-ADComputer                         | ActiveDirectory
                Get-ADDomainController                 | ActiveDirectory
                Get-ADReplicationAttributeMetadata     | ActiveDirectory
                Get-ADTrust                            | ActiveDirectory
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

        .NOTES
            Version:         1.0.0
            DateModified:    06/Mar/2026
            LastModifiedBy:  Vicente Rodriguez Eguibar
                vicente@eguibar.com
                EguibarIT
                http://www.eguibarit.com

        .LINK
            https://attack.mitre.org/techniques/T1134/005/

        .LINK
            https://github.com/vreguibar/EguibarIT.SecurityPS

        .COMPONENT
            EguibarIT.SecurityPS

        .ROLE
            Security Auditing

        .FUNCTIONALITY
            Detects SID History injection indicators using AD object state, event telemetry,
            replication metadata, and trust SID filtering configuration.
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
        [PSDefaultValue(Help = 'Default: Desktop\SIDHistoryAudit')]
        [string]
        $OutputPath = (Join-Path -Path $env:USERPROFILE -ChildPath 'Desktop\SIDHistoryAudit'),

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Number of days to analyze Event Logs for SID History modifications',
            Position = 1
        )]
        [ValidateRange(1, 365)]
        [PSDefaultValue(Help = 'Default: 90 days', Value = 90)]
        [int]
        $DaysBack = 90,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Include trust SID filtering status analysis',
            Position = 2
        )]
        [switch]
        $CheckTrusts
    )

    Begin {
        Set-StrictMode -Version Latest

        [datetime]$AuditTimestamp = Get-Date
        [datetime]$StartDate = (Get-Date).AddDays(-$DaysBack)

        [System.Collections.ArrayList]$Findings = @()
        [System.Collections.ArrayList]$RecommendedActions = @()
        [System.Collections.ArrayList]$ExportedReports = @()

        [System.Collections.ArrayList]$UsersWithSIDHistory = @()
        [System.Collections.ArrayList]$ComputersWithSIDHistory = @()

        [System.Collections.ArrayList]$LegitimateDCNames = @()
        [System.Collections.ArrayList]$LegitimateDCHostNames = @()

        [hashtable]$PrivilegedSidMap = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

        [System.Collections.Generic.HashSet[string]]$LegitimateDCIdentitySet =
            [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

        # Display function header if variables exist
        if ($null -ne $Variables -and
            $null -ne $Variables.HeaderSecurity) {

            $txt = ($Variables.HeaderSecurity -f
                (Get-Date).ToString('dd/MMM/yyyy'),
                $MyInvocation.Mycommand,
                (Get-FunctionDisplay -Hashtable $PsBoundParameters -Verbose:$False)
            )
            Write-Verbose -Message $txt
        } #end if

        ##############################
        # Module imports

        try {
            Import-MyModule -Name ActiveDirectory -Force -Verbose:$VerbosePreference -ErrorAction Stop
            Write-Verbose -Message 'Active Directory module loaded successfully.'
        } catch {
            Write-Error -Message (
                'ActiveDirectory PowerShell module is required but not available. Install RSAT-AD-PowerShell. Error: {0}' -f
                $_.Exception.Message
            ) -Category NotInstalled -ErrorAction Stop
        } #end try-catch

        ##############################
        # Variables Definition

        Write-Verbose -Message ('Starting SID History injection detection. Analysis window starts at {0}' -f $StartDate)
    } #end Begin

    Process {
        try {
            Write-Progress -Activity 'SID History Injection Detection Audit' `
                -Status 'Phase 1/5: Enumerating accounts with SID History' -PercentComplete 10

            # =============================================
            # PHASE 1: ENUMERATE ACCOUNTS WITH SID HISTORY
            # =============================================
            Write-Verbose -Message '[Phase 1] Enumerating accounts with non-empty SID History.'

            $AllUsers = Get-ADUser -Filter * -Properties sidHistory, whenCreated, PasswordLastSet, AdminCount -ErrorAction Stop
            foreach ($User in $AllUsers) {
                if ($null -ne $User.sidHistory -and $User.sidHistory.Count -gt 0) {
                    [void]$UsersWithSIDHistory.Add($User)
                } #end if
            } #end foreach

            $AllComputers = Get-ADComputer -Filter * -Properties sidHistory, whenCreated -ErrorAction Stop
            foreach ($Computer in $AllComputers) {
                if ($null -ne $Computer.sidHistory -and $Computer.sidHistory.Count -gt 0) {
                    [void]$ComputersWithSIDHistory.Add($Computer)
                } #end if
            } #end foreach

            Write-Verbose -Message ('[Phase 1] Users with SID History: {0}' -f $UsersWithSIDHistory.Count)
            Write-Verbose -Message ('[Phase 1] Computers with SID History: {0}' -f $ComputersWithSIDHistory.Count)

            Write-Progress -Activity 'SID History Injection Detection Audit' `
                -Status 'Phase 2/5: Analyzing privileged SID History values' -PercentComplete 30

            # =============================================
            # PHASE 2: ANALYZE PRIVILEGED SIDS IN SID HISTORY
            # =============================================
            Write-Verbose -Message '[Phase 2] Building privileged SID map from module Well-Known SID variables.'

            if ($null -ne $Variables -and
                $null -ne $Variables.WellKnownSIDs -and
                $Variables.WellKnownSIDs.Count -gt 0) {

                [string[]]$PrivilegedGroupNames = @(
                    'Domain Admins',
                    'Enterprise Admins',
                    'Schema Admins',
                    'Administrator'
                )

                foreach ($GroupName in $PrivilegedGroupNames) {
                    $MatchedSids = @(
                        $Variables.WellKnownSIDs.Keys.Where({
                                $Variables.WellKnownSIDs[$_] -eq $GroupName
                            })
                    )

                    foreach ($MatchedSid in $MatchedSids) {
                        if (-not $PrivilegedSidMap.ContainsKey($MatchedSid)) {
                            $PrivilegedSidMap.Add($MatchedSid, $GroupName)
                        } #end if
                    } #end foreach
                } #end foreach
            } else {
                Write-Warning -Message (
                    'WellKnownSIDs module variable is not initialized. Privileged SID History matching may be incomplete.'
                )
            } #end if-else

            foreach ($User in $UsersWithSIDHistory) {
                foreach ($SidEntry in $User.sidHistory) {
                    [string]$SidValue = if ($SidEntry.PSObject.Properties.Name -contains 'Value') {
                        [string]$SidEntry.Value
                    } else {
                        [string]$SidEntry
                    }

                    if ([string]::IsNullOrWhiteSpace($SidValue)) {
                        continue
                    } #end if

                    if ($PrivilegedSidMap.ContainsKey($SidValue)) {
                        [void]$Findings.Add([PSCustomObject]@{
                                PSTypeName         = 'EguibarIT.SIDHistoryInjectionAttack.Finding'
                                Timestamp          = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                                FindingType        = 'Privileged SID in SID History'
                                RiskLevel          = 'Critical'
                                ObjectType         = 'User'
                                AccountName        = $User.SamAccountName
                                DistinguishedName  = $User.DistinguishedName
                                SIDHistory         = $SidValue
                                PrivilegedGroup    = $PrivilegedSidMap[$SidValue]
                                DomainController   = $null
                                EventID            = $null
                                SubjectAccount     = $null
                                TargetAccount      = $null
                                OriginatingDC      = $null
                                TrustName          = $null
                                TrustDirection     = $null
                                TrustType          = $null
                                SIDFilteringStatus = $null
                                Indicator          = (
                                    'Account has {0} SID in SID History (admin-equivalent access without direct membership).' -f
                                    $PrivilegedSidMap[$SidValue]
                                )
                                Recommendation     = 'IMMEDIATE INVESTIGATION - validate and remove unauthorized SID History entries.'
                            })
                    } else {
                        [void]$Findings.Add([PSCustomObject]@{
                                PSTypeName         = 'EguibarIT.SIDHistoryInjectionAttack.Finding'
                                Timestamp          = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                                FindingType        = 'Non-Privileged SID History'
                                RiskLevel          = 'Medium'
                                ObjectType         = 'User'
                                AccountName        = $User.SamAccountName
                                DistinguishedName  = $User.DistinguishedName
                                SIDHistory         = $SidValue
                                PrivilegedGroup    = 'N/A'
                                DomainController   = $null
                                EventID            = $null
                                SubjectAccount     = $null
                                TargetAccount      = $null
                                OriginatingDC      = $null
                                TrustName          = $null
                                TrustDirection     = $null
                                TrustType          = $null
                                SIDFilteringStatus = $null
                                Indicator          = 'User account has SID History (unusual outside approved migrations).'
                                Recommendation     = 'Verify migration justification and clear SID History when no longer required.'
                            })
                    } #end if-else
                } #end foreach
            } #end foreach

            foreach ($Computer in $ComputersWithSIDHistory) {
                foreach ($SidEntry in $Computer.sidHistory) {
                    [string]$SidValue = if ($SidEntry.PSObject.Properties.Name -contains 'Value') {
                        [string]$SidEntry.Value
                    } else {
                        [string]$SidEntry
                    }

                    if ([string]::IsNullOrWhiteSpace($SidValue)) {
                        continue
                    } #end if

                    [void]$Findings.Add([PSCustomObject]@{
                            PSTypeName         = 'EguibarIT.SIDHistoryInjectionAttack.Finding'
                            Timestamp          = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                            FindingType        = 'Computer Account with SID History'
                            RiskLevel          = 'High'
                            ObjectType         = 'Computer'
                            AccountName        = $Computer.Name
                            DistinguishedName  = $Computer.DistinguishedName
                            SIDHistory         = $SidValue
                            PrivilegedGroup    = 'N/A'
                            DomainController   = $null
                            EventID            = $null
                            SubjectAccount     = $null
                            TargetAccount      = $null
                            OriginatingDC      = $null
                            TrustName          = $null
                            TrustDirection     = $null
                            TrustType          = $null
                            SIDFilteringStatus = $null
                            Indicator          = 'Computer account has SID History (rare and high-risk condition).'
                            Recommendation     = 'Investigate immediately and remove unauthorized SID History entries.'
                        })
                } #end foreach
            } #end foreach

            Write-Progress -Activity 'SID History Injection Detection Audit' `
                -Status 'Phase 3/5: Analyzing Event ID 4765' -PercentComplete 50

            # =============================================
            # PHASE 3: EVENT 4765 (SID HISTORY ADDED)
            # =============================================
            Write-Verbose -Message '[Phase 3] Querying Event ID 4765 from all domain controllers.'

            try {
                $DomainControllers = Get-ADDomainController -Filter * -ErrorAction Stop

                foreach ($DomainController in $DomainControllers) {
                    if (-not [string]::IsNullOrWhiteSpace($DomainController.Name)) {
                        [void]$LegitimateDCNames.Add($DomainController.Name)
                        [void]$LegitimateDCIdentitySet.Add($DomainController.Name)
                    } #end if

                    if (-not [string]::IsNullOrWhiteSpace($DomainController.HostName)) {
                        [void]$LegitimateDCHostNames.Add($DomainController.HostName)
                        [void]$LegitimateDCIdentitySet.Add($DomainController.HostName)
                        [void]$LegitimateDCIdentitySet.Add(($DomainController.HostName.Split('.')[0]))
                    } #end if

                    try {
                        $Event4765List = Get-WinEvent -ComputerName $DomainController.HostName -FilterHashtable @{
                            LogName   = 'Security'
                            Id        = 4765
                            StartTime = $StartDate
                        } -ErrorAction Stop

                        foreach ($Event4765 in $Event4765List) {
                            [xml]$EventXml = $Event4765.ToXml()

                            $TargetUser = ($EventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' } | Select-Object -First 1).'#text'
                            $SubjectUser = ($EventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' } | Select-Object -First 1).'#text'
                            $SidAdded = ($EventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'SidHistory' } | Select-Object -First 1).'#text'

                            [void]$Findings.Add([PSCustomObject]@{
                                    PSTypeName         = 'EguibarIT.SIDHistoryInjectionAttack.Finding'
                                    Timestamp          = $Event4765.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                                    FindingType        = 'SID History Modification Event'
                                    RiskLevel          = 'High'
                                    ObjectType         = 'EventLog'
                                    AccountName        = $TargetUser
                                    DistinguishedName  = $null
                                    SIDHistory         = $SidAdded
                                    PrivilegedGroup    = 'N/A'
                                    DomainController   = $DomainController.HostName
                                    EventID            = 4765
                                    SubjectAccount     = $SubjectUser
                                    TargetAccount      = $TargetUser
                                    OriginatingDC      = $null
                                    TrustName          = $null
                                    TrustDirection     = $null
                                    TrustType          = $null
                                    SIDFilteringStatus = $null
                                    Indicator          = 'Event 4765 indicates SID History was added to an account.'
                                    Recommendation     = 'Validate against approved migration changes and investigate unauthorized additions.'
                                })
                        } #end foreach
                    } catch {
                        Write-Warning -Message (
                            'Failed to query Event 4765 from {0}: {1}' -f
                            $DomainController.HostName,
                            $_.Exception.Message
                        )
                    } #end try-catch
                } #end foreach
            } catch {
                Write-Warning -Message ('Failed to enumerate domain controllers for Event 4765 analysis: {0}' -f $_.Exception.Message)
            } #end try-catch

            Write-Progress -Activity 'SID History Injection Detection Audit' `
                -Status 'Phase 4/5: Auditing replication metadata anomalies' -PercentComplete 70

            # =============================================
            # PHASE 4: REPLICATION METADATA AUDIT
            # =============================================
            Write-Verbose -Message '[Phase 4] Auditing sidHistory replication metadata origin servers.'

            [System.Collections.ArrayList]$AccountsForMetadataAudit = @()
            foreach ($User in $UsersWithSIDHistory) {
                [void]$AccountsForMetadataAudit.Add([PSCustomObject]@{
                        ObjectType        = 'User'
                        AccountName       = $User.SamAccountName
                        DistinguishedName = $User.DistinguishedName
                    })
            } #end foreach

            foreach ($Computer in $ComputersWithSIDHistory) {
                [void]$AccountsForMetadataAudit.Add([PSCustomObject]@{
                        ObjectType        = 'Computer'
                        AccountName       = $Computer.Name
                        DistinguishedName = $Computer.DistinguishedName
                    })
            } #end foreach

            if ($LegitimateDCHostNames.Count -gt 0) {
                [string]$MetadataServer = $LegitimateDCHostNames[0]

                foreach ($Account in $AccountsForMetadataAudit) {
                    try {
                        $MetadataRecords = Get-ADReplicationAttributeMetadata -Object $Account.DistinguishedName `
                            -Server $MetadataServer -ShowAllLinkedValues -ErrorAction Stop

                        foreach ($MetadataRecord in $MetadataRecords) {
                            if ($MetadataRecord.AttributeName -ne 'sidHistory') {
                                continue
                            } #end if

                            [string]$OriginatingDC = [string]$MetadataRecord.LastOriginatingChangeDirectoryServerIdentity

                            [System.Collections.ArrayList]$OriginCandidates = @()
                            if (-not [string]::IsNullOrWhiteSpace($OriginatingDC)) {
                                [void]$OriginCandidates.Add($OriginatingDC)

                                if ($OriginatingDC -match '^CN=([^,]+),') {
                                    [void]$OriginCandidates.Add($Matches[1])
                                } #end if

                                if ($OriginatingDC -match '\.') {
                                    [void]$OriginCandidates.Add(($OriginatingDC.Split('.')[0]))
                                } #end if
                            } #end if

                            [bool]$IsKnownDC = $false
                            foreach ($Candidate in $OriginCandidates) {
                                if ($LegitimateDCIdentitySet.Contains($Candidate)) {
                                    $IsKnownDC = $true
                                    break
                                } #end if
                            } #end foreach

                            if (-not $IsKnownDC) {
                                [void]$Findings.Add([PSCustomObject]@{
                                        PSTypeName         = 'EguibarIT.SIDHistoryInjectionAttack.Finding'
                                        Timestamp          = $MetadataRecord.LastOriginatingChangeTime.ToString('yyyy-MM-dd HH:mm:ss')
                                        FindingType        = 'SID History Modified by Unknown DC'
                                        RiskLevel          = 'Critical'
                                        ObjectType         = $Account.ObjectType
                                        AccountName        = $Account.AccountName
                                        DistinguishedName  = $Account.DistinguishedName
                                        SIDHistory         = $null
                                        PrivilegedGroup    = 'N/A'
                                        DomainController   = $MetadataServer
                                        EventID            = $null
                                        SubjectAccount     = $null
                                        TargetAccount      = $Account.AccountName
                                        OriginatingDC      = $OriginatingDC
                                        TrustName          = $null
                                        TrustDirection     = $null
                                        TrustType          = $null
                                        SIDFilteringStatus = $null
                                        Indicator          = 'sidHistory metadata change originated from unknown directory server identity.'
                                        Recommendation     = 'URGENT - investigate potential DCShadow or unauthorized replication activity.'
                                    })
                            } #end if
                        } #end foreach
                    } catch {
                        Write-Warning -Message (
                            'Failed to retrieve sidHistory metadata for {0}: {1}' -f
                            $Account.AccountName,
                            $_.Exception.Message
                        )
                    } #end try-catch
                } #end foreach
            } else {
                Write-Warning -Message 'No domain controllers available for replication metadata baseline; skipping metadata audit.'
            } #end if-else

            Write-Progress -Activity 'SID History Injection Detection Audit' `
                -Status 'Phase 5/5: Evaluating trust SID filtering' -PercentComplete 90

            # =============================================
            # PHASE 5: TRUST SID FILTERING STATUS (OPTIONAL)
            # =============================================
            if ($CheckTrusts.IsPresent) {
                Write-Verbose -Message '[Phase 5] Checking SID filtering status on trusts.'

                try {
                    $Trusts = Get-ADTrust -Filter * -ErrorAction Stop

                    foreach ($Trust in $Trusts) {
                        [bool]$SidFilteringEnabled = [bool]$Trust.SIDFilteringQuarantined

                        if (-not $SidFilteringEnabled) {
                            [void]$Findings.Add([PSCustomObject]@{
                                    PSTypeName         = 'EguibarIT.SIDHistoryInjectionAttack.Finding'
                                    Timestamp          = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                                    FindingType        = 'SID Filtering Disabled on Trust'
                                    RiskLevel          = 'High'
                                    ObjectType         = 'Trust'
                                    AccountName        = $null
                                    DistinguishedName  = $null
                                    SIDHistory         = $null
                                    PrivilegedGroup    = 'N/A'
                                    DomainController   = $null
                                    EventID            = $null
                                    SubjectAccount     = $null
                                    TargetAccount      = $null
                                    OriginatingDC      = $null
                                    TrustName          = $Trust.Name
                                    TrustDirection     = [string]$Trust.Direction
                                    TrustType          = [string]$Trust.TrustType
                                    SIDFilteringStatus = $false
                                    Indicator          = 'Trust has SID filtering disabled, allowing elevated cross-trust SID abuse scenarios.'
                                    Recommendation     = (
                                        'Enable SID filtering (quarantine) on trust {0} after validating business requirements.' -f
                                        $Trust.Name
                                    )
                                })
                        } #end if
                    } #end foreach
                } catch {
                    Write-Warning -Message ('Failed to check trust SID filtering status: {0}' -f $_.Exception.Message)
                } #end try-catch
            } #end if

            # =============================================
            # RECOMMENDED ACTIONS
            # =============================================
            [int]$CriticalCount = @($Findings | Where-Object { $_.RiskLevel -eq 'Critical' }).Count
            [int]$HighCount = @($Findings | Where-Object { $_.RiskLevel -eq 'High' }).Count
            [int]$MediumCount = @($Findings | Where-Object { $_.RiskLevel -eq 'Medium' }).Count

            if ($CriticalCount -gt 0) {
                [void]$RecommendedActions.Add('IMMEDIATE: Investigate all critical SID History findings and contain affected accounts.')
                [void]$RecommendedActions.Add('Validate and remove unauthorized privileged SID History values from impacted accounts.')
                [void]$RecommendedActions.Add('Investigate unknown metadata origin servers for DCShadow or rogue replication activity.')
            } #end if

            if ($HighCount -gt 0) {
                [void]$RecommendedActions.Add('Review Event 4765 entries and validate each SID History addition against approved changes.')
                [void]$RecommendedActions.Add('Investigate computer accounts with SID History and remove unsupported values.')
            } #end if

            if ($CheckTrusts.IsPresent -and ($Findings | Where-Object { $_.FindingType -eq 'SID Filtering Disabled on Trust' }).Count -gt 0) {
                [void]$RecommendedActions.Add('Enable SID filtering on trusts that do not require SID history traversal.')
            } #end if

            if ($Findings.Count -eq 0) {
                [void]$RecommendedActions.Add('No SID History injection indicators found; continue periodic monitoring and auditing.')
            } #end if

            Write-Progress -Activity 'SID History Injection Detection Audit' -Completed

            # =============================================
            # EXPORT
            # =============================================
            if (-not [string]::IsNullOrWhiteSpace($OutputPath) -and
                $PSCmdlet.ShouldProcess($OutputPath, 'Export SID History injection detection reports')) {

                if (-not (Test-Path -Path $OutputPath)) {
                    New-Item -Path $OutputPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
                    Write-Verbose -Message ('Created output directory: {0}' -f $OutputPath)
                } #end if

                [string]$TimestampSuffix = (Get-Date -Format 'yyyyMMdd-HHmmss')
                [string]$CsvPath = Join-Path -Path $OutputPath -ChildPath ('SIDHistory-Detection-{0}.csv' -f $TimestampSuffix)
                [string]$JsonPath = Join-Path -Path $OutputPath -ChildPath ('SIDHistory-Detection-{0}.json' -f $TimestampSuffix)

                $Findings | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8 -Force
                $Findings | ConvertTo-Json -Depth 6 | Out-File -FilePath $JsonPath -Encoding UTF8 -Force

                [void]$ExportedReports.Add($CsvPath)
                [void]$ExportedReports.Add($JsonPath)

                Write-Verbose -Message ('Exported reports: {0}, {1}' -f $CsvPath, $JsonPath)
            } #end if

            [PSCustomObject]$AuditResult = [PSCustomObject]@{
                PSTypeName                 = 'EguibarIT.SIDHistoryInjectionAttack'
                AuditTimestamp             = $AuditTimestamp
                AnalysisWindowDays         = $DaysBack
                UsersWithSIDHistoryCount   = $UsersWithSIDHistory.Count
                ComputersWithSIDHistoryCount = $ComputersWithSIDHistory.Count
                AccountsWithSIDHistoryCount = ($UsersWithSIDHistory.Count + $ComputersWithSIDHistory.Count)
                TotalFindings              = $Findings.Count
                CriticalCount              = $CriticalCount
                HighCount                  = $HighCount
                MediumCount                = $MediumCount
                IsCompromiseLikely         = ($CriticalCount -gt 0)
                TrustsChecked              = $CheckTrusts.IsPresent
                Findings                   = $Findings
                RecommendedActions         = $RecommendedActions
                ExportedReports            = $ExportedReports
            }

            Write-Output -InputObject $AuditResult
        } catch {
            Write-Error -Message ('Failed to execute SID History injection detection: {0}' -f $_.Exception.Message)
            throw
        } #end try-catch
    } #end Process

    End {
        if ($null -ne $Variables -and
            $null -ne $Variables.FooterSecurity) {

            $txt = ($Variables.FooterSecurity -f
                $MyInvocation.InvocationName,
                'finished auditing SID History injection indicators.'
            )
            Write-Verbose -Message $txt
        } #end if
    } #end End
} #end Function Get-SIDHistoryInjectionAttack
