function Get-DCSyncAttack {
    <#
        .SYNOPSIS
            Identifies accounts with dangerous replication permissions and monitors Event Logs for DCSync attacks.

        .DESCRIPTION
            Performs a comprehensive three-phase DCSync attack detection audit:

            **Phase 1 - PERMISSION AUDIT:**
            Identifies ALL accounts with DS-Replication-Get-Changes permissions on the domain.
            Separates domain controllers (expected) from non-DC accounts (critical security risk).

            **Phase 2 - EVENT MONITORING:**
            Analyzes Security Event Log ID 4662 (Directory Service Access) for replication requests.
            Correlates replication events from non-DC sources to detect active DCSync attacks.

            **Phase 3 - ATTACK DETECTION:**
            Identifies suspicious replication activity and provides incident response guidance.

            **ATTACK VECTOR:**
            DCSync exploits legitimate Active Directory replication to extract password hashes remotely.
            Attackers with replication permissions can impersonate domain controllers and dump:
            - krbtgt hash (enables Golden Ticket attacks)
            - Domain Admin password hashes
            - ALL user password hashes (using /all parameter)
            - No code execution on domain controller required

            **CRITICAL SECURITY PRINCIPLE:**
            ONLY domain controllers should have replication permissions.
            ANY other account with these rights represents a critical security vulnerability.

            **MITRE ATT&CK Mapping:**
            - **T1003.006**: OS Credential Dumping - DCSync

            **DETECTION REQUIREMENTS:**
            - Event ID 4662 auditing must be enabled on all domain controllers
            - Domain Admin or equivalent rights required to run audit
            - Access to Security Event Logs on all DCs

        .PARAMETER TimeSpanDays
            Number of days to look back when analyzing Event Logs for replication events.
            Default is 7 days. Increase for historical analysis or compliance audits.

        .PARAMETER ExportPath
            Path to export detailed CSV reports and audit summary.
            Exports will include:
            - Replication permissions report (non-DC accounts)
            - Suspicious event log entries
            - Comprehensive security assessment summary

            The export operation respects the -WhatIf and -Confirm parameters (ShouldProcess).

        .PARAMETER MonitorRealTime
            If specified, continuously monitors for DCSync attacks in real-time.
            Checks Event Logs every 30 seconds and alerts on suspicious replication activity.
            Press Ctrl+C to stop monitoring. Not compatible with -ExportPath parameter.

        .PARAMETER IncludeNormalEvents
            If specified, includes legitimate DC-to-DC replication events in the output.
            Default behavior only reports suspicious non-DC replication events.

        .EXAMPLE
            Get-DCSyncAttack

            Description
            -----------
            Runs the DCSync detection audit with default settings (7-day event log scan).
            Displays permission audit and suspicious event analysis to console.

        .EXAMPLE
            Get-DCSyncAttack -TimeSpanDays 30 -Verbose

            Description
            -----------
            Audits the last 30 days of replication events with verbose progress output.

        .EXAMPLE
            Get-DCSyncAttack -ExportPath 'C:\SecurityAudits' -TimeSpanDays 14

            Description
            -----------
            Performs 14-day historical analysis and exports detailed reports to C:\SecurityAudits.

        .EXAMPLE
            Get-DCSyncAttack -MonitorRealTime

            Description
            -----------
            Enters continuous monitoring mode, alerting on suspicious replication requests.
            Runs until Ctrl+C is pressed.

        .EXAMPLE
            $Result = Get-DCSyncAttack -TimeSpanDays 7
            if ($Result.NonDCAccountCount -gt 0) {
                Write-Warning ('CRITICAL: {0} non-DC accounts have replication permissions!' -f $Result.NonDCAccountCount)
            }

            Description
            -----------
            Captures the audit result object and takes automated action based on findings.

        .INPUTS
            None. This function does not accept pipeline input.

        .OUTPUTS
            PSCustomObject. Returns a DCSync audit summary object containing:
            - DomainName: DNS name of the audited domain
            - DomainDN: Distinguished name of the domain
            - AuditTimestamp: When the audit was performed
            - TotalAccountsWithPermissions: Total accounts with replication rights
            - DomainControllerCount: Number of DCs with delegation (expected)
            - NonDCAccountCount: Number of non-DC accounts with delegation (critical risk)
            - TotalReplicationEvents: Total events found in specified timespan
            - SuspiciousEventCount: Number of replication events from non-DC sources
            - IsSecure: Boolean indicating if configuration is secure (no non-DC permissions, no attacks)
            - RiskLevel: Overall risk assessment (Secure/Low/Medium/High/Critical)
            - RecommendedActions: Array of remediation steps
            - ExportedReports: Array of file paths if reports were exported
            - NonDCAccounts: Array of account objects with replication permissions
            - SuspiciousEvents: Array of suspicious replication event objects

        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Get-FunctionDisplay                    | EguibarIT.SecurityPS
                Get-ADDomain                           | Microsoft.ActiveDirectory.Management
                Get-ADDomainController                 | Microsoft.ActiveDirectory.Management
                Get-Acl                                | Microsoft.PowerShell.Security
                Get-WinEvent                           | Microsoft.PowerShell.Diagnostics
                Export-Csv                             | Microsoft.PowerShell.Utility
                Out-File                               | Microsoft.PowerShell.Utility
                Write-Verbose                          | Microsoft.PowerShell.Utility
                Write-Warning                          | Microsoft.PowerShell.Utility
                Write-Error                            | Microsoft.PowerShell.Utility
                Write-Output                           | Microsoft.PowerShell.Utility
                Write-Debug                            | Microsoft.PowerShell.Utility
                New-Item                               | Microsoft.PowerShell.Management
                Test-Path                              | Microsoft.PowerShell.Management
                Get-Date                               | Microsoft.PowerShell.Utility

        .NOTES
            Version:         1.0.0
            DateModified:    02/Mar/2026
            LastModifiedBy:  Vicente Rodriguez Eguibar
                vicente@eguibar.com
                EguibarIT
                http://www.eguibarit.com

        .LINK
            https://attack.mitre.org/techniques/T1003/006/

        .LINK
            https://adsecurity.org/?p=1729

        .LINK
            https://github.com/vreguibar/EguibarIT.SecurityPS

        .COMPONENT
            EguibarIT.SecurityPS

        .ROLE
            Security Auditing

        .FUNCTIONALITY
            Detects DCSync attack patterns by auditing replication permissions and monitoring Event Logs for suspicious activity.
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
            HelpMessage = 'Number of days to analyze Event Logs for replication events',
            Position = 0
        )]
        [ValidateRange(1, 365)]
        [PSDefaultValue(Help = 'Default: 7 days')]
        [int]
        $TimeSpanDays = 7,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Path to export detailed reports and audit summary',
            Position = 1
        )]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
                if (-not (Test-Path -Path $_ -IsValid)) {
                    throw 'Export path is not valid. Please provide a valid file system path.'
                }
                return $true
            })]
        [PSDefaultValue(Help = 'Default: C:\Logs')]
        [string]
        $ExportPath = 'C:\Logs',

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Enable real-time monitoring mode (Ctrl+C to stop)',
            Position = 2
        )]
        [PSDefaultValue(Help = 'Default: $false')]
        [switch]
        $MonitorRealTime,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Include legitimate DC replication events in output',
            Position = 3
        )]
        [PSDefaultValue(Help = 'Default: $false')]
        [switch]
        $IncludeNormalEvents
    )

    begin {

        Set-StrictMode -Version Latest

        # Display function header if variables exist
        if ($null -ne $Variables -and
            $null -ne $Variables.HeaderDelegation) {

            $txt = ($Variables.HeaderDelegation -f
                (Get-Date).ToString('dd/MMM/yyyy'),
                $MyInvocation.Mycommand,
                (Get-FunctionDisplay -Hashtable $PsBoundParameters -Verbose:$False)
            )
            Write-Verbose -Message $txt
        } #end If

        ##############################
        # Module imports

        try {
            # Import ActiveDirectory module using the robust Import-MyModule function
            # This provides enhanced error handling, logging, and advanced import options
            Import-MyModule -Name ActiveDirectory -Force -Verbose:$VerbosePreference -ErrorAction Stop
            Write-Verbose -Message 'Active Directory module loaded successfully'
        } catch {
            $errorMessage = 'Active Directory PowerShell module is required but not available. Install with: Install-WindowsFeature RSAT-AD-PowerShell'
            Write-Error -Message $errorMessage -Category NotInstalled -ErrorAction Stop
        } #end try-catch

        ##############################
        # Variables Definition

        Write-Verbose -Message 'Initializing DCSync detection audit...'
        Write-Verbose -Message ('MITRE ATT&CK: T1003.006 (OS Credential Dumping - DCSync)')

        # Replication rights names for DCSync detection (GUIDs retrieved from $Variables.ExtendedRightsMap)
        [array]$ReplicationRightNames = @(
            'DS-Replication-Get-Changes',
            'DS-Replication-Get-Changes-All',
            'DS-Replication-Get-Changes-In-Filtered-Set'
        )

        # Verify replication rights are available in module variables
        if ($null -eq $Variables.ExtendedRightsMap -or $Variables.ExtendedRightsMap.Count -eq 0) {
            $errorMessage = 'Module variables not initialized. Ensure Initialize-ModuleVariable was called during module import.'
            Write-Error -Message $errorMessage -Category InvalidOperation -ErrorAction Stop
        } #end if

        Write-Debug -Message ('Replication Rights Names: {0}' -f ($ReplicationRightNames -join ', '))
        Write-Debug -Message ('Extended Rights Map initialized with {0} entries' -f $Variables.ExtendedRightsMap.Count)

        # Initialize result collections using ArrayList for performance
        [System.Collections.ArrayList]$ReplicationPermissions = @()
        [System.Collections.ArrayList]$AllReplicationEvents = @()
        [System.Collections.ArrayList]$SuspiciousEvents = @()
        [System.Collections.ArrayList]$ExportedReports = @()

        # Initialize summary object
        [PSCustomObject]$AuditResult = [PSCustomObject]@{
            DomainName                   = $null
            DomainDN                     = $null
            AuditTimestamp               = Get-Date
            TotalAccountsWithPermissions = 0
            DomainControllerCount        = 0
            NonDCAccountCount            = 0
            TotalReplicationEvents       = 0
            SuspiciousEventCount         = 0
            IsSecure                     = $false
            RiskLevel                    = 'Unknown'
            RecommendedActions           = @()
            ExportedReports              = @()
            NonDCAccounts                = @()
            SuspiciousEvents             = @()
        }

    } #end Begin

    ######################
    # Section PROCESS
    process {

        try {
            # ========================================
            # PHASE 1: AUDIT REPLICATION PERMISSIONS
            # ========================================
            Write-Verbose -Message '[PHASE 1] Auditing Active Directory Replication Permissions'

            try {
                $Domain = Get-ADDomain -ErrorAction Stop
                $AuditResult.DomainName = $Domain.DNSRoot
                $AuditResult.DomainDN = $Domain.DistinguishedName

                Write-Verbose -Message ('Domain: {0}' -f $Domain.DNSRoot)
                Write-Verbose -Message ('Domain DN: {0}' -f $Domain.DistinguishedName)
                Write-Debug -Message ('Domain GUID: {0}' -f $Domain.ObjectGUID)

                # Get domain root ACL
                Write-Verbose -Message 'Retrieving ACL for domain root object...'
                $DomainACL = Get-Acl -Path ('AD:{0}' -f $Domain.DistinguishedName) -ErrorAction Stop

                Write-Debug -Message ('ACL contains {0} access control entries' -f $DomainACL.Access.Count)

                # Analyze each ACE for replication permissions
                foreach ($ACE in $DomainACL.Access) {
                    $HasReplicationPermission = $false
                    [System.Collections.ArrayList]$PermissionTypes = @()

                    # Check for replication rights (lookup GUIDs from module variables)
                    foreach ($RightName in $ReplicationRightNames) {
                        if ($RightName -in $Variables.ExtendedRightsMap.Keys) {
                            [guid]$RightGUID = $Variables.ExtendedRightsMap[$RightName]
                            if ($ACE.ObjectType -eq $RightGUID) {
                                $HasReplicationPermission = $true
                                [void]$PermissionTypes.Add($RightName)
                            } #end if
                        } #end if
                    } #end foreach

                    if ($HasReplicationPermission) {
                        # Resolve identity (SID to name)
                        [string]$IdentityName = $ACE.IdentityReference.Value

                        try {
                            # Try to resolve SID to AD object
                            $IdentitySID = [System.Security.Principal.SecurityIdentifier]::new($ACE.IdentityReference.Value)
                            $ResolvedIdentity = $IdentitySID.Translate([System.Security.Principal.NTAccount]).Value
                            $IdentityName = $ResolvedIdentity

                            Write-Debug -Message ('Resolved SID: {0} -> {1}' -f $ACE.IdentityReference.Value, $IdentityName)
                        } catch {
                            # Keep original name if SID translation fails
                            Write-Debug -Message ('Could not resolve SID: {0}' -f $ACE.IdentityReference.Value)
                        } #end try-catch

                        [void]$ReplicationPermissions.Add([PSCustomObject]@{
                                Identity          = $IdentityName
                                PermissionType    = ($PermissionTypes -join ', ')
                                AccessControlType = $ACE.AccessControlType
                                IsInherited       = $ACE.IsInherited
                            })
                    } #end if
                } #end foreach

                # Remove duplicates (same identity may have multiple ACEs)
                $UniquePermissions = $ReplicationPermissions |
                    Group-Object -Property Identity |
                        ForEach-Object {
                            [PSCustomObject]@{
                                Identity    = $_.Name
                                Permissions = (($_.Group.PermissionType | Select-Object -Unique) -join ', ')
                                AccessType  = ($_.Group.AccessControlType | Select-Object -First 1)
                            }
                        } #end pipeline

                $AuditResult.TotalAccountsWithPermissions = $UniquePermissions.Count

                Write-Verbose -Message ('Found {0} identities with replication permissions' -f $UniquePermissions.Count)

                # Categorize accounts (Domain Controllers vs. Everything Else)
                $DomainControllers = Get-ADDomainController -Filter * -ErrorAction Stop |
                    Select-Object -ExpandProperty Name

                Write-Debug -Message ('Domain Controllers: {0}' -f ($DomainControllers -join ', '))

                [System.Collections.ArrayList]$DCAccounts = @()
                [System.Collections.ArrayList]$NonDCAccounts = @()

                foreach ($Permission in $UniquePermissions) {
                    [string]$Identity = $Permission.Identity
                    [bool]$IsDC = $false

                    # Check if identity is a DC computer account
                    foreach ($DC in $DomainControllers) {
                        if ($Identity -like "*$DC*" -or $Identity -like '*Domain Controllers*') {
                            $IsDC = $true
                            break
                        } #end if
                    } #end foreach

                    if ($IsDC) {
                        [void]$DCAccounts.Add($Permission)
                    } else {
                        [void]$NonDCAccounts.Add($Permission)
                    } #end if-else
                } #end foreach

                $AuditResult.DomainControllerCount = $DCAccounts.Count
                $AuditResult.NonDCAccountCount = $NonDCAccounts.Count
                $AuditResult.NonDCAccounts = $NonDCAccounts

                Write-Verbose -Message ('Domain Controller Accounts: {0} (EXPECTED)' -f $DCAccounts.Count)

                if ($NonDCAccounts.Count -eq 0) {
                    Write-Verbose -Message 'Non-DC Accounts: 0 ✓ SECURE'
                } else {
                    Write-Warning -Message ('Non-DC Accounts: {0} 🚨 CRITICAL RISK' -f $NonDCAccounts.Count)
                    Write-Warning -Message 'The following accounts can perform DCSync attacks:'

                    foreach ($Account in $NonDCAccounts) {
                        Write-Warning -Message ('  - {0} ({1})' -f $Account.Identity, $Account.Permissions)
                    } #end foreach
                } #end if-else

            } catch {
                $errorMessage = 'Failed to audit replication permissions. Ensure you have Domain Admin or equivalent rights.'
                Write-Error -Message $errorMessage -Category PermissionDenied
                Write-Debug -Message ('Error details: {0}' -f $_.Exception.Message)
                throw
            } #end try-catch

            # ========================================
            # PHASE 2: MONITOR EVENT LOGS FOR DCSYNC ATTACKS
            # ========================================
            if (-not $MonitorRealTime) {
                Write-Verbose -Message ('[PHASE 2] Analyzing Event Logs for DCSync Activity (Last {0} Days)' -f $TimeSpanDays)

                [datetime]$StartTime = (Get-Date).AddDays(-$TimeSpanDays)
                Write-Debug -Message ('Event log search start time: {0}' -f $StartTime.ToString('yyyy-MM-dd HH:mm:ss'))

                Write-Verbose -Message 'Checking Event ID 4662 (Directory Service Access) on all DCs...'
                Write-Verbose -Message ('Scanning {0} domain controllers' -f $DomainControllers.Count)
                Write-Warning -Message 'Event ID 4662 auditing must be enabled for attack detection'

                [int]$DCsProcessed = 0

                foreach ($DC in $DomainControllers) {
                    $DCsProcessed++
                    Write-Verbose -Message ('[{0}/{1}] Querying {2}...' -f $DCsProcessed, $DomainControllers.Count, $DC)

                    try {
                        # Event ID 4662: An operation was performed on an object
                        # Filter for replication GUIDs
                        $Events = Get-WinEvent -ComputerName $DC -FilterHashtable @{
                            LogName   = 'Security'
                            Id        = 4662
                            StartTime = $StartTime
                        } -ErrorAction SilentlyContinue

                        if ($Events) {
                            Write-Debug -Message ('Retrieved {0} Event ID 4662 entries from {1}' -f $Events.Count, $DC)

                            foreach ($EventEntry in $Events) {
                                $XML = [xml]$EventEntry.ToXml()
                                [hashtable]$EventData = @{}

                                $XML.Event.EventData.Data | ForEach-Object {
                                    $EventData[$_.Name] = $_.'#text'
                                } #end pipeline

                                # Check if event is related to replication
                                [string]$Properties = $EventData['Properties']

                                # Build regex pattern from replication rights GUIDs
                                [string[]]$GUIDPatterns = @()
                                foreach ($RightName in $ReplicationRightNames) {
                                    if ($RightName -in $Variables.ExtendedRightsMap.Keys) {
                                        $GUIDPatterns += [regex]::Escape($Variables.ExtendedRightsMap[$RightName])
                                    } #end if
                                } #end foreach
                                [string]$ReplicationGUIDPattern = $GUIDPatterns -join '|'

                                if ($Properties -match $ReplicationGUIDPattern) {

                                    [string]$SubjectUserName = $EventData['SubjectUserName']
                                    [string]$SubjectDomainName = $EventData['SubjectDomainName']
                                    [string]$ObjectName = $EventData['ObjectName']

                                    # Check if subject is a domain controller (expected) or something else (suspicious)
                                    [bool]$IsDCAccount = $false
                                    foreach ($DCName in $DomainControllers) {
                                        if ($SubjectUserName -like "*$($DCName.Split('.')[0])*") {
                                            $IsDCAccount = $true
                                            break
                                        } #end if
                                    } #end foreach

                                    [bool]$IsSuspicious = -not $IsDCAccount

                                    [PSCustomObject]$EventRecord = [PSCustomObject]@{
                                        TimeCreated      = $EventEntry.TimeCreated
                                        DomainController = $DC
                                        SubjectUser      = ('{0}\{1}' -f $SubjectDomainName, $SubjectUserName)
                                        ObjectAccessed   = $ObjectName
                                        Properties       = $Properties
                                        IsDCAccount      = $IsDCAccount
                                        IsSuspicious     = $IsSuspicious
                                    }

                                    [void]$AllReplicationEvents.Add($EventRecord)

                                    if ($IsSuspicious) {
                                        [void]$SuspiciousEvents.Add($EventRecord)
                                        Write-Warning -Message ('SUSPICIOUS: Replication event from {0} on {1}' -f $EventRecord.SubjectUser, $DC)
                                    } #end if
                                } #end if
                            } #end foreach
                        } #end if

                    } catch {
                        if ($_.Exception.Message -like '*No events were found*') {
                            Write-Debug -Message ('No replication events found on {0}' -f $DC)
                        } elseif ($_.Exception.Message -like '*The RPC server is unavailable*') {
                            Write-Warning -Message ('Could not query {0}: DC may be offline or firewall blocking RPC' -f $DC)
                        } elseif ($_.Exception.Message -like '*Access is denied*') {
                            Write-Warning -Message ('Could not query {0}: Insufficient permissions - need Domain Admin' -f $DC)
                        } else {
                            Write-Warning -Message ('Could not query {0}: {1}' -f $DC, $_.Exception.Message)
                        } #end if-elseif-else
                    } #end try-catch
                } #end foreach

                $AuditResult.TotalReplicationEvents = $AllReplicationEvents.Count
                $AuditResult.SuspiciousEventCount = $SuspiciousEvents.Count
                $AuditResult.SuspiciousEvents = $SuspiciousEvents

                Write-Verbose -Message ('Retrieved {0} total replication events' -f $AllReplicationEvents.Count)

                if ($SuspiciousEvents.Count -gt 0) {
                    Write-Warning -Message ('🚨 ACTIVE DCSYNC ATTACK DETECTED - {0} suspicious events' -f $SuspiciousEvents.Count)
                    Write-Warning -Message 'Replication requests from NON-DOMAIN CONTROLLER accounts detected!'

                    foreach ($SuspEvent in $SuspiciousEvents) {
                        Write-Warning -Message ('  {0} - {1} on {2}' -f $SuspEvent.TimeCreated, $SuspEvent.SubjectUser, $SuspEvent.DomainController)
                    } #end foreach

                } elseif ($AllReplicationEvents.Count -gt 0) {
                    Write-Verbose -Message 'All replication events are from domain controllers (legitimate)'
                    Write-Verbose -Message 'No suspicious DCSync activity detected'
                } else {
                    Write-Verbose -Message 'No replication events found in the specified timeframe'
                    Write-Warning -Message 'If this seems unusual, verify Event ID 4662 auditing is enabled'
                    Write-Warning -Message 'Enable via: Group Policy > Advanced Audit Policy > Audit Directory Service Access'
                } #end if-elseif-else
            } #end if not monitor real-time

            # ========================================
            # PHASE 3: REAL-TIME MONITORING MODE
            # ========================================
            if ($MonitorRealTime) {
                Write-Verbose -Message '[REAL-TIME MODE] Monitoring for DCSync attacks (press Ctrl+C to stop)...'
                Write-Warning -Message 'Real-time monitoring mode is experimental and should not be Run in production without testing'

                Write-Verbose -Message ('Monitoring domain controllers: {0}' -f ($DomainControllers -join ', '))
                Write-Verbose -Message 'Alerting on Event ID 4662 with replication GUIDs from non-DC accounts'

                [datetime]$LastCheck = Get-Date

                while ($true) {
                    Start-Sleep -Seconds 30  # Check every 30 seconds

                    foreach ($DC in $DomainControllers) {
                        try {
                            $Events = Get-WinEvent -ComputerName $DC -FilterHashtable @{
                                LogName   = 'Security'
                                Id        = 4662
                                StartTime = $LastCheck
                            } -ErrorAction SilentlyContinue

                            if ($Events) {
                                foreach ($EventEntry in $Events) {
                                    $XML = [xml]$EventEntry.ToXml()
                                    [hashtable]$EventData = @{}

                                    $XML.Event.EventData.Data | ForEach-Object {
                                        $EventData[$_.Name] = $_.'#text'
                                    } #end pipeline

                                    [string]$Properties = $EventData['Properties']

                                    # Build regex pattern from replication rights GUIDs
                                    [string[]]$GUIDPatterns = @()
                                    foreach ($RightName in $ReplicationRightNames) {
                                        if ($RightName -in $Variables.ExtendedRightsMap.Keys) {
                                            $GUIDPatterns += [regex]::Escape($Variables.ExtendedRightsMap[$RightName])
                                        } #end if
                                    } #end foreach
                                    [string]$ReplicationGUIDPattern = $GUIDPatterns -join '|'

                                    if ($Properties -match $ReplicationGUIDPattern) {

                                        [string]$SubjectUserName = $EventData['SubjectUserName']

                                        # Check if DC account
                                        [bool]$IsDCAccount = $false
                                        foreach ($DCName in $DomainControllers) {
                                            if ($SubjectUserName -like "*$($DCName.Split('.')[0])*") {
                                                $IsDCAccount = $true
                                                break
                                            } #end if
                                        } #end foreach

                                        if (-not $IsDCAccount) {
                                            # ALERT! Non-DC replication request
                                            $AlertTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                                            Write-Warning -Message ('🚨 ALERT! DCSync attack detected at {0}' -f $AlertTime)
                                            Write-Warning -Message ('   Source Account: {0}\{1}' -f $EventData['SubjectDomainName'], $SubjectUserName)
                                            Write-Warning -Message ('   Domain Controller: {0}' -f $DC)
                                            Write-Warning -Message ('   Object Accessed: {0}' -f $EventData['ObjectName'])
                                        } #end if
                                    } #end if
                                } #end foreach
                            } #end if
                        } catch {
                            # Silently continue on errors (don't spam console)
                            Write-Debug -Message ('Real-time monitoring error on {0}: {1}' -f $DC, $_.Exception.Message)
                        } #end try-catch
                    } #end foreach

                    $LastCheck = Get-Date
                } #end while
            } #end if monitor real-time

        } catch {
            $errorMessage = 'DCSync detection audit failed'
            Write-Error -Message $errorMessage -Category OperationStopped
            Write-Debug -Message ('Error details: {0}' -f $_.Exception.Message)
            throw
        } #end try-catch

    } #end Process

    ######################
    # Section END
    end {

        if (-not $MonitorRealTime) {
            try {
                # Assess risk level
                if ($AuditResult.NonDCAccountCount -eq 0 -and $AuditResult.SuspiciousEventCount -eq 0) {
                    $AuditResult.IsSecure = $true
                    $AuditResult.RiskLevel = 'Secure'
                    $AuditResult.RecommendedActions = @(
                        'Continue monitoring Event ID 4662 for replication requests',
                        'Schedule monthly replication permission audits',
                        'Implement SIEM alerting for DCSync patterns'
                    )
                } elseif ($AuditResult.NonDCAccountCount -gt 0 -and $AuditResult.SuspiciousEventCount -eq 0) {
                    $AuditResult.IsSecure = $false
                    $AuditResult.RiskLevel = 'High'
                    $AuditResult.RecommendedActions = @(
                        ('URGENT: Remove replication permissions from {0} non-DC accounts' -f $AuditResult.NonDCAccountCount),
                        'Investigate why non-DC accounts have replication rights',
                        'Implement strict permission controls on domain root object',
                        'Enable Event ID 4662 auditing on all domain controllers',
                        'Rotate krbtgt password twice (10+ hour delay between rotations) as a precaution'
                    )
                } elseif ($AuditResult.SuspiciousEventCount -gt 0) {
                    $AuditResult.IsSecure = $false
                    $AuditResult.RiskLevel = 'Critical'
                    $AuditResult.RecommendedActions = @(
                        'IMMEDIATE ACTION REQUIRED: Active DCSync attack detected',
                        'Disable suspicious account(s) immediately',
                        'Investigate workstation/server where attack originated',
                        'Assume krbtgt hash is compromised',
                        'Rotate krbtgt password twice (10+ hour delay between rotations)',
                        'Review ALL Domain Admin accounts for unauthorized access',
                        'Engage incident response team for full forensic investigation',
                        'Check for lateral movement and persistence mechanisms'
                    )
                } else {
                    $AuditResult.IsSecure = $false
                    $AuditResult.RiskLevel = 'Unknown'
                    $AuditResult.RecommendedActions = @(
                        'Review audit results manually',
                        'Enable Event ID 4662 auditing if not already enabled'
                    )
                } #end if-elseif-else

                Write-Verbose -Message ('Risk Assessment: {0}' -f $AuditResult.RiskLevel)

                # Export reports if requested
                if ($PSBoundParameters.ContainsKey('ExportPath')) {
                    if ($PSCmdlet.ShouldProcess($ExportPath, 'Export DCSync audit reports')) {
                        Write-Verbose -Message 'Exporting detailed reports...'

                        # Create export directory if it doesn't exist
                        if (-not (Test-Path -Path $ExportPath)) {
                            try {
                                $null = New-Item -ItemType Directory -Path $ExportPath -Force -ErrorAction Stop
                                Write-Verbose -Message ('Created export directory: {0}' -f $ExportPath)
                            } catch {
                                Write-Error -Message ('Failed to create export directory: {0}' -f $ExportPath)
                                throw
                            } #end try-catch
                        } #end if

                        [string]$Timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'

                        # Export replication permissions
                        if ($AuditResult.NonDCAccounts.Count -gt 0) {
                            [string]$PermReport = Join-Path -Path $ExportPath -ChildPath ('DCSync-ReplicationPermissions-{0}.csv' -f $Timestamp)
                            try {
                                $AuditResult.NonDCAccounts | Export-Csv -Path $PermReport -NoTypeInformation -Force
                                [void]$ExportedReports.Add($PermReport)
                                Write-Verbose -Message ('Exported replication permissions report: {0}' -f $PermReport)
                            } catch {
                                Write-Warning -Message ('Failed to export permissions report: {0}' -f $_.Exception.Message)
                            } #end try-catch
                        } #end if

                        # Export suspicious events
                        if ($AuditResult.SuspiciousEvents.Count -gt 0) {
                            [string]$EventReport = Join-Path -Path $ExportPath -ChildPath ('DCSync-SuspiciousEvents-{0}.csv' -f $Timestamp)
                            try {
                                $AuditResult.SuspiciousEvents | Export-Csv -Path $EventReport -NoTypeInformation -Force
                                [void]$ExportedReports.Add($EventReport)
                                Write-Verbose -Message ('Exported suspicious events report: {0}' -f $EventReport)
                            } catch {
                                Write-Warning -Message ('Failed to export events report: {0}' -f $_.Exception.Message)
                            } #end try-catch
                        } #end if

                        # Export summary
                        [string]$SummaryReport = Join-Path -Path $ExportPath -ChildPath ('DCSync-Summary-{0}.txt' -f $Timestamp)
                        try {
                            [string]$SummaryText = @'
DCSync Attack Detection Summary
================================
Generated: {0}
Domain: {1}

REPLICATION PERMISSIONS AUDIT:
- Total Identities with Permissions: {2}
- Domain Controller Accounts: {3} (Expected)
- Non-DC Accounts: {4} {5}

EVENT LOG ANALYSIS (Last {6} Days):
- Total Replication Events: {7}
- Legitimate DC Replication: {8}
- SUSPICIOUS Events: {9} {10}

RISK ASSESSMENT:
- Security Status: {11}
- Risk Level: {12}

RECOMMENDED ACTIONS:
{13}

EXPORTED REPORTS:
{14}
'@ -f (Get-Date),
                            $AuditResult.DomainName,
                            $AuditResult.TotalAccountsWithPermissions,
                            $AuditResult.DomainControllerCount,
                            $AuditResult.NonDCAccountCount,
                            $(if ($AuditResult.NonDCAccountCount -eq 0) {
                                    '✓ SECURE'
                                } else {
                                    '🚨 CRITICAL RISK'
                                }),
                            $TimeSpanDays,
                            $AuditResult.TotalReplicationEvents,
                            ($AuditResult.TotalReplicationEvents - $AuditResult.SuspiciousEventCount),
                            $AuditResult.SuspiciousEventCount,
                            $(if ($AuditResult.SuspiciousEventCount -gt 0) {
                                    '🚨 ATTACK DETECTED'
                                } else {
                                    '✓ No attacks'
                                }),
                            $(if ($AuditResult.IsSecure) {
                                    'SECURE'
                                } else {
                                    'AT RISK'
                                }),
                            $AuditResult.RiskLevel,
                            (($AuditResult.RecommendedActions | ForEach-Object { "- $_" }) -join "`n"),
                            (($ExportedReports | ForEach-Object { "- $_" }) -join "`n")

                            $SummaryText | Out-File -FilePath $SummaryReport -Force
                            [void]$ExportedReports.Add($SummaryReport)
                            Write-Verbose -Message ('Exported summary report: {0}' -f $SummaryReport)
                        } catch {
                            Write-Warning -Message ('Failed to export summary report: {0}' -f $_.Exception.Message)
                        } #end try-catch

                        $AuditResult.ExportedReports = $ExportedReports

                    } #end if should process
                } #end if export path

                # Return audit result object
                Write-Output -InputObject $AuditResult

            } catch {
                Write-Error -Message 'Failed to finalize audit results'
                Write-Debug -Message ('Error details: {0}' -f $_.Exception.Message)
                throw
            } #end try-catch
        } #end if not monitor real-time

        if ($null -ne $Variables -and
            $null -ne $Variables.FooterSecurity) {

            $txt = ($Variables.FooterSecurity -f $MyInvocation.InvocationName,
                'finished auditing DCSync attacks.'
            )
            Write-Verbose -Message $txt
        } #end If

    } #end End

} #end function Get-DCSyncAttack
