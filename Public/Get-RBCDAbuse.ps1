function Get-RBCDAbuse {
    <#
    .SYNOPSIS
        Detects Resource-Based Constrained Delegation (RBCD) abuse in Active Directory.

    .DESCRIPTION
        This function performs comprehensive detection of RBCD abuse across your Active Directory environment
        by analyzing five critical detection vectors:

        Phase 1: Enumerate computers with msDS-AllowedToActOnBehalfOfOtherIdentity configured
        Phase 2: Detect Event 5136 (Directory Service Changes - RBCD attribute modifications)
        Phase 3: Monitor Event 4742 (Computer Account Changed)
        Phase 4: Analyze Event 4769 (Kerberos S4U2Proxy delegation requests)
        Phase 5: Audit MachineAccountQuota and detect anomalous computer account creation

        Resource-Based Constrained Delegation allows an attacker with WRITE permissions on a computer account
        to configure that computer to impersonate ANY domain user (including privileged accounts) to itself.
        This bypasses traditional Kerberos delegation controls and is a common privilege escalation vector.

        All findings are categorized by severity (CRITICAL/HIGH/MEDIUM) and exported to CSV and JSON formats.

    .PARAMETER DomainController
        Domain controller to query for Active Directory data and Event Log analysis.
        Supports pipeline input from Get-ADDomainController.

    .PARAMETER DaysToSearch
        Number of days to search backwards in Event Logs.
        Valid range: 1-365 days.

    .PARAMETER OutputPath
        Directory path for CSV/JSON output files.

    .PARAMETER CheckAllDCs
        Switch parameter to analyze all domain controllers in the forest.
        When enabled, queries all DCs for comprehensive event correlation.

    .EXAMPLE
        Get-RBCDAbuse -Verbose

        Scans the nearest domain controller for RBCD abuse indicators in the last 30 days.

    .EXAMPLE
        Get-RBCDAbuse -DomainController 'DC01.corp.local' -DaysToSearch 90 -OutputPath 'C:\SecurityAudits'

        Analyzes specific DC for RBCD abuse over the last 90 days with custom export path.

    .EXAMPLE
        Get-ADDomainController -Filter * | Get-RBCDAbuse -DaysToSearch 7

        Scans all domain controllers for recent RBCD activity (last 7 days) using pipeline input.

    .EXAMPLE
        Get-RBCDAbuse -CheckAllDCs -DaysToSearch 180 -Verbose

        Performs comprehensive 6-month analysis across all domain controllers with verbose output.

    .INPUTS
        System.String - Accepts domain controller names via pipeline (HostName, Name, ComputerName properties).

    .OUTPUTS
        PSCustomObject - Returns findings with properties:
        - DetectionPhase: Detection vector (Phase 1-5)
        - Severity: Risk level (CRITICAL/HIGH/MEDIUM)
        - ComputerName: Affected computer account
        - AllowedAccounts: Accounts permitted to delegate (Phase 1)
        - EventID: Windows Event ID (5136, 4742, 4769)
        - TimeCreated: Event timestamp
        - SubjectUserName: User who performed action
        - Recommendation: Remediation guidance

    .NOTES
        File Name      : Get-RBCDAbuse.ps1
        Author         : Vicente Rodriguez Eguibar
        Version        : 1.0.0
        Date Created   : 06/Mar/2026
        Date Modified  : 06/Mar/2026
        Prerequisite   : ActiveDirectory PowerShell module
        Copyright 2026 - Vicente Rodriguez Eguibar @ EguibarIT.com

    .LINK
        https://github.com/vreguibar/EguibarIT.SecurityPS

    .LINK
        https://attack.mitre.org/techniques/T1134/

    .COMPONENT
        EguibarIT.SecurityPS

    .ROLE
        Security Auditing

    .FUNCTIONALITY
        Resource-Based Constrained Delegation (RBCD) Abuse Detection
    #>

    [CmdletBinding(SupportsShouldProcess = $false, ConfirmImpact = 'Low')]
    [OutputType([PSCustomObject])]

    param(
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Domain controller to query for AD data and Event Logs.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('HostName', 'Name', 'ComputerName', 'Server')]
        [string]
        $DomainController,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Number of days to search backwards in Event Logs (1-365).',
            Position = 1)]
        [ValidateRange(1, 365)]
        [int]
        $DaysToSearch = 30,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Directory path for CSV/JSON output files.',
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        [string]
        $OutputPath = ('{0}\Desktop\RBCDAudit' -f $env:USERPROFILE),

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Analyze all domain controllers in the forest.',
            Position = 3)]
        [switch]
        $CheckAllDCs
    )

    Begin {

        $txt = ($Variables.HeaderHousekeeping -f
            (Get-Date).ToShortDateString(),
            $MyInvocation.Mycommand,
            (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
        )
        Write-Verbose -Message $txt

        ##############################
        # Module imports
        Import-MyModule -Name 'ActiveDirectory' -Verbose:$false

        ##############################
        # Variables Definition

        # Initialize result collections
        [System.Collections.ArrayList]$AllFindings = @()
        [int]$criticalAlerts = 0
        [int]$highAlerts = 0
        [int]$mediumAlerts = 0

        # Calculate start date
        $startDate = (Get-Date).AddDays(-$DaysToSearch)

        # Create output directory
        if (-not (Test-Path -Path $OutputPath)) {
            try {
                New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
                Write-Verbose -Message ('Created output directory: {0}' -f $OutputPath)
            } catch {
                Write-Warning -Message ('Failed to create output directory: {0}' -f $_.Exception.Message)
                $OutputPath = $env:USERPROFILE
                Write-Warning -Message ('Using fallback directory: {0}' -f $OutputPath)
            } #end try-catch
        } #end if

        Write-Verbose -Message ('RBCD Detection Initialized')
        Write-Verbose -Message ('Search Period: Last {0} days (from {1})' -f $DaysToSearch, $startDate.ToString('yyyy-MM-dd'))
        Write-Verbose -Message ('Output Path: {0}' -f $OutputPath)

    } #end Begin

    Process {

        try {

            # ============================================
            # Determine target domain controllers
            # ============================================

            if ($PSBoundParameters.ContainsKey('CheckAllDCs') -and $CheckAllDCs) {
                Write-Verbose -Message 'CheckAllDCs enabled - discovering all domain controllers...'
                try {
                    $domainControllers = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName
                    Write-Verbose -Message ('Found {0} domain controllers' -f $domainControllers.Count)
                } catch {
                    Write-Warning -Message ('Failed to enumerate domain controllers: {0}' -f $_.Exception.Message)
                    # Fallback to automatic discovery
                    $domainControllers = @((Get-ADDomainController -Discover -NextClosestSite).HostName)
                } #end try-catch
            } elseif ($PSBoundParameters.ContainsKey('DomainController') -and $DomainController) {
                Write-Verbose -Message ('Using specified domain controller: {0}' -f $DomainController)
                $domainControllers = @($DomainController)
            } else {
                # Auto-discover nearest DC
                try {
                    $discoveredDC = (Get-ADDomainController -Discover -NextClosestSite).HostName
                    Write-Verbose -Message ('Auto-discovered domain controller: {0}' -f $discoveredDC)
                    $domainControllers = @($discoveredDC)
                    $DomainController = $discoveredDC
                } catch {
                    Write-Error -Message ('Failed to discover domain controller: {0}' -f $_.Exception.Message) -ErrorAction Stop
                } #end try-catch
            } #end if-elseif-else

            # Use first DC for AD queries if not specified
            if (-not $DomainController) {
                $DomainController = $domainControllers[0]
            } #end if

            # ============================================
            # PHASE 1: ENUMERATE RBCD CONFIGURATIONS
            # ============================================

            Write-Verbose -Message '[Phase 1] Enumerating computers with RBCD configured...'

            try {
                $computersWithRBCD = Get-ADComputer -Filter * -Server $DomainController `
                    -Properties 'msDS-AllowedToActOnBehalfOfOtherIdentity', 'whenChanged', 'OperatingSystem', 'DistinguishedName' |
                Where-Object { $_.'msDS-AllowedToActOnBehalfOfOtherIdentity' -ne $null }

                Write-Verbose -Message ('[Phase 1] Found {0} computers with RBCD configured' -f $computersWithRBCD.Count)

                foreach ($computer in $computersWithRBCD) {
                    # Parse security descriptor to get allowed accounts
                    $rawSD = $computer.'msDS-AllowedToActOnBehalfOfOtherIdentity'
                    $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
                    $sd.SetSecurityDescriptorBinaryForm($rawSD)

                    [System.Collections.ArrayList]$allowedAccounts = @()
                    foreach ($ace in $sd.Access) {
                        try {
                            $account = New-Object System.Security.Principal.SecurityIdentifier($ace.IdentityReference)
                            $accountName = $account.Translate([System.Security.Principal.NTAccount]).Value
                            [void]$allowedAccounts.Add($accountName)
                        } catch {
                            [void]$allowedAccounts.Add($ace.IdentityReference.Value)
                        } #end try-catch
                    } #end foreach

                    # Determine severity - any RBCD config = critical until verified legitimate
                    $severity = 'CRITICAL'
                    $criticalAlerts++

                    $finding = [PSCustomObject]@{
                        DetectionPhase    = 'Phase 1: RBCD Configuration'
                        Severity          = $severity
                        ComputerName      = $computer.Name
                        OperatingSystem   = $computer.OperatingSystem
                        AllowedAccounts   = ($allowedAccounts -join '; ')
                        WhenChanged       = $computer.whenChanged
                        DistinguishedName = $computer.DistinguishedName
                        Recommendation    = ("Verify if RBCD configuration is legitimate. If unauthorized, remove with: Set-ADComputer '{0}' -Clear msDS-AllowedToActOnBehalfOfOtherIdentity" -f $computer.Name)
                        Timestamp         = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                    }
                    [void]$AllFindings.Add($finding)

                    Write-Debug -Message ('RBCD detected on {0} - Allowed: {1}' -f $computer.Name, ($allowedAccounts -join ', '))
                } #end foreach

            } catch {
                Write-Warning -Message ('[Phase 1] Error enumerating RBCD configurations: {0}' -f $_.Exception.Message)
            } #end try-catch

            # ============================================
            # PHASE 2: EVENT 5136 (DIRECTORY SERVICE CHANGES)
            # ============================================

            Write-Verbose -Message '[Phase 2] Analyzing Event 5136 (Directory Service Changes - RBCD attribute modifications)...'

            foreach ($dc in $domainControllers) {
                Write-Debug -Message ('[Phase 2] Querying {0}...' -f $dc)

                try {
                    $event5136 = Get-WinEvent -ComputerName $dc -FilterHashtable @{
                        LogName   = 'Security'
                        ID        = 5136
                        StartTime = $startDate
                    } -ErrorAction SilentlyContinue | Where-Object {
                        $_.Message -match 'msDS-AllowedToActOnBehalfOfOtherIdentity'
                    }

                    Write-Verbose -Message ('[Phase 2] {0}: Found {1} Event 5136 entries' -f $dc, $event5136.Count)

                    foreach ($event in $event5136) {
                        # Parse event properties
                        $eventXml = [xml]$event.ToXml()
                        $eventData = @{}
                        foreach ($data in $eventXml.Event.EventData.Data) {
                            $eventData[$data.Name] = $data.'#text'
                        } #end foreach

                        $severity = 'CRITICAL'
                        $criticalAlerts++

                        $finding = [PSCustomObject]@{
                            DetectionPhase    = 'Phase 2: Event 5136 (RBCD Modification)'
                            Severity          = $severity
                            EventID           = 5136
                            TimeCreated       = $event.TimeCreated
                            DomainController  = $dc
                            SubjectUserName   = $eventData['SubjectUserName']
                            SubjectDomainName = $eventData['SubjectDomainName']
                            ObjectDN          = $eventData['ObjectDN']
                            AttributeName     = $eventData['AttributeLDAPDisplayName']
                            OperationType     = $eventData['OperationType']
                            AttributeValue    = $eventData['AttributeValue']
                            Recommendation    = ("CRITICAL: msDS-AllowedToActOnBehalfOfOtherIdentity modified. Verify authorization. If unauthorized, remove RBCD config and investigate '{0}' account compromise." -f $eventData['SubjectUserName'])
                            Timestamp         = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                        }
                        [void]$AllFindings.Add($finding)

                        Write-Debug -Message ('Event 5136: {0} modified {1}' -f $eventData['SubjectUserName'], $eventData['ObjectDN'])
                    } #end foreach

                } catch {
                    Write-Warning -Message ('[Phase 2] Unable to query {0}: {1}' -f $dc, $_.Exception.Message)
                } #end try-catch
            } #end foreach

            Write-Verbose -Message '[Phase 2] Event 5136 analysis complete'

            # ============================================
            # PHASE 3: EVENT 4742 (COMPUTER ACCOUNT CHANGED)
            # ============================================

            Write-Verbose -Message '[Phase 3] Analyzing Event 4742 (Computer Account Changed)...'

            foreach ($dc in $domainControllers) {
                Write-Debug -Message ('[Phase 3] Querying {0}...' -f $dc)

                try {
                    $event4742 = Get-WinEvent -ComputerName $dc -FilterHashtable @{
                        LogName   = 'Security'
                        ID        = 4742
                        StartTime = $startDate
                    } -ErrorAction SilentlyContinue | Where-Object {
                        $_.Message -match 'msDS-AllowedToActOnBehalfOfOtherIdentity'
                    }

                    Write-Verbose -Message ('[Phase 3] {0}: Found {1} Event 4742 entries' -f $dc, $event4742.Count)

                    foreach ($event in $event4742) {
                        $eventXml = [xml]$event.ToXml()
                        $eventData = @{}
                        foreach ($data in $eventXml.Event.EventData.Data) {
                            $eventData[$data.Name] = $data.'#text'
                        } #end foreach

                        $severity = 'CRITICAL'
                        $criticalAlerts++

                        $finding = [PSCustomObject]@{
                            DetectionPhase     = 'Phase 3: Event 4742 (Computer Changed)'
                            Severity           = $severity
                            EventID            = 4742
                            TimeCreated        = $event.TimeCreated
                            DomainController   = $dc
                            SubjectUserName    = $eventData['SubjectUserName']
                            SubjectDomainName  = $eventData['SubjectDomainName']
                            TargetComputerName = $eventData['TargetUserName']
                            Recommendation     = 'CRITICAL: Computer account modified (RBCD-related). Correlate with Event 5136. Verify authorization.'
                            Timestamp          = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                        }
                        [void]$AllFindings.Add($finding)

                        Write-Debug -Message ('Event 4742: {0} modified computer {1}' -f $eventData['SubjectUserName'], $eventData['TargetUserName'])
                    } #end foreach

                } catch {
                    Write-Warning -Message ('[Phase 3] Unable to query {0}: {1}' -f $dc, $_.Exception.Message)
                } #end try-catch
            } #end foreach

            Write-Verbose -Message '[Phase 3] Event 4742 analysis complete'

            # ============================================
            # PHASE 4: EVENT 4769 (KERBEROS S4U2PROXY)
            # ============================================

            Write-Verbose -Message '[Phase 4] Analyzing Event 4769 (Kerberos S4U2Proxy delegation requests)...'

            foreach ($dc in $domainControllers) {
                Write-Debug -Message ('[Phase 4] Querying {0}...' -f $dc)

                try {
                    $event4769 = Get-WinEvent -ComputerName $dc -FilterHashtable @{
                        LogName   = 'Security'
                        ID        = 4769
                        StartTime = $startDate
                    } -MaxEvents 10000 -ErrorAction SilentlyContinue

                    # Filter for S4U2Proxy ticket requests (Ticket Options = 0x40810000)
                    $s4u2ProxyEvents = $event4769 | Where-Object {
                        $eventXml = [xml]$_.ToXml()
                        $ticketOptions = $eventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'TicketOptions' } | Select-Object -ExpandProperty '#text'
                        $ticketOptions -eq '0x40810000'
                    }

                    Write-Verbose -Message ('[Phase 4] {0}: Found {1} S4U2Proxy events' -f $dc, $s4u2ProxyEvents.Count)

                    foreach ($event in $s4u2ProxyEvents) {
                        $eventXml = [xml]$event.ToXml()
                        $eventData = @{}
                        foreach ($data in $eventXml.Event.EventData.Data) {
                            $eventData[$data.Name] = $data.'#text'
                        } #end foreach

                        # Severity based on context - S4U2Proxy = potential RBCD abuse (or legitimate delegation)
                        $severity = 'HIGH'
                        $highAlerts++

                        $finding = [PSCustomObject]@{
                            DetectionPhase        = 'Phase 4: Event 4769 (S4U2Proxy)'
                            Severity              = $severity
                            EventID               = 4769
                            TimeCreated           = $event.TimeCreated
                            DomainController      = $dc
                            ServiceName           = $eventData['ServiceName']
                            TargetUserName        = $eventData['TargetUserName']
                            ClientAddress         = $eventData['IpAddress']
                            TicketOptions         = $eventData['TicketOptions']
                            TicketEncryptionType  = $eventData['TicketEncryptionType']
                            Recommendation        = 'HIGH: S4U2Proxy delegation detected (Ticket Options 0x40810000). Verify if legitimate delegation or RBCD abuse. Correlate with Phase 1 RBCD configurations.'
                            Timestamp             = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                        }
                        [void]$AllFindings.Add($finding)

                        Write-Debug -Message ('Event 4769: S4U2Proxy - Service: {0}, Target: {1}' -f $eventData['ServiceName'], $eventData['TargetUserName'])
                    } #end foreach

                } catch {
                    Write-Warning -Message ('[Phase 4] Unable to query {0}: {1}' -f $dc, $_.Exception.Message)
                } #end try-catch
            } #end foreach

            Write-Verbose -Message '[Phase 4] Event 4769 analysis complete'

            # ============================================
            # PHASE 5: MACHINE ACCOUNT QUOTA AUDIT
            # ============================================

            Write-Verbose -Message '[Phase 5] Auditing MachineAccountQuota and computer account creation...'

            try {
                # Check MachineAccountQuota setting
                $domain = Get-ADDomain -Server $DomainController
                $domainDN = $domain.DistinguishedName
                $domainObject = Get-ADObject -Identity $domainDN -Properties 'ms-DS-MachineAccountQuota' -Server $DomainController
                $machineAccountQuota = $domainObject.'ms-DS-MachineAccountQuota'

                Write-Verbose -Message ('[Phase 5] Current MachineAccountQuota: {0}' -f $machineAccountQuota)

                if ($machineAccountQuota -gt 0) {
                    $severity = 'HIGH'
                    $highAlerts++

                    $finding = [PSCustomObject]@{
                        DetectionPhase = 'Phase 5: MachineAccountQuota Audit'
                        Severity       = $severity
                        Setting        = 'ms-DS-MachineAccountQuota'
                        CurrentValue   = $machineAccountQuota
                        Recommendation = ("HIGH: MachineAccountQuota is {0} (allows non-admin users to create computer accounts). Attackers exploit this to create controlled computers for RBCD. Set to 0: Set-ADDomain -Identity (Get-ADDomain) -Replace @{{'ms-DS-MachineAccountQuota' = 0}}" -f $machineAccountQuota)
                        Timestamp      = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                    }
                    [void]$AllFindings.Add($finding)

                    Write-Warning -Message ('MachineAccountQuota is {0} - allows non-admin computer creation (RBCD attack vector)' -f $machineAccountQuota)
                } else {
                    Write-Verbose -Message 'MachineAccountQuota is 0 (secure configuration)'
                } #end if-else

                # Enumerate recently created computer accounts
                $recentComputers = Get-ADComputer -Filter { whenCreated -gt $startDate } -Server $DomainController `
                    -Properties 'whenCreated', 'Creator', 'DistinguishedName'

                Write-Verbose -Message ('[Phase 5] Found {0} recently created computer accounts' -f $recentComputers.Count)

                foreach ($computer in $recentComputers) {
                    # Check if creator is NOT Domain Admin or Enterprise Admin
                    $creator = $computer.Creator
                    if ($creator) {
                        try {
                            $creatorUser = Get-ADUser -Filter { DistinguishedName -eq $creator } -Server $DomainController -ErrorAction SilentlyContinue

                            if ($creatorUser) {
                                $creatorGroups = Get-ADPrincipalGroupMembership -Identity $creatorUser -Server $DomainController | Select-Object -ExpandProperty Name
                                $isPrivileged = $creatorGroups -contains 'Domain Admins' -or $creatorGroups -contains 'Enterprise Admins'

                                if (-not $isPrivileged) {
                                    $severity = 'MEDIUM'
                                    $mediumAlerts++

                                    $finding = [PSCustomObject]@{
                                        DetectionPhase = 'Phase 5: Computer Account Creation'
                                        Severity       = $severity
                                        ComputerName   = $computer.Name
                                        Creator        = $creator
                                        WhenCreated    = $computer.whenCreated
                                        Recommendation = ("MEDIUM: Computer account created by non-admin user '{0}'. Verify legitimacy. If unauthorized, may be attacker-controlled account for RBCD (e.g., ATTACKER-PC$). Disable with: Disable-ADAccount '{1}'" -f $creator, $computer.Name)
                                        Timestamp      = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                                    }
                                    [void]$AllFindings.Add($finding)

                                    Write-Debug -Message ('Non-admin computer creation: {0} by {1}' -f $computer.Name, $creator)
                                } #end if
                            } #end if
                        } catch {
                            Write-Debug -Message ('Unable to resolve creator for {0}: {1}' -f $computer.Name, $_.Exception.Message)
                        } #end try-catch
                    } #end if
                } #end foreach

                Write-Verbose -Message '[Phase 5] MachineAccountQuota audit complete'

            } catch {
                Write-Warning -Message ('[Phase 5] Error during MachineAccountQuota audit: {0}' -f $_.Exception.Message)
            } #end try-catch

            # ============================================
            # EXPORT RESULTS
            # ============================================

            if ($AllFindings.Count -gt 0) {
                Write-Verbose -Message ('Exporting {0} findings to CSV and JSON...' -f $AllFindings.Count)

                $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'

                # Export CSV
                $csvPath = Join-Path -Path $OutputPath -ChildPath ('RBCD_Detection_{0}.csv' -f $timestamp)
                try {
                    $AllFindings | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
                    Write-Verbose -Message ('CSV exported: {0}' -f $csvPath)
                } catch {
                    Write-Warning -Message ('Failed to export CSV: {0}' -f $_.Exception.Message)
                } #end try-catch

                # Export JSON
                $jsonPath = Join-Path -Path $OutputPath -ChildPath ('RBCD_Detection_{0}.json' -f $timestamp)
                try {
                    $AllFindings | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
                    Write-Verbose -Message ('JSON exported: {0}' -f $jsonPath)
                } catch {
                    Write-Warning -Message ('Failed to export JSON: {0}' -f $_.Exception.Message)
                } #end try-catch

                # Output summary
                Write-Verbose -Message ''
                Write-Verbose -Message '==============================================='
                Write-Verbose -Message 'RBCD DETECTION SUMMARY'
                Write-Verbose -Message '==============================================='
                Write-Verbose -Message ('Total Findings: {0}' -f $AllFindings.Count)
                Write-Verbose -Message ('  CRITICAL: {0}' -f $criticalAlerts)
                Write-Verbose -Message ('  HIGH: {0}' -f $highAlerts)
                Write-Verbose -Message ('  MEDIUM: {0}' -f $mediumAlerts)
                Write-Verbose -Message ''
                Write-Verbose -Message 'Key Findings:'
                Write-Verbose -Message ('  - Computers with RBCD configured: {0}' -f $computersWithRBCD.Count)
                Write-Verbose -Message ('  - Event 5136 (RBCD modifications): {0}' -f ($AllFindings | Where-Object { $_.DetectionPhase -eq 'Phase 2: Event 5136 (RBCD Modification)' }).Count)
                Write-Verbose -Message ('  - Event 4769 (S4U2Proxy requests): {0}' -f ($AllFindings | Where-Object { $_.DetectionPhase -eq 'Phase 4: Event 4769 (S4U2Proxy)' }).Count)
                Write-Verbose -Message ('  - MachineAccountQuota: {0}' -f $machineAccountQuota)
                Write-Verbose -Message '==============================================='

                if ($criticalAlerts -gt 0) {
                    Write-Warning -Message ('{0} CRITICAL findings detected! Review RBCD configurations immediately.' -f $criticalAlerts)
                } #end if

            } else {
                Write-Verbose -Message 'No RBCD abuse indicators detected. Continue monitoring Event 5136 and periodic AD scans.'
            } #end if-else

        } catch {
            Write-Error -Message ('RBCD detection failed: {0}' -f $_.Exception.Message)
            throw
        } #end try-catch

    } #end Process

    End {
        $txt = ($Variables.FooterHousekeeping -f $MyInvocation.InvocationName, 'detecting RBCD abuse.')
        Write-Verbose -Message $txt

        # Return findings
        return $AllFindings
    } #end End

} #end function Get-RBCDAbuse
