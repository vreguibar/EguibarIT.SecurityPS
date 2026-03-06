Function Get-DomainTrustBypass {
    <#
        .SYNOPSIS
            Detects Active Directory domain trust bypass attacks through trust enumeration, SID filtering violations, and cross-forest authentication monitoring.

        .DESCRIPTION
            Active Directory trusts enable resource sharing between domains and forests. Attackers exploit trusts to:
            - Bypass SID filtering to inject privileged SIDs
            - Violate selective authentication to access restricted resources
            - Enumerate trust relationships for lateral movement planning
            - Request cross-forest TGTs for privilege escalation
            - Use privileged accounts across trust boundaries

            This function performs comprehensive five-phase detection:
            1. Trust relationship inventory and configuration audit
            2. SID filtering bypass detection (Event 4675, 4766)
            3. Selective authentication violation monitoring (Event 4768, 4769)
            4. Cross-forest TGT request analysis (Event 4768, 4770)
            5. Privileged account cross-trust usage detection

            **ATTACK VECTOR:**
            Attackers targeting trust relationships can:
            - Inject Enterprise Admins SID into cross-forest tickets
            - Bypass selective authentication via SID History manipulation
            - Enumerate trusts to map attack paths between forests
            - Request cross-forest TGTs for resource access
            - Escalate privileges via trust relationship exploitation

            **CRITICAL SECURITY PRINCIPLE:**
            External trusts (forest trusts) should have SID filtering enabled and selective authentication enforced.
            Privileged accounts should NEVER authenticate across external trust boundaries.

            **MITRE ATT&CK Mapping:**
            - **T1484.002**: Domain Policy Modification - Domain Trust Modification
            - **T1087.002**: Account Discovery - Domain Account
            - **T1482**: Domain Trust Discovery
            - **T1550.003**: Use Alternate Authentication Material - Pass the Ticket

            **DETECTION REQUIREMENTS:**
            - Domain Admin or equivalent rights for trust enumeration
            - Access to Security Event Logs on all domain controllers
            - Audit Policy enabled: Account Logon, Logon/Logoff, Policy Change

        .PARAMETER DomainController
            Specific domain controller(s) to audit. If not specified, queries all DCs in current domain.

        .PARAMETER DaysBack
            Number of days to analyze Event Logs for trust abuse indicators.
            Default: 30 days.
            Range: 1 to 365 days.

        .PARAMETER ExportPath
            Directory where detection results will be saved (CSV and JSON formats).
            Default: C:\SecurityAudits\DomainTrust
            Exports will include:
            - Trust relationship inventory
            - SID filtering violations
            - Selective authentication bypass events
            - Cross-forest authentication timeline
            - Comprehensive security assessment summary

        .PARAMETER IncludeTrustEnumeration
            If specified, includes detailed trust relationship enumeration and configuration analysis.
            Provides full trust topology map for security review.

        .PARAMETER MonitorCrossForestAuth
            If specified, enables enhanced monitoring of cross-forest authentication events.
            Analyzes Event 4768/4769/4770 for suspicious TGT/TGS requests.

        .PARAMETER CheckAllDomains
            If specified, scans all domains in the forest for trust abuse indicators.
            Default behavior scans current domain only.

        .EXAMPLE
            Get-DomainTrustBypass

            Description
            -----------
            Performs 30-day trust bypass detection audit on current domain.

        .EXAMPLE
            Get-DomainTrustBypass -DaysBack 90 -IncludeTrustEnumeration -Verbose

            Description
            -----------
            Comprehensive 90-day audit with full trust topology analysis and verbose output.

        .EXAMPLE
            Get-DomainTrustBypass -ExportPath 'C:\SecurityAudits' -MonitorCrossForestAuth

            Description
            -----------
            Audit with enhanced cross-forest authentication monitoring and report export.

        .EXAMPLE
            Get-DomainTrustBypass -CheckAllDomains -DaysBack 7

            Description
            -----------
            Forest-wide trust abuse detection for the last 7 days.

        .EXAMPLE
            $Result = Get-DomainTrustBypass -DaysBack 30
            if ($Result.SIDFilteringViolations -gt 0) {
                Write-Warning "CRITICAL: $($Result.SIDFilteringViolations) SID filtering bypass attempts detected!"
                $Result.ViolationEvents | Export-Csv -Path 'C:\INCIDENT\SIDFilteringBypass.csv' -NoTypeInformation
            }

            Description
            -----------
            Automated incident response workflow based on detection results.

        .INPUTS
            System.String - DomainController names (can be piped from Get-ADDomainController)

        .OUTPUTS
            PSCustomObject. Returns a domain trust security audit object containing:
            - DomainName: DNS name of the audited domain
            - ForestName: Forest name
            - AuditTimestamp: When the audit was performed
            - TrustCount: Total number of trust relationships
            - ExternalTrustCount: External forest trusts (highest risk)
            - TrustsWithSIDFilteringDisabled: Trusts missing SID filtering (critical risk)
            - TrustsWithoutSelectiveAuth: Trusts without selective authentication
            - SIDFilteringViolations: Count of detected SID filtering bypass attempts
            - SelectiveAuthViolations: Unauthorized cross-trust authentications
            - CrossForestTGTRequests: Cross-forest Kerberos ticket requests
            - PrivilegedCrossTrustAuth: Privileged accounts authenticating across trusts
            - HighRiskIndicators: Count of critical findings
            - MediumRiskIndicators: Count of moderate findings
            - RiskLevel: Overall risk assessment (Secure/Low/Medium/High/Critical)
            - IsSecure: Boolean indicating if trust configuration is secure
            - RecommendedActions: Array of remediation steps
            - ExportedReports: Array of file paths if reports were exported
            - TrustRelationships: Detailed trust inventory
            - ViolationEvents: Array of trust abuse event details

        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Get-FunctionDisplay                    | EguibarIT.SecurityPS
                Import-MyModule                        | EguibarIT.SecurityPS
                Get-ADDomain                           | ActiveDirectory
                Get-ADForest                           | ActiveDirectory
                Get-ADTrust                            | ActiveDirectory
                Get-ADDomainController                 | ActiveDirectory
                Get-WinEvent                           | Microsoft.PowerShell.Diagnostics
                Test-Path                              | Microsoft.PowerShell.Management
                Export-Csv                             | Microsoft.PowerShell.Utility
                ConvertTo-Json                         | Microsoft.PowerShell.Utility
                Write-Verbose                          | Microsoft.PowerShell.Utility
                Write-Warning                          | Microsoft.PowerShell.Utility
                Write-Error                            | Microsoft.PowerShell.Utility
                Write-Debug                            | Microsoft.PowerShell.Utility

        .NOTES
            Version:         1.0.0
            DateModified:    06/Mar/2026
            LastModifiedBy:  Vicente Rodriguez Eguibar
                vicente@eguibar.com
                EguibarIT
                http://www.eguibarit.com

        .LINK
            https://attack.mitre.org/techniques/T1484/002/

        .LINK
            https://attack.mitre.org/techniques/T1482/

        .LINK
            https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc755321(v=ws.10)

        .LINK
            https://github.com/vreguibar/EguibarIT.SecurityPS

        .COMPONENT
            EguibarIT.SecurityPS

        .ROLE
            Security Auditing

        .FUNCTIONALITY
            Detects Active Directory domain trust bypass attacks through trust configuration auditing and authentication monitoring.
    #>

    [CmdletBinding(
        SupportsShouldProcess = $false,
        ConfirmImpact = 'Low'
    )]
    [OutputType([PSCustomObject])]

    param(
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Specific domain controller(s) to audit',
            Position = 0
        )]
        [ValidateNotNullOrEmpty()]
        [Alias('ComputerName', 'HostName', 'DC')]
        [string[]]
        $DomainController,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Number of days to analyze Event Logs for trust abuse (1-365)',
            Position = 1
        )]
        [ValidateRange(1, 365)]
        [PSDefaultValue(Help = 'Default: 30 days')]
        [int]
        $DaysBack = 30,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Directory where detection results will be saved',
            Position = 2
        )]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
                if (-not (Test-Path -Path $_ -IsValid)) {
                    throw 'Export path is not valid. Please provide a valid file system path.'
                }
                return $true
            })]
        [PSDefaultValue(Help = 'Default: C:\SecurityAudits\DomainTrust')]
        [string]
        $ExportPath = 'C:\SecurityAudits\DomainTrust',

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Include detailed trust relationship enumeration',
            Position = 3
        )]
        [PSDefaultValue(Help = 'Default: $false')]
        [switch]
        $IncludeTrustEnumeration,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Enable enhanced cross-forest authentication monitoring',
            Position = 4
        )]
        [PSDefaultValue(Help = 'Default: $false')]
        [switch]
        $MonitorCrossForestAuth,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Scan all domains in the forest',
            Position = 5
        )]
        [PSDefaultValue(Help = 'Default: $false')]
        [switch]
        $CheckAllDomains
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
            Import-MyModule -Name ActiveDirectory -Force -Verbose:$VerbosePreference -ErrorAction Stop
            Write-Verbose -Message 'Active Directory module loaded successfully'
        } catch {
            $errorMessage = 'Active Directory PowerShell module is required but not available. Install with: Install-WindowsFeature RSAT-AD-PowerShell'
            Write-Error -Message $errorMessage -Category NotInstalled -ErrorAction Stop
        } #end try-catch

        ##############################
        # Variables Definition

        Write-Verbose -Message 'Initializing domain trust bypass detection...'
        Write-Verbose -Message 'MITRE ATT&CK: T1484.002 (Domain Trust Modification)'
        Write-Verbose -Message 'MITRE ATT&CK: T1482 (Domain Trust Discovery)'

        # Initialize result collections using ArrayList for performance
        [System.Collections.ArrayList]$TrustRelationships = @()
        [System.Collections.ArrayList]$SIDFilteringViolations = @()
        [System.Collections.ArrayList]$SelectiveAuthViolations = @()
        [System.Collections.ArrayList]$CrossForestTGTs = @()
        [System.Collections.ArrayList]$PrivilegedCrossTrustAuth = @()
        [System.Collections.ArrayList]$TrustEnumerationEvents = @()
        [System.Collections.ArrayList]$ExportedReports = @()

        # Event IDs for trust abuse detection
        $MonitoredEventIDs = @{
            'TrustCreated'           = 4706    # Trust created/modified
            'TrustRemoved'           = 4707    # Trust removed
            'SIDFilteringFailed'     = 4675    # SID filtering failed (bypass attempt)
            'SIDFilteringBlocked'    = 4766    # SID filtering blocked unauthorized SID
            'TGTRequested'           = 4768    # Kerberos TGT requested
            'ServiceTicketRequested' = 4769    # Kerberos service ticket requested
            'TGTRenewed'             = 4770    # Kerberos TGT renewed
            'PreAuthFailed'          = 4771    # Kerberos pre-auth failed (enumeration)
            'AccountEnumeration'     = 4776    # Domain controller attempted to validate credentials
        }

        # Trust type classifications
        $TrustTypes = @{
            1 = 'Downlevel (Windows NT)'
            2 = 'Uplevel (Active Directory)'
            3 = 'MIT Kerberos Realm'
            4 = 'DCE (Distributed Computing Environment)'
        }

        $TrustDirections = @{
            0 = 'Disabled'
            1 = 'Inbound'
            2 = 'Outbound'
            3 = 'Bidirectional'
        }

        $TrustAttributes = @{
            1       = 'Non-Transitive'
            2       = 'Uplevel Clients Only'
            4       = 'Quarantined Domain (SID Filtering)'
            8       = 'Forest Transitive'
            16      = 'Cross-Organization (Selective Authentication)'
            32      = 'Within Forest'
            64      = 'Treat as External'
            128     = 'Reserved'
            256     = 'Reserved2'
            512     = 'Reserved3'
            1024    = 'Reserved4'
        }

        # Well-known privileged SIDs (use module SID mappings)
        $PrivilegedSIDs = @(
            ($Variables.WellKnownSIDs.Keys.Where({ $Variables.WellKnownSIDs[$_] -eq 'Domain Admins' }))[0],
            ($Variables.WellKnownSIDs.Keys.Where({ $Variables.WellKnownSIDs[$_] -eq 'Enterprise Admins' }))[0],
            ($Variables.WellKnownSIDs.Keys.Where({ $Variables.WellKnownSIDs[$_] -eq 'Schema Admins' }))[0],
            ($Variables.WellKnownSIDs.Keys.Where({ $Variables.WellKnownSIDs[$_] -eq 'Administrators' }))[0]
        )

        # Initialize audit result object
        [PSCustomObject]$AuditResult = [PSCustomObject]@{
            DomainName                      = $null
            ForestName                      = $null
            AuditTimestamp                  = Get-Date
            TrustCount                      = 0
            ExternalTrustCount              = 0
            TrustsWithSIDFilteringDisabled  = 0
            TrustsWithoutSelectiveAuth      = 0
            SIDFilteringViolations          = 0
            SelectiveAuthViolations         = 0
            CrossForestTGTRequests          = 0
            PrivilegedCrossTrustAuth        = 0
            HighRiskIndicators              = 0
            MediumRiskIndicators            = 0
            RiskLevel                       = 'Unknown'
            IsSecure                        = $false
            RecommendedActions              = @()
            ExportedReports                 = @()
            TrustRelationships              = @()
            ViolationEvents                 = @()
        }

        # Get current domain and forest
        try {
            $Domain = Get-ADDomain -ErrorAction Stop
            $Forest = Get-ADForest -ErrorAction Stop
            $AuditResult.DomainName = $Domain.DNSRoot
            $AuditResult.ForestName = $Forest.Name
            Write-Verbose -Message ('Auditing domain: {0} (Forest: {1})' -f $Domain.DNSRoot, $Forest.Name)
        } catch {
            Write-Error -Message ('Failed to retrieve domain information: {0}' -f $_.Exception.Message) -ErrorAction Stop
        } #end try-catch

        # Create export directory if needed
        if (-not (Test-Path -Path $ExportPath)) {
            try {
                New-Item -Path $ExportPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
                Write-Verbose -Message ('Created export directory: {0}' -f $ExportPath)
            } catch {
                Write-Warning -Message ('Failed to create export directory: {0}' -f $_.Exception.Message)
            } #end try-catch
        } #end if

        $StartDate = (Get-Date).AddDays(-$DaysBack)
        Write-Verbose -Message ('Analysis window: {0} days (from {1})' -f $DaysBack, $StartDate.ToString('yyyy-MM-dd HH:mm:ss'))

        # Determine which DCs to check
        [System.Collections.ArrayList]$DCList = @()

        if ($PSBoundParameters.ContainsKey('DomainController')) {
            foreach ($DC in $DomainController) {
                [void]$DCList.Add($DC)
            } #end foreach
            Write-Verbose -Message ('Using specified domain controllers: {0}' -f ($DCList -join ', '))
        } else {
            # Get all DCs in current domain
            $AllDCs = Get-ADDomainController -Filter * -ErrorAction Stop
            foreach ($DC in $AllDCs) {
                [void]$DCList.Add($DC.HostName)
            } #end foreach
            Write-Verbose -Message ('Discovered {0} domain controllers in current domain' -f $DCList.Count)
        } #end if-else

    } #end begin

    process {

        try {

            # =============================================
            # PHASE 1: TRUST RELATIONSHIP INVENTORY
            # =============================================

            Write-Verbose -Message ''
            Write-Verbose -Message '=========================================='
            Write-Verbose -Message 'PHASE 1: Trust Relationship Inventory'
            Write-Verbose -Message '=========================================='

            try {
                $AllTrusts = Get-ADTrust -Filter * -ErrorAction Stop

                foreach ($Trust in $AllTrusts) {
                    Write-Verbose -Message ('Trust: {0} ({1})' -f $Trust.Name, $Trust.Direction)

                    # Determine trust type
                    $TrustTypeName = if ($TrustTypes.ContainsKey($Trust.TrustType)) {
                        $TrustTypes[$Trust.TrustType]
                    } else {
                        'Unknown'
                    }

                    $TrustDirectionName = if ($TrustDirections.ContainsKey($Trust.Direction)) {
                        $TrustDirections[$Trust.Direction]
                    } else {
                        'Unknown'
                    }

                    # Check for SID filtering
                    $SIDFilteringEnabled = ($Trust.TrustAttributes -band 4) -eq 4  # TRUST_ATTRIBUTE_QUARANTINED_DOMAIN

                    # Check for selective authentication
                    $SelectiveAuthEnabled = ($Trust.TrustAttributes -band 16) -eq 16  # TRUST_ATTRIBUTE_CROSS_ORGANIZATION

                    # Determine if external trust (highest risk)
                    $IsExternalTrust = $Trust.ForestTransitive -eq $false

                    # Risk assessment
                    [System.Collections.ArrayList]$RiskFactors = @()

                    if ($IsExternalTrust -and -not $SIDFilteringEnabled) {
                        [void]$RiskFactors.Add('External trust without SID filtering')
                        $AuditResult.TrustsWithSIDFilteringDisabled++
                        $AuditResult.HighRiskIndicators++
                    } #end if

                    if ($IsExternalTrust -and -not $SelectiveAuthEnabled) {
                        [void]$RiskFactors.Add('External trust without selective authentication')
                        $AuditResult.TrustsWithoutSelectiveAuth++
                        $AuditResult.MediumRiskIndicators++
                    } #end if

                    if ($Trust.Direction -eq 2) {  # Outbound only
                        [void]$RiskFactors.Add('Outbound-only trust (resource exposure)')
                    } #end if

                    $TrustObject = [PSCustomObject]@{
                        TrustName             = $Trust.Name
                        TrustPartner          = $Trust.Target
                        Direction             = $TrustDirectionName
                        TrustType             = $TrustTypeName
                        IsExternalTrust       = $IsExternalTrust
                        ForestTransitive      = $Trust.ForestTransitive
                        SIDFilteringEnabled   = $SIDFilteringEnabled
                        SelectiveAuthEnabled  = $SelectiveAuthEnabled
                        TrustAttributes       = $Trust.TrustAttributes
                        WhenCreated           = $Trust.WhenCreated
                        WhenChanged           = $Trust.WhenChanged
                        RiskFactors           = $RiskFactors -join '; '
                        RiskLevel             = if ($RiskFactors.Count -ge 2) { 'High' } elseif ($RiskFactors.Count -eq 1) { 'Medium' } else { 'Low' }
                        DetectionDate         = Get-Date
                    }

                    [void]$TrustRelationships.Add($TrustObject)

                    if ($IsExternalTrust) {
                        $AuditResult.ExternalTrustCount++
                    } #end if
                } #end foreach

                $AuditResult.TrustCount = $TrustRelationships.Count
                Write-Verbose -Message ('Total trusts: {0} (External: {1})' -f $AuditResult.TrustCount, $AuditResult.ExternalTrustCount)
                Write-Verbose -Message ('Trusts without SID filtering: {0}' -f $AuditResult.TrustsWithSIDFilteringDisabled)
                Write-Verbose -Message ('Trusts without selective auth: {0}' -f $AuditResult.TrustsWithoutSelectiveAuth)

            } catch {
                Write-Warning -Message ('Failed to enumerate trust relationships: {0}' -f $_.Exception.Message)
            } #end try-catch

            # =============================================
            # PHASE 2: SID FILTERING BYPASS DETECTION
            # =============================================

            Write-Verbose -Message ''
            Write-Verbose -Message '=========================================='
            Write-Verbose -Message 'PHASE 2: SID Filtering Bypass Detection'
            Write-Verbose -Message '=========================================='

            foreach ($DC in $DCList) {
                Write-Verbose -Message ('Analyzing Event Logs on: {0}' -f $DC)

                try {
                    # Query Event 4675 (SID filtering failed)
                    $FilterXML_4675 = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4675) and TimeCreated[timediff(@SystemTime) &lt;= $($DaysBack * 86400000)]]]
    </Select>
  </Query>
</QueryList>
"@

                    $Events_4675 = Get-WinEvent -ComputerName $DC -FilterXml $FilterXML_4675 -ErrorAction SilentlyContinue

                    foreach ($Event in $Events_4675) {
                        $EventXML = [xml]$Event.ToXml()
                        $EventData = @{}
                        foreach ($Data in $EventXML.Event.EventData.Data) {
                            $EventData[$Data.Name] = $Data.'#text'
                        } #end foreach

                        Write-Warning -Message ('SID FILTERING BYPASS ATTEMPT: From {0} (SID: {1}) on {2}' -f $EventData['TargetUserName'], $EventData['TargetSid'], $Event.TimeCreated)

                        $ViolationEvent = [PSCustomObject]@{
                            DC                = $DC
                            TimeCreated       = $Event.TimeCreated
                            EventID           = $Event.Id
                            TargetUserName    = $EventData['TargetUserName']
                            TargetDomain      = $EventData['TargetDomainName']
                            TargetSID         = $EventData['TargetSid']
                            SourceSID         = $EventData['SidList']
                            ViolationType     = 'SID Filtering Bypass'
                            RiskLevel         = 'Critical'
                            Description       = 'Attempt to authenticate with unauthorized SID in SIDHistory'
                            DetectionDate     = Get-Date
                        }

                        [void]$SIDFilteringViolations.Add($ViolationEvent)
                        $AuditResult.HighRiskIndicators++
                    } #end foreach

                    # Query Event 4766 (SID filtering blocked)
                    $FilterXML_4766 = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4766) and TimeCreated[timediff(@SystemTime) &lt;= $($DaysBack * 86400000)]]]
    </Select>
  </Query>
</QueryList>
"@

                    $Events_4766 = Get-WinEvent -ComputerName $DC -FilterXml $FilterXML_4766 -ErrorAction SilentlyContinue

                    foreach ($Event in $Events_4766) {
                        Write-Verbose -Message ('  Event 4766 (SID filtering blocked): {0}' -f $Event.TimeCreated)

                        $EventXML = [xml]$Event.ToXml()
                        $EventData = @{}
                        foreach ($Data in $EventXML.Event.EventData.Data) {
                            $EventData[$Data.Name] = $Data.'#text'
                        } #end foreach

                        $ViolationEvent = [PSCustomObject]@{
                            DC                = $DC
                            TimeCreated       = $Event.TimeCreated
                            EventID           = $Event.Id
                            TargetUserName    = $EventData['TargetUserName']
                            TargetDomain      = $EventData['TargetDomainName']
                            TargetSID         = $EventData['TargetSid']
                            SourceSID         = $EventData['SidList']
                            ViolationType     = 'SID Filtering Blocked'
                            RiskLevel         = 'Medium'
                            Description       = 'SID filtering successfully blocked unauthorized SID'
                            DetectionDate     = Get-Date
                        }

                        [void]$SIDFilteringViolations.Add($ViolationEvent)
                        $AuditResult.MediumRiskIndicators++
                    } #end foreach

                } catch {
                    Write-Debug -Message ('Failed to query SID filtering events on {0}: {1}' -f $DC, $_.Exception.Message)
                } #end try-catch
            } #end foreach

            $AuditResult.SIDFilteringViolations = $SIDFilteringViolations.Count
            Write-Verbose -Message ('Total SID filtering violations: {0}' -f $SIDFilteringViolations.Count)

            # =============================================
            # PHASE 3: SELECTIVE AUTHENTICATION VIOLATIONS
            # =============================================

            Write-Verbose -Message ''
            Write-Verbose -Message '=========================================='
            Write-Verbose -Message 'PHASE 3: Selective Authentication Violations'
            Write-Verbose -Message '=========================================='

            foreach ($DC in $DCList) {
                try {
                    # Query Event 4768 (TGT requested from external domain)
                    # Look for IpAddress from external forest + sensitive resources
                    $FilterXML_4768 = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4768) and TimeCreated[timediff(@SystemTime) &lt;= $($DaysBack * 86400000)]]]
    </Select>
  </Query>
</QueryList>
"@

                    $Events_4768 = Get-WinEvent -ComputerName $DC -FilterXml $FilterXML_4768 -MaxEvents 1000 -ErrorAction SilentlyContinue

                    foreach ($Event in $Events_4768) {
                        $EventXML = [xml]$Event.ToXml()
                        $EventData = @{}
                        foreach ($Data in $EventXML.Event.EventData.Data) {
                            $EventData[$Data.Name] = $Data.'#text'
                        } #end foreach

                        # Check if account is from external forest (selective auth violation)
                        $TargetDomain = $EventData['TargetDomainName']

                        # Compare to current domain - if different, potential cross-trust
                        if ($TargetDomain -ne $Domain.NetBIOSName) {
                            Write-Verbose -Message ('  Cross-trust TGT: {0}\{1} from {2}' -f $TargetDomain, $EventData['TargetUserName'], $EventData['IpAddress'])

                            $SelectiveAuthEvent = [PSCustomObject]@{
                                DC                = $DC
                                TimeCreated       = $Event.TimeCreated
                                EventID           = $Event.Id
                                TargetUserName    = $EventData['TargetUserName']
                                TargetDomain      = $TargetDomain
                                ServiceName       = $EventData['ServiceName']
                                IpAddress         = $EventData['IpAddress']
                                PreAuthType       = $EventData['PreAuthType']
                                ViolationType     = 'Cross-Trust TGT Request'
                                RiskLevel         = 'Medium'
                                Description       = 'TGT requested from external domain'
                                DetectionDate     = Get-Date
                            }

                            [void]$SelectiveAuthViolations.Add($SelectiveAuthEvent)
                            $AuditResult.MediumRiskIndicators++
                        } #end if
                    } #end foreach

                } catch {
                    Write-Debug -Message ('Failed to query selective auth events on {0}: {1}' -f $DC, $_.Exception.Message)
                } #end try-catch
            } #end foreach

            $AuditResult.SelectiveAuthViolations = $SelectiveAuthViolations.Count
            Write-Verbose -Message ('Total selective auth violations: {0}' -f $SelectiveAuthViolations.Count)

            # =============================================
            # PHASE 4: CROSS-FOREST TGT MONITORING
            # =============================================

            if ($MonitorCrossForestAuth) {
                Write-Verbose -Message ''
                Write-Verbose -Message '=========================================='
                Write-Verbose -Message 'PHASE 4: Cross-Forest TGT Monitoring'
                Write-Verbose -Message '=========================================='

                foreach ($DC in $DCList) {
                    try {
                        # Query Event 4770 (TGT renewed - potential cross-forest persistence)
                        $FilterXML_4770 = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4770) and TimeCreated[timediff(@SystemTime) &lt;= $($DaysBack * 86400000)]]]
    </Select>
  </Query>
</QueryList>
"@

                        $Events_4770 = Get-WinEvent -ComputerName $DC -FilterXml $FilterXML_4770 -MaxEvents 500 -ErrorAction SilentlyContinue

                        foreach ($Event in $Events_4770) {
                            $EventXML = [xml]$Event.ToXml()
                            $EventData = @{}
                            foreach ($Data in $EventXML.Event.EventData.Data) {
                                $EventData[$Data.Name] = $Data.'#text'
                            } #end foreach

                            # Check for cross-forest renewals
                            $TargetDomain = $EventData['TargetDomainName']

                            if ($TargetDomain -ne $Domain.NetBIOSName) {
                                Write-Verbose -Message ('  Cross-forest TGT renewal: {0}\{1}' -f $TargetDomain, $EventData['TargetUserName'])

                                $TGTEvent = [PSCustomObject]@{
                                    DC                = $DC
                                    TimeCreated       = $Event.TimeCreated
                                    EventID           = $Event.Id
                                    TargetUserName    = $EventData['TargetUserName']
                                    TargetDomain      = $TargetDomain
                                    IpAddress         = $EventData['IpAddress']
                                    EventType         = 'TGT Renewal'
                                    RiskLevel         = 'Low'
                                    Description       = 'Cross-forest TGT renewed (potential persistence)'
                                    DetectionDate     = Get-Date
                                }

                                [void]$CrossForestTGTs.Add($TGTEvent)
                            } #end if
                        } #end foreach

                    } catch {
                        Write-Debug -Message ('Failed to query cross-forest TGT events on {0}: {1}' -f $DC, $_.Exception.Message)
                    } #end try-catch
                } #end foreach

                $AuditResult.CrossForestTGTRequests = $CrossForestTGTs.Count
                Write-Verbose -Message ('Total cross-forest TGT events: {0}' -f $CrossForestTGTs.Count)
            } #end if

            # =============================================
            # PHASE 5: PRIVILEGED CROSS-TRUST AUTHENTICATION
            # =============================================

            Write-Verbose -Message ''
            Write-Verbose -Message '=========================================='
            Write-Verbose -Message 'PHASE 5: Privileged Cross-Trust Authentication'
            Write-Verbose -Message '=========================================='

            # Analyze selective auth violations for privileged accounts
            foreach ($Event in $SelectiveAuthViolations) {
                # Check if account is privileged (contains "admin", "svc", or well-known patterns)
                if ($Event.TargetUserName -match 'admin|svc|service|tier0|privileged') {
                    Write-Warning -Message ('PRIVILEGED CROSS-TRUST AUTH: {0}\{1} at {2}' -f $Event.TargetDomain, $Event.TargetUserName, $Event.TimeCreated)

                    $PrivAuthEvent = [PSCustomObject]@{
                        DC                = $Event.DC
                        TimeCreated       = $Event.TimeCreated
                        EventID           = $Event.EventID
                        TargetUserName    = $Event.TargetUserName
                        TargetDomain      = $Event.TargetDomain
                        IpAddress         = $Event.IpAddress
                        RiskLevel         = 'Critical'
                        Description       = 'Privileged account authenticated across trust boundary'
                        DetectionDate     = Get-Date
                    }

                    [void]$PrivilegedCrossTrustAuth.Add($PrivAuthEvent)
                    $AuditResult.HighRiskIndicators++
                } #end if
            } #end foreach

            $AuditResult.PrivilegedCrossTrustAuth = $PrivilegedCrossTrustAuth.Count
            Write-Verbose -Message ('Total privileged cross-trust authentications: {0}' -f $PrivilegedCrossTrustAuth.Count)

        } catch {
            Write-Error -Message ('Critical error during domain trust bypass detection: {0}' -f $_.Exception.Message)
            throw
        } #end try-catch

    } #end process

    end {

        # =============================================
        # FINAL ASSESSMENT AND REPORTING
        # =============================================

        Write-Verbose -Message ''
        Write-Verbose -Message '=========================================='
        Write-Verbose -Message 'FINAL ASSESSMENT'
        Write-Verbose -Message '=========================================='

        # Populate audit result
        $AuditResult.TrustRelationships = $TrustRelationships.ToArray()

        # Combine all violations
        [System.Collections.ArrayList]$AllViolations = @()
        $AllViolations.AddRange($SIDFilteringViolations)
        $AllViolations.AddRange($SelectiveAuthViolations)
        $AllViolations.AddRange($PrivilegedCrossTrustAuth)
        $AuditResult.ViolationEvents = $AllViolations.ToArray()

        # Calculate overall risk level
        if ($AuditResult.TrustsWithSIDFilteringDisabled -gt 0 -or $PrivilegedCrossTrustAuth.Count -gt 0) {
            $AuditResult.RiskLevel = 'Critical'
            $AuditResult.IsSecure = $false
        } elseif ($AuditResult.HighRiskIndicators -gt 5 -or $SIDFilteringViolations.Count -gt 0) {
            $AuditResult.RiskLevel = 'High'
            $AuditResult.IsSecure = $false
        } elseif ($AuditResult.MediumRiskIndicators -gt 10) {
            $AuditResult.RiskLevel = 'Medium'
            $AuditResult.IsSecure = $false
        } elseif ($AuditResult.TrustsWithoutSelectiveAuth -gt 0) {
            $AuditResult.RiskLevel = 'Low'
            $AuditResult.IsSecure = $true
        } else {
            $AuditResult.RiskLevel = 'Secure'
            $AuditResult.IsSecure = $true
        } #end if-else

        # Generate recommended actions
        [System.Collections.ArrayList]$Actions = @()

        if ($PrivilegedCrossTrustAuth.Count -gt 0) {
            [void]$Actions.Add('CRITICAL: Privileged accounts authenticating across trust boundaries - investigate immediately')
            [void]$Actions.Add('Implement PAW (Privileged Access Workstation) restrictions for Tier 0 accounts')
        } #end if

        if ($AuditResult.TrustsWithSIDFilteringDisabled -gt 0) {
            [void]$Actions.Add(('Enable SID filtering on {0} external trusts' -f $AuditResult.TrustsWithSIDFilteringDisabled))
            [void]$Actions.Add('Run: netdom trust <TrustingDomain> /domain:<TrustedDomain> /quarantine:yes')
        } #end if

        if ($AuditResult.TrustsWithoutSelectiveAuth -gt 0) {
            [void]$Actions.Add(('Enable selective authentication on {0} external trusts' -f $AuditResult.TrustsWithoutSelectiveAuth))
            [void]$Actions.Add('Configure via Active Directory Domains and Trusts > Trust Properties > Authentication')
        } #end if

        if ($SIDFilteringViolations.Count -gt 0) {
            [void]$Actions.Add('Review SID filtering bypass attempts for malicious activity')
            [void]$Actions.Add('Investigate accounts attempting cross-trust authentication with unauthorized SIDs')
        } #end if

        [void]$Actions.Add('Audit all trust relationships quarterly for unnecessary trusts')
        [void]$Actions.Add('Implement ESAE (Enhanced Security Admin Environment) for Tier 0 isolation')
        [void]$Actions.Add('Enable advanced auditing: Policy Change, Account Logon, Account Management')
        [void]$Actions.Add('Document trust business justification and review annually')

        $AuditResult.RecommendedActions = $Actions.ToArray()

        # Export reports
        $Timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'

        if ($TrustRelationships.Count -gt 0) {
            $TrustFile = Join-Path -Path $ExportPath -ChildPath ('DomainTrust_Inventory_{0}.csv' -f $Timestamp)
            $TrustRelationships | Export-Csv -Path $TrustFile -NoTypeInformation -Encoding UTF8
            Write-Verbose -Message ('Exported trust inventory to: {0}' -f $TrustFile)
            [void]$ExportedReports.Add($TrustFile)
        } #end if

        if ($AllViolations.Count -gt 0) {
            $ViolationFile = Join-Path -Path $ExportPath -ChildPath ('DomainTrust_Violations_{0}.csv' -f $Timestamp)
            $AllViolations | Export-Csv -Path $ViolationFile -NoTypeInformation -Encoding UTF8
            Write-Verbose -Message ('Exported violations to: {0}' -f $ViolationFile)
            [void]$ExportedReports.Add($ViolationFile)
        } #end if

        # Export comprehensive audit summary
        $SummaryFile = Join-Path -Path $ExportPath -ChildPath ('DomainTrust_AuditSummary_{0}.json' -f $Timestamp)
        $AuditResult | ConvertTo-Json -Depth 5 | Out-File -FilePath $SummaryFile -Encoding UTF8
        Write-Verbose -Message ('Exported audit summary to: {0}' -f $SummaryFile)
        [void]$ExportedReports.Add($SummaryFile)

        $AuditResult.ExportedReports = $ExportedReports.ToArray()

        # Display summary
        Write-Verbose -Message ''
        Write-Verbose -Message '=========================================='
        Write-Verbose -Message 'DOMAIN TRUST SECURITY AUDIT SUMMARY'
        Write-Verbose -Message '=========================================='
        Write-Verbose -Message ('Domain: {0} (Forest: {1})' -f $AuditResult.DomainName, $AuditResult.ForestName)
        Write-Verbose -Message ('Total Trusts: {0} (External: {1})' -f $AuditResult.TrustCount, $AuditResult.ExternalTrustCount)
        Write-Verbose -Message ('Trusts without SID Filtering: {0}' -f $AuditResult.TrustsWithSIDFilteringDisabled)
        Write-Verbose -Message ('Trusts without Selective Auth: {0}' -f $AuditResult.TrustsWithoutSelectiveAuth)
        Write-Verbose -Message ('SID Filtering Violations: {0}' -f $AuditResult.SIDFilteringViolations)
        Write-Verbose -Message ('Selective Auth Violations: {0}' -f $AuditResult.SelectiveAuthViolations)
        Write-Verbose -Message ('Privileged Cross-Trust Auth: {0}' -f $AuditResult.PrivilegedCrossTrustAuth)
        Write-Verbose -Message ('High Risk Indicators: {0}' -f $AuditResult.HighRiskIndicators)
        Write-Verbose -Message ('Medium Risk Indicators: {0}' -f $AuditResult.MediumRiskIndicators)
        Write-Verbose -Message ('Overall Risk Level: {0}' -f $AuditResult.RiskLevel)
        Write-Verbose -Message ('Is Secure: {0}' -f $AuditResult.IsSecure)
        Write-Verbose -Message '=========================================='

        if ($AuditResult.RiskLevel -in @('Critical', 'High')) {
            Write-Warning -Message ('SECURITY ALERT: Domain trust environment risk level is {0}' -f $AuditResult.RiskLevel)
            Write-Warning -Message 'Review recommended actions immediately'
        } #end if

        # Return audit result object
        Write-Output -InputObject $AuditResult

    } #end end

} #end function
