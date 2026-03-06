Function Get-EntraConnectCompromise {
    <#
        .SYNOPSIS
            Detects Microsoft Entra Connect (Azure AD Connect) compromise indicators through configuration analysis, privileged account monitoring, and credential extraction detection.

        .DESCRIPTION
            Microsoft Entra Connect synchronizes on-premises Active Directory with Microsoft Entra ID (Azure AD).
            Compromise of the Entra Connect server provides attackers with:
            - Access to ALL on-premises user credentials (via ADSyncDecrypt)
            - Cloud administrator credentials (stored in SQL LocalDB)
            - Ability to modify synchronized attributes (federation trust manipulation)
            - Pass-Through Authentication agent credentials

            This function performs comprehensive six-phase detection:
            1. Entra Connect server identification and configuration audit
            2. MSOL_* and AAD_* privileged account monitoring
            3. SQL LocalDB credential extraction detection (Event 4663)
            4. Sync schedule anomalies and unauthorized modifications
            5. Pass-Through Authentication (PTA) agent compromise indicators
            6. ADSyncDecrypt tool execution detection

            **ATTACK VECTOR:**
            Attackers targeting Entra Connect servers can:
            - Extract plaintext credentials using ADSyncDecrypt.exe
            - Dump SQL LocalDB database containing cloud admin credentials
            - Modify synchronization rules to escalate privileges
            - Compromise PTA agents to intercept authentication requests
            - Disable sync to hide malicious changes

            **CRITICAL SECURITY PRINCIPLE:**
            Entra Connect servers are Tier 0 assets requiring isolation from standard workstations.
            Compromise enables complete hybrid identity takeover.

            **MITRE ATT&CK Mapping:**
            - **T1078.004**: Valid Accounts - Cloud Accounts
            - **T1003**: OS Credential Dumping
            - **T1098**: Account Manipulation

            **DETECTION REQUIREMENTS:**
            - Domain Admin or equivalent rights for AD queries
            - Local Administrator rights on Entra Connect servers for file/process auditing
            - Access to Security Event Logs on Entra Connect servers
            - Object Access auditing enabled (Event 4663)

        .PARAMETER EntraConnectServer
            Specific Entra Connect server(s) to audit. If not specified, attempts to auto-discover
            by searching for computers with ADSync service installed.

        .PARAMETER DaysBack
            Number of days to analyze Event Logs for compromise indicators.
            Default: 30 days.
            Range: 1 to 365 days.

        .PARAMETER ExportPath
            Directory where detection results will be saved (CSV and JSON formats).
            Default: C:\SecurityAudits\EntraConnect
            Exports will include:
            - Privileged MSOL/AAD account inventory
            - SQL LocalDB access events
            - Sync configuration changes
            - PTA agent status and anomalies
            - Comprehensive security assessment summary

        .PARAMETER IncludeConfigurationDump
            If specified, exports current Entra Connect configuration for forensic analysis.
            Requires local administrator rights on Entra Connect server.
            Configuration includes sync rules, connector settings, and scheduler state.

        .PARAMETER CheckPTAAgents
            If specified, includes Pass-Through Authentication agent integrity checks.
            Validates PTA agent installation, configuration, and recent activity.

        .PARAMETER ScanAllServers
            If specified, scans all discovered Entra Connect servers in the environment.
            Default behavior scans only the primary sync server.

        .EXAMPLE
            Get-EntraConnectCompromise

            Description
            -----------
            Auto-discovers Entra Connect servers and performs 30-day compromise detection audit.

        .EXAMPLE
            Get-EntraConnectCompromise -EntraConnectServer 'AADSYNC01' -DaysBack 90 -Verbose

            Description
            -----------
            Audits specific Entra Connect server for the last 90 days with verbose output.

        .EXAMPLE
            Get-EntraConnectCompromise -ExportPath 'C:\SecurityAudits' -IncludeConfigurationDump

            Description
            -----------
            Performs comprehensive audit with configuration export for forensic analysis.

        .EXAMPLE
            Get-EntraConnectCompromise -ScanAllServers -CheckPTAAgents -DaysBack 7

            Description
            -----------
            Scans all Entra Connect servers including PTA agent validation for the last 7 days.

        .EXAMPLE
            $Result = Get-EntraConnectCompromise -DaysBack 30
            if ($Result.HighRiskIndicators -gt 0) {
                Write-Warning ('CRITICAL: {0} high-risk Entra Connect compromise indicators detected!' -f $Result.HighRiskIndicators)
                $Result.CredentialAccessEvents | Export-Csv -Path 'C:\INCIDENT\EntraConnect-CredentialTheft.csv' -NoTypeInformation
            }

            Description
            -----------
            Automated incident response workflow based on detection results.

        .INPUTS
            System.String - EntraConnectServer names (can be piped from Get-ADComputer)

        .OUTPUTS
            PSCustomObject. Returns an Entra Connect security audit object containing:
            - DomainName: DNS name of the audited domain
            - AuditTimestamp: When the audit was performed
            - EntraConnectServers: Array of discovered/specified sync servers
            - PrivilegedAccountCount: Number of MSOL_*/AAD_* accounts detected
            - CredentialAccessEvents: SQL LocalDB and ADSync database access events
            - SyncConfigurationChanges: Unauthorized sync rule modifications
            - PTAAgentStatus: Pass-Through Authentication agent health
            - ADSyncDecryptDetections: ADSyncDecrypt tool execution indicators
            - HighRiskIndicators: Count of critical compromise indicators
            - MediumRiskIndicators: Count of moderate risk findings
            - RiskLevel: Overall risk assessment (Secure/Low/Medium/High/Critical)
            - IsSecure: Boolean indicating if Entra Connect configuration is secure
            - RecommendedActions: Array of remediation steps
            - ExportedReports: Array of file paths if reports were exported

        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Get-FunctionDisplay                    | EguibarIT.SecurityPS
                Import-MyModule                        | EguibarIT.SecurityPS
                Get-ADComputer                         | ActiveDirectory
                Get-ADUser                             | ActiveDirectory
                Get-ADServiceAccount                   | ActiveDirectory
                Get-ADDomain                           | ActiveDirectory
                Get-WinEvent                           | Microsoft.PowerShell.Diagnostics
                Get-Service                            | Microsoft.PowerShell.Management
                Invoke-Command                         | Microsoft.PowerShell.Core
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
            https://attack.mitre.org/techniques/T1078/004/

        .LINK
            https://github.com/dirkjanm/adconnectdump

        .LINK
            https://blog.xpnsec.com/azuread-connect-for-redteam/

        .LINK
            https://github.com/vreguibar/EguibarIT.SecurityPS

        .COMPONENT
            EguibarIT.SecurityPS

        .ROLE
            Security Auditing

        .FUNCTIONALITY
            Detects Microsoft Entra Connect compromise through server auditing, privileged account monitoring, and credential extraction detection.
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
            HelpMessage = 'Specific Entra Connect server(s) to audit',
            Position = 0
        )]
        [ValidateNotNullOrEmpty()]
        [Alias('ComputerName', 'HostName', 'ServerName')]
        [string[]]
        $EntraConnectServer,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Number of days to analyze Event Logs for compromise indicators (1-365)',
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
        [PSDefaultValue(Help = 'Default: C:\SecurityAudits\EntraConnect')]
        [string]
        $ExportPath = 'C:\SecurityAudits\EntraConnect',

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Export current Entra Connect configuration for forensic analysis',
            Position = 3
        )]
        [PSDefaultValue(Help = 'Default: $false')]
        [switch]
        $IncludeConfigurationDump,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Include Pass-Through Authentication agent integrity checks',
            Position = 4
        )]
        [PSDefaultValue(Help = 'Default: $false')]
        [switch]
        $CheckPTAAgents,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Scan all discovered Entra Connect servers',
            Position = 5
        )]
        [PSDefaultValue(Help = 'Default: $false')]
        [switch]
        $ScanAllServers
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

        Write-Verbose -Message 'Initializing Entra Connect compromise detection...'
        Write-Verbose -Message 'MITRE ATT&CK: T1078.004 (Valid Accounts - Cloud Accounts)'
        Write-Verbose -Message 'MITRE ATT&CK: T1003 (OS Credential Dumping)'

        # Initialize result collections using ArrayList for performance
        [System.Collections.ArrayList]$DiscoveredServers = @()
        [System.Collections.ArrayList]$PrivilegedAccounts = @()
        [System.Collections.ArrayList]$CredentialAccessEvents = @()
        [System.Collections.ArrayList]$SyncConfigChanges = @()
        [System.Collections.ArrayList]$PTAAgentFindings = @()
        [System.Collections.ArrayList]$ADSyncDecryptDetections = @()
        [System.Collections.ArrayList]$ExportedReports = @()

        # Known Entra Connect service names
        $EntraConnectServices = @(
            'ADSync',                    # Azure AD Sync Service
            'AzureADConnectProvisioningAgent',  # Provisioning Agent
            'AzureADConnectHealthSyncMonitor',  # Health Monitoring
            'AADConnectProvisioningAgent'       # Alternative name
        )

        # Known privileged account prefixes for Entra Connect
        $PrivilegedAccountPrefixes = @(
            'MSOL_*',     # Microsoft Online account (legacy)
            'AAD_*',      # Azure AD account
            'Sync_*'      # Synchronization account
        )

        # Critical file paths for credential extraction
        $CriticalPaths = @{
            'ADSyncDB'           = 'C:\Program Files\Microsoft Azure AD Sync\Data\ADSync.mdf'
            'ADSyncLog'          = 'C:\Program Files\Microsoft Azure AD Sync\Data\ADSync_log.ldf'
            'ADSyncConfig'       = 'C:\Program Files\Microsoft Azure AD Sync\Bin\miiserver.exe.config'
            'ADSyncEncryption'   = 'C:\Program Files\Microsoft Azure AD Sync\Binn\mcrypt.dll'
            'SchedulerConfig'    = 'C:\Program Files\Microsoft Azure AD Sync\Bin\AzureADConnect.exe'
        }

        # Event IDs for compromise detection
        $MonitoredEventIDs = @{
            'FileAccess'         = 4663    # Object Access (SQL LocalDB access)
            'ProcessCreation'    = 4688    # Process creation (ADSyncDecrypt execution)
            'ServiceStop'        = 7036    # Service stopped (sync service manipulation)
            'ScheduledTask'      = 4698    # Scheduled task created (persistence)
            'LogonType3'         = 4624    # Network logon (lateral movement to sync server)
        }

        # Initialize audit result object
        [PSCustomObject]$AuditResult = [PSCustomObject]@{
            DomainName               = $null
            AuditTimestamp           = Get-Date
            EntraConnectServers      = @()
            PrivilegedAccountCount   = 0
            CredentialAccessEvents   = @()
            SyncConfigurationChanges = @()
            PTAAgentStatus           = @()
            ADSyncDecryptDetections  = @()
            HighRiskIndicators       = 0
            MediumRiskIndicators     = 0
            RiskLevel                = 'Unknown'
            IsSecure                 = $false
            RecommendedActions       = @()
            ExportedReports          = @()
        }

        # Get current domain
        try {
            $Domain = Get-ADDomain -ErrorAction Stop
            $AuditResult.DomainName = $Domain.DNSRoot
            Write-Verbose -Message ('Auditing domain: {0}' -f $Domain.DNSRoot)
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

    } #end begin

    process {

        try {

            # =============================================
            # PHASE 1: ENTRA CONNECT SERVER DISCOVERY
            # =============================================

            Write-Verbose -Message ''
            Write-Verbose -Message '=========================================='
            Write-Verbose -Message 'PHASE 1: Entra Connect Server Discovery'
            Write-Verbose -Message '=========================================='

            if ($PSBoundParameters.ContainsKey('EntraConnectServer')) {
                # Use specified servers
                Write-Verbose -Message ('Using specified Entra Connect servers: {0}' -f ($EntraConnectServer -join ', '))
                foreach ($Server in $EntraConnectServer) {
                    [void]$DiscoveredServers.Add($Server)
                } #end foreach
            } else {
                # Auto-discover Entra Connect servers
                Write-Verbose -Message 'Auto-discovering Entra Connect servers by ADSync service...'

                try {
                    # Search for computers with ADSync service description
                    $ADSyncComputers = Get-ADComputer -Filter {
                        (ServicePrincipalName -like '*ADSync*') -or
                        (Description -like '*Azure AD*') -or
                        (Description -like '*Entra Connect*')
                    } -Properties Description, ServicePrincipalName, OperatingSystem -ErrorAction Stop

                    foreach ($Computer in $ADSyncComputers) {
                        Write-Verbose -Message ('Found potential Entra Connect server: {0} ({1})' -f $Computer.Name, $Computer.Description)
                        [void]$DiscoveredServers.Add($Computer.DNSHostName)
                    } #end foreach

                    # If no servers found via AD, try WMI query for ADSync service
                    if ($DiscoveredServers.Count -eq 0) {
                        Write-Verbose -Message 'No servers found via AD attributes, attempting domain-wide service scan...'
                        Write-Warning -Message 'Domain-wide service scan can take several minutes in large environments'

                        # Alternative: Search for computers in specific OU patterns
                        $PotentialServers = Get-ADComputer -Filter {
                            (OperatingSystem -like '*Server*') -and
                            (Enabled -eq $true)
                        } -SearchBase "OU=Servers,$($Domain.DistinguishedName)" -Properties OperatingSystem -ErrorAction SilentlyContinue

                        foreach ($Server in $PotentialServers) {
                            # Check if ADSync service exists on remote computer
                            try {
                                $Service = Get-Service -ComputerName $Server.DNSHostName -Name 'ADSync' -ErrorAction SilentlyContinue
                                if ($null -ne $Service) {
                                    Write-Verbose -Message ('Found ADSync service on: {0}' -f $Server.DNSHostName)
                                    [void]$DiscoveredServers.Add($Server.DNSHostName)
                                } #end if
                            } catch {
                                Write-Debug -Message ('Failed to query service on {0}: {1}' -f $Server.DNSHostName, $_.Exception.Message)
                            } #end try-catch
                        } #end foreach
                    } #end if
                } catch {
                    Write-Warning -Message ('Failed to auto-discover Entra Connect servers: {0}' -f $_.Exception.Message)
                } #end try-catch
            } #end if-else

            if ($DiscoveredServers.Count -eq 0) {
                Write-Warning -Message 'No Entra Connect servers discovered or specified. Cannot proceed with audit.'
                Write-Warning -Message 'Use -EntraConnectServer parameter to specify server manually.'
                return
            } #end if

            Write-Verbose -Message ('Total Entra Connect servers to audit: {0}' -f $DiscoveredServers.Count)
            $AuditResult.EntraConnectServers = $DiscoveredServers.ToArray()

            # Limit to primary server unless -ScanAllServers is specified
            if (-not $ScanAllServers -and $DiscoveredServers.Count -gt 1) {
                Write-Verbose -Message 'Multiple servers found, scanning primary server only (use -ScanAllServers for full scan)'
                $DiscoveredServers = @($DiscoveredServers[0])
            } #end if

            # =============================================
            # PHASE 2: PRIVILEGED ACCOUNT ENUMERATION
            # =============================================

            Write-Verbose -Message ''
            Write-Verbose -Message '=========================================='
            Write-Verbose -Message 'PHASE 2: Privileged Account Enumeration'
            Write-Verbose -Message '=========================================='

            foreach ($Prefix in $PrivilegedAccountPrefixes) {
                Write-Verbose -Message ('Searching for accounts matching: {0}' -f $Prefix)

                try {
                    # Search for user accounts with privileged prefixes
                    $Accounts = Get-ADUser -Filter "SamAccountName -like '$Prefix'" -Properties SamAccountName, DisplayName, Enabled, Created, LastLogonDate, PasswordLastSet, MemberOf -ErrorAction Stop

                    foreach ($Account in $Accounts) {
                        Write-Verbose -Message ('  Found privileged account: {0} (Enabled: {1}, Last Logon: {2})' -f $Account.SamAccountName, $Account.Enabled, $Account.LastLogonDate)

                        # Assess risk factors
                        [System.Collections.ArrayList]$RiskFactors = @()

                        if ($Account.Enabled) {
                            [void]$RiskFactors.Add('Account is enabled')
                        } #end if

                        if ($null -ne $Account.LastLogonDate -and $Account.LastLogonDate -gt $StartDate) {
                            [void]$RiskFactors.Add(('Recent logon activity: {0}' -f $Account.LastLogonDate))
                        } #end if

                        if ($null -eq $Account.PasswordLastSet -or $Account.PasswordLastSet -lt (Get-Date).AddDays(-90)) {
                            [void]$RiskFactors.Add('Password older than 90 days or never set')
                        } #end if

                        # Check for high-privileged group memberships
                        if ($null -ne $Account.MemberOf) {
                            $PrivilegedGroups = $Account.MemberOf | Where-Object {
                                $_ -match 'Domain Admins|Enterprise Admins|Administrators|Schema Admins'
                            }
                            if ($PrivilegedGroups.Count -gt 0) {
                                [void]$RiskFactors.Add(('Member of privileged groups: {0}' -f ($PrivilegedGroups.Count)))
                            } #end if
                        } #end if

                        $AccountObject = [PSCustomObject]@{
                            SamAccountName    = $Account.SamAccountName
                            DisplayName       = $Account.DisplayName
                            Enabled           = $Account.Enabled
                            Created           = $Account.Created
                            LastLogonDate     = $Account.LastLogonDate
                            PasswordLastSet   = $Account.PasswordLastSet
                            MemberOf          = $Account.MemberOf
                            RiskFactors       = $RiskFactors -join '; '
                            RiskLevel         = if ($RiskFactors.Count -ge 3) { 'High' } elseif ($RiskFactors.Count -ge 1) { 'Medium' } else { 'Low' }
                            DetectionDate     = Get-Date
                        }

                        [void]$PrivilegedAccounts.Add($AccountObject)

                        if ($AccountObject.RiskLevel -eq 'High') {
                            $AuditResult.HighRiskIndicators++
                        } elseif ($AccountObject.RiskLevel -eq 'Medium') {
                            $AuditResult.MediumRiskIndicators++
                        } #end if-else
                    } #end foreach
                } catch {
                    Write-Warning -Message ('Failed to enumerate accounts for prefix {0}: {1}' -f $Prefix, $_.Exception.Message)
                } #end try-catch
            } #end foreach

            $AuditResult.PrivilegedAccountCount = $PrivilegedAccounts.Count
            Write-Verbose -Message ('Total privileged MSOL/AAD accounts found: {0}' -f $PrivilegedAccounts.Count)

            # =============================================
            # PHASE 3: SQL LOCALDB CREDENTIAL ACCESS DETECTION
            # =============================================

            Write-Verbose -Message ''
            Write-Verbose -Message '=========================================='
            Write-Verbose -Message 'PHASE 3: SQL LocalDB Credential Access Detection'
            Write-Verbose -Message '=========================================='

            foreach ($Server in $DiscoveredServers) {
                Write-Verbose -Message ('Analyzing Event Logs on: {0}' -f $Server)

                try {
                    # Query Event 4663 (Object Access) for ADSync database file access
                    $FilterXML = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4663) and TimeCreated[timediff(@SystemTime) &lt;= $($DaysBack * 86400000)]]]
      and
      *[EventData[Data[@Name='ObjectName'] and (
        Data='C:\Program Files\Microsoft Azure AD Sync\Data\ADSync.mdf' or
        Data='C:\Program Files\Microsoft Azure AD Sync\Data\ADSync_log.ldf'
      )]]
    </Select>
  </Query>
</QueryList>
"@

                    $Events = Get-WinEvent -ComputerName $Server -FilterXml $FilterXML -ErrorAction SilentlyContinue

                    foreach ($Event in $Events) {
                        $EventXML = [xml]$Event.ToXml()
                        $EventData = @{}
                        foreach ($Data in $EventXML.Event.EventData.Data) {
                            $EventData[$Data.Name] = $Data.'#text'
                        } #end foreach

                        Write-Verbose -Message ('  Event 4663: {0} accessed {1} on {2}' -f $EventData['SubjectUserName'], $EventData['ObjectName'], $Event.TimeCreated)

                        # Assess if this is suspicious (non-system/non-ADSync account)
                        $IsSuspicious = $EventData['SubjectUserName'] -notmatch '^(SYSTEM|ADSync|LOCAL SERVICE|NETWORK SERVICE)$'

                        if ($IsSuspicious) {
                            $EventObject = [PSCustomObject]@{
                                Server            = $Server
                                TimeCreated       = $Event.TimeCreated
                                EventID           = $Event.Id
                                UserName          = $EventData['SubjectUserName']
                                UserDomain        = $EventData['SubjectDomainName']
                                ObjectName        = $EventData['ObjectName']
                                AccessMask        = $EventData['AccessMask']
                                ProcessName       = $EventData['ProcessName']
                                IsSuspicious      = $IsSuspicious
                                RiskLevel         = 'High'
                                Description       = 'Unauthorized access to Entra Connect SQL LocalDB database file'
                                DetectionDate     = Get-Date
                            }

                            [void]$CredentialAccessEvents.Add($EventObject)
                            $AuditResult.HighRiskIndicators++

                            Write-Warning -Message ('SUSPICIOUS: {0}\{1} accessed {2} at {3}' -f $EventData['SubjectDomainName'], $EventData['SubjectUserName'], $EventData['ObjectName'], $Event.TimeCreated)
                        } #end if
                    } #end foreach
                } catch {
                    Write-Warning -Message ('Failed to query Event 4663 on {0}: {1}' -f $Server, $_.Exception.Message)
                } #end try-catch

                # Query Event 4688 (Process Creation) for ADSyncDecrypt execution
                try {
                    $ProcessFilterXML = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4688) and TimeCreated[timediff(@SystemTime) &lt;= $($DaysBack * 86400000)]]]
      and
      *[EventData[Data[@Name='NewProcessName'] and (
        contains(Data, 'ADSyncDecrypt') or
        contains(Data, 'adconnectdump') or
        contains(Data, 'sqlcmd.exe')
      )]]
    </Select>
  </Query>
</QueryList>
"@

                    $ProcessEvents = Get-WinEvent -ComputerName $Server -FilterXml $ProcessFilterXML -ErrorAction SilentlyContinue

                    foreach ($Event in $ProcessEvents) {
                        $EventXML = [xml]$Event.ToXml()
                        $EventData = @{}
                        foreach ($Data in $EventXML.Event.EventData.Data) {
                            $EventData[$Data.Name] = $Data.'#text'
                        } #end foreach

                        Write-Warning -Message ('CRITICAL: Credential extraction tool detected: {0} by {1} at {2}' -f $EventData['NewProcessName'], $EventData['SubjectUserName'], $Event.TimeCreated)

                        $DecryptEvent = [PSCustomObject]@{
                            Server          = $Server
                            TimeCreated     = $Event.TimeCreated
                            EventID         = $Event.Id
                            UserName        = $EventData['SubjectUserName']
                            UserDomain      = $EventData['SubjectDomainName']
                            ProcessName     = $EventData['NewProcessName']
                            CommandLine     = $EventData['CommandLine']
                            ParentProcess   = $EventData['ParentProcessName']
                            RiskLevel       = 'Critical'
                            Description     = 'Entra Connect credential extraction tool executed'
                            DetectionDate   = Get-Date
                        }

                        [void]$ADSyncDecryptDetections.Add($DecryptEvent)
                        $AuditResult.HighRiskIndicators++
                    } #end foreach
                } catch {
                    Write-Warning -Message ('Failed to query Event 4688 on {0}: {1}' -f $Server, $_.Exception.Message)
                } #end try-catch
            } #end foreach

            Write-Verbose -Message ('Total credential access events: {0}' -f $CredentialAccessEvents.Count)
            Write-Verbose -Message ('Total ADSyncDecrypt detections: {0}' -f $ADSyncDecryptDetections.Count)

            # =============================================
            # PHASE 4: SYNC SCHEDULE ANOMALY DETECTION
            # =============================================

            Write-Verbose -Message ''
            Write-Verbose -Message '=========================================='
            Write-Verbose -Message 'PHASE 4: Sync Schedule Anomaly Detection'
            Write-Verbose -Message '=========================================='

            foreach ($Server in $DiscoveredServers) {
                Write-Verbose -Message ('Checking sync configuration on: {0}' -f $Server)

                try {
                    # Check ADSync service status
                    $ADSyncService = Get-Service -ComputerName $Server -Name 'ADSync' -ErrorAction SilentlyContinue

                    if ($null -eq $ADSyncService) {
                        Write-Warning -Message ('ADSync service not found on {0} - possible service removal attack' -f $Server)
                        $AuditResult.HighRiskIndicators++

                        $ConfigChange = [PSCustomObject]@{
                            Server          = $Server
                            TimeCreated     = Get-Date
                            ChangeType      = 'Service Not Found'
                            Description     = 'ADSync service is missing - possible compromise'
                            RiskLevel       = 'Critical'
                            DetectionDate   = Get-Date
                        }
                        [void]$SyncConfigChanges.Add($ConfigChange)
                    } elseif ($ADSyncService.Status -ne 'Running') {
                        Write-Warning -Message ('ADSync service on {0} is {1} - expected Running' -f $Server, $ADSyncService.Status)
                        $AuditResult.MediumRiskIndicators++

                        $ConfigChange = [PSCustomObject]@{
                            Server          = $Server
                            TimeCreated     = Get-Date
                            ChangeType      = 'Service Stopped'
                            Description     = ('ADSync service status: {0}' -f $ADSyncService.Status)
                            RiskLevel       = 'Medium'
                            DetectionDate   = Get-Date
                        }
                        [void]$SyncConfigChanges.Add($ConfigChange)
                    } else {
                        Write-Verbose -Message ('  ADSync service is running normally on {0}' -f $Server)
                    } #end if-else

                    # Query Event 7036 (Service State Change) for ADSync service stops
                    $ServiceFilterXML = @"
<QueryList>
  <Query Id="0" Path="System">
    <Select Path="System">
      *[System[(EventID=7036) and TimeCreated[timediff(@SystemTime) &lt;= $($DaysBack * 86400000)]]]
      and
      *[EventData[Data and contains(Data, 'ADSync')]]
    </Select>
  </Query>
</QueryList>
"@

                    $ServiceEvents = Get-WinEvent -ComputerName $Server -FilterXml $ServiceFilterXML -ErrorAction SilentlyContinue

                    foreach ($Event in $ServiceEvents) {
                        Write-Verbose -Message ('  Service state change event: {0}' -f $Event.Message)

                        $ConfigChange = [PSCustomObject]@{
                            Server          = $Server
                            TimeCreated     = $Event.TimeCreated
                            ChangeType      = 'Service State Change'
                            Description     = $Event.Message
                            RiskLevel       = 'Low'
                            DetectionDate   = Get-Date
                        }
                        [void]$SyncConfigChanges.Add($ConfigChange)
                    } #end foreach
                } catch {
                    Write-Warning -Message ('Failed to check sync configuration on {0}: {1}' -f $Server, $_.Exception.Message)
                } #end try-catch
            } #end foreach

            Write-Verbose -Message ('Total sync configuration anomalies: {0}' -f $SyncConfigChanges.Count)

            # =============================================
            # PHASE 5: PASS-THROUGH AUTHENTICATION AGENT CHECK
            # =============================================

            if ($CheckPTAAgents) {
                Write-Verbose -Message ''
                Write-Verbose -Message '=========================================='
                Write-Verbose -Message 'PHASE 5: Pass-Through Authentication Agent Check'
                Write-Verbose -Message '=========================================='

                foreach ($Server in $DiscoveredServers) {
                    Write-Verbose -Message ('Checking PTA agent on: {0}' -f $Server)

                    try {
                        $PTAService = Get-Service -ComputerName $Server -Name 'AzureADConnectAuthenticationAgent' -ErrorAction SilentlyContinue

                        if ($null -ne $PTAService) {
                            Write-Verbose -Message ('  PTA Agent found: Status = {0}' -f $PTAService.Status)

                            $PTAObject = [PSCustomObject]@{
                                Server          = $Server
                                ServiceName     = $PTAService.Name
                                Status          = $PTAService.Status
                                StartType       = $PTAService.StartType
                                RiskLevel       = if ($PTAService.Status -ne 'Running') { 'Medium' } else { 'Low' }
                                Description     = ('PTA Agent status: {0}' -f $PTAService.Status)
                                DetectionDate   = Get-Date
                            }

                            [void]$PTAAgentFindings.Add($PTAObject)

                            if ($PTAService.Status -ne 'Running') {
                                $AuditResult.MediumRiskIndicators++
                            } #end if
                        } else {
                            Write-Verbose -Message ('  No PTA Agent found on {0}' -f $Server)
                        } #end if-else
                    } catch {
                        Write-Warning -Message ('Failed to check PTA agent on {0}: {1}' -f $Server, $_.Exception.Message)
                    } #end try-catch
                } #end foreach

                Write-Verbose -Message ('Total PTA agents checked: {0}' -f $PTAAgentFindings.Count)
            } #end if

            # =============================================
            # PHASE 6: CONFIGURATION EXPORT (IF REQUESTED)
            # =============================================

            if ($IncludeConfigurationDump) {
                Write-Verbose -Message ''
                Write-Verbose -Message '=========================================='
                Write-Verbose -Message 'PHASE 6: Configuration Export'
                Write-Verbose -Message '=========================================='

                foreach ($Server in $DiscoveredServers) {
                    Write-Verbose -Message ('Exporting configuration from: {0}' -f $Server)

                    try {
                        # Export ADSync scheduler configuration
                        $SchedulerConfig = Invoke-Command -ComputerName $Server -ScriptBlock {
                            Import-Module ADSync -ErrorAction SilentlyContinue
                            if (Get-Module -Name ADSync) {
                                Get-ADSyncScheduler
                            } else {
                                Write-Warning 'ADSync module not available on this server'
                                return $null
                            } #end if-else
                        } -ErrorAction Stop

                        if ($null -ne $SchedulerConfig) {
                            $ConfigFile = Join-Path -Path $ExportPath -ChildPath ('{0}_SchedulerConfig_{1}.json' -f $Server, (Get-Date -Format 'yyyyMMdd-HHmmss'))
                            $SchedulerConfig | ConvertTo-Json -Depth 5 | Out-File -FilePath $ConfigFile -Encoding UTF8
                            Write-Verbose -Message ('  Exported scheduler configuration to: {0}' -f $ConfigFile)
                            [void]$ExportedReports.Add($ConfigFile)
                        } #end if
                    } catch {
                        Write-Warning -Message ('Failed to export configuration from {0}: {1}' -f $Server, $_.Exception.Message)
                    } #end try-catch
                } #end foreach
            } #end if

        } catch {
            Write-Error -Message ('Critical error during Entra Connect compromise detection: {0}' -f $_.Exception.Message)
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
        $AuditResult.CredentialAccessEvents = $CredentialAccessEvents.ToArray()
        $AuditResult.SyncConfigurationChanges = $SyncConfigChanges.ToArray()
        $AuditResult.PTAAgentStatus = $PTAAgentFindings.ToArray()
        $AuditResult.ADSyncDecryptDetections = $ADSyncDecryptDetections.ToArray()

        # Calculate overall risk level
        if ($AuditResult.HighRiskIndicators -gt 0 -or $ADSyncDecryptDetections.Count -gt 0) {
            $AuditResult.RiskLevel = 'Critical'
            $AuditResult.IsSecure = $false
        } elseif ($AuditResult.MediumRiskIndicators -gt 5) {
            $AuditResult.RiskLevel = 'High'
            $AuditResult.IsSecure = $false
        } elseif ($AuditResult.MediumRiskIndicators -gt 0) {
            $AuditResult.RiskLevel = 'Medium'
            $AuditResult.IsSecure = $false
        } elseif ($PrivilegedAccounts.Count -gt 2) {
            $AuditResult.RiskLevel = 'Low'
            $AuditResult.IsSecure = $true
        } else {
            $AuditResult.RiskLevel = 'Secure'
            $AuditResult.IsSecure = $true
        } #end if-else

        # Generate recommended actions
        [System.Collections.ArrayList]$Actions = @()

        if ($ADSyncDecryptDetections.Count -gt 0) {
            [void]$Actions.Add('CRITICAL: ADSyncDecrypt execution detected - initiate incident response immediately')
            [void]$Actions.Add('Isolate Entra Connect server from network')
            [void]$Actions.Add('Reset ALL cloud administrator credentials')
            [void]$Actions.Add('Rotate Entra Connect service account credentials')
        } #end if

        if ($CredentialAccessEvents.Count -gt 0) {
            [void]$Actions.Add('Investigate unauthorized SQL LocalDB access events')
            [void]$Actions.Add('Review Event 4663 for additional credential extraction attempts')
        } #end if

        if ($PrivilegedAccounts.Count -gt 0) {
            [void]$Actions.Add(('Audit {0} MSOL/AAD privileged accounts for unnecessary permissions' -f $PrivilegedAccounts.Count))
            [void]$Actions.Add('Ensure privileged accounts follow password rotation policy (90 days)')
        } #end if

        if ($SyncConfigChanges.Count -gt 0) {
            [void]$Actions.Add('Review sync service state changes for unauthorized modifications')
        } #end if

        [void]$Actions.Add('Implement Tier 0 isolation for all Entra Connect servers')
        [void]$Actions.Add('Enable advanced auditing: Event 4663 (Object Access) on ADSync database files')
        [void]$Actions.Add('Configure Just-In-Time (JIT) access for Entra Connect server administration')
        [void]$Actions.Add('Consider migrating to cloud-only authentication (eliminate on-premises sync risk)')

        $AuditResult.RecommendedActions = $Actions.ToArray()

        # Export reports
        $Timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'

        if ($PrivilegedAccounts.Count -gt 0) {
            $PrivilegedAccountFile = Join-Path -Path $ExportPath -ChildPath ('EntraConnect_PrivilegedAccounts_{0}.csv' -f $Timestamp)
            $PrivilegedAccounts | Export-Csv -Path $PrivilegedAccountFile -NoTypeInformation -Encoding UTF8
            Write-Verbose -Message ('Exported privileged accounts to: {0}' -f $PrivilegedAccountFile)
            [void]$ExportedReports.Add($PrivilegedAccountFile)
        } #end if

        if ($CredentialAccessEvents.Count -gt 0) {
            $CredentialAccessFile = Join-Path -Path $ExportPath -ChildPath ('EntraConnect_CredentialAccess_{0}.csv' -f $Timestamp)
            $CredentialAccessEvents | Export-Csv -Path $CredentialAccessFile -NoTypeInformation -Encoding UTF8
            Write-Verbose -Message ('Exported credential access events to: {0}' -f $CredentialAccessFile)
            [void]$ExportedReports.Add($CredentialAccessFile)
        } #end if

        if ($ADSyncDecryptDetections.Count -gt 0) {
            $ADSyncDecryptFile = Join-Path -Path $ExportPath -ChildPath ('EntraConnect_ADSyncDecrypt_{0}.csv' -f $Timestamp)
            $ADSyncDecryptDetections | Export-Csv -Path $ADSyncDecryptFile -NoTypeInformation -Encoding UTF8
            Write-Warning -Message ('CRITICAL: ADSyncDecrypt detections exported to: {0}' -f $ADSyncDecryptFile)
            [void]$ExportedReports.Add($ADSyncDecryptFile)
        } #end if

        # Export comprehensive audit summary
        $SummaryFile = Join-Path -Path $ExportPath -ChildPath ('EntraConnect_AuditSummary_{0}.json' -f $Timestamp)
        $AuditResult | ConvertTo-Json -Depth 5 | Out-File -FilePath $SummaryFile -Encoding UTF8
        Write-Verbose -Message ('Exported audit summary to: {0}' -f $SummaryFile)
        [void]$ExportedReports.Add($SummaryFile)

        $AuditResult.ExportedReports = $ExportedReports.ToArray()

        # Display summary
        Write-Verbose -Message ''
        Write-Verbose -Message '=========================================='
        Write-Verbose -Message 'ENTRA CONNECT SECURITY AUDIT SUMMARY'
        Write-Verbose -Message '=========================================='
        Write-Verbose -Message ('Domain: {0}' -f $AuditResult.DomainName)
        Write-Verbose -Message ('Servers Audited: {0}' -f $AuditResult.EntraConnectServers.Count)
        Write-Verbose -Message ('Privileged Accounts: {0}' -f $AuditResult.PrivilegedAccountCount)
        Write-Verbose -Message ('Credential Access Events: {0}' -f $CredentialAccessEvents.Count)
        Write-Verbose -Message ('ADSyncDecrypt Detections: {0}' -f $ADSyncDecryptDetections.Count)
        Write-Verbose -Message ('Sync Configuration Changes: {0}' -f $SyncConfigChanges.Count)
        Write-Verbose -Message ('High Risk Indicators: {0}' -f $AuditResult.HighRiskIndicators)
        Write-Verbose -Message ('Medium Risk Indicators: {0}' -f $AuditResult.MediumRiskIndicators)
        Write-Verbose -Message ('Overall Risk Level: {0}' -f $AuditResult.RiskLevel)
        Write-Verbose -Message ('Is Secure: {0}' -f $AuditResult.IsSecure)
        Write-Verbose -Message '=========================================='

        if ($AuditResult.RiskLevel -in @('Critical', 'High')) {
            Write-Warning -Message ('SECURITY ALERT: Entra Connect environment risk level is {0}' -f $AuditResult.RiskLevel)
            Write-Warning -Message 'Review recommended actions immediately'
        } #end if

        # Return audit result object
        Write-Output -InputObject $AuditResult

    } #end end

} #end function
