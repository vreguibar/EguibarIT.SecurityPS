function Get-MachineAccountQuota {
    <#
    .SYNOPSIS
        Audits Active Directory MachineAccountQuota configuration and detects rogue computer account creation.

    .DESCRIPTION
        This function performs a comprehensive security audit of the MachineAccountQuota setting and identifies
        potential rogue computer account creation in Active Directory. It provides three layers of analysis:

        Phase 1 - CONFIGURATION AUDIT:
        Checks if MachineAccountQuota is set to the recommended secure value (0) and provides remediation guidance.

        Phase 2 - EVENT DETECTION:
        Monitors Event ID 4741 (computer account creation) from domain controllers to identify unauthorized creations.

        Phase 3 - FORENSIC ANALYSIS:
        Identifies suspicious computer accounts based on the following characteristics:
           - Never logged on (potential rogue account)
           - Located in default 'Computers' container (poor security practice)
           - Resource-Based Constrained Delegation (RBCD) configured (critical attack indicator)
           - Suspicious naming patterns (DESKTOP-, LAPTOP-, TEST-, TEMP-, ATTACKER-, ROGUE-)
           - Recently created within audit timespan

        **MITRE ATT&CK Mapping**:
        - **T1136.002**: Create Account: Domain Account
        - **T1069.002**: Permission Groups Discovery: Domain Groups

        **Detection Methodology**:
        By default, ANY authenticated user can add up to 10 computer accounts to a domain (MachineAccountQuota=10).
        Attackers exploit this misconfiguration to create rogue computers for privilege escalation attacks such as:
        - Resource-Based Constrained Delegation (RBCD) abuse
        - Kerberos delegation attacks
        - Lateral movement platforms
        - Persistence mechanisms

        The function analyzes three layers:
        1. MachineAccountQuota attribute value (secure setting = 0)
        2. Event ID 4741 (computer account creation) from all domain controllers
        3. Active Directory computer account characteristics indicative of Compromise

        **Recommended Hardening**:
        Set MachineAccountQuota to 0 to prevent standard users from creating computer accounts:
        ```powershell
        Set-ADDomain -Identity (Get-ADDomain).DistinguishedName -Replace @{'ms-DS-MachineAccountQuota'='0'}
        ```

        Only authorized service accounts (SCCM, MDT, Intune) and IT administrators should create computer accounts.

    .PARAMETER TimeSpanDays
        Number of days to look back for computer account creation events (Event ID 4741).
        Used to analyze recent suspicious computer creation patterns.

    .PARAMETER AuthorizedCreators
        Array of authorized user/group names allowed to create computer accounts.
        Accounts created by principals not matching these names will be flagged as suspicious.
        Common examples: 'Domain Admins', 'IT-Admins', 'SCCM-Service', 'MDT-Service', 'Account Operators'

    .PARAMETER ExportPath
        Path to export detailed CSV reports and configuration summary.
        If specified, the function exports:
        - Suspicious computer creations (CSV) - accounts created by unauthorized users
        - Suspicious computer account characteristics (CSV) - forensic analysis results
        - Configuration audit summary (TXT) - overall findings and recommendations

        The export operation respects the -WhatIf and -Confirm parameters (ShouldProcess).

    .EXAMPLE
        Get-MachineAccountQuota

        Description
        -----------
        Runs the audit with default settings (last 30 days, default authorized groups: Domain Admins, Enterprise Admins, Account Operators).
        Displays results to console without exporting.

    .EXAMPLE
        Get-MachineAccountQuota -TimeSpanDays 90 -Verbose

        Description
        -----------
        Audits the last 90 days with verbose output showing detailed progress through all three audit phases.

    .EXAMPLE
        Get-MachineAccountQuota -AuthorizedCreators @('Domain Admins','IT-Ops','SCCM-Service','MDT-Service') -ExportPath 'C:\SecurityAudits'

        Description
        -----------
        Audits computer account creation and flags accounts created by users not in the specified authorized groups.
        Exports detailed CSV and TXT reports to C:\SecurityAudits directory.

    .EXAMPLE
        Get-MachineAccountQuota -TimeSpanDays 180 -ExportPath 'D:\AuditReports' -WhatIf

        Description
        -----------
        Shows what the function would do (including export operations) without actually exporting files.
        Useful for testing the function before running in production.

    .EXAMPLE
        $Result = Get-MachineAccountQuota -TimeSpanDays 60 -AuthorizedCreators @('Domain Admins') -ExportPath 'C:\Logs'
        if (-not $Result.IsSecure) {
            Write-Warning 'MachineAccountQuota is not secure! Immediate action required.'
        }

        Description
        -----------
        Captures the audit result object and checks if MachineAccountQuota is securely configured.
        Takes automated action based on audit findings.

    .INPUTS
        None. This function does not accept pipeline input.

    .OUTPUTS
        PSCustomObject. Returns an audit summary object containing:
        - MachineAccountQuotaValue: Current MAQ setting
        - IsSecure: Whether MAQ is set to 0 (secure configuration)
        - SuspiciousComputersCount: Number of computer accounts with suspicious characteristics
        - CriticalRBCDCount: Number of computers with RBCD configured (critical severity)
        - HighRiskCount: Number of computers with multiple suspicious indicators
        - ModerateRiskCount: Number of computers with minor suspicious indicators
        - UnauthorizedCreationsCount: Number of computer accounts created by non-authorized users
        - TotalComputerAccounts: Total number of computer accounts in the domain
        - AuditTimeSpan: Date range analyzed for creation events
        - RecommendedAction: Next steps for remediation
        - ExportedReports: Array of file paths if reports were exported

    .NOTES
        Used Functions:
            Name                                   | Module
            --------------------------------------- | --------------------------
            Get-FunctionDisplay                    | EguibarIT.SecurityPS
            Get-ADDomain                           | Microsoft.ActiveDirectory.Management
            Get-ADDomainController                 | Microsoft.ActiveDirectory.Management
            Get-WinEvent                           | Microsoft.PowerShell.Diagnostics
            Get-ADComputer                         | Microsoft.ActiveDirectory.Management
            Export-Csv                             | Microsoft.PowerShell.Utility
            Out-File                               | Microsoft.PowerShell.Utility
            Write-Verbose                          | Microsoft.PowerShell.Utility
            Write-Warning                          | Microsoft.PowerShell.Utility
            Write-Error                            | Microsoft.PowerShell.Utility
            Write-Output                           | Microsoft.PowerShell.Utility
            New-Item                               | Microsoft.PowerShell.Management
            Test-Path                              | Microsoft.PowerShell.Management
            Join-Path                              | Microsoft.PowerShell.Management
            Get-Date                               | Microsoft.PowerShell.Utility

    .NOTES
        Used Functions:
            Name                                   | Module
            --------------------------------------- | --------------------------
            Get-FunctionDisplay                    | EguibarIT.SecurityPS
            Get-ADDomain                           | Microsoft.ActiveDirectory.Management
            Get-ADDomainController                 | Microsoft.ActiveDirectory.Management
            Get-WinEvent                           | Microsoft.PowerShell.Diagnostics
            Get-ADComputer                         | Microsoft.ActiveDirectory.Management
            Export-Csv                             | Microsoft.PowerShell.Utility
            Out-File                               | Microsoft.PowerShell.Utility
            Write-Verbose                          | Microsoft.PowerShell.Utility
            Write-Warning                          | Microsoft.PowerShell.Utility
            Write-Error                            | Microsoft.PowerShell.Utility
            Write-Output                           | Microsoft.PowerShell.Utility
            New-Item                               | Microsoft.PowerShell.Management
            Test-Path                              | Microsoft.PowerShell.Management
            Join-Path                              | Microsoft.PowerShell.Management
            Get-Date                               | Microsoft.PowerShell.Utility

        Version:         1.0.0
        DateModified:    02/Mar/2026
        LastModifiedBy:  Vicente Rodriguez Eguibar
            vicente@eguibar.com
            EguibarIT
            http://www.eguibarit.com

    .LINK
        https://attack.mitre.org/techniques/T1136/002/

    .LINK
        https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4741

    .LINK
        https://adsecurity.org/?p=4056

    .COMPONENT
        EguibarIT.SecurityPS

    .ROLE
        Security Auditing

    .FUNCTIONALITY
        Detects rogue computer account creation and misconfigurations in MachineAccountQuota setting.

    #>

    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([PSCustomObject])]

    param (
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Number of days to look back for computer account creation events.',
            Position = 0)]
        [ValidateRange(1, 36500)]
        [PSDefaultValue(Help = 'Default: 30 days')]
        [int]
        $TimeSpanDays = 30,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'List of authorized users/groups allowed to create computer accounts.',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [PSDefaultValue(Help = 'Default: Domain Admins, Enterprise Admins, Account Operators')]
        [string[]]
        $AuthorizedCreators = @('Domain Admins', 'Enterprise Admins', 'Account Operators'),

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Path to export detailed CSV and TXT reports.',
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        [PSDefaultValue(Help = 'Default: C:\Logs')]
        [string]
        $ExportPath = 'C:\Logs'
    )

    ######################
    # Section BEGIN
    begin {

        Set-StrictMode -Version Latest

        # Module imports
        $txt = ($Variables.HeaderSecurity -f
            (Get-Date).ToShortDateString(),
            $MyInvocation.Mycommand,
            (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
        )
        Write-Verbose -Message $txt

        ##############################
        # Variables Definition

        # Initialize collections for tracking audit findings
        [System.Collections.ArrayList]$AllCreationEvents = @()
        [System.Collections.ArrayList]$SuspiciousComputers = @()
        [System.Collections.ArrayList]$ExportedReports = @()

        # Calculate audit time window
        $StartTime = (Get-Date).AddDays(-$TimeSpanDays)
        $EndTime = Get-Date

        Write-Verbose -Message ('Audit Time Window: {0} to {1}' -f $StartTime.ToString('yyyy-MM-dd HH:mm:ss'), $EndTime.ToString('yyyy-MM-dd HH:mm:ss'))

    } # end Begin

    ######################
    # Section PROCESS
    process {

        try {

            # ========================================
            # PHASE 1: CHECK MACHINEACCOUNTQUOTA CONFIGURATION
            # ========================================
            Write-Verbose -Message '[PHASE 1] Checking MachineAccountQuota Configuration'

            try {
                $Domain = Get-ADDomain -ErrorAction Stop
                $MAQ = $Domain.'ms-DS-MachineAccountQuota'

                Write-Verbose -Message ('Domain: {0}' -f $Domain.DNSRoot)
                Write-Verbose -Message ('MachineAccountQuota Value: {0}' -f $MAQ)

                if ($MAQ -gt 0) {
                    Write-Warning -Message ('╔{0}╗' -f ('═' * 68))
                    Write-Warning -Message ('║  ⚠️  CRITICAL SECURITY MISCONFIGURATION DETECTED ⚠️           ║')
                    Write-Warning -Message ('╚{0}╝' -f ('═' * 68))
                    Write-Warning -Message ('MachineAccountQuota is set to {0} (INSECURE)' -f $MAQ)
                    Write-Warning -Message ('ANY authenticated user can create up to {0} computer accounts!' -f $MAQ)

                    $RiskAnalysis = @"
RISKS:
  • Attackers can create rogue computer accounts for persistence
  • Enables Resource-Based Constrained Delegation (RBCD) attacks
  • Provides privilege escalation path to Domain Admin
  • Bypasses security controls that only monitor user account creation

RECOMMENDED ACTION - Set MachineAccountQuota to 0:
  Set-ADDomain -Identity '$($Domain.DistinguishedName)' -Replace @{'ms-DS-MachineAccountQuota'='0'}

ALTERNATIVE - If you MUST allow computer joins (not recommended):
  1. Keep MAQ at current value for temporary compatibility
  2. Implement STRICT Event ID 4741 monitoring (see Phase 2 below)
  3. Plan migration to SCCM/Intune computer provisioning
  4. Set MAQ=0 after migration complete
"@
                    Write-Verbose -Message $RiskAnalysis
                } else {
                    $SecureConfig = @'
╔───────────────────────────────────────────────────────────────────╗
║  ✓ SECURE CONFIGURATION                                        ║
╚───────────────────────────────────────────────────────────────────╝
[+] MachineAccountQuota is set to 0 (SECURE)
[+] Standard users CANNOT create computer accounts
[+] This attack vector is ELIMINATED
'@
                    Write-Verbose -Message $SecureConfig
                } #end if $MAQ

            } catch {
                Write-Error -Message ('Error checking MachineAccountQuota: {0}' -f $_)
                throw
            } #end try-catch Phase 1

            # ========================================
            # PHASE 2: DETECT UNAUTHORIZED COMPUTER ACCOUNT CREATION
            # ========================================
            Write-Verbose -Message ('[PHASE 2] Analyzing Computer Account Creation Events (Last {0} Days)' -f $TimeSpanDays)

            try {
                $DomainControllers = Get-ADDomainController -Filter * -ErrorAction Stop | Select-Object -ExpandProperty HostName

                Write-Verbose -Message ('Authorized Creators: {0}' -f ($AuthorizedCreators -join ', '))
                Write-Verbose -Message ('Scanning {0} Domain Controllers' -f $DomainControllers.Count)

                Write-Verbose -Message ('Authorized Creators: {0}' -f ($AuthorizedCreators -join ', '))
                Write-Verbose -Message ('Scanning {0} Domain Controllers' -f $DomainControllers.Count)

                # Collect Event ID 4741 from all DCs
                foreach ($DC in $DomainControllers) {
                    Write-Verbose -Message ('  Querying {0}...' -f $DC)

                    try {
                        $Events = Get-WinEvent -ComputerName $DC -FilterHashtable @{
                            LogName   = 'Security'
                            Id        = 4741  # Computer account created
                            StartTime = $StartTime
                        } -ErrorAction SilentlyContinue

                        if ($Events) {
                            foreach ($EventItem in $Events) {
                                $XML = [xml]$EventItem.ToXml()
                                $EventData = @{}

                                $XML.Event.EventData.Data | ForEach-Object {
                                    $EventData[$_.Name] = $_.'#text'
                                } #end foreach

                                [void]$AllCreationEvents.Add([PSCustomObject]@{
                                        TimeCreated      = $EventItem.TimeCreated
                                        DomainController = $DC
                                        ComputerName     = $EventData['SamAccountName']
                                        CreatedBy        = $EventData['SubjectUserName']
                                        CreatedByDomain  = $EventData['SubjectDomainName']
                                        TargetDomain     = $EventData['TargetDomainName']
                                    })
                            } #end foreach event
                        } #end if events

                    } catch {
                        Write-Warning -Message ('Could not query {0}: {1}' -f $DC, $_)
                    } #end try-catch
                } #end foreach DC

                Write-Verbose -Message ('Retrieved {0} computer account creation events' -f $AllCreationEvents.Count)

                # Filter for suspicious creations (created by non-authorized users)
                $SuspiciousCreations = $AllCreationEvents | Where-Object {
                    $Creator = $_.CreatedBy
                    $IsAuthorized = $false

                    # Check if creator is in authorized list
                    foreach ($AuthGroup in $AuthorizedCreators) {
                        if ($Creator -like "*$AuthGroup*") {
                            $IsAuthorized = $true
                            break
                        } #end if
                    } #end foreach

                    -not $IsAuthorized
                } #end where

                if ($SuspiciousCreations.Count -gt 0) {
                    Write-Warning -Message ('{0} computer accounts created by NON-AUTHORIZED users!' -f $SuspiciousCreations.Count)
                    Write-Verbose -Message ($SuspiciousCreations | Format-Table TimeCreated, ComputerName, CreatedBy -AutoSize | Out-String)
                    Write-Verbose -Message 'INVESTIGATION REQUIRED:'
                    Write-Verbose -Message '  1. Verify if these computer accounts are legitimate'
                    Write-Verbose -Message '  2. Check if creators are IT staff not in authorized groups'
                    Write-Verbose -Message '  3. Investigate any accounts created by standard users'
                    Write-Verbose -Message '  4. Look for patterns (multiple accounts by same user, similar names)'
                } else {
                    Write-Verbose -Message 'All computer accounts created by authorized users'
                    Write-Verbose -Message 'No suspicious creation patterns detected'
                } #end if suspicious creations

            } catch {
                Write-Error -Message ('Error during Phase 2 analysis: {0}' -f $_)
            } #end try-catch Phase 2

            # ========================================
            # PHASE 3: FORENSIC ANALYSIS - IDENTIFY ROGUE COMPUTER ACCOUNTS
            # ========================================
            Write-Verbose -Message '[PHASE 3] Forensic Analysis - Detecting Rogue Computer Accounts'
            Write-Verbose -Message 'Scanning for suspicious computer account characteristics...'

            try {
                # Get all computer accounts with detailed properties
                $AllComputers = Get-ADComputer -Filter * -Properties `
                    Created, `
                    LastLogonDate, `
                    PasswordLastSet, `
                    Enabled, `
                    CanonicalName, `
                    Description, `
                    'msDS-AllowedToActOnBehalfOfOtherIdentity' -ErrorAction Stop

                # Analyze for indicators of compromise
                foreach ($Computer in $AllComputers) {
                    $Issues = @()

                    # CHECK 1: Never logged on (potential rogue account)
                    if ($null -eq $Computer.LastLogonDate -and $Computer.Created -lt (Get-Date).AddDays(-7)) {
                        $Issues += "Never used (created $((Get-Date) - $Computer.Created | Select-Object -ExpandProperty Days) days ago)"
                    } #end if

                    # CHECK 2: In default "Computers" container (not standard practice)
                    if ($Computer.CanonicalName -like '*Computers/*' -and $Computer.CanonicalName -notlike '*Domain Controllers*') {
                        $Issues += 'In default Computers container (should be in OU)'
                    } #end if

                    # CHECK 3: Resource-Based Constrained Delegation configured (RBCD attack indicator)
                    if ($Computer.'msDS-AllowedToActOnBehalfOfOtherIdentity') {
                        $Issues += '⚠️ RBCD CONFIGURED - CRITICAL'
                    } #end if

                    # CHECK 4: Created recently (within audit timespan)
                    if ($Computer.Created -gt $StartTime) {
                        $Issues += "Recently created ($($Computer.Created))"
                    } #end if

                    # CHECK 5: Suspicious naming patterns
                    if ($Computer.Name -match '^(DESKTOP|LAPTOP|PC|WORKSTATION|TEST|TEMP|ATTACKER|ROGUE|LAB)-.*') {
                        $Issues += 'Suspicious naming pattern'
                    } #end if

                    if ($Issues.Count -gt 0) {
                        [void]$SuspiciousComputers.Add([PSCustomObject]@{
                                Name       = $Computer.Name
                                Created    = $Computer.Created
                                LastLogon  = $Computer.LastLogonDate
                                Location   = $Computer.CanonicalName
                                Enabled    = $Computer.Enabled
                                Issues     = $Issues -join '; '
                                IssueCount = $Issues.Count
                            })
                    } #end if issues
                } #end foreach computer

                # Display results
                if ($SuspiciousComputers.Count -gt 0) {
                    Write-Warning -Message ('Found {0} computer accounts with suspicious characteristics!' -f $SuspiciousComputers.Count)

                    # Prioritize by severity (RBCD configured = highest priority)
                    $CriticalComputers = $SuspiciousComputers | Where-Object { $_.Issues -like '*RBCD CONFIGURED*' }
                    $HighRiskComputers = $SuspiciousComputers | Where-Object { $_.Issues -notlike '*RBCD CONFIGURED*' -and $_.IssueCount -ge 3 }
                    $ModerateRiskComputers = $SuspiciousComputers | Where-Object { $_.IssueCount -lt 3 -and $_.Issues -notlike '*RBCD CONFIGURED*' }

                    if ($CriticalComputers) {
                        $CriticalBox = @'
╔───────────────────────────────────────────────────────────────────╗
║  🚨 CRITICAL - RBCD ATTACK INDICATORS 🚨                       ║
╚───────────────────────────────────────────────────────────────────╝
'@
                        Write-Warning -Message $CriticalBox
                        Write-Verbose -Message ($CriticalComputers | Format-Table Name, Created, Issues -AutoSize -Wrap | Out-String)
                    } #end if critical

                    if ($HighRiskComputers) {
                        Write-Warning -Message 'HIGH RISK - Multiple Suspicious Indicators:'
                        Write-Verbose -Message ($HighRiskComputers | Format-Table Name, Created, LastLogon, Issues -AutoSize -Wrap | Out-String)
                    } #end if high risk

                    if ($ModerateRiskComputers) {
                        Write-Verbose -Message 'MODERATE RISK - Review Recommended:'
                        Write-Verbose -Message ($ModerateRiskComputers | Select-Object -First 20 | Format-Table Name, Created, Issues -AutoSize -Wrap | Out-String)
                        if ($ModerateRiskComputers.Count -gt 20) {
                            Write-Verbose -Message ('... and {0} more' -f ($ModerateRiskComputers.Count - 20))
                        } #end if
                    } #end if moderate

                    $RemediationSteps = @"
REMEDIATION STEPS:
  1. Investigate CRITICAL computers with RBCD immediately
  2. Verify if HIGH RISK computers are legitimate IT assets
  3. Delete confirmed rogue computer accounts:
     Remove-ADComputer -Identity 'COMPUTERNAME' -Confirm:`$false
  4. Move legitimate computers to proper OUs
  5. Implement Event ID 4741 monitoring to prevent future rogue creations
"@
                    Write-Verbose -Message $RemediationSteps
                } else {
                    Write-Verbose -Message 'No suspicious computer accounts detected'
                    Write-Verbose -Message 'All computers appear to be legitimate IT assets'
                } #end if suspicious computers
            } catch {
                Write-Error -Message ('Error during Phase 3 forensic analysis: {0}' -f $_)
            } #end try-catch Phase 3

        } catch {
            Write-Error -Message ('Error in main audit process: {0}' -f $_)
            throw
        } #end try-catch main

    } # end Process

    ######################
    # Section END
    end {

        try {

            # ========================================
            # EXPORT REPORTS (WITH SHOULDPROCESS)
            # ========================================
            if ($PSBoundParameters.ContainsKey('ExportPath')) {
                Write-Verbose -Message 'Preparing to export detailed reports...'

                if (-not (Test-Path -Path $ExportPath)) {
                    if ($PSCmdlet.ShouldProcess($ExportPath, 'Create directory')) {
                        try {
                            New-Item -ItemType Directory -Path $ExportPath -ErrorAction Stop | Out-Null
                            Write-Verbose -Message ('Created export directory: {0}' -f $ExportPath)
                        } catch {
                            Write-Error -Message ('Failed to create export directory: {0}' -f $_)
                            throw
                        } #end try-catch
                    } #end if ShouldProcess
                } #end if not exists

                $Timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'

                # Export suspicious creations
                if ($SuspiciousCreations -and $SuspiciousCreations.Count -gt 0) {
                    $CreationReport = Join-Path -Path $ExportPath -ChildPath "MAQ-SuspiciousCreations-$Timestamp.csv"
                    if ($PSCmdlet.ShouldProcess($CreationReport, 'Export suspicious creations report')) {
                        try {
                            $SuspiciousCreations | Export-Csv -Path $CreationReport -NoTypeInformation -ErrorAction Stop
                            Write-Verbose -Message ('Suspicious creations report exported: {0}' -f $CreationReport)
                            [void]$ExportedReports.Add($CreationReport)
                        } catch {
                            Write-Error -Message ('Failed to export suspicious creations report: {0}' -f $_)
                        } #end try-catch
                    } #end if ShouldProcess
                } #end if suspicious creations

                # Export suspicious computers
                if ($SuspiciousComputers -and $SuspiciousComputers.Count -gt 0) {
                    $ComputerReport = Join-Path -Path $ExportPath -ChildPath "MAQ-SuspiciousComputers-$Timestamp.csv"
                    if ($PSCmdlet.ShouldProcess($ComputerReport, 'Export suspicious computers report')) {
                        try {
                            $SuspiciousComputers | Export-Csv -Path $ComputerReport -NoTypeInformation -ErrorAction Stop
                            Write-Verbose -Message ('Suspicious computers report exported: {0}' -f $ComputerReport)
                            [void]$ExportedReports.Add($ComputerReport)
                        } catch {
                            Write-Error -Message ('Failed to export suspicious computers report: {0}' -f $_)
                        } #end try-catch
                    } #end if ShouldProcess
                } #end if suspicious computers

                # Export configuration summary
                $ConfigReport = Join-Path -Path $ExportPath -ChildPath "MAQ-Configuration-$Timestamp.txt"
                if ($PSCmdlet.ShouldProcess($ConfigReport, 'Export configuration summary')) {
                    try {
                        $SummaryText = @"
MachineAccountQuota Security Audit Summary
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Domain: $($Domain.DNSRoot)

CONFIGURATION:
- MachineAccountQuota: $MAQ $(if ($MAQ -eq 0) { '(SECURE)' } else { '(INSECURE - SET TO 0!)' })

STATISTICS:
- Total Computer Accounts: $($AllComputers.Count)
- Suspicious Computer Accounts: $($SuspiciousComputers.Count)
- Critical RBCD Indicators: $($CriticalComputers.Count)
- High Risk Indicators: $($HighRiskComputers.Count)
- Moderate Risk Indicators: $($ModerateRiskComputers.Count)
- Unauthorized Creations (Last $TimeSpanDays days): $($SuspiciousCreations.Count)

RECOMMENDATION:
$(if ($MAQ -gt 0) { 'IMMEDIATE ACTION REQUIRED: Set MachineAccountQuota to 0' } else { 'Configuration is secure. Continue monitoring.' })
"@
                        $SummaryText | Out-File -FilePath $ConfigReport -ErrorAction Stop
                        Write-Verbose -Message ('Configuration summary exported: {0}' -f $ConfigReport)
                        [void]$ExportedReports.Add($ConfigReport)
                    } catch {
                        Write-Error -Message ('Failed to export configuration summary: {0}' -f $_)
                    } #end try-catch
                } #end if ShouldProcess
            } #end if ExportPath

            # ========================================
            # BUILD AND RETURN AUDIT SUMMARY OBJECT
            # ========================================
            Write-Verbose -Message 'Building audit summary object...'

            $AuditResult = [PSCustomObject]@{
                PSTypeName                 = 'EguibarIT.MachineAccountQuotaAudit'
                AuditDate                  = Get-Date
                DomainDNS                  = $Domain.DNSRoot
                DomainDN                   = $Domain.DistinguishedName
                MachineAccountQuotaValue   = $MAQ
                IsSecure                   = ($MAQ -eq 0)
                TotalComputerAccounts      = $AllComputers.Count
                SuspiciousComputersCount   = $SuspiciousComputers.Count
                CriticalRBCDCount          = if ($CriticalComputers) {
                    $CriticalComputers.Count 
                } else {
                    0 
                }
                HighRiskCount              = if ($HighRiskComputers) {
                    $HighRiskComputers.Count 
                } else {
                    0 
                }
                ModerateRiskCount          = if ($ModerateRiskComputers) {
                    $ModerateRiskComputers.Count 
                } else {
                    0 
                }
                UnauthorizedCreationsCount = $SuspiciousCreations.Count
                AuditTimeSpanDays          = $TimeSpanDays
                AuditStartTime             = $StartTime
                AuditEndTime               = $EndTime
                RecommendedAction          = if ($MAQ -gt 0) {
                    'IMMEDIATE ACTION REQUIRED: Set MachineAccountQuota to 0'
                } else {
                    'Configuration is secure. Continue monitoring for suspicious computer accounts.'
                }
                ExportedReports            = if ($ExportedReports.Count -gt 0) {
                    $ExportedReports.ToArray() 
                } else {
                    @() 
                }
                AuthorizedCreators         = $AuthorizedCreators
                SuspiciousComputers        = if ($SuspiciousComputers.Count -gt 0) {
                    $SuspiciousComputers 
                } else {
                    @() 
                }
                SuspiciousCreations        = if ($SuspiciousCreations.Count -gt 0) {
                    $SuspiciousCreations 
                } else {
                    @() 
                }
                CriticalComputers          = if ($CriticalComputers) {
                    $CriticalComputers 
                } else {
                    @() 
                }
                HighRiskComputers          = if ($HighRiskComputers) {
                    $HighRiskComputers 
                } else {
                    @() 
                }
                ModerateRiskComputers      = if ($ModerateRiskComputers) {
                    $ModerateRiskComputers 
                } else {
                    @() 
                }
            }

            Write-Output -InputObject $AuditResult

            $AuditSummary = @"
╔───────────────────────────────────────────────────────────────────╗
║  Audit Complete                                                ║
╚───────────────────────────────────────────────────────────────────╝
Audit Summary:
  • MachineAccountQuota: $MAQ $(if ($MAQ -eq 0) { '✓ SECURE' } else { '✗ INSECURE' })
  • Suspicious Computer Accounts: $($SuspiciousComputers.Count)
  • Unauthorized Creations: $($SuspiciousCreations.Count)

Next Steps:
  1. Remediate MachineAccountQuota if MAQ > 0
  2. Investigate and remove rogue computer accounts
  3. Implement Event ID 4741 monitoring in SIEM
  4. Deploy SCCM/Intune for centralized computer provisioning
  5. Schedule monthly re-audits
"@
            Write-Verbose -Message $AuditSummary

        } catch {
            Write-Error -Message ('Error in End block: {0}' -f $_)
            throw
        } #end try-catch

        $Footer = @"
===============================================================================
$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
  Function: $($MyInvocation.InvocationName)
  Completed Audit Execution
===============================================================================
"@
        Write-Verbose -Message $Footer

    } # end END

} #end Function Get-MachineAccountQuota
