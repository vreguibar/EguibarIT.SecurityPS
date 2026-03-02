function Get-UnconstrainedDelegation {
    <#
    .SYNOPSIS
        Identifies and audits all objects with unconstrained delegation enabled in Active Directory.

    .DESCRIPTION
        Performs a comprehensive three-phase security audit to detect unconstrained delegation misconfigurations:

        **Phase 1 - CONFIGURATION AUDIT:**
        Identifies all computers and users with unconstrained delegation (TRUSTED_FOR_DELEGATION flag).
        Separates domain controllers (expected) from non-DC systems (security risk).

        **Phase 2 - RISK ANALYSIS:**
        Categorizes non-DC systems by risk level based on:
        - Activity status (active vs. stale systems)
        - Operating system version (legacy OS = higher risk)
        - Enable status (active systems = immediate threat)
        - Location (production OUs = critical impact)

        **Phase 3 - PRIVILEGED ACCOUNT PROTECTION:**
        Identifies privileged accounts vulnerable to delegation attacks (not in Protected Users group).
        Assesses Domain Admins, Enterprise Admins, Schema Admins, and other high-privilege groups.

        **ATTACK VECTOR:**
        Unconstrained delegation allows a service to impersonate ANY user who authenticates to it.
        Attackers who compromise delegated systems can:
        1. Force Domain Admin authentication (PrinterBug/PetitPotam attacks)
        2. Extract TGT from LSASS memory (Mimikatz)
        3. Achieve full domain compromise

        **MITRE ATT&CK Mapping:**
        - **T1484**: Domain Policy Modification
        - **T1558.003**: Kerberoasting
        - **T1550.003**: Pass the Ticket

        **BEST PRACTICE:**
        Remove unconstrained delegation from ALL systems except domain controllers.
        Migrate to constrained delegation or resource-based constrained delegation (RBCD).

    .PARAMETER IncludeServiceAccounts
        If specified, also audits user accounts (service accounts) with unconstrained delegation.
        Default behavior only checks computer accounts.

    .PARAMETER CheckProtectedUsers
        If specified, analyzes privileged accounts and identifies those NOT in Protected Users group.
        Provides remediation guidance for protecting high-privilege accounts from delegation attacks.

    .PARAMETER ExportPath
        Path to export detailed CSV reports and audit summary.
        Exports will include:
        - Delegated computers (non-DC systems)
        - Delegated service accounts (if IncludeServiceAccounts specified)
        - Vulnerable privileged accounts (if CheckProtectedUsers specified)
        - Audit summary with risk assessment

        The export operation respects the -WhatIf and -Confirm parameters (ShouldProcess).

    .EXAMPLE
        Get-UnconstrainedDelegation

        Description
        -----------
        Runs the audit with default settings, checking computer accounts only.
        Displays results to console without exporting.

    .EXAMPLE
        Get-UnconstrainedDelegation -IncludeServiceAccounts -Verbose

        Description
        -----------
        Audits both computer and user accounts with verbose output showing detailed progress.

    .EXAMPLE
        Get-UnconstrainedDelegation -CheckProtectedUsers -ExportPath 'C:\SecurityAudits'

        Description
        -----------
        Audits computer accounts and checks privileged account protection status.
        Exports detailed reports to C:\SecurityAudits directory.

    .EXAMPLE
        Get-UnconstrainedDelegation -IncludeServiceAccounts -CheckProtectedUsers -ExportPath 'D:\Logs' -WhatIf

        Description
        -----------
        Shows what the function would do (including export operations) without actually exporting files.
        Useful for testing before running in production.

    .EXAMPLE
        $Result = Get-UnconstrainedDelegation -CheckProtectedUsers
        if ($Result.NonDCComputerCount -gt 0) {
            Write-Warning ('Found {0} non-DC systems with unconstrained delegation' -f $Result.NonDCComputerCount)
        }

        Description
        -----------
        Captures the audit result object and takes automated action based on findings.

    .INPUTS
        None. This function does not accept pipeline input.

    .OUTPUTS
        PSCustomObject. Returns an audit summary object containing:
        - DomainName: DNS name of the audited domain
        - DomainControllerCount: Number of DCs with delegation (expected)
        - NonDCComputerCount: Number of non-DC systems with delegation (security risk)
        - HighRiskSystemCount: Number of high-risk systems
        - MediumRiskSystemCount: Number of medium-risk systems
        - LowRiskSystemCount: Number of low-risk systems
        - ServiceAccountCount: Number of delegated service accounts
        - PrivilegedAccountCount: Total privileged accounts analyzed
        - VulnerablePrivilegedAccountCount: Privileged accounts not protected from delegation
        - IsSecure: Boolean indicating if configuration is secure
        - RecommendedAction: Next steps for remediation
        - ExportedReports: Array of file paths if reports were exported

    .NOTES
        Used Functions:
            Name                                   | Module
            --------------------------------------- | --------------------------
            Get-FunctionDisplay                    | EguibarIT.SecurityPS
            Get-ADDomain                           | Microsoft.ActiveDirectory.Management
            Get-ADComputer                         | Microsoft.ActiveDirectory.Management
            Get-ADUser                             | Microsoft.ActiveDirectory.Management
            Get-ADGroup                            | Microsoft.ActiveDirectory.Management
            Get-ADGroupMember                      | Microsoft.ActiveDirectory.Management
            Export-Csv                             | Microsoft.PowerShell.Utility
            Out-File                               | Microsoft.PowerShell.Utility
            Write-Verbose                          | Microsoft.PowerShell.Utility
            Write-Warning                          | Microsoft.PowerShell.Utility
            Write-Error                            | Microsoft.PowerShell.Utility
            Write-Output                           | Microsoft.PowerShell.Utility
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
        https://attack.mitre.org/techniques/T1484/

    .LINK
        https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group

    .LINK
        https://adsecurity.org/?p=1667

    .COMPONENT
        EguibarIT.SecurityPS

    .ROLE
        Security Auditing

    .FUNCTIONALITY
        Detects unconstrained delegation misconfigurations and identifies systems vulnerable to Kerberos delegation attacks.

    #>

    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([PSCustomObject])]

    param(
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Include service accounts in the audit',
            Position = 0)]
        [PSDefaultValue(Help = 'Default: $false')]
        [switch]
        $IncludeServiceAccounts,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Check privileged account protection status',
            Position = 1)]
        [PSDefaultValue(Help = 'Default: $false')]
        [switch]
        $CheckProtectedUsers,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Path to export detailed reports',
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
            $(Get-Date),
            $MyInvocation.Mycommand,
            (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
        )
        Write-Verbose -Message $txt

        ##############################
        # Variables Definition

        # Initialize collections for tracking audit findings
        [System.Collections.ArrayList]$DelegatedComputers = @()
        [System.Collections.ArrayList]$DelegatedUsers = @()
        [System.Collections.ArrayList]$DomainControllers = @()
        [System.Collections.ArrayList]$NonDCComputers = @()
        [System.Collections.ArrayList]$HighRiskSystems = @()
        [System.Collections.ArrayList]$MediumRiskSystems = @()
        [System.Collections.ArrayList]$LowRiskSystems = @()
        [System.Collections.ArrayList]$AllPrivilegedUsers = @()
        [System.Collections.ArrayList]$VulnerableAdmins = @()
        [System.Collections.ArrayList]$ExportedReports = @()

        $HeaderMessage = @'
╔════════════════════════════════════════════════════════════════╗
║  Unconstrained Delegation Security Audit - EguibarIT           ║
║  MITRE ATT&CK T1484                                            ║
╚════════════════════════════════════════════════════════════════╝
'@
        Write-Verbose -Message $HeaderMessage

    } # end Begin

    ######################
    # Section PROCESS
    process {

        try {

            # ========================================
            # PHASE 1: IDENTIFY OBJECTS WITH UNCONSTRAINED DELEGATION
            # ========================================
            Write-Verbose -Message '[PHASE 1] Scanning for Unconstrained Delegation Configurations'

            try {
                # Get domain information
                $Domain = Get-ADDomain -ErrorAction Stop
                $DomainDN = $Domain.DistinguishedName
                $DomainName = $Domain.DNSRoot

                $DomainInfo = @"
Domain Information:
  • Domain: $DomainName
  • Distinguished Name: $DomainDN
  • Scanning for TRUSTED_FOR_DELEGATION flag (userAccountControl = 524288)
"@
                Write-Verbose -Message $DomainInfo

                # COMPUTER ACCOUNTS with unconstrained delegation
                # userAccountControl flag 524288 (0x80000) = TRUSTED_FOR_DELEGATION
                # Note: Domain Controllers have this flag by design (required for AD operations)
                Write-Verbose -Message 'Querying computer accounts with TrustedForDelegation attribute...'

                $DelegatedComputers = Get-ADComputer -Filter { TrustedForDelegation -eq $true } -Properties `
                    TrustedForDelegation, `
                    userAccountControl, `
                    Created, `
                    LastLogonDate, `
                    OperatingSystem, `
                    OperatingSystemVersion, `
                    Enabled, `
                    CanonicalName, `
                    Description, `
                    PrimaryGroupID -ErrorAction Stop

                Write-Verbose -Message ('Found {0} computer accounts with unconstrained delegation' -f $DelegatedComputers.Count)

                # Separate Domain Controllers from regular computers
                $DomainControllers = $DelegatedComputers | Where-Object { $_.PrimaryGroupID -eq 516 }  # Domain Controllers group
                $NonDCComputers = $DelegatedComputers | Where-Object { $_.PrimaryGroupID -ne 516 }

                $SeparationResult = @"
Computer Account Analysis:
  • Domain Controllers: $($DomainControllers.Count) (EXPECTED)
  • Non-DC Computers: $($NonDCComputers.Count) $(if ($NonDCComputers.Count -gt 0) { '⚠️ SECURITY RISK' } else { '✓ SECURE' })
"@
                Write-Verbose -Message $SeparationResult

                if ($NonDCComputers.Count -gt 0) {
                    Write-Warning -Message ('Found {0} non-DC computers with unconstrained delegation (CRITICAL SECURITY RISK)' -f $NonDCComputers.Count)
                }

                # USER/SERVICE ACCOUNTS with unconstrained delegation (optional)
                if ($IncludeServiceAccounts) {
                    Write-Verbose -Message 'Scanning service accounts for unconstrained delegation...'

                    $DelegatedUsers = Get-ADUser -Filter { TrustedForDelegation -eq $true } -Properties `
                        TrustedForDelegation, `
                        userAccountControl, `
                        Created, `
                        LastLogonDate, `
                        Enabled, `
                        CanonicalName, `
                        Description, `
                        ServicePrincipalName -ErrorAction Stop

                    Write-Verbose -Message ('Found {0} service accounts with unconstrained delegation' -f $DelegatedUsers.Count)

                    if ($DelegatedUsers.Count -gt 0) {
                        Write-Warning -Message ('Service accounts with unconstrained delegation: {0} (SECURITY RISK)' -f $DelegatedUsers.Count)
                    }
                } # end if IncludeServiceAccounts

            } catch {
                Write-Error -Message ('Error during Phase 1 configuration audit: {0}' -f $_)
                throw
            } # end try-catch Phase 1

            # ========================================
            # RISK ANALYSIS: CATEGORIZE NON-DC COMPUTERS BY THREAT LEVEL
            # ========================================
            if ($NonDCComputers.Count -gt 0) {
                Write-Verbose -Message 'Performing risk analysis on non-DC systems with unconstrained delegation...'

                $CriticalWarning = @'
╔════════════════════════════════════════════════════════════════╗
║  🚨 CRITICAL SECURITY MISCONFIGURATION DETECTED 🚨             ║
╚════════════════════════════════════════════════════════════════╝

NON-DOMAIN CONTROLLER SYSTEMS WITH UNCONSTRAINED DELEGATION DETECTED
'@
                Write-Warning -Message $CriticalWarning

                foreach ($Computer in $NonDCComputers) {
                    [System.Collections.ArrayList]$RiskFactors = @()
                    $RiskScore = 0

                    # RISK FACTOR 1: Recently used (attackers may have active access)
                    if ($Computer.LastLogonDate -and $Computer.LastLogonDate -gt (Get-Date).AddDays(-30)) {
                        [void]$RiskFactors.Add("Active (last logon: $($Computer.LastLogonDate.ToString('yyyy-MM-dd')))")
                        $RiskScore += 3
                    } elseif ($null -eq $Computer.LastLogonDate -or $Computer.LastLogonDate -lt (Get-Date).AddDays(-365)) {
                        [void]$RiskFactors.Add("Stale/Unused (last logon: $(if ($Computer.LastLogonDate) { $Computer.LastLogonDate.ToString('yyyy-MM-dd') } else { 'Never' }))")
                        $RiskScore += 1
                    }

                    # RISK FACTOR 2: Operating system (older OS = more vulnerabilities)
                    if ($Computer.OperatingSystem -match '2003|2008|2012') {
                        [void]$RiskFactors.Add("Legacy OS ($($Computer.OperatingSystem))")
                        $RiskScore += 2
                    }

                    # RISK FACTOR 3: Enabled (can be exploted immediately)
                    if ($Computer.Enabled) {
                        [void]$RiskFactors.Add('Enabled')
                        $RiskScore += 2
                    } else {
                        [void]$RiskFactors.Add('Disabled (lower immediate risk)')
                        $RiskScore -= 1
                    }

                    # RISK FACTOR 4: Location (Production OUs = higher risk)
                    if ($Computer.CanonicalName -match 'Production|Server|Infrastructure|Exchange|SQL') {
                        [void]$RiskFactors.Add('Production system')
                        $RiskScore += 2
                    }

                    # Categorize by total risk score
                    $SystemInfo = [PSCustomObject]@{
                        Name            = $Computer.Name
                        OperatingSystem = $Computer.OperatingSystem
                        LastLogon       = $Computer.LastLogonDate
                        Created         = $Computer.Created
                        Enabled         = $Computer.Enabled
                        Location        = $Computer.CanonicalName
                        Description     = $Computer.Description
                        RiskFactors     = $RiskFactors -join '; '
                        RiskScore       = $RiskScore
                    }

                    if ($RiskScore -ge 5) {
                        [void]$HighRiskSystems.Add($SystemInfo)
                    } elseif ($RiskScore -ge 3) {
                        [void]$MediumRiskSystems.Add($SystemInfo)
                    } else {
                        [void]$LowRiskSystems.Add($SystemInfo)
                    }
                } # end foreach computer

                # Display findings by severity
                if ($HighRiskSystems.Count -gt 0) {
                    Write-Warning -Message ('HIGH RISK - IMMEDIATE ACTION REQUIRED: {0} systems' -f $HighRiskSystems.Count)
                    Write-Verbose -Message ($HighRiskSystems | Format-Table Name, OperatingSystem, LastLogon, Enabled, RiskFactors -AutoSize -Wrap | Out-String)
                }

                if ($MediumRiskSystems.Count -gt 0) {
                    Write-Warning -Message ('MEDIUM RISK - REMEDIATE WITHIN 30 DAYS: {0} systems' -f $MediumRiskSystems.Count)
                    Write-Verbose -Message ($MediumRiskSystems | Format-Table Name, OperatingSystem, LastLogon, Enabled, RiskFactors -AutoSize -Wrap | Out-String)
                }

                if ($LowRiskSystems.Count -gt 0) {
                    Write-Verbose -Message ('LOW RISK - SCHEDULED REMEDIATION: {0} systems' -f $LowRiskSystems.Count)
                    Write-Verbose -Message ($LowRiskSystems | Format-Table Name, OperatingSystem, LastLogon, Enabled -AutoSize -Wrap | Out-String)
                }

                $AttackScenario = @'

ATTACK SCENARIO - Unconstrained Delegation Exploitation:
  1. Attacker compromises ANY of these systems (phishing, exploit, stolen credentials)
  2. Attacker forces Domain Admin to authenticate to compromised system (PrinterBug/PetitPotam)
  3. Domain Admin TGT cached in LSASS memory of delegated system
  4. Attacker extracts TGT with Mimikatz → Full domain compromise
'@
                Write-Warning -Message $AttackScenario

            } else {
                $SecureConfig = @'
╔════════════════════════════════════════════════════════════════╗
║  ✓ SECURE - No non-DC systems with unconstrained delegation   ║
╚════════════════════════════════════════════════════════════════╝

Configuration Status:
  [+] All delegated systems are Domain Controllers (expected behavior)
  [+] This attack vector is properly controlled
'@
                Write-Verbose -Message $SecureConfig
            } # end if NonDCComputers

            # ========================================
            # DISPLAY SERVICE ACCOUNTS (if requested)
            # ========================================
            if ($IncludeServiceAccounts -and $DelegatedUsers.Count -gt 0) {
                Write-Warning -Message ('SERVICE ACCOUNTS WITH UNCONSTRAINED DELEGATION: {0} accounts' -f $DelegatedUsers.Count)

                $ServiceAccountInfo = $DelegatedUsers | Select-Object Name, SamAccountName, Enabled, LastLogonDate, Description, @{
                    Name       = 'SPNs'
                    Expression = { $_.ServicePrincipalName -join '; ' }
                }
                Write-Verbose -Message ($ServiceAccountInfo | Format-Table -AutoSize -Wrap | Out-String)

                Write-Warning -Message 'Service accounts should use CONSTRAINED delegation or RBCD, not unconstrained!'
            } # end if IncludeServiceAccounts

            # ========================================
            # PHASE 2: PROTECTED USERS & DELEGATION PROTECTION ANALYSIS
            # ========================================
            if ($CheckProtectedUsers) {
                Write-Verbose -Message 'Phase 2: Analyzing Privileged Account Protection'

                # Get Protected Users group members
                try {
                    $ProtectedUsersGroup = Get-ADGroup -Identity 'Protected Users' -Properties Members -ErrorAction Stop
                    $ProtectedUsersDN = $ProtectedUsersGroup.Members
                    Write-Verbose -Message ('Protected Users Group: {0} members' -f $ProtectedUsersDN.Count)
                } catch {
                    Write-Warning -Message 'Protected Users group not found (requires Server 2012 R2+ functional level)'
                    $ProtectedUsersDN = @()
                }

                # Get privileged accounts (Domain Admins, Enterprise Admins, Schema Admins, Account Operators)
                $PrivilegedGroups = @(
                    'Domain Admins',
                    'Enterprise Admins',
                    'Schema Admins',
                    'Account Operators',
                    'Backup Operators',
                    'Server Operators',
                    'Administrators'
                )

                foreach ($GroupName in $PrivilegedGroups) {
                    try {
                        $Group = Get-ADGroup -Identity $GroupName -Properties Members -ErrorAction SilentlyContinue
                        if ($Group) {
                            foreach ($MemberDN in $Group.Members) {
                                # Get user object (skip nested groups for simplicity)
                                try {
                                    $User = Get-ADUser -Identity $MemberDN -Properties AccountNotDelegated, MemberOf -ErrorAction SilentlyContinue
                                    if ($User) {
                                        [void]$AllPrivilegedUsers.Add([PSCustomObject]@{
                                                Name                = $User.Name
                                                SamAccountName      = $User.SamAccountName
                                                Group               = $GroupName
                                                AccountNotDelegated = $User.AccountNotDelegated
                                                InProtectedUsers    = $ProtectedUsersDN -contains $User.DistinguishedName
                                            })
                                    }
                                } catch {
                                    # Member is a group or foreign security principal, skip
                                }
                            } # end foreach MemberDN
                        }
                    } catch {
                        Write-Warning -Message ('Could not query group: {0}' -f $GroupName)
                    }
                } # end foreach PrivilegedGroups

                # Remove duplicates (user in multiple groups)
                $UniquePrivilegedUsers = $AllPrivilegedUsers | Sort-Object SamAccountName -Unique

                # Identify vulnerable privileged accounts
                $VulnerableAdminsTemp = $UniquePrivilegedUsers | Where-Object {
                    -not $_.InProtectedUsers -and -not $_.AccountNotDelegated
                }
                foreach ($Admin in $VulnerableAdminsTemp) {
                    [void]$VulnerableAdmins.Add($Admin)
                }

                $ProtectedCount = ($UniquePrivilegedUsers | Where-Object { $_.InProtectedUsers -or $_.AccountNotDelegated }).Count

                Write-Verbose -Message ('Total Privileged Accounts: {0}' -f $UniquePrivilegedUsers.Count)
                Write-Verbose -Message ('Protected from Delegation: {0}' -f $ProtectedCount)

                if ($VulnerableAdmins.Count -gt 0) {
                    Write-Warning -Message ('VULNERABLE to Delegation: {0}' -f $VulnerableAdmins.Count)
                } else {
                    Write-Verbose -Message ('VULNERABLE to Delegation: {0}' -f $VulnerableAdmins.Count)
                }

                if ($VulnerableAdmins.Count -gt 0) {
                    $VulnerableWarning = @'
╔════════════════════════════════════════════════════════════════╗
║  ⚠️  PRIVILEGED ACCOUNTS VULNERABLE TO DELEGATION ATTACKS ⚠️  ║
╚════════════════════════════════════════════════════════════════╝
'@
                    Write-Warning -Message $VulnerableWarning

                    $VulnerableList = $VulnerableAdmins | Select-Object -First 25
                    Write-Verbose -Message ($VulnerableList | Format-Table Name, Group -AutoSize -Wrap | Out-String)

                    if ($VulnerableAdmins.Count -gt 25) {
                        Write-Warning -Message ('... and {0} more' -f ($VulnerableAdmins.Count - 25))
                    }

                    $RemediationOptions = @'

REMEDIATION OPTIONS:
  OPTION 1 - Add to Protected Users group (recommended for Server 2012 R2+):
    Add-ADGroupMember -Identity 'Protected Users' -Members (Get-ADUser admin)

  OPTION 2 - Set 'Account is sensitive' flag (works on older domains):
    Set-ADUser -Identity admin -AccountNotDelegated $true
'@
                    Write-Verbose -Message $RemediationOptions

                } else {
                    $ProtectionStatus = @'
[+] All privileged accounts are protected from delegation attacks
[+] Accounts are in Protected Users group or have AccountNotDelegated flag
'@
                    Write-Verbose -Message $ProtectionStatus
                }
            } # end if CheckProtectedUsers

            # ========================================
            # REMEDIATION GUIDANCE
            # ========================================
            $RemediationHeader = @'
╔════════════════════════════════════════════════════════════════╗
║  REMEDIATION STEPS                                             ║
╚════════════════════════════════════════════════════════════════╝
'@
            Write-Verbose -Message $RemediationHeader

            if ($NonDCComputers.Count -gt 0) {
                $Step1Guidance = @'

[STEP 1] Remove Unconstrained Delegation from Computers

For each system identified above, verify no legitimate delegation requirements:

# Disable unconstrained delegation:
$Computer = Get-ADComputer -Identity 'SERVERNAME'
$Computer | Set-ADAccountControl -TrustedForDelegation $false

# Verify removal:
Get-ADComputer -Identity 'SERVERNAME' -Properties TrustedForDelegation | Select Name,TrustedForDelegation

[STEP 2] Migrate to Constrained Delegation (if delegation is required)

If application requires delegation, use CONSTRAINED delegation instead:
Set-ADComputer -Identity 'SERVERNAME' -Add @{'msDS-AllowedToDelegateTo'=@('HTTP/webserver','CIFS/fileserver')}
'@
                Write-Verbose -Message $Step1Guidance
            }

            $ProtectionGuidance = @'

[STEP 3] Protect Privileged Accounts

Add Domain Admins to Protected Users group:
Add-ADGroupMember -Identity 'Protected Users' -Members (Get-ADGroupMember 'Domain Admins')

[STEP 4] Disable Print Spooler on Domain Controllers

Prevent PrinterBug/SpoolSample attacks:
Get-ADDomainController -Filter * | ForEach-Object { Invoke-Command -ComputerName $_.Name -ScriptBlock { Stop-Service Spooler; Set-Service Spooler -StartupType Disabled } }

[STEP 5] Implement Monitoring

Monitor for delegation changes in SIEM:
• Event ID 5136 (Directory Service Object Modified) - filter for userAccountControl changes
• Event ID 4624 (Logon) - Logon Type 3 from privileged accounts to delegated systems
• Event ID 4768/4769 (Kerberos) - TGT/Service Ticket with delegation flags
'@
            Write-Verbose -Message $ProtectionGuidance

            # ========================================
            # EXPORT REPORTS
            # ========================================
            if ($PSBoundParameters.ContainsKey('ExportPath')) {
                Write-Verbose -Message 'Preparing detailed reports for export...'

                if (-not (Test-Path $ExportPath)) {
                    if ($PSCmdlet.ShouldProcess($ExportPath, 'Create directory')) {
                        try {
                            New-Item -ItemType Directory -Path $ExportPath -ErrorAction Stop | Out-Null
                            Write-Verbose -Message ('Created export directory: {0}' -f $ExportPath)
                        } catch {
                            Write-Error -Message ('Failed to create export directory: {0}' -f $_.Exception.Message)
                            throw
                        }
                    }
                }

                $Timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'

                # Export delegated computers
                if ($NonDCComputers.Count -gt 0) {
                    $ComputerReport = Join-Path -Path $ExportPath -ChildPath "UnconstrainedDelegation-Computers-$Timestamp.csv"
                    if ($PSCmdlet.ShouldProcess($ComputerReport, 'Export delegated computers report')) {
                        try {
                            $NonDCComputers | Select-Object Name, OperatingSystem, LastLogonDate, Created, Enabled, CanonicalName, Description |
                                Export-Csv -Path $ComputerReport -NoTypeInformation -ErrorAction Stop
                            Write-Verbose -Message ('Delegated computers report: {0}' -f $ComputerReport)
                            [void]$ExportedReports.Add($ComputerReport)
                        } catch {
                            Write-Error -Message ('Failed to export computers report: {0}' -f $_.Exception.Message)
                        }
                    }
                }

                # Export delegated users
                if ($DelegatedUsers.Count -gt 0) {
                    $UserReport = Join-Path -Path $ExportPath -ChildPath "UnconstrainedDelegation-ServiceAccounts-$Timestamp.csv"
                    if ($PSCmdlet.ShouldProcess($UserReport, 'Export delegated service accounts report')) {
                        try {
                            $DelegatedUsers | Select-Object Name, SamAccountName, Enabled, LastLogonDate, Description |
                                Export-Csv -Path $UserReport -NoTypeInformation -ErrorAction Stop
                            Write-Verbose -Message ('Delegated service accounts report: {0}' -f $UserReport)
                            [void]$ExportedReports.Add($UserReport)
                        } catch {
                            Write-Error -Message ('Failed to export service accounts report: {0}' -f $_.Exception.Message)
                        }
                    }
                }

                # Export vulnerable admins
                if ($CheckProtectedUsers -and $VulnerableAdmins.Count -gt 0) {
                    $AdminReport = Join-Path -Path $ExportPath -ChildPath "UnconstrainedDelegation-VulnerableAdmins-$Timestamp.csv"
                    if ($PSCmdlet.ShouldProcess($AdminReport, 'Export vulnerable admins report')) {
                        try {
                            $VulnerableAdmins | Export-Csv -Path $AdminReport -NoTypeInformation -ErrorAction Stop
                            Write-Verbose -Message ('Vulnerable admins report: {0}' -f $AdminReport)
                            [void]$ExportedReports.Add($AdminReport)
                        } catch {
                            Write-Error -Message ('Failed to export vulnerable admins report: {0}' -f $_.Exception.Message)
                        }
                    }
                }

                # Export summary
                $SummaryReport = Join-Path -Path $ExportPath -ChildPath "UnconstrainedDelegation-Summary-$Timestamp.txt"
                if ($PSCmdlet.ShouldProcess($SummaryReport, 'Export summary report')) {
                    try {
                        $SummaryContent = @"
Unconstrained Delegation Security Audit Summary
Generated: $(Get-Date)
Domain: $DomainName

FINDINGS:
- Domain Controllers: $($DomainControllers.Count) (Expected)
- Non-DC Systems with Delegation: $($NonDCComputers.Count) $(if ($NonDCComputers.Count -eq 0) { '✓ SECURE' } else { '⚠️ SECURITY RISK' })
- Service Accounts with Delegation: $($DelegatedUsers.Count)
- Vulnerable Privileged Accounts: $(if ($CheckProtectedUsers) { $VulnerableAdmins.Count } else { 'Not Checked' })

RISK ASSESSMENT:
$(if ($NonDCComputers.Count -eq 0) {
    '✓ SECURE - No non-DC systems have unconstrained delegation enabled.'
} else {
    "⚠️ CRITICAL - $($NonDCComputers.Count) systems vulnerable to credential theft attacks.
  High Risk: $($HighRiskSystems.Count)
  Medium Risk: $($MediumRiskSystems.Count)
  Low Risk: $($LowRiskSystems.Count)"
})

RECOMMENDATION:
$(if ($NonDCComputers.Count -eq 0) {
    'Continue monitoring for new delegation grants. Implement SIEM alerts on Event ID 5136.'
} else {
    'IMMEDIATE ACTION: Remove unconstrained delegation from all non-DC systems.
Migrate to constrained delegation or RBCD if delegation is required.
Add privileged accounts to Protected Users group.'
})
"@
                        $SummaryContent | Out-File -FilePath $SummaryReport -ErrorAction Stop
                        Write-Verbose -Message ('Summary report: {0}' -f $SummaryReport)
                        [void]$ExportedReports.Add($SummaryReport)
                    } catch {
                        Write-Error -Message ('Failed to export summary report: {0}' -f $_.Exception.Message)
                    }
                }
            } # end if ExportPath

        } catch {
            Write-Error -Message ('Error during unconstrained delegation audit: {0}' -f $_.Exception.Message)
            throw
        } # end try-catch

    } # end Process

    end {

        # ========================================
        # AUDIT SUMMARY
        # ========================================
        $AuditSummary = @'
╔════════════════════════════════════════════════════════════════╗
║  Audit Complete                                                ║
╚════════════════════════════════════════════════════════════════╝

SUMMARY:
'@
        Write-Verbose -Message $AuditSummary
        Write-Verbose -Message ('  • Domain Controllers: {0}' -f $DomainControllers.Count)

        if ($NonDCComputers.Count -eq 0) {
            Write-Verbose -Message ('  • Non-DC Systems: {0} ✓' -f $NonDCComputers.Count)
        } else {
            Write-Warning -Message ('  • Non-DC Systems: {0} ⚠️ REMEDIATE IMMEDIATELY' -f $NonDCComputers.Count)
        }

        if ($IncludeServiceAccounts) {
            if ($DelegatedUsers.Count -eq 0) {
                Write-Verbose -Message ('  • Service Accounts: {0} ✓' -f $DelegatedUsers.Count)
            } else {
                Write-Warning -Message ('  • Service Accounts: {0} ⚠️' -f $DelegatedUsers.Count)
            }
        }

        if ($CheckProtectedUsers) {
            if ($VulnerableAdmins.Count -eq 0) {
                Write-Verbose -Message ('  • Vulnerable Privileged Accounts: {0} ✓' -f $VulnerableAdmins.Count)
            } else {
                Write-Warning -Message ('  • Vulnerable Privileged Accounts: {0} ⚠️' -f $VulnerableAdmins.Count)
            }
        }

        $RecommendedActions = @'

RECOMMENDED ACTIONS:
  1. Remove unconstrained delegation from all non-DC systems
  2. Add privileged accounts to Protected Users group
  3. Disable Print Spooler on domain controllers
  4. Implement SIEM monitoring for delegation changes (Event 5136)
  5. Schedule quarterly re-audits
'@
        Write-Verbose -Message $RecommendedActions

        # ========================================
        # BUILD OUTPUT OBJECT
        # ========================================
        $IsSecure = ($NonDCComputers.Count -eq 0)
        $RecommendedAction = if ($IsSecure) {
            'Continue monitoring for new delegation grants. Implement SIEM alerts on Event ID 5136.'
        } else {
            'IMMEDIATE ACTION: Remove unconstrained delegation from all non-DC systems. Migrate to constrained delegation or RBCD if needed.'
        }

        $AuditResult = [PSCustomObject]@{
            PSTypeName                       = 'EguibarIT.Security.UnconstrainedDelegationAudit'
            DomainName                       = $DomainName
            DomainControllerCount            = $DomainControllers.Count
            NonDCComputerCount               = $NonDCComputers.Count
            HighRiskSystemCount              = $HighRiskSystems.Count
            MediumRiskSystemCount            = $MediumRiskSystems.Count
            LowRiskSystemCount               = $LowRiskSystems.Count
            ServiceAccountCount              = $DelegatedUsers.Count
            PrivilegedAccountCount           = if ($CheckProtectedUsers) {
                $AllPrivilegedUsers.Count
            } else {
                $null
            }
            VulnerablePrivilegedAccountCount = if ($CheckProtectedUsers) {
                $VulnerableAdmins.Count
            } else {
                $null
            }
            IsSecure                         = $IsSecure
            RecommendedAction                = $RecommendedAction
            ExportedReports                  = $ExportedReports
            AuditDate                        = Get-Date
        }

        Write-Output -InputObject $AuditResult

        if ($null -ne $Variables -and
            $null -ne $Variables.FooterSecurity) {

            $txt = ($Variables.FooterSecurity -f $MyInvocation.InvocationName,
                'finished finding unconstrained delegations.'
            )
            Write-Verbose -Message $txt
        } #end If
    } # end End

} # end function Get-UnconstrainedDelegation
