function Get-PrivilegedDelegationViolation {
    <#
        .SYNOPSIS
            Detects privileged accounts that violate the Kerberos delegation security baseline in Active Directory.

        .DESCRIPTION
            Performs a three-phase audit to find privileged admin accounts (Tier 0, Tier 1, Tier 2 and
            direct privileged group members) that have insecure Kerberos delegation configurations:

            **Phase 1 - UNCONSTRAINED DELEGATION ON PRIVILEGED ACCOUNTS:**
            Identifies privileged accounts where TrustedForDelegation = $true. This means the account
            can impersonate ANY authenticated user and present their credentials to ANY service in the
            forest — a catastrophic misconfiguration on admin accounts.

            **Phase 2 - MISSING "ACCOUNT IS SENSITIVE AND CANNOT BE DELEGATED" FLAG:**
            Identifies privileged accounts where AccountNotDelegated = $false (flag not set). While this
            does not enable delegation directly, it allows another service account configured for constrained
            delegation to impersonate the privileged user. This is the standard security baseline requirement:
            all Tier 0/1/2 accounts MUST have this flag set.

            **Phase 3 - PRIVILEGED GROUP MEMBER DELEGATION SCAN:**
            Enumerates current members of Domain Admins, Enterprise Admins, Schema Admins, Administrators,
            Account Operators, Backup Operators, and Server Operators and applies the same checks.
            Catches accounts not following the Tier naming convention.

            **ATTACK VECTOR:**
            Kerberos delegation allows services to act on behalf of users. If a privileged account does
            not have the "sensitive and cannot be delegated" flag and an attacker compromises a system
            configured for constrained delegation TO a service that the privileged user authenticates to,
            the attacker can impersonate the privileged user. Unconstrained delegation is worse — any
            system can capture and replay a Domain Admin's TGT if the admin authenticates to it.

            **MITRE ATT&CK Mapping:**
            - **T1558.001**: Steal or Forge Kerberos Tickets - Golden Ticket
            - **T1550.003**: Use Alternate Authentication Material - Pass the Ticket
            - **T1484**: Domain Policy Modification

            **DETECTION REQUIREMENTS:**
            - Read access to user objects in Active Directory
            - ActiveDirectory module available

        .PARAMETER TierNamePatterns
            Array of account name patterns (supports wildcards) used to identify tiered admin accounts.
            Default patterns: 'T0_*', 'T1_*', 'T2_*', 'Adm_*', 'Admin_*', '_Admin*', 'PA_*'.
            Adjust to match your organization's naming convention.

        .PARAMETER IncludeDisabled
            If specified, includes disabled accounts in the findings.
            By default, only enabled accounts are reported (disabled accounts represent lower immediate risk).

        .PARAMETER OutputPath
            Directory where detection results are exported in CSV and JSON format.
            Export respects -WhatIf and -Confirm.

        .EXAMPLE
            Get-PrivilegedDelegationViolation

            Description
            -----------
            Runs all three phases using default tier naming patterns.

        .EXAMPLE
            Get-PrivilegedDelegationViolation -TierNamePatterns @('ADM_*', 'TIER0_*', 'TIER1_*') -Verbose

            Description
            -----------
            Runs the audit with custom tier account naming patterns and verbose output.

        .EXAMPLE
            Get-PrivilegedDelegationViolation -IncludeDisabled -OutputPath 'C:\SecurityAudits'

            Description
            -----------
            Includes disabled accounts and exports all findings.

        .EXAMPLE
            $Result = Get-PrivilegedDelegationViolation
            $Result.Findings | Where-Object RiskLevel -eq 'Critical' | Select-Object AccountName, Indicator

            Description
            -----------
            Captures results and filters for critical severity findings only.

        .INPUTS
            None. This function does not accept pipeline input.

        .OUTPUTS
            PSCustomObject. Returns an audit summary with the following properties:
            - AuditTimestamp: When the audit ran
            - DomainName: DNS name of the audited domain
            - UnconstrainedDelegationCount: Privileged accounts with TrustedForDelegation = $true
            - MissingNotDelegatedFlagCount: Privileged accounts with AccountNotDelegated = $false
            - TotalFindings: Combined finding count
            - CriticalCount: Critical severity findings
            - HighCount: High severity findings
            - IsSecure: $true only when zero findings
            - Findings: Array of detailed finding objects
            - RecommendedActions: Array of remediation strings
            - ExportedReports: Array of file paths if OutputPath was specified

        .NOTES
            Used Functions:
                Name                                   | Module
                --------------------------------------- | --------------------------
                Get-FunctionDisplay                    | EguibarIT.SecurityPS
                Import-MyModule                        | EguibarIT.SecurityPS
                Get-ADDomain                           | ActiveDirectory
                Get-ADUser                             | ActiveDirectory
                Get-ADGroup                            | ActiveDirectory
                Get-ADGroupMember                      | ActiveDirectory
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
            DateModified:    24/Aug/2026
            LastModifiedBy:  Vicente Rodriguez Eguibar
                vicente@eguibar.com
                EguibarIT
                http://www.eguibarit.com

        .LINK
            https://attack.mitre.org/techniques/T1558/001/

        .LINK
            https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group

        .LINK
            https://github.com/vreguibar/EguibarIT.SecurityPS

        .COMPONENT
            EguibarIT.SecurityPS

        .ROLE
            Security Auditing

        .FUNCTIONALITY
            Detects Kerberos delegation misconfigurations on privileged Active Directory accounts
            to prevent credential impersonation attacks.
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
            HelpMessage = 'Wildcard patterns matching tiered admin account names (e.g. T0_*, Adm_*)',
            Position = 0
        )]
        [AllowEmptyCollection()]
        [ValidateNotNull()]
        [PSDefaultValue(Help = 'Default: T0_*, T1_*, T2_*, Adm_*, Admin_*, _Admin*, PA_*')]
        [string[]]
        $TierNamePatterns = @('T0_*', 'T1_*', 'T2_*', 'Adm_*', 'Admin_*', '_Admin*', 'PA_*'),

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Include disabled accounts in findings',
            Position = 1
        )]
        [PSDefaultValue(
            Help  = 'Default: $false',
            Value = $false
        )]
        [switch]
        $IncludeDisabled,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Directory where detection results are exported in CSV and JSON format',
            Position = 2
        )]
        [ValidateNotNullOrEmpty()]
        [Alias('ExportPath', 'Path')]
        [PSDefaultValue(
            Help  = 'Default: Desktop\DelegationAudit',
            Value = 'Desktop\DelegationAudit'
        )]
        [string]
        $OutputPath = (Join-Path -Path $env:USERPROFILE -ChildPath 'Desktop\DelegationAudit')
    )

    begin {
        Set-StrictMode -Version Latest

        [datetime]$AuditTimestamp = Get-Date

        [System.Collections.Generic.List[PSCustomObject]]$Findings =
            [System.Collections.Generic.List[PSCustomObject]]::new()

        [System.Collections.Generic.List[string]]$RecommendedActions =
            [System.Collections.Generic.List[string]]::new()

        [System.Collections.Generic.List[string]]$ExportedReports =
            [System.Collections.Generic.List[string]]::new()

        # Track DNs already reported to avoid duplicate findings from Phase 2 and Phase 3 overlap
        [System.Collections.Generic.HashSet[string]]$ReportedDNs =
            [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

        [int]$UnconstrainedDelegationCount  = 0
        [int]$MissingNotDelegatedFlagCount  = 0

        if ($null -ne $Variables -and $null -ne $Variables.HeaderSecurity) {
            $txt = ($Variables.HeaderSecurity -f
                $AuditTimestamp.ToString('dd/MMM/yyyy'),
                $MyInvocation.Mycommand,
                (Get-FunctionDisplay -Hashtable $PsBoundParameters -Verbose:$false)
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
                'ActiveDirectory module is required but not available. Install RSAT-AD-PowerShell. Error: {0}' -f
                $_.Exception.Message
            ) -Category NotInstalled -ErrorAction Stop
        } #end try-catch

        ##############################
        # Variables Definition

        [string[]]$PrivilegedGroupNames = @(
            'Domain Admins',
            'Enterprise Admins',
            'Schema Admins',
            'Administrators',
            'Account Operators',
            'Backup Operators',
            'Server Operators'
        )

        [string[]]$RequiredProperties = @(
            'TrustedForDelegation',
            'AccountNotDelegated',
            'UserAccountControl',
            'Enabled',
            'DistinguishedName',
            'SamAccountName',
            'PasswordLastSet',
            'AdminCount',
            'Description'
        )

        $SplatParams = $null

        Write-Verbose -Message ('Privileged delegation violation audit initialized. Tier patterns: {0}' -f ($TierNamePatterns -join ', '))
    } #end begin

    process {
        try {
            # Inline helper: evaluate delegation flags and add findings
            $EvaluateAccount = {
                param([object]$Account, [string]$DiscoveredVia)

                # Apply enabled filter
                if (-not $IncludeDisabled -and -not $Account.Enabled) {
                    return
                } #end if

                if ($Account.TrustedForDelegation -eq $true) {
                    $script:UnconstrainedDelegationCount++
                    $Findings.Add([PSCustomObject]@{
                        PSTypeName           = 'EguibarIT.PrivilegedDelegationViolation.Finding'
                        Timestamp            = $AuditTimestamp.ToString('yyyy-MM-dd HH:mm:ss')
                        Phase                = 'UnconstrainedDelegation'
                        RiskLevel            = 'Critical'
                        DiscoveredVia        = $DiscoveredVia
                        AccountName          = $Account.SamAccountName
                        DistinguishedName    = $Account.DistinguishedName
                        Enabled              = $Account.Enabled
                        TrustedForDelegation = $Account.TrustedForDelegation
                        AccountNotDelegated  = $Account.AccountNotDelegated
                        AdminCount           = $Account.AdminCount
                        PasswordLastSet      = $Account.PasswordLastSet
                        Indicator            = (
                            'Privileged account "{0}" has TrustedForDelegation = $true (unconstrained Kerberos delegation). Any user authenticating to this account exposes their TGT to impersonation.' -f
                            $Account.SamAccountName
                        )
                        Remediation          = (
                            'Immediately: Set-ADUser -Identity "{0}" -TrustedForDelegation $false. Verify no services require unconstrained delegation on this account.' -f
                            $Account.SamAccountName
                        )
                    })
                    [void]$ReportedDNs.Add($Account.DistinguishedName)
                } #end if TrustedForDelegation

                if (-not $Account.AccountNotDelegated) {
                    $script:MissingNotDelegatedFlagCount++
                    $Findings.Add([PSCustomObject]@{
                        PSTypeName           = 'EguibarIT.PrivilegedDelegationViolation.Finding'
                        Timestamp            = $AuditTimestamp.ToString('yyyy-MM-dd HH:mm:ss')
                        Phase                = 'MissingNotDelegatedFlag'
                        RiskLevel            = 'High'
                        DiscoveredVia        = $DiscoveredVia
                        AccountName          = $Account.SamAccountName
                        DistinguishedName    = $Account.DistinguishedName
                        Enabled              = $Account.Enabled
                        TrustedForDelegation = $Account.TrustedForDelegation
                        AccountNotDelegated  = $Account.AccountNotDelegated
                        AdminCount           = $Account.AdminCount
                        PasswordLastSet      = $Account.PasswordLastSet
                        Indicator            = (
                            'Privileged account "{0}" does not have the "Account is sensitive and cannot be delegated" flag set (AccountNotDelegated = $false). A service with constrained delegation targeting a service this account uses can impersonate it.' -f
                            $Account.SamAccountName
                        )
                        Remediation          = (
                            'Set-ADUser -Identity "{0}" -AccountNotDelegated $true' -f
                            $Account.SamAccountName
                        )
                    })
                } #end if AccountNotDelegated
            } #end EvaluateAccount scriptblock

            # =====================================================================
            # PHASE 1 & 2 — TIERED ADMIN ACCOUNTS by naming pattern
            # =====================================================================
            $SplatParams = @{
                Activity        = 'Privileged Delegation Violation Audit'
                Status          = 'Phase 1/3: Scanning tiered admin accounts by name pattern'
                PercentComplete = 10
            }
            Write-Progress @SplatParams

            Write-Verbose -Message '[Phase 1/2] Querying tiered admin accounts by name pattern.'

            foreach ($Pattern in $TierNamePatterns) {
                Write-Verbose -Message ('[Phase 1/2] Searching pattern: {0}' -f $Pattern)

                try {
                    $SplatParams = @{
                        Filter      = "SamAccountName -like '$Pattern'"
                        Properties  = $RequiredProperties
                        ErrorAction = 'Stop'
                    }
                    $TierAccounts = Get-ADUser @SplatParams

                    foreach ($Account in $TierAccounts) {
                        & $EvaluateAccount $Account ('TierPattern:{0}' -f $Pattern)
                    } #end foreach
                } catch {
                    Write-Warning -Message ('[Phase 1/2] Error querying pattern "{0}": {1}' -f $Pattern, $_.Exception.Message)
                } #end try-catch
            } #end foreach Pattern

            Write-Verbose -Message ('[Phase 1/2] After tier-pattern scan — Critical: {0}, High: {1}' -f $UnconstrainedDelegationCount, $MissingNotDelegatedFlagCount)

            # =====================================================================
            # PHASE 3 — PRIVILEGED GROUP MEMBERS (catches non-tiered accounts)
            # =====================================================================
            $SplatParams = @{
                Activity        = 'Privileged Delegation Violation Audit'
                Status          = 'Phase 3/3: Scanning privileged group members'
                PercentComplete = 55
            }
            Write-Progress @SplatParams

            Write-Verbose -Message '[Phase 3] Scanning members of privileged groups.'

            foreach ($GroupName in $PrivilegedGroupNames) {
                try {
                    $SplatParams = @{ Identity = $GroupName; Recursive = $true; ErrorAction = 'Stop' }
                    $GroupMembers = Get-ADGroupMember @SplatParams

                    foreach ($Member in $GroupMembers) {
                        if ($Member.objectClass -ne 'user') {
                            continue
                        } #end if

                        try {
                            $SplatParams = @{
                                Identity    = $Member.DistinguishedName
                                Properties  = $RequiredProperties
                                ErrorAction = 'Stop'
                            }
                            $Account = Get-ADUser @SplatParams

                            & $EvaluateAccount $Account ('PrivilegedGroup:{0}' -f $GroupName)
                        } catch {
                            Write-Warning -Message ('[Phase 3] Could not read user "{0}": {1}' -f $Member.DistinguishedName, $_.Exception.Message)
                        } #end try-catch
                    } #end foreach Member
                } catch {
                    Write-Warning -Message ('[Phase 3] Could not enumerate group "{0}": {1}' -f $GroupName, $_.Exception.Message)
                } #end try-catch
            } #end foreach GroupName

            Write-Verbose -Message ('[Phase 3] Total — Unconstrained: {0}, Missing Not-Delegated flag: {1}' -f $UnconstrainedDelegationCount, $MissingNotDelegatedFlagCount)

            # Build remediation recommendations
            if ($UnconstrainedDelegationCount -gt 0) {
                $RecommendedActions.Add(
                    ('CRITICAL: {0} privileged account(s) have unconstrained Kerberos delegation enabled. Disable immediately with Set-ADUser -TrustedForDelegation $false.' -f $UnconstrainedDelegationCount)
                )
            } #end if

            if ($MissingNotDelegatedFlagCount -gt 0) {
                $RecommendedActions.Add(
                    ('HIGH: {0} privileged account(s) are missing the "Account is sensitive and cannot be delegated" flag. Apply: Set-ADUser -AccountNotDelegated $true.' -f $MissingNotDelegatedFlagCount)
                )
            } #end if

            # =====================================================================
            # OPTIONAL EXPORT
            # =====================================================================
            if ($PSBoundParameters.ContainsKey('OutputPath') -and $Findings.Count -gt 0) {
                if ($PSCmdlet.ShouldProcess($OutputPath, 'Export privileged delegation violation findings')) {
                    try {
                        if (-not (Test-Path -Path $OutputPath)) {
                            New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
                        } #end if

                        [string]$Stamp    = $AuditTimestamp.ToString('yyyyMMdd-HHmmss')
                        [string]$CsvFile  = Join-Path -Path $OutputPath -ChildPath ('PrivilegedDelegationViolation-{0}.csv' -f $Stamp)
                        [string]$JsonFile = Join-Path -Path $OutputPath -ChildPath ('PrivilegedDelegationViolation-{0}.json' -f $Stamp)

                        $Findings | Export-Csv -Path $CsvFile -NoTypeInformation -Encoding UTF8 -Force
                        $Findings | ConvertTo-Json -Depth 5 | Out-File -FilePath $JsonFile -Encoding UTF8 -Force

                        $ExportedReports.Add($CsvFile)
                        $ExportedReports.Add($JsonFile)
                        Write-Verbose -Message ('Findings exported to: {0}' -f $OutputPath)
                    } catch {
                        Write-Warning -Message ('Failed to export findings: {0}' -f $_.Exception.Message)
                    } #end try-catch
                } #end if ShouldProcess
            } #end if OutputPath

        } catch {
            Write-Error -Message ('Privileged delegation violation audit failed: {0}' -f $_.Exception.Message) -ErrorAction Stop
        } #end try-catch
    } #end process

    end {
        [int]$CriticalCount = ($Findings | Where-Object { $_.RiskLevel -eq 'Critical' }).Count
        [int]$HighCount     = ($Findings | Where-Object { $_.RiskLevel -eq 'High' }).Count
        [int]$TotalFindings = $Findings.Count

        if ($TotalFindings -eq 0) {
            $RecommendedActions.Add('No delegation violations found. All audited privileged accounts comply with the delegation security baseline.')
        } #end if

        [PSCustomObject]$AuditResult = [PSCustomObject]@{
            PSTypeName                   = 'EguibarIT.PrivilegedDelegationViolation.Summary'
            AuditTimestamp               = $AuditTimestamp.ToString('yyyy-MM-dd HH:mm:ss')
            DomainName                   = $Variables.DnsFqdn
            UnconstrainedDelegationCount = $UnconstrainedDelegationCount
            MissingNotDelegatedFlagCount = $MissingNotDelegatedFlagCount
            TotalFindings                = $TotalFindings
            CriticalCount                = $CriticalCount
            HighCount                    = $HighCount
            IsSecure                     = ($TotalFindings -eq 0)
            Findings                     = $Findings
            RecommendedActions           = $RecommendedActions
            ExportedReports              = $ExportedReports
        }

        if ($null -ne $Variables -and $null -ne $Variables.FooterSecurity) {
            $txt = ($Variables.FooterSecurity -f $MyInvocation.MyCommand, (Get-Date).ToString('dd/MMM/yyyy HH:mm:ss'))
            Write-Verbose -Message $txt
        } #end if

        Write-Output -InputObject $AuditResult
    } #end end

} #end Function Get-PrivilegedDelegationViolation
