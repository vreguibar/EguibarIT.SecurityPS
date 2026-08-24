function Get-AdminSDHolderAnomaly {
    <#
        .SYNOPSIS
            Detects AdminSDHolder and AdminCount anomalies in Active Directory, including orphaned protection and ACL drift.

        .DESCRIPTION
            Performs a comprehensive three-phase AdminSDHolder security audit:

            **Phase 1 - ORPHANED ADMINCOUNT:**
            Identifies accounts with AdminCount > 0 that are NO LONGER members of any protected privileged
            group. The SDProp process (runs every 60 minutes) continues to override ACL inheritance on these
            accounts even after removal from privileged groups. Orphaned accounts are harder to audit, may
            retain over-permissive ACLs silently, and represent a persistence vector for attackers who achieve
            brief privileged group membership.

            **Phase 2 - ADMINSDHOLDER ACL DRIFT:**
            Audits the ACL on CN=AdminSDHolder,CN=System against a documented baseline of expected principals.
            Any unexpected ACE on AdminSDHolder propagates to every protected account in the domain within
            60 minutes via SDProp, making this a high-impact persistence and privilege escalation vector.

            **Phase 3 - UNPROTECTED PRIVILEGED ACCOUNTS (OPTIONAL):**
            Identifies accounts that ARE current members of privileged groups but have AdminCount = 0,
            meaning SDProp has not yet protected them. This can occur with very recently added accounts
            or if SDProp has been interfered with.

            **ATTACK VECTOR:**
            Attackers briefly add a compromised account to Domain Admins, wait for SDProp to harden the
            ACL (preventing ACL-based detection), then remove from the group. The account retains the
            AdminCount > 0 flag and the hardened ACL. Adding a rogue ACE to AdminSDHolder propagates
            covert permissions to all ~100 protected accounts within one SDProp cycle (default 60 min).

            **MITRE ATT&CK Mapping:**
            - **T1098**: Account Manipulation
            - **T1078.002**: Valid Accounts: Domain Accounts
            - **T1484.001**: Domain Policy Modification: Group Policy Modification

            **DETECTION REQUIREMENTS:**
            - Domain read permissions sufficient for Phase 1 and Phase 3
            - Permission to read the AdminSDHolder object ACL for Phase 2
            - ActiveDirectory module available

        .PARAMETER IncludeUnprotected
            If specified, runs Phase 3 to identify privileged group members with AdminCount = 0.
            Useful for detecting SDProp failures or very recently added accounts.

        .PARAMETER TrustedAdminSids
            Array of additional SID strings (S-1-5-...) or well-known names to treat as expected
            principals on the AdminSDHolder ACL. Used to whitelist legitimate delegated access
            that has been approved in the organization's delegation model.

        .PARAMETER OutputPath
            Directory where detection results are exported in CSV and JSON format.
            Export respects -WhatIf and -Confirm.

        .EXAMPLE
            Get-AdminSDHolderAnomaly

            Description
            -----------
            Runs Phase 1 and Phase 2 audits using default settings.

        .EXAMPLE
            Get-AdminSDHolderAnomaly -IncludeUnprotected -Verbose

            Description
            -----------
            Runs all three phases with verbose output.

        .EXAMPLE
            Get-AdminSDHolderAnomaly -TrustedAdminSids @('S-1-5-21-1234567890-123456789-1234567890-1111') -OutputPath 'C:\SecurityAudits'

            Description
            -----------
            Audits AdminSDHolder ACL while whitelisting a known delegated SID, and exports results.

        .EXAMPLE
            $Result = Get-AdminSDHolderAnomaly -IncludeUnprotected
            if ($Result.OrphanedAdminCountTotal -gt 0) {
                Write-Warning ('Found {0} accounts with orphaned AdminCount' -f $Result.OrphanedAdminCountTotal)
            }

            Description
            -----------
            Captures the audit result and evaluates findings programmatically.

        .INPUTS
            None. This function does not accept pipeline input.

        .OUTPUTS
            PSCustomObject. Returns an audit summary with the following properties:
            - AuditTimestamp: When the audit ran
            - DomainName: DNS name of the audited domain
            - OrphanedAdminCountTotal: Accounts with AdminCount > 0 but not in privileged groups
            - AdminSDHolderAceCount: Total ACEs on AdminSDHolder
            - UnexpectedAceCount: ACEs not matching expected principals
            - UnprotectedPrivilegedTotal: Privileged members with AdminCount = 0 (Phase 3, if requested)
            - TotalFindings: Combined finding count
            - CriticalCount: Critical severity findings
            - HighCount: High severity findings
            - MediumCount: Medium severity findings
            - IsClean: $true if no anomalies detected
            - Findings: Array of detailed finding objects
            - RecommendedActions: Array of remediation strings
            - ExportedReports: Array of file paths if OutputPath was specified

        .NOTES
            Used Functions:
                Name                                   | Module
                -------------------------------------- | --------------------------
                Get-FunctionDisplay                    | EguibarIT.SecurityPS
                Import-MyModule                        | EguibarIT.SecurityPS
                Get-ADDomain                           | ActiveDirectory
                Get-ADUser                             | ActiveDirectory
                Get-ADGroup                            | ActiveDirectory
                Get-ADGroupMember                      | ActiveDirectory
                Get-ADObject                           | ActiveDirectory
                Get-Acl                                | Microsoft.PowerShell.Security
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
            https://attack.mitre.org/techniques/T1098/

        .LINK
            https://technet.microsoft.com/en-us/magazine/2009.09.sdadminholder.aspx

        .LINK
            https://github.com/vreguibar/EguibarIT.SecurityPS

        .COMPONENT
            EguibarIT.SecurityPS

        .ROLE
            Security Auditing

        .FUNCTIONALITY
            Detects AdminSDHolder ACL drift and orphaned AdminCount protection to identify persistence
            and privilege escalation vectors in Active Directory.
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
            HelpMessage = 'Run Phase 3: find privileged group members with AdminCount = 0',
            Position = 0
        )]
        [PSDefaultValue(
            Help = 'Default: $false',
            Value = $false
        )]
        [switch]
        $IncludeUnprotected,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Additional SID strings approved as trusted on the AdminSDHolder ACL',
            Position = 1
        )]
        [AllowEmptyCollection()]
        [ValidateNotNull()]
        [PSDefaultValue(
            Help = 'Default: $false',
            Value = $false
        )]
        [string[]]
        $TrustedAdminSids = @(),

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
            Help = 'Default: Desktop\AdminSDHolderAudit',
            Value = 'Desktop\AdminSDHolderAudit'
        )]
        [string]
        $OutputPath = (Join-Path -Path $env:USERPROFILE -ChildPath 'Desktop\AdminSDHolderAudit')
    )

    begin {

        # Set strict mode
        Set-StrictMode -Version Latest

        # Display function header if variables exist
        if ($null -ne $Variables -and
            $null -ne $Variables.HeaderSecurity) {

            # Log function invocation with parameters
            $txt = ($Variables.HeaderSecurity -f
                (Get-Date).ToString('dd/MMM/yyyy'),
                $MyInvocation.Mycommand,
                (Get-FunctionDisplay -Hashtable $PsBoundParameters -Verbose:$False)
            )
            Write-Verbose -Message $txt
        } #end If

        Write-Verbose -Message 'AdminSDHolder anomaly detection | MITRE ATT&CK T1098, T1078.002, T1484.001'

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

        $SplatParams = $null

        [datetime]$AuditTimestamp = Get-Date

        [System.Collections.Generic.List[PSCustomObject]]$Findings =
        [System.Collections.Generic.List[PSCustomObject]]::new()

        [System.Collections.Generic.List[string]]$RecommendedActions =
        [System.Collections.Generic.List[string]]::new()

        [System.Collections.Generic.List[string]]$ExportedReports =
        [System.Collections.Generic.List[string]]::new()

        [int]$OrphanedAdminCountTotal = 0
        [int]$UnexpectedAceCount = 0
        [int]$AdminSDHolderAceCount = 0
        [int]$UnprotectedPrivilegedTotal = 0

        # Protected groups whose members receive AdminSDHolder ACL protection via SDProp
        [string[]]$ProtectedGroupNames = @(
            'Domain Admins',
            'Enterprise Admins',
            'Schema Admins',
            'Administrators',
            'Account Operators',
            'Backup Operators',
            'Print Operators',
            'Server Operators',
            'Group Policy Creator Owners',
            'Replicator',
            'Domain Controllers',
            'Read-only Domain Controllers'
        )

        # Default well-known SIDs expected on AdminSDHolder ACL (built-ins); everything else is suspicious
        [System.Collections.Generic.HashSet[string]]$ExpectedSidPrefixes =
        [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

        # Well-known built-in SIDs that are always legitimate on AdminSDHolder
        @(
            'S-1-5-32-544',   # BUILTIN\Administrators
            'S-1-5-18',       # NT AUTHORITY\SYSTEM
            'S-1-3-0',        # Creator Owner
            'S-1-5-9'         # Enterprise Domain Controllers
        ) | ForEach-Object { [void]$ExpectedSidPrefixes.Add($_) }

        # Add any caller-supplied trusted SIDs
        foreach ($Sid in $TrustedAdminSids) {
            [void]$ExpectedSidPrefixes.Add($Sid)
        } #end foreach

        [System.Collections.Generic.HashSet[string]]$CurrentProtectedDNs =
        [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

        # Pre-compute AdminSDHolder DN once; Phase 2 reads its ACL
        [string]$AdminSDHolderDN = ('CN=AdminSDHolder,CN=System,{0}' -f $Variables.AdDN)

        # Resolve domain-local privileged group SIDs in Begin so Phase 2 can compare ACEs
        try {
            $SplatParams = @{ Identity = 'Domain Admins';    ErrorAction = 'Stop' }
            [void]$ExpectedSidPrefixes.Add((Get-ADGroup @SplatParams).SID.Value)
            $SplatParams = @{ Identity = 'Enterprise Admins'; ErrorAction = 'Stop' }
            [void]$ExpectedSidPrefixes.Add((Get-ADGroup @SplatParams).SID.Value)
        } catch {
            Write-Warning -Message 'Could not resolve Domain Admins or Enterprise Admins SID; AdminSDHolder ACL check may flag them as unexpected.'
        } #end try-catch

        Write-Verbose -Message 'AdminSDHolder anomaly detection initialized.'
    } #end begin

    process {
        try {
            # =====================================================================
            # PHASE 1: ORPHANED ADMINCOUNT — accounts with AdminCount > 0 not in
            #          any protected group
            # =====================================================================
            $SplatParams = @{
                Activity        = 'AdminSDHolder Anomaly Detection'
                Status          = 'Phase 1/3: Collecting current protected group membership'
                PercentComplete = 5
            }
            Write-Progress @SplatParams

            Write-Verbose -Message '[Phase 1] Collecting current members of all protected groups.'

            foreach ($GroupName in $ProtectedGroupNames) {
                try {
                    $SplatParams = @{ Identity = $GroupName; Recursive = $true; ErrorAction = 'Stop' }
                    $GroupMembers = Get-ADGroupMember @SplatParams
                    foreach ($Member in $GroupMembers) {
                        [void]$CurrentProtectedDNs.Add($Member.DistinguishedName)
                    } #end foreach
                } catch {
                    Write-Warning -Message ('[Phase 1] Could not enumerate members of "{0}": {1}' -f $GroupName, $_.Exception.Message)
                } #end try-catch
            } #end foreach

            Write-Verbose -Message ('[Phase 1] Total distinct members across all protected groups: {0}' -f $CurrentProtectedDNs.Count)

            $SplatParams = @{
                Activity        = 'AdminSDHolder Anomaly Detection'
                Status          = 'Phase 1/3: Querying accounts with AdminCount > 0'
                PercentComplete = 20
            }
            Write-Progress @SplatParams

            $SplatParams = @{
                Filter      = { AdminCount -gt 0 }
                Properties  = @('AdminCount', 'AdminDescription', 'DistinguishedName', 'Enabled', 'PasswordLastSet', 'WhenCreated')
                ErrorAction = 'Stop'
            }
            $AdminCountUsers = Get-ADUser @SplatParams

            foreach ($User in $AdminCountUsers) {
                if (-not $CurrentProtectedDNs.Contains($User.DistinguishedName)) {
                    $OrphanedAdminCountTotal++
                    $Findings.Add([PSCustomObject]@{
                            PSTypeName        = 'EguibarIT.AdminSDHolderAnomaly.Finding'
                            Timestamp         = $AuditTimestamp.ToString('yyyy-MM-dd HH:mm:ss')
                            Phase             = 'Phase1-OrphanedAdminCount'
                            RiskLevel         = 'High'
                            ObjectType        = 'User'
                            AccountName       = $User.SamAccountName
                            DistinguishedName = $User.DistinguishedName
                            AdminCount        = $User.AdminCount
                            Enabled           = $User.Enabled
                            PasswordLastSet   = $User.PasswordLastSet
                            WhenCreated       = $User.WhenCreated
                            AffectedSID       = $null
                            AffectedACE       = $null
                            Indicator         = (
                                'Account has AdminCount = {0} but is not a member of any protected group. SDProp continues to harden its ACL and block inheritance.' -f
                                $User.AdminCount
                            )
                            Remediation       = 'Clear AdminCount attribute, re-enable ACL inheritance, and verify no unauthorized group memberships remain.'
                        })
                } #end if
            } #end foreach

            Write-Verbose -Message ('[Phase 1] Orphaned AdminCount accounts found: {0}' -f $OrphanedAdminCountTotal)

            if ($OrphanedAdminCountTotal -gt 0) {
                $RecommendedActions.Add(
                    ('Clear AdminCount on {0} orphaned account(s) and re-enable ACL inheritance. Use: Set-ADUser -Identity <SamAccountName> -Clear AdminCount' -f $OrphanedAdminCountTotal)
                )
            } #end if

            # =====================================================================
            # PHASE 2: ADMINSDHOLDER ACL DRIFT — check the ACL on
            #          CN=AdminSDHolder,CN=System for unauthorized principals
            # =====================================================================
            $SplatParams = @{
                Activity        = 'AdminSDHolder Anomaly Detection'
                Status          = 'Phase 2/3: Auditing AdminSDHolder ACL'
                PercentComplete = 50
            }
            Write-Progress @SplatParams

            Write-Verbose -Message '[Phase 2] Reading AdminSDHolder ACL.'

            try {
                $AdminSDHolderPath = ('AD:\{0}' -f $AdminSDHolderDN)
                $AdminSDHolderAcl = Get-Acl -Path $AdminSDHolderPath -ErrorAction Stop
                $AdminSDHolderAceCount = $AdminSDHolderAcl.Access.Count

                Write-Verbose -Message ('[Phase 2] AdminSDHolder has {0} ACEs.' -f $AdminSDHolderAceCount)

                foreach ($Ace in $AdminSDHolderAcl.Access) {
                    [string]$IdentityRef = $Ace.IdentityReference.Value

                    # Resolve the identity to a SID for comparison
                    [string]$ResolvedSid = ''
                    try {
                        $NtAccount = [System.Security.Principal.NTAccount]$IdentityRef
                        $ResolvedSid = $NtAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
                    } catch {
                        # If the identity cannot be translated to a SID it is already an orphaned SID
                        $ResolvedSid = $IdentityRef
                    } #end try-catch

                    [bool]$IsTrusted = $false
                    foreach ($ExpectedSid in $ExpectedSidPrefixes) {
                        if ($ResolvedSid -eq $ExpectedSid -or $IdentityRef -like "*$ExpectedSid*") {
                            $IsTrusted = $true
                            break
                        } #end if
                    } #end foreach

                    if (-not $IsTrusted) {
                        $UnexpectedAceCount++
                        $Findings.Add([PSCustomObject]@{
                                PSTypeName        = 'EguibarIT.AdminSDHolderAnomaly.Finding'
                                Timestamp         = $AuditTimestamp.ToString('yyyy-MM-dd HH:mm:ss')
                                Phase             = 'Phase2-AdminSDHolderACL'
                                RiskLevel         = 'Critical'
                                ObjectType        = 'ACE'
                                AccountName       = $IdentityRef
                                DistinguishedName = $AdminSDHolderDN
                                AdminCount        = $null
                                Enabled           = $null
                                PasswordLastSet   = $null
                                WhenCreated       = $null
                                AffectedSID       = $ResolvedSid
                                AffectedACE       = ('{0} - {1} ({2})' -f $Ace.AccessControlType, $Ace.ActiveDirectoryRights, $Ace.InheritanceType)
                                Indicator         = (
                                    'Unexpected principal "{0}" (SID: {1}) has ACE on AdminSDHolder. SDProp will propagate this ACE to all ~100 protected AD accounts within 60 minutes.' -f
                                    $IdentityRef, $ResolvedSid
                                )
                                Remediation       = ('Remove ACE for "{0}" from AdminSDHolder unless formally approved in the delegation model.' -f $IdentityRef)
                            })
                    } #end if
                } #end foreach

                Write-Verbose -Message ('[Phase 2] Unexpected ACEs on AdminSDHolder: {0}' -f $UnexpectedAceCount)

                if ($UnexpectedAceCount -gt 0) {
                    $RecommendedActions.Add(
                        ('Remove {0} unexpected ACE(s) from CN=AdminSDHolder,CN=System. Use dsacls or Set-Acl after confirming each principal with the delegation model.' -f $UnexpectedAceCount)
                    )
                } #end if

            } catch {
                Write-Warning -Message ('[Phase 2] Could not read AdminSDHolder ACL: {0}' -f $_.Exception.Message)
            } #end try-catch

            # =====================================================================
            # PHASE 3 (OPTIONAL): UNPROTECTED PRIVILEGED ACCOUNTS — current
            #          privileged group members with AdminCount = 0
            # =====================================================================
            if ($IncludeUnprotected) {
                $SplatParams = @{
                    Activity        = 'AdminSDHolder Anomaly Detection'
                    Status          = 'Phase 3/3: Checking for unprotected privileged members'
                    PercentComplete = 80
                }
                Write-Progress @SplatParams

                Write-Verbose -Message '[Phase 3] Checking privileged group members for AdminCount = 0.'

                foreach ($Dn in $CurrentProtectedDNs) {
                    try {
                        $SplatParams = @{ Identity = $Dn; Properties = @('AdminCount', 'Enabled'); ErrorAction = 'SilentlyContinue' }
                        $PrivUser = Get-ADUser @SplatParams
                        if ($null -ne $PrivUser -and $PrivUser.AdminCount -eq 0) {
                            $UnprotectedPrivilegedTotal++
                            $Findings.Add([PSCustomObject]@{
                                    PSTypeName        = 'EguibarIT.AdminSDHolderAnomaly.Finding'
                                    Timestamp         = $AuditTimestamp.ToString('yyyy-MM-dd HH:mm:ss')
                                    Phase             = 'Phase3-UnprotectedPrivileged'
                                    RiskLevel         = 'Medium'
                                    ObjectType        = 'User'
                                    AccountName       = $PrivUser.SamAccountName
                                    DistinguishedName = $PrivUser.DistinguishedName
                                    AdminCount        = $PrivUser.AdminCount
                                    Enabled           = $PrivUser.Enabled
                                    PasswordLastSet   = $null
                                    WhenCreated       = $null
                                    AffectedSID       = $null
                                    AffectedACE       = $null
                                    Indicator         = 'Account is a member of a protected group but AdminCount = 0. SDProp has not yet hardened this account, or SDProp has been disrupted.'
                                    Remediation       = 'Verify SDProp is running correctly (check Event ID 1837 on PDC Emulator). If recently added, wait one SDProp cycle (default 60 min).'
                                })
                        } #end if
                    } catch {
                        # Skip non-user objects (computer accounts, groups) in the protected member list
                    } #end try-catch
                } #end foreach

                Write-Verbose -Message ('[Phase 3] Unprotected privileged accounts found: {0}' -f $UnprotectedPrivilegedTotal)

                if ($UnprotectedPrivilegedTotal -gt 0) {
                    $RecommendedActions.Add(
                        ('Investigate {0} privileged account(s) with AdminCount = 0. Verify SDProp is operational on the PDC Emulator.' -f $UnprotectedPrivilegedTotal)
                    )
                } #end if
            } #end if IncludeUnprotected

            # =====================================================================
            # OPTIONAL EXPORT
            # =====================================================================
            if ($PSBoundParameters.ContainsKey('OutputPath') -and $Findings.Count -gt 0) {
                if ($PSCmdlet.ShouldProcess($OutputPath, 'Export AdminSDHolder anomaly findings')) {
                    try {
                        if (-not (Test-Path -Path $OutputPath)) {
                            New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
                        } #end if

                        [string]$Stamp = $AuditTimestamp.ToString('yyyyMMdd-HHmmss')
                        [string]$CsvFile = Join-Path -Path $OutputPath -ChildPath ('AdminSDHolderAnomaly-{0}.csv' -f $Stamp)
                        [string]$JsonFile = Join-Path -Path $OutputPath -ChildPath ('AdminSDHolderAnomaly-{0}.json' -f $Stamp)

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
            Write-Error -Message ('AdminSDHolder anomaly detection failed: {0}' -f $_.Exception.Message) -ErrorAction Stop
        } #end try-catch
    } #end process

    end {
        [int]$CriticalCount = ($Findings | Where-Object { $_.RiskLevel -eq 'Critical' }).Count
        [int]$HighCount = ($Findings | Where-Object { $_.RiskLevel -eq 'High' }).Count
        [int]$MediumCount = ($Findings | Where-Object { $_.RiskLevel -eq 'Medium' }).Count
        [int]$TotalFindings = $Findings.Count

        if ($TotalFindings -eq 0) {
            $RecommendedActions.Add('No anomalies detected. Continue scheduled AdminSDHolder audits as part of regular housekeeping.')
        } #end if

        [PSCustomObject]$AuditResult = [PSCustomObject]@{
            PSTypeName                 = 'EguibarIT.AdminSDHolderAnomaly.Summary'
            AuditTimestamp             = $AuditTimestamp.ToString('yyyy-MM-dd HH:mm:ss')
            DomainName                 = $Variables.DnsFqdn
            OrphanedAdminCountTotal    = $OrphanedAdminCountTotal
            AdminSDHolderAceCount      = $AdminSDHolderAceCount
            UnexpectedAceCount         = $UnexpectedAceCount
            UnprotectedPrivilegedTotal = $UnprotectedPrivilegedTotal
            TotalFindings              = $TotalFindings
            CriticalCount              = $CriticalCount
            HighCount                  = $HighCount
            MediumCount                = $MediumCount
            IsClean                    = ($TotalFindings -eq 0)
            Findings                   = $Findings
            RecommendedActions         = $RecommendedActions
            ExportedReports            = $ExportedReports
        }

        if ($null -ne $Variables -and
            $null -ne $Variables.FooterSecurity) {
            $txt = ($Variables.FooterSecurity -f $MyInvocation.MyCommand, (Get-Date).ToString('dd/MMM/yyyy HH:mm:ss'))
            Write-Verbose -Message $txt
        } #end if

        Write-Output -InputObject $AuditResult
    } #end end

} #end Function Get-AdminSDHolderAnomaly
