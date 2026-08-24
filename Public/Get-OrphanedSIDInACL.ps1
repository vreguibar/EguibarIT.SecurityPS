function Get-OrphanedSIDInACL {
    <#
        .SYNOPSIS
            Scans Active Directory object ACLs for orphaned SIDs that no longer resolve to a valid security principal.

        .DESCRIPTION
            Performs a two-phase scan of Active Directory object discretionary access control lists (DACLs)
            to identify access control entries (ACEs) whose security principal (user, group, computer) has
            been deleted from AD but whose SID remains in the ACL:

            **Phase 1 - OBJECT ENUMERATION:**
            Enumerates the target scope:
            - By default, scans all Organizational Units (OUs) and the domain root.
            - When -ScanAllObjects is specified, extends the scan to all AD objects with a non-null nTSecurityDescriptor
              (groups, computers, users, containers, etc.).
            - When -SearchBase is provided, limits the scan to that subtree.

            **Phase 2 - ACL ANALYSIS:**
            For each object, retrieves its DACL via Get-Acl on the AD: PSDrive. For each ACE, attempts
            to translate the IdentityReference to a valid NTAccount. If translation fails and the reference
            is a raw SID string (S-1-5-21-...), the ACE is an orphan: the account was deleted without
            cleaning up the permission.

            **SECURITY IMPACT:**
            - Orphaned SIDs cannot be used by living principals, so they cannot directly grant access.
            - However, if a new object is created that inadvertently receives the same RID (rare but possible
              in domains that have had RID pool issues or been restored from old backups), it may inherit
              the orphaned permissions.
            - More commonly, orphaned SIDs obscure the real ACL, prevent clean ACL audits, and may indicate
              an attacker deleted an account after using it (covering tracks while leaving a backdoor SID
              if they controlled the RID).
            - Large numbers of orphaned SIDs indicate poor lifecycle management.

            **MITRE ATT&CK Mapping:**
            - **T1098**: Account Manipulation (cleanup indicator)
            - **T1070**: Indicator Removal

            **DETECTION REQUIREMENTS:**
            - Read access to AD object security descriptors (Domain Users have this by default)
            - ActiveDirectory PowerShell module
            - AD: PSDrive available (loaded with ActiveDirectory module)

        .PARAMETER SearchBase
            Distinguished Name of the AD container to limit the scan to. Defaults to the domain root,
            scanning all OUs domain-wide.

        .PARAMETER ScanAllObjects
            If specified, scans ACLs on all AD objects (users, groups, computers, containers, OUs).
            By default, only OUs and the domain root are scanned, which is faster and covers most
            privileged delegation paths. Warning: full object scans in large domains can take significant time.

        .PARAMETER OutputPath
            Directory where detection results are exported in CSV and JSON format.
            Export respects -WhatIf and -Confirm.

        .EXAMPLE
            Get-OrphanedSIDInACL

            Description
            -----------
            Scans all OU ACLs domain-wide for orphaned SIDs.

        .EXAMPLE
            Get-OrphanedSIDInACL -SearchBase 'OU=Admin,DC=EguibarIT,DC=local' -Verbose

            Description
            -----------
            Limits the scan to the Admin OU subtree with verbose output.

        .EXAMPLE
            Get-OrphanedSIDInACL -ScanAllObjects -OutputPath 'C:\SecurityAudits'

            Description
            -----------
            Full domain object scan with results exported to CSV and JSON.

        .EXAMPLE
            $Result = Get-OrphanedSIDInACL
            $Result.Findings | Select-Object ObjectDN, OrphanedSID, AccessRight | Format-Table -AutoSize

            Description
            -----------
            Tabulates orphaned SID findings for review.

        .INPUTS
            None. This function does not accept pipeline input.

        .OUTPUTS
            PSCustomObject. Returns an audit summary with the following properties:
            - AuditTimestamp: When the audit ran
            - DomainName: DNS name of the audited domain
            - ObjectsScanned: Total number of objects whose ACLs were checked
            - OrphanedSIDTotal: Total number of orphaned SID ACEs found
            - AffectedObjectCount: Number of distinct objects with at least one orphaned SID
            - TotalFindings: Same as OrphanedSIDTotal
            - IsClean: $true when OrphanedSIDTotal = 0
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
                Get-ADOrganizationalUnit               | ActiveDirectory
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
            https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-descriptors

        .LINK
            https://github.com/vreguibar/EguibarIT.SecurityPS

        .COMPONENT
            EguibarIT.SecurityPS

        .ROLE
            Security Auditing

        .FUNCTIONALITY
            Scans Active Directory object ACLs for orphaned SIDs to detect access control hygiene issues
            and potential post-compromise indicator removal.
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
            HelpMessage = 'Distinguished Name of the AD container to scope the scan (default: domain root)',
            Position = 0
        )]
        [ValidateNotNullOrEmpty()]
        [Alias('Base', 'OU')]
        [PSDefaultValue(
            Help = 'Default: domain root DistinguishedName',
            Value = 'Domain root'
        )]
        [string]
        $SearchBase,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Scan all AD objects (not just OUs). Slower in large domains.',
            Position = 1
        )]
        [PSDefaultValue(
            Help = 'Default: $false (OU-only scan)',
            Value = $false
        )]
        [switch]
        $ScanAllObjects,

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
            Help = 'Default: Desktop\OrphanedSIDScan',
            Value = 'Desktop\OrphanedSIDScan'
        )]
        [string]
        $OutputPath = (Join-Path -Path $env:USERPROFILE -ChildPath 'Desktop\OrphanedSIDScan')
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

        [datetime]$AuditTimestamp = Get-Date

        [System.Collections.Generic.List[PSCustomObject]]$Findings =
        [System.Collections.Generic.List[PSCustomObject]]::new()

        [System.Collections.Generic.List[string]]$RecommendedActions =
        [System.Collections.Generic.List[string]]::new()

        [System.Collections.Generic.List[string]]$ExportedReports =
        [System.Collections.Generic.List[string]]::new()

        [int]$ObjectsScanned    = 0
        [int]$OrphanedSIDTotal  = 0

        # Track distinct objects with at least one orphan
        [System.Collections.Generic.HashSet[string]]$AffectedObjects =
        [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

        $SplatParams = $null

        [int]$TotalObjects = 0
        [int]$Index        = 0

        [System.Collections.Generic.List[string]]$ObjectDNList =
        [System.Collections.Generic.List[string]]::new()

        # Init to domain root; overridden in Process when -SearchBase is supplied
        [string]$EffectiveBase = $Variables.AdDN

        # $Constants.SidRegEx (compiled at module load) matches raw unresolved SID strings

        Write-Verbose -Message 'Orphaned SID ACL scanner initialized.'
    } #end begin

    process {
        try {
            # Override EffectiveBase when caller provides -SearchBase
            if ($PSBoundParameters.ContainsKey('SearchBase')) {
                $EffectiveBase = $SearchBase
            } #end if

            Write-Verbose -Message ('Effective search base: {0}' -f $EffectiveBase)

            # =====================================================================
            # PHASE 1 — ENUMERATE TARGET OBJECTS
            # =====================================================================
            $SplatParams = @{
                Activity        = 'Orphaned SID ACL Scan'
                Status          = 'Phase 1/2: Enumerating target AD objects'
                PercentComplete = 5
            }
            Write-Progress @SplatParams

            Write-Verbose -Message ('[Phase 1] Enumerating objects. ScanAllObjects = {0}' -f $ScanAllObjects)

            $ObjectDNList.Clear()

            # Always include the search base itself
            $ObjectDNList.Add($EffectiveBase)

            if ($ScanAllObjects) {
                $SplatParams = @{
                    SearchBase  = $EffectiveBase
                    Filter      = '*'
                    Properties  = @('DistinguishedName')
                    ErrorAction = 'Stop'
                }
                $AdObjects = Get-ADObject @SplatParams

                foreach ($Obj in $AdObjects) {
                    $ObjectDNList.Add($Obj.DistinguishedName)
                } #end foreach
            } else {
                # Default: OUs only — they hold the most sensitive delegation ACEs
                $SplatParams = @{
                    SearchBase  = $EffectiveBase
                    Filter      = '*'
                    Properties  = @('DistinguishedName')
                    ErrorAction = 'Stop'
                }
                $OUs = Get-ADOrganizationalUnit @SplatParams

                foreach ($OU in $OUs) {
                    $ObjectDNList.Add($OU.DistinguishedName)
                } #end foreach
            } #end if ScanAllObjects

            Write-Verbose -Message ('[Phase 1] Objects to scan: {0}' -f $ObjectDNList.Count)

            # =====================================================================
            # PHASE 2 — ACL ANALYSIS
            # =====================================================================
            Write-Verbose -Message '[Phase 2] Scanning object ACLs for orphaned SIDs.'

            [int]$TotalObjects = $ObjectDNList.Count

            foreach ($ObjectDN in $ObjectDNList) {
                $Index++

                if ($Index % 50 -eq 0 -or $Index -eq $TotalObjects) {
                    $SplatParams = @{
                        Activity        = 'Orphaned SID ACL Scan'
                        Status          = ('Phase 2/2: Scanning ACLs [{0}/{1}] {2}' -f $Index, $TotalObjects, $ObjectDN)
                        PercentComplete = ([Math]::Round(($Index / $TotalObjects) * 95 + 5))
                    }
                    Write-Progress @SplatParams
                } #end if progress throttle

                try {
                    [string]$AdPath = ('AD:\{0}' -f $ObjectDN)
                    $Acl = Get-Acl -Path $AdPath -ErrorAction Stop
                    $ObjectsScanned++

                    foreach ($Ace in $Acl.Access) {
                        [string]$IdentityRef = $Ace.IdentityReference.Value

                        # A raw SID string in IdentityReference means Windows could not resolve it
                        if ($Constants.SidRegEx.IsMatch($IdentityRef)) {
                            $OrphanedSIDTotal++
                            [void]$AffectedObjects.Add($ObjectDN)

                            $Findings.Add([PSCustomObject]@{
                                    PSTypeName        = 'EguibarIT.OrphanedSIDInACL.Finding'
                                    Timestamp         = $AuditTimestamp.ToString('yyyy-MM-dd HH:mm:ss')
                                    RiskLevel         = 'Medium'
                                    ObjectDN          = $ObjectDN
                                    OrphanedSID       = $IdentityRef
                                    AccessControlType = $Ace.AccessControlType.ToString()
                                    AccessRight       = $Ace.ActiveDirectoryRights.ToString()
                                    InheritanceType   = $Ace.InheritanceType.ToString()
                                    IsInherited       = $Ace.IsInherited
                                    Indicator         = (
                                        'Object "{0}" has an ACE for SID "{1}" which cannot be resolved to a security principal. The account was deleted without cleaning the ACL.' -f
                                        $ObjectDN, $IdentityRef
                                    )
                                    Remediation       = (
                                        'Remove the orphaned ACE. Use: $Acl = Get-Acl "AD:\{0}"; $OldAce = $Acl.Access | Where-Object IdentityReference -eq "{1}"; $Acl.RemoveAccessRule($OldAce); Set-Acl "AD:\{0}" $Acl' -f
                                        $ObjectDN, $IdentityRef
                                    )
                                })
                        } #end if SID pattern
                    } #end foreach Ace
                } catch {
                    Write-Warning -Message ('[Phase 2] Could not read ACL for "{0}": {1}' -f $ObjectDN, $_.Exception.Message)
                } #end try-catch
            } #end foreach ObjectDN

            Write-Verbose -Message ('[Phase 2] Objects scanned: {0}. Orphaned SIDs found: {1}. Affected objects: {2}' -f $ObjectsScanned, $OrphanedSIDTotal, $AffectedObjects.Count)

            if ($OrphanedSIDTotal -gt 0) {
                $RecommendedActions.Add(
                    ('Remove {0} orphaned SID ACE(s) across {1} object(s). Use dsacls or PowerShell Set-Acl to clean each affected object. Prioritize OUs used for privileged delegation.' -f
                    $OrphanedSIDTotal, $AffectedObjects.Count)
                )
                $RecommendedActions.Add(
                    'Review lifecycle management process: orphaned SIDs indicate accounts were deleted without running an AD cleanup procedure. Implement pre-deletion ACL sweep.'
                )
            } #end if

            # =====================================================================
            # OPTIONAL EXPORT
            # =====================================================================
            if ($PSBoundParameters.ContainsKey('OutputPath') -and $Findings.Count -gt 0) {
                if ($PSCmdlet.ShouldProcess($OutputPath, 'Export orphaned SID findings')) {
                    try {
                        if (-not (Test-Path -Path $OutputPath)) {
                            New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
                        } #end if

                        [string]$Stamp = $AuditTimestamp.ToString('yyyyMMdd-HHmmss')
                        [string]$CsvFile = Join-Path -Path $OutputPath -ChildPath ('OrphanedSIDInACL-{0}.csv' -f $Stamp)
                        [string]$JsonFile = Join-Path -Path $OutputPath -ChildPath ('OrphanedSIDInACL-{0}.json' -f $Stamp)

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
            Write-Error -Message ('Orphaned SID ACL scan failed: {0}' -f $_.Exception.Message) -ErrorAction Stop
        } #end try-catch
    } #end process

    end {
        [int]$TotalFindings = $Findings.Count

        if ($TotalFindings -eq 0) {
            $RecommendedActions.Add('No orphaned SIDs found in scanned ACLs. Continue scheduled ACL hygiene audits.')
        } #end if

        [PSCustomObject]$AuditResult = [PSCustomObject]@{
            PSTypeName          = 'EguibarIT.OrphanedSIDInACL.Summary'
            AuditTimestamp      = $AuditTimestamp.ToString('yyyy-MM-dd HH:mm:ss')
            DomainName          = $Variables.DnsFqdn
            SearchBase          = $EffectiveBase
            ObjectsScanned      = $ObjectsScanned
            OrphanedSIDTotal    = $OrphanedSIDTotal
            AffectedObjectCount = $AffectedObjects.Count
            TotalFindings       = $TotalFindings
            IsClean             = ($TotalFindings -eq 0)
            Findings            = $Findings
            RecommendedActions  = $RecommendedActions
            ExportedReports     = $ExportedReports
        }

        if ($null -ne $Variables -and $null -ne $Variables.FooterSecurity) {
            $txt = ($Variables.FooterSecurity -f $MyInvocation.MyCommand, (Get-Date).ToString('dd/MMM/yyyy HH:mm:ss'))
            Write-Verbose -Message $txt
        } #end if

        Write-Output -InputObject $AuditResult
    } #end end

} #end Function Get-OrphanedSIDInACL
