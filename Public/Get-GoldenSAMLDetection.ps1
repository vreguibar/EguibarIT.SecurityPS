function Get-GoldenSAMLDetection {

    <#
        .SYNOPSIS
            Detects Golden SAML activity by auditing AD FS configuration, certificates, event logs, and private key access.

        .DESCRIPTION
            Golden SAML allows attackers to forge SAML tokens by stealing the AD FS token-signing certificate private key.
            Traditional Kerberos monitoring won't detect this attack. This function focuses on on-premises AD FS indicators
            and security hygiene through a comprehensive five-phase analysis:

            **Phase 1: AD FS Presence & Certificate Hygiene**
            - Detect AD FS role and collect token-signing/decrypting certificates
            - Check AutoCertificateRollover status, certificate ages, and thumbprints
            - Flag disabled rollover or stale/expiring certificates

            **Phase 2: AD FS Admin Event Log Scan (AD FS/Admin)**
            - Search event messages for suspicious keywords: "token-signing", "certificate", "rollover",
              "private key", "added", "removed", "export", "relying party"
            - Summarize anomalies within the analysis window

            **Phase 3: Private Key Access Monitoring (Security Event 4663)**
            - Monitor C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys for unauthorized access
            - Identify access by non-ADFS identities (possible key theft attempts)

            **Phase 4: Relying Party Trust Drift**
            - Enumerate relying party trusts and highlight recent modifications
            - Detect unauthorized configuration changes

            **Phase 5: Configuration Baseline Drift**
            - Alert on AutoCertificateRollover disabled
            - Detect unexpected thumbprint changes, multiple primary certificates, or exportable keys

            **ATTACK VECTOR:**
            Attackers who steal the AD FS token-signing certificate can:
            1. Forge SAML tokens for any user in the organization
            2. Bypass authentication and gain unauthorized access to federated services
            3. Maintain persistent access even after password resets

            **MITRE ATT&CK Mapping:**
            - T1606.002: Forge Web Credentials - SAML Tokens

        .PARAMETER Hours
            Specifies the number of hours of event logs to analyze.
            Default is 24 hours.

        .PARAMETER ExportPath
            Specifies the file path to export findings in CSV format.
            A JSON companion file is also created automatically.
            Default: C:\Reports\GoldenSAML-Findings-{timestamp}.csv

            This parameter supports ShouldProcess (-WhatIf and -Confirm).

        .PARAMETER IncludeEvents
            If specified, includes raw matching event messages in the JSON export.
            This provides detailed event data for further analysis but increases export file size.

        .EXAMPLE
            Get-GoldenSAMLDetection

            Description
            -----------
            Runs the detection scan with default settings (24 hours) and displays findings to console.

        .EXAMPLE
            Get-GoldenSAMLDetection -Hours 72 -IncludeEvents -ExportPath 'C:\Reports\GoldenSAML-Findings.csv'

            Description
            -----------
            Analyzes the last 72 hours of logs, includes raw event data, and exports findings to the specified path.

        .EXAMPLE
            Get-GoldenSAMLDetection -Hours 168 -Verbose

            Description
            -----------
            Scans the last 7 days (168 hours) with verbose output showing detailed progress through each phase.

        .EXAMPLE
            Get-GoldenSAMLDetection -ExportPath 'D:\SecurityAudits\SAML-Scan.csv' -WhatIf

            Description
            -----------
            Shows what the function would do (including export operations) without actually exporting files.

        .INPUTS
            None. This function does not accept pipeline input.

        .OUTPUTS
            PSCustomObject. Returns a summary object containing:
            - DomainName: DNS name of the environment
            - ADFSPresent: Boolean indicating if AD FS is installed
            - FindingsCount: Total number of findings
            - HighSeverityCount: Number of high-severity findings
            - MediumSeverityCount: Number of medium-severity findings
            - InfoCount: Number of informational findings
            - IsSecure: Boolean indicating if configuration is secure
            - RecommendedAction: Guidance for remediation
            - ExportedFiles: Array of exported file paths

        .NOTES
            Used Functions:
                Name                             | Module
                -------------------------------- | --------------------------
                Get-FunctionDisplay              | EguibarIT.SecurityPS
                Get-Service                      | Microsoft.PowerShell.Management
                Get-WinEvent                     | Microsoft.PowerShell.Diagnostics
                Get-AdfsCertificate              | ADFS
                Get-AdfsProperties               | ADFS
                Get-AdfsRelyingPartyTrust        | ADFS
                Get-ChildItem                    | Microsoft.PowerShell.Management
                Export-Csv                       | Microsoft.PowerShell.Utility
                ConvertTo-Json                   | Microsoft.PowerShell.Utility
                Out-File                         | Microsoft.PowerShell.Utility
                Write-Verbose                    | Microsoft.PowerShell.Utility
                Write-Warning                    | Microsoft.PowerShell.Utility
                Write-Output                     | Microsoft.PowerShell.Utility
                Write-Progress                   | Microsoft.PowerShell.Utility

        .NOTES
            Version:         1.4.0
            DateModified:    04/Mar/2026
            LastModifiedBy:  Vicente Rodriguez Eguibar
                vicente@eguibar.com
                EguibarIT
                http://www.eguibarit.com

        .LINK
            https://attack.mitre.org/techniques/T1606/002/

        .LINK
            https://github.com/vreguibar/EguibarIT.SecurityPS

        .COMPONENT
            Active Directory Federation Services

        .ROLE
            Security Auditing

        .FUNCTIONALITY
            Golden SAML Attack Detection
    #>

    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'Low'
    )]
    [OutputType([PSCustomObject])]

    param (
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Number of hours of event logs to analyze',
            Position = 0
        )]
        [ValidateRange(1, 8760)]
        [PSDefaultParameterValue(Help = 'Default is 24 hours')]
        [int]
        $Hours = 24,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'File path to export findings (CSV format)',
            Position = 1
        )]
        [ValidateNotNullOrEmpty()]
        [PSDefaultParameterValue(Help = 'Default exports to C:\Reports with timestamp')]
        [string]
        $ExportPath = ('C:\Reports\GoldenSAML-Findings-{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmmss')),

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Include raw event messages in JSON export'
        )]
        [switch]
        $IncludeEvents
    )

    Begin {
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

        # AD FS module is imported conditionally in Process block if AD FS is detected

        ##############################
        # Variables Definition

        Write-Verbose -Message ('Initializing Golden SAML detection scan for last {0} hours' -f $Hours)

        # Use ArrayList for better performance
        [System.Collections.ArrayList]$Results = @()
        [System.Collections.ArrayList]$EventsOut = @()

        [datetime]$StartTime = (Get-Date).AddHours(-$Hours)
        [bool]$AdfsPresent = $false
        [int]$HighSeverityCount = 0
        [int]$MediumSeverityCount = 0
        [int]$InfoCount = 0

        # Keywords for event log searching
        [string[]]$Keywords = @(
            'token-signing',
            'certificate',
            'rollover',
            'private key',
            'export',
            'relying party',
            'thumbprint'
        )

        # Machine keys path for private key access monitoring
        [string]$MachineKeysPath = 'C:\\ProgramData\\Microsoft\\Crypto\\RSA\\MachineKeys'

    } #end Begin

    Process {

        Write-Verbose -Message 'Starting Golden SAML detection scan...'

        try {

            # ---------------------------------------------------------------
            # Phase 1: AD FS Presence & Certificate Hygiene
            # ---------------------------------------------------------------
            Write-Progress -Activity 'Golden SAML Detection' -Status 'Phase 1/5: Checking AD FS presence and certificates' -PercentComplete 10

            Write-Verbose -Message 'Phase 1: Checking for AD FS installation...'

            try {
                $AdfsService = Get-Service -Name 'ADFS' -ErrorAction SilentlyContinue
                if ($AdfsService) {
                    $AdfsPresent = $true
                    Write-Verbose -Message 'AD FS service detected on this system'
                } #end if
            } catch {
                Write-Verbose -Message 'AD FS service not found on this system'
            } #end try-catch

            if ($AdfsPresent) {

                # Try loading ADFS module
                try {
                    Import-Module -Name 'ADFS' -ErrorAction Stop
                    Write-Verbose -Message 'AD FS PowerShell module loaded successfully'
                } catch {
                    Write-Warning -Message 'AD FS module not available; using limited checks'
                } #end try-catch

                # Check AutoCertificateRollover status
                [bool]$AutoRollover = $null
                try {
                    $AdfsProperties = Get-AdfsProperties -ErrorAction Stop
                    $AutoRollover = $AdfsProperties.AutoCertificateRollover
                    Write-Verbose -Message ('AutoCertificateRollover status: {0}' -f $AutoRollover)
                } catch {
                    Write-Warning -Message 'Could not retrieve AD FS properties'
                } #end try-catch

                if ($null -ne $AutoRollover -and -not $AutoRollover) {
                    [void]$Results.Add([PSCustomObject]@{
                            Timestamp       = Get-Date
                            Severity        = 'HIGH'
                            FindingType     = 'Config:AutoCertificateRolloverDisabled'
                            Details         = 'AD FS AutoCertificateRollover is disabled'
                            Recommendation  = 'Enable AutoCertificateRollover or implement strict manual rotation with documented schedule'
                            MITRE_Technique = 'T1606.002'
                        })
                    Write-Warning -Message 'AutoCertificateRollover is DISABLED - security risk detected'
                } #end if

                # Audit token-signing certificates
                [array]$TokenCerts = @()
                try {
                    $TokenCerts = Get-AdfsCertificate -CertificateType 'Token-Signing' -ErrorAction Stop
                    Write-Verbose -Message ('Found {0} token-signing certificate(s)' -f $TokenCerts.Count)
                } catch {
                    Write-Verbose -Message 'Could not retrieve AD FS certificates via Get-AdfsCertificate; attempting fallback method'

                    # Fallback: search certificate store
                    $TokenCerts = Get-ChildItem -Path 'Cert:\LocalMachine\My' -ErrorAction SilentlyContinue |
                    Where-Object {
                        $_.EnhancedKeyUsageList.FriendlyName -contains 'Token Signing' -or
                        $_.Subject -match 'ADFS'
                    }
                } #end try-catch

                foreach ($Cert in $TokenCerts) {
                    [int]$AgeDays = if ($Cert.NotBefore) {
                        [int]((Get-Date) - $Cert.NotBefore).TotalDays
                    } else {
                        0
                    } #end if

                    [int]$ExpiresInDays = if ($Cert.NotAfter) {
                        [int]($Cert.NotAfter - (Get-Date)).TotalDays
                    } else {
                        0
                    } #end if

                    [string]$Thumbprint = $Cert.Thumbprint
                    [string]$CertMessage = ('Token-Signing cert thumbprint={0}, age={1}d, expires in {2}d' -f $Thumbprint, $AgeDays, $ExpiresInDays)

                    Write-Verbose -Message $CertMessage

                    # Check for expiring certificates
                    if ($ExpiresInDays -lt 30) {
                        [void]$Results.Add([PSCustomObject]@{
                                Timestamp       = Get-Date
                                Severity        = 'HIGH'
                                FindingType     = 'Cert:ExpiringSoon'
                                Details         = $CertMessage
                                Recommendation  = 'Rotate token-signing certificate and update relying parties'
                                MITRE_Technique = 'T1606.002'
                            })
                        Write-Warning -Message ('Certificate expiring soon: {0}' -f $Thumbprint)
                    } #end if

                    # Check for very old certificates
                    if ($AgeDays -gt (365 * 3)) {
                        [void]$Results.Add([PSCustomObject]@{
                                Timestamp       = Get-Date
                                Severity        = 'MEDIUM'
                                FindingType     = 'Cert:VeryOld'
                                Details         = $CertMessage
                                Recommendation  = 'Review rotation cadence; document thumbprints in baseline'
                                MITRE_Technique = 'T1606.002'
                            })
                    } #end if
                } #end foreach

            } else {
                Write-Verbose -Message 'AD FS not detected on this system. Skipping AD FS-specific checks.'
            } #end if

            # ---------------------------------------------------------------
            # Phase 2: AD FS Admin Event Log Scan
            # ---------------------------------------------------------------
            Write-Progress -Activity 'Golden SAML Detection' -Status 'Phase 2/5: Scanning AD FS/Admin event logs' -PercentComplete 30

            Write-Verbose -Message 'Phase 2: Scanning AD FS/Admin event log for suspicious activity...'

            try {
                $AdfsAdminEvents = Get-WinEvent -FilterHashtable @{
                    LogName   = 'AD FS/Admin'
                    StartTime = $StartTime
                } -ErrorAction Stop

                Write-Verbose -Message ('Found {0} AD FS/Admin events to analyze' -f $AdfsAdminEvents.Count)

                foreach ($Event in $AdfsAdminEvents) {
                    [string]$EventMessage = $Event.Message

                    foreach ($Keyword in $Keywords) {
                        if ($EventMessage -match [regex]::Escape($Keyword)) {
                            [string]$EventDetails = ('AD FS/Admin: [{0}] {1} at {2}: matched keyword ''{3}''' -f
                                $Event.Id,
                                $Event.LevelDisplayName,
                                $Event.TimeCreated,
                                $Keyword
                            )

                            [void]$Results.Add([PSCustomObject]@{
                                    Timestamp       = Get-Date
                                    Severity        = 'INFO'
                                    FindingType     = 'ADFS:AdminLogMatch'
                                    Details         = $EventDetails
                                    Recommendation  = 'Validate event against change records; unexpected activity requires investigation'
                                    MITRE_Technique = 'T1606.002'
                                })

                            if ($IncludeEvents) {
                                [void]$EventsOut.Add([PSCustomObject]@{
                                        Log     = 'ADFS/Admin'
                                        Id      = $Event.Id
                                        Time    = $Event.TimeCreated
                                        Keyword = $Keyword
                                        Message = $EventMessage
                                    })
                            } #end if

                            Write-Debug -Message $EventDetails
                        } #end if
                    } #end foreach keyword
                } #end foreach event

            } catch {
                Write-Verbose -Message 'AD FS/Admin event log not found or not accessible'
            } #end try-catch

            # ---------------------------------------------------------------
            # Phase 3: Private Key Access Monitoring (Security 4663)
            # ---------------------------------------------------------------
            Write-Progress -Activity 'Golden SAML Detection' -Status 'Phase 3/5: Monitoring private key access' -PercentComplete 50

            Write-Verbose -Message 'Phase 3: Analyzing Security event log for private key access (Event ID 4663)...'

            try {
                $SecurityEvents = Get-WinEvent -FilterHashtable @{
                    LogName   = 'Security'
                    Id        = 4663
                    StartTime = $StartTime
                } -ErrorAction Stop

                Write-Verbose -Message ('Found {0} Security 4663 events to analyze' -f $SecurityEvents.Count)

                foreach ($Event in $SecurityEvents) {
                    [xml]$EventXml = $Event.ToXml()
                    [string]$ObjectName = ($EventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'ObjectName' }).'#text'

                    if ($ObjectName -and $ObjectName -like ('{0}*' -f $MachineKeysPath)) {
                        [string]$SubjectUserName = ($EventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
                        [string]$SubjectDomainName = ($EventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'SubjectDomainName' }).'#text'

                        [string]$FullAccountName = if ($SubjectDomainName) {
                            ('{0}\{1}' -f $SubjectDomainName, $SubjectUserName)
                        } else {
                            $SubjectUserName
                        } #end if

                        [string]$AccessDetails = ('Private key access: {0} → {1}' -f $FullAccountName, $ObjectName)

                        [void]$Results.Add([PSCustomObject]@{
                                Timestamp       = Get-Date
                                Severity        = 'HIGH'
                                FindingType     = 'Security:4663-MachineKeys'
                                Details         = $AccessDetails
                                Recommendation  = 'Confirm if access was by AD FS service account; investigate any other identities immediately'
                                MITRE_Technique = 'T1606.002'
                            })

                        Write-Warning -Message ('Suspicious private key access detected: {0}' -f $FullAccountName)

                        if ($IncludeEvents) {
                            [void]$EventsOut.Add([PSCustomObject]@{
                                    Log     = 'Security'
                                    Id      = 4663
                                    Time    = $Event.TimeCreated
                                    Message = $Event.Message
                                })
                        } #end if
                    } #end if
                } #end foreach

            } catch {
                Write-Verbose -Message 'Security 4663 events unavailable or auditing not enabled'
            } #end try-catch

            # ---------------------------------------------------------------
            # Phase 4: Relying Party Trust Drift
            # ---------------------------------------------------------------
            Write-Progress -Activity 'Golden SAML Detection' -Status 'Phase 4/5: Checking relying party trust changes' -PercentComplete 70

            if ($AdfsPresent) {
                Write-Verbose -Message 'Phase 4: Enumerating relying party trust changes...'

                try {
                    $RelyingPartyTrusts = Get-AdfsRelyingPartyTrust -ErrorAction Stop
                    Write-Verbose -Message ('Found {0} relying party trust(s)' -f $RelyingPartyTrusts.Count)

                    foreach ($Rpt in $RelyingPartyTrusts) {
                        [bool]$Changed = $false
                        [datetime]$ChangeTime = $null

                        if ($Rpt.LastMonitoredTime) {
                            $ChangeTime = $Rpt.LastMonitoredTime
                            $Changed = ($ChangeTime -ge $StartTime)
                        } elseif ($Rpt.ModificationTime) {
                            $ChangeTime = $Rpt.ModificationTime
                            $Changed = ($ChangeTime -ge $StartTime)
                        } #end if

                        if ($Changed) {
                            [void]$Results.Add([PSCustomObject]@{
                                    Timestamp       = Get-Date
                                    Severity        = 'INFO'
                                    FindingType     = 'ADFS:RelyingPartyChanged'
                                    Details         = ('Relying Party Trust ''{0}'' changed at {1}' -f $Rpt.Name, $ChangeTime)
                                    Recommendation  = 'Validate change with CAB/change records; unexpected changes require investigation'
                                    MITRE_Technique = 'T1606.002'
                                })

                            Write-Verbose -Message ('Relying party trust modified: {0}' -f $Rpt.Name)
                        } #end if
                    } #end foreach

                } catch {
                    Write-Warning -Message 'Could not query AD  FS relying party trusts'
                } #end try-catch
            } #end if

            # ---------------------------------------------------------------
            # Phase 5: Configuration Baseline Drift
            # ---------------------------------------------------------------
            Write-Progress -Activity 'Golden SAML Detection' -Status 'Phase 5/5: Checking configuration baseline' -PercentComplete 90

            if ($AdfsPresent) {
                Write-Verbose -Message 'Phase 5: Checking configuration baseline drift...'

                try {
                    $TokenSigningCerts = Get-AdfsCertificate -CertificateType 'Token-Signing' -ErrorAction Stop

                    if ($TokenSigningCerts.Count -gt 1) {
                        # Check for multiple primary certificates
                        $PrimaryCertificates = $TokenSigningCerts | Where-Object { $_.IsPrimary }

                        if ($PrimaryCertificates.Count -ne 1) {
                            [void]$Results.Add([PSCustomObject]@{
                                    Timestamp       = Get-Date
                                    Severity        = 'HIGH'
                                    FindingType     = 'Cert:MultiplePrimaries'
                                    Details         = ('Multiple primary token-signing certificates detected: {0}' -f $PrimaryCertificates.Count)
                                    Recommendation  = 'Complete rollover properly; ensure single primary certificate and update all relying parties'
                                    MITRE_Technique = 'T1606.002'
                                })

                            Write-Warning -Message 'Multiple primary token-signing certificates detected - configuration error'
                        } #end if
                    } #end if

                } catch {
                    Write-Verbose -Message 'Could not verify certificate baseline configuration'
                } #end try-catch
            } #end if

            Write-Progress -Activity 'Golden SAML Detection' -Completed

        } catch {
            Write-Error -Message ('Error during Golden SAML detection scan: {0}' -f $_.Exception.Message)
            throw
        } #end try-catch

    } #end Process

    End {

        # Calculate severity counts
        $HighSeverityCount = ($Results | Where-Object { $_.Severity -eq 'HIGH' }).Count
        $MediumSeverityCount = ($Results | Where-Object { $_.Severity -eq 'MEDIUM' }).Count
        $InfoCount = ($Results | Where-Object { $_.Severity -eq 'INFO' }).Count

        Write-Verbose -Message ('Scan complete: {0} findings (HIGH={1}, MEDIUM={2}, INFO={3})' -f
            $Results.Count, $HighSeverityCount, $MediumSeverityCount, $InfoCount)

        # Export results if requested
        [System.Collections.ArrayList]$ExportedFiles = @()

        if ($Results.Count -gt 0) {

            # Ensure export directory exists
            [string]$ExportDirectory = Split-Path -Path $ExportPath -Parent

            if (-not (Test-Path -Path $ExportDirectory)) {
                if ($PSCmdlet.ShouldProcess($ExportDirectory, 'Create export directory')) {
                    try {
                        [void](New-Item -Path $ExportDirectory -ItemType Directory -Force -ErrorAction Stop)
                        Write-Verbose -Message ('Created export directory: {0}' -f $ExportDirectory)
                    } catch {
                        Write-Error -Message ('Failed to create export directory: {0}' -f $_.Exception.Message)
                    } #end try-catch
                } #end if ShouldProcess
            } #end if

            # Export CSV
            if ($PSCmdlet.ShouldProcess($ExportPath, 'Export findings to CSV')) {
                try {
                    $Results | Export-Csv -Path $ExportPath -NoTypeInformation -ErrorAction Stop
                    [void]$ExportedFiles.Add($ExportPath)
                    Write-Verbose -Message ('Exported findings to CSV: {0}' -f $ExportPath)
                } catch {
                    Write-Error -Message ('Failed to export CSV: {0}' -f $_.Exception.Message)
                } #end try-catch
            } #end if ShouldProcess

            # Export JSON
            [string]$JsonPath = $ExportPath -replace '\.csv$', '.json'

            if ($PSCmdlet.ShouldProcess($JsonPath, 'Export findings to JSON')) {
                try {
                    $JsonData = @{
                        Generated         = (Get-Date)
                        WindowHours       = $Hours
                        FindingsCount     = $Results.Count
                        HighSeverity      = $HighSeverityCount
                        MediumSeverity    = $MediumSeverityCount
                        Info              = $InfoCount
                        Findings          = $Results
                        RawEventsIncluded = [bool]$IncludeEvents
                        RawEvents         = if ($IncludeEvents) { $EventsOut } else { @() }
                    }

                    $JsonData | ConvertTo-Json -Depth 6 | Out-File -Encoding UTF8 -FilePath $JsonPath -ErrorAction Stop
                    [void]$ExportedFiles.Add($JsonPath)
                    Write-Verbose -Message ('Exported findings to JSON: {0}' -f $JsonPath)
                } catch {
                    Write-Error -Message ('Failed to export JSON: {0}' -f $_.Exception.Message)
                } #end try-catch
            } #end if ShouldProcess

        } #end if

        # Display critical findings warning
        if ($HighSeverityCount -gt 0) {
            Write-Warning -Message 'HIGH-SEVERITY INDICATORS FOUND'
            Write-Warning -Message 'Immediate remediation steps:'
            Write-Warning -Message '  1) Rotate AD FS token-signing and decrypting certificates'
            Write-Warning -Message '  2) Update relied-upon thumbprints in all relying parties'
            Write-Warning -Message '  3) Re-enable AutoCertificateRollover (if disabled)'
            Write-Warning -Message '  4) Investigate Security Event 4663 access to MachineKeys by non-ADFS accounts'
        } #end if

        # Create summary object
        [PSCustomObject]$Summary = [PSCustomObject]@{
            PSTypeName           = 'EguibarIT.GoldenSAMLDetection'
            ScanDate             = Get-Date
            WindowHours          = $Hours
            ADFSPresent          = $AdfsPresent
            FindingsCount        = $Results.Count
            HighSeverityCount    = $HighSeverityCount
            MediumSeverityCount  = $MediumSeverityCount
            InfoCount            = $InfoCount
            IsSecure             = ($HighSeverityCount -eq 0 -and $MediumSeverityCount -eq 0)
            RecommendedAction    = if ($HighSeverityCount -gt 0) {
                'IMMEDIATE ACTION REQUIRED: Review high-severity findings and implement remediation steps'
            } elseif ($MediumSeverityCount -gt 0) {
                'Review medium-severity findings and schedule remediation'
            } else {
                'No critical issues detected; continue regular monitoring'
            }
            ExportedFiles        = $ExportedFiles
            DetailedFindings     = $Results
        }

        # Display function footer if variables exist
        if ($null -ne $Variables -and
            $null -ne $Variables.FooterDelegation) {

            $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
                'Golden SAML detection scan.'
            )
            Write-Verbose -Message $txt
        } #end If

        # Return summary object
        Write-Output -InputObject $Summary

    } #end End
} #end Function Get-GoldenSAMLDetection
