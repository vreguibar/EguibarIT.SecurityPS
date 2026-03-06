Function Get-NTDSDitExtraction {
    <#
        .SYNOPSIS
            Detects NTDS.dit extraction attempts on domain controllers through file access monitoring, process analysis, and event correlation.

        .DESCRIPTION
            NTDS.dit contains ALL domain credentials (password hashes, Kerberos keys). This function detects extraction attempts via:
            - Volume Shadow Copy (VSS) creation and NTDS.dit access
            - NTDSUtil IFM (Install From Media) backup operations
            - ESentUtl.exe database copy operations
            - Event 4663 (file access auditing for ntds.dit)
            - Sysmon Event 11 (file creation of ntds.dit copies)

            The function performs comprehensive five-phase detection:
            1. Volume Shadow Copy (VSS) activity monitoring
            2. NTDS extraction tool execution detection
            3. Event 4663 (NTDS.dit file access) analysis
            4. Event 2004 (NTDSUtil IFM backup) detection
            5. Sysmon Event 11 (ntds.dit file creation) monitoring

        .PARAMETER DomainController
            Target domain controller(s) to analyze for NTDS.dit extraction indicators.
            Accepts pipeline input from Get-ADDomainController.

        .PARAMETER DaysBack
            Number of days to analyze event logs for NTDS.dit extraction indicators.
            Default: 30 days.
            Range: 1 to 365 days.

        .PARAMETER ExportPath
            Directory where detection results will be saved (CSV and JSON formats).
            Default: $env:USERPROFILE\Desktop\NTDSExtractionAudit

        .PARAMETER CheckAllDCs
            Switch to scan all domain controllers for NTDS.dit extraction indicators.
            Default: Current DC only.

        .EXAMPLE
            Get-NTDSDitExtraction
            Performs NTDS.dit extraction detection on the current domain controller for the last 30 days.

        .EXAMPLE
            Get-NTDSDitExtraction -CheckAllDCs -DaysBack 90 -Verbose
            Comprehensive NTDS.dit extraction detection across all domain controllers for the last 90 days.

        .EXAMPLE
            Get-ADDomainController -Filter * | Get-NTDSDitExtraction -ExportPath 'C:\SecurityAudits'
            Pipeline all domain controllers for NTDS.dit extraction analysis.

        .EXAMPLE
            Get-NTDSDitExtraction -DomainController 'DC01' -DaysBack 7
            Analyzes specific domain controller for NTDS.dit extraction attempts in the last 7 days.

        .INPUTS
            System.String
            Microsoft.ActiveDirectory.Management.ADDomainController

        .OUTPUTS
            PSCustomObject

        .NOTES
            Used Functions:
                Name                                    ║ Module/Namespace
                ════════════════════════════════════════╬══════════════════════════════
                Get-ADDomainController                  ║ ActiveDirectory
                Get-WinEvent                            ║ Microsoft.PowerShell.Diagnostics
                Get-Service                             ║ Microsoft.PowerShell.Management
                Invoke-Command                          ║ Microsoft.PowerShell.Core
                Write-Verbose                           ║ Microsoft.PowerShell.Utility
                Write-Warning                           ║ Microsoft.PowerShell.Utility
                Write-Debug                             ║ Microsoft.PowerShell.Utility
                Get-FunctionDisplay                     ║ EguibarIT.SecurityPS

        .NOTES
            Version:        1.0
            DateModified:   06/Mar/2026
            LastModifiedBy: Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar IT
                http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT.SecurityPS

        .COMPONENT
            Security Auditing

        .ROLE
            Threat Detection

        .FUNCTIONALITY
            NTDS.dit Extraction Detection
    #>

    [CmdletBinding(SupportsShouldProcess = $false, ConfirmImpact = 'Low')]
    [OutputType([System.Collections.ArrayList])]

    param(
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Target domain controller(s) to analyze for NTDS.dit extraction indicators.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('HostName', 'Name', 'ComputerName')]
        [string[]]
        $DomainController,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Number of days to analyze event logs (1-365 days).',
            Position = 1)]
        [ValidateRange(1, 365)]
        [int]
        $DaysBack = 30,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Directory where detection results will be saved (CSV and JSON formats).',
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ExportPath = ('{0}\Desktop\NTDSExtractionAudit' -f $env:USERPROFILE),

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Switch to scan all domain controllers for NTDS.dit extraction indicators.',
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

        [System.Collections.ArrayList]$AllFindings = @()
        $StartDate = (Get-Date).AddDays(-$DaysBack)
        $Timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'

        # Create output directory if it doesn't exist
        if (-not (Test-Path -Path $ExportPath)) {
            try {
                New-Item -Path $ExportPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
                Write-Verbose -Message ('Created output directory: {0}' -f $ExportPath)
            } catch {
                Write-Error -Message ('Failed to create output directory: {0}. Error: {1}' -f $ExportPath, $_.Exception.Message)
                throw
            } #end try-catch
        } #end if

        Write-Verbose -Message 'NTDS.dit Extraction Detection initialized'
        Write-Verbose -Message ('Analysis Window: Last {0} days (from {1})' -f $DaysBack, $StartDate.ToString('yyyy-MM-dd'))
        Write-Verbose -Message ('Output Directory: {0}' -f $ExportPath)

    } #end Begin

    Process {
        try {
            # Determine which DCs to check
            [System.Collections.ArrayList]$DCList = @()

            if ($PSBoundParameters.ContainsKey('DomainController') -and $DomainController.Count -gt 0) {
                # Use specified DCs from parameter
                Write-Verbose -Message ('Using specified domain controllers: {0}' -f ($DomainController -join ', '))
                foreach ($DC in $DomainController) {
                    [void]$DCList.Add($DC)
                } #end foreach
            } elseif ($CheckAllDCs) {
                # Get all DCs in the domain
                Write-Verbose -Message 'Retrieving all domain controllers in the domain...'
                $AllDCs = Get-ADDomainController -Filter *
                foreach ($DC in $AllDCs) {
                    [void]$DCList.Add($DC.HostName)
                } #end foreach
                Write-Verbose -Message ('Found {0} domain controllers' -f $DCList.Count)
            } else {
                # Use current computer (must be a DC)
                [void]$DCList.Add($env:COMPUTERNAME)
                Write-Verbose -Message ('Using current domain controller: {0}' -f $env:COMPUTERNAME)
            } #end if-else

            Write-Verbose -Message ('Total domain controllers to scan: {0}' -f $DCList.Count)

            # =============================================
            # PHASE 1: VOLUME SHADOW COPY (VSS) DETECTION
            # =============================================

            Write-Verbose -Message '[Phase 1] Analyzing Volume Shadow Copy (VSS) activity...'

            foreach ($DC in $DCList) {
                Write-Debug -Message ('  Checking VSS activity on {0}...' -f $DC)

                try {
                    # Event 7036 (Service Control Manager - VSS service start)
                    $VSSServiceEvents = Get-WinEvent -ComputerName $DC -FilterHashtable @{
                        LogName   = 'System'
                        ID        = 7036
                        StartTime = $StartDate
                    } -ErrorAction SilentlyContinue | Where-Object {
                        $_.Message -match 'Volume Shadow Copy'
                    }

                    if ($VSSServiceEvents) {
                        Write-Warning -Message ('  [!] ALERT: {0} VSS service events detected on {1}' -f $VSSServiceEvents.Count, $DC)

                        foreach ($Event in $VSSServiceEvents) {
                            [void]$AllFindings.Add([PSCustomObject]@{
                                    Timestamp         = $Event.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                                    FindingType       = 'VSS Service Activity'
                                    RiskLevel         = 'High'
                                    DomainController  = $DC
                                    EventID           = 7036
                                    ServiceName       = 'Volume Shadow Copy'
                                    Indicator         = 'VSS service started (potential NTDS.dit extraction via vssadmin)'
                                    Recommendation    = 'Verify VSS usage - legitimate backups or malicious NTDS.dit extraction? Check Event 8222 for shadow copy creation.'
                                    AdditionalDetails = $Event.Message.Substring(0, [Math]::Min(200, $Event.Message.Length))
                                })

                            Write-Verbose -Message ('    [!] HIGH: VSS service started at {0}' -f $Event.TimeCreated)
                        } #end foreach
                    } #end if

                    # Event 8222 (VSS - Shadow copy created)
                    $VSSShadowEvents = Get-WinEvent -ComputerName $DC -FilterHashtable @{
                        LogName      = 'System'
                        ProviderName = 'VSS'
                        StartTime    = $StartDate
                    } -ErrorAction SilentlyContinue | Where-Object {
                        $_.Id -eq 8222  # Shadow copy created successfully
                    }

                    if ($VSSShadowEvents) {
                        Write-Warning -Message ('  [!] CRITICAL: {0} VSS shadow copy creation events on {1}' -f $VSSShadowEvents.Count, $DC)

                        foreach ($Event in $VSSShadowEvents) {
                            [void]$AllFindings.Add([PSCustomObject]@{
                                    Timestamp        = $Event.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                                    FindingType      = 'VSS Shadow Copy Created'
                                    RiskLevel        = 'Critical'
                                    DomainController = $DC
                                    EventID          = 8222
                                    Indicator        = 'Volume shadow copy created on DC (common NTDS.dit extraction technique)'
                                    Recommendation   = 'URGENT - Investigate shadow copy creation: vssadmin list shadows. Correlate with Event 4663 (ntds.dit file access).'
                                })

                            Write-Verbose -Message ('    [!] CRITICAL: Shadow copy created at {0}' -f $Event.TimeCreated)
                        } #end foreach
                    } #end if

                } catch {
                    Write-Warning -Message ('  Failed to query VSS events from {0}: {1}' -f $DC, $_.Exception.Message)
                } #end try-catch
            } #end foreach DC

            # =============================================
            # PHASE 2: NTDSUTIL / ESENTUTL / DISKSHADOW PROCESS DETECTION
            # =============================================

            Write-Verbose -Message '[Phase 2] Analyzing NTDS.dit extraction tool execution...'

            foreach ($DC in $DCList) {
                Write-Debug -Message ('  Querying process execution on {0}...' -f $DC)

                try {
                    # Check if Sysmon is installed
                    $SysmonService = Get-Service -ComputerName $DC -Name 'Sysmon64' -ErrorAction SilentlyContinue

                    if (-not $SysmonService) {
                        [void]$AllFindings.Add([PSCustomObject]@{
                                Timestamp        = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                                FindingType      = 'Sysmon Not Installed'
                                RiskLevel        = 'High'
                                DomainController = $DC
                                Indicator        = 'Sysmon not installed - process creation monitoring unavailable (ntdsutil/vssadmin execution invisible)'
                                Recommendation   = 'Deploy Sysmon with process creation monitoring (Event 1)'
                            })

                        Write-Warning -Message ('  [!] HIGH: Sysmon NOT installed on {0} (Event 1 detection unavailable)' -f $DC)
                    } else {
                        # Query Sysmon Event 1 (Process Creation) for extraction tools
                        $SuspiciousProcesses = Get-WinEvent -ComputerName $DC -FilterHashtable @{
                            LogName   = 'Microsoft-Windows-Sysmon/Operational'
                            ID        = 1
                            StartTime = $StartDate
                        } -ErrorAction SilentlyContinue | Where-Object {
                            $_.Properties[4].Value -match 'ntdsutil\.exe|vssadmin\.exe|esentutl\.exe|diskshadow\.exe'
                        }

                        if ($SuspiciousProcesses) {
                            Write-Warning -Message ('  [!] CRITICAL: {0} suspicious process executions detected on {1}' -f $SuspiciousProcesses.Count, $DC)

                            foreach ($Event in $SuspiciousProcesses) {
                                $ProcessName = $Event.Properties[4].Value  # Image (process executable path)
                                $CommandLine = $Event.Properties[10].Value  # CommandLine
                                $User = $Event.Properties[11].Value  # User

                                [void]$AllFindings.Add([PSCustomObject]@{
                                        Timestamp        = $Event.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                                        FindingType      = 'NTDS Extraction Tool Executed'
                                        RiskLevel        = 'Critical'
                                        DomainController = $DC
                                        EventID          = 1
                                        ProcessName      = $ProcessName
                                        CommandLine      = $CommandLine
                                        User             = $User
                                        Indicator        = 'NTDS.dit extraction tool executed (ntdsutil/vssadmin/esentutl)'
                                        Recommendation   = 'IMMEDIATE INVESTIGATION - Check for ntds.dit file copies, review Event 4663, initiate incident response'
                                    })

                                Write-Verbose -Message ('    [!] CRITICAL: {0} executed by {1}' -f $ProcessName, $User)
                                Write-Debug -Message ('        CommandLine: {0}' -f $CommandLine)
                            } #end foreach
                        } #end if
                    } #end if-else

                } catch {
                    Write-Warning -Message ('  Failed to query Sysmon Event 1 from {0}: {1}' -f $DC, $_.Exception.Message)
                } #end try-catch
            } #end foreach DC

            # =============================================
            # PHASE 3: EVENT 4663 (NTDS.DIT FILE ACCESS AUDITING)
            # =============================================

            Write-Verbose -Message '[Phase 3] Analyzing Event 4663 (NTDS.dit file access)...'

            foreach ($DC in $DCList) {
                Write-Debug -Message ('  Querying Event 4663 on {0}...' -f $DC)

                try {
                    # Check if Object Access auditing is enabled
                    $ObjectAccessAuditEnabled = Invoke-Command -ComputerName $DC -ScriptBlock {
                        $AuditPolicy = auditpol /get /subcategory:'File System' /r | ConvertFrom-Csv
                        $AuditPolicy.'Inclusion Setting' -match 'Success'
                    } -ErrorAction SilentlyContinue

                    if (-not $ObjectAccessAuditEnabled) {
                        [void]$AllFindings.Add([PSCustomObject]@{
                                Timestamp        = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                                FindingType      = 'Object Access Auditing Disabled'
                                RiskLevel        = 'High'
                                DomainController = $DC
                                Indicator        = 'Object Access auditing not enabled - Event 4663 (file access) not logged (NTDS.dit access invisible)'
                                Recommendation   = 'Enable Object Access auditing via Group Policy: Advanced Audit Policy -> Object Access -> Audit File System = Success'
                            })

                        Write-Warning -Message ('  [!] HIGH: Object Access auditing disabled on {0}' -f $DC)
                        continue
                    } #end if

                    # Query Event 4663 (Object Access - file read)
                    $NTDSFileAccessEvents = Get-WinEvent -ComputerName $DC -FilterHashtable @{
                        LogName   = 'Security'
                        ID        = 4663
                        StartTime = $StartDate
                    } -ErrorAction SilentlyContinue | Where-Object {
                        $_.Message -match 'ntds\.dit'
                    }

                    if ($NTDSFileAccessEvents) {
                        Write-Verbose -Message ('  Found {0} NTDS.dit file access events on {1}' -f $NTDSFileAccessEvents.Count, $DC)

                        foreach ($Event in $NTDSFileAccessEvents) {
                            $EventXml = [xml]$Event.ToXml()
                            $SubjectUserName = ($EventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
                            $ObjectName = ($EventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'ObjectName' }).'#text'
                            $ProcessName = ($EventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'ProcessName' }).'#text'
                            $AccessList = ($EventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'AccessList' }).'#text'

                            # LSASS.exe accessing ntds.dit is normal (database in use)
                            # Any OTHER process accessing ntds.dit = high-risk indicator
                            $RiskLevel = if ($ProcessName -notmatch 'lsass\.exe') { 'Critical' } else { 'Low' }

                            if ($RiskLevel -eq 'Critical') {
                                [void]$AllFindings.Add([PSCustomObject]@{
                                        Timestamp        = $Event.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                                        FindingType      = 'Unauthorized NTDS.dit File Access'
                                        RiskLevel        = 'Critical'
                                        DomainController = $DC
                                        EventID          = 4663
                                        SubjectUser      = $SubjectUserName
                                        ProcessName      = $ProcessName
                                        ObjectName       = $ObjectName
                                        AccessList       = $AccessList
                                        Indicator        = 'Non-LSASS process accessed ntds.dit file (potential extraction attempt)'
                                        Recommendation   = ('URGENT - Investigate process {0}. Check for ntds.dit copies, initiate incident response.' -f $ProcessName)
                                    })

                                Write-Warning -Message ('    [!] CRITICAL: Non-LSASS process {0} accessed ntds.dit' -f $ProcessName)
                                Write-Verbose -Message ('        User: {0}, Time: {1}' -f $SubjectUserName, $Event.TimeCreated)
                            } #end if
                        } #end foreach
                    } #end if

                } catch {
                    Write-Warning -Message ('  Failed to query Event 4663 from {0}: {1}' -f $DC, $_.Exception.Message)
                } #end try-catch
            } #end foreach DC

            # =============================================
            # PHASE 4: EVENT 2004 (DIRECTORY SERVICE - NTDSUTIL IFM BACKUP)
            # =============================================

            Write-Verbose -Message '[Phase 4] Analyzing Event 2004 (NTDSUtil IFM backup operations)...'

            foreach ($DC in $DCList) {
                Write-Debug -Message ('  Querying Event 2004 on {0}...' -f $DC)

                try {
                    # Event 2004 (Directory Service - IFM backup)
                    $IFMBackupEvents = Get-WinEvent -ComputerName $DC -FilterHashtable @{
                        LogName   = 'Directory Service'
                        ID        = 2004
                        StartTime = $StartDate
                    } -ErrorAction SilentlyContinue

                    if ($IFMBackupEvents) {
                        Write-Warning -Message ('  [!] CRITICAL: {0} NTDSUtil IFM backup events detected on {1}' -f $IFMBackupEvents.Count, $DC)

                        foreach ($Event in $IFMBackupEvents) {
                            [void]$AllFindings.Add([PSCustomObject]@{
                                    Timestamp         = $Event.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                                    FindingType       = 'NTDSUtil IFM Backup'
                                    RiskLevel         = 'Critical'
                                    DomainController  = $DC
                                    EventID           = 2004
                                    Indicator         = 'NTDSUtil IFM (Install From Media) backup created - NTDS.dit extracted to filesystem'
                                    Recommendation    = 'URGENT - Verify backup legitimacy. Outside maintenance windows = incident response. Search DC for IFM folders (contains ntds.dit copy).'
                                    AdditionalDetails = $Event.Message.Substring(0, [Math]::Min(200, $Event.Message.Length))
                                })

                            Write-Verbose -Message ('    [!] CRITICAL: IFM backup created at {0}' -f $Event.TimeCreated)
                        } #end foreach
                    } else {
                        Write-Verbose -Message ('  [OK] No IFM backup events detected on {0}' -f $DC)
                    } #end if-else

                } catch {
                    Write-Warning -Message ('  Failed to query Event 2004 from {0}: {1}' -f $DC, $_.Exception.Message)
                } #end try-catch
            } #end foreach DC

            # =============================================
            # PHASE 5: SYSMON EVENT 11 (NTDS.DIT FILE CREATION)
            # =============================================

            Write-Verbose -Message '[Phase 5] Analyzing Sysmon Event 11 (ntds.dit file creation in non-standard locations)...'

            foreach ($DC in $DCList) {
                Write-Debug -Message ('  Querying Sysmon Event 11 on {0}...' -f $DC)

                try {
                    # Check if Sysmon is installed
                    $SysmonService = Get-Service -ComputerName $DC -Name 'Sysmon64' -ErrorAction SilentlyContinue

                    if (-not $SysmonService) {
                        Write-Verbose -Message ('  [SKIPPED] Sysmon not installed on {0} (Event 11 unavailable)' -f $DC)
                        continue
                    } #end if

                    # Query Sysmon Event 11 (File Creation) for ntds.dit copies
                    $NTDSFileCreationEvents = Get-WinEvent -ComputerName $DC -FilterHashtable @{
                        LogName   = 'Microsoft-Windows-Sysmon/Operational'
                        ID        = 11
                        StartTime = $StartDate
                    } -ErrorAction SilentlyContinue | Where-Object {
                        # TargetFilename property (index 4) contains 'ntds.dit'
                        $_.Properties[4].Value -match 'ntds\.dit' -and
                        # Exclude legitimate NTDS location (C:\Windows\NTDS\ntds.dit)
                        $_.Properties[4].Value -notmatch 'C:\\Windows\\NTDS\\ntds\.dit'
                    }

                    if ($NTDSFileCreationEvents) {
                        Write-Warning -Message ('  [!] CRITICAL: {0} ntds.dit file creation events in non-standard locations on {1}' -f $NTDSFileCreationEvents.Count, $DC)

                        foreach ($Event in $NTDSFileCreationEvents) {
                            $TargetFilename = $Event.Properties[4].Value  # TargetFilename
                            $ProcessName = $Event.Properties[5].Value  # Image (process that created file)
                            $User = $Event.Properties[1].Value  # User

                            [void]$AllFindings.Add([PSCustomObject]@{
                                    Timestamp        = $Event.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                                    FindingType      = 'NTDS.dit File Copy Created'
                                    RiskLevel        = 'Critical'
                                    DomainController = $DC
                                    EventID          = 11
                                    TargetFilename   = $TargetFilename
                                    ProcessName      = $ProcessName
                                    User             = $User
                                    Indicator        = 'ntds.dit file created outside C:\Windows\NTDS\ (extraction confirmed)'
                                    Recommendation   = 'IMMEDIATE INCIDENT RESPONSE - NTDS.dit extracted. Assume domain compromise. Delete file, investigate process, reset KRBTGT, force password resets.'
                                })

                            Write-Warning -Message ('    [!] CRITICAL: ntds.dit copy created at {0}' -f $TargetFilename)
                            Write-Verbose -Message ('        Process: {0}, User: {1}' -f $ProcessName, $User)
                        } #end foreach
                    } #end if

                    # Also check for SYSTEM registry hive copies (required to decrypt NTDS.dit)
                    $SystemHiveCopyEvents = Get-WinEvent -ComputerName $DC -FilterHashtable @{
                        LogName   = 'Microsoft-Windows-Sysmon/Operational'
                        ID        = 11
                        StartTime = $StartDate
                    } -ErrorAction SilentlyContinue | Where-Object {
                        # TargetFilename contains 'SYSTEM' AND path is NOT registry location
                        $_.Properties[4].Value -match '\\SYSTEM$|\\SYSTEM\.sav$' -and
                        $_.Properties[4].Value -notmatch 'C:\\Windows\\System32\\config\\SYSTEM'
                    }

                    if ($SystemHiveCopyEvents) {
                        Write-Warning -Message ('  [!] HIGH: {0} SYSTEM registry hive copy events on {1}' -f $SystemHiveCopyEvents.Count, $DC)

                        foreach ($Event in $SystemHiveCopyEvents) {
                            $TargetFilename = $Event.Properties[4].Value
                            $ProcessName = $Event.Properties[5].Value
                            $User = $Event.Properties[1].Value

                            [void]$AllFindings.Add([PSCustomObject]@{
                                    Timestamp        = $Event.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                                    FindingType      = 'SYSTEM Registry Hive Copy'
                                    RiskLevel        = 'High'
                                    DomainController = $DC
                                    EventID          = 11
                                    TargetFilename   = $TargetFilename
                                    ProcessName      = $ProcessName
                                    User             = $User
                                    Indicator        = 'SYSTEM registry hive copied (contains NTDS.dit decryption keys, usually paired with ntds.dit extraction)'
                                    Recommendation   = 'Check for paired ntds.dit extraction. SYSTEM + ntds.dit = full credential database theft.'
                                })

                            Write-Verbose -Message ('    [!] HIGH: SYSTEM registry hive copied to {0}' -f $TargetFilename)
                        } #end foreach
                    } #end if

                } catch {
                    Write-Warning -Message ('  Failed to query Sysmon Event 11 from {0}: {1}' -f $DC, $_.Exception.Message)
                } #end try-catch
            } #end foreach DC

        } catch {
            Write-Error -Message ('Error during NTDS.dit extraction detection: {0}' -f $_.Exception.Message) -ErrorAction Stop
        } #end try-catch

    } #end Process

    End {
        # Generate summary
        Write-Verbose -Message 'Generating detection summary...'

        $CriticalCount = ($AllFindings | Where-Object { $_.RiskLevel -eq 'Critical' }).Count
        $HighCount = ($AllFindings | Where-Object { $_.RiskLevel -eq 'High' }).Count
        $MediumCount = ($AllFindings | Where-Object { $_.RiskLevel -eq 'Medium' }).Count
        $LowCount = ($AllFindings | Where-Object { $_.RiskLevel -eq 'Low' }).Count

        Write-Verbose -Message '=== Detection Summary ==='
        Write-Verbose -Message ('Total Findings: {0}' -f $AllFindings.Count)
        if ($CriticalCount -gt 0) { Write-Warning -Message ('  Critical: {0}' -f $CriticalCount) }
        if ($HighCount -gt 0) { Write-Warning -Message ('  High: {0}' -f $HighCount) }
        if ($MediumCount -gt 0) { Write-Verbose -Message ('  Medium: {0}' -f $MediumCount) }
        if ($LowCount -gt 0) { Write-Verbose -Message ('  Low: {0}' -f $LowCount) }

        # Export results
        if ($AllFindings.Count -gt 0) {
            $CsvPath = Join-Path -Path $ExportPath -ChildPath ('NTDSExtraction-Detection-{0}.csv' -f $Timestamp)
            $JsonPath = Join-Path -Path $ExportPath -ChildPath ('NTDSExtraction-Detection-{0}.json' -f $Timestamp)

            try {
                $AllFindings | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
                $AllFindings | ConvertTo-Json -Depth 5 | Out-File -FilePath $JsonPath -Encoding UTF8

                Write-Verbose -Message 'Results exported:'
                Write-Verbose -Message ('  CSV:  {0}' -f $CsvPath)
                Write-Verbose -Message ('  JSON: {0}' -f $JsonPath)
            } catch {
                Write-Warning -Message ('Failed to export results: {0}' -f $_.Exception.Message)
            } #end try-catch
        } #end if

        # Provide actionable recommendations
        if ($CriticalCount -gt 0) {
            Write-Warning -Message '=== IMMEDIATE ACTION REQUIRED ==='
            Write-Warning -Message 'Critical NTDS.dit extraction indicators detected. ASSUME DOMAIN COMPROMISE.'
            Write-Warning -Message 'Recommended actions:'
            Write-Warning -Message '  1. ISOLATE affected domain controllers'
            Write-Warning -Message '  2. Reset KRBTGT password IMMEDIATELY (twice, 10 hours apart)'
            Write-Warning -Message '  3. Search for ntds.dit file copies on DC filesystems'
            Write-Warning -Message '  4. Check for SYSTEM registry hive copies'
            Write-Warning -Message '  5. Review outbound network traffic from DCs'
            Write-Warning -Message '  6. Force password reset for ALL privileged accounts'
            Write-Warning -Message '  7. Engage incident response team'
        } #end if

        $txt = ($Variables.FooterHousekeeping -f $MyInvocation.InvocationName, 'detecting NTDS.dit extraction attempts (Event-based detection).')
        Write-Verbose -Message $txt

        # Return findings
        return $AllFindings

    } #end End

} #end Function Get-NTDSDitExtraction
