function Get-ADKerberoastingPattern {
    <#
        .SYNOPSIS
            Detects Kerberoasting attacks by analyzing Kerberos service ticket requests.

        .DESCRIPTION
            Monitors Security Event Log (Event ID 4769) for suspicious service ticket request patterns
            indicating Kerberoasting activity (MITRE ATT&CK T1558.003). This function analyzes Windows
            Security event logs on domain controllers to identify:

            - High-volume service ticket requests from single accounts
            - RC4-HMAC encryption usage (0x17) preferred by attackers for faster credential cracking
            - Requests targeting service accounts with SPNs (excluding krbtgt and computer accounts)
            - Honeypot SPN access attempts

            The function provides comprehensive detection output including source accounts, targeted SPNs,
            source IPs, timeline analysis, and incident response recommendations. Optionally exports detailed
            findings to CSV for further analysis or SIEM integration.

            This is part of the Five Eyes AD Attack Detection Suite designed to identify credential access
            techniques targeting Active Directory environments.

        .PARAMETER DomainController
            Target domain controller to query for security events. Accepts pipeline input to scan multiple DCs.
            If not specified, automatically discovers an available domain controller in the current domain
            using Get-ADDomainController. Accepts 'HostName' or 'Name' properties from Get-ADDomainController output.
            The executing account must have permissions to read the Security event log on the target DC.

        .PARAMETER TimeSpanMinutes
            Number of minutes to look back in event logs for analysis. Default: 60 minutes.
            Adjust based on environment size and typical activity patterns.

        .PARAMETER ThresholdCount
            Minimum number of service ticket requests from a single account within the time span to trigger
            an alert. Default: 10 requests. Lower values increase sensitivity but may generate false positives
            in environments with legitimate high-volume service accounts.

        .PARAMETER ExportPath
            Optional path to export detailed CSV report of suspicious events. If not specified, results are
            only displayed to console. When specified, triggers -WhatIf/-Confirm support for file creation.

        .PARAMETER HoneypotSPNs
            Optional array of honeypot/canary SPN values to monitor for access attempts. Access to these SPNs
            indicates confirmed attack activity. Example: 'HTTP/decoy.corp.local', 'MSSQLSvc/honeypot.corp.local'

        .INPUTS
            [System.String]
            Accepts domain controller names via pipeline. Compatible with output from Get-ADDomainController.

        .OUTPUTS
            [PSCustomObject]
            Returns custom objects containing detection results with the following properties:
            - DetectionType: 'Kerberoasting' or 'HoneypotAccess'
            - Severity: 'Critical', 'High', 'Medium', or 'Low'
            - SourceAccount: Account performing suspicious ticket requests
            - RequestCount: Number of ticket requests detected
            - TargetedSPNs: Array of service principal names targeted
            - SourceIPs: Array of source IP addresses
            - FirstRequest: Timestamp of first suspicious request
            - LastRequest: Timestamp of last suspicious request
            - RecommendedActions: Array of remediation steps

        .EXAMPLE
            Get-ADKerberoastingPattern -DomainController 'DC01' -TimeSpanMinutes 30 -ThresholdCount 5

            Analyzes the last 30 minutes of Event ID 4769 on DC01, alerting on accounts with 5 or more
            suspicious service ticket requests. Results displayed to console only.

        .EXAMPLE
            Get-ADKerberoastingPattern -DomainController 'DC01' -ExportPath 'C:\SecurityAudits\Kerberoast.csv' -Verbose

            Performs default detection (60 min window, threshold 10) with verbose output and exports detailed
            findings to CSV file. File creation prompts for confirmation due to ShouldProcess.

        .EXAMPLE
            Get-ADKerberoastingPattern -HoneypotSPNs @('HTTP/trap.corp.local','MSSQL/canary.corp.local') -WhatIf

            Performs detection including honeypot monitoring. WhatIf shows what CSV export would occur without
            actually creating files.

        .EXAMPLE
            $Results = Get-ADKerberoastingPattern -ThresholdCount 5
            $Results | Where-Object { $_.Severity -eq 'Critical' } | Format-Table -AutoSize

            Captures detection results to variable for further processing and filters for critical severity findings.

        .EXAMPLE
            'DC01', 'DC02', 'DC03' | Get-ADKerberoastingPattern -TimeSpanMinutes 30 -Verbose

            Scans multiple domain controllers via pipeline in the last 30 minutes. Results from all DCs are combined.

        .EXAMPLE
            Get-ADDomainController -Filter * | Get-ADKerberoastingPattern -ThresholdCount 5

            Automatically discovers all domain controllers and scans each for Kerberoasting activity.

        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Get-FunctionDisplay                    | EguibarIT.SecurityPS
                Set-StrictMode                         | PowerShell Core
                Get-Date                               | Microsoft.PowerShell.Utility
                Write-Verbose                          | Microsoft.PowerShell.Utility
                Write-Error                            | Microsoft.PowerShell.Utility
                Write-Warning                          | Microsoft.PowerShell.Utility
                Write-Output                           | Microsoft.PowerShell.Utility
                Get-WinEvent                           | Microsoft.PowerShell.Diagnostics
                Get-ADDomainController                 | ActiveDirectory

        .NOTES
            Version:         1.2.0
            DateModified:    25/Feb/2026
            LastModifiedBy:  Vicente R. Eguibar
                vicente@eguibar.com
                EguibarIT
                http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT.SecurityPS

        .LINK
            https://attack.mitre.org/techniques/T1558/003/

        .LINK
            https://adsecurity.org/?p=3458

        .COMPONENT
            EguibarIT.SecurityPS

        .ROLE
            Security Auditing

        .FUNCTIONALITY
            Detects Kerberoasting attacks through Event ID 4769 analysis
    #>

    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'Medium'
    )]
    [OutputType([PSCustomObject])]

    param(
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0,
            HelpMessage = 'Target domain controller to query for security events'
        )]
        [ValidateNotNullOrEmpty()]
        [Alias('DC', 'Server', 'HostName', 'Name')]
        [string]
        $DomainController,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            Position = 1,
            HelpMessage = 'Number of minutes to look back in event logs (default: 60)'
        )]
        [ValidateRange(1, 10080)]  # 1 minute to 7 days
        [int]
        $TimeSpanMinutes = 60,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            Position = 2,
            HelpMessage = 'Minimum number of ticket requests to trigger alert (default: 10)'
        )]
        [ValidateRange(1, 1000)]
        [int]
        $ThresholdCount = 10,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            Position = 3,
            HelpMessage = 'Optional path to export CSV report of suspicious events'
        )]
        [ValidateNotNullOrEmpty()]
        [string]
        $ExportPath,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            Position = 4,
            HelpMessage = 'Optional array of honeypot SPN values to monitor for access attempts'
        )]
        [string[]]
        $HoneypotSPNs
    )

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

        [int]$script:DetectionCount = 0
        [System.Collections.ArrayList]$script:DetectionResults = @()
        [System.Collections.ArrayList]$script:ProcessedDCs = @()

        # Calculate time range once for all DCs
        $script:StartTime = (Get-Date).AddMinutes(-$TimeSpanMinutes)

        Write-Verbose -Message ('[*] Starting Kerberoasting Detection Scanner')
        Write-Verbose -Message ('[*] Time Range: Last {0} minutes (since {1})' -f $TimeSpanMinutes, $script:StartTime)
        Write-Verbose -Message ('[*] Alert Threshold: {0} requests per account' -f $ThresholdCount)

    } #end begin

    process {

        # Determine target domain controller if not provided via pipeline
        if (-not $PSBoundParameters.ContainsKey('DomainController') -or [string]::IsNullOrWhiteSpace($DomainController)) {

            Write-Verbose -Message '[*] No domain controller specified, attempting to locate one'

            try {

                # Try to get a domain controller from the current domain
                $DC = Get-ADDomainController -Discover -ErrorAction Stop
                $DomainController = $DC.HostName
                Write-Verbose -Message ('[*] Discovered domain controller: {0}' -f $DomainController)

            } catch {

                # If Get-ADDomainController fails, try alternate method
                Write-Warning -Message 'Unable to discover domain controller using Get-ADDomainController'

                try {

                    # Fallback: Use environment variable or DNS query
                    $DomainName = $env:USERDNSDOMAIN
                    if ($DomainName) {

                        $DomainController = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().FindDomainController().Name
                        Write-Verbose -Message ('[*] Located domain controller via DNS: {0}' -f $DomainController)

                    } else {

                        $ErrorMsg = 'Cannot locate domain controller. Machine may not be domain-joined or ActiveDirectory module not available.'
                        Write-Error -Message $ErrorMsg
                        return

                    } #end if-else DomainName

                } catch {

                    $ErrorMsg = 'Failed to locate domain controller: {0}' -f $_.Exception.Message
                    Write-Error -Message $ErrorMsg
                    return

                } #end try-catch fallback

            } #end try-catch

        } #end if DomainController not specified

        # Skip if this DC was already processed (duplicate pipeline input)
        if ($script:ProcessedDCs -contains $DomainController) {
            Write-Verbose -Message ('[*] Skipping {0} - already processed' -f $DomainController)
            return
        } #end if

        [void]$script:ProcessedDCs.Add($DomainController)
        Write-Verbose -Message ('[*] Processing Domain Controller: {0}' -f $DomainController)

        try {

            # Query Event ID 4769 (Kerberos Service Ticket Request)
            Write-Verbose -Message ('[*] Querying Event ID 4769 on {0}' -f $DomainController)

            $EventLogParams = @{
                ComputerName    = $DomainController
                FilterHashtable = @{
                    LogName   = 'Security'
                    Id        = 4769
                    StartTime = $script:StartTime
                }
                ErrorAction     = 'Stop'
            } #end Hashtable

            $SecurityEvents = Get-WinEvent @EventLogParams

            Write-Verbose -Message ('[+] Retrieved {0} Event ID 4769 entries' -f $SecurityEvents.Count)

        } catch {

            $ErrorMessage = 'Error querying Security event log on {0}: {1}' -f $DomainController, $_.Exception.Message
            Write-Error -Message $ErrorMessage
            return

        } #end try-catch

        # Parse events and filter for Kerberoasting indicators
        Write-Verbose -Message '[*] Parsing events and filtering for Kerberoasting patterns'

        $SuspiciousEvents = [System.Collections.ArrayList]::new()

        foreach ($SecurityEvent in $SecurityEvents) {

            try {

                $XML = [xml]$SecurityEvent.ToXml()
                $EventData = @{}

                # Extract event properties
                $XML.Event.EventData.Data | ForEach-Object {
                    $EventData[$_.Name] = $_.'#text'
                } #end ForEach-Object

                <#
                    Filter criteria for Kerberoasting:
                    1. Encryption Type = 0x17 (RC4-HMAC) - preferred by attackers for faster cracking
                    2. Service Name NOT 'krbtgt' (exclude TGT requests)
                    3. Service Name NOT ending with '$' (exclude computer accounts)
                #>

                if (
                    $EventData['TicketEncryptionType'] -eq '0x17' -and
                    $EventData['ServiceName'] -notlike '*krbtgt*' -and
                    $EventData['ServiceName'] -notlike '*$*'
                ) {

                    $SuspiciousEvent = [PSCustomObject]@{
                        TimeCreated    = $SecurityEvent.TimeCreated
                        TargetAccount  = $EventData['TargetUserName']
                        SourceAccount  = '{0}\{1}' -f $EventData['TargetDomainName'], $EventData['TargetUserName']
                        ServiceName    = $EventData['ServiceName']
                        SourceIP       = $EventData['IpAddress']
                        EncryptionType = $EventData['TicketEncryptionType']
                        TicketOptions  = $EventData['TicketOptions']
                    } #end PSCustomObject

                    [void]$SuspiciousEvents.Add($SuspiciousEvent)

                } #end if

            } catch {

                Write-Warning -Message ('Error parsing event at {0}: {1}' -f $SecurityEvent.TimeCreated, $_.Exception.Message)
                continue

            } #end try-catch

        } #end foreach

        Write-Verbose -Message ('[*] Filtered to {0} suspicious RC4 service ticket requests' -f $SuspiciousEvents.Count)

        # Group by source account and count requests
        Write-Verbose -Message '[*] Analyzing account activity patterns'

        $AccountActivity = $SuspiciousEvents |
            Group-Object -Property SourceAccount |
                Where-Object { $_.Count -ge $ThresholdCount } |
                    Sort-Object -Property Count -Descending

        # Process detection results
        if ($AccountActivity.Count -gt 0) {

            Write-Warning -Message ('[!] KERBEROASTING DETECTED - {0} accounts exceed threshold' -f $AccountActivity.Count)

            foreach ($Account in $AccountActivity) {

                $TargetedSPNs = $Account.Group | Select-Object -ExpandProperty ServiceName -Unique
                $SourceIPs = $Account.Group | Select-Object -ExpandProperty SourceIP -Unique
                $FirstRequest = ($Account.Group | Sort-Object -Property TimeCreated)[0].TimeCreated
                $LastRequest = ($Account.Group | Sort-Object -Property TimeCreated -Descending)[0].TimeCreated

                # Determine severity based on request count
                $Severity = switch ($Account.Count) {
                    { $_ -ge 50 } {
                        'Critical'; break
                    }
                    { $_ -ge 25 } {
                        'High'; break
                    }
                    { $_ -ge 15 } {
                        'Medium'; break
                    }
                    default {
                        'Low'
                    }
                } #end switch

                # Create detection result object
                $DetectionResult = [PSCustomObject]@{
                    PSTypeName         = 'EguibarIT.SecurityPS.KerberoastingDetection'
                    DetectionType      = 'Kerberoasting'
                    Severity           = $Severity
                    DomainController   = $DomainController
                    SourceAccount      = $Account.Name
                    RequestCount       = $Account.Count
                    TargetedSPNs       = $TargetedSPNs
                    SourceIPs          = $SourceIPs
                    FirstRequest       = $FirstRequest
                    LastRequest        = $LastRequest
                    TimeSpanMinutes    = $TimeSpanMinutes
                    RecommendedActions = @(
                        'Immediately investigate source account and IPs'
                        'Reset passwords for ALL service accounts with targeted SPNs'
                        'Review recent account logins from source IPs for lateral movement'
                        'Check for suspicious PowerShell execution (Event ID 4104) from source hosts'
                        'Audit SPN configurations: Get-ADUser -Filter {ServicePrincipalName -like ''*''}'
                        'Consider migrating service accounts to gMSA (240-char auto-rotated passwords)'
                    )
                } #end PSCustomObject

                [void]$script:DetectionResults.Add($DetectionResult)
                $script:DetectionCount++

                # Display detailed alert information
                Write-Warning -Message ('    Account: {0}' -f $Account.Name)
                Write-Warning -Message ('    Severity: {0}' -f $Severity)
                Write-Warning -Message ('    Request Count: {0}' -f $Account.Count)
                Write-Verbose -Message '    Targeted SPNs:'
                $TargetedSPNs | ForEach-Object {
                    Write-Verbose -Message ('        - {0}' -f $_)
                } #end ForEach-Object
                Write-Verbose -Message '    Source IPs:'
                $SourceIPs | ForEach-Object {
                    Write-Verbose -Message ('        - {0}' -f $_)
                } #end ForEach-Object
                Write-Verbose -Message ('    First Request: {0}' -f $FirstRequest)
                Write-Verbose -Message ('    Last Request: {0}' -f $LastRequest)

            } #end foreach

            # Display incident response recommendations
            Write-Verbose -Message ''
            Write-Verbose -Message '[!] RECOMMENDED ACTIONS:'
            Write-Verbose -Message '    1. Immediately investigate source accounts and IPs listed above'
            Write-Verbose -Message '    2. Reset passwords for ALL service accounts with SPNs (targeted accounts)'
            Write-Verbose -Message '    3. Review recent account logins from source IPs for lateral movement'
            Write-Verbose -Message '    4. Check for suspicious PowerShell execution (Event ID 4104) from source hosts'
            Write-Verbose -Message '    5. Audit SPN configurations: Get-ADUser -Filter {ServicePrincipalName -like ''*''}'
            Write-Verbose -Message '    6. Consider migrating service accounts to gMSA (240-char auto-rotated passwords)'

            # Export detailed report if path specified
            if ($PSBoundParameters.ContainsKey('ExportPath')) {

                if ($PSCmdlet.ShouldProcess($ExportPath, 'Export detailed Kerberoasting detection report')) {

                    try {

                        # Ensure directory exists
                        $ExportDirectory = Split-Path -Path $ExportPath -Parent
                        if (-not (Test-Path -Path $ExportDirectory)) {
                            New-Item -Path $ExportDirectory -ItemType Directory -Force | Out-Null
                        } #end if

                        # Export raw suspicious events
                        $SuspiciousEvents | Export-Csv -Path $ExportPath -NoTypeInformation -Force
                        Write-Verbose -Message ('[*] Detailed event report exported to: {0}' -f $ExportPath)

                    } catch {

                        Write-Warning -Message ('Failed to export report to {0}: {1}' -f $ExportPath, $_.Exception.Message)

                    } #end try-catch

                } #end if ShouldProcess

            } #end if ExportPath

        } else {

            Write-Verbose -Message '[+] No Kerberoasting activity detected'
            Write-Verbose -Message '[+] All Event ID 4769 patterns within normal thresholds'

        } #end if-else

        # Additional hunting: Check for honeypot SPN access
        if ($PSBoundParameters.ContainsKey('HoneypotSPNs') -and $HoneypotSPNs.Count -gt 0) {

            Write-Verbose -Message '[*] Checking for honeypot/canary SPN access attempts'

            $HoneypotHits = $SuspiciousEvents | Where-Object {
                $CurrentServiceName = $_.ServiceName
                $HoneypotSPNs | Where-Object { $CurrentServiceName -like $_ }
            } #end Where-Object

            if ($HoneypotHits.Count -gt 0) {

                Write-Warning -Message '[!] CRITICAL: Honeypot SPN accessed - Confirmed attack activity!'

                foreach ($Hit in $HoneypotHits) {

                    $HoneypotDetection = [PSCustomObject]@{
                        PSTypeName         = 'EguibarIT.SecurityPS.KerberoastingDetection'
                        DetectionType      = 'HoneypotAccess'
                        Severity           = 'Critical'
                        DomainController   = $DomainController
                        SourceAccount      = $Hit.SourceAccount
                        RequestCount       = 1
                        TargetedSPNs       = @($Hit.ServiceName)
                        SourceIPs          = @($Hit.SourceIP)
                        FirstRequest       = $Hit.TimeCreated
                        LastRequest        = $Hit.TimeCreated
                        TimeSpanMinutes    = $TimeSpanMinutes
                        RecommendedActions = @(
                            'CRITICAL: Confirmed attack detected via honeypot access'
                            'Immediately isolate source account and IPs'
                            'Initiate incident response procedures'
                            'Review all activity from source account and IPs'
                            'Consider blocking source IPs at firewall level'
                        )
                    } #end PSCustomObject

                    [void]$script:DetectionResults.Add($HoneypotDetection)
                    $script:DetectionCount++

                    Write-Warning -Message ('    Honeypot SPN: {0}' -f $Hit.ServiceName)
                    Write-Warning -Message ('    Source Account: {0}' -f $Hit.SourceAccount)
                    Write-Warning -Message ('    Source IP: {0}' -f $Hit.SourceIP)
                    Write-Warning -Message ('    Time: {0}' -f $Hit.TimeCreated)

                } #end foreach

            } else {

                Write-Verbose -Message '[+] No honeypot SPN access detected'

            } #end if-else

        } #end if HoneypotSPNs

        Write-Verbose -Message ('[*] Completed scan of {0}' -f $DomainController)

    } #end process

    end {

        Write-Verbose -Message ('[*] Detection scan complete at {0}' -f (Get-Date))
        Write-Verbose -Message ('[*] Processed {0} domain controller(s)' -f $script:ProcessedDCs.Count)
        Write-Verbose -Message ('[*] Total detections across all DCs: {0}' -f $script:DetectionCount)

        # Return detection results
        if ($script:DetectionResults.Count -gt 0) {

            Write-Output -InputObject $script:DetectionResults

        } else {

            Write-Verbose -Message '[+] No Kerberoasting activity detected across all scanned domain controllers'

        } #end if-else

        if ($null -ne $Variables -and
            $null -ne $Variables.FooterSecurity) {

            $txt = ($Variables.FooterSecurity -f $MyInvocation.InvocationName,
                'finished detecting Kerberoasting patterns.'
            )
            Write-Verbose -Message $txt
        } #end If

    } #end end

} #end function Get-KerberoastingPatterns
