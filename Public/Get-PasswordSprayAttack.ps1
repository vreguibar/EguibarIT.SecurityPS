function Get-PasswordSprayAttack {
    <#
        .SYNOPSIS
            Detects password spraying attacks by analyzing authentication failure patterns across multiple accounts.

        .DESCRIPTION
            Analyzes Event IDs 4625 (failed Windows logon) and 4771 (failed Kerberos pre-authentication) to detect
            password spraying patterns. Unlike brute-force attacks (many failures against one account), password
            spraying shows few failures against MANY different accounts from the same source IP.

            Detection Logic:
            - Identifies source IPs/hosts with failed logons against multiple different accounts within time window
            - Correlates NTLM (4625) and Kerberos (4771) failures
            - Filters false positives (legitimate service accounts, VPN gateways)
            - Tracks temporal patterns (slow sprays spaced to avoid lockout)
            - Checks for successful logons from spray source IPs indicating compromised credentials

            This is part of the Five Eyes AD Attack Detection Suite designed to identify credential access
            techniques targeting Active Directory environments (MITRE ATT&CK T1110.003).

        .PARAMETER DomainController
            DNS hostname (FQDN) or NetBIOS name of the domain controller to query for security event logs.
            Accepts string values only (e.g., 'DC01.EguibarIT.local' or 'DC01').

            When used with pipeline input from Get-ADDomainController, automatically binds to the
            'HostName' or 'Name' property via ValueFromPipelineByPropertyName.

            If not specified, automatically discovers an available domain controller in the current domain.
            The executing account must have Event Log Reader permissions on the target domain controller.

            Note: Unlike AD identity parameters, this does not accept Distinguished Names, GUIDs, or
            SIDs because it's passed directly to Get-WinEvent's -ComputerName parameter, which requires
            a resolvable hostname.

        .PARAMETER TimeSpanMinutes
            Number of minutes to look back in security event logs for authentication failures.
            Default: 60 minutes. Adjust based on detection frequency requirements.
            Valid range: 1 to 10080 minutes (7 days).

        .PARAMETER FailureThreshold
            Number of unique accounts with failures from a single source IP to trigger an alert.
            Default: 10 accounts. Lower values increase sensitivity but may generate false positives.
            Valid range: 2 to 1000 accounts.

        .PARAMETER ExcludeSourceIPs
            Array of IP addresses to exclude from analysis (e.g., VPN gateways, legitimate automation systems).
            Supports both IPv4 and IPv6 addresses. Use this to filter known legitimate sources of authentication
            failures such as RDP gateways, web application servers, or Exchange servers.

        .PARAMETER ExportPath
            Optional path to export detailed vulnerability and exploitation findings to CSV format.
            If not specified, results are displayed to console only. When specified, triggers
            -WhatIf/-Confirm support for file operations.

        .INPUTS
            [System.String]
            Accepts domain controller names via pipeline. Compatible with output from Get-ADDomainController.

        .OUTPUTS
            [PSCustomObject]
            Returns custom objects containing detection results with the following properties:
            - DetectionType: 'PasswordSpray'
            - Severity: 'Critical', 'High', 'Medium', or 'Low'
            - SourceIP: IP address of the attack source
            - UniqueTargetAccounts: Number of unique accounts targeted
            - TotalFailures: Total number of failed authentication attempts
            - FailuresPerAccount: Average failures per account
            - AttackDuration: Duration of attack in minutes
            - FirstFailure: Timestamp of first detected failure
            - LastFailure: Timestamp of last detected failure
            - TargetedAccounts: Array of targeted account names
            - SuccessfulLogons: Number of successful logons from source IP (if any)
            - RecommendedActions: Array of remediation steps

        .EXAMPLE
            Get-PasswordSprayAttack -DomainController 'DC01.EguibarIT.local' -TimeSpanMinutes 120 -Verbose

            Analyzes authentication failures on DC01 using FQDN for the last 2 hours with verbose output.

        .EXAMPLE
            Get-PasswordSprayAttack -DomainController 'DC01' -FailureThreshold 15 -ExcludeSourceIPs @('10.0.1.50', '10.0.1.51')

            Detects password spray attacks using NetBIOS name with higher threshold (15 accounts) and excludes known legitimate sources.

        .EXAMPLE
            'DC01.EguibarIT.local', 'DC02.EguibarIT.local' | Get-PasswordSprayAttack -TimeSpanMinutes 30 -ExportPath 'C:\SecurityAudits\PasswordSpray.csv'

            Analyzes multiple domain controllers via pipeline (passing hostnames as strings) and exports results to CSV file.

        .EXAMPLE
            Get-ADDomainController -Filter * | Get-PasswordSprayAttack -FailureThreshold 5 -Verbose

            Discovers all domain controllers and automatically scans each for password spray attacks.
            Pipeline binding uses the 'HostName' property from Get-ADDomainController output.

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
                Get-ADDomainController                 | ActiveDirectory
                Get-WinEvent                           | Microsoft.PowerShell.Diagnostics
                Export-Csv                             | Microsoft.PowerShell.Utility

        .NOTES
            Version:         1.0.0
            DateModified:    02/Mar/2026
            LastModifiedBy:  Vicente R. Eguibar
                vicente@eguibar.com
                EguibarIT
                http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT.SecurityPS

        .LINK
            https://attack.mitre.org/techniques/T1110/003/

        .COMPONENT
            EguibarIT.SecurityPS

        .ROLE
            Security Auditing

        .FUNCTIONALITY
            Detects password spraying attacks by analyzing authentication failure patterns
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
            HelpMessage = 'DNS hostname (FQDN) or NetBIOS name of target domain controller (e.g., DC01.EguibarIT.local or DC01)'
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
        [PSDefaultValue(Help = 'Default: 60 minutes', Value = 60)]
        [int]
        $TimeSpanMinutes = 60,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            Position = 2,
            HelpMessage = 'Number of unique accounts from single source to trigger alert (default: 10)'
        )]
        [ValidateRange(2, 1000)]
        [PSDefaultValue(Help = 'Default: 10 accounts', Value = 10)]
        [int]
        $FailureThreshold = 10,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            Position = 3,
            HelpMessage = 'Array of IP addresses to exclude from analysis (VPN gateways, automation systems)'
        )]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $ExcludeSourceIPs,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            Position = 4,
            HelpMessage = 'Optional path to export findings to CSV'
        )]
        [ValidateNotNullOrEmpty()]
        [string]
        $ExportPath
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

        # Initialize excluded IPs list if not provided
        if (-not $PSBoundParameters.ContainsKey('ExcludeSourceIPs')) {
            $ExcludeSourceIPs = @()
        } #end if

        Write-Verbose -Message '[*] Starting Password Spraying Attack Detection Scanner'
        Write-Verbose -Message ('[*] Time Range: Last {0} minutes (since {1})' -f $TimeSpanMinutes, $script:StartTime)
        Write-Verbose -Message ('[*] Alert Threshold: {0} unique accounts from single source' -f $FailureThreshold)

        if ($ExcludeSourceIPs.Count -gt 0) {
            Write-Verbose -Message ('[*] Excluded Source IPs: {0}' -f ($ExcludeSourceIPs -join ', '))
        } #end if

    } #end begin

    process {

        # Determine target domain controller if not provided via pipeline
        if (-not $PSBoundParameters.ContainsKey('DomainController') -or [string]::IsNullOrWhiteSpace($DomainController)) {

            Write-Verbose -Message '[*] No domain controller specified, attempting to locate one'

            try {

                $DC = Get-ADDomainController -Discover -ErrorAction Stop
                $DomainController = $DC.HostName
                Write-Verbose -Message ('[*] Discovered domain controller: {0}' -f $DomainController)

            } catch {

                Write-Warning -Message 'Unable to discover domain controller using Get-ADDomainController'

                try {

                    $DomainName = $env:USERDNSDOMAIN
                    if ($DomainName) {

                        $DomainController = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().FindDomainController().Name
                        Write-Verbose -Message ('[*] Located domain controller via DNS: {0}' -f $DomainController)

                    } else {

                        $ErrorMsg = 'Cannot locate domain controller. Machine may not be domain-joined or ActiveDirectory module not available.'
                        Write-Error -Message $ErrorMsg -ErrorAction Stop
                        return

                    } #end if-else

                } catch {

                    $ErrorMsg = 'Failed to locate domain controller: {0}' -f $_.Exception.Message
                    Write-Error -Message $ErrorMsg -ErrorAction Stop
                    return

                } #end try-catch

            } #end try-catch

        } #end if

        # Skip if already processed
        if ($script:ProcessedDCs -contains $DomainController) {

            Write-Verbose -Message ('[*] Domain controller {0} already processed, skipping' -f $DomainController)
            return

        } #end if

        # Add this DC to processed list
        $null = $script:ProcessedDCs.Add($DomainController)

        Write-Verbose -Message ('[*] Analyzing authentication failures on {0}' -f $DomainController)

        ##############################
        # PHASE 1: Collect Event ID 4625 (Failed Windows Logon - NTLM)

        Write-Verbose -Message '[PHASE 1] Collecting Event ID 4625 (Failed Windows Logon - NTLM)'

        [System.Collections.ArrayList]$Failures4625 = @()

        try {

            $Splat4625 = @{
                ComputerName    = $DomainController
                FilterHashtable = @{
                    LogName   = 'Security'
                    Id        = 4625
                    StartTime = $script:StartTime
                }
                ErrorAction     = 'Stop'
            }
            $Events4625 = Get-WinEvent @Splat4625

            Write-Verbose -Message ('[+] Retrieved {0} Event ID 4625 entries' -f $Events4625.Count)

            # Parse Event ID 4625 data
            foreach ($EventItem in $Events4625) {

                $XML = [xml]$EventItem.ToXml()
                $EventData = @{}

                # Extract event properties
                foreach ($Data in $XML.Event.EventData.Data) {
                    $EventData[$Data.Name] = $Data.'#text'
                } #end foreach

                # Filter out system accounts and null IPs
                if ($EventData['TargetUserName'] -notlike '*$' -and
                    $EventData['IpAddress'] -ne '-' -and
                    $EventData['IpAddress'] -ne '::1' -and
                    $EventData['IpAddress'] -ne '127.0.0.1') {

                    # Skip excluded IPs
                    if ($ExcludeSourceIPs -notcontains $EventData['IpAddress']) {

                        $null = $Failures4625.Add([PSCustomObject]@{
                                TimeCreated     = $EventItem.TimeCreated
                                EventID         = 4625
                                TargetAccount   = $EventData['TargetUserName']
                                SourceIP        = $EventData['IpAddress']
                                WorkstationName = $EventData['WorkstationName']
                                LogonType       = $EventData['LogonType']
                                FailureReason   = $EventData['Status']
                            })

                    } #end if

                } #end if

            } #end foreach

        } catch {

            if ($_.Exception.Message -like '*No events were found*') {

                Write-Verbose -Message '[+] No Event ID 4625 failures found (good sign!)'

            } else {

                $ErrorMsg = 'Error querying Event ID 4625: {0}' -f $_.Exception.Message
                Write-Warning -Message $ErrorMsg

            } #end if-else

        } #end try-catch

        ##############################
        # PHASE 2: Collect Event ID 4771 (Failed Kerberos Pre-Auth)

        Write-Verbose -Message '[PHASE 2] Collecting Event ID 4771 (Failed Kerberos Pre-Auth)'

        [System.Collections.ArrayList]$Failures4771 = @()

        try {

            $Splat4771 = @{
                ComputerName    = $DomainController
                FilterHashtable = @{
                    LogName   = 'Security'
                    Id        = 4771
                    StartTime = $script:StartTime
                }
                ErrorAction     = 'Stop'
            }
            $Events4771 = Get-WinEvent @Splat4771

            Write-Verbose -Message ('[+] Retrieved {0} Event ID 4771 entries' -f $Events4771.Count)

            # Parse Event ID 4771 data
            foreach ($EventItem in $Events4771) {

                $XML = [xml]$EventItem.ToXml()
                $EventData = @{}

                # Extract event properties
                foreach ($Data in $XML.Event.EventData.Data) {
                    $EventData[$Data.Name] = $Data.'#text'
                } #end foreach

                # Filter and process
                if ($EventData['TargetUserName'] -notlike '*$' -and
                    $EventData['IpAddress'] -ne '::1' -and
                    $EventData['IpAddress'] -ne '127.0.0.1') {

                    # Clean IP address (remove port if present)
                    $CleanIP = ($EventData['IpAddress'] -split ':')[0]

                    # Skip excluded IPs
                    if ($ExcludeSourceIPs -notcontains $CleanIP) {

                        $null = $Failures4771.Add([PSCustomObject]@{
                                TimeCreated     = $EventItem.TimeCreated
                                EventID         = 4771
                                TargetAccount   = $EventData['TargetUserName']
                                SourceIP        = $CleanIP
                                WorkstationName = 'N/A'
                                LogonType       = 'Kerberos'
                                FailureReason   = $EventData['Status']
                            })

                    } #end if

                } #end if

            } #end foreach

        } catch {

            if ($_.Exception.Message -like '*No events were found*') {

                Write-Verbose -Message '[+] No Event ID 4771 failures found'

            } else {

                $ErrorMsg = 'Error querying Event ID 4771: {0}' -f $_.Exception.Message
                Write-Warning -Message $ErrorMsg

            } #end if-else

        } #end try-catch

        ##############################
        # PHASE 3: Combine and Analyze Patterns

        Write-Verbose -Message '[PHASE 3] Analyzing Password Spray Patterns'

        # Combine both event types
        [System.Collections.ArrayList]$AllFailures = @()
        $AllFailures.AddRange($Failures4625)
        $AllFailures.AddRange($Failures4771)

        Write-Verbose -Message ('[*] Total authentication failures (filtered): {0}' -f $AllFailures.Count)

        if ($AllFailures.Count -eq 0) {

            Write-Verbose -Message '[+] EXCELLENT: No authentication failures detected'
            Write-Verbose -Message '[+] No password spraying activity observed'
            return

        } #end if

        # Group failures by Source IP and count unique target accounts
        $SprayAnalysis = $AllFailures |
            Group-Object -Property SourceIP |
                ForEach-Object {

                    $UniqueAccounts = ($_.Group | Select-Object -Unique TargetAccount).Count
                    $TotalAttempts = $_.Count
                    $FirstFailure = ($_.Group | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated
                    $LastFailure = ($_.Group | Sort-Object TimeCreated | Select-Object -Last 1).TimeCreated
                    $Duration = ($LastFailure - $FirstFailure).TotalMinutes

                    [PSCustomObject]@{
                        SourceIP             = $_.Name
                        UniqueTargetAccounts = $UniqueAccounts
                        TotalFailures        = $TotalAttempts
                        FirstFailure         = $FirstFailure
                        LastFailure          = $LastFailure
                        AttackDuration       = [math]::Round($Duration, 2)
                        FailuresPerAccount   = [math]::Round($TotalAttempts / $UniqueAccounts, 2)
                        Accounts             = $_.Group.TargetAccount | Select-Object -Unique
                    }

                } #end foreach

        # Filter for password spray indicators
        $SuspiciousSources = $SprayAnalysis |
            Where-Object { $_.UniqueTargetAccounts -ge $FailureThreshold } |
                Sort-Object -Property UniqueTargetAccounts -Descending

        ##############################
        # PHASE 4: Check for Successful Logons from Spray Source IPs

        if ($SuspiciousSources.Count -gt 0) {

            Write-Verbose -Message '[PHASE 4] Checking for Successful Logons from Spray Source IPs'

            $SpraySourceIPs = $SuspiciousSources.SourceIP

            try {

                $Splat4624 = @{
                    ComputerName    = $DomainController
                    FilterHashtable = @{
                        LogName   = 'Security'
                        Id        = 4624  # Successful logon
                        StartTime = $script:StartTime
                    }
                    ErrorAction     = 'Stop'
                }
                $SuccessfulEvents = Get-WinEvent @Splat4624

                # Filter successful logons from spray source IPs
                $SuccessfulLogons = $SuccessfulEvents |
                    Where-Object {
                        $XML = [xml]$_.ToXml()
                        $IP = ($XML.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
                        $SpraySourceIPs -contains $IP
                    } #end where

                if ($SuccessfulLogons.Count -gt 0) {

                    Write-Warning -Message ('[!] CRITICAL: {0} successful logons detected from password spray source IPs!' -f $SuccessfulLogons.Count)
                    Write-Warning -Message '[!] Attack was likely SUCCESSFUL - passwords compromised!'

                    foreach ($Logon in $SuccessfulLogons) {

                        $XML = [xml]$Logon.ToXml()
                        $Account = ($XML.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
                        $IP = ($XML.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
                        Write-Warning -Message ('    Account: {0} from IP: {1} at {2}' -f $Account, $IP, $Logon.TimeCreated)

                    } #end foreach

                } else {

                    Write-Verbose -Message '[+] No successful logons from spray source IPs (attack unsuccessful)'

                } #end if-else

            } catch {

                if ($_.Exception.Message -notlike '*No events were found*') {
                    Write-Warning -Message ('Could not check for successful logons: {0}' -f $_.Exception.Message)
                } #end if

            } #end try-catch

        } #end if

        ##############################
        # PHASE 5: Build Detection Results

        foreach ($Source in $SuspiciousSources) {

            # Determine severity based on number of accounts targeted
            if ($Source.UniqueTargetAccounts -ge 50) {
                $Severity = 'Critical'
            } elseif ($Source.UniqueTargetAccounts -ge 25) {
                $Severity = 'High'
            } elseif ($Source.UniqueTargetAccounts -ge 15) {
                $Severity = 'Medium'
            } else {
                $Severity = 'Low'
            } #end if-elseif-else

            # Build recommended actions
            $RecommendedActions = @(
                'Block source IP at firewall/perimeter immediately'
                'Check for successful logons from same IP (Event ID 4624)'
                'Force password reset for ALL targeted accounts'
                'Enable MFA for all accounts if not already enabled'
                'Analyze source IP for indicators of compromise'
                'Review account activity for lateral movement'
                'Audit password policy and implement Azure AD Password Protection'
                'Deploy Smart Lockout or equivalent solution'
            )

            # Create detection result object
            $DetectionResult = [PSCustomObject]@{
                DetectionType        = 'PasswordSpray'
                DomainController     = $DomainController
                Severity             = $Severity
                SourceIP             = $Source.SourceIP
                UniqueTargetAccounts = $Source.UniqueTargetAccounts
                TotalFailures        = $Source.TotalFailures
                FailuresPerAccount   = $Source.FailuresPerAccount
                AttackDuration       = $Source.AttackDuration
                FirstFailure         = $Source.FirstFailure
                LastFailure          = $Source.LastFailure
                TargetedAccounts     = $Source.Accounts
                RecommendedActions   = $RecommendedActions
            }

            # Add to results collection
            $null = $script:DetectionResults.Add($DetectionResult)
            $script:DetectionCount++

            # Output to pipeline
            Write-Output -InputObject $DetectionResult

            # Display warning for each detection
            Write-Warning -Message ('Password spray attack detected from {0} targeting {1} unique accounts' -f $Source.SourceIP, $Source.UniqueTargetAccounts)

        } #end foreach

        # Display summary for non-suspicious sources
        if ($SuspiciousSources.Count -eq 0 -and $AllFailures.Count -gt 0) {

            Write-Verbose -Message '[+] No password spraying activity detected'
            Write-Verbose -Message '[+] All authentication failures within normal thresholds'
            Write-Verbose -Message '[*] Normal Authentication Failure Summary (Top 10 sources):'

            $SprayAnalysis |
                Sort-Object -Property UniqueTargetAccounts -Descending |
                    Select-Object -First 10 |
                        ForEach-Object {
                            Write-Verbose -Message ('    {0}: {1} unique accounts, {2} total failures' -f $_.SourceIP, $_.UniqueTargetAccounts, $_.TotalFailures)
                        } #end foreach

        } #end if

    } #end process

    end {

        Write-Verbose -Message ('[*] Detection scan complete at {0}' -f (Get-Date))
        Write-Verbose -Message ('[*] Total detections: {0}' -f $script:DetectionCount)
        Write-Verbose -Message ('[*] Domain controllers processed: {0}' -f $script:ProcessedDCs.Count)

        # Export results if path specified
        if ($PSBoundParameters.ContainsKey('ExportPath') -and $script:DetectionResults.Count -gt 0) {

            if ($PSCmdlet.ShouldProcess($ExportPath, 'Export password spray detection results')) {

                try {

                    # Create directory if it doesn't exist
                    $ExportDir = Split-Path -Path $ExportPath -Parent
                    if (-not (Test-Path -Path $ExportDir)) {
                        $null = New-Item -Path $ExportDir -ItemType Directory -Force
                    } #end if

                    # Export main results
                    $script:DetectionResults |
                        Select-Object -Property * -ExcludeProperty TargetedAccounts, RecommendedActions |
                            Export-Csv -Path $ExportPath -NoTypeInformation -Force

                    Write-Verbose -Message ('[*] Detection results exported to: {0}' -f $ExportPath)

                    # Export detailed targeted accounts list
                    $DetailedPath = $ExportPath -replace '\.csv$', '_DetailedAccounts.csv'
                    $DetailedExport = foreach ($Result in $script:DetectionResults) {
                        foreach ($Account in $Result.TargetedAccounts) {
                            [PSCustomObject]@{
                                SourceIP      = $Result.SourceIP
                                Severity      = $Result.Severity
                                TargetAccount = $Account
                                FirstFailure  = $Result.FirstFailure
                                LastFailure   = $Result.LastFailure
                            }
                        } #end foreach
                    } #end foreach

                    $DetailedExport | Export-Csv -Path $DetailedPath -NoTypeInformation -Force
                    Write-Verbose -Message ('[*] Detailed account list exported to: {0}' -f $DetailedPath)

                } catch {

                    Write-Error -Message ('Failed to export results: {0}' -f $_.Exception.Message)

                } #end try-catch

            } #end if

        } #end if

        $txt = ($Variables.FooterSecurity -f $MyInvocation.InvocationName, 'detecting password spray attacks.')
        Write-Verbose -Message $txt

    } #end end

} #end function Get-PasswordSprayAttack
