function Get-AdKerberosPacValidation {
    <#
        .SYNOPSIS
            Identifies Kerberos service tickets that indicate PAC validation failures or suspicious authorization data handling.

        .DESCRIPTION
            Reviews Kerberos security events (Event ID 4769) on a domain controller and identifies service ticket
            requests where the PAC could not be validated or where status codes suggest a forged or tampered ticket.
            This supports detection of Kerberos PAC manipulation, service-side validation failures, and suspicious
            privilege escalation activity where a service may have received unverifiable authorization data.

            The function focuses on the Kerberos PAC validation workflow described in MS-KILE and the Microsoft
            Active Directory Security guidance. It is designed to highlight PAC tampering indicators without
            relying on administrative assumptions, and it supports optional CSV export for incident triage.

        .PARAMETER DomainController
            Domain controller to query. If omitted, the function attempts to discover an available controller.

        .PARAMETER TimeSpanMinutes
            Number of minutes to examine in the Security log. Default: 60 minutes.

        .PARAMETER MinimumIssueCount
            Minimum number of PAC-related issues required before the function returns findings. Default: 1.

        .PARAMETER ServiceName
            Optional service name filter, such as LDAP, CIFS, or MSSQLSvc.

        .PARAMETER ExportPath
            Optional path for exporting PAC validation findings to CSV.

        .INPUTS
            [System.String]
            Accepts domain controller names via pipeline.

        .OUTPUTS
            [PSCustomObject[]]
            Returns PAC validation findings with event metadata, validation status, and recommended actions.

        .EXAMPLE
            Get-AdKerberosPacValidation -DomainController 'DC01' -TimeSpanMinutes 60

            Reviews the last 60 minutes of Event ID 4769 entries and returns Kerberos PAC validation findings.

        .EXAMPLE
            Get-AdKerberosPacValidation -DomainController 'DC01' -ServiceName 'LDAP' -ExportPath 'C:\Security\PACValidation.csv'

            Filters ticket results for the LDAP service and exports suspicious findings to CSV.

        .NOTES
            Used Functions:
                Name                           | Module/Namespace
                -------------------------------|-----------------------------
                Get-FunctionDisplay            | EguibarIT.SecurityPS
                Set-StrictMode                 | PowerShell Core
                Get-ADDomainController         | ActiveDirectory
                Get-WinEvent                   | Microsoft.PowerShell.Diagnostics
                Export-Csv                     | Microsoft.PowerShell.Utility
                Get-Date                       | Microsoft.PowerShell.Utility
                Write-Verbose                  | Microsoft.PowerShell.Utility
                Write-Warning                  | Microsoft.PowerShell.Utility
                New-Item                       | Microsoft.PowerShell.Management

        .NOTES
            Version:         1.0.0
            DateModified:    19/Aug/2026
            LastModifiedBy:  Vicente R. Eguibar
                vicente@eguibarit.com
                Eguibar IT
                http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT.SecurityPS

        .LINK
            https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/2a32282e-dd48-4ad9-a542-609804b02cc9

        .LINK
            https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-apds/a00d0b83-97e3-44ad-ba2d-1221d4f51a35#gt_26456104-0afb-4afe-a92e-ac160a9efdf8

        .COMPONENT
            EguibarIT.SecurityPS

        .ROLE
            Security Auditing

        .FUNCTIONALITY
            Identifies PAC validation failures and suspicious Kerberos ticket activity in Active Directory.
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
            HelpMessage = 'Domain controller to query for Kerberos service ticket events.'
        )]
        [ValidateNotNullOrEmpty()]
        [Alias('DC', 'Server', 'HostName', 'Name')]
        [string]
        $DomainController,

        [Parameter(
            Mandatory = $false,
            Position = 1,
            HelpMessage = 'Number of minutes to look back in the Security log.'
        )]
        [ValidateRange(1, 10080)]
        [PSDefaultValue(
            Help = 'Default lookback window is 60 minutes.',
            Value = 60
        )]
        [int]
        $TimeSpanMinutes = 60,

        [Parameter(
            Mandatory = $false,
            Position = 2,
            HelpMessage = 'Minimum number of PAC-related issues required before returning findings.'
        )]
        [ValidateRange(1, 1000)]
        [PSDefaultValue(
            Help = 'Default minimum issue count is 1.',
            Value = 1
        )]
        [int]
        $MinimumIssueCount = 1,

        [Parameter(
            Mandatory = $false,
            Position = 3,
            HelpMessage = 'Optional service name filter, such as LDAP, CIFS, or MSSQLSvc.'
        )]
        [string]
        $ServiceName,

        [Parameter(
            Mandatory = $false,
            Position = 4,
            HelpMessage = 'Optional path to export PAC validation findings to CSV.'
        )]
        [string]
        $ExportPath
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

        ##############################
        # Variables Definition

        if (-not $PSBoundParameters.ContainsKey('DomainController') -or [string]::IsNullOrWhiteSpace($DomainController)) {
            try {
                $DiscoveredController = Get-ADDomainController -Discover -ErrorAction Stop
                $DomainController = $DiscoveredController.HostName
                if ([string]::IsNullOrWhiteSpace($DomainController)) {
                    $DomainController = $DiscoveredController.Name
                }
            } catch {
                Write-Warning -Message 'Unable to discover a domain controller automatically. Use -DomainController to specify one.'
                return @()
            }
        }

        $StartTime = (Get-Date).AddMinutes(-$TimeSpanMinutes)
        $EndTime = Get-Date

        $Findings = [System.Collections.ArrayList]::new()
    }

    process {
        $Query = @{
            LogName   = 'Security'
            Id        = 4769
            StartTime = $StartTime
            EndTime   = $EndTime
        }

        try {
            $Events = Get-WinEvent -ComputerName $DomainController -FilterHashtable $Query -ErrorAction Stop
        } catch {
            Write-Warning -Message ('Unable to read Kerberos service ticket events from {0}: {1}' -f $DomainController, $_.Exception.Message)
            return @()
        }

        foreach ($Event in $Events) {
            $Xml = [xml]$Event.ToXml()
            $Data = @{}

            foreach ($Node in $Xml.GetElementsByTagName('Data')) {
                if (-not [string]::IsNullOrWhiteSpace($Node.Name)) {
                    $Data[$Node.Name] = $Node.InnerText
                }
            }

            $TargetUserName = if ($Data.ContainsKey('TargetUserName')) {
                $Data['TargetUserName']
            } else {
                ''
            }
            $TicketService = if ($Data.ContainsKey('ServiceName')) {
                $Data['ServiceName']
            } else {
                ''
            }
            $StatusCode = if ($Data.ContainsKey('Status')) {
                $Data['Status']
            } else {
                'Unknown'
            }
            $TicketType = if ($Data.ContainsKey('TicketEncryptionType')) {
                $Data['TicketEncryptionType']
            } else {
                'Unknown'
            }
            $ClientIp = if ($Data.ContainsKey('IpAddress')) {
                $Data['IpAddress']
            } else {
                'Unknown'
            }

            if (-not [string]::IsNullOrWhiteSpace($ServiceName) -and $TicketService -notlike "*$ServiceName*") {
                continue
            }

            $IsFailure = $false
            $ValidationState = 'Success'
            $Severity = 'Low'
            $Details = 'Kerberos ticket was accepted and the PAC validation result was not flagged.'
            $RecommendedActions = @(
                'Continue monitoring for additional Kerberos ticket anomalies.',
                'Review the service account and ticket request activity for unexpected access patterns.'
            )

            switch ($StatusCode) {
                '0x0' {
                    $ValidationState = 'Success'
                    $Severity = 'Low'
                    $Details = 'PAC validation succeeded and the ticket status is normal.'
                }
                '0x1F' {
                    $IsFailure = $true
                    $ValidationState = 'Failure'
                    $Severity = 'Critical'
                    $Details = 'Kerberos service ticket indicates a PAC validation failure or rejected authorization data.'
                    $RecommendedActions = @(
                        'Investigate the service ticket for PAC tampering or forged Kerberos data.',
                        'Review the service account, user account, and ticket source IP for unauthorized access attempts.',
                        'Validate Kerberos PAC enforcement and rotate affected credentials if tampering is confirmed.'
                    )
                }
                default {
                    if (-not [string]::IsNullOrWhiteSpace($StatusCode) -and $StatusCode -ne 'Unknown') {
                        $IsFailure = $true
                        $ValidationState = 'Failure'
                        $Severity = 'High'
                        $Details = ('Kerberos ticket returned an unexpected status code ({0}) that may indicate PAC validation issues.' -f $StatusCode)
                        $RecommendedActions = @(
                            'Review the ticket status code for Kerberos or PAC validation issues.',
                            'Validate the source service and client identity before granting additional access.',
                            'Check for ticket tampering, service account compromise, or stale Kerberos cache data.'
                        )
                    }
                }
            }

            if ($IsFailure -or $ValidationState -eq 'Failure') {
                $Finding = [PSCustomObject]@{
                    TimeCreated          = $Event.TimeCreated
                    DomainController     = $DomainController
                    TargetUserName       = $TargetUserName
                    ServiceName          = $TicketService
                    TicketEncryptionType = $TicketType
                    StatusCode           = $StatusCode
                    ClientIPAddress      = $ClientIp
                    ValidationState      = $ValidationState
                    Severity             = $Severity
                    Details              = $Details
                    RecommendedActions   = $RecommendedActions
                }

                [void]$Findings.Add($Finding)
            }
        }

        if ($Findings.Count -ge $MinimumIssueCount) {
            if ($PSBoundParameters.ContainsKey('ExportPath') -and -not [string]::IsNullOrWhiteSpace($ExportPath)) {
                $ExportDirectory = Split-Path -Path $ExportPath -Parent
                if (-not [string]::IsNullOrWhiteSpace($ExportDirectory) -and -not (Test-Path -Path $ExportDirectory -PathType Container)) {
                    if ($PSCmdlet.ShouldProcess($ExportPath, 'Export PAC validation findings')) {
                        New-Item -ItemType Directory -Path $ExportDirectory -Force -ErrorAction Stop | Out-Null
                    }
                }

                if ($PSCmdlet.ShouldProcess($ExportPath, 'Export PAC validation findings')) {
                    $Findings | Export-Csv -Path $ExportPath -NoTypeInformation
                }
            }

            return @($Findings)
        }

        return @()
    }

    end {
        Write-Verbose -Message ('Completed PAC validation review for {0}. Findings: {1}' -f $DomainController, $Findings.Count)

        if ($null -ne $Variables -and
            $null -ne $Variables.FooterSecurity) {

            $txt = ($Variables.FooterSecurity -f $MyInvocation.InvocationName,
                'finished detecting group policy preferences passwords.'
            )
            Write-Verbose -Message $txt
        } #end If
    }
}
#end Function Get-AdKerberosPacValidation
