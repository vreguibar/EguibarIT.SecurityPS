function Get-ZeroLogon {
    <#
    .SYNOPSIS
        Audits for ZeroLogon (CVE-2020-1472) indicators and suspicious Netlogon activity.

    .DESCRIPTION
        Reviews Windows Security log entries and Netlogon-related messages that are consistent with the
        ZeroLogon attack path or abuse of the Netlogon secure channel. This is a read-only detection
        function intended for Active Directory security review and hunting workflows.

    .PARAMETER DomainController
        Optional domain controller to query for event data.

    .PARAMETER DaysBack
        Number of days of event history to review.

    .PARAMETER ExportPath
        Optional CSV export path.

    .INPUTS
        [System.String]

    .OUTPUTS
        [System.Management.Automation.PSCustomObject]

    .EXAMPLE
        Get-ZeroLogon -DaysBack 7

        Reviews the last 7 days of Netlogon and recent logon events for ZeroLogon indicators.

    .NOTES
        Used Functions:
            Name                  | Module/Namespace
            --------------------- | ---------------------------
            Get-Date              | Microsoft.PowerShell.Utility
            Get-WinEvent          | Microsoft.PowerShell.Management
            Export-Csv            | Microsoft.PowerShell.Utility
            New-Item              | Microsoft.PowerShell.Management
            Write-Verbose         | Microsoft.PowerShell.Utility
            Write-Warning         | Microsoft.PowerShell.Utility

        Version:         1.0.0
        DateModified:    20/Aug/2026
        LastModifiedBy:  Vicente R. Eguibar

        Component: EguibarIT.SecurityPS
    #>

    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'Medium'
    )]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(
            Mandatory = $false,
            Position = 0,
            HelpMessage = 'Optional domain controller to query.'
        )]
        [string]
        $DomainController,

        [Parameter(
            Mandatory = $false,
            Position = 1,
            HelpMessage = 'Number of days of event history to review.'
        )]
        [PSDefaultValue(
            Help = 'Review the previous 30 days of event history.',
            Value = 30
        )]
        [ValidateRange(1, 365)]
        [int]
        $DaysBack = 30,

        [Parameter(
            Mandatory = $false,
            Position = 2,
            HelpMessage = 'Optional CSV export path.'
        )]
        [string]
        $ExportPath
    )

    begin {
        Set-StrictMode -Version Latest

        if ($null -ne $Variables -and $null -ne $Variables.HeaderSecurity) {
            $HeaderText = ($Variables.HeaderSecurity -f
                (Get-Date).ToString('dd/MMM/yyyy'),
                $MyInvocation.MyCommand,
                (Get-FunctionDisplay -Hashtable $PSBoundParameters -Verbose:$False)
            )
            Write-Verbose -Message $HeaderText
        }

        [datetime]$WindowStart = (Get-Date).AddDays(-$DaysBack)
        [System.Collections.Generic.List[object]]$Events = [System.Collections.Generic.List[object]]::new()
        [int[]]$EventIds = @(4624, 4625, 4771, 4740)

        Write-Verbose -Message ('Reviewing ZeroLogon indicators for the last {0} day(s).' -f $DaysBack)
    }

    process {
        try {
            [System.Collections.Generic.List[string]]$TargetComputers = [System.Collections.Generic.List[string]]::new()

            if (-not [string]::IsNullOrWhiteSpace($DomainController)) {
                [void]$TargetComputers.Add($DomainController)
            }

            if ($TargetComputers.Count -eq 0) {
                [void]$TargetComputers.Add($env:COMPUTERNAME)
            }

            foreach ($TargetComputer in $TargetComputers) {
                $CurrentEvents = Get-WinEvent -ComputerName $TargetComputer -LogName 'Security' -MaxEvents 5000 -ErrorAction Stop |
                    Where-Object {
                        $_.TimeCreated -ge $WindowStart -and
                        ($_.Id -in $EventIds -or $_.Message -match 'Netlogon|NetrLogon|ZeroLogon')
                    }

                foreach ($Event in $CurrentEvents) {
                    [void]$Events.Add($Event)
                }
            }
        } catch {
            Write-Warning -Message ('Unable to review ZeroLogon indicators: {0}' -f $_.Exception.Message)
            return [PSCustomObject]([ordered]@{
                    TotalEvents          = 0
                    RiskLevel            = 'Low'
                    HasSuspiciousPattern = $false
                    Summary              = 'No Netlogon/ZeroLogon event data was available.'
                    CollectedAt          = (Get-Date)
                })
        }

        [int]$EventCount = $Events.Count
        [System.Collections.Generic.List[object]]$SuspiciousEvents = [System.Collections.Generic.List[object]]::new()

        foreach ($Event in $Events) {
            if ($Event.Message -match 'Netlogon|NetrLogon|ZeroLogon') {
                [void]$SuspiciousEvents.Add($Event)
            }
        }

        [bool]$HasSuspiciousPattern = $SuspiciousEvents.Count -gt 0

        if ($HasSuspiciousPattern -and $EventCount -gt 0) {
            $RiskLevel = 'Critical'
        } elseif ($EventCount -gt 0) {
            $RiskLevel = 'Medium'
        } else {
            $RiskLevel = 'Low'
        }

        $Report = [PSCustomObject]([ordered]@{
                TotalEvents          = $EventCount
                RiskLevel            = $RiskLevel
                HasSuspiciousPattern = $HasSuspiciousPattern
                Summary              = if ($HasSuspiciousPattern) {
                    'Suspicious Netlogon/ZeroLogon indicators were observed.'
                } else {
                    'No suspicious ZeroLogon indicators were identified in the selected window.'
                }
                CollectedAt          = (Get-Date)
            })

        if (-not [string]::IsNullOrWhiteSpace($ExportPath)) {
            if ($PSCmdlet.ShouldProcess($ExportPath, 'Export ZeroLogon review to CSV')) {
                $Directory = Split-Path -Path $ExportPath -Parent
                if (-not [string]::IsNullOrWhiteSpace($Directory) -and -not (Test-Path -Path $Directory)) {
                    New-Item -Path $Directory -ItemType Directory -Force | Out-Null
                }
                $Report | Export-Csv -Path $ExportPath -NoTypeInformation -Force
            }
        }

        return $Report
    }

    end {
        Write-Verbose -Message ('ZeroLogon review completed for {0} event(s).' -f $Events.Count)

        if ($null -ne $Variables -and
            $null -ne $Variables.FooterSecurity) {

            $txt = ($Variables.FooterSecurity -f $MyInvocation.InvocationName,
                'finished detecting group policy preferences passwords.'
            )
            Write-Verbose -Message $txt
        } #end If
    }
}
#end Function Get-ZeroLogon
