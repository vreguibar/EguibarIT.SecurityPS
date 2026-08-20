function Get-NtlmUsageInventory {
    <#
    .SYNOPSIS
        Inventories NTLM authentication usage and classifies the environment risk.

    .DESCRIPTION
        Reviews NTLM-related Windows Security log events and summarizes observed activity volume,
        source IP addresses, and overall risk. This supports AD hardening review by identifying
        environments that still rely heavily on NTLM for authentication.

    .PARAMETER DomainController
        Optional domain controller to query.

    .PARAMETER DaysBack
        Number of days to review.

    .PARAMETER CheckAllDCs
        If specified, reviews activity across all available domain controllers.

    .PARAMETER ExportPath
        Optional path to export findings as CSV.

    .INPUTS
        [System.String]

    .OUTPUTS
        [System.Management.Automation.PSCustomObject]

    .EXAMPLE
        Get-NtlmUsageInventory -DaysBack 14

        Reviews the last two weeks of NTLM event activity and reports the aggregate risk level.

    .NOTES
        Used Functions:
            Name                         | Module/Namespace
            --------------------------- | ---------------------------
            Get-ADDomainController       | ActiveDirectory
            Get-Date                    | Microsoft.PowerShell.Utility
            Get-WinEvent                | Microsoft.PowerShell.Management
            Export-Csv                  | Microsoft.PowerShell.Utility
            New-Item                    | Microsoft.PowerShell.Management
            Write-Verbose               | Microsoft.PowerShell.Utility
            Write-Warning               | Microsoft.PowerShell.Utility

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
            HelpMessage = 'Number of days to review.'
        )]
        [PSDefaultValue(
            Help = 'Review the previous 30 days of NTLM activity.',
            Value = 30
        )]
        [ValidateRange(1, 365)]
        [int]
        $DaysBack = 30,

        [Parameter(
            Mandatory = $false,
            Position = 2,
            HelpMessage = 'Review NTLM activity across all domain controllers.'
        )]
        [switch]
        $CheckAllDCs,

        [Parameter(
            Mandatory = $false,
            Position = 3,
            HelpMessage = 'Optional path to export findings as CSV.'
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
        [int[]]$EventIds = @(8001, 8002, 8004, 4624, 4625)
        [System.Collections.Generic.List[object]]$Events = [System.Collections.Generic.List[object]]::new()

        Write-Verbose -Message ('Reviewing NTLM activity for the last {0} day(s).' -f $DaysBack)
    }

    process {
        try {
            [System.Collections.Generic.List[string]]$TargetComputers = [System.Collections.Generic.List[string]]::new()

            if ($CheckAllDCs) {
                try {
                    $DomainControllers = Get-ADDomainController -Filter * -ErrorAction Stop
                    foreach ($DomainControllerItem in $DomainControllers) {
                        if (-not [string]::IsNullOrWhiteSpace($DomainControllerItem.HostName)) {
                            [void]$TargetComputers.Add($DomainControllerItem.HostName)
                        }
                    }
                } catch {
                    Write-Verbose -Message 'Unable to enumerate all domain controllers; falling back to the current target.'
                }
            }

            if (-not [string]::IsNullOrWhiteSpace($DomainController)) {
                $TargetComputers = [System.Collections.Generic.List[string]]::new()
                [void]$TargetComputers.Add($DomainController)
            }

            if ($TargetComputers.Count -eq 0) {
                [void]$TargetComputers.Add($env:COMPUTERNAME)
            }

            foreach ($TargetComputer in $TargetComputers) {
                $CurrentEvents = Get-WinEvent -ComputerName $TargetComputer -LogName 'Security' -MaxEvents 5000 -ErrorAction Stop |
                    Where-Object {
                        $_.TimeCreated -ge $WindowStart -and
                        ($_.Id -in $EventIds -or $_.Message -match 'NTLM')
                    }

                foreach ($item in $CurrentEvents) {
                    [void]$Events.Add($item)
                }
            }
        } catch {
            Write-Warning -Message ('Unable to inventory NTLM events: {0}' -f $_.Exception.Message)
            return [PSCustomObject]([ordered]@{
                    TotalEvents     = 0
                    UniqueSourceIPs = @()
                    RiskLevel       = 'Low'
                    Summary         = 'No NTLM event data was available for the selected time window.'
                    CollectedAt     = (Get-Date)
                })
        }

        [System.Collections.Generic.List[string]]$UniqueSourceIps = [System.Collections.Generic.List[string]]::new()

        foreach ($item in $Events) {
            foreach ($IpAddress in [regex]::Matches($item.Message, '\b(?:\d{1,3}\.){3}\d{1,3}\b')) {
                if (-not $UniqueSourceIps.Contains($IpAddress.Value)) {
                    [void]$UniqueSourceIps.Add($IpAddress.Value)
                }
            }
        }

        [int]$EventCount = $Events.Count

        if ($EventCount -ge 100) {
            $RiskLevel = 'High'
        } elseif ($EventCount -ge 20) {
            $RiskLevel = 'Medium'
        } else {
            $RiskLevel = 'Low'
        }

        $Report = [PSCustomObject]([ordered]@{
                TotalEvents     = $EventCount
                UniqueSourceIPs = @($UniqueSourceIps)
                RiskLevel       = $RiskLevel
                Summary         = 'Inventory completed for the selected NTLM activity window.'
                CollectedAt     = (Get-Date)
            })

        if (-not [string]::IsNullOrWhiteSpace($ExportPath)) {

            if ($PSCmdlet.ShouldProcess($ExportPath, 'Export NTLM inventory summary to CSV')) {

                $Directory = Split-Path -Path $ExportPath -Parent

                if (-not [string]::IsNullOrWhiteSpace($Directory) -and -not (Test-Path -Path $Directory)) {

                    New-Item -Path $Directory -ItemType Directory -Force | Out-Null

                } #end if

                $Report | Export-Csv -Path $ExportPath -NoTypeInformation -Force

            } #end if

        } #end if

        return $Report
    } #end process

    end {
        Write-Verbose -Message ('NTLM inventory complete. {0} event(s) reviewed.' -f $Events.Count)

        if ($null -ne $Variables -and
            $null -ne $Variables.FooterSecurity) {

            $txt = ($Variables.FooterSecurity -f $MyInvocation.InvocationName,
                'finished detecting group policy preferences passwords.'
            )
            Write-Verbose -Message $txt
        } #end If
    } #end end

} #end Function Get-NtlmUsageInventory
