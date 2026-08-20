function Get-LapsPasswordRetrieval {

    <#
    .SYNOPSIS
        Audits Active Directory computer objects for LAPS password exposure and local admin credential visibility.

    .DESCRIPTION
        Enumerates AD computer objects and inspects the ms-Mcs-AdmPwd attribute to determine whether local administrator
        passwords are present in Active Directory. The function summarizes inventory for review and optionally exports
        the findings as a CSV file. It supports ShouldProcess semantics to safely preview export operations before writing
        data to disk.

    .PARAMETER DomainController
        Optional domain controller name or FQDN to query instead of the default controller discovered by the current
        session. Use this when validating a specific DC or when targeting a read-only domain controller.

    .PARAMETER DaysBack
        Number of days to evaluate when reviewing the AD inventory window for LAPS exposure. Valid values are between
        1 and 365 inclusive. The default is 30 days.

    .PARAMETER ExportPath
        Optional destination path for CSV export. If specified, the function creates the parent directory when needed
        and writes the current result set to disk. The export respects the -WhatIf and -Confirm parameters.

    .INPUTS
        None. This function does not accept pipeline input by default.

    .OUTPUTS
        [System.Management.Automation.PSCustomObject[]]

        Each output object contains:
        - ComputerName
        - DistinguishedName
        - Enabled
        - LAPSStatus
        - PasswordAvailable
        - WhenCreated
        - RiskLevel
        - RecommendedAction

    .EXAMPLE
        Get-LapsPasswordRetrieval

        Reviews the current AD computer inventory for LAPS password exposure using the default 30-day window.

    .EXAMPLE
        Get-LapsPasswordRetrieval -DaysBack 90 -DomainController 'DC01.eguibarit.com'

        Reviews computers in the context of a specific domain controller over the previous 90 days.

    .EXAMPLE
        Get-LapsPasswordRetrieval -ExportPath 'C:\Security\LapsInventory.csv'

        Exports the discovered LAPS inventory to a CSV file after creating the parent folder if it does not exist.

    .EXAMPLE
        Get-LapsPasswordRetrieval -ExportPath 'C:\Security\LapsInventory.csv' -WhatIf

        Shows what the function would export without writing any data to disk.

    .NOTES
        Used Functions:
            Name                  | Module/Namespace
            --------------------- | ---------------------------
            Get-ADComputer        | ActiveDirectory
            Get-Date              | Microsoft.PowerShell.Utility
            Export-Csv            | Microsoft.PowerShell.Utility
            New-Item              | Microsoft.PowerShell.Management
            Split-Path            | Microsoft.PowerShell.Management
            Test-Path             | Microsoft.PowerShell.Management
            Write-Verbose         | Microsoft.PowerShell.Utility
            Write-Warning         | Microsoft.PowerShell.Utility
            Get-FunctionDisplay   | EguibarIT.SecurityPS (Private)

    .NOTES
        Version:         1.0.1
        DateModified:    20/Aug/2026
        LastModifiedBy:  Vicente R. Eguibar
                vicente@eguibarit.com
                Eguibar IT
                http://www.eguibarit.com

    .LINK
        https://github.com/vreguibar/EguibarIT.SecurityPS

    .LINK
        https://learn.microsoft.com/windows-server/identity/laps/laps-overview

    .LINK
        https://learn.microsoft.com/powershell/module/addsadministration/get-adcomputer

    .COMPONENT
        EguibarIT.SecurityPS

    .ROLE
        Security Auditor, Penetration Tester, Security Operations

    .FUNCTIONALITY
        Active Directory Security Auditing, LAPS Password Exposure Assessment

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
            Position = 0,
            HelpMessage = 'Optional domain controller name or FQDN to query.'
        )]
        [ValidateNotNullOrEmpty()]
        [string]
        $DomainController,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            Position = 1,
            HelpMessage = 'Number of days to evaluate in the AD inventory window (1-365).'
        )]
        [PSDefaultValue(
            Help = 'Default: 30 days',
            Value = 30
        )]
        [ValidateRange(1, 365)]
        [int]
        $DaysBack = 30,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            Position = 2,
            HelpMessage = 'Optional path to export the results as CSV.'
        )]
        [ValidateNotNullOrEmpty()]
        [Alias('Path', 'OutputPath')]
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

        Write-Verbose -Message 'GPP Password Discovery & Decryption | MITRE ATT&CK T1552.006'

        ##############################
        # Module imports

        Import-MyModule -ModuleName 'ActiveDirectory'

        ##############################
        # Variables Definition

        [System.Collections.Generic.List[PSCustomObject]]$Results = [System.Collections.Generic.List[PSCustomObject]]::new()

        Write-Verbose -Message ('Reviewing LAPS inventory for the last {0} day(s).' -f $DaysBack)
    }

    process {
        try {
            $QueryParameters = @{
                Filter      = '*'
                Properties  = @('Name', 'Enabled', 'WhenCreated', 'ms-Mcs-AdmPwd', 'DistinguishedName')
                ErrorAction = 'Stop'
            }

            if (-not [string]::IsNullOrWhiteSpace($DomainController)) {
                $QueryParameters.Server = $DomainController
            }

            $Computers = Get-ADComputer @QueryParameters
        } catch {
            Write-Warning -Message ('Unable to enumerate computer objects for LAPS validation: {0}' -f $_.Exception.Message)
            return @()
        }

        foreach ($Computer in $Computers) {
            [bool]$HasLapsPassword = -not [string]::IsNullOrWhiteSpace($Computer.'ms-Mcs-AdmPwd')
            $Status = if ($HasLapsPassword) {
                'Enabled'
            } else {
                'NotConfigured'
            }

            $DistinguishedName = if ($Computer.PSObject.Properties.Name -contains 'DistinguishedName') {
                $Computer.DistinguishedName
            } else {
                $null
            }

            $WhenCreated = if ($Computer.PSObject.Properties.Name -contains 'WhenCreated') {
                $Computer.WhenCreated
            } else {
                $null
            }

            $RiskLevel = if ($HasLapsPassword) {
                'Medium'
            } else {
                'Low'
            }

            [PSCustomObject]$Entry = [PSCustomObject]@{
                ComputerName      = $Computer.Name
                DistinguishedName = $DistinguishedName
                Enabled           = $Computer.Enabled
                LAPSStatus        = $Status
                PasswordAvailable = $HasLapsPassword
                WhenCreated       = $WhenCreated
                RiskLevel         = $RiskLevel
                RecommendedAction = 'Verify whether LAPS is intended and review local admin password rotation policy.'
            }

            [void]$Results.Add($Entry)
        }

        if (-not [string]::IsNullOrWhiteSpace($ExportPath)) {

            if ($PSCmdlet.ShouldProcess($ExportPath, 'Export LAPS inventory to CSV')) {

                $Directory = Split-Path -Path $ExportPath -Parent

                if (-not [string]::IsNullOrWhiteSpace($Directory) -and -not (Test-Path -Path $Directory)) {
                    New-Item -Path $Directory -ItemType Directory -Force | Out-Null
                } #end if

                $Results | Export-Csv -Path $ExportPath -NoTypeInformation -Force

            } #end if

        } #end if
    } #end process

    end {

        if ($null -ne $Variables -and
            $null -ne $Variables.FooterSecurity) {

            $txt = ($Variables.FooterSecurity -f $MyInvocation.InvocationName,
                'finished detecting group policy preferences passwords.'
            )
            Write-Verbose -Message $txt
        } #end If

        return @($Results)

    } #end end
} #end Function Get-LapsPasswordRetrieval
