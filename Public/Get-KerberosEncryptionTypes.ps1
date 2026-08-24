function Get-KerberosEncryptionTypes {
    <#
        .SYNOPSIS
            Enumerates Kerberos encryption types configured for AD users and computers.

        .DESCRIPTION
            Reviews the msDS-SupportedEncryptionTypes property for user and computer objects in Active Directory.
            The function maps the underlying bitmask to descriptive Kerberos encryption types and identifies
            whether the object supports insecure options such as RC4_HMAC_MD5. This helps assess Kerberos
            hardening posture and detect legacy configurations that may be vulnerable to downgrade or cracking.

        .PARAMETER ObjectType
            Type of AD object to query. Supported values: User, Computer.

        .PARAMETER DomainController
            Optional domain controller to query. If omitted, the function uses the current domain.

        .PARAMETER IncludeDisabled
            Includes disabled objects in the result set. Default: False.

        .PARAMETER ExportPath
            Optional path to export the results to CSV.

        .INPUTS
            [System.String]
            Accepts the object type name via parameter.

        .OUTPUTS
            [PSCustomObject[]]
            Returns a row per AD object with the supported encryption types, risk classification, and details.

        .EXAMPLE
            Get-KerberosEncryptionTypes -ObjectType 'User'

            Lists Kerberos supported encryption types for all enabled user accounts.

        .EXAMPLE
            Get-KerberosEncryptionTypes -ObjectType 'Computer' -IncludeDisabled

            Reviews computer objects, including disabled ones, for legacy Kerberos encryption exposure.

        .NOTES
            Used Functions:
                Name                              | Module/Namespace
                ----------------------------------|---------------------------
                Get-FunctionDisplay               | EguibarIT.SecurityPS
                Import-MyModule                   | EguibarIT.SecurityPS
                Get-ADUser                        | ActiveDirectory
                Get-ADComputer                    | ActiveDirectory
                Export-Csv                        | Microsoft.PowerShell.Utility
                Get-Date                          | Microsoft.PowerShell.Utility
                Write-Verbose                     | Microsoft.PowerShell.Utility
                Write-Warning                     | Microsoft.PowerShell.Utility

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
            https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/network-security-configure-encryption-types-allowed-for-kerberos

        .COMPONENT
            EguibarIT.SecurityPS

        .ROLE
            Security Auditing

        .FUNCTIONALITY
            Assesses Kerberos encryption settings for Active Directory users and computers.
    #>

    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'Medium'
    )]
    [OutputType([PSCustomObject])]

    param(
        [Parameter(
            Mandatory = $true,
            Position = 0,
            HelpMessage = 'Type of AD object to evaluate. Supported values: User or Computer.'
        )]
        [ValidateSet('User', 'Computer')]
        [string]
        $ObjectType,

        [Parameter(
            Mandatory = $false,
            Position = 1,
            HelpMessage = 'Optional domain controller to query for Kerberos encryption data.'
        )]
        [string]
        $DomainController,

        [Parameter(
            Mandatory = $false,
            Position = 2,
            HelpMessage = 'Include disabled objects in the result set.'
        )]
        [PSDefaultValue(
            Help = 'Disabled objects are excluded by default.',
            Value = $false
        )]
        [bool]
        $IncludeDisabled = $false,

        [Parameter(
            Mandatory = $false,
            Position = 3,
            HelpMessage = 'Optional path to export the results as CSV.'
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

        $CurrentDomainController = $null

        if (-not [string]::IsNullOrWhiteSpace($DomainController)) {
            $CurrentDomainController = $DomainController
        }

        $EncryptionMap = @{
            0x01 = 'DES_CBC_CRC'
            0x02 = 'DES_CBC_MD5'
            0x04 = 'RC4_HMAC_MD5'
            0x08 = 'AES128_HMAC_SHA1_96'
            0x10 = 'AES256_HMAC_SHA1_96'
            0x20 = 'RC4_HMAC_MD5'
            0x40 = 'RC4_HMAC_MD5'
            0x80 = 'RC4_HMAC_MD5'
        }

        $Results = [System.Collections.Generic.List[PSCustomObject]]::new()
    }

    process {
        try {
            if ($ObjectType -eq 'User') {
                if ($null -ne $CurrentDomainController) {
                    $Query = Get-ADUser -Filter * -Properties SamAccountName, Name, Enabled, msDS-SupportedEncryptionTypes -Server $CurrentDomainController -ErrorAction Stop
                } else {
                    $Query = Get-ADUser -Filter * -Properties SamAccountName, Name, Enabled, msDS-SupportedEncryptionTypes -ErrorAction Stop
                }#end if-else
            } else {
                if ($null -ne $CurrentDomainController) {
                    $Query = Get-ADComputer -Filter * -Properties SamAccountName, Name, Enabled, msDS-SupportedEncryptionTypes -Server $CurrentDomainController -ErrorAction Stop
                } else {
                    $Query = Get-ADComputer -Filter * -Properties SamAccountName, Name, Enabled, msDS-SupportedEncryptionTypes -ErrorAction Stop
                } #end if-else
            } #end if-else
        } catch {
            Write-Warning -Message ('Unable to enumerate AD objects of type {0}: {1}' -f $ObjectType, $_.Exception.Message)
            return @()
        } #end try-catch

        foreach ($Object in $Query) {
            if (-not $IncludeDisabled -and $Object.Enabled -eq $false) {
                continue
            }

            $RawValue = $Object.'msDS-SupportedEncryptionTypes'
            if ($null -eq $RawValue) {
                $RawValue = 0
            }

            [int]$SupportedValue = [int]$RawValue
            [System.Collections.Generic.List[string]]$SupportedTypes = [System.Collections.Generic.List[string]]::new()
            [System.Collections.Generic.List[string]]$WeakTypes = [System.Collections.Generic.List[string]]::new()

            foreach ($Entry in $EncryptionMap.GetEnumerator() | Sort-Object Key) {
                if (($SupportedValue -band [int]$Entry.Key) -eq [int]$Entry.Key) {
                    [void]$SupportedTypes.Add($Entry.Value)

                    if ($Entry.Value -match 'RC4|DES') {
                        [void]$WeakTypes.Add($Entry.Value)
                    }
                }
            }

            $WeakEncryptionEnabled = $WeakTypes.Count -gt 0
            if ($WeakEncryptionEnabled) {
                $RiskLevel = 'High'
                $RiskDescription = 'Legacy Kerberos encryption types are enabled.'
            } elseif ($SupportedTypes.Count -eq 0) {
                $RiskLevel = 'Unknown'
                $RiskDescription = 'No supported encryption types were identified.'
            } else {
                $RiskLevel = 'Low'
                $RiskDescription = 'Only modern Kerberos encryption types are enabled.'
            }

            $Finding = [PSCustomObject]@{
                ObjectType               = $ObjectType
                SamAccountName           = $Object.SamAccountName
                DisplayName              = $Object.Name
                Enabled                  = $Object.Enabled
                SupportedEncryptionTypes = @($SupportedTypes)
                WeakEncryptionEnabled    = $WeakEncryptionEnabled
                WeakEncryptionTypes      = @($WeakTypes)
                RiskLevel                = $RiskLevel
                RiskDescription          = $RiskDescription
                RawEncryptionBitmask     = $SupportedValue
                LastReviewed             = (Get-Date)
            }

            [void]$Results.Add($Finding)
        } #end foreach

        if ($PSBoundParameters.ContainsKey('ExportPath') -and -not [string]::IsNullOrWhiteSpace($ExportPath)) {

            if ($PSCmdlet.ShouldProcess($ExportPath, 'Export Kerberos encryption inventory')) {

                $Directory = Split-Path -Path $ExportPath -Parent

                if (-not [string]::IsNullOrWhiteSpace($Directory) -and -not (Test-Path -Path $Directory -PathType Container)) {
                    New-Item -ItemType Directory -Path $Directory -Force | Out-Null
                } #end If

                $Results | Export-Csv -Path $ExportPath -NoTypeInformation

            } #end If

        } #end If

    } #end process

    end {
        Write-Verbose -Message ('Kerberos encryption review completed for {0} objects of type {1}.' -f $Results.Count, $ObjectType)

        if ($null -ne $Variables -and
            $null -ne $Variables.FooterSecurity) {

            $txt = ($Variables.FooterSecurity -f $MyInvocation.InvocationName,
                'finished detecting group policy preferences passwords.'
            )
            Write-Verbose -Message $txt
        } #end If

        return @($Results)

    } #end end
} #end Function Get-KerberosEncryptionTypes
