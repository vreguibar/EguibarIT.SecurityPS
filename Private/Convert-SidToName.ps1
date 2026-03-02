Function Convert-SidToName {

    <#
        .SYNOPSIS
            Converts a Security Identifier (SID) to its corresponding NT Account Name with improved error handling.

        .DESCRIPTION
            This function translates a given Security Identifier (SID) to the corresponding NT Account Name
            using .NET Framework classes. It accepts both string representations of SIDs and SID objects.

            The function first checks against a comprehensive list of Well-Known SIDs before attempting
            dynamic resolution through the Windows API. It implements caching to optimize performance in large
            Active Directory environments where the same SIDs may be repeatedly resolved.

            For improved security and reliability, the function performs thorough validation of input SIDs
            before processing and handles various error conditions that might occur during translation.

            This version has been enhanced with improved error handling to prevent terminating errors
            when dealing with invalid SIDs, which is particularly important in GPO processing contexts.

            The function supports pipeline input, making it suitable for batch processing of SIDs.

        .PARAMETER SID
            The Security Identifier (SID) to convert. This parameter accepts:
            - String representation of a SID (e.g., "S-1-5-32-544")
            - System.Security.Principal.SecurityIdentifier object
            - Any object with a SID property containing either of the above

            This parameter supports pipeline input by value and by property name.

        .EXAMPLE
            Convert-SidToName -SID 'S-1-5-21-3623811015-3361044348-30300820-1013'

            # Output: EguibarIT\davade

            Converts the specified domain SID string to its corresponding NT Account Name.

        .EXAMPLE
            Get-ADUser -Identity davade | Select-Object SID | Convert-SidToName

            Retrieves the SID for user davade from Active Directory and converts it to the corresponding NT Account Name.

        .EXAMPLE
            "S-1-5-32-544" | Convert-SidToName

            # Output: BUILTIN\Administrators

            Converts the Well-Known SID for the Administrators group using pipeline input.

        .INPUTS
            System.String, System.Security.Principal.SecurityIdentifier, Microsoft.ActiveDirectory.Management.ADObject

        .OUTPUTS
            System.String

        .NOTES
            Used Functions:
                Name                                         ║ Module/Namespace
                ═════════════════════════════════════════════╬══════════════════════════════
                Write-Verbose                                ║ Microsoft.PowerShell.Utility
                Write-Warning                                ║ Microsoft.PowerShell.Utility
                Write-Debug                                  ║ Microsoft.PowerShell.Utility
                Write-Error                                  ║ Microsoft.PowerShell.Utility
                Get-Date                                     ║ Microsoft.PowerShell.Utility
                Set-StrictMode                               ║ Microsoft.PowerShell.Utility
                Test-Path                                    ║ Microsoft.PowerShell.Management
                Get-FunctionDisplay                          ║ EguibarIT.SecurityPS
                Test-IsValidSID                              ║ EguibarIT.SecurityPS
                Get-AdWellKnownSID                           ║ EguibarIT.SecurityPS

        .NOTES
            Version:         1.3
            DateModified:    27/May/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
        https://github.com/vreguibar/EguibarIT.SecurityPS/blob/main/Private/Convert-SidToName.ps1

        .COMPONENT
            Active Directory

        .ROLE
            Security

        .FUNCTIONALITY
            SID to Name Conversion, Directory Lookup

    #>

    [CmdletBinding()]
    [OutputType([string])]

    param (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [alias('ID')]
        [object]
        $SID
    )

    Begin {
        Set-StrictMode -Version Latest

        # Display function header if variables exist
        if ($null -ne $Variables -and $null -ne $Variables.HeaderSecurity) {
            $txt = ($Variables.HeaderSecurity -f
                (Get-Date).ToString('dd/MMM/yyyy'),
                $MyInvocation.Mycommand,
                (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
            )
            Write-Verbose -Message $txt
        } #end If

        ##############################
        # Variables Definition        # Static hashtable to cache SID → Name mappings
        if (-not (Test-Path -Path variable:script:SidNameCache)) {
            $script:SidNameCache = @{ }
        } #end If

        # Regex pattern for validating SID format
        $sidRegex = '^S-\d+-\d+(-\d+)*$'

        # Regex pattern for privilege rights keys
        $privilegeKeyRegex = '^Se[A-Za-z]+Privilege$|^Se[A-Za-z]+Right$'
    } #end Begin

    Process {
        $sidValue = $null
        $result = $null

        # Skip processing if input matches privilege key pattern
        if ($SID -is [string] -and
            $SID -match $privilegeKeyRegex) {

            Write-Debug -Message ('Value appears to be a privilege key: {0}, skipping resolution' -f $SID)
            return $null

        } #end if

        # Extract SID string from input
        try {

            if ($SID -is [System.Security.Principal.SecurityIdentifier]) {

                $sidValue = $SID.Value

            } elseif ($SID -is [string]) {

                $sidValue = $SID

            } elseif ($null -ne $SID.ObjectSID) {

                if ($SID.ObjectSID -is [System.Security.Principal.SecurityIdentifier]) {

                    $sidValue = $SID.ObjectSID.Value

                } else {

                    $sidValue = $SID.ObjectSID.ToString()

                } #end if-elseif

            } else {

                # Try to convert to string and check if it's a valid SID pattern
                $sidString = $SID.ToString()

                if ($sidString -match $sidRegex) {

                    $sidValue = $sidString

                } else {

                    Write-Warning -Message ('Cannot extract SID from input object: {0}' -f $SID)
                    return $null

                } #end if-else

            } #end if-elseif-else

        } catch {

            Write-Error -Message ('Error extracting SID value: {0}' -f $_.Exception.Message)
            return $null

        } #end try-catch

        # If no SID extracted, return null
        if ([string]::IsNullOrEmpty($sidValue)) {

            Write-Error -Message 'Extracted SID value is null or empty.'
            return $null

        } #end if

        # Validate SID format
        if (-not ($sidValue -match $sidRegex)) {

            Write-Error -Message ('Invalid SID format: {0}' -f $sidValue)
            return $null

        } #end if

        # Check if result is cached
        if ($script:SidNameCache.ContainsKey($sidValue)) {

            Write-Debug -Message ('Using cached value for SID {0}: {1}' -f $sidValue, $script:SidNameCache[$sidValue])
            return $script:SidNameCache[$sidValue]

        } #end if

        # Check if the SID is a Well-Known SID
        # ToDo: Consider if this block should be at the beginning of the Process block. Early detect a WellKnown sid is good.
        try {

            $wellKnownSid = Get-AdWellKnownSID -SID $sidValue -ErrorAction SilentlyContinue

            if ($null -ne $wellKnownSid) {

                $script:SidNameCache[$sidValue] = $wellKnownSid
                return $wellKnownSid

            } #end if

        } catch {

            Write-Debug -Message ('Error checking Well-Known SIDs: {0}' -f $_.Exception.Message)
            # Continue with other resolution methods

        } #end try-catch

        # Try to resolve SID to name using .NET
        try {

            $sidObj = [System.Security.Principal.SecurityIdentifier]::new($sidValue)
            $ntAccount = $sidObj.Translate([System.Security.Principal.NTAccount])

            if ($null -ne $ntAccount) {

                $result = $ntAccount.Value
                $script:SidNameCache[$sidValue] = $result
                return $result

            } #end if

        } catch [System.Security.Principal.IdentityNotMappedException] {

            Write-Error -Message ('SID {0} cannot be resolved to a name (not found)' -f $sidValue)
            return $null

        } catch {

            Write-Error -Message ('Error translating SID {0}: {1}' -f $sidValue, $_.Exception.Message)
            return $null

        } #end try-catch

        # If all methods fail, return null
        return $null
    } #end Process

    End {
        if ($null -ne $Variables -and
            $null -ne $Variables.FooterSecurity) {

            $txt = ($Variables.FooterSecurity -f $MyInvocation.InvocationName,
                'Converted SID to Name.')
            Write-Verbose -Message $txt
        } #end if
    } #end End
} #end Function Convert-SidToName
