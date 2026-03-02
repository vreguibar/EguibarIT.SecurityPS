function Test-IsValidGUID {
    <#
        .SYNOPSIS
            Validates if the input string is a valid Global Unique Identifier (GUID).

        .DESCRIPTION
            This function validates whether a provided string conforms to the standard
            format of a Global Unique Identifier (GUID). It uses a regular expression
            pattern from the module's constants to perform the validation.

            GUIDs are 128-bit identifiers that are guaranteed to be unique across all devices
            and time. They are widely used in Active Directory for identifying schema objects,
            attributes, and class definitions.

            This function is particularly useful when working with Active Directory schema
            operations, extended rights, and property sets that are identified by GUIDs.

            The function can be used:
            - As a standalone validator
            - As part of a ValidateScript attribute in parameter validation
            - Within other functions that need to verify GUID inputs

        .PARAMETER ObjectGUID
            The GUID string to validate. Must be in the standard format:
            "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

            Where each 'x' represents a hexadecimal digit (0-9, a-f, A-F).

            Total length is 36 characters including hyphens in the specified positions.

        .EXAMPLE
            Test-IsValidGUID -ObjectGUID '550e8400-e29b-41d4-a716-446655440000'

            Returns $true as this is a valid GUID format.

        .EXAMPLE
            '550e8400-e29b-41d4-a716-446655440000' | Test-IsValidGUID

            Shows pipeline input usage. Returns $true.

        .EXAMPLE
            Test-IsValidGUID -ObjectGUID 'invalid-guid'

            Returns $false as this is not a valid GUID format.

        .EXAMPLE
            function Set-SchemaAttribute {
                param (
                    [ValidateScript({ Test-IsValidGUID -ObjectGUID $_ })]
                    [string]$AttributeGUID
                )
                # Function implementation
            }

            Shows how to use the function as a validation script in parameter attributes.

        .INPUTS
            System.String

            You can pipe a string representing a GUID to this function.

        .OUTPUTS
            System.Boolean

            Returns $true if the input is a valid GUID, $false otherwise.

        .NOTES
            Used Functions:
                Name                                       ║ Module/Namespace
                ═══════════════════════════════════════════╬══════════════════════════════
                Write-Verbose                              ║ Microsoft.PowerShell.Utility
                Write-Error                                ║ Microsoft.PowerShell.Utility
                Write-Debug                                ║ Microsoft.PowerShell.Utility

        .NOTES
            Version:         2.0
            DateModified:    22/May/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT.SecurityPS

        .LINK
            https://learn.microsoft.com/en-us/dotnet/api/system.guid

        .COMPONENT
            Active Directory

        .ROLE
            Security

        .FUNCTIONALITY
            Identity Validation
    #>

    [CmdletBinding(ConfirmImpact = 'Low',
        SupportsShouldProcess = $false)]
    [OutputType([bool])]

    param (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'String to be validated as Global Unique Identifier (GUID)',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('GUID', 'GlobalUniqueIdentifier', 'Id')]
        [string]
        $ObjectGUID
    )

    begin {

        Set-StrictMode -Version Latest

        ##############################
        # Module imports

        ##############################
        # Variables Definition

        [bool]$isValid = $false

        Write-Debug 'Begin block: Regex pattern for GUID validation initialized.'

    } #end Begin

    process {

        try {

            # Perform the actual validation
            #$isValid = $ObjectDN -match $distinguishedNameRegex
            $isValid = $ObjectGUID -match $Constants.GuidRegEx

            Write-Verbose -Message ('GUID validation result: {0}' -f $isValid)

        } catch {

            # Handle exceptions gracefully
            Write-Error -Message 'Error when validating GUID'

        } #end Try-Catch

    } #end Process

    end {
        return $isValid
    } #end End
} #end Function Test-IsValidGUID
