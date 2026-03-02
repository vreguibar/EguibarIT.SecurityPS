function Convert-GUIDToName {
    <#
        .SYNOPSIS
            Converts a GUID to its corresponding Active Directory object name.

        .DESCRIPTION
            This function converts a GUID (Globally Unique Identifier) into its corresponding
            human-readable display name in Active Directory. It supports translating GUIDs for
            classSchema objects, attributeSchema objects, and extended rights.

            The function first checks if the provided GUID is a null GUID. If not, it searches the
            schema naming context for a matching schemaIDGUID. If found, it determines whether it's
            a classSchema or attributeSchema object and formats the output accordingly. If not found
            in the schema, it checks the Extended-Rights container in the configuration naming context.

            This function is particularly useful for interpreting security descriptors and ACLs where
            GUIDs are used to reference schema objects or extended rights.

        .PARAMETER Guid
            The GUID to be translated into a display name. It must be a valid GUID format.
            This parameter accepts pipeline input.

        .EXAMPLE
            Convert-GUIDToName -Guid "bf967aba-0de6-11d0-a285-00aa003049e2"

            Output: user [classSchema]

            Converts the specified GUID to its display name in Active Directory.

        .EXAMPLE
            "bf967a86-0de6-11d0-a285-00aa003049e2" | Convert-GUIDToName

            Output: computer [classSchema]

            Converts the specified GUID to its display name using pipeline input.

        .EXAMPLE
            $Splat = @{
                GUID = 'bf967aba-0de6-11d0-a285-00aa003049e2'
                Verbose = $true
            }
            Convert-GUIDToName @Splat

            Output with verbose information about the conversion process.

        .EXAMPLE
            ---------- Class Schema
            Convert-GUIDToName -Guid "bf967a86-0de6-11d0-a285-00aa003049e2" # computer
            Convert-GUIDToName -Guid "bf967a9c-0de6-11d0-a285-00aa003049e2" # group
            Convert-GUIDToName -Guid "b7b13124-b82e-11d0-afee-0000f80367c1" # subnet
            Convert-GUIDToName -Guid "bf967aba-0de6-11d0-a285-00aa003049e2" # user

            ---------- Attribute Schema
            Convert-GUIDToName -Guid "bf967915-0de6-11d0-a285-00aa003049e2" # AccountExpires
            Convert-GUIDToName -Guid "f0f8ff84-1191-11d0-a060-00aa006c33ed" # StreetAddress (attributeSchema)
            Convert-GUIDToName -Guid "bf96793e-0de6-11d0-a285-00aa003049e2" # Comment
            Convert-GUIDToName -Guid "bf967950-0de6-11d0-a285-00aa003049e2" # Description
            Convert-GUIDToName -Guid "bf967962-0de6-11d0-a285-00aa003049e2" # Employee-ID
            Convert-GUIDToName -Guid "bf9679b5-0de6-11d0-a285-00aa003049e2" # Manager
            Convert-GUIDToName -Guid "8d3bca50-1d7e-11d0-a081-00aa006c33ed" # Picture
            Convert-GUIDToName -Guid "3e0abfd0-126a-11d0-a060-00aa006c33ed" # SamAccountName

            ---------- Extended Rights
            Convert-GUIDToName -Guid "68b1d179-0d15-4d4f-ab71-46152e79a7bc" # Allowed to Authenticate [Extended Right]
            Convert-GUIDToName -Guid "ba33815a-4f93-4c76-87f3-57574bff8109" # Migrate SID History [Extended Right]
            Convert-GUIDToName -Guid "00299570-246d-11d0-a768-00aa006e0529" # Reset Password [Extended Right]
            Convert-GUIDToName -Guid "ab721a53-1e2f-11d0-9819-00aa0040529b" # Change Password [Extended Right]
            Convert-GUIDToName -Guid "59ba2f42-79a2-11d0-9020-00c04fc2d3cf" # General Information [Extended Right]
            Convert-GUIDToName -Guid "5f202010-79a5-11d0-9020-00c04fc2d4cf" # Logon Information [Property Set]
            Convert-GUIDToName -Guid "77b5b886-944a-11d1-aebd-0000f80367c1" # Personal Information [Property Set]
            Convert-GUIDToName -Guid "4c164200-20c0-11d0-a768-00aa006e0529" # Account Restrictions [Property Set]

        .INPUTS
            [String], [Guid]
            You can pipe a GUID value to this function.

        .OUTPUTS
            [String]
            Returns the name of the AD object corresponding to the GUID.

        .NOTES
            Used Functions:
                Name                                       ║ Module/Namespace
                ═══════════════════════════════════════════╬══════════════════════════════
                Get-ADObject                               ║ ActiveDirectory
                Write-Verbose                              ║ Microsoft.PowerShell.Utility
                Write-Error                                ║ Microsoft.PowerShell.Utility
                Write-Debug                                ║ Microsoft.PowerShell.Utility
                Write-Warning                              ║ Microsoft.PowerShell.Utility
                Set-StrictMode                             ║ Microsoft.PowerShell.Utility
                Get-Date                                   ║ Microsoft.PowerShell.Utility
                Test-IsValidGUID                           ║ EguibarIT.SecurityPS
                Get-FunctionDisplay                        ║ EguibarIT.SecurityPS

        .NOTES
            Version:         2.0
            DateModified:    06/Jun/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT.SecurityPS/blob/main/Private/Convert-GUIDToName.ps1

        .LINK
            https://learn.microsoft.com/en-us/windows/win32/adschema/attributes-all

        .COMPONENT
            Active Directory

        .ROLE
            Security

        .FUNCTIONALITY
            AD Schema, GUID Translation,GUID to Name Conversion, Directory Lookup
            https://learn.microsoft.com/en-us/windows/win32/adschema/classes
            https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1522b774-6464-41a3-87a5-1e5633c3fbbb

    #>

    [CmdletBinding(
        SupportsShouldProcess = $false,
        ConfirmImpact = 'Low'
    )]
    [OutputType([String])]

    param (
        # PARAM1 STRING representing the GUID
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Enter a GUID to translate into a display name',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript(
            { Test-IsValidGUID -ObjectGUID $_ },
            ErrorMessage = '[PARAMETER] Provided GUID is not valid! Function will not continue. Please check.'
        )]
        [Alias('ID', 'ObjectGUID')]
        $Guid
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
        } #end if

        ##############################
        # Module imports

        ##############################
        # Variables Definition

        [String]$Output = $null
        [hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

    } #end Begin

    Process {


        Try {

            # Ensure string is converted to GUID
            if ($PSBoundParameters['Guid'] -is [String]) {

                Write-Verbose -Message ('Converting string {0} to GUID' -f $guid)
                [GUID]$Guid = [System.guid]::New($PSBoundParameters['Guid'])

            } #end If

            # Get ALL [GuidNULL]
            If ($guid -eq ([System.guid]::New('00000000-0000-0000-0000-000000000000'))) {

                $Output = 'All [GuidNULL]'

            } else {

                $Splat = @{
                    SearchBase  = $Variables.SchemaNamingContext
                    Filter      = { schemaIDGUID -eq $guid }
                    Properties  = 'lDAPDisplayName'
                    ErrorAction = 'Stop'
                }
                $result = Get-ADObject @Splat

                #if $Result return empty, is because GUID is Extended Right
                #Check result value
                If ($result) {

                    # Check result for classSchema
                    If ($result.ObjectClass -eq 'classSchema') {

                        Write-Verbose -Message 'Found it as ClassSchema'
                        $Output = ('{0} [classSchema]' -f $result.lDAPDisplayName)

                    } #end If

                    # Check result for attributeSchema
                    If ($result.ObjectClass -eq 'attributeSchema') {

                        Write-Verbose -Message 'Found it as AttributeSchema'
                        $Output = ('{0} [attributeSchema]' -f $result.lDAPDisplayName)

                    } #end If

                } else {

                    # If not found in schema, check extended rights
                    $SearchBase = 'CN=Extended-Rights,{0}' -f $Variables.configurationNamingContext

                    $Splat = @{
                        SearchBase  = $SearchBase
                        Filter      = { rightsGUID -eq $guid }
                        Properties  = 'DisplayName', 'rightsGUID'
                        ErrorAction = 'Stop'
                    }
                    $result = Get-ADObject @Splat

                    if ($Result) {

                        Write-Verbose -Message ('Found it as ExtendedRight: {0}' -f $Result.DisplayName)
                        $Output = ('{0} [ExtendedRight]' -f $Result.DisplayName)

                    } else {

                        Write-Verbose -Message 'GUID not found in any known location'
                        $Output = ('Unknown GUID: {0}' -f $Guid)

                    } #end if-else

                } #end If-ElseIf
            } #end If-Else

        } catch {

            Write-Error -Message ('Error processing GUID {0}: {1}' -f $Guid, $_.Exception.Message)
            return

        } #end try-catch


    } #end Process

    End {
        # Display function footer if variables exist
        if ($null -ne $Variables -and
            $null -ne $Variables.FooterSecurity) {

            $txt = ($Variables.FooterSecurity -f $MyInvocation.InvocationName,
                'converting GUID to name (Private Function).'
            )
            Write-Verbose -Message $txt

        } #end if

        Return $Output
    } #end End

} #end Function Convert-GUIDToName
