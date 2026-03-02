function Test-IsPrivilegedAccount {
    <#
        .SYNOPSIS
            Determines if an Active Directory account is privileged based on SID analysis.

        .DESCRIPTION
            This function checks if an Active Directory user account is privileged by analyzing:
            - User's Security Identifier (SID) for well-known privileged accounts (RID 500, etc.)
            - Membership in privileged groups (Domain Admins, Schema Admins, Enterprise Admins, etc.)
            - Membership in custom privileged groups/users provided by the caller

            The function uses SID-based detection to work across localized Active Directory
            environments where group names may differ by language.

        .PARAMETER ADUser
            The Active Directory user object to check for privilege status. Must contain
            ObjectSid property and optionally MemberOf property for group membership analysis.

        .PARAMETER PrivilegedGroupSIDs
            Array of Security Identifiers representing privileged groups. Typically includes
            well-known groups like Domain Admins, Schema Admins, Enterprise Admins, and
            optionally custom administrative groups.

        .PARAMETER PrivilegedUserSIDs
            Array of Security Identifiers representing individual privileged user accounts.
            Used to flag specific service accounts or administrative users that should be
            treated as high-privilege regardless of group membership.

        .PARAMETER Server
            Domain controller to query for group membership resolution. If not specified,
            uses the current domain's nearest DC.

        .EXAMPLE
            $User = Get-ADUser -Identity 'jsmith' -Properties ObjectSid, MemberOf
            $PrivilegedGroups = @('S-1-5-21-512', 'S-1-5-21-518')
            Test-IsPrivilegedAccount -ADUser $User -PrivilegedGroupSIDs $PrivilegedGroups -PrivilegedUserSIDs @()

            Returns $true if jsmith is a member of Domain Admins or Schema Admins.

        .EXAMPLE
            $Splat = @{
                ADUser              = $UserObject
                PrivilegedGroupSIDs = @('S-1-5-21-512', 'S-1-5-32-544')
                PrivilegedUserSIDs  = @('S-1-5-21-3623811015-3361044348-30300820-1104')
                Server              = 'DC01.EguibarIT.local'
            }
            Test-IsPrivilegedAccount @Splat

            Checks if user is privileged using custom group and user SID lists.

        .INPUTS
            None
            This function does not accept pipeline input.

        .OUTPUTS
            [System.Boolean]
            Returns $true if the account is privileged, otherwise $false.

        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Test-IsValidSID                        | EguibarIT.SecurityPS
                Get-AdWellKnownSID                     | EguibarIT.SecurityPS
                Get-AdObjectType                       | EguibarIT.SecurityPS
                Write-Verbose                          | Microsoft.PowerShell.Utility

            Version:         1.0.1
            DateModified:    02/Mar/2026
            LastModifiedBy:  Vicente Rodriguez Eguibar
                vicente@eguibar.com
                EguibarIT
                http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT.SecurityPS

        .COMPONENT
            EguibarIT.SecurityPS

        .ROLE
            Security Analysis

        .FUNCTIONALITY
            Privilege Detection
    #>

    [CmdletBinding(
        SupportsShouldProcess = $false,
        ConfirmImpact = 'Low'
    )]
    [OutputType([bool])]

    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            Position = 0,
            HelpMessage = 'AD user object to check for privilege status'
        )]
        [ValidateNotNull()]
        [object]
        $ADUser,

        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            Position = 1,
            HelpMessage = 'Array of privileged group SIDs to check membership against'
        )]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $PrivilegedGroupSIDs,

        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            Position = 2,
            HelpMessage = 'Array of privileged user SIDs to check against'
        )]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $PrivilegedUserSIDs,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            Position = 3,
            HelpMessage = 'Domain controller to query for group resolution'
        )]
        [ValidateNotNullOrEmpty()]
        [string]
        $Server
    )

    Begin {

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

        [bool]$IsPrivileged = $false

    } #end Begin

    Process {

        try {

            # Get user's SID
            if ($ADUser.PSObject.Properties.Name -contains 'ObjectSid') {
                $UserSID = $ADUser.ObjectSid.Value
            } else {
                Write-Verbose -Message ('    [WARNING] ADUser object does not contain ObjectSid property for {0}' -f $ADUser.SamAccountName)
                return $false
            } #end if

            # Validate SID format using module helper
            if (-not (Test-IsValidSID -ObjectSID $UserSID)) {
                Write-Verbose -Message ('    [WARNING] Invalid SID format for user {0}: {1}' -f $ADUser.SamAccountName, $UserSID)
                return $false
            } #end if

            # Check if user's RID is 500 (Administrator account)
            if ($UserSID -match '-500$') {
                Write-Verbose -Message ('    [PRIVILEGE] User has Administrator RID (500): {0}' -f $ADUser.SamAccountName)
                return $true
            } #end if

            # Check if it's a well-known privileged SID using module helper
            if (Get-AdWellKnownSID -SID $UserSID) {
                $WellKnownInfo = Get-AdWellKnownSID -SID $UserSID -Detailed
                Write-Verbose -Message ('    [PRIVILEGE] User is well-known SID ({0}): {1}' -f $WellKnownInfo.Description, $ADUser.SamAccountName)
                return $true
            } #end if

            # Check if user is in any privileged groups (by membership SID)
            if ($ADUser.PSObject.Properties.Name -contains 'MemberOf' -and $null -ne $ADUser.MemberOf) {
                foreach ($GroupDN in $ADUser.MemberOf) {
                    try {
                        # Use Get-AdObjectType to resolve group DN to SID
                        $Splat = @{
                            Identity = $GroupDN
                        }
                        if ($PSBoundParameters.ContainsKey('Server')) {
                            $Splat['Server'] = $Server
                        } #end if

                        $GrpObject = Get-AdObjectType @Splat

                        if ($null -ne $GrpObject) {
                            $GroupSID = $GrpObject.SID.Value

                            if ($GroupSID -in $PrivilegedGroupSIDs) {
                                Write-Verbose -Message ('    [PRIVILEGE] Member of privileged group (SID: {0}): {1}' -f $GroupSID, $GroupDN)
                                return $true
                            } #end if

                            if ($GroupSID -in $PrivilegedUserSIDs) {
                                Write-Verbose -Message ('    [PRIVILEGE] Matches additional privileged group (SID: {0}): {1}' -f $GroupSID, $GroupDN)
                                return $true
                            } #end if
                        } #end if
                    } catch {
                        # If group cannot be resolved, skip it
                        Write-Verbose -Message ('    [DEBUG] Could not resolve group SID for {0}: {1}' -f $GroupDN, $_.Exception.Message)
                    } #end try-catch
                } #end foreach
            } #end if

            # Check if user matches any additional privileged users by SID
            if ($UserSID -in $PrivilegedUserSIDs) {
                Write-Verbose -Message ('    [PRIVILEGE] Matches additional privileged user SID: {0}' -f $UserSID)
                return $true
            } #end if

        } catch {

            Write-Warning -Message ('Error checking privilege status for {0}: {1}' -f $ADUser.SamAccountName, $_.Exception.Message)
            return $false

        } #end try-catch

    } #end Process

    End {

        if ($null -ne $Variables -and $null -ne $Variables.FooterSecurity) {
            $txt = ($Variables.FooterSecurity -f $MyInvocation.InvocationName, 'completed.')
            Write-Verbose -Message $txt
        } #end if

        return $IsPrivileged

    } #end End

} #end Function Test-IsPrivilegedAccount
