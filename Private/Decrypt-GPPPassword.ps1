function Decrypt-GPPPassword {

    <#
    .SYNOPSIS
        Decrypts Group Policy Preferences passwords using Microsoft's published AES-256 key.

    .DESCRIPTION
        Internal helper function that decrypts GPP cpassword attributes using the AES-256
        key published by Microsoft in the MS-GPPREF specification.

        Group Policy Preferences stored passwords using reversible AES-256 encryption.
        In 2012, Microsoft published the decryption key in their official documentation,
        making all GPP passwords instantly decryptable by any domain user.

        This function implements the decryption algorithm for security auditing purposes.

        SECURITY CONTEXT:
        - Microsoft published the AES-256 key in MS-GPPREF specification
        - ANY domain user can decrypt GPP passwords using this key
        - Microsoft deprecated GPP passwords in 2014 (KB2862966)
        - Existing GPP passwords remain in SYSVOL until manually removed

    .PARAMETER EncryptedPassword
        Base64 encoded encrypted password extracted from GPP XML cpassword attribute.
        Expected format: Base64 string (e.g., "j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw")

    .EXAMPLE
        Decrypt-GPPPassword -EncryptedPassword 'j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw'

        Decrypts the provided Base64 encoded GPP password and returns the plaintext password.

    .EXAMPLE
        $Content = Get-Content 'Groups.xml' -Raw
        if ($Content -match 'cpassword="([^"]+)"') {
            $PlaintextPassword = Decrypt-GPPPassword -EncryptedPassword $Matches[1]
            Write-Output "Decrypted Password: $PlaintextPassword"
        }

        Extracts encrypted password from GPP XML file and decrypts it.

    .INPUTS
        String
        Accepts Base64 encoded encrypted password string.

    .OUTPUTS
        String
        Returns decrypted plaintext password, or '[DECRYPTION_FAILED]' if decryption fails.

    .NOTES
        Used Functions:
          Name                                       ║ Module/Namespace
          ═══════════════════════════════════════════╬══════════════════════════════
          Write-Warning                              ║ Microsoft.PowerShell.Utility
          [System.Convert]::FromBase64String()       ║ System
          [System.Security.Cryptography.AesCryptoServiceProvider]::new() ║ System.Security.Cryptography
          [System.Text.Encoding]::Unicode            ║ System.Text

      Version:         1.0
      DateModified:    2/Mar/2026
      LastModifiedBy:  Vicente Rodriguez Eguibar
                       vicente@eguibarit.com
                       Eguibar IT
                       http://www.eguibarit.com

    .LINK
        https://github.com/vreguibar/EguibarIT.SecurityPS

    .LINK
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be

    .LINK
        https://support.microsoft.com/kb/2862966

    .COMPONENT
        EguibarIT.SecurityPS

    .ROLE
        Security Auditor, Penetration Tester

    .FUNCTIONALITY
        Decrypts Group Policy Preferences passwords using Microsoft's published AES-256 key
        for security auditing and vulnerability assessment.
    #>

    [CmdletBinding(SupportsShouldProcess = $false)]
    [OutputType([string])]

    param(

        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Base64 encoded encrypted password from GPP cpassword attribute',
            Position = 0
        )]
        [ValidateNotNullOrEmpty()]
        [string]
        $EncryptedPassword

    ) #end Param

    ################################################################################

    begin {

        Set-StrictMode -Version Latest

        # Log function invocation with parameters
        $txt = ($Variables.HeaderSecurity -f
            (Get-Date).ToShortDateString(),
            $MyInvocation.Mycommand,
            (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
        )
        Write-Verbose -Message $txt

        ################################################################################
        #region Variables Definition

        # Microsoft's published AES-256 key for GPP password decryption
        # Documented in MS-GPPREF specification section 2.2.1.1.4
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be
        [byte[]]$AESKey = @(
            0x4e, 0x99, 0x06, 0xe8, 0xfc, 0xb6, 0x6c, 0xc9,
            0xfa, 0xf4, 0x93, 0x10, 0x62, 0x0f, 0xfe, 0xe8,
            0xf4, 0x96, 0xe8, 0x06, 0xcc, 0x05, 0x79, 0x90,
            0x20, 0x9b, 0x09, 0xa4, 0x33, 0xb6, 0x6c, 0x1b
        )

        #endregion Variables Definition
        ################################################################################

    } #end Begin

    ################################################################################

    process {

        try {

            Write-Verbose -Message ('Attempting to decrypt GPP password (length: {0})' -f $EncryptedPassword.Length)

            # Base64 decode the encrypted password
            [byte[]]$EncryptedBytes = [System.Convert]::FromBase64String($EncryptedPassword)

            Write-Verbose -Message ('Base64 decoded to {0} bytes' -f $EncryptedBytes.Length)

            # Create AES decryptor using .NET constructor
            [System.Security.Cryptography.AesCryptoServiceProvider]$AES = [System.Security.Cryptography.AesCryptoServiceProvider]::new()
            $AES.Key = $AESKey
            $AES.IV = [System.Byte[]]::new(16)  # IV is all zeros for GPP encryption

            # Decrypt using AES-256-CBC
            $Decryptor = $AES.CreateDecryptor()
            [byte[]]$DecryptedBytes = $Decryptor.TransformFinalBlock($EncryptedBytes, 0, $EncryptedBytes.Length)

            # Convert bytes to Unicode string and remove null padding
            [string]$DecryptedPassword = [System.Text.Encoding]::Unicode.GetString($DecryptedBytes)
            $DecryptedPassword = $DecryptedPassword.TrimEnd([char]0)

            Write-Verbose -Message 'GPP password decryption successful'

            return $DecryptedPassword

        } catch {

            Write-Warning -Message ('GPP password decryption failed: {0}' -f $_.Exception.Message)
            Write-Verbose -Message ('Encrypted value: {0}' -f $EncryptedPassword)

            return '[DECRYPTION_FAILED]'

        } #end try-catch

    } #end Process

    ################################################################################

    end {
        # No cleanup required - stateless decryption operation

        if ($null -ne $Variables -and
            $null -ne $Variables.FooterSecurity) {

            $txt = ($Variables.FooterSecurity -f $MyInvocation.InvocationName,
                'finished decrypting GPP passwords.'
            )
            Write-Verbose -Message $txt
        } #end If

    } #end End

} #end Function Decrypt-GPPPassword
