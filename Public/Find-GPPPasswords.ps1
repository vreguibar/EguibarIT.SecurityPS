function Find-GPPPasswords {

    <#
    .SYNOPSIS
        Discovers and decrypts Group Policy Preferences (GPP) passwords stored in SYSVOL.

    .DESCRIPTION
        Comprehensive GPP password audit tool that performs multi-phase security analysis:

        PHASE 1 - DISCOVERY: Scans SYSVOL for XML files containing encrypted passwords (cpassword attribute)
        PHASE 2 - DECRYPTION: Automatically decrypts passwords using Microsoft's published AES-256 key
        PHASE 3 - ANALYSIS: Categorizes findings by password type, age, and risk level
        PHASE 4 - REMEDIATION: Provides step-by-step cleanup guidance with automated deletion option

        CRITICAL SECURITY CONTEXT:
        GPP passwords are encrypted with AES-256, but Microsoft published the decryption key in 2012.
        ANY domain user can extract and decrypt these passwords from SYSVOL. Microsoft deprecated
        GPP passwords in 2014 (KB2862966) but did NOT remove existing passwords from SYSVOL.

        Organizations often have 10+ year old GPP passwords in SYSVOL from Windows Server 2008 R2 era.
        These credentials may provide Local Administrator, Service Account, or Domain Admin access.

        MITRE ATT&CK FRAMEWORK:
        - T1552.006: Unsecured Credentials - Group Policy Preferences
        - T1003: OS Credential Dumping
        - T1078: Valid Accounts

        BEST PRACTICE: Remove ALL GPP password files from SYSVOL and rotate exposed credentials immediately.

    .PARAMETER ExportReport
        If specified, exports detailed findings to CSV, JSON, and TXT reports.
        Reports are saved to the path specified in ExportPath parameter.

    .PARAMETER DecryptPasswords
        If specified, attempts to decrypt discovered passwords using Microsoft's published AES-256 key.
        Default: $true (passwords are decrypted automatically for impact assessment).

    .PARAMETER DeleteFiles
        If specified, uses ShouldProcess to delete GPP password files from SYSVOL after confirmation.
        Supports -WhatIf and -Confirm parameters.
        WARNING: Only use after rotating all exposed passwords!

    .PARAMETER ExportPath
        Directory path where reports will be exported when using -ExportReport.
        Directory will be created if it does not exist.

    .EXAMPLE
        Find-GPPPasswords

        Scans SYSVOL for GPP passwords, decrypts them, and displays results to console.
        No files are deleted or exported.

    .EXAMPLE
        Find-GPPPasswords -ExportReport -ExportPath 'C:\SecurityAudits'

        Performs full GPP password scan with decryption and exports detailed reports
        (CSV, JSON, TXT) to C:\SecurityAudits directory.

    .EXAMPLE
        Find-GPPPasswords -DeleteFiles -Confirm:$false

        Scans for GPP passwords and automatically deletes discovered files without confirmation.
        WARNING: Only use after rotating all exposed credentials!

    .EXAMPLE
        Find-GPPPasswords -DeleteFiles -WhatIf

        Previews which GPP password files would be deleted without actually removing them.
        Safe way to test deletion operation.

    .EXAMPLE
        Find-GPPPasswords -DecryptPasswords:$false -ExportReport

        Scans for GPP passwords but does NOT decrypt them (only shows encrypted values).
        Useful for initial discovery pass or compliance audits where decryption is restricted.

    .INPUTS
        None. This function does not accept pipeline input.

    .OUTPUTS
        PSCustomObject
        Returns custom object with PSTypeName 'EguibarIT.Security.GPPPasswordAudit' containing:
        - DomainName: Name of the scanned Active Directory domain
        - SYSVOLPath: UNC path to SYSVOL Policies folder
        - TotalXMLFiles: Total count of XML files scanned in SYSVOL
        - PasswordFilesFound: Count of files containing GPP passwords
        - PasswordsDecrypted: Boolean indicating if passwords were decrypted
        - OldestPasswordAge: Age in years of the oldest discovered password
        - PasswordsByType: Hashtable categorizing passwords by file type
        - IsSecure: Boolean indicating if SYSVOL is free of GPP passwords
        - RiskLevel: String ('None', 'Critical') indicating security posture
        - FilesDeleted: Boolean indicating if files were removed
        - ReportsExported: Array of file paths to exported reports
        - AuditDate: Timestamp of the scan

    .NOTES
        Used Functions:
          Name                                                                  ║ Module/Namespace
          ══════════════════════════════════════════════════════════════════════╬══════════════════════════════
          Write-Verbose                                                         ║ Microsoft.PowerShell.Utility
          Write-Warning                                                         ║ Microsoft.PowerShell.Utility
          Write-Error                                                           ║ Microsoft.PowerShell.Utility
          Get-Date                                                              ║ Microsoft.PowerShell.Utility
          Test-Path                                                             ║ Microsoft.PowerShell.Management
          New-Item                                                              ║ Microsoft.PowerShell.Management
          Get-ChildItem                                                         ║ Microsoft.PowerShell.Management
          Get-Content                                                           ║ Microsoft.PowerShell.Management
          Remove-Item                                                           ║ Microsoft.PowerShell.Management
          Export-Csv                                                            ║ Microsoft.PowerShell.Utility
          ConvertTo-Json                                                        ║ Microsoft.PowerShell.Utility
          Out-File                                                              ║ Microsoft.PowerShell.Utility
          Decrypt-GPPPassword                                                   ║ EguibarIT.SecurityPS (Private)
          Get-FunctionDisplay                                                   ║ EguibarIT.SecurityPS (Private)
          [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() ║ System.DirectoryServices
          [System.Convert]::FromBase64String()                                  ║ System
          [System.Security.Cryptography.AesCryptoServiceProvider]::new()        ║ System.Security.Cryptography
          [System.Text.Encoding]::Unicode                                       ║ System.Text

    .NOTES
        Version:         1.1
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
        Security Auditor, Penetration Tester, Security Operations

    .FUNCTIONALITY
        Discovers and decrypts Group Policy Preferences passwords in SYSVOL, provides risk assessment,
        and supports automated remediation with file deletion and detailed reporting.
    #>

    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'High'
    )]

    [OutputType([PSCustomObject])]

    param(

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Export detailed findings to CSV, JSON, and TXT reports.',
            Position = 0
        )]
        [switch]
        $ExportReport,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Decrypt discovered passwords using Microsoft published AES-256 key. Default: $true',
            Position = 1
        )]
        [PSDefaultValue(Help = 'Passwords are decrypted by default for impact assessment', Value = $true)]
        [bool]
        $DecryptPasswords = $true,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Delete GPP password files from SYSVOL. WARNING: Only use after rotating exposed passwords!',
            Position = 2
        )]
        [switch]
        $DeleteFiles,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Directory path where reports will be exported. Default: C:\Logs',
            Position = 3
        )]
        [ValidateNotNullOrEmpty()]
        [PSDefaultValue(Help = 'Reports exported to C:\Logs by default', Value = 'C:\Logs')]
        [string]
        $ExportPath = 'C:\Logs'

    ) #end Param

    begin {

        # Set strict mode
        Set-StrictMode -Version Latest

        # Log function invocation with parameters
        $txt = ($Variables.HeaderSecurity -f
            (Get-Date).ToShortDateString(),
            $MyInvocation.Mycommand,
            (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
        )
        Write-Verbose -Message $txt

        Write-Verbose -Message 'GPP Password Discovery & Decryption | MITRE ATT&CK T1552.006'

        # ========================================
        # Variables Definition
        # ========================================

        [System.Collections.ArrayList]$FilesWithPasswords = @()
        [System.Collections.ArrayList]$AllXMLFiles = @()
        [System.Collections.ArrayList]$ExportedReports = @()

        [string]$DomainName = $null
        [string]$SYSVOLPath = $null
        [bool]$FilesDeleted = $false
        [int]$TotalXMLFilesCount = 0

        # XML files that may contain passwords
        [hashtable]$PasswordFileTypes = @{
            'Groups.xml'         = 'Local Administrator password changes'
            'Services.xml'       = 'Service account credentials'
            'Scheduledtasks.xml' = 'Scheduled task credentials'
            'DataSources.xml'    = 'Database connection strings'
            'Drives.xml'         = 'Mapped drive credentials'
            'Printers.xml'       = 'Printer deployment credentials'
        } #end hashtable

    } #end Begin

    process {

        try {

            # ========================================
            # PHASE 1: DISCOVER SYSVOL PATH
            # ========================================

            Write-Verbose -Message '[PHASE 1] Locating SYSVOL Share'

            try {
                $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
                $DomainName = $Domain.Name
                $SYSVOLPath = '\\{0}\SYSVOL\{0}\Policies' -f $DomainName

                Write-Verbose -Message ('Domain: {0} | SYSVOL: {1}' -f $DomainName, $SYSVOLPath)

                # Test SYSVOL accessibility
                if (-not (Test-Path -Path $SYSVOLPath)) {
                    Write-Error -Message ('Cannot access SYSVOL path: {0}. Ensure you are on domain-joined system with network connectivity to domain.' -f $SYSVOLPath) -ErrorAction Stop
                } #end if

                Write-Verbose -Message 'SYSVOL is accessible'

            } catch {
                Write-Error -Message ('Cannot determine domain information: {0}' -f $_.Exception.Message) -ErrorAction Stop
            } #end try-catch

            # ========================================
            # PHASE 2: SCAN FOR GPP PASSWORD FILES
            # ========================================

            Write-Verbose -Message '[PHASE 2] Scanning SYSVOL for GPP files (Groups.xml, Services.xml, ScheduledTasks.xml, DataSources.xml, Drives.xml)'

            $TempXMLFiles = Get-ChildItem -Path $SYSVOLPath -Recurse -Include *.xml -ErrorAction SilentlyContinue

            # Convert to ArrayList for efficient processing
            foreach ($XmlFile in $TempXMLFiles) {
                [void]$AllXMLFiles.Add($XmlFile)
            } #end foreach

            $TotalXMLFilesCount = $AllXMLFiles.Count
            Write-Verbose -Message ('Found {0} total XML files in SYSVOL' -f $TotalXMLFilesCount)

            # ========================================
            # PHASE 3: SEARCH FOR CPASSWORD ATTRIBUTE
            # ========================================

            Write-Verbose -Message '[PHASE 3] Searching for cpassword attributes in XML files'

            foreach ($File in $AllXMLFiles) {
                try {
                    [string]$Content = Get-Content -Path $File.FullName -Raw -ErrorAction SilentlyContinue

                    # Check if file contains cpassword attribute
                    if ($Content -match 'cpassword="([^"]+)"') {

                        # Extract all cpassword values from the file
                        $PasswordMatches = [regex]::Matches($Content, 'cpassword="([^"]+)"')

                        foreach ($Match in $PasswordMatches) {
                            [string]$EncryptedPassword = $Match.Groups[1].Value

                            # Decrypt password if requested
                            [string]$DecryptedPassword = $null
                            if ($DecryptPasswords) {
                                $DecryptedPassword = Decrypt-GPPPassword -EncryptedPassword $EncryptedPassword
                            } #end if

                            # Determine password context (what is this password for?)
                            [string]$PasswordContext = 'Unknown'
                            [string]$Username = 'Unknown'

                            # Try to extract username/account name
                            if ($Content -match 'userName="([^"]+)"') {
                                $Username = $Matches[1]
                            } elseif ($Content -match 'accountName="([^"]+)"') {
                                $Username = $Matches[1]
                            } elseif ($Content -match 'runAs="([^"]+)"') {
                                $Username = $Matches[1]
                            } #end if-elseif

                            # Determine file type
                            [string]$FileType = $PasswordFileTypes.Keys | Where-Object { $File.Name -eq $_ } | Select-Object -First 1
                            if ($FileType) {
                                $PasswordContext = $PasswordFileTypes[$FileType]
                            } #end if

                            # Add finding to collection using ArrayList.Add()
                            [void]$FilesWithPasswords.Add([PSCustomObject]@{
                                    FilePath          = $File.FullName
                                    FileName          = $File.Name
                                    FileType          = $FileType
                                    Created           = $File.CreationTime
                                    Modified          = $File.LastWriteTime
                                    PasswordContext   = $PasswordContext
                                    Username          = $Username
                                    EncryptedPassword = $EncryptedPassword
                                    DecryptedPassword = $DecryptedPassword
                                })

                        } #end foreach Match

                    } #end if cpassword match

                } catch {
                    Write-Warning -Message ('Error reading file: {0}' -f $File.FullName)
                } #end try-catch

            } #end foreach File

            # ========================================
            # PHASE 4: DISPLAY FINDINGS
            # ========================================

            if ($FilesWithPasswords.Count -eq 0) {

                Write-Verbose -Message '✓ SECURE - No GPP passwords found in SYSVOL. Recommendation: Implement quarterly scans to detect future deployments.'

            } else {

                # PASSWORDS FOUND - CRITICAL SECURITY ISSUE
                Write-Warning -Message ('CRITICAL VULNERABILITY: {0} GPP passwords found in SYSVOL. ANY domain user can decrypt these instantly using the published AES key.' -f $FilesWithPasswords.Count)

                # Display findings with decrypted passwords
                Write-Verbose -Message '═══════════════════════════════════════════════════════════════════════════════'
                Write-Verbose -Message 'GPP PASSWORD FINDINGS:'
                Write-Verbose -Message '═══════════════════════════════════════════════════════════════════════════════'

                [int]$Index = 1
                foreach ($Finding in $FilesWithPasswords) {

                    [timespan]$Age = (Get-Date) - $Finding.Created
                    [int]$AgeDays = [math]::Round($Age.TotalDays)
                    [double]$AgeYears = [math]::Round($Age.TotalDays / 365, 1)

                    Write-Verbose -Message ('[{0}] PASSWORD EXPOSURE DETAILS:' -f $Index)
                    Write-Verbose -Message ('    File: {0}' -f $Finding.FileName)
                    Write-Verbose -Message ('    Type: {0}' -f $Finding.PasswordContext)
                    Write-Verbose -Message ('    Path: {0}' -f $Finding.FilePath)
                    Write-Verbose -Message ('    Username: {0}' -f $Finding.Username)

                    if ($AgeDays -gt 365) {
                        Write-Warning -Message ('    Created: {0} ({1} years ago / {2} days)' -f $Finding.Created, $AgeYears, $AgeDays)
                    } else {
                        Write-Verbose -Message ('    Created: {0} ({1} years ago / {2} days)' -f $Finding.Created, $AgeYears, $AgeDays)
                    } #end if-else

                    Write-Verbose -Message ('    Last Modified: {0}' -f $Finding.Modified)
                    Write-Verbose -Message ('    Encrypted: {0}' -f $Finding.EncryptedPassword)

                    if ($DecryptPasswords) {
                        Write-Warning -Message ('    DECRYPTED PASSWORD: {0}' -f $Finding.DecryptedPassword)
                    } #end if

                    $Index++

                } #end foreach Finding

                # ========================================
                # RISK ANALYSIS
                # ========================================

                Write-Verbose -Message '[RISK ANALYSIS]'

                # Categorize by file type
                $GroupsByType = $FilesWithPasswords | Group-Object -Property FileType

                Write-Verbose -Message 'Password Types Found:'
                foreach ($Group in $GroupsByType) {
                    [string]$TypeName = if ($Group.Name) {
                        $Group.Name
                    } else {
                        'Unknown Type'
                    }
                    [string]$TypeDescription = $PasswordFileTypes[$Group.Name]
                    Write-Verbose -Message ('  • {0} ({1}): {2}' -f $TypeName, $Group.Count, $TypeDescription)
                } #end foreach

                # Identify oldest passwords
                $OldestPassword = $FilesWithPasswords | Sort-Object -Property Created | Select-Object -First 1
                [double]$OldestAge = [math]::Round(((Get-Date) - $OldestPassword.Created).TotalDays / 365, 1)

                Write-Warning -Message 'Oldest Password:'
                Write-Warning -Message ('  • File: {0}' -f $OldestPassword.FileName)
                Write-Warning -Message ('  • Created: {0} ({1} years ago)' -f $OldestPassword.Created, $OldestAge)
                Write-Warning -Message ('  • This password has been exposed for {0} YEARS!' -f $OldestAge)

                # ========================================
                # REMEDIATION GUIDANCE
                # ========================================

                Write-Verbose -Message '╔════════════════════════════════════════════════════════════════╗'
                Write-Verbose -Message '║  REMEDIATION STEPS - CRITICAL IMMEDIATE ACTION REQUIRED       ║'
                Write-Verbose -Message '╚════════════════════════════════════════════════════════════════╝'

                Write-Warning -Message '[STEP 1] ROTATE ALL EXPOSED PASSWORDS IMMEDIATELY'
                Write-Verbose -Message 'DO THIS FIRST - Before deleting files, change ALL discovered passwords:'

                foreach ($Finding in $FilesWithPasswords) {
                    Write-Verbose -Message ('  • {0} ({1})' -f $Finding.Username, $Finding.PasswordContext)

                    # Provide specific guidance based on password type
                    switch ($Finding.FileType) {
                        'Groups.xml' {
                            Write-Verbose -Message '    Remediation: Deploy Microsoft LAPS for automatic unique local admin passwords'
                            Write-Verbose -Message '    Emergency Fix: Change local admin password via GPO immediately'
                        }
                        'Services.xml' {
                            Write-Verbose -Message '    Remediation: Migrate to Group Managed Service Account (gMSA)'
                            Write-Verbose -Message '    Emergency Fix: Change service account password in AD and update service configuration'
                        }
                        'Scheduledtasks.xml' {
                            Write-Verbose -Message '    Remediation: Reconfigure scheduled task with new credentials or use gMSA'
                        }
                        'DataSources.xml' {
                            Write-Verbose -Message '    Remediation: Change database credentials and update connection strings'
                        }
                        default {
                            Write-Verbose -Message '    Remediation: Rotate credential and remove from GPP file'
                        }
                    } #end switch

                } #end foreach Finding

                Write-Warning -Message '[STEP 2] DELETE GPP PASSWORD FILES FROM SYSVOL'
                Write-Verbose -Message 'After rotating passwords, delete the XML files:'

                foreach ($Finding in ($FilesWithPasswords | Select-Object -Property FilePath -Unique)) {
                    Write-Verbose -Message ('  Remove-Item -Path ''{0}'' -Force' -f $Finding.FilePath)
                } #end foreach

                Write-Warning -Message '[STEP 3] INSTALL KB2862966 ON ALL DOMAIN CONTROLLERS'
                Write-Verbose -Message 'Prevents NEW GPP passwords from being created:'
                Write-Verbose -Message '  https://support.microsoft.com/kb/2862966'

                Write-Warning -Message '[STEP 4] DEPLOY MODERN CREDENTIAL MANAGEMENT'
                Write-Verbose -Message 'Replace GPP passwords with secure alternatives:'
                Write-Verbose -Message '  • Microsoft LAPS (Local Admin Password Solution) for workstation/server local admins'
                Write-Verbose -Message '  • Group Managed Service Accounts (gMSA) for service accounts'
                Write-Verbose -Message '  • Privileged Access Management (CyberArk, HashiCorp Vault) for sensitive credentials'

                Write-Warning -Message '[STEP 5] IMPLEMENT ONGOING MONITORING'
                Write-Verbose -Message 'Schedule quarterly SYSVOL scans:'
                Write-Verbose -Message '  • Run this script via scheduled task'
                Write-Verbose -Message '  • Alert if new cpassword attributes appear (indicates rogue GPO deployment)'
                Write-Verbose -Message '  • Monitor Event ID 5136 for GPO modifications'

                # ========================================
                # AUTOMATED DELETION (OPTIONAL)
                # ========================================

                if ($DeleteFiles) {

                    Write-Verbose -Message 'DeleteFiles parameter specified - preparing to delete GPP password files'

                    # Get unique file paths to delete
                    $UniqueFilePaths = $FilesWithPasswords | Select-Object -Property FilePath -Unique

                    foreach ($FileToDelete in $UniqueFilePaths) {

                        if ($PSCmdlet.ShouldProcess($FileToDelete.FilePath, 'Delete GPP password file from SYSVOL')) {

                            try {
                                Remove-Item -Path $FileToDelete.FilePath -Force -ErrorAction Stop
                                Write-Verbose -Message ('Deleted: {0}' -f $FileToDelete.FilePath)
                                $FilesDeleted = $true

                            } catch {
                                Write-Error -Message ('ERROR deleting: {0} - {1}' -f $FileToDelete.FilePath, $_.Exception.Message)
                            } #end try-catch

                        } #end if ShouldProcess

                    } #end foreach FileToDelete

                    if ($FilesDeleted) {
                        Write-Warning -Message 'File deletion complete - REMINDER: Ensure all exposed passwords have been rotated!'
                    } #end if

                } #end if DeleteFiles

                # ========================================
                # EXPORT REPORTS
                # ========================================

                if ($ExportReport) {

                    Write-Verbose -Message 'Exporting detailed reports...'

                    # Create export directory if it doesn't exist
                    if (-not (Test-Path -Path $ExportPath)) {
                        [void](New-Item -ItemType Directory -Path $ExportPath -Force)
                        Write-Verbose -Message ('Created export directory: {0}' -f $ExportPath)
                    } #end if

                    [string]$Timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'

                    # CSV Export
                    [string]$CSVReport = '{0}\GPP-Passwords-{1}.csv' -f $ExportPath, $Timestamp
                    $FilesWithPasswords | Export-Csv -Path $CSVReport -NoTypeInformation -Force
                    [void]$ExportedReports.Add($CSVReport)
                    Write-Verbose -Message ('CSV Report: {0}' -f $CSVReport)

                    # JSON Export (machine-readable for SIEM integration)
                    [string]$JSONReport = '{0}\GPP-Passwords-{1}.json' -f $ExportPath, $Timestamp
                    $FilesWithPasswords | ConvertTo-Json -Depth 10 | Out-File -FilePath $JSONReport -Encoding UTF8 -Force
                    [void]$ExportedReports.Add($JSONReport)
                    Write-Verbose -Message ('JSON Report: {0}' -f $JSONReport)

                    # Text Summary Report
                    [string]$TextReport = '{0}\GPP-Passwords-{1}.txt' -f $ExportPath, $Timestamp

                    [System.Text.StringBuilder]$ReportContent = [System.Text.StringBuilder]::new()
                    [void]$ReportContent.AppendLine('========================================================================')
                    [void]$ReportContent.AppendLine('GPP PASSWORD DISCOVERY REPORT')
                    [void]$ReportContent.AppendLine('========================================================================')
                    [void]$ReportContent.AppendLine(('Domain: {0}' -f $DomainName))
                    [void]$ReportContent.AppendLine(('Scan Date: {0}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')))
                    [void]$ReportContent.AppendLine(('Total Passwords Found: {0}' -f $FilesWithPasswords.Count))
                    [void]$ReportContent.AppendLine('')
                    [void]$ReportContent.AppendLine('CRITICAL SECURITY VULNERABILITY DETECTED')
                    [void]$ReportContent.AppendLine('All discovered passwords can be decrypted by ANY domain user.')
                    [void]$ReportContent.AppendLine('IMMEDIATE ACTION REQUIRED: Rotate all passwords and delete GPP files.')
                    [void]$ReportContent.AppendLine('')
                    [void]$ReportContent.AppendLine('========================================================================')
                    [void]$ReportContent.AppendLine('DISCOVERED PASSWORDS')
                    [void]$ReportContent.AppendLine('========================================================================')
                    [void]$ReportContent.AppendLine('')

                    [int]$ReportIndex = 1
                    foreach ($Finding in $FilesWithPasswords) {
                        [double]$ReportAge = [math]::Round(((Get-Date) - $Finding.Created).TotalDays / 365, 1)

                        [void]$ReportContent.AppendLine(('[{0}] PASSWORD EXPOSURE:' -f $ReportIndex))
                        [void]$ReportContent.AppendLine(('    File Name: {0}' -f $Finding.FileName))
                        [void]$ReportContent.AppendLine(('    File Path: {0}' -f $Finding.FilePath))
                        [void]$ReportContent.AppendLine(('    Type: {0}' -f $Finding.PasswordContext))
                        [void]$ReportContent.AppendLine(('    Username: {0}' -f $Finding.Username))
                        [void]$ReportContent.AppendLine(('    Created: {0} ({1} years ago)' -f $Finding.Created, $ReportAge))
                        [void]$ReportContent.AppendLine(('    Modified: {0}' -f $Finding.Modified))
                        [void]$ReportContent.AppendLine(('    Encrypted: {0}' -f $Finding.EncryptedPassword))
                        [void]$ReportContent.AppendLine(('    DECRYPTED: {0}' -f $Finding.DecryptedPassword))
                        [void]$ReportContent.AppendLine('')

                        $ReportIndex++
                    } #end foreach Finding

                    [void]$ReportContent.AppendLine('========================================================================')
                    [void]$ReportContent.AppendLine('REMEDIATION STEPS')
                    [void]$ReportContent.AppendLine('========================================================================')
                    [void]$ReportContent.AppendLine('')
                    [void]$ReportContent.AppendLine('[STEP 1] ROTATE ALL EXPOSED PASSWORDS IMMEDIATELY')
                    [void]$ReportContent.AppendLine('Before deleting files, change ALL discovered passwords:')
                    [void]$ReportContent.AppendLine('')

                    foreach ($Finding in $FilesWithPasswords) {
                        [void]$ReportContent.AppendLine(('  - {0} ({1})' -f $Finding.Username, $Finding.PasswordContext))
                    } #end foreach

                    [void]$ReportContent.AppendLine('')
                    [void]$ReportContent.AppendLine('[STEP 2] DELETE GPP PASSWORD FILES FROM SYSVOL')
                    [void]$ReportContent.AppendLine('After rotating passwords, delete the XML files:')
                    [void]$ReportContent.AppendLine('')

                    foreach ($Finding in ($FilesWithPasswords | Select-Object -Property FilePath -Unique)) {
                        [void]$ReportContent.AppendLine(('  Remove-Item -Path ''{0}'' -Force' -f $Finding.FilePath))
                    } #end foreach

                    [void]$ReportContent.AppendLine('')
                    [void]$ReportContent.AppendLine('[STEP 3] INSTALL KB2862966 ON ALL DOMAIN CONTROLLERS')
                    [void]$ReportContent.AppendLine('Prevents NEW GPP passwords from being created.')
                    [void]$ReportContent.AppendLine('Download: https://support.microsoft.com/kb/2862966')
                    [void]$ReportContent.AppendLine('')
                    [void]$ReportContent.AppendLine('[STEP 4] DEPLOY MODERN CREDENTIAL MANAGEMENT')
                    [void]$ReportContent.AppendLine('  - Microsoft LAPS for local admin passwords')
                    [void]$ReportContent.AppendLine('  - Group Managed Service Accounts (gMSA) for service accounts')
                    [void]$ReportContent.AppendLine('  - Privileged Access Management for sensitive credentials')
                    [void]$ReportContent.AppendLine('')
                    [void]$ReportContent.AppendLine('[STEP 5] IMPLEMENT ONGOING MONITORING')
                    [void]$ReportContent.AppendLine('  - Schedule quarterly SYSVOL scans')
                    [void]$ReportContent.AppendLine('  - Monitor Event ID 5136 for GPO modifications')
                    [void]$ReportContent.AppendLine('  - Alert if new cpassword attributes appear')
                    [void]$ReportContent.AppendLine('')
                    [void]$ReportContent.AppendLine('========================================================================')
                    [void]$ReportContent.AppendLine('END OF REPORT')
                    [void]$ReportContent.AppendLine('========================================================================')

                    $ReportContent.ToString() | Out-File -FilePath $TextReport -Encoding UTF8 -Force
                    [void]$ExportedReports.Add($TextReport)
                    Write-Verbose -Message ('Text Report: {0}' -f $TextReport)

                } #end if ExportReport

            } #end if-else FilesWithPasswords.Count

        } catch {

            Write-Error -Message ('An error occurred during GPP password scan: {0}' -f $_.Exception.Message)
            throw

        } #end try-catch

    } #end Process

    end {

        Write-Verbose -Message '╔════════════════════════════════════════════════════════════════╗'
        Write-Verbose -Message '║  Scan Complete                                                 ║'
        Write-Verbose -Message '╚════════════════════════════════════════════════════════════════╝'

        # Calculate results
        [double]$OldestPasswordAgeYears = 0
        [hashtable]$PasswordsByType = @{}
        [bool]$IsSecure = ($FilesWithPasswords.Count -eq 0)
        [string]$RiskLevel = if ($IsSecure) {
            'None'
        } else {
            'Critical'
        }

        if ($FilesWithPasswords.Count -gt 0) {
            $OldestPassword = $FilesWithPasswords | Sort-Object -Property Created | Select-Object -First 1
            $OldestPasswordAgeYears = [math]::Round(((Get-Date) - $OldestPassword.Created).TotalDays / 365, 1)

            # Build PasswordsByType hashtable
            $GroupsByType = $FilesWithPasswords | Group-Object -Property FileType
            foreach ($Group in $GroupsByType) {
                $PasswordsByType[$Group.Name] = $Group.Count
            } #end foreach
        } #end if

        Write-Verbose -Message 'Summary:'
        Write-Verbose -Message ('  • GPP Password Files: {0} {1}' -f $FilesWithPasswords.Count, $(if ($IsSecure) {
                    '✓ SECURE'
                } else {
                    '🚨 CRITICAL'
                }))
        Write-Verbose -Message ('  • Oldest Password Age: {0} years' -f $OldestPasswordAgeYears)
        Write-Verbose -Message ('  • Passwords Decrypted: {0}' -f $(if ($DecryptPasswords) {
                    'Yes'
                } else {
                    'No'
                }))

        if (-not $IsSecure) {
            Write-Warning -Message 'NEXT ACTIONS:'
            Write-Warning -Message '  1. Rotate ALL discovered passwords IMMEDIATELY'
            Write-Warning -Message '  2. Delete GPP files from SYSVOL after password rotation'
            Write-Warning -Message '  3. Deploy Microsoft LAPS and gMSA'
            Write-Warning -Message '  4. Schedule quarterly re-scans'
        } #end if

        if ($null -ne $Variables -and
            $null -ne $Variables.FooterSecurity) {

            $txt = ($Variables.FooterSecurity -f $MyInvocation.InvocationName,
                'finished detecting group policy preferences passwords.'
            )
            Write-Verbose -Message $txt
        } #end If

        # Return results object
        [PSCustomObject]@{
            PSTypeName         = 'EguibarIT.Security.GPPPasswordAudit'
            DomainName         = $DomainName
            SYSVOLPath         = $SYSVOLPath
            TotalXMLFiles      = $TotalXMLFilesCount
            PasswordFilesFound = $FilesWithPasswords.Count
            PasswordsDecrypted = $DecryptPasswords
            OldestPasswordAge  = $OldestPasswordAgeYears
            PasswordsByType    = $PasswordsByType
            IsSecure           = $IsSecure
            RiskLevel          = $RiskLevel
            FilesDeleted       = $FilesDeleted
            ReportsExported    = $ExportedReports.ToArray()
            AuditDate          = Get-Date
            PasswordFindings   = $FilesWithPasswords.ToArray()
        }

    } #end End

} #end Function Find-GPPPasswords
