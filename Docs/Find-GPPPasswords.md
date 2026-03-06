# Find-GPPPasswords Function Documentation

## Overview

**Find-GPPPasswords** is a comprehensive PowerShell function that discovers and decrypts passwords stored in Group Policy Preferences (GPP) within SYSVOL, a critical vulnerability patched in MS14-025 but still prevalent in many legacy environments.

**Function File:** `Public/Find-GPPPasswords.ps1`
**Version:** 1.0.0
**Last Modified:** 02/Mar/2026
**Author:** Vicente Rodriguez Eguibar

## Purpose

This function performs comprehensive GPP password discovery and risk analysis:

1. **SYSVOL Discovery** - Searches all XML files in SYSVOL for encrypted passwords
2. **AES-256 Decryption** - Decrypts cpassword attributes using published Microsoft key
3. **Risk Analysis** - Assesses account type, privilege level, and exposure
4. **Remediation Guidance** - Provides specific cleanup and mitigation steps

**Vulnerability Background:**
Prior to MS14-025 (May 2014), Group Policy Preferences allowed storing passwords for:
- Local Administrator accounts
- Scheduled tasks
- Services
- Data sources
- Mapped drives

These passwords were encrypted with AES-256, but Microsoft published the encryption key in MSDN documentation, making decryption trivial for ANY domain user.

## Critical Principle

**ANY domain user can decrypt GPP passwords stored in SYSVOL.**
SYSVOL is replicated to all domain controllers and readable by Authenticated Users. GPP password XML files are:
- Readable by any domain user without special privileges
- Decryptable using published Microsoft AES key
- Often contain local administrator or service account credentials
- Replicated across multiple DCs (difficult to completely erase)

**Attack Scenario:**
```
1. Attacker authenticates as standard domain user
2. Connects to \\domain\SYSVOL share (default access)
3. Finds Groups.xml with cpassword attribute for local admin
4. Decrypts password using publicly available key
5. Uses credential for lateral movement across workstations
```

## Key Features

### Four-Phase Discovery

#### Phase 1: SYSVOL Enumeration

- Connects to SYSVOL share on domain controller
- Searches all GPO folders for XML files
- Identifies files containing 'cpassword' attribute
- Tracks affected GPO GUIDs and file paths

#### Phase 2: Password Extraction & Decryption

- Parses XML structure (Groups.xml, Services.xml, etc.)
- Extracts usernames and encrypted cpassword values
- Decrypts passwords using Microsoft published AES key
- Validates decryption success

#### Phase 3: Context Analysis

- Identifies account type (Local User, Service, Scheduled Task, etc.)
- Extracts group membership (Administrators, Users, etc.)
- Determines GPO name and linkage
- Assesses last modification timestamp

#### Phase 4: Risk Assessment

- **Privilege Detection:** Local Administrator group membership
- **Account Sensitivity:** Built-in Administrator accounts (SID-500)
- **Exposure Age:** Time since password was set in GPO
- **Active Status:** GPO link status (enabled/disabled)

### Smart Risk Categorization

Each finding receives a severity assessment:
- **Critical:** Administrator account OR privileged group membership
- **High:** Service account OR scheduled task credential
- **Medium:** Data source or mapped drive credential
- **Low:** Disabled GPO or > 365 days since modification

## Usage

### Basic Domain-Wide Scan

```powershell
Find-GPPPasswords
```

Discovers all GPP passwords in current domain SYSVOL.

### Comprehensive Analysis with Export

```powershell
Find-GPPPasswords -DomainController 'DC01' -Verbose -ExportPath 'C:\SecurityAudits\GPPPasswords.csv'
```

Full discovery with CSV export and verbose logging.

### Specific Domain Controller

```powershell
Find-GPPPasswords -DomainController 'DC01.contoso.com'
```

Queries specific DC for GPP password files.

### Multiple DC Scan (Comprehensive)

```powershell
Get-ADDomainController -Filter * | ForEach-Object {
    Find-GPPPasswords -DomainController $_.HostName -Verbose
}
```

Scans all domain controllers for complete coverage.

### Export with Remediation Plan

```powershell
$Results = Find-GPPPasswords -ExportPath 'C:\SecurityReports'

# Group by GPO for cleanup
$ByGPO = $Results | Group-Object -Property GPOName

Write-Host "`nGPOs containing GPP passwords: $($ByGPO.Count)"
foreach ($GPO in $ByGPO) {
    Write-Host "`nGPO: $($GPO.Name)"
    Write-Host "  Passwords found: $($GPO.Count)"
    $GPO.Group | Format-Table UserName, AccountType, GroupMembership, Severity
}
```

### Automation Integration

```powershell
# Monthly scheduled scan
$Results = Find-GPPPasswords -Verbose

if ($Results.Count -gt 0) {
    Send-MailMessage -To 'security@contoso.com' `
        -Subject "CRITICAL: GPP Passwords Detected in SYSVOL" `
        -Body "Found $($Results.Count) GPP password entries requiring immediate removal!" `
        -Priority High

    # Export for remediation team
    $Results | Export-Csv 'C:\SecurityAlerts\GPPPasswords-Found.csv' -NoTypeInformation
} else {
    Write-Host "No GPP passwords detected - environment clean"
}
```

## Parameters

### DomainController

- **Type:** string
- **Default:** Auto-discovered from current domain
- **Description:** Target domain controller for SYSVOL access
- **Pipeline:** Accepts 'HostName' or 'Name' from Get-ADDomainController
- **Permissions:** Any authenticated domain user (SYSVOL is world-readable)

### SysvolPath

- **Type:** string
- **Default:** `\\$DomainController\SYSVOL\$DomainFQDN\Policies`
- **Description:** Custom SYSVOL path (for non-standard configurations)
- **Example:** '\\DC01\SYSVOL\contoso.com\Policies'

### ExportPath

- **Type:** string
- **Default:** None (console output only)
- **Description:** Directory path for CSV export
- **WhatIf:** Supports -WhatIf/-Confirm for file operations
- **Example:** 'C:\SecurityAudits' (creates timestamped CSV)

## Output

Returns `PSCustomObject` array with the following properties:

```powershell
[PSCustomObject]@{
    UserName                # Username configured in GPP
    Password                # DECRYPTED password (cleartext)
    AccountType             # LocalUser/LocalService/ScheduledTask/DataSource/Drive
    GroupMembership         # Group(s) account is member of
    GPOName                 # Friendly name of Group Policy Object
    GPOGUID                 # GUID of affected GPO
    GPOPath                 # File path to XML in SYSVOL
    FileName                # XML filename (Groups.xml, Services.xml, etc.)
    Changed                 # Last modified timestamp of XML
    ExposureAgeDays         # Days since password was set in GPO
    GPOLinked               # Boolean - GPO currently linked/enabled
    IsAdministrator         # Boolean - member of Administrators group
    IsBuiltinAdmin          # Boolean - SID-500 Administrator account
    Severity                # Critical/High/Medium/Low
    RecommendedActions      # Array of remediation steps
}
```

## Severity Levels

| Severity | Criteria |
|----------|----------|
| **Critical** | Built-in Administrator (SID-500) OR Administrators group membership |
| **High** | Service account OR scheduled task credential |
| **Medium** | Data source, mapped drive, or standard user credential |
| **Low** | GPO disabled/unlinked OR > 365 days since modification |

## MITRE ATT&CK Mapping

- **T1552.006:** Unsecured Credentials - Group Policy Preferences
- **T1552:** Unsecured Credentials (parent technique)
- **T1003.002:** OS Credential Dumping - Security Account Manager

## Requirements

### Permissions

- **Authenticated Users** (ANY domain user can access SYSVOL)
- **No special privileges required** for discovery
- **Domain Admin** required for GPO cleanup/remediation

### Network Access

- **SMB access** to domain controller SYSVOL share (port 445)
- **DNS resolution** for domain controller name resolution

### PowerShell Modules

- **ActiveDirectory** - For GPO and domain queries
- **System.Security** - For AES-256 decryption

## Remediation Guidance

### Immediate Actions: Remove GPP Passwords

**CRITICAL:** Remove ALL cpassword attributes from GPP XML files immediately.

```powershell
# Step 1: Identify affected GPOs
$Results = Find-GPPPasswords

# Step 2: Open each GPO in GPMC for cleanup
foreach ($Finding in $Results) {
    Write-Warning "`nGPO: $($Finding.GPOName)"
    Write-Host "  File: $($Finding.FileName)"
    Write-Host "  User: $($Finding.UserName)"
    Write-Host "  Password: $($Finding.Password)"  # Document for rotation

    # Open GPO for editing
    Write-Host "`nAction: Remove password from preference item in GPMC"
    Write-Host "  Path: Computer/User Configuration -> Preferences -> Control Panel Settings"
}
```

### Automated GPP Password Removal (Direct XML Edit)

**WARNING:** Direct XML editing bypasses GPMC validation. Test thoroughly.

```powershell
# Backup SYSVOL before modification
$BackupPath = 'C:\GPOBackup'
New-Item -Path $BackupPath -ItemType Directory -Force

# Remove cpassword attributes from XML files
$Results = Find-GPPPasswords
foreach ($Finding in $Results) {
    # Backup original file
    $BackupFile = Join-Path $BackupPath (Split-Path $Finding.GPOPath -Leaf)
    Copy-Item -Path $Finding.GPOPath -Destination $BackupFile

    # Load XML
    [xml]$XML = Get-Content $Finding.GPOPath

    # Remove cpassword attribute
    $Nodes = $XML.SelectNodes("//*[@cpassword]")
    foreach ($Node in $Nodes) {
        $Node.RemoveAttribute('cpassword')
        Write-Host "Removed cpassword from $($Finding.GPOPath)"
    }

    # Save modified XML
    $XML.Save($Finding.GPOPath)

    # Increment GPO version to trigger replication
    $GPO = Get-GPO -Guid $Finding.GPOGUID
    $GPO.MakeAclConsistent()  # Forces version increment
}

Write-Host "`nGPP passwords removed. Backup saved to: $BackupPath"
```

### Rotate Affected Credentials

```powershell
# All decrypted passwords MUST be considered compromised
$Results = Find-GPPPasswords

# Group by credential type
$LocalAdmins = $Results | Where-Object { $_.IsAdministrator -eq $true }
$ServiceAccounts = $Results | Where-Object { $_.AccountType -eq 'LocalService' }
$ScheduledTasks = $Results | Where-Object { $_.AccountType -eq 'ScheduledTask' }

# Rotate local administrator passwords
Write-Host "Local Administrator Credentials to Rotate:"
$LocalAdmins | Format-Table UserName, Password, GPOName

# Implement LAPS for automated local admin password rotation
Write-Host "`nRecommendation: Deploy Local Administrator Password Solution (LAPS)"
Write-Host "  https://docs.microsoft.com/windows-server/identity/laps/laps-overview"

# Document service account passwords for manual rotation
Write-Host "`nService Account Credentials to Rotate:"
$ServiceAccounts | Format-Table UserName, Password, GPOName
```

### Implement Group Managed Service Accounts (gMSA)

```powershell
# For service accounts discovered in GPP
$ServiceAccounts = Find-GPPPasswords | Where-Object { $_.AccountType -eq 'LocalService' }

foreach ($Account in $ServiceAccounts) {
    Write-Host "`nMigrate to gMSA: $($Account.UserName)"
    Write-Host "  Current Password: $($Account.Password)"
    Write-Host "  Used in GPO: $($Account.GPOName)"

    # gMSA creation template (customize per service)
    Write-Host "`nExample gMSA creation:"
    Write-Host "  New-ADServiceAccount -Name 'svc-$($Account.UserName)' -DNSHostName 'svc-$($Account.UserName).contoso.com' -PrincipalsAllowedToRetrieveManagedPassword 'CN=Server01,OU=Servers,DC=contoso,DC=com'"
}
```

### Implement Continuous Monitoring

```powershell
# Scheduled task runs weekly
$Results = Find-GPPPasswords

if ($Results.Count -eq 0) {
    Write-Host "GPP password scan complete - No passwords detected"
} else {
    # Compare to baseline
    $BaselinePath = 'C:\SecurityBaselines\GPPPasswords-Baseline.csv'

    if (Test-Path $BaselinePath) {
        $Baseline = Import-Csv $BaselinePath

        # Alert on NEW passwords (should never happen after remediation)
        $NewPasswords = $Results | Where-Object {
            $_.GPOGUID -notin $Baseline.GPOGUID
        }

        if ($NewPasswords.Count -gt 0) {
            Send-MailMessage -To 'security@contoso.com' `
                -Subject "CRITICAL: New GPP Passwords Detected" `
                -Body "Detected $($NewPasswords.Count) NEW GPP passwords after remediation! Possible re-introduction." `
                -Priority High
        }
    } else {
        # Create baseline (should be empty after remediation)
        $Results | Export-Csv $BaselinePath -NoTypeInformation
    }
}
```

## Example Workflows

### Initial Discovery and Remediation Campaign

```powershell
# Step 1: Comprehensive domain-wide scan
$Results = Find-GPPPasswords -Verbose -ExportPath 'C:\SecurityReports'

Write-Host "`nGPP Password Discovery Summary:"
Write-Host "  Total passwords found: $($Results.Count)"

# Step 2: Group by severity
$BySeverity = $Results | Group-Object -Property Severity
foreach ($Group in $BySeverity) {
    Write-Host "  $($Group.Name): $($Group.Count) passwords"
}

# Step 3: Identify critical exposures
$CriticalFindings = $Results | Where-Object { $_.Severity -eq 'Critical' }
if ($CriticalFindings.Count -gt 0) {
    Write-Warning "`nCRITICAL: $($CriticalFindings.Count) privileged credentials exposed!"
    $CriticalFindings | Format-Table UserName, Password, GroupMembership, GPOName
}

# Step 4: Generate remediation plan
$ByGPO = $Results | Group-Object -Property GPOName
Write-Host "`nRemediation Plan - $($ByGPO.Count) GPOs require cleanup:"
foreach ($GPO in $ByGPO) {
    Write-Host "`n  GPO: $($GPO.Name)"
    Write-Host "    Passwords: $($GPO.Count)"
    Write-Host "    Action: Open GPO in GPMC and remove password preferences"
}

# Step 5: Document credentials for rotation
Write-Host "`nCredential Rotation Required:"
$Results | Select-Object UserName, Password, AccountType |
    Sort-Object AccountType |
    Format-Table -AutoSize
```

### Incident Response Investigation

```powershell
# During suspected lateral movement incident
$Results = Find-GPPPasswords

# Check if compromised account matches GPP password
$CompromisedAccount = 'LocalAdmin'
$Match = $Results | Where-Object { $_.UserName -eq $CompromisedAccount }

if ($Match) {
    Write-Warning "CONFIRMED: Compromised account '$CompromisedAccount' found in GPP passwords!"
    Write-Host "  Password: $($Match.Password)"
    Write-Host "  Exposure: $($Match.ExposureAgeDays) days"
    Write-Host "  GPO: $($Match.GPOName)"
    Write-Host "  Group Membership: $($Match.GroupMembership)"

    # Check for recent access to this GPO
    $GPOPath = $Match.GPOPath
    Write-Host "`nRecent access to affected GPO file:"
    Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 5145  # Network share object access
        StartTime = (Get-Date).AddDays(-7)
    } | Where-Object { $_.Properties[6].Value -like "*$($Match.GPOGUID)*" } |
        Select-Object TimeCreated, @{N='User';E={$_.Properties[1].Value}}, @{N='SourceIP';E={$_.Properties[18].Value}}
}
```

### Post-Remediation Validation

```powershell
# After GPP password removal, verify cleanup
$Results = Find-GPPPasswords

if ($Results.Count -eq 0) {
    Write-Host "SUCCESS: No GPP passwords detected. Environment clean." -ForegroundColor Green
} else {
    Write-Warning "Remediation incomplete. $($Results.Count) passwords still present:"
    $Results | Format-Table GPOName, UserName, FileName
}

# Verify GPO replication
$DCs = Get-ADDomainController -Filter *
foreach ($DC in $DCs) {
    $DCResults = Find-GPPPasswords -DomainController $DC.HostName
    Write-Host "$($DC.HostName): $($DCResults.Count) GPP passwords"
}
```

## Performance Considerations

- **SYSVOL scan:** Typically completes in < 1 minute for most domains
- **Large environments:** 1000+ GPOs may take 2-5 minutes
- **Network latency:** WAN-connected DCs may have slower SYSVOL access
- **XML parsing:** Minimal CPU impact

## False Positives

Common scenarios that may appear as findings:

- **Disabled GPOs:** GPO exists but not linked/applied (still requires cleanup)
- **Test GPOs:** Lab environment policies (should still be removed)
- **Legacy GPOs:** Old policies no longer in use (delete entirely)

**Best Practice:** ALL GPP passwords must be removed regardless of GPO status. Even disabled GPOs replicate to SYSVOL and remain readable.

## Related Functions

- [Get-ADKerberoastingPattern](Get-ADKerberoastingPattern.md) - Detects Kerberoasting attacks
- [Get-PasswordSprayAttack](Get-PasswordSprayAttack.md) - Detects password spraying
- [Get-ADASREPRoastingVulnerability](Get-ADASREPRoastingVulnerability.md) - Detects AS-REP Roasting

## Additional Resources

- [MITRE ATT&CK T1552.006](https://attack.mitre.org/techniques/T1552/006/)
- [MS14-025 Security Bulletin](https://docs.microsoft.com/security-updates/securitybulletins/2014/ms14-025)
- [Local Administrator Password Solution (LAPS)](https://docs.microsoft.com/windows-server/identity/laps/laps-overview)
- [Group Managed Service Accounts](https://docs.microsoft.com/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview)
- [GPP Password Vulnerability](https://adsecurity.org/?p=63)
- [GitHub Repository](https://github.com/vreguibar/EguibarIT.SecurityPS)

---

**Module:** EguibarIT.SecurityPS
**Component:** Security Auditing
**Role:** Vulnerability Assessment
**Functionality:** GPP Password Discovery and Decryption
