# Get-UnconstrainedDelegation Function Documentation

## Overview

**Get-UnconstrainedDelegation** is a comprehensive PowerShell function that identifies and analyzes Active Directory objects configured with Unconstrained Delegation, one of the most dangerous misconfigurations in Active Directory environments.

**Function File:** `Public/Get-UnconstrainedDelegation.ps1`
**Version:** 1.0.0
**Last Modified:** 02/Mar/2026
**Author:** Vicente Rodriguez Eguibar

## Purpose

This function performs comprehensive detection and risk analysis for Unconstrained Delegation:

1. **Configuration Identification** - Locates computers and users with TRUSTED_FOR_DELEGATION flag
2. **Risk Analysis** - Assesses account activity, operating system, and location
3. **Privileged Account Protection** - Identifies delegation-protected privileged accounts

**Attack Method:** Unconstrained Delegation allows attackers to:
1. Compromise a delegated server/computer
2. Wait for privileged users to authenticate to the compromised system
3. Extract user TGTs from LSASS memory
4. Use stolen TGTs to impersonate privileged users across domain

## Critical Principle

**Unconstrained Delegation creates domain-wide privilege escalation vectors.**
When a user authenticates to an unconstrained delegation system, their TGT is delivered to that system. An attacker with local admin on the delegated system can extract ALL TGTs and impersonate ANY user that authenticates—including Domain Admins. This is the **most dangerous** delegation configuration in AD.

**Attack Scenario:**
```
1. Attacker compromises Computer01 (unconstrained delegation enabled)
2. Domain Admin connects to Computer01 (routine administration)
3. Domain Admin TGT is cached in Computer01's LSASS
4. Attacker extracts Domain Admin TGT using Mimikatz
5. Attacker impersonates Domain Admin across entire domain
```

## Key Features

### Three-Phase Analysis

#### Phase 1: Configuration Discovery

- Identifies all objects with TRUSTED_FOR_DELEGATION flag
- Separates computers from user accounts
- Excludes domain controllers (legitimate delegation)
- Tracks total delegation exposure

#### Phase 2: Risk Factor Assessment

For each delegated object:
- **Activity Status:** Enabled vs. disabled accounts
- **Last Activity:** Password age and logon timestamps
- **Operating System:** OS version and service pack (computers only)
- **Organizational Unit:** Placement in AD structure
- **Description:** Documented justification or purpose
- **Created Date:** Age of configuration

#### Phase 3: Privileged Account Protection Analysis

- Checks for "Account is sensitive and cannot be delegated" flag
- Validates Protected Users group membership
- Identifies privileged accounts WITHOUT protection
- **Critical Finding:** Privileged users not protected from delegation attacks

### Smart Risk Categorization

Each finding receives a severity assessment:
- **Critical:** Active privileged account without delegation protection
- **High:** Active computer/account with recent activity (< 90 days)
- **Medium:** Active account with stale activity (90-180 days)
- **Low:** Disabled account or > 180 days inactive

## Usage

### Basic Domain-Wide Scan

```powershell
Get-UnconstrainedDelegation
```

Discovers all unconstrained delegation configurations in the current domain.

### Comprehensive Analysis with Export

```powershell
Get-UnconstrainedDelegation -Verbose -ExportPath 'C:\SecurityAudits\UnconstrainedDelegation.csv'
```

Full risk analysis with CSV export and verbose logging.

### Identify Unprotected Privileged Accounts

```powershell
$Results = Get-UnconstrainedDelegation
$UnprotectedPrivileged = $Results | Where-Object {
    $_.Severity -eq 'Critical' -and
    $_.IsPrivilegedAccount -eq $true
}

if ($UnprotectedPrivileged.Count -gt 0) {
    Write-Warning "CRITICAL: $($UnprotectedPrivileged.Count) privileged accounts vulnerable to delegation attacks!"
    $UnprotectedPrivileged | Format-Table SamAccountName, ObjectType, ProtectedFromDelegation, LastLogonDate
}
```

### Custom Privileged Group Detection

```powershell
$CustomGroups = @(
    'CN=Database Admins,OU=Groups,DC=contoso,DC=com',
    'CN=Exchange Admins,OU=Groups,DC=contoso,DC=com'
)

Get-UnconstrainedDelegation -PrivilegedGroupIdentities $CustomGroups -Verbose
```

Includes custom groups in privilege detection logic.

### Domain Controller Exclusion

```powershell
Get-UnconstrainedDelegation -ExcludeDomainControllers
```

Excludes domain controllers from results (they have legitimate delegation).

### Filter by Object Type

```powershell
# Computers only
Get-UnconstrainedDelegation | Where-Object { $_.ObjectType -eq 'Computer' }

# Users/Service accounts only
Get-UnconstrainedDelegation | Where-Object { $_.ObjectType -eq 'User' }
```

### Automation Integration

```powershell
# Daily scheduled task
$Results = Get-UnconstrainedDelegation -ExportPath 'C:\SecurityReports'

# Alert on new high-risk findings
$HighRisk = $Results | Where-Object { $_.Severity -in @('Critical', 'High') }

if ($HighRisk.Count -gt 0) {
    Send-MailMessage -To 'security@contoso.com' `
        -Subject "Unconstrained Delegation Risk Detected" `
        -Body "Found $($HighRisk.Count) high-risk delegation configurations requiring immediate review."
}
```

## Parameters

### ExcludeDomainControllers

- **Type:** switch
- **Default:** $true (domain controllers excluded by default)
- **Description:** Domain controllers require unconstrained delegation for Kerberos; exclude from risk analysis
- **Note:** Set to $false to include DCs in output

### PrivilegedGroupIdentities

- **Type:** string[]
- **Default:** None (uses built-in privileged groups)
- **Description:** Additional groups to consider privileged
- **Accepts:** Distinguished Names (DN), SIDs, or sAMAccountNames
- **Examples:** @('CN=SQL Admins,OU=Groups,DC=contoso,DC=com', 'S-1-5-21-...-1150')

### PrivilegedUserIdentities

- **Type:** string[]
- **Default:** None
- **Description:** Additional users to consider privileged
- **Accepts:** Distinguished Names (DN), SIDs, or sAMAccountNames
- **Examples:** @('CN=Backup Admin,OU=Users,DC=contoso,DC=com', 'CONTOSO\ServiceAccount')

### ExportPath

- **Type:** string
- **Default:** None (console output only)
- **Description:** Directory path for CSV export
- **WhatIf:** Supports -WhatIf/-Confirm for file operations
- **Example:** 'C:\SecurityAudits' (creates timestamped CSV)

### IncludeBuiltinAdministrators

- **Type:** switch
- **Default:** $true
- **Description:** Include Administrators group (S-1-5-32-544) in privilege check

## Output

Returns `PSCustomObject` array with the following properties:

```powershell
[PSCustomObject]@{
    SamAccountName              # Account name
    ObjectType                  # 'Computer' or 'User'
    Enabled                     # Boolean - account enabled status
    OperatingSystem             # OS version (computers only)
    OperatingSystemServicePack  # Service pack (computers only)
    PasswordLastSet             # Last password change date
    PasswordAge                 # Age in days
    LastLogonDate               # Last successful logon timestamp
    DistinguishedName           # Full DN
    Description                 # Account description
    Created                     # Creation date
    IsPrivilegedAccount         # Boolean - member of privileged groups
    ProtectedFromDelegation     # Boolean - NOT_DELEGATED flag set
    InProtectedUsersGroup       # Boolean - Protected Users group member
    Severity                    # Critical/High/Medium/Low
    RiskFactors                 # Array of identified risks
    RecommendedActions          # Array of remediation steps
}
```

## Severity Levels

| Severity | Criteria |
|----------|----------|
| **Critical** | Privileged account (DA/EA/SA) without delegation protection enabled |
| **High** | Active account with password age < 90 days (frequent use) |
| **Medium** | Active account with password age 90-180 days (moderate use) |
| **Low** | Disabled account OR password age > 180 days (minimal risk) |

## MITRE ATT&CK Mapping

- **T1484:** Domain Policy Modification (configuring unconstrained delegation)
- **T1558.003:** Kerberoasting (service ticket extraction from delegated systems)
- **T1550.003:** Pass the Ticket (using extracted TGTs)

## Requirements

### Permissions

- **Domain Admin** or equivalent for userAccountControl attribute queries
- **Read** access to domain objects

### PowerShell Modules

- **ActiveDirectory** - For user, computer, and group queries

## Remediation Guidance

### Immediate Actions for Critical Findings

**Priority 1: Protect Privileged Accounts from Delegation**

```powershell
# Identify unprotected privileged accounts
$Results = Get-UnconstrainedDelegation
$Unprotected = $Results | Where-Object {
    $_.IsPrivilegedAccount -eq $true -and
    $_.ProtectedFromDelegation -eq $false
}

# Enable delegation protection for privileged accounts
foreach ($Account in $Unprotected) {
    Set-ADAccountControl -Identity $Account.SamAccountName -AccountNotDelegated $true
    Write-Host "Protected $($Account.SamAccountName) from delegation attacks"
}

# Verify protection
Get-ADUser -Filter {adminCount -eq 1} -Properties AccountNotDelegated |
    Where-Object { $_.AccountNotDelegated -eq $false }
# Should return no results
```

**Priority 2: Add Privileged Users to Protected Users Group**

```powershell
# Protected Users group provides automatic delegation protection
$ProtectedUsersGroup = Get-ADGroup -Identity 'Protected Users'

$PrivilegedUsers = Get-ADUser -Filter {adminCount -eq 1} -Properties MemberOf
foreach ($User in $PrivilegedUsers) {
    if ($User.MemberOf -notcontains $ProtectedUsersGroup.DistinguishedName) {
        Add-ADGroupMember -Identity $ProtectedUsersGroup -Members $User
        Write-Host "Added $($User.SamAccountName) to Protected Users group"
    }
}
```

### Migrate from Unconstrained to Constrained Delegation

**Resource-Based Constrained Delegation (RBCD) is the modern replacement.**

```powershell
# Identify unconstrained delegation computers
$Results = Get-UnconstrainedDelegation -ExcludeDomainControllers
$Computers = $Results | Where-Object { $_.ObjectType -eq 'Computer' -and $_.Enabled -eq $true }

foreach ($Computer in $Computers) {
    Write-Host "`nReviewing: $($Computer.SamAccountName)"
    Write-Host "  Description: $($Computer.Description)"
    Write-Host "  OU: $($Computer.DistinguishedName -replace '^CN=[^,]+,')"

    # Document current delegation usage
    Write-Host "  Action Required: Identify services requiring delegation"
    Write-Host "  Migration: Configure Resource-Based Constrained Delegation"

    # Example RBCD configuration (requires service analysis):
    # Set-ADComputer -Identity $Computer.SamAccountName -PrincipalsAllowedToDelegateToAccount @{Add='CN=WebServer01,OU=Servers,DC=contoso,DC=com'}

    # After migration, remove unconstrained delegation
    # Set-ADAccountControl -Identity $Computer.SamAccountName -TrustedForDelegation $false
}
```

### Remove Delegation from Service Accounts

```powershell
# User accounts should NEVER have unconstrained delegation
$Results = Get-UnconstrainedDelegation
$UserAccounts = $Results | Where-Object { $_.ObjectType -eq 'User' }

foreach ($User in $UserAccounts) {
    # Remove delegation flag
    Set-ADAccountControl -Identity $User.SamAccountName -TrustedForDelegation $false
    Write-Warning "Removed unconstrained delegation from user: $($User.SamAccountName)"

    # If service account requires delegation, investigate constrained delegation
    Write-Host "  Review: Does $($User.SamAccountName) require constrained delegation?"
}
```

### Implement Continuous Monitoring

```powershell
# Scheduled task runs weekly
$Results = Get-UnconstrainedDelegation -ExportPath 'C:\SecurityReports'

# Compare to baseline
$BaselinePath = 'C:\SecurityBaselines\UnconstrainedDelegation-Baseline.csv'
if (Test-Path $BaselinePath) {
    $Baseline = Import-Csv $BaselinePath
    $New = $Results | Where-Object {
        $_.SamAccountName -notin $Baseline.SamAccountName
    }

    if ($New.Count -gt 0) {
        Send-MailMessage -To 'security@contoso.com' `
            -Subject "ALERT: New Unconstrained Delegation Configuration" `
            -Body "Detected $($New.Count) new unconstrained delegation configurations requiring review!"
    }
} else {
    # Create baseline on first run
    $Results | Export-Csv $BaselinePath -NoTypeInformation
}
```

## Example Workflows

### Prioritized Remediation Campaign

```powershell
# Step 1: Identify all unconstrained delegation
$Results = Get-UnconstrainedDelegation -Verbose

# Step 2: Group by severity
$BySeverity = $Results | Group-Object -Property Severity

Write-Host "`nUnconstrained Delegation Risk Summary:"
foreach ($Group in $BySeverity) {
    Write-Host "  $($Group.Name): $($Group.Count) objects"
}

# Step 3: Auto-remediate disabled accounts (safe)
$DisabledAccounts = $Results | Where-Object { $_.Enabled -eq $false }
foreach ($Account in $DisabledAccounts) {
    Set-ADAccountControl -Identity $Account.SamAccountName -TrustedForDelegation $false
    Write-Host "Removed delegation from disabled account: $($Account.SamAccountName)"
}

# Step 4: Protect all privileged accounts (automated)
$PrivilegedAccounts = $Results | Where-Object {
    $_.IsPrivilegedAccount -eq $true -and
    $_.ProtectedFromDelegation -eq $false
}
foreach ($Account in $PrivilegedAccounts) {
    Set-ADAccountControl -Identity $Account.SamAccountName -AccountNotDelegated $true
    Write-Host "Protected privileged account: $($Account.SamAccountName)"
}

# Step 5: Manual review required for active delegated systems
$RequiresReview = $Results | Where-Object {
    $_.Enabled -eq $true -and
    $_.Severity -in @('High', 'Medium')
}

if ($RequiresReview.Count -gt 0) {
    Write-Warning "`nManual review required for $($RequiresReview.Count) active delegated systems:"
    $RequiresReview | Format-Table SamAccountName, ObjectType, PasswordAge, LastLogonDate, Description
}
```

### Incident Response Investigation

```powershell
# During suspected delegation attack
$Results = Get-UnconstrainedDelegation -ExcludeDomainControllers

# Identify recently modified delegation configurations
$Recent = $Results | Where-Object {
    ((Get-Date) - $_.Created).TotalDays -lt 30
}

if ($Recent.Count -gt 0) {
    Write-Warning "Recently created unconstrained delegation configurations:"
    $Recent | Format-Table SamAccountName, Created, Description

    # Investigate each
    foreach ($Object in $Recent) {
        # Check for suspicious activity
        $Events = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            ID = 4624  # Logon events
            StartTime = $Object.Created
        } | Where-Object { $_.Properties[5].Value -eq $Object.SamAccountName }

        Write-Host "`nActivity for $($Object.SamAccountName) since creation:"
        $Events | Select-Object TimeCreated, @{N='SourceIP';E={$_.Properties[18].Value}}
    }
}
```

## Performance Considerations

- **AD queries:** Searching for TRUSTED_FOR_DELEGATION flag is fast (indexed attribute)
- **Large domains:** May take 2-5 minutes for 100,000+ objects
- **Network:** Query performance depends on DC proximity

## False Positives

Common scenarios that may appear as findings:

- **Domain Controllers:** Legitimately require unconstrained delegation (excluded by default)
- **Print Servers:** May require delegation for print queue access (migrate to RBCD)
- **Legacy Applications:** Some old enterprise software requires unconstrained delegation (should be upgraded)
- **Test/Development:** Lab environments may have delegation for convenience (should still be protected)

**Best Practice:** No modern use case REQUIRES unconstrained delegation. Migrate ALL configurations to Resource-Based Constrained Delegation (RBCD).

## Related Functions

- [Get-GoldenTicketDetection](Get-GoldenTicketDetection.md) - Detects forged TGTs
- [Get-SilverTicketDetection](Get-SilverTicketDetection.md) - Detects forged service tickets
- [Get-ADKerberoastingPattern](Get-ADKerberoastingPattern.md) - Detects Kerberoasting attacks

## Additional Resources

- [MITRE ATT&CK T1484](https://attack.mitre.org/techniques/T1484/)
- [Unconstrained Delegation Explained](https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/)
- [Resource-Based Constrained Delegation](https://docs.microsoft.com/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Protected Users Security Group](https://docs.microsoft.com/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [GitHub Repository](https://github.com/vreguibar/EguibarIT.SecurityPS)

---

**Module:** EguibarIT.SecurityPS
**Component:** Security Auditing
**Role:** Configuration Assessment
**Functionality:** Unconstrained Delegation Risk Detection
