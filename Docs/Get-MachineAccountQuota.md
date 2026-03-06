# Get-MachineAccountQuota Function Documentation

## Overview

**Get-MachineAccountQuota** is a comprehensive PowerShell function that audits Active Directory MachineAccountQuota configuration and detects rogue computer account creation in Active Directory environments.

**Function File:** `Public/Get-MachineAccountQuota.ps1`
**Version:** 1.1.0
**Last Modified:** 02/Mar/2026
**Author:** Vicente Rodriguez Eguibar

## Purpose

This function performs three-phase security audit of MachineAccountQuota:

1. **Configuration Audit** - Checks if MachineAccountQuota is set to secure value (0)
2. **Event Detection** - Monitors Event ID 4741 for unauthorized computer account creation
3. **Forensic Analysis** - Identifies suspicious computer accounts based on characteristics

## Critical Principle

**By default, ANY authenticated user can add up to 10 computer accounts to a domain.**
This misconfiguration (MachineAccountQuota=10) allows attackers to:
- Create rogue computers for privilege escalation
- Configure Resource-Based Constrained Delegation (RBCD) attacks
- Establish persistence mechanisms
- Perform lateral movement

## Key Features

### Three-Phase Audit

#### Phase 1: Configuration Audit

- Checks current MachineAccountQuota value on domain object
- Compares against recommended secure value (0)
- Provides remediation command for hardening
- Validates historical configuration changes

#### Phase 2: Event Detection (Event ID 4741)

- Monitors computer account creation events from all domain controllers
- Identifies creator account for each new computer
- Compares against authorized creator list (Domain Admins, SCCM, MDT, Intune)
- Flags unauthorized creations for investigation

#### Phase 3: Forensic Analysis

Identifies suspicious computer accounts based on:
- **Never logged on** (potential rogue account never joined to domain)
- **Located in default Computers container** (poor security practice)
- **RBCD configured** (Resource-Based Constrained Delegation = critical attack vector)
- **Suspicious naming patterns** (DESKTOP-, LAPTOP-, TEST-, TEMP-, ATTACKER-, ROGUE-)
- **Recently created** (within audit timespan)
- **Stale password** (password not changed in > 90 days)

### Smart Reporting

- **Risk Categorization:** Critical (RBCD) / High / Medium severity
- **Authorized Creator Validation:** Flags non-authorized account creations
- **Actionable Recommendations:** Specific remediation steps with PowerShell commands
- **Automated Export:** CSV reports and configuration summary

## Usage

### Basic Audit (Default)

```powershell
Get-MachineAccountQuota
```

Runs audit with default settings (last 30 days, default authorized groups).

### Extended Historical Analysis

```powershell
Get-MachineAccountQuota -TimeSpanDays 90 -Verbose
```

Audits the last 90 days with verbose output showing detailed progress.

### Custom Authorized Creators

```powershell
Get-MachineAccountQuota -AuthorizedCreators @('Domain Admins','IT-Ops','SCCM-Service','MDT-Service') -ExportPath 'C:\SecurityAudits'
```

Audits computer account creation and flags accounts created by non-authorized users, exports reports.

### WhatIf Testing

```powershell
Get-MachineAccountQuota -TimeSpanDays 180 -ExportPath 'D:\AuditReports' -WhatIf
```

Shows what the function would do without actually exporting files.

### Automation Integration

```powershell
$Result = Get-MachineAccountQuota -TimeSpanDays 60 -AuthorizedCreators @('Domain Admins') -ExportPath 'C:\Logs'
if (-not $Result.IsSecure) {
    Write-Warning 'MachineAccountQuota is not secure! Immediate action required.'
    # Trigger remediation workflow
}
```

## Parameters

### TimeSpanDays

- **Type:** int
- **Default:** 30 days
- **Range:** 1 to 365 days
- **Description:** Number of days to look back for Event ID 4741 (computer account creation)
- **Use Case:** Analyze recent suspicious computer creation patterns

### AuthorizedCreators

- **Type:** string[]
- **Default:** @('Domain Admins', 'Enterprise Admins', 'Account Operators')
- **Description:** Array of authorized user/group names allowed to create computer accounts
- **Examples:** 'SCCM-Service', 'MDT-Service', 'Intune-Service', 'IT-Ops'
- **Validation:** Accounts created by non-matching principals flagged as suspicious

### ExportPath

- **Type:** string
- **Default:** None (console output only)
- **Description:** Path to export CSV reports and configuration summary
- **Exports:**
  - Suspicious computer creations (CSV)
  - Suspicious computer characteristics (CSV)
  - Configuration audit summary (TXT)
- **WhatIf:** Supports -WhatIf/-Confirm for file operations

## Output

Returns a structured `PSCustomObject` containing:

```powershell
[PSCustomObject]@{
    DomainName                      # DNS name of audited domain
    DomainDN                        # Distinguished name of domain
    AuditTimestamp                  # When audit was performed
    MachineAccountQuotaValue        # Current MAQ setting (secure = 0)
    IsSecure                        # Boolean - whether MAQ is 0
    SuspiciousComputersCount        # Total computers with suspicious characteristics
    CriticalRBCDCount               # Computers with RBCD (critical severity)
    HighRiskCount                   # Computers with multiple suspicious indicators
    ModerateRiskCount               # Computers with minor suspicious indicators
    UnauthorizedCreationsCount      # Computers created by non-authorized users
    RiskLevel                       # Overall: Secure/Low/Medium/High/Critical
    RecommendedActions              # Array of remediation steps
    ExportedReports                 # File paths of exported reports
    SuspiciousComputers             # Array of suspicious computer details
    UnauthorizedCreations           # Array of unauthorized creation events
}
```

### Suspicious Computer Detail Structure

```powershell
@{
    ComputerName                    # Computer account name
    DistinguishedName               # Full DN
    Created                         # Creation timestamp
    Enabled                         # Account enabled status
    LastLogonDate                   # Last successful logon
    PasswordLastSet                 # Password age indicator
    OperatingSystem                 # OS version
    RBCDConfigured                  # Boolean - RBCD delegation set
    SuspiciousNaming                # Boolean - matches suspicious pattern
    InDefaultContainer              # Boolean - in CN=Computers
    NeverLoggedOn                   # Boolean - no logon history
    StalePassword                   # Boolean - password > 90 days
    RiskLevel                       # Critical/High/Medium
    RiskFactors                     # Array of identified risk factors
}
```

## MITRE ATT&CK Mapping

- **T1136.002:** Create Account - Domain Account
- **T1069.002:** Permission Groups Discovery - Domain Groups
- **T1484.001:** Domain Policy Modification - Group Policy Modification
- **T1484.002:** Domain Trust Modification

## Requirements

### Permissions

- **Domain User** or higher for AD queries
- **Event Log Reader** on domain controllers for Event ID 4741
- **Read** access to Security event log
- **Read** access to domain object attributes (ms-DS-MachineAccountQuota)

### Event Logging

Security auditing must be enabled for:
- Event ID 4741 (Computer account created) - Audit Computer Account Management

**Enable auditing:**
```powershell
auditpol /set /subcategory:"Computer Account Management" /success:enable
```

### PowerShell Modules

- **ActiveDirectory** - For domain and computer queries

## Remediation Guidance

### Secure MachineAccountQuota Configuration

**CRITICAL:** Set MachineAccountQuota to 0 to prevent standard users from creating computer accounts.

```powershell
# Check current value
Get-ADDomain | Select-Object -ExpandProperty ms-DS-MachineAccountQuota

# Set to secure value (0)
Set-ADDomain -Identity (Get-ADDomain).DistinguishedName -Replace @{'ms-DS-MachineAccountQuota'='0'}

# Verify change
Get-ADDomain | Select-Object -ExpandProperty ms-DS-MachineAccountQuota
```

**WARNING:** This change is domain-wide and affects all users immediately. Ensure authorized service accounts (SCCM, MDT, Intune) use dedicated accounts with proper permissions.

### Delegate Computer Account Creation

Only authorized service accounts and IT administrators should create computers:

```powershell
# Delegate computer creation to specific group/account
$TargetOU = "OU=Workstations,DC=contoso,DC=com"
$DelegatedGroup = "CN=Computer-Creators,OU=Groups,DC=contoso,DC=com"

# Grant CreateChild permission for computer objects
dsacls $TargetOU /G "$DelegatedGroup:CC;computer"
```

### Remove Rogue Computer Accounts

```powershell
# Identify and remove rogue computers
$Results = Get-MachineAccountQuota -TimeSpanDays 30 -ExportPath 'C:\Logs'

# Review critical RBCD computers
$RBCDComputers = $Results.SuspiciousComputers | Where-Object { $_.RBCDConfigured -eq $true }

foreach ($Computer in $RBCDComputers) {
    Write-Warning "RBCD configured on: $($Computer.ComputerName)"
    
    # Option 1: Remove RBCD delegation
    Set-ADComputer -Identity $Computer.DistinguishedName -PrincipalsAllowedToDelegateToAccount $null
    
    # Option 2: Disable account for investigation
    # Disable-ADAccount -Identity $Computer.DistinguishedName
    
    # Option 3: Delete rogue account (after investigation)
    # Remove-ADComputer -Identity $Computer.DistinguishedName -Confirm
}
```

### Monitor for RBCD Abuse

Resource-Based Constrained Delegation on rogue computers is a **CRITICAL** indicator of attack:

```powershell
# Continuous monitoring for RBCD configuration changes
Get-ADComputer -Filter * -Properties PrincipalsAllowedToDelegateToAccount |
    Where-Object { $_.PrincipalsAllowedToDelegateToAccount -ne $null } |
    Select-Object Name, DistinguishedName, PrincipalsAllowedToDelegateToAccount
```

## Example Workflows

### Weekly Automated Audit

```powershell
# Scheduled task runs weekly
$Result = Get-MachineAccountQuota -TimeSpanDays 7 -ExportPath 'D:\SecurityLogs\MachineAccountQuota'

if (-not $Result.IsSecure) {
    # Send alert to security team
    $Body = @"
MachineAccountQuota Audit Results:
- Current MAQ Value: $($Result.MachineAccountQuotaValue)
- Unauthorized Creations: $($Result.UnauthorizedCreationsCount)
- Suspicious Computers: $($Result.SuspiciousComputersCount)
- Critical RBCD Count: $($Result.CriticalRBCDCount)

IMMEDIATE ACTION REQUIRED if RBCD count > 0!
Review attached reports for details.
"@
    
    Send-MailMessage -To 'security@contoso.com' -Subject "MachineAccountQuota Audit Alert" -Body $Body
}

# Export to SIEM
$Result | ConvertTo-Json -Depth 10 | Out-File 'D:\SIEM\Import\MachineAccountQuota.json'
```

### Incident Response Investigation

```powershell
# Extended forensic analysis
$Result = Get-MachineAccountQuota -TimeSpanDays 180 -AuthorizedCreators @('Domain Admins') -Verbose

# Identify all unauthorized creations
$Unauthorized = $Result.UnauthorizedCreations

# Export for investigation
$Unauthorized | Export-Csv 'C:\IR\UnauthorizedComputerCreations.csv' -NoTypeInformation

# Check for compromised accounts (users creating multiple computers)
$Creators = $Unauthorized | Group-Object -Property CreatorAccount | Where-Object { $_.Count -ge 3 }

foreach ($Creator in $Creators) {
    Write-Warning "User $($Creator.Name) created $($Creator.Count) unauthorized computers!"
    # Investigate account for compromise
    # Get-ADUser -Identity $Creator.Name -Properties LastLogonDate, PasswordLastSet
}
```

## Performance Considerations

- **Event log queries:** Event ID 4741 queries may take 1-2 minutes on large domains
- **Computer enumeration:** Searching for RBCD attributes scans all computer objects
- **Time span:** Longer spans (> 90 days) increase query time proportionally
- **Export operations:** CSV exports are fast (< 1 second for typical datasets)

## False Positives

Common scenarios that may trigger findings:

- **SCCM/MDT service accounts:** Add to AuthorizedCreators parameter
- **Intune/Autopilot:** Add to AuthorizedCreators parameter
- **Test environments:** Computers in default container may be intentional
- **Development:** Developers creating test VMs (should use separate OU)

**Mitigation:** Use `-AuthorizedCreators` parameter to whitelist known legitimate service accounts.

## Related Functions

- [Get-UnconstrainedDelegation](Get-UnconstrainedDelegation.md) - Detects delegation attacks
- [Get-DCSyncAttack](Get-DCSyncAttack.md) - Detects replication permission abuse
- [Find-GPPPasswords](Find-GPPPasswords.md) - Detects stored credentials

## Additional Resources

- [MITRE ATT&CK T1136.002](https://attack.mitre.org/techniques/T1136/002/)
- [Microsoft: ms-DS-MachineAccountQuota](https://docs.microsoft.com/windows/win32/adschema/a-ms-ds-machineaccountquota)
- [Resource-Based Constrained Delegation Abuse](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution)
- [GitHub Repository](https://github.com/vreguibar/EguibarIT.SecurityPS)

---

**Module:** EguibarIT.SecurityPS
**Component:** Security Auditing
**Role:** Configuration Hardening
**Functionality:** MachineAccountQuota Security Audit
