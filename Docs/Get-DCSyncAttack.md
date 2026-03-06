# Get-DCSyncAttack Function Documentation

## Overview

**Get-DCSyncAttack** is a comprehensive PowerShell function that detects DCSync attack patterns in Active Directory environments by auditing replication permissions and analyzing event logs.

**Function File:** `Public/Get-DCSyncAttack.ps1`
**Version:** 1.0.0
**Last Modified:** 02/Mar/2026
**Author:** Vicente Rodriguez Eguibar

## Purpose

This function performs three-phase detection of DCSync attacks (MITRE ATT&CK T1003.006):

1. **Permission Audit** - Identifies accounts with replication rights
2. **Event Log Analysis** - Detects suspicious replication activity
3. **Real-Time Monitoring** - Optional continuous detection

## Critical Principle

**ONLY domain controllers should have replication permissions.**
Any other account with replication rights represents a critical security vulnerability.

## Key Features

### Three-Phase Detection

#### Phase 1: Permission Audit

- Enumerates all ACEs on the domain root
- Identifies accounts with DS-Replication rights
- Categorizes findings: Expected (DC) vs. Unexpected (Non-DC)
- Provides remediation commands

#### Phase 2: Event Log Analysis

- Analyzes Event ID 4662 (Directory Service Access)
- Looks for replication GUIDs in security logs
- Correlates events by source account
- Distinguishes legitimate DC-to-DC vs. suspicious traffic

#### Phase 3: Real-Time Monitoring

- Optional continuous monitoring mode
- Checks every 30 seconds for suspicious activity
- Alerts immediately on non-DC replication requests
- Useful for incident response scenarios

### Smart Reporting

- **Risk Assessment:** Categorizes findings (Secure/High/Critical)
- **Actionable Recommendations:** Specific remediation steps
- **Automated Export:** CSV reports and summary files
- **Structured Output:** Suitable for automation and pipeline use

## Usage

### Basic Audit (Default)

```powershell
Get-DCSyncAttack
```

Runs with default 7-day event log scan, displays results to console.

### Extended Historical Analysis

```powershell
Get-DCSyncAttack -TimeSpanDays 30 -Verbose
```

Analyzes 30 days of event logs with verbose progress output.

### Generate Reports

```powershell
Get-DCSyncAttack -ExportPath 'C:\SecurityAudits' -TimeSpanDays 14
```

Exports detailed CSV and text reports to specified directory.

### Real-Time Monitoring

```powershell
Get-DCSyncAttack -MonitorRealTime
```

Enters continuous monitoring mode (Ctrl+C to stop).

### Automation Integration

```powershell
$Result = Get-DCSyncAttack -TimeSpanDays 7
if ($Result.NonDCAccountCount -gt 0) {
    Write-Warning "CRITICAL: $($Result.NonDCAccountCount) non-DC accounts with replication!"
    # Trigger incident response workflow
}
```

## Parameters

### TimeSpanDays

- **Type:** int
- **Default:** 7
- **Range:** 1-365
- **Description:** Number of days to analyze event logs for replication events

### ExportPath

- **Type:** string
- **Default:** C:\Logs
- **Description:** Directory path for exporting CSV and summary reports
- **Validation:** Must be valid file system path

### MonitorRealTime

- **Type:** switch
- **Default:** $false
- **Description:** Enable continuous monitoring mode (runs until Ctrl+C)

### IncludeNormalEvents

- **Type:** switch
- **Default:** $false
- **Description:** Include legitimate DC-to-DC replication events in output

## Output

Returns a structured `PSCustomObject` containing:

```powershell
[PSCustomObject]@{
    DomainName                    # DNS name of audited domain
    DomainDN                      # Distinguished name of domain
    AuditTimestamp                # When audit was performed
    TotalAccountsWithPermissions  # Total accounts with replication rights
    DomainControllerCount         # Expected (DC) accounts
    NonDCAccountCount             # Unexpected (Non-DC) accounts = RISK
    TotalReplicationEvents        # Events found in timespan
    SuspiciousEventCount          # Events from non-DC sources = ATTACKS
    IsSecure                      # Boolean - no risks detected
    RiskLevel                     # Assessment: Secure/High/Critical
    RecommendedActions            # Array of remediation steps
    ExportedReports               # File paths of exported reports
    NonDCAccounts                 # Array of accounts with permissions
    SuspiciousEvents              # Array of suspicious event details
}
```

## Risk Levels

### Secure ✓

- No accounts with replication rights except DCs
- No suspicious activity detected
- **Action:** Continue monitoring

### High ⚠️

- Non-DC accounts have replication permissions
- No active attacks detected
- **Action REQUIRED:**
  - Remove replication permissions immediately
  - Investigate why they were granted
  - Implement strict ACL controls
  - Rotate krbtgt password twice (10+ hour delay)

### Critical 🚨

- Active DCSync attack detected
- Non-DC sources performing replication
- **IMMEDIATE ACTIONS REQUIRED:**
  - Disable compromised account(s)
  - Investigate source systems
  - Assume krbtgt hash compromised
  - Rotate krbtgt password twice
  - Review all Domain Admin accounts
  - Full forensic investigation

## Requirements

- Domain Admin or equivalent rights
- Active Directory module (RSAT-AD-PowerShell)
- Event ID 4662 auditing enabled on all domain controllers
- PowerShell 5.1 or higher

### Enabling Event ID 4662 Auditing

**Group Policy:**

1. Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy
2. Enable: Audit Directory Service Access (Success)

**Command Line:**

```powershell
auditpol /set /subcategory:"Directory Service Access" /success:enable
```

## Implementation Details

### Module Variable Integration

The function dynamically retrieves replication right GUIDs from `$Variables.ExtendedRightsMap` (populated during module initialization) instead of hardcoding:

```powershell
# Dynamic lookup from module variables
$GUID = $Variables.ExtendedRightsMap['DS-Replication-Get-Changes']

# Not hardcoded
# $GUID = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'  # WRONG
```

**Benefits:**

- Single source of truth for AD schema values
- Automatically reflects AD environment changes
- Localization-aware extended rights names
- No maintenance needed when AD updates

### Performance Optimization

Uses ArrayList for dynamic collections (O(1) append):

```powershell
[System.Collections.ArrayList]$Results = @()
[void]$Results.Add($Item)  # Fast append, not += which is O(n²)
```

### Error Handling

- Graceful module loading with `Import-MyModule`
- Comprehensive try-catch blocks per phase
- Detailed error messages with remediation guidance
- Proper error propagation without silencing issues

## Common Findings

### Non-DC Accounts with Replication Rights

**Example Finding:**

```
Identity: CONTOSO\ServiceAccount-DCSync
Permissions: DS-Replication-Get-Changes, DS-Replication-Get-Changes-All
AccessType: Allow
IsInherited: False
```

**Risk:** This service account can dump all AD passwords

**Remediation:**

```powershell
# Remove the permissions
dsacls "DC=contoso,DC=com" /R "CONTOSO\ServiceAccount-DCSync"

# Verify removal - no matching ACEs should appear
Get-Acl -Path "AD:DC=contoso,DC=com" | Where-Object { $_.ObjectType -eq '1131f6aa-...' }
```

### Suspicious Replication Events

**Example Finding:**

```
TimeCreated: 2026-03-02 14:23:45
SubjectUser: CONTOSO\AttackerAccount
DomainController: DC01
IsSuspicious: True
Reason: Non-DC account requesting replication
```

**Risk:** Active DCSync attack in progress

**Response:**

```powershell
# IMMEDIATE - Disable account
Disable-ADAccount -Identity "CONTOSO\AttackerAccount"

# Check for lateral movement
Get-ADUser -Filter * -Properties LastLogonDate, AccountLockoutTime

# Rotate krbtgt twice (10+ hours apart)
# See: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-forest-recovery-procedures
```

## Troubleshooting

### "Module variables not initialized"

**Cause:** `Initialize-ModuleVariable` not called on module import

**Solution:**

```powershell
# Trigger module reload
Remove-Module EguibarIT.SecurityPS -Force
Import-Module EguibarIT.SecurityPS
```

### "No replication events found"

**Causes:**

1. Event ID 4662 auditing not enabled on DCs
2. No replication activity in timeframe
3. Insufficient permissions to read security logs

**Check auditing:**

```powershell
auditpol /get /subcategory:"Directory Service Access"
```

### "Could not resolve SID"

**Cause:** Non-standard accounts or deleted accounts

**Workaround:** Check the SID string directly in output (appears in brackets)

## Performance Notes

- **Small domains (<1000 objects):** < 1 second
- **Medium domains (1000-50000 objects):** 1-5 seconds
- **Large domains (>50000 objects):** 5-30 seconds depending on network latency

Event log analysis timing depends on:

- Number of domain controllers
- Security event log size
- Network connectivity to DCs

## References

- [MITRE ATT&CK T1003.006](https://attack.mitre.org/techniques/T1003/006/)
- [AD Security - DCSync](https://adsecurity.org/?p=1729)
- [Event ID 4662 Documentation](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4662)
- [Protected Users Documentation](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)

## Related Functions

- `Get-UnconstrainedDelegation` - Kerberos delegation audit
- `Get-ADKerberoastingPattern` - Kerberoasting vulnerability detection
- `Find-GPPPasswords` - Group Policy preferences password scanning
- `Get-PasswordSprayAttack` - Password spray attack detection

## Version History

**1.0.0 (02/Mar/2026)**

- Initial release
- Three-phase DCSync detection
- Event log analysis
- Real-time monitoring mode
- Export and reporting functionality
