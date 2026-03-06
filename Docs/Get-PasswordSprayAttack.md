# Get-PasswordSprayAttack Function Documentation

## Overview

**Get-PasswordSprayAttack** is a comprehensive PowerShell function that detects password spraying attacks by analyzing authentication failure patterns across multiple accounts in Active Directory environments.

**Function File:** `Public/Get-PasswordSprayAttack.ps1`
**Version:** 1.0.0
**Last Modified:** 02/Mar/2026
**Author:** Vicente Rodriguez Eguibar

## Purpose

This function detects password spraying attacks (MITRE ATT&CK T1110.003) by analyzing:

- Event ID 4625 (Failed Windows logon) - NTLM authentication failures
- Event ID 4771 (Failed Kerberos pre-authentication) - Kerberos failures

**Attack Pattern:** Unlike brute-force attacks (many failures against ONE account), password spraying shows **few failures against MANY different accounts** from the same source IP.

## Critical Principle

**Password spraying avoids account lockout by trying common passwords against multiple accounts.**
Attackers use this technique to:
- Test common passwords (Welcome1, Summer2024, Company123)
- Stay below lockout threshold (< 3-5 failures per account)
- Target hundreds of accounts from single source
- Identify weak passwords without triggering alerts

## Key Features

### Detection Logic

- **Source IP Correlation:** Identifies IPs with failed logons against multiple different accounts
- **Dual Protocol Analysis:** Correlates NTLM (4625) and Kerberos (4771) failures
- **False Positive Filtering:** Excludes legitimate service accounts and VPN gateways
- **Temporal Pattern Analysis:** Tracks slow sprays spaced to avoid lockout
- **Success Correlation:** Checks for successful logons from spray source IPs (compromised credentials)

### Smart Analysis

- **Unique Account Threshold:** Configurable alert threshold (default: 10 accounts)
- **Time Window Analysis:** Configurable lookback period (default: 60 minutes)
- **Source IP Exclusion:** Whitelist known legitimate sources
- **Attack Duration Tracking:** Measures spray campaign duration
- **Failures Per Account:** Calculates average to distinguish spray from brute-force

## Usage

### Basic Detection (Default)

```powershell
Get-PasswordSprayAttack -DomainController 'DC01.contoso.com' -TimeSpanMinutes 120 -Verbose
```

Analyzes authentication failures on DC01 using FQDN for the last 2 hours with verbose output.

### Higher Sensitivity with IP Exclusion

```powershell
Get-PasswordSprayAttack -DomainController 'DC01' -FailureThreshold 15 -ExcludeSourceIPs @('10.0.1.50', '10.0.1.51')
```

Detects sprays with higher threshold (15 accounts) and excludes known legitimate sources (VPN gateways).

### Multiple Domain Controllers via Pipeline

```powershell
'DC01.contoso.com', 'DC02.contoso.com' | Get-PasswordSprayAttack -TimeSpanMinutes 30 -ExportPath 'C:\SecurityAudits\PasswordSpray.csv'
```

Analyzes multiple domain controllers via pipeline and exports results to CSV file.

### Comprehensive Domain-Wide Scan

```powershell
Get-ADDomainController -Filter * | Get-PasswordSprayAttack -FailureThreshold 5 -Verbose
```

Discovers all domain controllers and automatically scans each for password spray attacks.

### Automation Integration

```powershell
$Result = Get-PasswordSprayAttack -TimeSpanMinutes 60
if ($Result.Count -gt 0) {
    foreach ($Attack in $Result) {
        if ($Attack.Severity -eq 'Critical') {
            Write-Warning "CRITICAL: Password spray from $($Attack.SourceIP) targeting $($Attack.UniqueTargetAccounts) accounts!"
            # Block IP at firewall
            # New-NetFirewallRule -DisplayName "Block $($Attack.SourceIP)" -Direction Inbound -RemoteAddress $Attack.SourceIP -Action Block
        }
    }
}
```

## Parameters

### DomainController

- **Type:** string
- **Default:** Auto-discovered from current domain
- **Description:** DNS hostname (FQDN) or NetBIOS name of the domain controller to query
- **Pipeline:** Accepts 'HostName' or 'Name' from Get-ADDomainController
- **Validation:** Valid resolvable hostname (not DN, GUID, or SID)
- **Permissions:** Event Log Reader permissions required

### TimeSpanMinutes

- **Type:** int
- **Default:** 60 minutes
- **Range:** 1 to 10080 minutes (7 days)
- **Description:** Number of minutes to look back in security event logs

### FailureThreshold

- **Type:** int
- **Default:** 10 accounts
- **Range:** 2 to 1000 accounts
- **Description:** Number of unique accounts with failures from single source IP to trigger alert
- **Tuning:** Lower = higher sensitivity + more false positives

### ExcludeSourceIPs

- **Type:** string[]
- **Default:** Empty array
- **Description:** IP addresses to exclude from analysis (VPN gateways, RDP gateways, Exchange servers)
- **Supports:** IPv4 and IPv6 addresses
- **Examples:** @('10.0.1.50', '192.168.1.100', '2001:db8::1')

### ExportPath

- **Type:** string
- **Default:** None (console output only)
- **Description:** Path to export detailed findings to CSV format
- **Validation:** Valid file path
- **WhatIf:** Supports -WhatIf/-Confirm for file operations

## Output

Returns `PSCustomObject` array with the following properties:

```powershell
[PSCustomObject]@{
    DetectionType            # 'PasswordSpray'
    Severity                 # Critical/High/Medium/Low
    SourceIP                 # IP address of attack source
    UniqueTargetAccounts     # Number of unique accounts targeted
    TotalFailures            # Total failed authentication attempts
    FailuresPerAccount       # Average failures per account
    AttackDuration           # Duration of attack in minutes
    FirstFailure             # Timestamp of first detected failure
    LastFailure              # Timestamp of last detected failure
    TargetedAccounts         # Array of targeted account names
    SuccessfulLogons         # Number of successful logons from source IP
    SuccessfulAccounts       # Accounts with successful logons (if any)
    RecommendedActions       # Array of remediation steps
}
```

## Severity Levels

| Severity | Criteria |
|----------|----------|
| **Critical** | 50+ accounts targeted OR any successful logons from spray source |
| **High** | 25-49 accounts targeted with attack duration > 30 minutes |
| **Medium** | 15-24 accounts targeted OR failures per account < 2 (true spray pattern) |
| **Low** | 10-14 accounts targeted (may be legitimate service failure) |

## MITRE ATT&CK Mapping

- **T1110.003:** Brute Force - Password Spraying
- **T1110:** Brute Force (parent technique)
- **T1078:** Valid Accounts (when spray succeeds)

## Requirements

### Permissions

- **Event Log Reader** permissions on target domain controller(s)
- **Domain User** or higher for AD queries
- **Read** access to Security event log

### Event Logging

Security auditing must be enabled for:
- Event ID 4625 (Failed logon) - Audit Logon
- Event ID 4771 (Kerberos pre-authentication failed) - Audit Kerberos Authentication Service
- Event ID 4624 (Successful logon) - Audit Logon (for success correlation)

**Recommended Advanced Audit Policy:**
```powershell
auditpol /set /subcategory:"Logon" /failure:enable /success:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /failure:enable
```

### PowerShell Modules

- **ActiveDirectory** - For Get-ADDomainController
- **Microsoft.PowerShell.Diagnostics** - For Get-WinEvent

## Remediation Guidance

### If Password Spray Detected

1. **IMMEDIATE ACTIONS:**
   - Block source IP at firewall/perimeter
   - Force password reset for successfully compromised accounts
   - Enable MFA for all targeted accounts
   - Review recent logons from source IP
   - Check for lateral movement from compromised accounts

2. **FORENSIC ANALYSIS:**
   - Identify all accounts targeted in spray campaign
   - Review successful logons from spray source IP
   - Analyze timing patterns (slow spray vs. rapid)
   - Check for multiple source IPs (distributed spray)
   - Review VPN/RDP logs for external attack sources

3. **LONG-TERM HARDENING:**
   - Implement Smart Lockout (Azure AD) or Extranet Lockout (ADFS)
   - Enable MFA for all accounts (especially privileged)
   - Enforce strong password policy (> 14 characters, complexity)
   - Deploy password spray detection alerts (SIEM integration)
   - Implement IP reputation blocking (Azure Conditional Access)
   - Use passwordless authentication (Windows Hello, FIDO2)

### Blocking Source IP Example

```powershell
# Automated response to critical password spray
$Results = Get-PasswordSprayAttack -FailureThreshold 10

foreach ($Attack in $Results | Where-Object { $_.Severity -in @('Critical', 'High') }) {
    # Block at Windows Firewall
    New-NetFirewallRule -DisplayName "Block Password Spray: $($Attack.SourceIP)" `
        -Direction Inbound -RemoteAddress $Attack.SourceIP -Action Block -Enabled True

    Write-Warning "Blocked IP $($Attack.SourceIP) targeting $($Attack.UniqueTargetAccounts) accounts"
}
```

### Force Password Reset for Compromised Accounts

```powershell
# Reset passwords for successfully compromised accounts
$Results = Get-PasswordSprayAttack -TimeSpanMinutes 120

foreach ($Attack in $Results | Where-Object { $_.SuccessfulLogons -gt 0 }) {
    foreach ($Account in $Attack.SuccessfulAccounts) {
        Set-ADUser -Identity $Account -ChangePasswordAtLogon $true
        Disable-ADAccount -Identity $Account # Disable until password reset
        Write-Warning "Account $Account compromised - password reset required"
    }
}
```

## Example Workflows

### Continuous Monitoring (Scheduled Task)

```powershell
# Run every 15 minutes via scheduled task
$Results = Get-PasswordSprayAttack -TimeSpanMinutes 20 -FailureThreshold 8

if ($Results.Count -gt 0) {
    # Export to SIEM
    $Results | Export-Csv "D:\SIEM\Import\PasswordSpray-$(Get-Date -Format 'yyyyMMdd-HHmm').csv" -NoTypeInformation

    # Send alert for critical findings
    $Critical = $Results | Where-Object { $_.Severity -eq 'Critical' }
    if ($Critical.Count -gt 0) {
        Send-MailMessage -To 'soc@contoso.com' -Subject "CRITICAL: Password Spray Attack Detected" `
            -Body "Detected $($Critical.Count) critical password spray attempts. Review logs immediately." `
            -Attachments "D:\SIEM\Import\PasswordSpray-$(Get-Date -Format 'yyyyMMdd-HHmm').csv"
    }
}
```

### Domain-Wide Weekly Audit

```powershell
# Weekly comprehensive audit
$AllDCs = Get-ADDomainController -Filter *
$AllResults = @()

foreach ($DC in $AllDCs) {
    Write-Verbose "Scanning $($DC.HostName)..."
    $Results = Get-PasswordSprayAttack -DomainController $DC.HostName -TimeSpanMinutes 10080 -FailureThreshold 5
    $AllResults += $Results
}

# Consolidated report
$AllResults | Export-Csv "C:\SecurityReports\PasswordSpray-Weekly-$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation

# Summary statistics
$TotalAttacks = $AllResults.Count
$UniqueSources = ($AllResults | Select-Object -ExpandProperty SourceIP -Unique).Count
$TotalAccountsTargeted = ($AllResults | ForEach-Object { $_.TargetedAccounts } | Select-Object -Unique).Count

Write-Host "Weekly Password Spray Summary:"
Write-Host "  Total Attacks: $TotalAttacks"
Write-Host "  Unique Source IPs: $UniqueSources"
Write-Host "  Total Accounts Targeted: $TotalAccountsTargeted"
```

## Performance Considerations

- **Event log size:** Large Security logs (> 2GB) may take 5-10 minutes to query
- **Time span:** Longer spans (> 24 hours) exponentially increase query time
- **Multiple DCs:** Query in parallel using PowerShell jobs for faster results
- **Filtering:** Use ExcludeSourceIPs to reduce false positive processing

## False Positives

Common scenarios that may trigger detections:

- **VPN gateways:** Multiple users authenticating through single IP
- **RDP gateways:** Terminal server presenting as single source IP
- **Exchange servers:** OWA/ActiveSync failures from single server IP
- **Load balancers:** Web applications authenticating as single IP
- **Service accounts:** Automated systems with incorrect credentials

**Mitigation:** Use `-ExcludeSourceIPs` parameter to whitelist known infrastructure.

## Related Functions

- [Get-ADKerberoastingPattern](Get-ADKerberoastingPattern.md) - Detects Kerberoasting attacks
- [Get-ADASREPRoastingVulnerability](Get-ADASREPRoastingVulnerability.md) - Detects AS-REP Roasting
- [Get-UnconstrainedDelegation](Get-UnconstrainedDelegation.md) - Detects delegation attacks

## Additional Resources

- [MITRE ATT&CK T1110.003](https://attack.mitre.org/techniques/T1110/003/)
- [Microsoft: Password Spray Detection](https://docs.microsoft.com/azure/active-directory/identity-protection/concept-identity-protection-risks)
- [NIST: Password Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [GitHub Repository](https://github.com/vreguibar/EguibarIT.SecurityPS)

---

**Module:** EguibarIT.SecurityPS
**Component:** Security Auditing
**Role:** Threat Detection
**Functionality:** Password Spray Attack Detection
