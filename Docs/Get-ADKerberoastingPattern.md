# Get-ADKerberoastingPattern Function Documentation

## Overview

**Get-ADKerberoastingPattern** is a comprehensive PowerShell function that detects Kerberoasting attacks by analyzing Kerberos service ticket request patterns in Active Directory environments.

**Function File:** `Public/Get-ADKerberoastingPattern.ps1`
**Version:** 1.2.0
**Last Modified:** 25/Feb/2026
**Author:** Vicente Rodriguez Eguibar

## Purpose

This function detects Kerberoasting attacks (MITRE ATT&CK T1558.003) by monitoring Security Event ID 4769 for suspicious service ticket request patterns.

**Attack Method:** Kerberoasting allows attackers to:
1. Request service tickets for accounts with SPNs (no special privileges required)
2. Extract encrypted tickets from memory
3. Perform offline password cracking against service account passwords
4. Gain access to service accounts (often privileged)

## Critical Principle

**ANY domain user can request service tickets for accounts with SPNs.**
Service tickets are encrypted with the service account's password hash, allowing offline cracking. Service accounts often have:
- Weak passwords (easy to crack)
- High privileges (Domain Admin in many cases)
- Password Never Expires setting
- No MFA protection

## Key Features

### Detection Capabilities

- **High-Volume Detection:** Identifies accounts requesting many service tickets rapidly
- **RC4-HMAC Analysis:** Detects downgrade to RC4 encryption (0x17) preferred by attackers
- **SPN Filtering:** Excludes krbtgt and computer accounts (focuses on service accounts)
- **Honeypot Monitoring:** Alerts on access to decoy/canary SPNs
- **Timeline Analysis:** Tracks first/last request timestamps and attack duration
- **Source IP Correlation:** Identifies attack source locations

### Smart Analysis

- **Configurable Thresholds:** Adjust sensitivity based on environment
- **Automated Severity Assessment:** Critical/High/Medium/Low based on request count and patterns
- **Pipeline Support:** Scan multiple domain controllers simultaneously
- **CSV Export:** SIEM integration ready

## Usage

### Basic Detection

```powershell
Get-ADKerberoastingPattern -DomainController 'DC01' -TimeSpanMinutes 30 -ThresholdCount 5
```

Analyzes the last 30 minutes on DC01, alerting on accounts with 5+ suspicious service ticket requests.

### Verbose Output with Export

```powershell
Get-ADKerberoastingPattern -DomainController 'DC01' -ExportPath 'C:\SecurityAudits\Kerberoast.csv' -Verbose
```

Performs default detection (60 min, threshold 10) with verbose output and CSV export.

### Honeypot Monitoring

```powershell
Get-ADKerberoastingPattern -HoneypotSPNs @('HTTP/trap.corp.local','MSSQL/canary.corp.local') -WhatIf
```

Detects honeypot access (confirmed attack). WhatIf shows export actions without creating files.

### Pipeline Processing

```powershell
'DC01', 'DC02', 'DC03' | Get-ADKerberoastingPattern -TimeSpanMinutes 30 -Verbose
```

Scans multiple domain controllers via pipeline in parallel.

### Comprehensive Domain Scan

```powershell
Get-ADDomainController -Filter * | Get-ADKerberoastingPattern -ThresholdCount 5
```

Auto-discovers all DCs and scans each for Kerberoasting activity.

### Automation Integration

```powershell
$Results = Get-ADKerberoastingPattern -ThresholdCount 5
$Results | Where-Object { $_.Severity -eq 'Critical' } | ForEach-Object {
    Write-Warning "CRITICAL: $($_.SourceAccount) requested $($_.RequestCount) service tickets!"
    # Trigger incident response
}
```

## Parameters

### DomainController

- **Type:** string
- **Default:** Auto-discovered from current domain
- **Description:** Target domain controller to query for Event ID 4769
- **Pipeline:** Accepts 'HostName' or 'Name' from Get-ADDomainController
- **Permissions:** Event Log Reader permissions required

### TimeSpanMinutes

- **Type:** int
- **Default:** 60 minutes
- **Range:** 1 to 10080 minutes (7 days)
- **Description:** Number of minutes to look back in Security event log

### ThresholdCount

- **Type:** int
- **Default:** 10 requests
- **Range:** 1 to 1000
- **Description:** Minimum service ticket requests from single account to trigger alert
- **Tuning:** Lower = higher sensitivity + more false positives

### ExportPath

- **Type:** string
- **Default:** None (console output only)
- **Description:** Path to export detailed CSV report
- **WhatIf:** Supports -WhatIf/-Confirm for file operations

### HoneypotSPNs

- **Type:** string[]
- **Default:** None
- **Description:** Array of honeypot/canary SPN values to monitor
- **Examples:** @('HTTP/decoy.corp.local', 'MSSQLSvc/honeypot.corp.local')
- **Purpose:** Access to these SPNs indicates **confirmed** attack activity

## Output

Returns `PSCustomObject` array with the following properties:

```powershell
[PSCustomObject]@{
    DetectionType            # 'Kerberoasting' or 'HoneypotAccess'
    Severity                 # Critical/High/Medium/Low
    SourceAccount            # Account performing suspicious requests
    RequestCount             # Number of ticket requests detected
    TargetedSPNs             # Array of service principal names targeted
    UniqueServiceCount       # Number of different services targeted
    SourceIPs                # Array of source IP addresses
    FirstRequest             # Timestamp of first suspicious request
    LastRequest              # Timestamp of last suspicious request
    AttackDuration           # Duration in minutes
    RC4EncryptionUsed        # Boolean - RC4 downgrade detected
    RecommendedActions       # Array of remediation steps
}
```

## Severity Levels

| Severity | Criteria |
|----------|----------|
| **Critical** | Honeypot SPN access OR 50+ ticket requests OR RC4 encryption + 25+ requests |
| **High** | 25-49 ticket requests OR RC4 encryption + 10+ requests |
| **Medium** | 15-24 ticket requests OR confirmed Kerberoasting tool patterns |
| **Low** | 10-14 ticket requests (may be legitimate high-volume service account) |

## MITRE ATT&CK Mapping

- **T1558.003:** Steal or Forge Kerberos Tickets - Kerberoasting
- **T1558:** Steal or Forge Kerberos Tickets (parent technique)
- **T1003:** OS Credential Dumping (password cracking phase)

## Requirements

### Permissions

- **Event Log Reader** permissions on target domain controller(s)
- **Domain User** or higher for AD queries
- **Read** access to Security event log

### Event Logging

Security auditing must be enabled for:
- Event ID 4769 (Kerberos service ticket requested) - Audit Kerberos Service Ticket Operations

**Enable auditing:**
```powershell
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
```

### PowerShell Modules

- **ActiveDirectory** - For Get-ADDomainController
- **Microsoft.PowerShell.Diagnostics** - For Get-WinEvent

## Remediation Guidance

### If Kerberoasting Detected

1. **IMMEDIATE ACTIONS:**
   - Identify compromised source account
   - Reset passwords for all targeted service accounts (25+ character complexity)
   - Force Kerberos ticket purge on attacking system: `Invoke-Command -ComputerName <AttackerPC> -ScriptBlock { klist purge }`
   - Disable attacking user account pending investigation
   - Review recent activity from source account

2. **FORENSIC ANALYSIS:**
   - Identify how attacker gained initial access
   - Review all SPNs targeted (prioritize privileged service accounts)
   - Check for successful authentications from attacking account
   - Analyze lateral movement from attacking system
   - Review PowerShell/command-line history on attacking system

3. **LONG-TERM HARDENING:**
   - **Migrate to Group Managed Service Accounts (gMSAs):** Automatic 120-character password rotation
   - **Enforce strong service account passwords:** Minimum 25 characters, max complexity
   - **Remove service accounts from privileged groups:** Least privilege principle
   - **Enable AES encryption only:** Disable RC4 support via Group Policy
   - **Implement Protected Users group:** Prevents delegation and RC4
   - **Deploy honeypot SPNs:** Early warning system for Kerberoasting
   - **Enable Service Account Auditing:** Alert on SPN modifications

### Service Account Hardening

```powershell
# Identify service accounts with weak passwords or high privileges
$ServiceAccounts = Get-ADUser -Filter {ServicePrincipalName -like '*'} -Properties ServicePrincipalName, MemberOf, PasswordLastSet, PasswordNeverExpires

foreach ($Account in $ServiceAccounts) {
    # Check for Domain Admin membership
    if ($Account.MemberOf -match 'Domain Admins') {
        Write-Warning "Service account $($Account.SamAccountName) is in Domain Admins!"
    }
    
    # Check password age
    if ($Account.PasswordLastSet -lt (Get-Date).AddDays(-365)) {
        Write-Warning "Service account $($Account.SamAccountName) has password older than 1 year!"
    }
    
    # Check Password Never Expires
    if ($Account.PasswordNeverExpires) {
        Write-Warning "Service account $($Account.SamAccountName) has 'Password Never Expires' set!"
    }
}

# Convert to Group Managed Service Account (gMSA)
New-ADServiceAccount -Name 'SQL-gMSA' -DNSHostName 'SQLPROD01.contoso.com' `
    -PrincipalsAllowedToRetrieveManagedPassword 'SQL-Servers' `
    -ServicePrincipalNames 'MSSQLSvc/SQLPROD01.contoso.com:1433'
```

### Deploy Honeypot SPNs

```powershell
# Create honeypot service account with SPN
New-ADUser -Name 'svc-decoy-sql' -SamAccountName 'svc-decoy-sql' `
    -AccountPassword (ConvertTo-SecureString -AsPlainText 'P@ssw0rd123!' -Force) `
    -Enabled $true -PasswordNeverExpires $true `
    -Description 'Honeypot account - DO NOT USE'

# Add honeypot SPN
Set-ADUser -Identity 'svc-decoy-sql' -ServicePrincipalNames @{Add='MSSQLSvc/decoy-sql.corp.local:1433'}

# Monitor for access
Get-ADKerberoastingPattern -HoneypotSPNs @('MSSQLSvc/decoy-sql.corp.local:1433')
```

### Disable RC4 Encryption

```powershell
# Configure domain to use AES only (disable RC4)
# Group Policy: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options
# Network security: Configure encryption types allowed for Kerberos
# Enable: AES256_HMAC_SHA1, AES128_HMAC_SHA1
# Disable: RC4_HMAC_MD5, DES_CBC_CRC, DES_CBC_MD5

# Via registry on critical servers
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' `
    -Name 'SupportedEncryptionTypes' -Value 0x1C  # AES128, AES256 only
```

## Example Workflows

### Continuous Monitoring (Scheduled Task)

```powershell
# Run every 30 minutes via scheduled task
$Results = Get-ADKerberoastingPattern -TimeSpanMinutes 35 -ThresholdCount 8

if ($Results.Count -gt 0) {
    # Export to SIEM
    $Results | Export-Csv "D:\SIEM\Import\Kerberoast-$(Get-Date -Format 'yyyyMMdd-HHmm').csv" -NoTypeInformation
    
    # Alert on critical findings
    $Critical = $Results | Where-Object { $_.Severity -eq 'Critical' }
    if ($Critical.Count -gt 0) {
        Send-MailMessage -To 'soc@contoso.com' -Subject "CRITICAL: Kerberoasting Attack Detected" `
            -Body "Detected $($Critical.Count) critical Kerberoasting attempts. Account: $($Critical[0].SourceAccount)" `
            -Priority High
    }
}
```

### Weekly Service Account Audit

```powershell
# Comprehensive weekly audit
$AllDCs = Get-ADDomainController -Filter *
$AllResults = @()

foreach ($DC in $AllDCs) {
    Write-Verbose "Scanning $($DC.HostName)..."
    $Results = Get-ADKerberoastingPattern -DomainController $DC.HostName -TimeSpanMinutes 10080 -ThresholdCount 5
    $AllResults += $Results
}

# Generate summary report
$Report = @{
    TotalAttacks = $AllResults.Count
    UniqueSources = ($AllResults | Select-Object -ExpandProperty SourceAccount -Unique).Count
    TotalSPNsTargeted = ($AllResults | ForEach-Object { $_.TargetedSPNs } | Select-Object -Unique).Count
    MostTargetedSPNs = $AllResults | ForEach-Object { $_.TargetedSPNs } | Group-Object | Sort-Object Count -Descending | Select-Object -First 5
}

$Report | ConvertTo-Json | Out-File "C:\SecurityReports\Kerberoast-Weekly-$(Get-Date -Format 'yyyyMMdd').json"
```

## Performance Considerations

- **Event log size:** Querying large logs (> 2GB) may take 5-10 minutes
- **Time span:** Longer spans exponentially increase query time
- **Domain controllers:** Query PDC Emulator preferentially for comprehensive logs
- **Threshold tuning:** Lower thresholds increase processing time due to more matches

## False Positives

Common scenarios that may trigger detections:

- **Legitimate service applications:** High-volume service-to-service authentication
- **Monitoring tools:** Management applications querying service health
- **Backup software:** Accessing multiple SQL/file services
- **Load balancers:** Health checks generating service ticket requests

**Mitigation:** Baseline environment for 30 days to identify normal patterns and adjust threshold accordingly.

## Related Functions

- [Get-PasswordSprayAttack](Get-PasswordSprayAttack.md) - Detects password spraying
- [Get-ADASREPRoastingVulnerability](Get-ADASREPRoastingVulnerability.md) - Detects AS-REP Roasting
- [Get-GoldenTicketDetection](Get-GoldenTicketDetection.md) - Detects forged TGTs
- [Get-SilverTicketDetection](Get-SilverTicketDetection.md) - Detects forged service tickets

## Additional Resources

- [MITRE ATT&CK T1558.003](https://attack.mitre.org/techniques/T1558/003/)
- [Kerberoasting Attack Detection](https://adsecurity.org/?p=3458)
- [Group Managed Service Accounts](https://docs.microsoft.com/windows-server/security/group-managed-service-accounts)
- [Kerberos Encryption Type Selection](https://docs.microsoft.com/windows/security/threat-protection/security-policy-settings/network-security-configure-encryption-types-allowed-for-kerberos)
- [GitHub Repository](https://github.com/vreguibar/EguibarIT.SecurityPS)

---

**Module:** EguibarIT.SecurityPS
**Component:** Security Auditing
**Role:** Threat Detection
**Functionality:** Kerberoasting Attack Detection
