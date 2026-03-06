# Get-SilverTicketDetection Function Documentation

## Overview

**Get-SilverTicketDetection** is a comprehensive PowerShell function that detects Silver Ticket attack patterns in Active Directory by correlating service logons, Kerberos service ticket requests, and service account security posture.

**Function File:** `Public/Get-SilverTicketDetection.ps1`
**Version:** 1.0.0
**Last Modified:** 03/Mar/2026
**Author:** Vicente Rodriguez Eguibar

## Purpose

This function performs five-phase detection of Silver Ticket attacks (MITRE ATT&CK T1558.002):

1. **Service Account Security Audit** - Analyzes SPN accounts, password age, privilege risk
2. **Event Correlation** - Detects Event ID 4624 logons without matching Event ID 4769 requests
3. **Event ID 4769 Anomaly Analysis** - Identifies deleted users, RC4 downgrade, PAC validation failures
4. **Computer Account Misuse** - Detects stale computer passwords and delegation abuse
5. **Behavioral Baseline Advisory** - Summarizes trends for baseline learning

## Critical Principle

**Silver Tickets allow attackers to forge service tickets for specific services.**
Unlike Golden Tickets (domain-wide), Silver Tickets target individual services (SQL, CIFS, HTTP, LDAP) but are harder to detect because:
- No KDC interaction (no Event ID 4768)
- Service-level encryption key required (not krbtgt)
- Detection requires correlating service logons with ticket requests

## Key Features

### Five-Phase Detection

#### Phase 1: Service Account Security Audit

- Identifies accounts with Service Principal Names (SPNs)
- Checks password age (> 365 days = critical risk)
- Analyzes privilege level (Domain Admin SPNs = critical)
- Validates encryption posture (RC4 support = risk)
- Detects privileged group memberships

#### Phase 2: Event ID 4624/4769 Correlation

- Detects service logons (4624) without matching service ticket requests (4769)
- Indicates forged tickets bypassing KDC
- Correlates logon type with expected authentication flow
- Flags administrative service access without proper Kerberos telemetry

#### Phase 3: Event ID 4769 Anomaly Analysis

- Detects ticket requests for deleted/disabled accounts
- Identifies RC4-HMAC encryption downgrade attacks
- Analyzes PAC validation failures
- Correlates unusual service ticket patterns

#### Phase 4: Computer Account Misuse Detection

- Identifies stale computer account passwords (> 90 days)
- Detects computer accounts with SPNs (unusual configuration)
- Analyzes delegation settings on service hosts
- Flags disabled computers still generating service tickets

#### Phase 5: Behavioral Baseline Advisory

- Summarizes normal vs. anomalous patterns
- Provides baseline learning mode for environment tuning
- Identifies high-volume service accounts for whitelisting
- Recommends detection threshold adjustments

### Smart Reporting

- **Risk Assessment:** Categorizes findings (Low/Medium/High/Critical)
- **Server Auto-Discovery:** Discovers SQL, file servers, web servers automatically
- **Service Type Filtering:** Focus on specific service types (MSSQLSvc, CIFS, HTTP)
- **Automated Export:** CSV reports suitable for SIEM integration

## Usage

### Basic Audit (Default)

```powershell
Get-SilverTicketDetection
```

Runs with auto-discovered servers for the last 24 hours.

### Focused SQL Server Analysis

```powershell
Get-SilverTicketDetection -TargetServers 'SQLPROD01','SQLPROD02' -ServiceTypes 'MSSQLSvc' -Hours 168
```

Analyzes 7-day SQL service Silver Ticket patterns on specific servers.

### Baseline Learning Mode

```powershell
Get-SilverTicketDetection -BaselineMode -Hours 720 -ExportPath 'C:\Reports'
```

Runs 30-day baseline learning and exports telemetry for environment tuning.

### Comprehensive Audit with Remediation

```powershell
Get-SilverTicketDetection -IncludeServiceAccountAudit -ExportPath 'C:\SecurityAudits' -Remediate
```

Full service account audit with export and automatic remediation guidance.

### Automation Integration

```powershell
$Result = Get-SilverTicketDetection -Hours 24
if ($Result.CriticalFindings -gt 0) {
    Write-Warning "CRITICAL: $($Result.CriticalFindings) Silver Ticket indicators detected!"
    # Trigger incident response workflow
}
```

## Parameters

### TargetServers

- **Type:** string[]
- **Default:** Auto-discovered (DCs, SQL SPNs, file servers)
- **Description:** Target servers to analyze for Silver Ticket activity
- **Validation:** Valid server hostnames

### ServiceTypes

- **Type:** string[]
- **Default:** @('MSSQLSvc', 'CIFS', 'HTTP', 'LDAP', 'HOST')
- **Description:** Service SPN prefixes to monitor
- **Examples:** 'MSSQLSvc' (SQL), 'CIFS' (file shares), 'HTTP' (web services)

### Hours

- **Type:** int
- **Default:** 24
- **Range:** 1-720 (30 days)
- **Description:** Number of hours to analyze from current time

### ExportPath

- **Type:** string
- **Default:** None (console output only)
- **Description:** Directory path where CSV reports are exported
- **Validation:** Valid directory path

### IncludeServiceAccountAudit

- **Type:** switch
- **Default:** $false
- **Description:** Includes full service account audit export and remediation recommendations

### BaselineMode

- **Type:** switch
- **Default:** $false
- **Description:** Baseline learning mode - detections analyzed but not promoted as alerts

### Remediate

- **Type:** switch
- **Default:** $false
- **Description:** Opens Silver Ticket remediation guidance URL when critical findings present

## Output

Returns a structured `PSCustomObject` containing:

```powershell
[PSCustomObject]@{
    AnalyzedServers             # Number of servers analyzed
    ServiceAccountsAudited      # Number of SPN accounts reviewed
    TotalFindings               # Total suspicious indicators
    CriticalFindings            # Critical severity (confirmed attacks)
    HighFindings                # High severity (strong indicators)
    MediumFindings              # Medium severity (anomalies)
    LowFindings                 # Low severity (baseline learning)
    ServiceAccountRisks         # Service account security issues
    CorrelationAnomalies        # 4624 without 4769 events
    Event4769Anomalies          # Ticket request anomalies
    ComputerAccountRisks        # Stale/misconfigured computers
    IsCompromiseLikely          # Boolean - strong attack evidence
    RiskLevel                   # Overall: Low/Medium/High/Critical
    RecommendedActions          # Array of remediation steps
    ExportedReports             # File paths of exported reports
    DetectionDetails            # Array of detailed findings
}
```

### Detection Detail Structure

```powershell
@{
    Phase                       # Detection phase (1-5)
    DetectionType               # Type of anomaly
    Severity                    # Critical/High/Medium/Low
    Timestamp                   # When detected
    AccountName                 # Service account or user
    ServiceName                 # Targeted service (SQL, CIFS, etc.)
    TargetServer                # Service host server
    SourceIP                    # Source of access (if available)
    Details                     # Human-readable description
}
```

## MITRE ATT&CK Mapping

- **T1558.002:** Steal or Forge Kerberos Tickets - Silver Ticket
- **T1558.003:** Kerberoasting (service account credential theft)
- **T1550.003:** Use Alternate Authentication Material - Pass the Ticket

## Requirements

### Permissions

- **Event Log Reader** on domain controllers and target service hosts
- **Domain User** or higher for AD queries
- **Read** access to Security event logs

### Event Logging

Security auditing must be enabled for:
- Event ID 4769 (Service ticket requests) - Audit Kerberos Service Ticket Operations
- Event ID 4624 (Logon events) - Audit Logon
- Event ID 4625 (Failed logons) - Audit Logon

### PowerShell Modules

- **ActiveDirectory** - For domain, user, and computer queries

## Remediation Guidance

### If Silver Ticket Attack Detected

1. **IMMEDIATE ACTIONS:**
   - Identify compromised service account(s)
   - Reset service account password **immediately**
   - Restart affected service to clear ticket cache
   - Isolate affected service hosts if needed
   - Force Kerberos ticket purge: `klist purge -li 0x3e7`

2. **FORENSIC ANALYSIS:**
   - Identify how service account hash was obtained (Kerberoasting, NTDS.dit, memory dump)
   - Review service account activity during compromise window
   - Check for lateral movement from compromised services
   - Analyze service host security logs for unauthorized access

3. **LONG-TERM HARDENING:**
   - Implement Group Managed Service Accounts (gMSAs) - automatic password rotation
   - Remove service accounts from privileged groups
   - Enforce strong passwords (> 25 characters) for service accounts
   - Configure Service Principal Name (SPN) monitoring
   - Enable AES encryption only (disable RC4)
   - Use Protected Users group for privileged service accounts

### Service Account Security Best Practices

```powershell
# Identify service accounts with weak passwords
Get-ADUser -Filter {ServicePrincipalName -like '*'} -Properties PasswordLastSet, PasswordNeverExpires |
    Where-Object { 
        $_.PasswordLastSet -lt (Get-Date).AddDays(-365) -or 
        $_.PasswordNeverExpires -eq $true 
    } |
    Select-Object SamAccountName, PasswordLastSet, PasswordNeverExpires

# Convert to Group Managed Service Account (gMSA)
New-ADServiceAccount -Name 'SQL-gMSA' -DNSHostName 'SQLPROD01.contoso.com' `
    -PrincipalsAllowedToRetrieveManagedPassword 'SQL-Servers'
```

## Example Workflows

### Daily Automated Monitoring

```powershell
# Scheduled task runs daily
$Result = Get-SilverTicketDetection -Hours 24 -ExportPath 'D:\SecurityLogs\SilverTicket'

if ($Result.IsCompromiseLikely) {
    # Send alert to SOC
    Send-MailMessage -To 'soc@contoso.com' -Subject "CRITICAL: Silver Ticket Attack Detected" `
        -Body "Critical findings: $($Result.CriticalFindings). Review logs immediately."
}

# Export to SIEM
$Result.DetectionDetails | Export-Csv 'D:\SIEM\Import\SilverTicket.csv' -NoTypeInformation
```

### Incident Response Investigation

```powershell
# Extended forensic analysis
$Result = Get-SilverTicketDetection -Hours 168 -IncludeServiceAccountAudit -Remediate -Verbose

# Filter critical findings
$CriticalFindings = $Result.DetectionDetails | Where-Object { $_.Severity -eq 'Critical' }

# Identify compromised service accounts
$CompromisedAccounts = $CriticalFindings | Select-Object -ExpandProperty AccountName -Unique

# Reset passwords for compromised accounts
foreach ($Account in $CompromisedAccounts) {
    Write-Warning "Resetting password for compromised service account: $Account"
    # Set-ADAccountPassword -Identity $Account -Reset -Confirm
}
```

## Performance Considerations

- **Auto-discovery:** May take 1-2 minutes to enumerate servers with SPNs
- **Event correlation:** Requires matching 4624 and 4769 events across multiple servers
- **Baseline mode:** Use for 30+ days to establish normal service access patterns
- **Service types:** Limit to specific service types for faster analysis

## False Positives

Common scenarios that may trigger detections:

- **Cached credentials:** Applications using cached service tickets (normal behavior)
- **Service account lockouts:** Failed authentications may appear as anomalies
- **Time synchronization:** Timestamp mismatches between DC and service hosts
- **Load balancers:** May show logons without corresponding ticket requests

Use `-BaselineMode` for 30 days to identify normal patterns before production alerting.

## Related Functions

- [Get-GoldenTicketDetection](Get-GoldenTicketDetection.md) - Detects forged TGTs
- [Get-ADKerberoastingPattern](Get-ADKerberoastingPattern.md) - Detects service account credential theft
- [Get-UnconstrainedDelegation](Get-UnconstrainedDelegation.md) - Detects delegation abuse

## Additional Resources

- [MITRE ATT&CK T1558.002](https://attack.mitre.org/techniques/T1558/002/)
- [Silver Ticket Attack Detection](https://adsecurity.org/?p=2011)
- [Group Managed Service Accounts](https://docs.microsoft.com/windows-server/security/group-managed-service-accounts)
- [GitHub Repository](https://github.com/vreguibar/EguibarIT.SecurityPS)

---

**Module:** EguibarIT.SecurityPS
**Component:** Security Auditing
**Role:** Threat Detection
**Functionality:** Silver Ticket Attack Detection
