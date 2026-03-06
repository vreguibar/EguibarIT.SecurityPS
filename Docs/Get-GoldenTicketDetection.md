# Get-GoldenTicketDetection Function Documentation

## Overview

**Get-GoldenTicketDetection** is a comprehensive PowerShell function that detects Golden Ticket attack patterns in Active Directory environments by auditing krbtgt password age, analyzing Kerberos events, and correlating authentication anomalies.

**Function File:** `Public/Get-GoldenTicketDetection.ps1`
**Version:** 1.0.0
**Last Modified:** 03/Mar/2026
**Author:** Vicente Rodriguez Eguibar

## Purpose

This function performs five-phase detection of Golden Ticket attacks (MITRE ATT&CK T1558.001):

1. **krbtgt Password Age Audit** - Validates password rotation across forest domains
2. **Event ID 4768 Analysis** - Detects TGT request anomalies
3. **Event ID 4624 Correlation** - Identifies logons without prior TGT requests
4. **Event ID 4769 Analysis** - Detects service ticket anomalies
5. **Event ID 4672 Analysis** - Identifies privileged access outliers

## Critical Principle

**Golden Tickets allow attackers to forge valid Kerberos tickets with arbitrary privileges.**
If krbtgt password is compromised, attackers can:
- Create tickets with any username (including non-existent accounts)
- Assign arbitrary group memberships (including Domain Admins)
- Bypass authentication entirely
- Maintain access for up to 10 years (max ticket lifetime)

## Key Features

### Five-Phase Detection

#### Phase 1: krbtgt Password Age Audit

- Checks password age across all forest domains
- Identifies stale passwords (> 180 days = high risk)
- Provides rotation guidance for krbtgt account
- Validates KRBTGT_TIMESTAMP registry markers

#### Phase 2: Event ID 4768 Anomaly Analysis

- Analyzes TGT request patterns
- Detects encryption downgrade (RC4 usage)
- Identifies requests from legacy/unusual sources
- Correlates user account status with TGT requests

#### Phase 3: Event ID 4624 Correlation

- Detects logons without matching TGT requests
- Identifies forged ticket usage patterns
- Correlates logon type with expected authentication flow
- Flags administrative logons without proper Kerberos telemetry

#### Phase 4: Event ID 4769 Service Ticket Analysis

- Analyzes service ticket request anomalies
- Detects unusual ticket encryption types
- Identifies service access from impossible sources
- Correlates with prior TGT requests

#### Phase 5: Event ID 4672 Privileged Access Analysis

- Detects privilege assignments without proper authentication
- Identifies accounts with unexpected special privileges
- Correlates with logon events and TGT requests
- Flags privilege escalation patterns

### Smart Reporting

- **Risk Assessment:** Categorizes findings (Low/Medium/High/Critical)
- **Actionable Recommendations:** Specific remediation steps
- **Automated Export:** CSV reports and summary files
- **Structured Output:** Suitable for automation and SIEM integration

## Usage

### Basic Audit (Default)

```powershell
Get-GoldenTicketDetection
```

Runs with default 24-hour event log scan on PDC Emulator.

### Extended Historical Analysis

```powershell
Get-GoldenTicketDetection -Hours 168 -Verbose
```

Analyzes 7 days (168 hours) of event logs with verbose progress output.

### Generate Reports

```powershell
Get-GoldenTicketDetection -Hours 48 -ExportPath 'C:\SecurityAudits' -IncludeKrbtgtRotation
```

Exports detailed CSV and text reports with krbtgt rotation guidance.

### Specific Domain Controller

```powershell
Get-GoldenTicketDetection -DomainController 'DC01.contoso.com' -Hours 72
```

Targets specific domain controller for event log analysis.

### Automation Integration with Remediation

```powershell
$Result = Get-GoldenTicketDetection -Hours 24 -Remediate
if ($Result.CriticalDetections -gt 0) {
    Write-Warning "CRITICAL: $($Result.CriticalDetections) Golden Ticket indicators detected!"
    # Trigger incident response workflow
}
```

## Parameters

### DomainController

- **Type:** string
- **Default:** PDC Emulator (auto-discovered)
- **Description:** Target domain controller for Security log analysis
- **Validation:** Must be valid DC hostname

### Hours

- **Type:** int
- **Default:** 24
- **Range:** 1-720 (30 days)
- **Description:** Number of hours to analyze in security event logs

### ExportPath

- **Type:** string
- **Default:** None (console output only)
- **Description:** Directory path for exporting CSV and summary reports
- **Validation:** Must be valid file system path

### IncludeKrbtgtRotation

- **Type:** switch
- **Default:** $false
- **Description:** Include krbtgt password rotation guidance in recommendations

### Remediate

- **Type:** switch
- **Default:** $false
- **Description:** Opens remediation guidance URL if critical findings exist

## Output

Returns a structured `PSCustomObject` containing:

```powershell
[PSCustomObject]@{
    DomainName               # DNS name of audited domain
    PDCEmulator              # PDC Emulator queried
    AnalysisHours            # Time span analyzed
    KrbtgtPasswordAge        # Age of krbtgt password in days
    KrbtgtRotationNeeded     # Boolean - password > 180 days
    TotalDetections          # Total suspicious indicators found
    CriticalDetections       # Critical severity findings
    HighDetections           # High severity findings
    MediumDetections         # Medium severity findings
    LowDetections            # Low severity findings
    RiskLevel                # Overall: Low/Medium/High/Critical
    IsCompromiseLikely       # Boolean - strong attack indicators
    RecommendedActions       # Array of remediation steps
    ExportedReports          # File paths of exported reports
    DetectionDetails         # Array of detailed findings
}
```

### Detection Detail Structure

Each finding in `DetectionDetails` contains:

```powershell
@{
    Phase                    # Detection phase (1-5)
    DetectionType            # Type of anomaly detected
    Severity                 # Critical/High/Medium/Low
    Timestamp                # When detected
    AccountName              # Affected account
    SourceIP                 # Source IP address (if available)
    Details                  # Human-readable description
    EventID                  # Related Windows Event ID
}
```

## MITRE ATT&CK Mapping

- **T1558.001:** Steal or Forge Kerberos Tickets - Golden Ticket
- **T1003.006:** OS Credential Dumping - DCSync (krbtgt extraction)
- **T1550.003:** Use Alternate Authentication Material - Pass the Ticket

## Requirements

### Permissions

- **Event Log Reader** permissions on target domain controller
- **Domain User** or higher for AD queries
- **Read** access to Security event log

### Event Logging

Security auditing must be enabled for:
- Event ID 4768 (TGT requests) - Audit Kerberos Authentication Service
- Event ID 4769 (Service ticket requests) - Audit Kerberos Service Ticket Operations
- Event ID 4624 (Logon events) - Audit Logon
- Event ID 4672 (Special privileges) - Audit Sensitive Privilege Use

### PowerShell Modules

- **ActiveDirectory** - For domain and user queries

## Remediation Guidance

### If Golden Ticket Attack Detected

1. **IMMEDIATE ACTIONS:**
   - Isolate affected systems from network
   - Reset krbtgt password **twice** (with 10-hour delay between resets)
   - Revoke all Kerberos tickets (reboot all DCs)
   - Force password reset for all privileged accounts

2. **FORENSIC ANALYSIS:**
   - Identify initial compromise vector (DCSync, NTDS.dit theft)
   - Review krbtgt password history
   - Analyze all privileged account activity during compromise window
   - Check for persistence mechanisms (scheduled tasks, services, WMI subscriptions)

3. **LONG-TERM HARDENING:**
   - Implement krbtgt password rotation schedule (every 180 days)
   - Enable Advanced Threat Analytics (ATA) or Microsoft Defender for Identity
   - Configure Kerberos encryption type restrictions (AES only)
   - Implement privileged access workstations (PAWs)
   - Enable Protected Users group for privileged accounts

### krbtgt Password Rotation

```powershell
# Reset krbtgt password (run TWICE with 10-hour delay)
# First reset
$krbtgtAccount = Get-ADUser -Identity 'krbtgt'
Set-ADAccountPassword -Identity $krbtgtAccount -Reset

# Wait 10+ hours (max TGT lifetime)
# Second reset
Set-ADAccountPassword -Identity $krbtgtAccount -Reset
```

**WARNING:** Improper krbtgt reset can cause authentication failures. Follow Microsoft guidance carefully.

## Example Workflow

### Weekly Automated Monitoring

```powershell
# Scheduled task runs weekly
$Result = Get-GoldenTicketDetection -Hours 168 -ExportPath 'D:\SecurityLogs\GoldenTicket'

if ($Result.IsCompromiseLikely) {
    # Send alert to SOC
    Send-MailMessage -To 'soc@contoso.com' -Subject "CRITICAL: Golden Ticket Attack Detected" `
        -Body "Detection count: $($Result.CriticalDetections). Review logs immediately."

    # Export to SIEM
    $Result.DetectionDetails | Export-Csv 'D:\SIEM\Import\GoldenTicket.csv' -NoTypeInformation
}

# Always log results
$Result | ConvertTo-Json -Depth 10 | Out-File 'D:\SecurityLogs\GoldenTicket\latest.json'
```

### Incident Response Investigation

```powershell
# Extended analysis during incident
$Result = Get-GoldenTicketDetection -Hours 720 -IncludeKrbtgtRotation -Remediate -Verbose

# Filter critical findings only
$CriticalFindings = $Result.DetectionDetails | Where-Object { $_.Severity -eq 'Critical' }

# Export for forensic team
$CriticalFindings | Export-Csv 'C:\IR\GoldenTicket-Critical.csv' -NoTypeInformation

# Check krbtgt status
if ($Result.KrbtgtRotationNeeded) {
    Write-Warning "krbtgt password is $($Result.KrbtgtPasswordAge) days old - ROTATE IMMEDIATELY"
}
```

## Performance Considerations

- **Event log size:** Large Security logs (> 1GB) may take several minutes to query
- **Domain controllers:** Query PDC Emulator preferentially for most comprehensive logs
- **Time span:** Limit to 7 days (168 hours) for routine monitoring, 30 days (720 hours) for investigations
- **Network bandwidth:** Event log queries over WAN can be slow, consider local execution on DC

## False Positives

Common scenarios that may trigger detections:

- **Legacy applications** using NTLM instead of Kerberos (Event 4624 without 4768)
- **Service accounts** with very old passwords (may appear as forged tickets)
- **Time synchronization issues** causing timestamp mismatches
- **Domain trust relationships** generating cross-domain TGT requests

Use `-Verbose` to identify false positive patterns and adjust detection logic if needed.

## Related Functions

- [Get-DCSyncAttack](Get-DCSyncAttack.md) - Detects DCSync credential theft
- [Get-SilverTicketDetection](Get-SilverTicketDetection.md) - Detects forged service tickets
- [Get-ADKerberoastingPattern](Get-ADKerberoastingPattern.md) - Detects credential cracking attempts

## Additional Resources

- [MITRE ATT&CK T1558.001](https://attack.mitre.org/techniques/T1558/001/)
- [Microsoft: Krbtgt Account Password Reset Scripts](https://aka.ms/krbtgt)
- [Detecting Forged Kerberos Tickets (Golden Ticket)](https://adsecurity.org/?p=1515)
- [GitHub Repository](https://github.com/vreguibar/EguibarIT.SecurityPS)

---

**Module:** EguibarIT.SecurityPS
**Component:** Security Auditing
**Role:** Threat Detection
**Functionality:** Golden Ticket Attack Detection
