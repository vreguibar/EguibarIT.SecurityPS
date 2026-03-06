# Get-EntraConnectCompromise Function Documentation

## Overview

**Get-EntraConnectCompromise** is a comprehensive PowerShell function that detects Microsoft Entra Connect (Azure AD Connect) compromise indicators through server auditing, privileged account monitoring, and credential extraction detection.

**Function File:** `Public/Get-EntraConnectCompromise.ps1`
**Version:** 1.0.0
**Last Modified:** 06/Mar/2026
**Author:** Vicente Rodriguez Eguibar

## Purpose

This function performs six-phase detection of Entra Connect compromise (MITRE ATT&CK T1078.004, T1003):

1. **Server Discovery** - Identifies Entra Connect servers in the environment
2. **Privileged Account Enumeration** - Monitors MSOL_*/AAD_* accounts
3. **Credential Access Detection** - SQL LocalDB access monitoring
4. **Sync Anomaly Detection** - Configuration and schedule changes
5. **PTA Agent Validation** - Pass-Through Authentication integrity checks
6. **Configuration Export** - Forensic data collection

## Critical Principle

**Entra Connect servers are Tier 0 assets requiring complete isolation.**
Compromise enables complete hybrid identity takeover and access to ALL on-premises credentials.

## Key Features

### Six-Phase Detection

#### Phase 1: Server Discovery

- Auto-discovers Entra Connect servers via ADSync service
- Searches by AD attributes (ServicePrincipalName, Description)
- Fallback to domain-wide service enumeration
- Validates server accessibility and service status

#### Phase 2: Privileged Account Enumeration

- Identifies MSOL_*, AAD_*, Sync_* accounts
- Monitors account status, last logon, password age
- Detects high-privileged group memberships
- Risk assessment based on configuration

#### Phase 3: Credential Access Detection

- Event 4663 monitoring (SQL LocalDB file access)
- Event 4688 analysis (ADSyncDecrypt execution)
- Unauthorized access to ADSync.mdf database
- Credential extraction tool detection

#### Phase 4: Sync Schedule Anomaly Detection

- ADSync service status monitoring
- Event 7036 analysis (service state changes)
- Sync scheduler configuration validation
- Unauthorized service manipulation detection

#### Phase 5: PTA Agent Validation

- Pass-Through Authentication agent discovery
- Service health monitoring
- Configuration integrity validation
- Agent compromise indicators

#### Phase 6: Configuration Export

- ADSync scheduler configuration export
- Sync rule inventory (forensic analysis)
- Connector settings documentation
- Complete audit trail preservation

### Smart Reporting

- **Risk Tiering:** Categorizes findings (Secure/Low/Medium/High/Critical)
- **Incident Correlation:** Links related compromise indicators
- **Automated Export:** CSV, JSON reports for SIEM integration
- **Actionable Remediation:** Specific security hardening steps

## Usage

### Basic Audit (Default)

```powershell
Get-EntraConnectCompromise
```

Auto-discovers servers, performs 30-day audit, displays results to console.

### Specific Server Audit

```powershell
Get-EntraConnectCompromise -EntraConnectServer 'AADSYNC01' -DaysBack 90 -Verbose
```

Audits specific server for 90 days with verbose output.

### Comprehensive Forensic Analysis

```powershell
Get-EntraConnectCompromise -ExportPath 'C:\SecurityAudits' -IncludeConfigurationDump -CheckPTAAgents
```

Full audit with configuration export and PTA agent validation.

### Multi-Server Scan

```powershell
Get-EntraConnectCompromise -ScanAllServers -DaysBack 7
```

Scans all discovered Entra Connect servers for the last 7 days.

### Automated Incident Response

```powershell
$Result = Get-EntraConnectCompromise -DaysBack 30
if ($Result.HighRiskIndicators -gt 0) {
    Write-Warning "CRITICAL: $($Result.HighRiskIndicators) high-risk indicators detected!"

    # Export detailed evidence
    $Result.CredentialAccessEvents | Export-Csv -Path 'C:\INCIDENT\EntraConnect-CredTheft.csv' -NoTypeInformation

    # Alert security team
    Send-MailMessage -To 'soc@company.com' -Subject 'CRITICAL: Entra Connect Compromise' -Body "Review: $($Result.ExportedReports -join '; ')"
}
```

### Pipeline Integration

```powershell
Get-ADComputer -Filter {Name -like '*SYNC*'} | Get-EntraConnectCompromise -DaysBack 14
```

Pipeline computers to audit for Entra Connect compromise.

## Parameters

### EntraConnectServer

- **Type:** string[]
- **Mandatory:** No
- **Pipeline:** Yes (ByValue, ByPropertyName)
- **Aliases:** ComputerName, HostName, ServerName
- **Description:** Specific Entra Connect server(s) to audit. If omitted, auto-discovery is attempted.

### DaysBack

- **Type:** int
- **Default:** 30
- **Range:** 1-365
- **Description:** Number of days to analyze event logs for compromise indicators

### ExportPath

- **Type:** string
- **Default:** C:\SecurityAudits\EntraConnect
- **Validation:** Must be valid file system path
- **Description:** Directory where detection results will be saved (CSV/JSON)

### IncludeConfigurationDump

- **Type:** switch
- **Default:** $false
- **Description:** Export current Entra Connect configuration for forensic analysis
- **Requires:** Local administrator rights on Entra Connect server

### CheckPTAAgents

- **Type:** switch
- **Default:** $false
- **Description:** Include Pass-Through Authentication agent integrity checks

### ScanAllServers

- **Type:** switch
- **Default:** $false
- **Description:** Scan all discovered Entra Connect servers (default: primary only)

## Output

Returns a structured `PSCustomObject` containing:

```powershell
[PSCustomObject]@{
    DomainName                # DNS name of audited domain
    AuditTimestamp            # When audit was performed
    EntraConnectServers       # Array of discovered/specified servers
    PrivilegedAccountCount    # Number of MSOL_*/AAD_* accounts
    CredentialAccessEvents    # SQL LocalDB access events (Event 4663)
    SyncConfigurationChanges  # Unauthorized sync modifications
    PTAAgentStatus            # PTA agent health and integrity
    ADSyncDecryptDetections   # Credential extraction tool execution
    HighRiskIndicators        # Count of critical findings
    MediumRiskIndicators      # Count of moderate findings
    RiskLevel                 # Overall: Secure/Low/Medium/High/Critical
    IsSecure                  # Boolean - no risks detected
    RecommendedActions        # Array of remediation steps
    ExportedReports           # File paths of generated reports
}
```

### Sample Output

```powershell
DomainName               : eguibarit.local
AuditTimestamp           : 2026-03-06 14:32:15
EntraConnectServers      : {AADSYNC01.eguibarit.local}
PrivilegedAccountCount   : 3
CredentialAccessEvents   : {Event 1, Event 2}
SyncConfigurationChanges : {}
PTAAgentStatus           : {Agent 1}
ADSyncDecryptDetections  : {}
HighRiskIndicators       : 2
MediumRiskIndicators     : 1
RiskLevel                : High
IsSecure                 : False
RecommendedActions       : {Investigate unauthorized SQL LocalDB access events, ...}
ExportedReports          : {C:\SecurityAudits\EntraConnect_PrivilegedAccounts_20260306-143215.csv, ...}
```

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Phase |
|--------------|---------------|-------|
| **T1078.004** | Valid Accounts: Cloud Accounts | Persistence, Defense Evasion |
| **T1003** | OS Credential Dumping | Credential Access |
| **T1098** | Account Manipulation | Persistence |
| **T1484** | Domain Policy Modification | Privilege Escalation |
| **T1550.002** | Use Alternate Authentication Material: Pass the Hash | Defense Evasion, Lateral Movement |

## Attack Scenarios Detected

### Scenario 1: ADSyncDecrypt Credential Extraction

**Attacker Goal:** Extract plaintext credentials from Entra Connect database

**Detection Indicators:**
- Event 4688: ADSyncDecrypt.exe or adconnectdump execution
- Event 4663: Unauthorized access to ADSync.mdf database
- Process: sqlcmd.exe accessing SQL LocalDB

**Function Response:**
- Creates `ADSyncDecryptDetections` array with full forensic details
- Sets `RiskLevel` to Critical
- Exports detailed event timeline to CSV
- Recommends immediate incident response

**Remediation:**
```powershell
# Isolate Entra Connect server
Disable-NetAdapter -Name "Ethernet" -Confirm:$false

# Reset ALL cloud administrator credentials
Get-MsolUser -UserPrincipalName 'admin@tenant.onmicrosoft.com' | Set-MsolUserPassword -ForceChangePassword $true

# Rotate service account
Set-ADAccountPassword -Identity 'MSOL_1234567890ab' -Reset
```

### Scenario 2: Privileged Account Abuse

**Attacker Goal:** Use MSOL_* account for privilege escalation

**Detection Indicators:**
- MSOL_* account with recent logon activity
- Account enabled when should be disabled
- Unusual group memberships (Domain Admins, etc.)

**Function Response:**
- Enumerates all MSOL_*/AAD_*/Sync_* accounts
- Risk assessment based on enabled status, password age, logon activity
- Highlights accounts with high-privileged group memberships

**Remediation:**
```powershell
# Disable unnecessary privileged accounts
Disable-ADAccount -Identity 'MSOL_1234567890ab'

# Remove from privileged groups
Remove-ADGroupMember -Identity 'Domain Admins' -Members 'MSOL_1234567890ab' -Confirm:$false

# Rotate credentials
Set-ADAccountPassword -Identity 'MSOL_1234567890ab' -Reset
```

### Scenario 3: Sync Service Manipulation

**Attacker Goal:** Disable sync to hide malicious changes

**Detection Indicators:**
- ADSync service stopped unexpectedly
- Event 7036: Service state change to stopped
- Sync scheduler configuration modified

**Function Response:**
- Monitors ADSync service status
- Analyzes Event 7036 for service state changes
- Exports sync configuration for comparison

**Remediation:**
```powershell
# Restart sync service
Start-Service -Name 'ADSync'

# Verify scheduler configuration
Import-Module ADSync
Get-ADSyncScheduler

# Re-enable sync if disabled
Set-ADSyncScheduler -SyncCycleEnabled $true
```

### Scenario 4: Pass-Through Authentication Agent Compromise

**Attacker Goal:** Intercept authentication requests via PTA agent

**Detection Indicators:**
- PTA agent service stopped or removed
- Agent configuration modified
- Unauthorized agent installation

**Function Response:**
- Validates PTA agent service status (with -CheckPTAAgents)
- Monitors agent health and configuration
- Detects unauthorized service manipulation

**Remediation:**
```powershell
# Verify agent integrity
Get-Service -Name 'AzureADConnectAuthenticationAgent'

# Reinstall compromised agent
# Download from Azure AD Connect portal
.\AzureADConnectAuthenticationAgentSetup.exe /quiet

# Validate registration
Get-AzureADConnectAuthenticationAgentStatus
```

## Requirements

### Permissions

- **Active Directory:** Domain Admin or equivalent (for account enumeration)
- **Entra Connect Server:** Local Administrator (for event log access, configuration export)
- **Network:** RPC/WinRM access to Entra Connect servers

### Prerequisites

```powershell
# Required modules
Import-Module ActiveDirectory

# Enable Object Access auditing on Entra Connect servers
auditpol /set /subcategory:"File System" /success:enable /failure:enable

# Enable Process Tracking auditing (for ADSyncDecrypt detection)
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
```

### Supported Environments

- **PowerShell:** 5.1, 7.0+
- **Windows Server:** 2016, 2019, 2022
- **Entra Connect:** All versions (Azure AD Connect 1.x, 2.x)
- **Active Directory:** Windows Server 2012 R2 - 2022

## Remediation

### Immediate Actions (CRITICAL)

If ADSyncDecrypt execution is detected:

1. **Isolate Server:**
   ```powershell
   # Disconnect from network
   Disable-NetAdapter -Name * -Confirm:$false
   ```

2. **Reset Cloud Credentials:**
   ```powershell
   # Reset all cloud administrator accounts
   Connect-MsolService
   Get-MsolUser -UserPrincipalName 'admin@tenant.onmicrosoft.com' | Set-MsolUserPassword -ForceChangePassword $true
   ```

3. **Rotate Service Accounts:**
   ```powershell
   # Reset MSOL_* account credentials
   Set-ADAccountPassword -Identity 'MSOL_1234567890ab' -Reset

   # Force Entra Connect reconfiguration
   # Use Azure AD Connect wizard to update credentials
   ```

4. **Enable Advanced Auditing:**
   ```powershell
   # Configure GPO for Entra Connect server
   auditpol /set /subcategory:"File System" /success:enable /failure:enable
   auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
   auditpol /set /subcategory:"Handle Manipulation" /success:enable /failure:enable
   ```

### Preventive Controls

#### Tier 0 Isolation

```powershell
# Deny interactive logon for standard users
$EntraConnectOU = "OU=Tier0,OU=Admin,DC=eguibarit,DC=local"
New-GPO -Name "Tier0-EntraConnect-Restrictions" | New-GPLink -Target $EntraConnectOU

# Configure logon restrictions via GPO
Set-GPRegistryValue -Name "Tier0-EntraConnect-Restrictions" -Key "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ValueName "CachedLogonsCount" -Type String -Value "0"
```

#### Credential Guard

```powershell
# Enable Credential Guard on Entra Connect server
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 1 -PropertyType DWORD -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -Value 1 -PropertyType DWORD -Force

# Reboot required
Restart-Computer -Force
```

#### Just-In-Time (JIT) Access

```powershell
# Remove persistent admin access
Remove-ADGroupMember -Identity 'Tier0-EntraConnect-Admins' -Members 'AdminUser1' -Confirm:$false

# Implement time-limited group membership via PAM/PIM
# Use Azure PIM or Microsoft Identity Manager for JIT elevation
```

#### File Integrity Monitoring

```powershell
# Configure FIM for critical files
$CriticalFiles = @(
    'C:\Program Files\Microsoft Azure AD Sync\Data\ADSync.mdf',
    'C:\Program Files\Microsoft Azure AD Sync\Data\ADSync_log.ldf',
    'C:\Program Files\Microsoft Azure AD Sync\Bin\miiserver.exe.config'
)

foreach ($File in $CriticalFiles) {
    # Configure SACL for file access auditing
    $ACL = Get-Acl -Path $File
    $AuditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
        'Everyone',
        'Read,Write,Delete',
        'Success,Failure'
    )
    $ACL.AddAuditRule($AuditRule)
    Set-Acl -Path $File -AclObject $ACL
}
```

### Long-Term Strategy

1. **Cloud-Only Authentication Migration:**
   - Eliminate on-premises sync risk entirely
   - Migrate to Azure AD-native authentication
   - Sunset Entra Connect servers

2. **Quarterly Credential Rotation:**
   ```powershell
   # Scheduled task for credential rotation
   $Action = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument '-File C:\Scripts\Rotate-EntraConnectCredentials.ps1'
   $Trigger = New-ScheduledTaskTrigger -Weekly -WeeksInterval 12 -DayOfWeek Sunday -At 2AM
   Register-ScheduledTask -TaskName 'EntraConnect-CredentialRotation' -Action $Action -Trigger $Trigger -User 'SYSTEM'
   ```

3. **Continuous Monitoring:**
   ```powershell
   # Scheduled hourly audit
   $Action = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument '-Command "Get-EntraConnectCompromise -DaysBack 1 -ExportPath C:\SecurityAudits"'
   $Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Hours 1)
   Register-ScheduledTask -TaskName 'EntraConnect-HourlyAudit' -Action $Action -Trigger $Trigger -User 'SYSTEM'
   ```

## Workflow Integration

### SIEM Integration (Splunk)

```powershell
# Export to JSON for Splunk HEC
$Result = Get-EntraConnectCompromise -DaysBack 7

$SplunkPayload = @{
    time = (Get-Date).ToUniversalTime().ToString('o')
    host = $env:COMPUTERNAME
    source = 'EguibarIT.SecurityPS'
    sourcetype = 'entra_connect_audit'
    event = $Result
} | ConvertTo-Json -Depth 10

Invoke-RestMethod -Uri 'https://splunk.company.com:8088/services/collector/event' `
    -Method POST `
    -Headers @{Authorization = "Splunk $env:SPLUNK_HEC_TOKEN"} `
    -Body $SplunkPayload
```

### Microsoft Sentinel Integration

```powershell
# Export to Log Analytics workspace
$Result = Get-EntraConnectCompromise -DaysBack 7

$WorkspaceId = 'your-workspace-id'
$SharedKey = 'your-shared-key'
$LogType = 'EntraConnectAudit'

# Send to Log Analytics (requires OMSIngestionAPI module)
Send-OMSAPIIngestionFile -CustomerId $WorkspaceId -SharedKey $SharedKey -Body ($Result | ConvertTo-Json -Depth 10) -LogType $LogType
```

### ServiceNow Incident Creation

```powershell
# Automated incident creation for high-risk findings
$Result = Get-EntraConnectCompromise -DaysBack 1

if ($Result.RiskLevel -in @('Critical', 'High')) {
    $IncidentBody = @{
        short_description = "Entra Connect Compromise Detected - Risk Level: $($Result.RiskLevel)"
        description = "High-risk indicators: $($Result.HighRiskIndicators)`nMedium-risk indicators: $($Result.MediumRiskIndicators)`nReview exported reports: $($Result.ExportedReports -join '; ')"
        urgency = '1'
        impact = '1'
        category = 'Security'
    } | ConvertTo-Json

    Invoke-RestMethod -Uri 'https://instance.service-now.com/api/now/table/incident' `
        -Method POST `
        -Headers @{Authorization = "Basic $env:SERVICENOW_AUTH"} `
        -Body $IncidentBody `
        -ContentType 'application/json'
}
```

## Performance Considerations

### Large Environments (10,000+ Users)

- **Account Enumeration:** Filters by prefix (efficient indexed search)
- **Event Log Analysis:** Processes in batches to avoid memory exhaustion
- **Multi-Server Scan:** Use `-ScanAllServers` with caution in environments with many sync servers

### Optimization Tips

```powershell
# Limit event log timeframe for faster scans
Get-EntraConnectCompromise -DaysBack 7

# Scan primary server only (default)
Get-EntraConnectCompromise

# Full scan only when incident suspected
Get-EntraConnectCompromise -ScanAllServers -CheckPTAAgents -IncludeConfigurationDump
```

## False Positives

### Legitimate Administrative Activity

**Scenario:** Administrator accessing ADSync.mdf for troubleshooting

**Indicator:** Event 4663 from administrative account during business hours

**Mitigation:**
- Review account identity against approved administrator list
- Correlate with change management records
- Validate business justification via ServiceNow ticket

### Scheduled Maintenance

**Scenario:** Planned service restart for Entra Connect upgrade

**Indicator:** Event 7036 (service stopped) during maintenance window

**Mitigation:**
- Filter events by maintenance calendar
- Exclude known maintenance accounts from alerting
- Document maintenance activities in audit trail

### Backup Operations

**Scenario:** Legitimate SQL LocalDB backup accessing ADSync.mdf

**Indicator:** Event 4663 from backup service account

**Mitigation:**
```powershell
# Exclude known backup accounts
$Result = Get-EntraConnectCompromise -DaysBack 7
$FilteredEvents = $Result.CredentialAccessEvents | Where-Object {
    $_.UserName -notin @('BackupExec', 'Veeam', 'CommVault')
}
```

## Related Functions

- **Get-PasswordSprayAttack** - Detects credential guessing against cloud accounts
- **Get-GoldenSAMLDetection** - Identifies SAML token forgery (federation trust compromise)
- **Get-ADKerberoastingPattern** - Monitors service account credential theft
- **Get-DCSyncAttack** - Detects replication-based credential dumping

## External Resources

### Offensive Research

- [Azure AD Connect for Red Team](https://blog.xpnsec.com/azuread-connect-for-redteam/)
- [ADConnect Dump Tool](https://github.com/dirkjanm/adconnectdump)
- [Extracting AAD Connect Credentials](https://blog.fox-it.com/2020/08/25/recovery-of-azure-ad-connect-credentials/)

### Microsoft Documentation

- [Entra Connect Security Best Practices](https://learn.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-security-best-practices)
- [Tier 0 Asset Isolation](https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-deployment)
- [Pass-Through Authentication Security](https://learn.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-pta-security-deep-dive)

### MITRE ATT&CK

- [T1078.004 - Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
- [T1003 - OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)
- [T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)

## Related Website Documentation

This function is part of the comprehensive [Five Eyes Active Directory Attacks Guide](https://www.eguibarit.com/security/five-eyes-ad-attacks.html).

For detailed technical background, real-world case studies, and enterprise implementation guidance, see:
- [Attack #14: Entra Connect Compromise](https://www.eguibarit.com/security/five-eyes-ad-attacks.html#entra-connect-compromise)
- [PowerShell Detection Script](https://www.eguibarit.com/powershell/detect-entra-connect-compromise.html)

---

**Module:** EguibarIT.SecurityPS
**Category:** Security Auditing
**Tags:** EntraConnect, AzureADConnect, HybridIdentity, CredentialTheft, Tier0
