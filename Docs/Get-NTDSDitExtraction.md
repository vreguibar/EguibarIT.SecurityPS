# Get-NTDSDitExtraction Function Documentation

## Overview

**Get-NTDSDitExtraction** is a comprehensive PowerShell function that detects NTDS.dit extraction attempts on domain controllers through multi-layered event correlation, file access monitoring, and process analysis.

**Function File:** `Public/Get-NTDSDitExtraction.ps1`
**Version:** 1.0.0
**Last Modified:** 06/Mar/2026
**Author:** Vicente Rodriguez Eguibar

## Purpose

This function performs comprehensive five-phase detection for NTDS.dit database extraction:

1. **Volume Shadow Copy (VSS) Detection** - Monitors VSS service activity and shadow copy creation
2. **Extraction Tool Detection** - Identifies execution of ntdsutil.exe, vssadmin.exe, esentutl.exe
3. **File Access Monitoring** - Analyzes Event 4663 for unauthorized ntds.dit access
4. **IFM Backup Detection** - Monitors Event 2004 for NTDSUtil Install From Media operations
5. **File Creation Monitoring** - Detects ntds.dit copies outside legitimate locations

**Attack Method:** NTDS.dit extraction allows attackers to:
1. Access the complete Active Directory database offline
2. Extract ALL domain credentials (password hashes, Kerberos keys)
3. Crack passwords at unlimited speed without authentication
4. Forge Kerberos tickets (Golden Ticket, Silver Ticket)
5. Gain complete domain control

## Critical Principle

**NTDS.dit contains EVERY credential in your Active Directory domain.**
The ntds.dit database file is the single most valuable target in Active Directory. It contains:
- NTLM password hashes for all user accounts
- Kerberos AES keys (128-bit and 256-bit)
- KRBTGT account keys (Golden Ticket creation)
- Password history (past 24 passwords by default)
- Service account credentials
- Computer account hashes

**Attack Scenario:**
```
1. Attacker gains Domain Admin access (via Kerberoasting, password spray, etc.)
2. Creates Volume Shadow Copy on DC: vssadmin create shadow /for=C:
3. Copies ntds.dit from shadow copy: copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\temp\
4. Copies SYSTEM registry hive: reg save HKLM\SYSTEM C:\temp\SYSTEM
5. Exfiltrates both files (total < 5GB typically)
6. Offline extraction: secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
7. Obtains 100,000+ password hashes in minutes
8. Cracks passwords, forges Golden Tickets, maintains persistence indefinitely
```

## Key Features

### Five-Phase Detection

#### Phase 1: Volume Shadow Copy (VSS) Activity Monitoring

- **Event 7036:** VSS service started (high-risk indicator on DCs)
- **Event 8222:** Shadow copy successfully created
- Legitimate vs. malicious VSS usage correlation
- Timestamp correlation with other extraction indicators

#### Phase 2: NTDS Extraction Tool Execution Detection

Requires Sysmon deployment for visibility:
- **Sysmon Event 1:** Process creation monitoring
- Detects `ntdsutil.exe` execution (IFM backup command)
- Detects `vssadmin.exe` execution (shadow copy creation)
- Detects `esentutl.exe` execution (database copy operations)
- Detects `diskshadow.exe` execution (scriptable VSS operations)
- Captures full command-line arguments and user context

#### Phase 3: Event 4663 (NTDS.dit File Access) Analysis

- Monitors Object Access events for `ntds.dit` file
- **Normal:** `lsass.exe` accessing ntds.dit (database in use)
- **Malicious:** ANY other process accessing ntds.dit
- Requires SACL configuration on ntds.dit file
- Captures process name, user account, access type

#### Phase 4: Event 2004 (NTDSUtil IFM Backup) Detection

- Directory Service Event 2004: IFM backup created
- Rare in production (only used for DC cloning/deployment)
- Any occurrence outside maintenance windows = critical alert
- IFM backups create full ntds.dit copy on filesystem

#### Phase 5: Sysmon Event 11 (File Creation) Monitoring

- Detects ntds.dit file creation outside `C:\Windows\NTDS\`
- Monitors SYSTEM registry hive copies (required for decryption)
- Captures file path, creating process, user context
- **Critical:** SYSTEM + ntds.dit copy = confirmed extraction

### Smart Risk Categorization

Each finding receives a severity assessment:
- **Critical:** Confirmed ntds.dit extraction (Event 11, non-LSASS Event 4663)
- **High:** VSS shadow copy creation, Sysmon not installed, auditing disabled
- **Medium:** Reserved for future use
- **Low:** Normal LSASS.exe accessing ntds.dit

## Usage

### Basic Domain-Wide Scan

```powershell
Get-NTDSDitExtraction -CheckAllDCs -Verbose
```

Scans all domain controllers for NTDS.dit extraction indicators in the last 30 days.

### Specific Domain Controller Analysis

```powershell
Get-NTDSDitExtraction -DomainController 'DC01' -DaysBack 90
```

Analyzes specific DC for extraction attempts over the last 90 days.

### Pipeline from Get-ADDomainController

```powershell
Get-ADDomainController -Filter * | Get-NTDSDitExtraction -ExportPath 'C:\SecurityAudits'
```

Scans all DCs and exports findings to CSV/JSON.

### Current DC Only (Quick Check)

```powershell
Get-NTDSDitExtraction -DaysBack 7 -Verbose
```

Analyzes current domain controller for recent extraction attempts.

### Extended Analysis with Custom Export Path

```powershell
Get-NTDSDitExtraction -CheckAllDCs -DaysBack 180 -ExportPath 'C:\IR\NTDSAudit' -Verbose
```

Comprehensive 6-month analysis across all DCs with incident response export path.

### Automation Integration

```powershell
# Daily scheduled task
$Results = Get-NTDSDitExtraction -CheckAllDCs -DaysBack 1 -ExportPath 'C:\SecurityMonitoring'

# Alert on critical findings
$Critical = $Results | Where-Object { $_.RiskLevel -eq 'Critical' }

if ($Critical.Count -gt 0) {
    Send-MailMessage -To 'soc@contoso.com' `
        -Subject 'CRITICAL: NTDS.dit Extraction Detected' `
        -Body "Detected $($Critical.Count) critical NTDS.dit extraction indicators! ASSUME DOMAIN COMPROMISE." `
        -Priority High -Attachments (Join-Path $ExportPath "NTDSExtraction-Detection-*.csv")
}
```

## Parameters

### DomainController

- **Type:** string[]
- **Default:** Current computer (if not CheckAllDCs)
- **Description:** Target domain controller(s) to analyze
- **Pipeline:** Accepts 'HostName', 'Name', 'ComputerName' from Get-ADDomainController
- **Permissions:** Domain Admin or Event Log Reader on target DCs
- **Examples:** 'DC01', 'DC01.contoso.com', @('DC01', 'DC02', 'DC03')

### DaysBack

- **Type:** int
- **Default:** 30 days
- **Range:** 1 to 365 days
- **Description:** Number of days to analyze event logs for extraction indicators
- **Performance:** Longer time spans increase query duration

### ExportPath

- **Type:** string
- **Default:** `$env:USERPROFILE\Desktop\NTDSExtractionAudit`
- **Description:** Directory where CSV and JSON results are saved
- **Auto-Create:** Directory created if it doesn't exist
- **Output Files:** `NTDSExtraction-Detection-yyyyMMdd-HHmmss.csv` and `.json`

### CheckAllDCs

- **Type:** switch
- **Default:** $false (current DC only)
- **Description:** Scans all domain controllers in the domain
- **Discovery:** Uses `Get-ADDomainController -Filter *`
- **Performance:** Scanning multiple DCs takes longer but provides comprehensive coverage

## Output

Returns `PSCustomObject` array with the following properties:

```powershell
[PSCustomObject]@{
    Timestamp            # Detection timestamp (yyyy-MM-dd HH:mm:ss)
    FindingType          # Type of detection indicator
    RiskLevel            # Critical/High/Medium/Low
    DomainController     # Affected domain controller
    EventID              # Windows Event ID (4663, 7036, 8222, 2004, 1, 11)
    ProcessName          # Process that performed action (if applicable)
    CommandLine          # Full command line (if applicable)
    User                 # User account context (if applicable)
    TargetFilename       # File path (for Event 11 file creation)
    ServiceName          # Service name (for Event 7036)
    Indicator            # Description of detected activity
    Recommendation       # Remediation guidance
    AdditionalDetails    # Event message excerpt or additional context
}
```

## Severity Levels

| Severity | Criteria |
|----------|----------|
| **Critical** | ntds.dit file created outside C:\Windows\NTDS\ (Event 11) OR non-LSASS process accessed ntds.dit (Event 4663) OR NTDSUtil IFM backup (Event 2004) OR extraction tool executed (Event 1) OR VSS shadow copy created (Event 8222) |
| **High** | VSS service activity (Event 7036) OR Sysmon not installed OR Object Access auditing disabled OR SYSTEM registry hive copied |
| **Medium** | Reserved for future use |
| **Low** | Normal LSASS.exe accessing ntds.dit (expected behavior) |

## Detection Details

### Finding Types

| Finding Type | Event Source | Risk Level | Description |
|--------------|-------------|------------|-------------|
| **NTDS.dit File Copy Created** | Sysmon Event 11 | Critical | ntds.dit created outside C:\Windows\NTDS\ |
| **Unauthorized NTDS.dit File Access** | Event 4663 | Critical | Non-LSASS process accessed ntds.dit |
| **NTDSUtil IFM Backup** | Event 2004 | Critical | Install From Media backup created |
| **NTDS Extraction Tool Executed** | Sysmon Event 1 | Critical | ntdsutil/vssadmin/esentutl executed |
| **VSS Shadow Copy Created** | Event 8222 | Critical | Volume shadow copy created on DC |
| **SYSTEM Registry Hive Copy** | Sysmon Event 11 | High | SYSTEM hive copied (contains decryption keys) |
| **VSS Service Activity** | Event 7036 | High | VSS service started on DC |
| **Sysmon Not Installed** | Service Check | High | Process monitoring unavailable |
| **Object Access Auditing Disabled** | Audit Policy Check | High | Event 4663 not logged |

## MITRE ATT&CK Mapping

- **T1003.003:** OS Credential Dumping - NTDS
- **T1003:** OS Credential Dumping (parent technique)
- **T1557:** Adversary-in-the-Middle
- **T1558.001:** Steal or Forge Kerberos Tickets - Golden Ticket (post-extraction)

## Requirements

### Permissions

- **Domain Admin** or equivalent for cross-DC event log queries
- **Event Log Reader** on target domain controllers
- **Remote Management** rights for WinRM/PSRemoting

### Event Logging

Critical events that MUST be enabled for detection:

#### Event ID 4663 (Object Access - File)
```powershell
# Enable Advanced Audit Policy
auditpol /set /subcategory:"File System" /success:enable /failure:enable

# Configure SACL on ntds.dit file (run on each DC)
$NTDSPath = 'C:\Windows\NTDS\ntds.dit'
$ACL = Get-Acl -Path $NTDSPath -Audit
$AuditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
    'Everyone',
    'Read,ReadAndExecute',
    'Success'
)
$ACL.AddAuditRule($AuditRule)
Set-Acl -Path $NTDSPath -AclObject $ACL
```

#### Event ID 7036 & 8222 (System Events - VSS)
- Enabled by default in System event log
- Ensure System log retention is adequate (30+ days)

#### Event ID 2004 (Directory Service - IFM Backup)
- Enabled by default in Directory Service event log
- Forward to SIEM for centralized monitoring

#### Sysmon Event 1 & 11 (Process Creation, File Creation)
**CRITICAL:** Deploy Sysmon to all domain controllers for comprehensive visibility.

```powershell
# Download Sysmon
Invoke-WebRequest -Uri 'https://live.sysinternals.com/sysmon64.exe' -OutFile 'C:\temp\sysmon64.exe'

# Create Sysmon configuration for NTDS.dit monitoring
$SysmonConfig = @'
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <ProcessCreate onmatch="include">
      <Image condition="contains">ntdsutil.exe</Image>
      <Image condition="contains">vssadmin.exe</Image>
      <Image condition="contains">esentutl.exe</Image>
      <Image condition="contains">diskshadow.exe</Image>
    </ProcessCreate>
    <FileCreate onmatch="include">
      <TargetFilename condition="contains">ntds.dit</TargetFilename>
      <TargetFilename condition="end with">SYSTEM</TargetFilename>
    </FileCreate>
  </EventFiltering>
</Sysmon>
'@
$SysmonConfig | Out-File 'C:\temp\sysmon-ntds-config.xml' -Encoding UTF8

# Install Sysmon
C:\temp\sysmon64.exe -accepteula -i C:\temp\sysmon-ntds-config.xml
```

### PowerShell Modules

- **ActiveDirectory** - For Get-ADDomainController

### Network Requirements

- **WinRM/PSRemoting** enabled on all domain controllers
- **Event Log Remote Access** (RPC/TCP 135, dynamic high ports)

## Remediation Guidance

### Immediate Response to Critical Findings

**CRITICAL:** Any NTDS.dit extraction indicator = ASSUME DOMAIN COMPROMISE.

```powershell
# Step 1: ISOLATE affected domain controllers
# Disconnect from network if possible (physical datacenter) or implement firewall ACLs

# Step 2: Search for ntds.dit file copies on DC filesystems
Get-ChildItem -Path C:\ -Recurse -Filter 'ntds.dit' -ErrorAction SilentlyContinue | 
    Where-Object { $_.FullName -notmatch 'C:\\Windows\\NTDS\\ntds\.dit' }

# Step 3: Search for SYSTEM registry hive copies
Get-ChildItem -Path C:\ -Recurse -Filter 'SYSTEM' -ErrorAction SilentlyContinue | 
    Where-Object { $_.FullName -notmatch 'C:\\Windows\\System32\\config\\SYSTEM' }

# Step 4: Delete any extracted files (evidence preservation: backup first)
# Copy to forensic storage, then delete from DC

# Step 5: Reset KRBTGT password IMMEDIATELY (twice, 10 hours apart)
# Download New-KrbtgtKeys.ps1 from Microsoft
# https://github.com/microsoft/New-KrbtgtKeys.ps1
New-KrbtgtKeys.ps1 -PasswordOption Interactive -SkipPreChecks

# Wait 10+ hours for replication
Start-Sleep -Seconds 36000

# Second KRBTGT reset
New-KrbtgtKeys.ps1 -PasswordOption Interactive -SkipPreChecks

# Step 6: Force password reset for ALL privileged accounts
Get-ADGroupMember -Identity 'Domain Admins' -Recursive | ForEach-Object {
    Set-ADUser -Identity $_.SamAccountName -ChangePasswordAtLogon $true
    Write-Host "Forced password reset for: $($_.SamAccountName)"
}

Get-ADGroupMember -Identity 'Enterprise Admins' -Recursive | ForEach-Object {
    Set-ADUser -Identity $_.SamAccountName -ChangePasswordAtLogon $true
}

Get-ADGroupMember -Identity 'Schema Admins' -Recursive | ForEach-Object {
    Set-ADUser -Identity $_.SamAccountName -ChangePasswordAtLogon $true
}

# Step 7: Audit Event 4624 (logon events) for lateral movement
$StartDate = (Get-Date).AddDays(-30)
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4624
    StartTime = $StartDate
} | Where-Object { $_.Properties[8].Value -eq 3 } |  # Network logon (type 3)
    Select-Object TimeCreated, @{N='User';E={$_.Properties[5].Value}}, @{N='SourceIP';E={$_.Properties[18].Value}}

# Step 8: Review outbound network traffic from DCs (identify exfiltration)
# Firewall logs, NetFlow, proxy logs - look for large file transfers (1-5GB)

# Step 9: Engage incident response team
# Full domain compromise - professional forensics required
```

### Deploy Sysmon to All Domain Controllers

```powershell
# Sysmon deployment script
$DCs = (Get-ADDomainController -Filter *).HostName

$SysmonConfig = @'
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <ProcessCreate onmatch="include">
      <Image condition="contains">ntdsutil.exe</Image>
      <Image condition="contains">vssadmin.exe</Image>
      <Image condition="contains">esentutl.exe</Image>
      <Image condition="contains">diskshadow.exe</Image>
    </ProcessCreate>
    <FileCreate onmatch="include">
      <TargetFilename condition="contains">ntds.dit</TargetFilename>
      <TargetFilename condition="end with">SYSTEM</TargetFilename>
      <TargetFilename condition="end with">SYSTEM.sav</TargetFilename>
    </FileCreate>
  </EventFiltering>
</Sysmon>
'@

foreach ($DC in $DCs) {
    Write-Host "Deploying Sysmon to $DC..."
    
    # Copy Sysmon binary
    Copy-Item -Path 'C:\Tools\sysmon64.exe' -Destination "\\$DC\C$\Windows\Temp\" -Force
    
    # Copy config
    $SysmonConfig | Out-File "\\$DC\C$\Windows\Temp\sysmon-config.xml" -Encoding UTF8
    
    # Install Sysmon
    Invoke-Command -ComputerName $DC -ScriptBlock {
        C:\Windows\Temp\sysmon64.exe -accepteula -i C:\Windows\Temp\sysmon-config.xml
    }
    
    Write-Host "Sysmon deployed to $DC" -ForegroundColor Green
}
```

### Enable Event 4663 (Object Access) on ntds.dit

```powershell
# Deploy SACL to all DCs via Group Policy or direct configuration
$DCs = (Get-ADDomainController -Filter *).HostName

foreach ($DC in $DCs) {
    Write-Host "Configuring SACL on $DC..."
    
    Invoke-Command -ComputerName $DC -ScriptBlock {
        # Enable File System auditing
        auditpol /set /subcategory:"File System" /success:enable /failure:enable
        
        # Configure SACL on ntds.dit
        $NTDSPath = 'C:\Windows\NTDS\ntds.dit'
        $ACL = Get-Acl -Path $NTDSPath -Audit
        
        # Remove existing audit rules to avoid duplicates
        $ACL.AuditRules | ForEach-Object { $ACL.RemoveAuditRule($_) }
        
        # Add audit rule for Everyone (Read access)
        $AuditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
            'Everyone',
            'Read,ReadAndExecute',
            'Success'
        )
        $ACL.AddAuditRule($AuditRule)
        
        # Apply SACL
        Set-Acl -Path $NTDSPath -AclObject $ACL
        
        Write-Host "SACL configured on ntds.dit"
    }
}
```

### Implement Continuous Monitoring

```powershell
# Scheduled task: Run hourly on dedicated monitoring server
$Results = Get-NTDSDitExtraction -CheckAllDCs -DaysBack 2 -ExportPath 'C:\SecurityMonitoring\NTDS'

# Alert on ANY critical findings
$Critical = $Results | Where-Object { $_.RiskLevel -eq 'Critical' }

if ($Critical.Count -gt 0) {
    # Send high-priority alert
    Send-MailMessage -To 'soc@contoso.com', 'ciso@contoso.com' `
        -Subject 'CRITICAL: NTDS.dit Extraction Detected - DOMAIN COMPROMISE' `
        -Body @"
CRITICAL SECURITY ALERT

NTDS.dit extraction detected on domain controller(s).
This indicates TOTAL DOMAIN COMPROMISE.

Domain Controllers Affected: $($Critical.DomainController | Select-Object -Unique)
Total Critical Findings: $($Critical.Count)

Finding Types:
$($Critical | Group-Object -Property FindingType | Format-Table -AutoSize | Out-String)

IMMEDIATE ACTIONS REQUIRED:
1. ISOLATE affected domain controllers
2. Reset KRBTGT password (twice, 10 hours apart)
3. Force password reset for ALL privileged accounts
4. Engage incident response team
5. Review attached CSV for full details

Attachment: Latest detection report
"@ `
        -Priority High `
        -Attachments (Get-ChildItem -Path 'C:\SecurityMonitoring\NTDS\*.csv' | Sort-Object -Property LastWriteTime -Descending | Select-Object -First 1).FullName
}

# Alert on high-risk gaps (Sysmon not installed, auditing disabled)
$HighRiskGaps = $Results | Where-Object { 
    $_.FindingType -in @('Sysmon Not Installed', 'Object Access Auditing Disabled') 
}

if ($HighRiskGaps.Count -gt 0) {
    Send-MailMessage -To 'security@contoso.com' `
        -Subject 'URGENT: NTDS.dit Extraction Detection Gaps on DCs' `
        -Body "Detected $($HighRiskGaps.Count) domain controllers with detection gaps. Deploy Sysmon and enable Object Access auditing immediately."
}
```

## Example Workflows

### Post-Incident Forensic Analysis

```powershell
# Extended 6-month forensic analysis after suspected breach
$Results = Get-NTDSDitExtraction -CheckAllDCs -DaysBack 180 -ExportPath 'C:\IR\ForensicAnalysis' -Verbose

# Group findings by DC
$ByDC = $Results | Group-Object -Property DomainController

Write-Host "=== Forensic Analysis Summary ===" -ForegroundColor Cyan
foreach ($DC in $ByDC) {
    Write-Host "`nDomain Controller: $($DC.Name)" -ForegroundColor Yellow
    
    $Critical = ($DC.Group | Where-Object RiskLevel -eq 'Critical').Count
    $High = ($DC.Group | Where-Object RiskLevel -eq 'High').Count
    
    Write-Host "  Critical Findings: $Critical" -ForegroundColor $(if ($Critical -gt 0) { 'Red' } else { 'Green' })
    Write-Host "  High Findings: $High" -ForegroundColor $(if ($High -gt 0) { 'Magenta' } else { 'Green' })
    
    # Timeline analysis
    $Timeline = $DC.Group | Sort-Object -Property Timestamp
    if ($Timeline.Count -gt 0) {
        Write-Host "  First Indicator: $($Timeline[0].Timestamp) - $($Timeline[0].FindingType)"
        Write-Host "  Last Indicator: $($Timeline[-1].Timestamp) - $($Timeline[-1].FindingType)"
    }
}

# Identify attack timeline
$ExtractedFiles = $Results | Where-Object { $_.FindingType -eq 'NTDS.dit File Copy Created' }
if ($ExtractedFiles.Count -gt 0) {
    Write-Host "`n=== CONFIRMED NTDS.dit EXTRACTION ===" -ForegroundColor Red
    $ExtractedFiles | Format-Table Timestamp, DomainController, TargetFilename, User, ProcessName
}
```

### Weekly Security Posture Assessment

```powershell
# Weekly scheduled task: Assess detection coverage
$Results = Get-NTDSDitExtraction -CheckAllDCs -DaysBack 7 -ExportPath 'C:\WeeklyReports'

# Calculate detection coverage score
$TotalDCs = (Get-ADDomainController -Filter *).Count
$DCsWithSysmon = $TotalDCs - ($Results | Where-Object FindingType -eq 'Sysmon Not Installed').Count
$DCsWithAuditing = $TotalDCs - ($Results | Where-Object FindingType -eq 'Object Access Auditing Disabled').Count

$SysmonCoverage = [math]::Round(($DCsWithSysmon / $TotalDCs) * 100, 2)
$AuditingCoverage = [math]::Round(($DCsWithAuditing / $TotalDCs) * 100, 2)

Write-Host "`n=== NTDS.dit Extraction Detection Coverage ===" -ForegroundColor Cyan
Write-Host "Total Domain Controllers: $TotalDCs"
Write-Host "Sysmon Deployment: $SysmonCoverage% ($DCsWithSysmon/$TotalDCs)" -ForegroundColor $(if ($SysmonCoverage -eq 100) { 'Green' } else { 'Yellow' })
Write-Host "Object Access Auditing: $AuditingCoverage% ($DCsWithAuditing/$TotalDCs)" -ForegroundColor $(if ($AuditingCoverage -eq 100) { 'Green' } else { 'Yellow' })

if ($SysmonCoverage -lt 100 -or $AuditingCoverage -lt 100) {
    Write-Warning "Detection gaps exist. Full NTDS.dit extraction visibility requires 100% coverage."
}
```

## Performance Considerations

- **Event log queries:** Large Security logs (1GB+) may take 5-10 minutes per DC
- **Multi-DC scanning:** 10 DCs with 30-day window typically completes in 15-30 minutes
- **Network bandwidth:** Minimal (event data < 1MB typically)
- **Time span:** Limit to 30-90 days for routine monitoring; 180-365 days for forensic analysis

## False Positives

Common scenarios that may appear as findings:

- **Legitimate DC backups:** Scheduled Windows Server Backup creates VSS snapshots (Event 8222)
  - **Mitigation:** Correlate with change management calendar, verify backup software identity
- **DC cloning/deployment:** NTDSUtil IFM (Event 2004) is normal during DC promotion
  - **Mitigation:** Expected only during planned DC deployments
- **Antivirus/EDR scanning:** Some security software may access ntds.dit (Event 4663)
  - **Mitigation:** Whitelist known security software process names

**Best Practice:** All VSS and IFM activity on production DCs should be correlated with approved change management tickets. ANY unscheduled occurrence = investigate immediately.

## Related Functions

- [Get-DCSyncAttack](Get-DCSyncAttack.md) - Detects DCSync replication attacks
- [Get-GoldenTicketDetection](Get-GoldenTicketDetection.md) - Detects forged TGTs (post-NTDS extraction)
- [Get-SilverTicketDetection](Get-SilverTicketDetection.md) - Detects forged service tickets
- [Get-UnconstrainedDelegation](Get-UnconstrainedDelegation.md) - Identifies delegation misconfigurations

## Additional Resources

- [MITRE ATT&CK T1003.003](https://attack.mitre.org/techniques/T1003/003/)
- [NTDS.dit Extraction Explained](https://adsecurity.org/?p=2398)
- [Sysmon Configuration Guide](https://github.com/SwiftOnSecurity/sysmon-config)
- [New-KrbtgtKeys.ps1 Script](https://github.com/microsoft/New-KrbtgtKeys.ps1)
- [Event 4663 Object Access Auditing](https://docs.microsoft.com/windows/security/threat-protection/auditing/event-4663)
- [GitHub Repository](https://github.com/vreguibar/EguibarIT.SecurityPS)

---

**Module:** EguibarIT.SecurityPS
**Component:** Security Auditing
**Role:** Threat Detection
**Functionality:** NTDS.dit Extraction Detection
