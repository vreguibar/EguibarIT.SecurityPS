# Get-RBCDAbuse Function Documentation

## Overview

**Get-RBCDAbuse** is a comprehensive PowerShell function that detects Resource-Based Constrained Delegation (RBCD) abuse in Active Directory through multi-phase event correlation, AD attribute analysis, and Kerberos delegation monitoring.

**Function File:** `Public/Get-RBCDAbuse.ps1`
**Version:** 1.0.0
**Last Modified:** 06/Mar/2026
**Author:** Vicente Rodriguez Eguibar

## Purpose

This function performs comprehensive five-phase detection for Resource-Based Constrained Delegation abuse:

1. **RBCD Configuration Enumeration** - Identifies computers with msDS-AllowedToActOnBehalfOfOtherIdentity attribute
2. **Event 5136 Detection** - Monitors Directory Service Changes for RBCD attribute modifications
3. **Event 4742 Monitoring** - Detects computer account changes related to RBCD
4. **Event 4769 Analysis** - Analyzes Kerberos S4U2Proxy delegation ticket requests
5. **MachineAccountQuota Audit** - Detects anomalous computer account creation enabling RBCD attacks

**Attack Method:** Resource-Based Constrained Delegation allows attackers to:

1. Gain WRITE permissions on a target computer account (any user with GenericWrite, WriteProperty, or WriteDACL)
2. Modify the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute to allow an attacker-controlled account to impersonate users
3. Request a service ticket (TGS) for ANY domain user (including Domain Admins) to the target computer
4. Authenticate to the target computer as a privileged user without knowing their password
5. Escalate privileges and move laterally across the domain

## Critical Principle

**RBCD bypasses traditional Kerberos delegation security controls.**

Unlike traditional Constrained Delegation (configured via `msDS-AllowedToDelegateTo`) which requires SeEnableDelegationPrivilege (Domain Admin equivalent), RBCD allows ANY user with WRITE permissions on a computer account to configure delegation.

**Attack Scenario:**

```
1. Attacker compromises low-privilege user account (UserA)
2. Discovers UserA has GenericWrite on SERVER01 computer account (common misconfiguration)
3. Creates attacker-controlled computer account: EVIL-PC$ (via MachineAccountQuota if > 0)
4. Configures RBCD on SERVER01:
   Set-ADComputer SERVER01 -PrincipalsAllowedToDelegateToAccount EVIL-PC$

5. Requests TGS for Domain Admin to SERVER01 using Rubeus:
   Rubeus.exe s4u /user:EVIL-PC$ /rc4:<EVIL-PC$ hash> /impersonateuser:Administrator /msdsspn:cifs/SERVER01 /ptt

6. Now has Domain Admin privileges on SERVER01 (can dump credentials, install backdoors, etc.)
7. Lateral movement to other systems using stolen credentials
8. Full domain compromise
```

**Key Exploitation Requirements:**

- WRITE permission on target computer account (GenericWrite, WriteProperty, WriteDACL, GenericAll)
- Ability to create or control a computer account (MachineAccountQuota > 0 OR pre-existing compromised computer)
- Kerberos S4U2Self and S4U2Proxy extensions (enabled by default in all AD environments)

## Key Features

### Five-Phase Detection

#### Phase 1: RBCD Configuration Enumeration

- Queries all computer accounts for `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute
- Parses security descriptors to extract allowed delegation accounts
- **Severity:** CRITICAL (any RBCD configuration requires verification)
- Identifies both legitimate and malicious delegation configurations
- Captures WhenChanged timestamp for timeline analysis

**Detection Logic:**

```powershell
Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |
    Where-Object { $_.'msDS-AllowedToActOnBehalfOfOtherIdentity' -ne $null }
```

#### Phase 2: Event 5136 (Directory Service Changes) Detection

- Monitors Security event log for Event ID 5136
- Filters for `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute modifications
- **Severity:** CRITICAL (modification = potential RBCD attack in progress)
- Captures:
  - User who made the change (SubjectUserName)
  - Target object (ObjectDN)
  - Operation type (Value Added, Value Deleted, Value Cleared)
  - Full attribute value (security descriptor binary)
  - Timestamp

**Event Structure:**

```xml
<Event>
  <EventData>
    <Data Name="SubjectUserName">attacker</Data>
    <Data Name="ObjectDN">CN=SERVER01,OU=Servers,DC=corp,DC=local</Data>
    <Data Name="AttributeLDAPDisplayName">msDS-AllowedToActOnBehalfOfOtherIdentity</Data>
    <Data Name="OperationType">%%14674</Data> <!-- Value Added -->
  </EventData>
</Event>
```

#### Phase 3: Event 4742 (Computer Account Changed) Monitoring

- Detects Event ID 4742 related to RBCD attribute changes
- Provides additional context for computer modifications
- **Severity:** CRITICAL (correlates with Event 5136)
- Cross-references with Phase 1 configurations

#### Phase 4: Event 4769 (Kerberos S4U2Proxy) Analysis

Requires Kerberos service ticket auditing:

- **Event ID 4769:** Kerberos service ticket requested
- **Ticket Options:** `0x40810000` (S4U2Proxy delegation request)
- **Severity:** HIGH (indicates active delegation - may be legitimate OR exploitation)
- **Detection Pattern:** S4U2Proxy requests from non-standard sources or to unexpected services

**S4U2Proxy Indicator:**

```
Event 4769
TicketOptions: 0x40810000
ServiceName: cifs/SERVER01.corp.local
TargetUserName: Administrator
```

**Legitimate vs. Malicious S4U2Proxy:**
| Legitimate | Malicious |
|------------|-----------|
| IIS application pools | Recently created computer accounts |
| SQL Server service accounts | Unusual service names (not cifs/http/ldap) |
| Scheduled tasks with constrained delegation | High-privilege impersonation (Domain Admins) |
| Consistent patterns (same service/user pairs) | Sporadic, unusual delegation patterns |

#### Phase 5: MachineAccountQuota and Computer Account Creation Audit

- **MachineAccountQuota Check:** Verifies `ms-DS-MachineAccountQuota` attribute on domain object
  - **Default:** 10 (allows ANY authenticated user to create 10 computer accounts)
  - **Secure:** 0 (prevents non-admin computer creation)
  - **Severity:** HIGH if > 0 (enables RBCD attack vector)

- **Recent Computer Creation:** Enumerates computers created within search timeframe
  - Identifies creators (non-Domain Admin = potential attack)
  - **Severity:** MEDIUM (requires verification)
  - Detects attacker-controlled accounts like `EVIL-PC$`, `ATTACKER-WORKSTATION$`

**Attack Enabler:**

```powershell
# Default configuration (VULNERABLE)
(Get-ADDomain).'ms-DS-MachineAccountQuota'  # Returns 10

# Attacker exploitation
New-ADComputer -Name "EVIL-PC" -Enabled $true  # Succeeds without Domain Admin
```

### Smart Risk Categorization

Each finding receives a severity assessment:

- **CRITICAL:** RBCD attribute configured (Phase 1), Event 5136/4742 modifications detected
- **HIGH:** S4U2Proxy delegation detected (Phase 4), MachineAccountQuota > 0 (Phase 5)
- **MEDIUM:** Non-admin computer account creation (potential attacker-controlled account)

## Usage

### Basic Domain-Wide Scan

```powershell
Get-RBCDAbuse -Verbose
```

Scans the nearest domain controller for RBCD abuse indicators in the last 30 days.

### Specific Domain Controller Analysis

```powershell
Get-RBCDAbuse -DomainController 'DC01.corp.local' -DaysToSearch 90 -OutputPath 'C:\SecurityAudits'
```

Analyzes specific DC for RBCD abuse over the last 90 days with custom export path.

### Pipeline from Get-ADDomainController

```powershell
Get-ADDomainController -Filter * | Get-RBCDAbuse -DaysToSearch 7 -Verbose
```

Scans all domain controllers for recent RBCD activity using pipeline input.

### Comprehensive Multi-DC Analysis

```powershell
Get-RBCDAbuse -CheckAllDCs -DaysToSearch 180 -OutputPath 'C:\IR\RBCD' -Verbose
```

Performs comprehensive 6-month analysis across all domain controllers.

### Automation Integration

```powershell
# Daily scheduled task for RBCD monitoring
$Results = Get-RBCDAbuse -CheckAllDCs -DaysToSearch 1 -OutputPath 'C:\SecurityMonitoring\RBCD'

# Alert on critical findings
$Critical = $Results | Where-Object { $_.Severity -eq 'CRITICAL' }

if ($Critical.Count -gt 0) {
    Send-MailMessage -To 'soc@contoso.com' `
        -Subject 'CRITICAL: RBCD Abuse Detected - Privilege Escalation' `
        -Body @"
CRITICAL SECURITY ALERT

Resource-Based Constrained Delegation abuse detected.
This indicates privilege escalation in progress.

Critical Findings: $($Critical.Count)
Computers with RBCD: $(($Critical | Where-Object DetectionPhase -eq 'Phase 1: RBCD Configuration').Count)
Recent RBCD Modifications (Event 5136): $(($Critical | Where-Object EventID -eq 5136).Count)

IMMEDIATE ACTIONS REQUIRED:
1. Review attached CSV for full details
2. Verify each RBCD configuration is legitimate
3. Remove unauthorized delegations: Set-ADComputer -Clear msDS-AllowedToActOnBehalfOfOtherIdentity
4. Set MachineAccountQuota to 0
5. Investigate user accounts that modified RBCD attributes

Attachment: Latest detection report
"@ `
        -Priority High `
        -Attachments (Get-ChildItem -Path 'C:\SecurityMonitoring\RBCD\*.csv' | Sort-Object -Property LastWriteTime -Descending | Select-Object -First 1).FullName
}

# Alert on MachineAccountQuota misconfiguration
$MAQIssue = $Results | Where-Object { $_.Setting -eq 'ms-DS-MachineAccountQuota' -and $_.CurrentValue -gt 0 }
if ($MAQIssue) {
    Write-Warning 'MachineAccountQuota allows non-admin computer creation - set to 0 immediately'
}
```

## Parameters

### DomainController

- **Type:** string
- **Default:** Auto-discovered (Get-ADDomainController -Discover -NextClosestSite)
- **Description:** Target domain controller to analyze
- **Pipeline:** Accepts 'HostName', 'Name', 'ComputerName', 'Server' from Get-ADDomainController
- **Permissions:** Domain Admin or Event Log Reader + AD Read permissions
- **Examples:** 'DC01', 'DC01.corp.local', @('DC01', 'DC02')

### DaysToSearch

- **Type:** int
- **Default:** 30 days
- **Range:** 1 to 365 days
- **Description:** Number of days to analyze event logs for RBCD indicators
- **Performance:** Longer time spans increase query duration

### OutputPath

- **Type:** string
- **Default:** `$env:USERPROFILE\Desktop\RBCDAudit`
- **Description:** Directory where CSV and JSON results are saved
- **Auto-Create:** Directory created if it doesn't exist
- **Output Files:** `RBCD_Detection_yyyyMMdd_HHmmss.csv` and `.json`

### CheckAllDCs

- **Type:** switch
- **Default:** $false (current DC only)
- **Description:** Scans all domain controllers in the forest
- **Discovery:** Uses `Get-ADDomainController -Filter *`
- **Performance:** Scanning multiple DCs takes longer but provides comprehensive event coverage

## Output

Returns `PSCustomObject` array with the following properties:

```powershell
[PSCustomObject]@{
    DetectionPhase      # Detection vector (Phase 1-5)
    Severity            # CRITICAL/HIGH/MEDIUM
    ComputerName        # Affected computer account (Phase 1, 5)
    OperatingSystem     # OS version (Phase 1)
    AllowedAccounts     # Accounts permitted to delegate (Phase 1)
    WhenChanged         # Attribute modification timestamp (Phase 1)
    EventID             # Windows Event ID (5136, 4742, 4769)
    TimeCreated         # Event timestamp (Phase 2-4)
    DomainController    # DC where event was logged
    SubjectUserName     # User who performed action (Events 5136, 4742)
    SubjectDomainName   # Domain of acting user
    ObjectDN            # Target AD object DN (Event 5136)
    AttributeName       # Modified attribute (msDS-AllowedToActOnBehalfOfOtherIdentity)
    OperationType       # Value Added/Deleted/Cleared (Event 5136)
    AttributeValue      # Security descriptor value (Event 5136)
    TargetComputerName  # Modified computer (Event 4742)
    ServiceName         # Kerberos service (Event 4769)
    TargetUserName      # Impersonated user (Event 4769)
    ClientAddress       # Source IP (Event 4769)
    TicketOptions       # 0x40810000 = S4U2Proxy (Event 4769)
    TicketEncryptionType# Encryption type (Event 4769)
    Setting             # Configuration name (Phase 5)
    CurrentValue        # MachineAccountQuota value (Phase 5)
    Creator             # Computer account creator (Phase 5)
    Recommendation      # Remediation guidance
    Timestamp           # Detection timestamp (yyyy-MM-dd HH:mm:ss)
}
```

## Severity Levels

| Severity     | Criteria                                                                                                                                                                                |
| ------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **CRITICAL** | Computer has `msDS-AllowedToActOnBehalfOfOtherIdentity` configured (Phase 1) OR Event 5136 RBCD modification detected (Phase 2) OR Event 4742 computer change related to RBCD (Phase 3) |
| **HIGH**     | S4U2Proxy delegation detected via Event 4769 (Phase 4) OR MachineAccountQuota > 0 (Phase 5)                                                                                             |
| **MEDIUM**   | Non-admin user created computer account (potential attacker-controlled account for RBCD - Phase 5)                                                                                      |

## Detection Details

### Finding Types

| Finding Type                                | Detection Source    | Risk Level | Description                                                        |
| ------------------------------------------- | ------------------- | ---------- | ------------------------------------------------------------------ |
| **Phase 1: RBCD Configuration**             | AD Attribute Query  | Critical   | Computer has `msDS-AllowedToActOnBehalfOfOtherIdentity` configured |
| **Phase 2: Event 5136 (RBCD Modification)** | Event 5136          | Critical   | Directory Service change to RBCD attribute                         |
| **Phase 3: Event 4742 (Computer Changed)**  | Event 4742          | Critical   | Computer account modified (RBCD-related)                           |
| **Phase 4: Event 4769 (S4U2Proxy)**         | Event 4769          | High       | Kerberos delegation request (Ticket Options 0x40810000)            |
| **Phase 5: MachineAccountQuota Audit**      | AD Domain Attribute | High       | MachineAccountQuota > 0 (allows non-admin computer creation)       |
| **Phase 5: Computer Account Creation**      | AD Computer Query   | Medium     | Non-admin user created computer (potential attacker account)       |

## MITRE ATT&CK Mapping

- **T1134:** Access Token Manipulation (RBCD enables impersonation-based privilege escalation)
- **T1548:** Abuse Elevation Control Mechanism
- **T1550.003:** Use Alternate Authentication Material - Pass the Ticket (S4U2Proxy tickets)

## Requirements

### Permissions

- **Domain Admin** or equivalent for cross-DC event log queries and AD enumeration
- **Event Log Reader** on target domain controllers
- **Remote Management** rights for WinRM/PSRemoting

### Event Logging

Critical events that MUST be enabled for detection:

#### Event ID 5136 (Directory Service Changes)

**MOST CRITICAL EVENT FOR RBCD DETECTION**

```powershell
# Enable Advanced Audit Policy for Directory Service Changes
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable

# Verify
auditpol /get /subcategory:"Directory Service Changes"
```

**Event Details:**

- **Log:** Security
- **Event ID:** 5136
- **Trigger:** `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute modified
- **Criticality:** HIGH - Only logged when RBCD is actively configured

#### Event ID 4742 (Computer Account Changed)

```powershell
# Enable audit policy
auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable
```

#### Event ID 4769 (Kerberos Service Ticket Operations)

```powershell
# Enable Kerberos Service Ticket Operations auditing
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
```

**Warning:** Event 4769 is EXTREMELY high volume (hundreds/thousands per minute in large environments). Consider:

- Filtering to specific DCs
- Using SIEM for long-term storage
- Limiting DaysToSearch parameter (7-30 days max)

### PowerShell Modules

- **ActiveDirectory** - For Get-ADDomainController, Get-ADComputer, Get-ADDomain

### Network Requirements

- **WinRM/PSRemoting** enabled on all domain controllers
- **Event Log Remote Access** (RPC/TCP 135, dynamic high ports)

## Remediation Guidance

### Immediate Response to RBCD Detection

**CRITICAL:** Any RBCD configuration on non-delegated servers = INVESTIGATE IMMEDIATELY.

```powershell
# Step 1: Enumerate all RBCD configurations
$RBCDComputers = Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |
    Where-Object { $_.'msDS-AllowedToActOnBehalfOfOtherIdentity' -ne $null }

foreach ($Computer in $RBCDComputers) {
    Write-Host "RBCD configured on: $($Computer.Name)" -ForegroundColor Red

    # Parse allowed accounts
    $rawSD = $Computer.'msDS-AllowedToActOnBehalfOfOtherIdentity'
    $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
    $sd.SetSecurityDescriptorBinaryForm($rawSD)

    foreach ($ace in $sd.Access) {
        $account = New-Object System.Security.Principal.SecurityIdentifier($ace.IdentityReference)
        $accountName = $account.Translate([System.Security.Principal.NTAccount]).Value
        Write-Host "  Allowed to delegate: $accountName" -ForegroundColor Yellow
    }
}

# Step 2: Remove UNAUTHORIZED RBCD configurations
# CRITICAL: Verify legitimacy before removal (may break applications)
Set-ADComputer 'SERVER01' -Clear 'msDS-AllowedToActOnBehalfOfOtherIdentity'

# Step 3: Investigate user accounts that modified RBCD (Event 5136)
# Query Event 5136 for SubjectUserName - may indicate compromised account
$Event5136 = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 5136
} -MaxEvents 100 | Where-Object { $_.Message -match 'msDS-AllowedToActOnBehalfOfOtherIdentity' }

foreach ($Event in $Event5136) {
    $EventXml = [xml]$Event.ToXml()
    $SubjectUser = $EventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' } | Select-Object -ExpandProperty '#text'
    Write-Host "RBCD modified by: $SubjectUser at $($Event.TimeCreated)" -ForegroundColor Red
}

# Step 4: Search for attacker-controlled computer accounts
# Pattern: Recently created by non-admin users, unusual naming (EVIL-PC$, ATTACKER$)
$SuspiciousComputers = Get-ADComputer -Filter { whenCreated -gt (Get-Date).AddDays(-30) } -Properties Creator, whenCreated

foreach ($Computer in $SuspiciousComputers) {
    if ($Computer.Creator) {
        # Check if created by non-Domain Admin
        $CreatorUser = Get-ADUser -Filter { DistinguishedName -eq $Computer.Creator } -ErrorAction SilentlyContinue
        if ($CreatorUser) {
            $Groups = Get-ADPrincipalGroupMembership -Identity $CreatorUser | Select-Object -ExpandProperty Name
            if ($Groups -notcontains 'Domain Admins') {
                Write-Host "Suspicious computer: $($Computer.Name) created by $($Computer.Creator)" -ForegroundColor Yellow

                # Disable suspicious computer (preserve for forensics)
                # Disable-ADAccount -Identity $Computer.Name
            }
        }
    }
}

# Step 5: Set MachineAccountQuota to 0 (CRITICAL HARDENING)
$Domain = Get-ADDomain
Set-ADDomain -Identity $Domain -Replace @{'ms-DS-MachineAccountQuota' = 0}
Write-Host "MachineAccountQuota set to 0 - non-admin computer creation disabled" -ForegroundColor Green

# Step 6: Audit GenericWrite/WriteProperty permissions on computer accounts
# Identify users/groups with write access (RBCD attack prerequisite)
$Computers = Get-ADComputer -Filter * -Properties nTSecurityDescriptor
foreach ($Computer in $Computers) {
    $ACL = $Computer.nTSecurityDescriptor.Access
    $WriteACEs = $ACL | Where-Object {
        $_.ActiveDirectoryRights -match 'GenericWrite|WriteProperty|WriteDacl|GenericAll' -and
        $_.IdentityReference -notmatch 'SYSTEM|Domain Admins|Enterprise Admins'
    }

    if ($WriteACEs) {
        Write-Host "Write permissions on $($Computer.Name):" -ForegroundColor Yellow
        $WriteACEs | ForEach-Object {
            Write-Host "  $($_.IdentityReference) - $($_.ActiveDirectoryRights)" -ForegroundColor Red
        }
    }
}
```

### Deploy Event 5136 Monitoring to All DCs

```powershell
# Enable Directory Service Changes auditing on all DCs
$DCs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName

foreach ($DC in $DCs) {
    Write-Host "Enabling Event 5136 auditing on $DC..." -ForegroundColor Cyan

    Invoke-Command -ComputerName $DC -ScriptBlock {
        # Enable Directory Service Changes
        auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable

        # Enable Computer Account Management
        auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable

        # Verify
        auditpol /get /subcategory:"Directory Service Changes"
    }

    Write-Host "Auditing enabled on $DC" -ForegroundColor Green
}
```

### Implement Continuous Monitoring

```powershell
# Scheduled task: Run daily on monitoring server
$Results = Get-RBCDAbuse -CheckAllDCs -DaysToSearch 2 -OutputPath 'C:\SecurityMonitoring\RBCD'

# Alert on ANY RBCD configurations (should be whitelisted)
$RBCDConfigs = $Results | Where-Object { $_.DetectionPhase -eq 'Phase 1: RBCD Configuration' }

if ($RBCDConfigs.Count -gt 0) {
    # Check against whitelist
    $WhitelistedComputers = @('IIS-SERVER01', 'SQL-SERVER02')  # Known legitimate delegations

    $UnauthorizedRBCD = $RBCDConfigs | Where-Object { $_.ComputerName -notin $WhitelistedComputers }

    if ($UnauthorizedRBCD.Count -gt 0) {
        Send-MailMessage -To 'soc@contoso.com' `
            -Subject 'CRITICAL: Unauthorized RBCD Detected - Privilege Escalation' `
            -Body @"
CRITICAL SECURITY ALERT

Unauthorized Resource-Based Constrained Delegation detected.
This indicates privilege escalation attack in progress.

Unauthorized RBCD Configurations: $($UnauthorizedRBCD.Count)

Affected Computers:
$($UnauthorizedRBCD | Format-Table ComputerName, AllowedAccounts, WhenChanged | Out-String)

IMMEDIATE ACTIONS:
1. Remove RBCD: Set-ADComputer '<computer>' -Clear msDS-AllowedToActOnBehalfOfOtherIdentity
2. Investigate allowed delegation accounts (may be attacker-controlled)
3. Review Event 5136 for modification user
4. Check for suspicious computer accounts created recently

"@ `
            -Priority High
    }
}

# Alert on Event 5136 modifications
$Event5136 = $Results | Where-Object { $_.EventID -eq 5136 }
if ($Event5136.Count -gt 0) {
    Write-Warning "Event 5136 detected: RBCD attribute modified by $($Event5136[0].SubjectUserName)"
}

# Alert on MachineAccountQuota misconfiguration
$MAQ = $Results | Where-Object { $_.Setting -eq 'ms-DS-MachineAccountQuota' -and $_.CurrentValue -gt 0 }
if ($MAQ) {
    Write-Warning "MachineAccountQuota is $($MAQ.CurrentValue) - set to 0 to prevent attacker computer creation"
}
```

## Example Workflows

### Incident Response Investigation

```powershell
# Extended forensic analysis after suspected RBCD attack
$Results = Get-RBCDAbuse -CheckAllDCs -DaysToSearch 180 -OutputPath 'C:\IR\RBCD' -Verbose

# Timeline analysis
$Timeline = $Results | Sort-Object -Property TimeCreated, Timestamp

Write-Host "=== RBCD Attack Timeline ===" -ForegroundColor Cyan
foreach ($Event in $Timeline) {
    $Timestamp = if ($Event.TimeCreated) { $Event.TimeCreated } else { $Event.Timestamp }
    Write-Host "$Timestamp - $($Event.DetectionPhase) - Severity: $($Event.Severity)" -ForegroundColor Yellow

    if ($Event.SubjectUserName) {
        Write-Host "  Actor: $($Event.SubjectUserName)" -ForegroundColor Red
    }
    if ($Event.ComputerName) {
        Write-Host "  Target: $($Event.ComputerName)" -ForegroundColor Magenta
    }
}

# Identify pivot points (compromised accounts)
$CompromisedAccounts = $Results | Where-Object { $_.SubjectUserName } |
    Group-Object -Property SubjectUserName |
    Sort-Object -Property Count -Descending

Write-Host "`n=== Potential Compromised Accounts ===" -ForegroundColor Cyan
$CompromisedAccounts | Format-Table Name, Count

# Correlate with S4U2Proxy delegation (exploitation)
$S4U2Proxy = $Results | Where-Object { $_.DetectionPhase -eq 'Phase 4: Event 4769 (S4U2Proxy)' }
if ($S4U2Proxy.Count -gt 0) {
    Write-Host "`n=== S4U2Proxy Delegation (Active Exploitation) ===" -ForegroundColor Red
    $S4U2Proxy | Format-Table TimeCreated, ServiceName, TargetUserName, ClientAddress
}
```

### Weekly Security Posture Assessment

```powershell
# Weekly RBCD security assessment
$Results = Get-RBCDAbuse -CheckAllDCs -DaysToSearch 7 -OutputPath 'C:\WeeklyReports'

# Generate scorecard
$TotalComputers = (Get-ADComputer -Filter *).Count
$RBCDComputers = ($Results | Where-Object DetectionPhase -eq 'Phase 1: RBCD Configuration').Count
$RBCDPercentage = [math]::Round(($RBCDComputers / $TotalComputers) * 100, 2)

Write-Host "`n=== RBCD Security Posture ===" -ForegroundColor Cyan
Write-Host "Total Computers: $TotalComputers"
Write-Host "Computers with RBCD: $RBCDComputers ($RBCDPercentage%)" -ForegroundColor $(if ($RBCDComputers -gt 0) { 'Yellow' } else { 'Green' })

$MAQ = (Get-ADDomain).'ms-DS-MachineAccountQuota'
Write-Host "MachineAccountQuota: $MAQ" -ForegroundColor $(if ($MAQ -gt 0) { 'Red' } else { 'Green' })

if ($MAQ -gt 0) {
    Write-Warning "Set MachineAccountQuota to 0 to prevent RBCD attack vector"
}

# Check Event 5136 logging
$AuditCheck = Invoke-Command -ComputerName (Get-ADDomainController -Discover).HostName -ScriptBlock {
    auditpol /get /subcategory:"Directory Service Changes"
}
Write-Host "`nEvent 5136 Auditing: $($AuditCheck -match 'Success')" -ForegroundColor $(if ($AuditCheck -match 'Success') { 'Green' } else { 'Red' })
```

## Performance Considerations

- **Event 4769 queries:** VERY high volume (10,000+ events/day in large environments) - limit DaysToSearch or exclude Phase 4
- **Multi-DC scanning:** 10 DCs with 30-day window typically completes in 20-40 minutes
- **Event 5136 is low volume:** Typically < 100 events/day (RBCD modifications are rare)
- **Network bandwidth:** Event log queries < 5MB per DC typically

**Performance Optimization:**

```powershell
# Skip Event 4769 (Phase 4) for faster scans
# Modify script to bypass Phase 4 if not needed (reduces execution time by 80%)

# Limit Event 4769 MaxEvents (default 10,000)
-MaxEvents 1000  # Reduces query time significantly
```

## False Positives

Common scenarios that may appear as findings:

- **Legitimate application delegation:** IIS application pools, SQL Server service accounts
  - **Mitigation:** Maintain whitelist of authorized RBCD configurations, document business justification
- **Test/Dev environment RBCD:** Developers testing delegation scenarios
  - **Mitigation:** Separate monitoring policies for test environments, require change tickets
- **S4U2Proxy from service accounts:** Scheduled tasks, web applications using Kerberos delegation
  - **Mitigation:** Baseline normal S4U2Proxy patterns, alert on deviations

**Best Practice:** Maintain RBCD whitelist with business justification. ANY unauthorized RBCD = investigate immediately.

## Related Functions

- [Get-UnconstrainedDelegation](Get-UnconstrainedDelegation.md) - Detects unconstrained delegation misconfigurations
- [Get-ADKerberoastingPattern](Get-ADKerberoastingPattern.md) - Detects Kerberoasting attacks
- [Get-MachineAccountQuota](Get-MachineAccountQuota.md) - Audits MachineAccountQuota settings
- [Get-GoldenTicketDetection](Get-GoldenTicketDetection.md) - Detects forged TGTs (post-privilege escalation)

## Additional Resources

- [MITRE ATT&CK T1134](https://attack.mitre.org/techniques/T1134/)
- [Elad Shamir - RBCD Whitepaper](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [Microsoft - Kerberos Delegation](https://docs.microsoft.com/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Event 5136 Documentation](https://docs.microsoft.com/windows/security/threat-protection/auditing/event-5136)
- [Event 4769 Analysis](https://docs.microsoft.com/windows/security/threat-protection/auditing/event-4769)
- [GitHub Repository](https://github.com/vreguibar/EguibarIT.SecurityPS)

---

**Module:** EguibarIT.SecurityPS
**Component:** Security Auditing
**Role:** Threat Detection
**Functionality:** Resource-Based Constrained Delegation (RBCD) Abuse Detection
