# Get-DomainTrustBypass

## Overview

**Function Name:** Get-DomainTrustBypass
**Module:** EguibarIT.SecurityPS
**Version:** 1.0.0
**Author:** Vicente Rodriguez Eguibar (vicente@eguibar.com)
**MITRE ATT&CK:** T1484.002 (Domain Trust Modification), T1482 (Domain Trust Discovery), T1550.003 (Pass the Ticket)
**Attack Type:** Domain Trust Bypass Exploitation
**Detection Type:** Trust Enumeration, SID Filtering Bypass, Selective Authentication Violation, Cross-Forest TGT Monitoring

## Purpose

Detects Active Directory domain trust bypass attacks through comprehensive trust configuration auditing and cross-forest authentication monitoring.

**Attack #15 from Five Eyes Joint Advisory** - Domain Trust Bypass

## Critical Principle

> **"External trusts (forest trusts) MUST have SID filtering enabled and selective authentication enforced. Privileged accounts should NEVER authenticate across external trust boundaries."**

Domain and forest trusts enable resource sharing but create attack paths for lateral movement and privilege escalation. Attackers exploit trust relationships to:

- **SID Filtering Bypass:** Inject privileged SIDs (e.g., Enterprise Admins) into cross-forest tickets
- **Selective Authentication Violations:** Access restricted resources without proper authorization
- **Trust Enumeration:** Map trust topology to identify attack paths between forests
- **Cross-Forest TGT Requests:** Request Kerberos tickets for privilege escalation
- **Privileged Account Abuse:** Use administrative credentials across trust boundaries

## Key Features

This function performs **five-phase detection**:

### Phase 1: Trust Relationship Inventory

- Enumerates all domain and forest trusts
- Identifies trust type, direction, and attributes
- Detects trusts without SID filtering (`TRUST_ATTRIBUTE_QUARANTINED_DOMAIN`)
- Detects trusts without selective authentication (`TRUST_ATTRIBUTE_CROSS_ORGANIZATION`)
- Classifies external trusts (highest risk)
- Assesses trust risk level based on configuration

### Phase 2: SID Filtering Bypass Detection

- Monitors Event 4675 (SID filtering failed - bypass attempt)
- Monitors Event 4766 (SID filtering blocked unauthorized SID)
- Correlates SID injection attempts with trust relationships
- Identifies accounts attempting SIDHistory abuse
- Detects privileged SID injection (Domain Admins, Enterprise Admins)

### Phase 3: Selective Authentication Violations

- Analyzes Event 4768 (Kerberos TGT requests from external domains)
- Detects cross-trust authentication to sensitive resources
- Identifies unauthorized cross-forest access attempts
- Correlates selective authentication bypass with account patterns

### Phase 4: Cross-Forest TGT Monitoring (Optional)

- Monitors Event 4770 (Kerberos TGT renewed)
- Detects cross-forest TGT renewals (persistence indicator)
- Analyzes TGT request patterns for anomalies
- Identifies long-running cross-trust sessions

### Phase 5: Privileged Cross-Trust Authentication

- Detects administrative account authentication across trusts
- Identifies Tier 0 account trust boundary violations
- Correlates privileged accounts with cross-forest activity
- Generates critical alerts for privileged trust abuse

## Usage

### Example 1: Basic Trust Audit

```powershell
Get-DomainTrustBypass
```

Performs 30-day trust bypass detection audit on current domain.

**Detection Coverage:**

- Trust configuration inventory
- SID filtering bypass attempts
- Selective authentication violations
- Privileged cross-trust authentications

### Example 2: Comprehensive 90-Day Audit

```powershell
Get-DomainTrustBypass -DaysBack 90 -IncludeTrustEnumeration -Verbose
```

Performs comprehensive 90-day audit with:

- Full trust topology analysis
- Extended event log window
- Verbose progress output
- Trust attribute detailed analysis

**Use Case:** Quarterly security review, compliance audits, trust relationship documentation

### Example 3: Enhanced Cross-Forest Monitoring

```powershell
Get-DomainTrustBypass -ExportPath 'C:\SecurityAudits' -MonitorCrossForestAuth
```

Enables enhanced cross-forest authentication monitoring:

- Event 4770 (TGT renewals) analysis
- Cross-forest TGT persistence detection
- Comprehensive CSV/JSON export

**Use Case:** Merger/acquisition integration monitoring, external partner trust auditing

### Example 4: Forest-Wide Audit

```powershell
Get-DomainTrustBypass -CheckAllDomains -DaysBack 7
```

Scans all domains in the forest:

- Child domain trust validation
- Forest-wide SID filtering audit
- Multi-domain selective authentication review

**Use Case:** Enterprise-wide security assessments, multi-domain environments

### Example 5: Automated Incident Response

```powershell
$Result = Get-DomainTrustBypass -DaysBack 30

if ($Result.SIDFilteringViolations -gt 0) {
    Write-Warning "CRITICAL: $($Result.SIDFilteringViolations) SID filtering bypass attempts detected!"
    $Result.ViolationEvents | Export-Csv -Path 'C:\INCIDENT\SIDFilteringBypass.csv' -NoTypeInformation
}

if ($Result.PrivilegedCrossTrustAuth -gt 0) {
    Write-Warning "SECURITY ALERT: Privileged accounts crossed trust boundaries!"
    # Trigger incident response workflow
    Send-MailMessage -To 'security@contoso.com' -Subject 'Trust Bypass Detected' -Body "Privileged cross-trust auth: $($Result.PrivilegedCrossTrustAuth)"
}
```

Automated security monitoring workflow with alerting.

### Example 6: Trust Configuration Report

```powershell
$Audit = Get-DomainTrustBypass -IncludeTrustEnumeration

# Display trust configuration summary
$Audit.TrustRelationships | Where-Object { $_.IsExternalTrust -eq $true } | Format-Table -AutoSize

# Export high-risk trusts
$Audit.TrustRelationships | Where-Object { $_.RiskLevel -eq 'High' } | Export-Csv -Path 'HighRiskTrusts.csv' -NoTypeInformation
```

Trust security posture assessment and reporting.

## Parameters

### `-DomainController`

**Type:** String[]
**Mandatory:** No
**Pipeline:** Yes (ValueFromPipeline, ValueFromPipelineByPropertyName)
**Default:** All DCs in current domain
**Aliases:** ComputerName, HostName, DC

Specific domain controller(s) to audit. If not specified, queries all DCs in current domain.

**Example:**

```powershell
Get-DomainTrustBypass -DomainController 'DC01.contoso.com','DC02.contoso.com'
```

### `-DaysBack`

**Type:** Int
**Mandatory:** No
**Range:** 1 to 365
**Default:** 30

Number of days to analyze Event Logs for trust abuse indicators.

**Example:**

```powershell
Get-DomainTrustBypass -DaysBack 90  # 90-day audit window
```

### `-ExportPath`

**Type:** String
**Mandatory:** No
**Default:** C:\SecurityAudits\DomainTrust

Directory where detection results will be saved (CSV and JSON formats).

**Exports Include:**

- `DomainTrust_Inventory_{timestamp}.csv` - Trust relationship inventory
- `DomainTrust_Violations_{timestamp}.csv` - SID filtering and selective auth violations
- `DomainTrust_AuditSummary_{timestamp}.json` - Comprehensive audit summary

**Example:**

```powershell
Get-DomainTrustBypass -ExportPath 'C:\SecurityReports\Monthly'
```

### `-IncludeTrustEnumeration`

**Type:** Switch
**Mandatory:** No
**Default:** $false

Includes detailed trust relationship enumeration and configuration analysis. Provides full trust topology map for security review.

**Example:**

```powershell
Get-DomainTrustBypass -IncludeTrustEnumeration
```

### `-MonitorCrossForestAuth`

**Type:** Switch
**Mandatory:** No
**Default:** $false

Enables enhanced monitoring of cross-forest authentication events. Analyzes Event 4768/4769/4770 for suspicious TGT/TGS requests.

**Example:**

```powershell
Get-DomainTrustBypass -MonitorCrossForestAuth
```

### `-CheckAllDomains`

**Type:** Switch
**Mandatory:** No
**Default:** $false

Scans all domains in the forest for trust abuse indicators. Default behavior scans current domain only.

**Example:**

```powershell
Get-DomainTrustBypass -CheckAllDomains -DaysBack 14
```

## Output

Returns `PSCustomObject` with the following properties:

| Property                           | Type     | Description                                               |
| ---------------------------------- | -------- | --------------------------------------------------------- |
| **DomainName**                     | String   | DNS name of the audited domain                            |
| **ForestName**                     | String   | Forest name                                               |
| **AuditTimestamp**                 | DateTime | When the audit was performed                              |
| **TrustCount**                     | Int      | Total number of trust relationships                       |
| **ExternalTrustCount**             | Int      | External forest trusts (highest risk)                     |
| **TrustsWithSIDFilteringDisabled** | Int      | Trusts missing SID filtering (critical risk)              |
| **TrustsWithoutSelectiveAuth**     | Int      | Trusts without selective authentication                   |
| **SIDFilteringViolations**         | Int      | Count of detected SID filtering bypass attempts           |
| **SelectiveAuthViolations**        | Int      | Unauthorized cross-trust authentications                  |
| **CrossForestTGTRequests**         | Int      | Cross-forest Kerberos ticket requests                     |
| **PrivilegedCrossTrustAuth**       | Int      | Privileged accounts authenticating across trusts          |
| **HighRiskIndicators**             | Int      | Count of critical findings                                |
| **MediumRiskIndicators**           | Int      | Count of moderate findings                                |
| **RiskLevel**                      | String   | Overall risk assessment (Secure/Low/Medium/High/Critical) |
| **IsSecure**                       | Boolean  | Indicates if trust configuration is secure                |
| **RecommendedActions**             | Array    | Remediation steps                                         |
| **ExportedReports**                | Array    | File paths if reports were exported                       |
| **TrustRelationships**             | Array    | Detailed trust inventory                                  |
| **ViolationEvents**                | Array    | Trust abuse event details                                 |

### Trust Relationship Object Properties

Each trust in `TrustRelationships` array contains:

```powershell
@{
    TrustName            = 'fabrikam.com'
    TrustPartner         = 'fabrikam.com'
    Direction            = 'Bidirectional'
    TrustType            = 'Uplevel (Active Directory)'
    IsExternalTrust      = $true
    ForestTransitive     = $false
    SIDFilteringEnabled  = $false  # CRITICAL RISK
    SelectiveAuthEnabled = $false  # HIGH RISK
    TrustAttributes      = 8
    WhenCreated          = '2024-01-15 10:30:00'
    WhenChanged          = '2024-01-15 10:30:00'
    RiskFactors          = 'External trust without SID filtering; External trust without selective authentication'
    RiskLevel            = 'High'
    DetectionDate        = '2025-03-06 14:22:15'
}
```

### Violation Event Object Properties

Each violation in `ViolationEvents` array contains:

```powershell
@{
    DC                = 'DC01.contoso.com'
    TimeCreated       = '2025-03-05 18:45:32'
    EventID           = 4675
    TargetUserName    = 'attacker_user'
    TargetDomain      = 'FABRIKAM'
    TargetSID         = 'S-1-5-21-...'
    SourceSID         = 'S-1-5-21-...-512'  # Injected Domain Admins SID
    ViolationType     = 'SID Filtering Bypass'
    RiskLevel         = 'Critical'
    Description       = 'Attempt to authenticate with unauthorized SID in SIDHistory'
    DetectionDate     = '2025-03-06 14:22:15'
}
```

## MITRE ATT&CK Mapping

### T1484.002 - Domain Policy Modification: Domain Trust Modification

**Tactic:** Defense Evasion, Privilege Escalation
**Detection Focus:**

- Trust creation/modification (Event 4706)
- Trust attribute changes
- SID filtering disabled on trusts
- Selective authentication removed

**Indicators:**

- Recent trust modifications without business justification
- SID filtering disabled on external trusts
- Trust attribute changes (Event 4707)

### T1482 - Domain Trust Discovery

**Tactic:** Discovery
**Detection Focus:**

- Trust relationship enumeration
- LDAP queries for trust objects
- PowerShell commands: `Get-ADTrust`, `nltest /domain_trusts`

**Indicators:**

- Multiple trust enumeration events from single account
- Non-administrator accounts querying trust relationships
- Automated trust discovery tools

### T1550.003 - Use Alternate Authentication Material: Pass the Ticket

**Tactic:** Defense Evasion, Lateral Movement
**Detection Focus:**

- Cross-forest TGT requests (Event 4768)
- Cross-forest service ticket requests (Event 4769)
- TGT renewals across trust boundaries (Event 4770)

**Indicators:**

- TGT requests from unusual source IPs
- Cross-forest authentication from non-standard accounts
- TGT renewals indicating persistence

## Attack Scenarios

### Scenario 1: SID Filtering Bypass for Privilege Escalation

**Attack Steps:**

1. Attacker compromises account in TrustedDomain
2. Uses Mimikatz to inject Enterprise Admins SID into SIDHistory: `sid::patch`
3. Requests cross-forest TGT with forged SIDHistory
4. SID filtering fails (trust misconfigured)
5. Attacker gains Enterprise Admin privileges in TrustingDomain

**Detection Indicators:**

```powershell
$Result = Get-DomainTrustBypass -DaysBack 7

# Check for SID filtering violations
if ($Result.SIDFilteringViolations -gt 0) {
    Write-Warning "SID filtering bypass detected!"
    $Result.ViolationEvents | Where-Object { $_.EventID -eq 4675 } | Format-Table -AutoSize
}
```

**Remediation:**

```powershell
# Enable SID filtering on external trust
netdom trust contoso.com /domain:fabrikam.com /quarantine:yes

# Verify SID filtering enabled
Get-ADTrust -Filter * | Where-Object { ($_.TrustAttributes -band 4) -ne 4 } | Format-Table Name, TrustAttributes
```

### Scenario 2: Selective Authentication Bypass

**Attack Steps:**

1. External trust configured without selective authentication
2. Attacker compromises account in TrustedDomain
3. Requests TGT for resource in TrustingDomain (Event 4768)
4. Accesses sensitive resource without explicit authorization
5. Moves laterally within TrustingDomain

**Detection Indicators:**

```powershell
$Result = Get-DomainTrustBypass -DaysBack 14 -MonitorCrossForestAuth

# Check for unauthorized cross-trust access
if ($Result.SelectiveAuthViolations -gt 0) {
    Write-Warning "Selective authentication violations detected!"
    $Result.ViolationEvents | Where-Object { $_.ViolationType -eq 'Cross-Trust TGT Request' } | Format-Table
}
```

**Remediation:**

```powershell
# Enable selective authentication on external trust
# 1. Open Active Directory Domains and Trusts
# 2. Right-click trust -> Properties -> Authentication tab
# 3. Select "Selective authentication"

# Grant "Allowed to Authenticate" permission only to specific resources
$TrustedAccount = Get-ADUser -Identity "fabrikam_user" -Server fabrikam.com
$TargetServer = "CN=FileServer01,OU=Servers,DC=contoso,DC=com"
dsacls $TargetServer /G "$($TrustedAccount.SID):CA;Allowed-To-Authenticate"
```

### Scenario 3: Privileged Account Cross-Trust Abuse

**Attack Steps:**

1. Attacker compromises Domain Admin account in ChildDomain
2. Uses Pass-the-Ticket to authenticate to Parent Domain
3. Requests TGT for Parent Domain resources (Event 4768)
4. Escalates to Enterprise Admin privileges
5. Pivots to other child domains

**Detection Indicators:**

```powershell
$Result = Get-DomainTrustBypass -CheckAllDomains -DaysBack 30

# Check for privileged cross-trust auth
if ($Result.PrivilegedCrossTrustAuth -gt 0) {
    Write-Warning "CRITICAL: Privileged accounts crossed trust boundaries!"
    $Result.ViolationEvents | Where-Object { $_.RiskLevel -eq 'Critical' } | Format-Table
}
```

**Remediation:**

```powershell
# Implement Protected Users group for Tier 0 accounts
Add-ADGroupMember -Identity "Protected Users" -Members "Domain Admins"

# Block privileged accounts from cross-trust auth via GPO
# Computer Configuration -> Policies -> Security Settings -> Local Policies -> User Rights Assignment
# Deny access to this computer from the network: FABRIKAM\*

# Create authentication policy silo for Tier 0 accounts
New-ADAuthenticationPolicySilo -Name "Tier0Silo" -UserAuthenticationPolicy "Tier0UserPolicy" -ComputerAuthenticationPolicy "Tier0ComputerPolicy" -Enforce
```

### Scenario 4: Trust Enumeration for Lateral Movement Planning

**Attack Steps:**

1. Attacker compromises low-privileged account
2. Enumerates trust relationships: `Get-ADTrust -Filter *`, `nltest /domain_trusts`
3. Maps forest topology to identify attack paths
4. Targets trusts without SID filtering or selective authentication
5. Plans lateral movement through trust chain

**Detection Indicators:**

```powershell
$Result = Get-DomainTrustBypass -IncludeTrustEnumeration

# Identify high-risk trusts
$HighRiskTrusts = $Result.TrustRelationships | Where-Object { $_.RiskLevel -in @('High', 'Critical') }

if ($HighRiskTrusts.Count -gt 0) {
    Write-Warning "High-risk trust configurations detected:"
    $HighRiskTrusts | Format-Table TrustName, RiskFactors, SIDFilteringEnabled, SelectiveAuthEnabled
}
```

**Remediation:**

```powershell
# Remove unnecessary trusts
Remove-ADTrust -Identity "fabrikam.com" -Confirm:$false

# Document trust business justification
# Quarterly trust review process
# Implement least-privilege trust configuration
```

## Requirements

### Module Dependencies

- **ActiveDirectory** PowerShell module (RSAT-AD-PowerShell)
- **EguibarIT.SecurityPS** (this module)

### Permissions Required

- **Domain Admin** or equivalent for trust enumeration
- **Event Log Reader** permissions on all domain controllers
- **WinRM** access to domain controllers for event log queries

### Audit Policy Requirements

Enable the following advanced audit policies on all domain controllers:

```powershell
# Enable Policy Change auditing
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable

# Enable Account Logon auditing
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable

# Enable Logon/Logoff auditing
auditpol /set /subcategory:"Logon" /success:enable /failure:enable

# Verify audit policy
auditpol /get /category:*
```

### Event Log Retention

Ensure adequate event log retention for comprehensive detection:

```powershell
# Increase Security log size to 2GB
wevtutil sl Security /ms:2147483648

# Enable auto-backup when full
wevtutil sl Security /ab:true
```

## Remediation

### Immediate Actions (Incident Response)

#### 1. Isolate Affected Trusts

If SID filtering bypass or privileged cross-trust authentication is detected:

```powershell
# Temporarily disable trust (emergency only)
Disable-ADTrust -Identity "fabrikam.com" -Confirm:$false

# Or enable SID filtering immediately
netdom trust contoso.com /domain:fabrikam.com /quarantine:yes
```

#### 2. Reset Compromised Account Credentials

```powershell
# Reset accounts involved in trust violations
$CompromisedAccounts = $Result.ViolationEvents | Select-Object -ExpandProperty TargetUserName -Unique

foreach ($Account in $CompromisedAccounts) {
    Set-ADAccountPassword -Identity $Account -Reset -NewPassword (ConvertTo-SecureString -String (New-Guid).Guid -AsPlainText -Force)
    Set-ADUser -Identity $Account -ChangePasswordAtLogon $true
    Write-Warning "Reset password for: $Account"
}
```

#### 3. Revoke Active Sessions

```powershell
# Identify and terminate compromised sessions
$CompromisedSessions = Get-PSSession | Where-Object { $_.ComputerName -in $Result.ViolationEvents.DC }
$CompromisedSessions | Remove-PSSession

# Force Kerberos TGT purge on affected systems
Invoke-Command -ComputerName $Result.ViolationEvents.DC -ScriptBlock { klist purge }
```

### Preventive Controls

#### 1. Enable SID Filtering on All External Trusts

```powershell
# Get all external trusts
$ExternalTrusts = Get-ADTrust -Filter * | Where-Object { $_.ForestTransitive -eq $false }

# Enable SID filtering (quarantine)
foreach ($Trust in $ExternalTrusts) {
    netdom trust $env:USERDNSDOMAIN /domain:$($Trust.Name) /quarantine:yes
    Write-Verbose "Enabled SID filtering for: $($Trust.Name)"
}

# Verify SID filtering
Get-ADTrust -Filter * | Select-Object Name, @{N='SIDFilteringEnabled'; E={($_.TrustAttributes -band 4) -eq 4}} | Format-Table
```

#### 2. Enable Selective Authentication

Configure via Active Directory Domains and Trusts:

1. Open **Active Directory Domains and Trusts**
2. Right-click forest root domain → **Properties** → **Trusts** tab
3. Select external trust → **Properties**
4. **Authentication** tab → Select **"Selective authentication"**
5. Click **OK**

Grant "Allowed to Authenticate" permission only to specific resources:

```powershell
# Grant selective auth permission
$TrustedAccount = "FABRIKAM\TrustedUser"
$TargetResource = "CN=FileServer01,OU=Servers,DC=contoso,DC=com"
dsacls $TargetResource /G "$TrustedAccount:CA;Allowed-To-Authenticate"
```

#### 3. Implement PAW Restrictions for Tier 0 Accounts

```powershell
# Add Tier 0 accounts to Protected Users group
$Tier0Accounts = Get-ADGroupMember -Identity "Domain Admins"
foreach ($Account in $Tier0Accounts) {
    Add-ADGroupMember -Identity "Protected Users" -Members $Account
}

# Create GPO to restrict Tier 0 logon locations
New-GPO -Name "Tier 0 - Logon Restrictions" | New-GPLink -Target "OU=Tier0,OU=Admin,DC=contoso,DC=com"

# Configure via Group Policy:
# Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
# Deny access to this computer from the network: Add external domain accounts
```

#### 4. Enable Advanced Auditing for Trust Activity

```powershell
# Deploy advanced audit policy via GPO
$AuditGPO = New-GPO -Name "Trust Activity Auditing"
New-GPLink -Name "Trust Activity Auditing" -Target "OU=Domain Controllers,DC=contoso,DC=com"

# Configure via Group Policy:
# Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration
# - Policy Change: Audit Policy Change (Success, Failure)
# - Account Logon: Kerberos Authentication Service (Success, Failure)
# - Logon/Logoff: Logon (Success, Failure)
# - Account Management: User Account Management (Success, Failure)
```

### Long-Term Strategy

#### 1. Quarterly Trust Review Process

```powershell
# Scheduled task for quarterly trust audit
$Trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 2am
$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -Command `"Get-DomainTrustBypass -DaysBack 90 -IncludeTrustEnumeration | Export-Clixml -Path C:\TrustAudits\Quarterly_$(Get-Date -Format 'yyyyMMdd').xml`""
Register-ScheduledTask -TaskName "Quarterly Trust Audit" -Trigger $Trigger -Action $Action -User "NT AUTHORITY\SYSTEM"
```

#### 2. Implement ESAE (Red Forest) for Tier 0 Isolation

Dedicate administrative forest for Tier 0 management:

- Separate administrative accounts from production forest
- One-way trusts from production to administrative forest
- Privileged accounts exist only in administrative forest
- Reference: [Microsoft ESAE Architecture](https://learn.microsoft.com/en-us/security/privileged-access-workstations/esae-retirement)

#### 3. Trust Documentation and Business Justification

Maintain trust inventory documentation:

```powershell
# Export trust documentation
$TrustDocs = Get-DomainTrustBypass -IncludeTrustEnumeration
$TrustDocs.TrustRelationships | Select-Object TrustName, TrustPartner, Direction, WhenCreated, RiskLevel |
    Export-Csv -Path "C:\Documentation\TrustInventory_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation
```

Document for each trust:

- Business justification
- Security controls (SID filtering, selective auth)
- Approval authority
- Annual renewal requirement
- Contact information for partner domain

#### 4. Remove Unnecessary Trusts

```powershell
# Identify and remove unused trusts
$TrustAudit = Get-DomainTrustBypass -MonitorCrossForestAuth -DaysBack 90

# Trusts with zero cross-forest activity (potential candidates for removal)
$UnusedTrusts = $TrustAudit.TrustRelationships | Where-Object {
    $TrustName = $_.TrustName
    $CrossForestAuth = $TrustAudit.ViolationEvents | Where-Object { $_.TargetDomain -like "*$TrustName*" }
    $CrossForestAuth.Count -eq 0
}

# Review and remove after business validation
foreach ($Trust in $UnusedTrusts) {
    Write-Warning "Trust with zero activity: $($Trust.TrustName) - Review for removal"
    # Remove-ADTrust -Identity $Trust.TrustName -Confirm:$true  # Uncomment after validation
}
```

## Workflow Integration

### Integration with Microsoft Sentinel

```powershell
# Send trust violations to Azure Sentinel
$WorkspaceId = "your-workspace-id"
$SharedKey = "your-shared-key"

$Result = Get-DomainTrustBypass -DaysBack 7

if ($Result.RiskLevel -in @('High', 'Critical')) {
    $LogType = "DomainTrustBypass"
    $TimeStampField = "AuditTimestamp"

    $JsonPayload = $Result | ConvertTo-Json -Depth 5

    # Send-OMSAPIIngestionData function (Azure Sentinel HTTP Data Collector API)
    Send-OMSAPIIngestionData -WorkspaceId $WorkspaceId -SharedKey $SharedKey -Body $JsonPayload -LogType $LogType -TimeStampField $TimeStampField
}
```

### Integration with Splunk

```powershell
# Send trust violations to Splunk HEC
$SplunkServer = "https://splunk.contoso.com:8088"
$SplunkToken = "your-hec-token"

$Result = Get-DomainTrustBypass -DaysBack 14

if ($Result.ViolationEvents.Count -gt 0) {
    foreach ($Event in $Result.ViolationEvents) {
        $SplunkEvent = @{
            time = (Get-Date $Event.TimeCreated -UFormat %s)
            host = $Event.DC
            sourcetype = "windows:security"
            event = $Event
        } | ConvertTo-Json -Depth 5

        Invoke-RestMethod -Uri "$SplunkServer/services/collector" -Method Post -Headers @{Authorization="Splunk $SplunkToken"} -Body $SplunkEvent
    }
}
```

### Integration with ServiceNow

```powershell
# Create ServiceNow incident for critical trust violations
$SNowInstance = "your-instance.service-now.com"
$SNowUser = "api_user"
$SNowPass = ConvertTo-SecureString "api_password" -AsPlainText -Force
$SNowCred = New-Object PSCredential($SNowUser, $SNowPass)

$Result = Get-DomainTrustBypass -DaysBack 7

if ($Result.PrivilegedCrossTrustAuth -gt 0) {
    $IncidentBody = @{
        short_description = "CRITICAL: Privileged Account Trust Boundary Violation"
        description = "Detected $($Result.PrivilegedCrossTrustAuth) privileged accounts authenticating across trust boundaries. Risk Level: $($Result.RiskLevel)"
        urgency = "1"
        impact = "1"
        category = "Security"
        subcategory = "Active Directory"
        assignment_group = "Tier 0 Security Team"
    } | ConvertTo-Json

    Invoke-RestMethod -Uri "https://$SNowInstance/api/now/table/incident" -Method Post -Credential $SNowCred -ContentType "application/json" -Body $IncidentBody
}
```

## Performance Considerations

### Large Domain Environments (>10,000 objects)

- **Event Log Queries:** Limit `MaxEvents` parameter to reduce DC load
- **DaysBack Range:** Use shorter windows (7-14 days) for frequent scans
- **Domain Controller Selection:** Target specific DCs with `-DomainController` parameter
- **Scheduled Execution:** Run during maintenance windows to avoid peak hours

### Optimized Scan for Large Environments

```powershell
# Phase 1: Quick daily scan (7 days, current domain only)
Get-DomainTrustBypass -DaysBack 7

# Phase 2: Weekly comprehensive scan (30 days, trust enumeration)
Get-DomainTrustBypass -DaysBack 30 -IncludeTrustEnumeration -MonitorCrossForestAuth

# Phase 3: Monthly forest-wide audit (90 days, all domains)
Get-DomainTrustBypass -DaysBack 90 -CheckAllDomains -IncludeTrustEnumeration
```

### Event Log Performance

- Ensure adequate Security event log size (minimum 2GB)
- Enable circular logging with auto-backup
- Archive old logs to separate storage
- Use `-MaxEvents` parameter in `Get-WinEvent` for large result sets

## False Positives

Common scenarios that may trigger detections:

1. **Legitimate Cross-Forest Service Accounts**
   - **Cause:** Service accounts requiring cross-trust access
   - **Mitigation:** Document approved service accounts, exclude from privileged auth detection

2. **Migration Activities**
   - **Cause:** Domain migrations, forest restructuring
   - **Mitigation:** Temporarily increase `DaysBack` threshold during migration windows

3. **Administrative Tools**
   - **Cause:** Legitimate use of `Get-ADTrust`, `nltest` by IT staff
   - **Mitigation:** Baseline normal administrative activity, exclude known admin accounts

4. **Hybrid Cloud Synchronization**
   - **Cause:** Entra Connect synchronization from child domains
   - **Mitigation:** Exclude Entra Connect service accounts from monitoring

## Related Functions

- **Get-DCSyncAttack** - Detects DCSync replication attacks
- **Get-GoldenTicketDetection** - Monitors for forged Kerberos TGTs
- **Get-ADKerberoastingPattern** - Identifies Kerberoasting attacks
- **Get-UnconstrainedDelegation** - Detects unconstrained delegation abuse

## External Resources

- [Microsoft: Managing Trusts](<https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc755321(v=ws.10)>)
- [MITRE ATT&CK: T1484.002](https://attack.mitre.org/techniques/T1484/002/)
- [MITRE ATT&CK: T1482](https://attack.mitre.org/techniques/T1482/)
- [Microsoft: SID Filtering](<https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/cc772633(v=ws.10)>)
- [Microsoft: Selective Authentication](<https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/cc755844(v=ws.10)>)
- [Microsoft ESAE Architecture](https://learn.microsoft.com/en-us/security/privileged-access-workstations/esae-retirement)

## Website Documentation

For comprehensive guidance on domain trust bypass attacks and Five Eyes Joint Advisory coverage, visit:

**https://www.eguibarit.com/security/five-eyes-ad-attacks.html#domain-trust-bypass**

This resource provides:

- Detailed attack methodology walkthroughs
- Real-world compromise case studies
- Step-by-step hardening procedures
- Audit automation scripts
- Trust configuration best practices
- Compliance mapping (NIST, CIS, ISO 27001)

## Notes

- **Trust Type Classifications:**
  - **Shortcut Trusts:** Within forest, reduce authentication hops (low risk)
  - **Forest Trusts:** Between forests, highest risk (require SID filtering + selective auth)
  - **External Trusts:** Legacy domain trusts (require SID filtering)
  - **Realm Trusts:** Non-Windows Kerberos realms (MIT, Unix)

- **SID Filtering Quarantine:**
  - Automatically filters out non-forest SIDs (protects against SIDHistory injection)
  - Must be enabled on all external trusts
  - Test before enabling in production (can break legitimate cross-forest access)

- **Selective Authentication:**
  - Requires explicit "Allowed to Authenticate" permission for cross-trust access
  - Provides granular control over trust resource access
  - Recommended for all external trusts

- **Event Log Considerations:**
  - Event 4675 (SID filtering failed) indicates bypass attempt - CRITICAL ALERT
  - Event 4766 (SID filtering blocked) indicates functioning protection - review for patterns
  - Event 4768 (TGT requested) high volume - filter by source domain for cross-trust detection
  - Event 4770 (TGT renewed) indicates persistence - correlate with 4768 for timeline

- **Privileged Account Protection:**
  - Tier 0 accounts should NEVER cross trust boundaries
  - Implement Protected Users group for all administrative accounts
  - Use authentication policies to restrict privileged logon locations
  - Deploy PAW (Privileged Access Workstations) for Tier 0 administration

---

**Last Updated:** 06/Mar/2026
**Version:** 1.0.0
**Maintained By:** Vicente Rodriguez Eguibar (EguibarIT)
