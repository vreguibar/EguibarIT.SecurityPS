# Get-DCShadowAttack Function Documentation

## Overview

**Get-DCShadowAttack** is a PowerShell function that detects DCShadow attack indicators by correlating rogue domain controller registration activity, replication metadata anomalies, and privileged-object tampering.

**Function File:** `Public/Get-DCShadowAttack.ps1`
**Version:** 1.0.0
**Last Modified:** 04/Mar/2026
**Author:** Vicente Rodriguez Eguibar

## Purpose

The function implements a five-phase detection model:

1. **Baseline Domain Controllers**
2. **Rogue Registration Event Analysis**
3. **Replication Metadata Anomaly Review**
4. **Privileged Account Provenance Check**
5. **AdminSDHolder Modification Monitoring**

This approach helps identify high-confidence DCShadow tradecraft and related persistence actions.

## Key Features

### Phase 1: Baseline Domain Controllers

- Enumerates legitimate DC objects (`Get-ADDomainController`)
- Collects expected DC names/hostnames for later correlation
- Flags computer accounts with `PrimaryGroupID = 516` outside `OU=Domain Controllers`

### Phase 2: Rogue DC Registration Event Analysis

- **Event 5137:** Server / nTDSDSA object creation
- **Event 5141:** Replication partner registration artifacts
- **Event 4742:** Unauthorized replication SPN assignment (`GC/`, DRS UUID)

### Phase 3: Replication Metadata Anomaly Review

- Audits privileged accounts and `AdminSDHolder`
- Detects unknown `LastOriginatingChangeDirectoryServerIdentity`
- Highlights changes originating from systems not in DC baseline

### Phase 4: Privileged Account Provenance Check

- Reviews privileged users from administrative groups
- Searches for account creation evidence (`Event 4720`) in analysis window
- Flags privileged users lacking matching creation evidence

### Phase 5: AdminSDHolder Modification Monitoring

- Monitors `Event 5136` targeting `CN=AdminSDHolder,CN=System`
- Captures modified attribute and actor account
- Elevates findings due to persistence impact

## Usage

### Basic Analysis

```powershell
Get-DCShadowAttack
```

### Extended Lookback with Verbose Logging

```powershell
Get-DCShadowAttack -DaysBack 90 -Verbose
```

### Export Reports

```powershell
Get-DCShadowAttack -OutputPath 'C:\SecurityAudits\DCShadow' -DaysBack 60
```

### Include Raw Event Samples

```powershell
Get-DCShadowAttack -IncludeEvents -DaysBack 14
```

### Automation Pattern

```powershell
$Result = Get-DCShadowAttack -DaysBack 30
if ($Result.CriticalCount -gt 0) {
    Write-Warning ('Critical DCShadow indicators detected: {0}' -f $Result.CriticalCount)
}
```

## Parameters

### OutputPath

- **Type:** string
- **Aliases:** `ExportPath`, `Path`
- **Required:** No
- **Description:** Export directory for CSV and JSON reports. If omitted, no files are written.

### DaysBack

- **Type:** int
- **Default:** 30
- **Range:** 1-365
- **Required:** No
- **Description:** Number of days to evaluate event and metadata evidence.

### IncludeEvents

- **Type:** switch
- **Default:** False
- **Required:** No
- **Description:** Includes raw event samples in the returned object.

## Output

Returns a structured `PSCustomObject` with `PSTypeName` **EguibarIT.DCShadowAttack**:

```powershell
[PSCustomObject]@{
    AuditTimestamp
    AnalysisWindowDays
    DomainControllerCount
    TotalFindings
    CriticalCount
    HighCount
    MediumCount
    IsCompromiseLikely
    Findings
    RecommendedActions
    ExportedReports
    IncludedRawEvents
}
```

## Risk Interpretation

- **Critical:** High-confidence DCShadow indicators (rogue replication artifacts, AdminSDHolder abuse, unknown originating DC)
- **High:** Privileged-account lifecycle anomalies requiring validation
- **Medium:** Contextual risk requiring investigation and correlation

## Requirements

- Domain Admin or equivalent read permissions
- ActiveDirectory PowerShell module
- Access to Security logs on domain controllers
- Relevant auditing enabled for events `4720`, `4742`, `5136`, `5137`, `5141`

## MITRE ATT&CK Mapping

- **T1207** - Rogue Domain Controller
- **T1484.001** - Domain Policy Modification
- **T1098** - Account Manipulation

## Related Links

- [Function Source](https://github.com/vreguibar/EguibarIT.SecurityPS/blob/main/Public/Get-DCShadowAttack.ps1)
- [Repository](https://github.com/vreguibar/EguibarIT.SecurityPS)
- [DCShadow Reference](https://www.dcshadow.com/)
