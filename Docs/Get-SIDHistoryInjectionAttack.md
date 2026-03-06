# Get-SIDHistoryInjectionAttack Function Documentation

## Overview

**Get-SIDHistoryInjectionAttack** detects SID History injection indicators by auditing `sidHistory` values across AD accounts, Event ID 4765 activity, replication metadata anomalies, and optional trust SID filtering configuration.

**Function File:** `Public/Get-SIDHistoryInjectionAttack.ps1`
**Version:** 1.0.0
**Last Modified:** 06/Mar/2026
**Author:** Vicente Rodriguez Eguibar

## Purpose

The function implements a five-phase detection model:

1. **Enumerate accounts with SID History**
2. **Detect privileged SID values in SID History**
3. **Analyze Event ID 4765 (SID History Added)**
4. **Audit sidHistory replication metadata origin**
5. **Optionally check trust SID filtering status**

This helps identify unauthorized privilege persistence and potential DCShadow-linked SID History manipulation.

## Key Features

### Phase 1: Account Enumeration

- Enumerates users and computers with non-empty `sidHistory`
- Provides baseline counts for immediate risk triage

### Phase 2: Privileged SID History Analysis

- Uses `$Variables.WellKnownSIDs` (no hardcoded SID literals)
- Flags Domain Admins, Enterprise Admins, Schema Admins, and Administrator SIDs in SID History as critical
- Flags non-privileged SID History entries as medium risk

### Phase 3: Event 4765 Monitoring

- Queries all domain controllers for Event ID `4765`
- Captures target account, subject account, and SID value added
- Produces high-risk findings for each event occurrence

### Phase 4: Replication Metadata Anomaly Detection

- Audits `sidHistory` replication attribute metadata
- Detects unknown originating directory server identities
- Flags likely rogue replication/DCShadow indicators as critical

### Phase 5: Trust SID Filtering (Optional)

- Checks `SIDFilteringQuarantined` for trusts when `-CheckTrusts` is used
- Flags trusts with disabled SID filtering as high risk

## Usage

### Basic Detection

```powershell
Get-SIDHistoryInjectionAttack
```

### Extended Window with Trust Analysis

```powershell
Get-SIDHistoryInjectionAttack -DaysBack 180 -CheckTrusts -Verbose
```

### Custom Export Path

```powershell
Get-SIDHistoryInjectionAttack -OutputPath 'C:\SIDHistoryAudit' -DaysBack 30
```

### Automation Pattern

```powershell
$Result = Get-SIDHistoryInjectionAttack -CheckTrusts
if ($Result.CriticalCount -gt 0) {
    Write-Warning ('Critical SID History findings detected: {0}' -f $Result.CriticalCount)
}
```

## Parameters

### OutputPath

- **Type:** string
- **Aliases:** `ExportPath`, `Path`
- **Default:** `$env:USERPROFILE\Desktop\SIDHistoryAudit`
- **Required:** No
- **Description:** Export directory for CSV/JSON report files.

### DaysBack

- **Type:** int
- **Default:** 90
- **Range:** 1-365
- **Required:** No
- **Description:** Number of days to analyze Event ID 4765 activity.

### CheckTrusts

- **Type:** switch
- **Default:** False
- **Required:** No
- **Description:** Enables trust SID filtering checks.

## Output

Returns a structured `PSCustomObject` with `PSTypeName` **EguibarIT.SIDHistoryInjectionAttack**:

```powershell
[PSCustomObject]@{
    AuditTimestamp
    AnalysisWindowDays
    UsersWithSIDHistoryCount
    ComputersWithSIDHistoryCount
    AccountsWithSIDHistoryCount
    TotalFindings
    CriticalCount
    HighCount
    MediumCount
    IsCompromiseLikely
    TrustsChecked
    Findings
    RecommendedActions
    ExportedReports
}
```

## Risk Interpretation

- **Critical:** Privileged SID History and/or unknown replication metadata origin indicators
- **High:** SID History added events and trust SID filtering disabled
- **Medium:** Non-privileged SID History requiring business validation

## Requirements

- Domain Admin or equivalent read access
- ActiveDirectory PowerShell module
- Access to Security logs on domain controllers
- Relevant auditing for Event ID `4765`

## MITRE ATT&CK Mapping

- **T1134.005** - Access Token Manipulation: SID-History Injection
- **T1484.001** - Domain Policy Modification (trust-hardening relevance)

## Related Links

- [Function Source](https://github.com/vreguibar/EguibarIT.SecurityPS/blob/main/Public/Get-SIDHistoryInjectionAttack.ps1)
- [Repository](https://github.com/vreguibar/EguibarIT.SecurityPS)
- [MITRE T1134.005](https://attack.mitre.org/techniques/T1134/005/)