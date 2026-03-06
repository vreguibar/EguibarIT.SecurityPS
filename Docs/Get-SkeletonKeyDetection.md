# Get-SkeletonKeyDetection Function Documentation

## Overview

**Get-SkeletonKeyDetection** detects Skeleton Key malware indicators on domain controllers through endpoint posture checks, LSASS access telemetry, service installation analysis, and authentication anomaly correlation.

**Function File:** `Public/Get-SkeletonKeyDetection.ps1`
**Version:** 1.0.0
**Last Modified:** 06/Mar/2026
**Author:** Vicente Rodriguez Eguibar

## Purpose

The function implements a five-phase detection model:

1. **Credential Guard status check**
2. **Sysmon Event 10 LSASS memory access analysis**
3. **System Event 7045 suspicious service installation analysis**
4. **Security Event 4624 authentication anomaly detection**
5. **NTLM auditing and Event 8004 anomaly checks**

This approach helps detect probable Skeleton Key deployment conditions and suspicious post-compromise authentication behavior.

## Key Features

### Phase 1: Credential Guard Validation

- Checks if Credential Guard is configured and running per scanned DC
- Flags DCs where LSASS tampering resistance is absent

### Phase 2: LSASS Process Access Detection (Sysmon Event 10)

- Detects process access against `lsass.exe`
- Elevates risk when `GrantedAccess` indicates full access (`0x1FFFFF`)
- Flags missing Sysmon deployment as high risk due to telemetry blind spot

### Phase 3: Suspicious Service Installation (Event 7045)

- Scans for suspicious service names and image paths
- Highlights PsExec-like and temporary-path deployment artifacts

### Phase 4: Authentication Outlier Detection (Event 4624)

- Groups successful logons by source IP
- Flags IPs authenticating as 5 or more distinct users in the analysis window

### Phase 5: NTLM Auditing and Usage Anomalies

- Detects disabled NTLM auditing posture
- Flags privileged account NTLM usage as medium-risk anomaly

## Usage

### Default Scope (Current Host)

```powershell
Get-SkeletonKeyDetection
```

### All Domain Controllers, Extended Window

```powershell
Get-SkeletonKeyDetection -DaysBack 90 -CheckAllDCs -Verbose
```

### Export Reports

```powershell
Get-SkeletonKeyDetection -OutputPath 'C:\SkeletonKeyAudit' -CheckAllDCs
```

### Automation Pattern

```powershell
$Result = Get-SkeletonKeyDetection -CheckAllDCs
if ($Result.CriticalCount -gt 0) {
    Write-Warning ('Critical Skeleton Key indicators detected: {0}' -f $Result.CriticalCount)
}
```

## Parameters

### OutputPath

- **Type:** string
- **Aliases:** `ExportPath`, `Path`
- **Default:** `$env:USERPROFILE\Desktop\SkeletonKeyAudit`
- **Required:** No
- **Description:** Directory for CSV/JSON report export.

### DaysBack

- **Type:** int
- **Default:** 30
- **Range:** 1-365
- **Required:** No
- **Description:** Number of days of event telemetry to analyze.

### CheckAllDCs

- **Type:** switch
- **Default:** False
- **Required:** No
- **Description:** Scans all domain controllers when set; otherwise scans current host.

## Output

Returns a structured `PSCustomObject` with `PSTypeName` **EguibarIT.SkeletonKeyDetection**:

```powershell
[PSCustomObject]@{
    AuditTimestamp
    AnalysisWindowDays
    DomainControllersScanned
    CheckedAllDomainControllers
    TotalFindings
    CriticalCount
    HighCount
    MediumCount
    IsCompromiseLikely
    Findings
    RecommendedActions
    ExportedReports
}
```

## Risk Interpretation

- **Critical:** High-confidence LSASS tampering exposure or direct LSASS full-access indicators
- **High:** Strong suspicious behavior requiring immediate investigation
- **Medium:** Security telemetry/hardening gaps and protocol usage anomalies

## Requirements

- Domain Admin or equivalent read access
- ActiveDirectory PowerShell module
- Sysmon deployed to domain controllers for Event ID 10 coverage
- Access to Security, System, Sysmon, and NTLM operational logs

## MITRE ATT&CK Mapping

- **T1556.001** - Modify Authentication Process: Domain Controller Authentication
- **T1003.001** - OS Credential Dumping: LSASS Memory

## Related Links

- [Function Source](https://github.com/vreguibar/EguibarIT.SecurityPS/blob/main/Public/Get-SkeletonKeyDetection.ps1)
- [Repository](https://github.com/vreguibar/EguibarIT.SecurityPS)
- [MITRE T1556.001](https://attack.mitre.org/techniques/T1556/001/)