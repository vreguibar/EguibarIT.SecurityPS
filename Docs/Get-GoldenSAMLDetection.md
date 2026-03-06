# Get-GoldenSAMLDetection

## SYNOPSIS
Detects Golden SAML activity by auditing AD FS configuration, certificates, event logs, and private key access.

## SYNTAX

```powershell
Get-GoldenSAMLDetection
    [[-Hours] <Int32>]
    [[-ExportPath] <String>]
    [-IncludeEvents]
    [-WhatIf]
    [-Confirm]
    [<CommonParameters>]
```

## DESCRIPTION
Golden SAML allows attackers to forge SAML tokens by stealing the AD FS token-signing certificate private key. Traditional Kerberos monitoring won't detect this attack. This function focuses on on-premises AD FS indicators and security hygiene through a comprehensive five-phase analysis:

### Phase 1: AD FS Presence & Certificate Hygiene
- Detect AD FS role and collect token-signing/decrypting certificates
- Check AutoCertificateRollover status, certificate ages, and thumbprints
- Flag disabled rollover or stale/expiring certificates

### Phase 2: AD FS Admin Event Log Scan (AD FS/Admin)
- Search event messages for suspicious keywords: "token-signing", "certificate", "rollover", "private key", "added", "removed", "export", "relying party"
- Summarize anomalies within the analysis window

### Phase 3: Private Key Access Monitoring (Security Event 4663)
- Monitor C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys for unauthorized access
- Identify access by non-ADFS identities (possible key theft attempts)

### Phase 4: Relying Party Trust Drift
- Enumerate relying party trusts and highlight recent modifications
- Detect unauthorized configuration changes

### Phase 5: Configuration Baseline Drift
- Alert on AutoCertificateRollover disabled
- Detect unexpected thumbprint changes, multiple primary certificates, or exportable keys

### ATTACK VECTOR
Attackers who steal the AD FS token-signing certificate can:
1. Forge SAML tokens for any user in the organization
2. Bypass authentication and gain unauthorized access to federated services
3. Maintain persistent access even after password resets

### MITRE ATT&CK Mapping
- **T1606.002**: Forge Web Credentials - SAML Tokens

## PARAMETERS

### -Hours
Specifies the number of hours of event logs to analyze. Default is 24 hours.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases: None
Required: False
Position: 0
Default value: 24
Accept pipeline input: False
Accept wildcard characters: False
```

### -ExportPath
Specifies the file path to export findings in CSV format. A JSON companion file is also created automatically.

```yaml
Type: String
Parameter Sets: (All)
Aliases: None
Required: False
Position: 1
Default value: C:\Reports\GoldenSAML-Findings-{timestamp}.csv
Accept pipeline input: False
Accept wildcard characters: False
```

### -IncludeEvents
If specified, includes raw matching event messages in the JSON export. This provides detailed event data for further analysis but increases export file size.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: None
Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -WhatIf
Shows what would happen if the cmdlet runs. The cmdlet is not run.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: wi
Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Confirm
Prompts you for confirmation before running the cmdlet.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: cf
Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None
This function does not accept pipeline input.

## OUTPUTS

### PSCustomObject
Returns a summary object containing:
- **DomainName**: DNS name of the environment
- **ADFSPresent**: Boolean indicating if AD FS is installed
- **FindingsCount**: Total number of findings
- **HighSeverityCount**: Number of high-severity findings
- **MediumSeverityCount**: Number of medium-severity findings
- **InfoCount**: Number of informational findings
- **IsSecure**: Boolean indicating if configuration is secure
- **RecommendedAction**: Guidance for remediation
- **ExportedFiles**: Array of exported file paths
- **DetailedFindings**: Complete list of all findings

## EXAMPLES

### Example 1: Run detection scan with default settings
```powershell
PS C:\> Get-GoldenSAMLDetection
```

Runs the detection scan with default settings (24 hours) and displays findings to console.

### Example 2: Analyze 72 hours with event details
```powershell
PS C:\> Get-GoldenSAMLDetection -Hours 72 -IncludeEvents -ExportPath 'C:\Reports\GoldenSAML-Findings.csv'
```

Analyzes the last 72 hours of logs, includes raw event data, and exports findings to the specified path.

### Example 3: Extended scan with verbose output
```powershell
PS C:\> Get-GoldenSAMLDetection -Hours 168 -Verbose
```

Scans the last 7 days (168 hours) with verbose output showing detailed progress through each phase.

### Example 4: Test export without creating files
```powershell
PS C:\> Get-GoldenSAMLDetection -ExportPath 'D:\SecurityAudits\SAML-Scan.csv' -WhatIf
```

Shows what the function would do (including export operations) without actually exporting files.

### Example 5: Automated security assessment
```powershell
PS C:\> $Result = Get-GoldenSAMLDetection -Hours 24
PS C:\> if ($Result.HighSeverityCount -gt 0) {
    Write-Warning ('Found {0} high-severity Golden SAML indicators!' -f $Result.HighSeverityCount)
    $Result.DetailedFindings | Where-Object { $_.Severity -eq 'HIGH' } | Format-Table
}
```

Captures the audit result and takes automated action based on high-severity findings.

## NOTES

**Version**: 1.4.0  
**Date Modified**: 04/Mar/2026  
**Last Modified By**: Vicente Rodriguez Eguibar  
**Contact**: vicente@eguibar.com  
**Company**: EguibarIT  
**Website**: http://www.eguibarit.com

### Requirements
- Active Directory Federation Services (AD FS) installed (for full detection capabilities)
- Local Administrator privileges (for event log access)
- PowerShell 5.1 or later
- ADFS PowerShell module (automatically imported if available)

### Security Note
This function performs read-only operations and does not modify any AD FS configuration. Export operations respect the -WhatIf and -Confirm parameters.

## RELATED LINKS

- [MITRE ATT&CK - T1606.002: Forge Web Credentials - SAML Tokens](https://attack.mitre.org/techniques/T1606/002/)
- [GitHub Repository](https://github.com/vreguibar/EguibarIT.SecurityPS)
- [Get-GoldenTicketDetection](Get-GoldenTicketDetection.md)
- [Get-SilverTicketDetection](Get-SilverTicketDetection.md)
- [Get-DCSyncAttack](Get-DCSyncAttack.md)
