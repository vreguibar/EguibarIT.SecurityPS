# Security Policy

## Overview

`EguibarIT.SecurityPS` is a PowerShell module designed to **audit and remediate** Active Directory security vulnerabilities, specifically focusing on credential theft attacks documented in the Five Eyes advisories (Pass-the-Hash, Pass-the-Ticket, Golden Ticket, Silver Ticket, and related attack vectors).

Because this module operates in privileged security contexts and handles sensitive Active Directory data, we take security very seriously.

## Supported Versions

We provide security updates for the following versions:

| Version | Supported          | Notes                              |
| ------- | ------------------ | ---------------------------------- |
| 0.0.x   | :white_check_mark: | Pre-release / Development          |
| 1.x.x   | :white_check_mark: | Current stable (when released)     |
| < 1.0   | :x:                | Not recommended for production use |

## Reporting a Vulnerability

**Please DO NOT report security vulnerabilities through public GitHub issues.**

### Preferred Reporting Method

Email security concerns to: [vicente@eguibar.com](mailto:vicente@eguibar.com)

Include the following information:

1. **Description**: Detailed description of the vulnerability
2. **Impact**: Potential security impact (privilege escalation, information disclosure, etc.)
3. **Reproduction**: Steps to reproduce the vulnerability
4. **Affected Versions**: Which versions are affected
5. **Proposed Fix**: If you have suggestions for remediation
6. **Your Contact Info**: So we can follow up with questions

### Response Timeline

- **Initial Response**: Within 48 hours of report submission
- **Status Update**: Within 7 days with initial assessment
- **Fix Timeline**: Critical issues will be addressed within 30 days
- **Disclosure**: Coordinated disclosure after fix is available

### What to Expect

1. We will acknowledge receipt of your vulnerability report
2. We will investigate and validate the issue
3. We will develop and test a fix
4. We will release a security patch
5. We will credit you in the release notes (unless you prefer to remain anonymous)

## Security Best Practices for Users

### When Using This Module

1. **Audit Mode First**: Always run security audits in read-only mode before attempting remediation
2. **Least Privilege**: Use the minimum required AD permissions for your task
   - **Audit functions**: Domain User with extended read rights
   - **Remediation functions**: Delegated permissions or Domain Admin (as required)
3. **Credential Protection**: Never hardcode credentials in scripts
   - Use `Get-Credential` for interactive sessions
   - Use secure credential storage (Windows Credential Manager, Azure Key Vault, etc.)
4. **Test Environment**: Test all remediation functions in a non-production AD environment first
5. **Logging**: Enable verbose logging for audit trails: `-Verbose`
6. **WhatIf**: Use `-WhatIf` parameter before running any remediation function

### Secure Credential Handling

```powershell
# GOOD - Interactive credential prompt
$Cred = Get-Credential
Invoke-ADSecurityAudit -Credential $Cred

# GOOD - Using saved credential with encryption
$Cred = Import-Clixml -Path (Join-Path $env:USERPROFILE 'MyCred.xml')

# BAD - Never do this
$Password = ConvertTo-SecureString 'MyPassword123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('Domain\User', $Password)
```

### Protecting Audit Results

Audit results may contain sensitive information:

- **Privileged account names**
- **Group memberships**
- **Weak security configurations**
- **Kerberos encryption details**

**Always protect audit output files:**

```powershell
# Save audit results to secure location
$AuditPath = "C:\SecureLocation\AD-SecurityAudit-$(Get-Date -Format 'yyyyMMdd').xml"
Invoke-ADSecurityAudit | Export-Clixml -Path $AuditPath

# Protect the file
$Acl = Get-Acl $AuditPath
$Acl.SetAccessRuleProtection($true, $false)
# Add only specific users
Set-Acl -Path $AuditPath -AclObject $Acl
```

## Known Security Considerations

### Privileged Operations

This module contains functions that require elevated privileges:

- ✅ **Audit functions**: Read-only, low risk
- ⚠️ **Remediation functions**: Write operations, requires careful review
- 🔒 **All functions**: Support `-WhatIf` and `-Confirm` for safety

### Event Logging

The module logs security-relevant events to the Windows Event Log:

- **Log Name**: `EguibarIT-Events`
- **Source**: `EguibarIT-PowerShellModule`
- **Contains**: Function calls, parameters (credentials are never logged)

### Credential Storage

The module:

- ✅ Uses `[PSCredential]` objects for credential handling
- ✅ Never logs passwords or secrets
- ✅ Does not store credentials in memory longer than necessary
- ✅ Masks sensitive parameters in verbose output

## Security Testing

This module undergoes:

- **Static Analysis**: PSScriptAnalyzer with security-focused rules
- **Pester Tests**: Comprehensive test coverage including security scenarios
- **Manual Review**: All code changes reviewed for security implications
- **AD Lab Testing**: Tested in isolated Active Directory lab environments

## Compliance & Standards

This module is developed following:

- **PowerShell Security Best Practices** (Microsoft)
- **Active Directory Security Best Practices** (Microsoft)
- **CIS Microsoft Windows Server Benchmarks**
- **NIST Cybersecurity Framework**
- **Five Eyes Joint Advisory on AD Security**

## Third-Party Dependencies

This module has minimal dependencies:

- **ActiveDirectory PowerShell Module** (Microsoft-provided)
- **.NET Framework/Core** (System libraries only)

We do not use third-party modules to minimize supply chain risk.

## Module Integrity

### Code Signing

Production releases are:

- ✅ Digitally signed with an EV code signing certificate
- ✅ Published to PowerShell Gallery with hash verification
- ✅ Available on GitHub with release checksums

### Verifying Module Integrity

```powershell
# Check module signature
Get-AuthenticodeSignature -FilePath (Get-Module EguibarIT.SecurityPS -ListAvailable).Path

# Verify from PowerShell Gallery
Find-Module EguibarIT.SecurityPS | Select-Object Name, Version, PublishedDate
```

## Additional Resources

- **Project Website**: <https://www.eguibarit.com>
- **Documentation**: <https://www.eguibarit.com/security/five-eyes-ad-attacks.html>
- **GitHub Repository**: <https://github.com/vreguibar/EguibarIT>
- **PowerShell Gallery**: <https://www.powershellgallery.com/packages/EguibarIT.SecurityPS>

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Last Updated**: February 2026
**Maintained By**: Vicente Rodriguez Eguibar ([vicente@eguibar.com](mailto:vicente@eguibar.com))
