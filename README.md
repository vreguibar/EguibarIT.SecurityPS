# EguibarIT.SecurityPS

[![PowerShell Gallery Version](https://img.shields.io/powershellgallery/v/EguibarIT.SecurityPS.svg)](https://www.powershellgallery.com/packages/EguibarIT.SecurityPS)
[![PowerShell Gallery](https://img.shields.io/powershellgallery/p/EguibarIT.SecurityPS.svg)](https://www.powershellgallery.com/packages/EguibarIT.SecurityPS)
[![PowerShell Gallery Downloads](https://img.shields.io/powershellgallery/dt/EguibarIT.SecurityPS.svg)](https://www.powershellgallery.com/packages/EguibarIT.SecurityPS)
[![GitHub Release](https://img.shields.io/github/v/release/vreguibar/EguibarIT)](https://github.com/vreguibar/EguibarIT/releases)
[![GitHub License](https://img.shields.io/github/license/vreguibar/EguibarIT.svg)](https://github.com/vreguibar/EguibarIT/blob/main/LICENSE)

[![LinkedIn](https://img.shields.io/badge/LinkedIn-VicenteRodriguezEguibar-0077B5.svg?logo=LinkedIn)](https://www.linkedin.com/in/VicenteRodriguezEguibar)
![GitHub Sponsors](https://img.shields.io/github/sponsors/vreguibar)

> **PowerShell module for auditing and remediating Active Directory security vulnerabilities**

## Overview

`EguibarIT.SecurityPS` is a comprehensive PowerShell module designed to **audit** and **remediate** Active Directory security vulnerabilities, with a primary focus on credential theft attacks documented in the [Five Eyes Joint Advisory on Active Directory Security](https://www.eguibarit.com/security/five-eyes-ad-attacks.html).

This module addresses critical attack vectors including:

- 🎯 **Pass-the-Hash** (PtH) attacks
- 🎫 **Pass-the-Ticket** (PtT) attacks
- 👑 **Golden Ticket** attacks
- 🥈 **Silver Ticket** attacks
- 🔐 **Kerberos** encryption weaknesses
- 🚨 **Credential theft** vulnerabilities
- ⚠️ **Privilege escalation** risks

## Key Features

✅ **Audit-First Approach**: All functions start in read-only mode for safe assessment  
✅ **Multi-Environment Support**: Works with on-premises AD, Azure AD/Entra ID, and hybrid environments  
✅ **Multi-Forest/Multi-Domain**: Enterprise-ready for complex AD topologies  
✅ **Comprehensive Logging**: Built-in Windows Event Log integration for audit trails  
✅ **WhatIf Support**: Preview all changes before applying remediation  
✅ **PowerShell 5.1+ & 7+**: Compatible with both Windows PowerShell and PowerShell Core  

## Installation

### From PowerShell Gallery (Recommended)

    Install-Module -Name EguibarIT.SecurityPS -Scope AllUsers -Force
    Import-Module EguibarIT.SecurityPS

### From GitHub

    git clone https://github.com/vreguibar/EguibarIT.git
    cd EguibarIT/Modules/EguibarIT.SecurityPS
    Import-Module .\EguibarIT.SecurityPS.psd1

## Requirements

- **PowerShell**: Version 5.1 or higher (Windows PowerShell or PowerShell Core)
- **ActiveDirectory Module**: Microsoft's ActiveDirectory PowerShell module
- **Permissions**:
  - **Audit Functions**: Domain User with extended read rights
  - **Remediation Functions**: Domain Admin or delegated permissions (varies by function)
- **Supported OS**: Windows Server 2012 R2+, Windows 10+, Windows 11+

## Quick Start

### Example 1: Basic Security Audit (Coming Soon)

```powershell
# Import the module
Import-Module EguibarIT.SecurityPS

# Run a comprehensive AD security audit
$AuditResults = Invoke-ADSecurityAudit -Verbose

# Export results for review
$AuditResults | Export-Clixml -Path "C:\Reports\AD-SecurityAudit-$(Get-Date -Format 'yyyyMMdd').xml"
```

### Example 2: Check for Weak Kerberos Encryption (Coming Soon)

```powershell
# Identify accounts using weak Kerberos encryption
Test-ADKerberosEncryption -ReportOnly

# Remediate weak encryption (use -WhatIf first)
Set-ADKerberosEncryption -MinimumEncryptionType AES256 -WhatIf
```

### Example 3: Detect Credential Theft Indicators (Coming Soon)

```powershell
# Check for Pass-the-Hash attack indicators
Test-ADCredentialTheft -AttackType PassTheHash -Days 30 -Verbose
```

## Module Structure

    EguibarIT.SecurityPS/
    ├── Classes/           # C# classes for event logging
    ├── Enums/             # Module constants and variables
    ├── Private/           # Internal helper functions
    ├── Public/            # Exported functions (to be added)
    ├── Tests/             # Pester test suite
    ├── .gitignore         # Security-focused file exclusions
    ├── LICENSE            # MIT License
    ├── README.md          # This file
    ├── SECURITY.md        # Security policy and vulnerability reporting
    └── PSScriptAnalyzerSettings.psd1  # Code quality rules

## Security Best Practices

When using this module:

1. ✅ **Test in Non-Production First**: Always test in a lab environment
2. ✅ **Use Audit Mode**: Run audits before attempting remediation
3. ✅ **Review WhatIf Output**: Preview changes with `-WhatIf` before executing
4. ✅ **Secure Credentials**: Never hardcode credentials in scripts
5. ✅ **Log Everything**: Enable verbose logging for audit trails
6. ✅ **Least Privilege**: Use minimum required permissions for each task

See [SECURITY.md](SECURITY.md) for detailed security guidelines.

## Documentation

- **Project Website**: <https://www.eguibarit.com>
- **Five Eyes AD Attacks**: <https://www.eguibarit.com/security/five-eyes-ad-attacks.html>
- **Delegation Model**: <https://www.DelegationModel.com>
- **Tier Model**: <https://www.TierModel.com>

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Follow the coding standards (see `.github/copilot-instructions.md`)
4. Add Pester tests for new functionality
5. Submit a pull request

## Support

- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/vreguibar/EguibarIT/issues)
- 💬 **Questions**: [GitHub Discussions](https://github.com/vreguibar/EguibarIT/discussions)
- 📧 **Security Issues**: [vicente@eguibar.com](mailto:vicente@eguibar.com) (see [SECURITY.md](SECURITY.md))

## Roadmap

### Phase 1: Foundation (Current)

- ✅ Module infrastructure
- ✅ Event logging framework
- ✅ Security policies and documentation
- 🔄 Initial audit functions (In Progress)

### Phase 2: Core Audit Functions

- ⏳ Pass-the-Hash detection
- ⏳ Pass-the-Ticket detection
- ⏳ Golden/Silver Ticket indicators
- ⏳ Kerberos encryption analysis
- ⏳ Privileged account auditing

### Phase 3: Remediation Capabilities

- ⏳ Weak encryption remediation
- ⏳ ACL hardening
- ⏳ SID History cleanup
- ⏳ Delegation security improvements

### Phase 4: Advanced Features

- ⏳ Compliance reporting (CIS, STIG, NIST)
- ⏳ Automated remediation workflows
- ⏳ Integration with SIEM systems
- ⏳ Multi-forest analysis

## License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

## Author

**Vicente Rodriguez Eguibar**  
📧 [vicente@eguibar.com](mailto:vicente@eguibar.com)  
🌐 [www.eguibarit.com](https://www.eguibarit.com)  
💼 [LinkedIn](https://www.linkedin.com/in/VicenteRodriguezEguibar)

---

**⚠️ Disclaimer**: This module is provided "as is" without warranty. Always test in non-production environments before deploying to production Active Directory domains.
