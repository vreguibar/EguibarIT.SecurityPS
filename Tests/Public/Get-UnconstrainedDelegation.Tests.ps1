Describe 'Get-UnconstrainedDelegation Setup' {
BeforeAll {
    # Import the module
    $ModulePath = Join-Path -Path $PSScriptRoot -ChildPath '..\..\EguibarIT.SecurityPS.psd1'
    Import-Module $ModulePath -Force

    $FunctionName = 'Get-UnconstrainedDelegation'

    # Mock internal functions to prevent AD calls during module initialization
    Mock -CommandName Initialize-EventLogging -MockWith { }
    Mock -CommandName Initialize-ModuleVariable -MockWith {
        $Global:Variables = @{
            HeaderSecurity = '{0} - {1} - {2}'
            FooterSecurity = '{0} - {1}'
        }
    }
}

BeforeEach {
    # Mock Get-ADDomain
    Mock -CommandName Get-ADDomain -MockWith {
        return [PSCustomObject]@{
            DNSRoot           = 'contoso.com'
            DistinguishedName = 'DC=contoso,DC=com'
            ObjectGUID        = [guid]::NewGuid()
        }
    }

    # Mock Get-ADComputer for delegated computers
    Mock -CommandName Get-ADComputer -MockWith {
        param($Filter, $Properties)

        if ($Filter -match 'TrustedForDelegation') {
            return @(
                # Domain Controller (expected)
                [PSCustomObject]@{
                    Name                    = 'DC01'
                    TrustedForDelegation    = $true
                    userAccountControl      = 532480  # 524288 + 8192 (TRUSTED_FOR_DELEGATION + SERVER_TRUST_ACCOUNT)
                    Created                 = (Get-Date).AddYears(-2)
                    LastLogonDate           = (Get-Date).AddDays(-1)
                    OperatingSystem         = 'Windows Server 2022'
                    OperatingSystemVersion  = '10.0 (20348)'
                    Enabled                 = $true
                    CanonicalName           = 'contoso.com/Domain Controllers/DC01'
                    Description             = 'Domain Controller'
                    PrimaryGroupID          = 516  # Domain Controllers group
                    DistinguishedName       = 'CN=DC01,OU=Domain Controllers,DC=contoso,DC=com'
                },
                # Non-DC computer with delegation (HIGH RISK - active, enabled, production)
                [PSCustomObject]@{
                    Name                    = 'WEB-PROD01'
                    TrustedForDelegation    = $true
                    userAccountControl      = 524288  # TRUSTED_FOR_DELEGATION
                    Created                 = (Get-Date).AddYears(-1)
                    LastLogonDate           = (Get-Date).AddDays(-5)
                    OperatingSystem         = 'Windows Server 2019'
                    OperatingSystemVersion  = '10.0 (17763)'
                    Enabled                 = $true
                    CanonicalName           = 'contoso.com/Production/Servers/WEB-PROD01'
                    Description             = 'Production web server'
                    PrimaryGroupID          = 515  # Domain Computers
                    DistinguishedName       = 'CN=WEB-PROD01,OU=Servers,OU=Production,DC=contoso,DC=com'
                },
                # Non-DC computer with delegation (MEDIUM RISK - active but not in production)
                [PSCustomObject]@{
                    Name                    = 'APP-DEV01'
                    TrustedForDelegation    = $true
                    userAccountControl      = 524288
                    Created                 = (Get-Date).AddMonths(-6)
                    LastLogonDate           = (Get-Date).AddDays(-15)
                    OperatingSystem         = 'Windows Server 2016'
                    OperatingSystemVersion  = '10.0 (14393)'
                    Enabled                 = $true
                    CanonicalName           = 'contoso.com/Development/Servers/APP-DEV01'
                    Description             = 'Development application server'
                    PrimaryGroupID          = 515
                    DistinguishedName       = 'CN=APP-DEV01,OU=Servers,OU=Development,DC=contoso,DC=com'
                },
                # Non-DC computer with delegation (LOW RISK - stale, disabled)
                [PSCustomObject]@{
                    Name                    = 'LEGACY-SRV01'
                    TrustedForDelegation    = $true
                    userAccountControl      = 524290  # TRUSTED_FOR_DELEGATION + ACCOUNTDISABLE
                    Created                 = (Get-Date).AddYears(-5)
                    LastLogonDate           = (Get-Date).AddYears(-2)
                    OperatingSystem         = 'Windows Server 2008 R2'
                    OperatingSystemVersion  = '6.1 (7601)'
                    Enabled                 = $false
                    CanonicalName           = 'contoso.com/Legacy/Servers/LEGACY-SRV01'
                    Description             = 'Legacy server - to be decommissioned'
                    PrimaryGroupID          = 515
                    DistinguishedName       = 'CN=LEGACY-SRV01,OU=Servers,OU=Legacy,DC=contoso,DC=com'
                }
            )
        }
    }

    # Mock Get-ADUser for service accounts
    Mock -CommandName Get-ADUser -MockWith {
        param($Filter, $Properties, $Identity)

        if ($Filter -match 'TrustedForDelegation') {
            return @(
                [PSCustomObject]@{
                    Name                   = 'Service Account 1'
                    SamAccountName         = 'svc_delegation'
                    TrustedForDelegation   = $true
                    userAccountControl     = 524800  # TRUSTED_FOR_DELEGATION + NORMAL_ACCOUNT
                    Created                = (Get-Date).AddYears(-1)
                    LastLogonDate          = (Get-Date).AddDays(-3)
                    Enabled                = $true
                    CanonicalName          = 'contoso.com/Service Accounts/svc_delegation'
                    Description            = 'Service account with delegation'
                    ServicePrincipalName   = @('HTTP/webserver.contoso.com', 'HTTP/webserver')
                    DistinguishedName      = 'CN=svc_delegation,OU=Service Accounts,DC=contoso,DC=com'
                    AccountNotDelegated    = $false
                    MemberOf               = @()
                }
            )
        } elseif ($Identity) {
            # Return user identified by DN (for privileged group member enumeration)
            return [PSCustomObject]@{
                Name                = 'Administrator'
                SamAccountName      = 'Administrator'
                DistinguishedName   = $Identity
                AccountNotDelegated = $false
                MemberOf            = @()
            }
        }
    }

    # Mock Get-ADGroup
    Mock -CommandName Get-ADGroup -MockWith {
        param($Identity, $Properties)

        if ($Identity -eq 'Protected Users') {
            return [PSCustomObject]@{
                Name               = 'Protected Users'
                DistinguishedName  = 'CN=Protected Users,CN=Users,DC=contoso,DC=com'
                Members            = @(
                    'CN=ProtectedAdmin,CN=Users,DC=contoso,DC=com'
                )
            }
        } elseif ($Identity -in @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Account Operators', 'Backup Operators', 'Server Operators', 'Administrators')) {
            return [PSCustomObject]@{
                Name               = $Identity
                DistinguishedName  = "CN=$Identity,CN=Users,DC=contoso,DC=com"
                Members            = @(
                    'CN=Administrator,CN=Users,DC=contoso,DC=com',
                    'CN=VulnerableAdmin,CN=Users,DC=contoso,DC=com'
                )
            }
        }
    }

    # Mock Get-ADGroupMember
    Mock -CommandName Get-ADGroupMember -MockWith {
        param($Identity)

        return @(
            [PSCustomObject]@{
                Name              = 'Administrator'
                SamAccountName    = 'Administrator'
                distinguishedName = 'CN=Administrator,CN=Users,DC=contoso,DC=com'
            },
            [PSCustomObject]@{
                Name              = 'VulnerableAdmin'
                SamAccountName    = 'VulnerableAdmin'
                distinguishedName = 'CN=VulnerableAdmin,CN=Users,DC=contoso,DC=com'
            }
        )
    }

    # Mock Get-FunctionDisplay
    Mock -CommandName Get-FunctionDisplay -MockWith {
        return 'Mocked Display'
    }

    # Mock Export-Csv
    Mock -CommandName Export-Csv -MockWith { }

    # Mock Out-File
    Mock -CommandName Out-File -MockWith { }

    # Mock Test-Path
    Mock -CommandName Test-Path -MockWith {
        param($Path)
        return $false  # Default to directory not existing
    }

    # Mock New-Item
    Mock -CommandName New-Item -MockWith {
        param($ItemType, $Path, $Force)
        return [PSCustomObject]@{
            FullName = $Path
        }
    }
}

AfterEach {
    # Cleanup
    [System.GC]::Collect()
}

Describe 'Get-UnconstrainedDelegation' -Tag 'Unit' {

    Context 'Parameter Validation' {

        It 'Should have IncludeServiceAccounts switch parameter' {
            $Command = Get-Command -Name $FunctionName
            $Parameter = $Command.Parameters['IncludeServiceAccounts']

            $Parameter | Should -Not -BeNullOrEmpty
            $Parameter.SwitchParameter | Should -Be $true
        }

        It 'Should have CheckProtectedUsers switch parameter' {
            $Command = Get-Command -Name $FunctionName
            $Parameter = $Command.Parameters['CheckProtectedUsers']

            $Parameter | Should -Not -BeNullOrEmpty
            $Parameter.SwitchParameter | Should -Be $true
        }

        It 'Should have ExportPath parameter with default value' {
            $Command = Get-Command -Name $FunctionName
            $Parameter = $Command.Parameters['ExportPath']

            $Parameter | Should -Not -BeNullOrEmpty
            $Parameter.Attributes.PSDefaultValue | Should -Not -BeNullOrEmpty
        }

        It 'Should support WhatIf parameter (ShouldProcess)' {
            $Command = Get-Command -Name $FunctionName
            $Command.Parameters.ContainsKey('WhatIf') | Should -Be $true
        }

        It 'Should support Confirm parameter (ShouldProcess)' {
            $Command = Get-Command -Name $FunctionName
            $Command.Parameters.ContainsKey('Confirm') | Should -Be $true
        }

    } #end Context Parameter Validation

    Context 'Core Detection Behavior' {

        It 'Should return a PSCustomObject with expected PSTypeName' {
            $Result = & $FunctionName

            $Result | Should -Not -BeNullOrEmpty
            $Result.PSTypeName | Should -Be 'EguibarIT.Security.UnconstrainedDelegationAudit'
        }

        It 'Should call Get-ADDomain to retrieve domain information' {
            $Result = & $FunctionName

            Should -Invoke -CommandName Get-ADDomain -Times 1 -Exactly
        }

        It 'Should call Get-ADComputer with TrustedForDelegation filter' {
            $Result = & $FunctionName

            Should -Invoke -CommandName Get-ADComputer -Times 1 -Exactly -ParameterFilter {
                $Filter -match 'TrustedForDelegation'
            }
        }

        It 'Should populate DomainName property' {
            $Result = & $FunctionName

            $Result.DomainName | Should -Be 'contoso.com'
        }

        It 'Should populate AuditDate property with current date' {
            $Result = & $FunctionName

            $Result.AuditDate | Should -Not -BeNullOrEmpty
            $Result.AuditDate | Should -BeOfType [DateTime]
        }

        It 'Should separate domain controllers from non-DC computers' {
            $Result = & $FunctionName

            $Result.DomainControllerCount | Should -BeGreaterThan 0
            $Result.NonDCComputerCount | Should -BeGreaterThan 0
        }

        It 'Should identify domain controllers by PrimaryGroupID 516' {
            $Result = & $FunctionName

            # Should find 1 DC (DC01)
            $Result.DomainControllerCount | Should -Be 1
        }

        It 'Should identify non-DC computers as security risk' {
            $Result = & $FunctionName

            # Should find 3 non-DC computers (WEB-PROD01, APP-DEV01, LEGACY-SRV01)
            $Result.NonDCComputerCount | Should -Be 3
        }

    } #end Context Core Detection Behavior

    Context 'Phase 1: Configuration Audit' {

        It 'Should query computers with TRUSTED_FOR_DELEGATION flag (userAccountControl 524288)' {
            $Result = & $FunctionName

            Should -Invoke -CommandName Get-ADComputer -Times 1 -Exactly -ParameterFilter {
                $Filter -match 'TrustedForDelegation.*eq.*true'
            }
        }

        It 'Should request relevant properties from Get-ADComputer' {
            $Result = & $FunctionName

            Should -Invoke -CommandName Get-ADComputer -Times 1 -Exactly -ParameterFilter {
                $Properties -contains 'TrustedForDelegation' -and
                $Properties -contains 'LastLogonDate' -and
                $Properties -contains 'OperatingSystem'
            }
        }

        It 'Should include service accounts when IncludeServiceAccounts is specified' {
            $Result = & $FunctionName -IncludeServiceAccounts

            Should -Invoke -CommandName Get-ADUser -Times 1 -Exactly -ParameterFilter {
                $Filter -match 'TrustedForDelegation'
            }
        }

        It 'Should not query service accounts when IncludeServiceAccounts is not specified' {
            $Result = & $FunctionName

            Should -Invoke -CommandName Get-ADUser -Times 0 -Exactly -ParameterFilter {
                $Filter -match 'TrustedForDelegation'
            }
        }

        It 'Should populate ServiceAccountCount when IncludeServiceAccounts is used' {
            $Result = & $FunctionName -IncludeServiceAccounts

            $Result.ServiceAccountCount | Should -Be 1
        }

    } #end Context Phase 1

    Context 'Risk Analysis and Categorization' {

        It 'Should categorize systems by risk level (High/Medium/Low)' {
            $Result = & $FunctionName

            $Result.HighRiskSystemCount | Should -BeGreaterOrEqual 0
            $Result.MediumRiskSystemCount | Should -BeGreaterOrEqual 0
            $Result.LowRiskSystemCount | Should -BeGreaterOrEqual 0
        }

        It 'Should identify high-risk systems (active, enabled, production)' {
            $Result = & $FunctionName

            # WEB-PROD01 should be high risk (active within 30 days, enabled, production location)
            $Result.HighRiskSystemCount | Should -BeGreaterThan 0
        }

        It 'Should identify medium-risk systems (active but not production)' {
            $Result = & $FunctionName

            # APP-DEV01 should be medium risk
            $Result.MediumRiskSystemCount | Should -BeGreaterThan 0
        }

        It 'Should identify low-risk systems (stale or disabled)' {
            $Result = & $FunctionName

            # LEGACY-SRV01 should be low risk (disabled, stale)
            $Result.LowRiskSystemCount | Should -BeGreaterThan 0
        }

        It 'Should consider LastLogonDate in risk assessment (recent activity = higher risk)' {
            $Result = & $FunctionName

            # Systems with recent logon dates (within 30 days) should be higher risk
            $Result.HighRiskSystemCount -or $Result.MediumRiskSystemCount | Should -BeGreaterThan 0
        }

        It 'Should consider legacy operating systems in risk assessment' {
            $Result = & $FunctionName

            # LEGACY-SRV01 with Server 2008 R2 should be flagged
            $Result.LowRiskSystemCount | Should -BeGreaterThan 0
        }

        It 'Should consider production location in risk assessment' {
            $Result = & $FunctionName

            # WEB-PROD01 in Production OU should be high risk
            $Result.HighRiskSystemCount | Should -BeGreaterThan 0
        }

    } #end Context Risk Analysis

    Context 'Phase 2: Protected Users and Privileged Account Analysis' {

        It 'Should query Protected Users group when CheckProtectedUsers is specified' {
            $Result = & $FunctionName -CheckProtectedUsers

            Should -Invoke -CommandName Get-ADGroup -Times 1 -Exactly -ParameterFilter {
                $Identity -eq 'Protected Users'
            }
        }

        It 'Should query privileged groups (Domain Admins, Enterprise Admins, etc.)' {
            $Result = & $FunctionName -CheckProtectedUsers

            Should -Invoke -CommandName Get-ADGroup -Times 1 -Exactly -ParameterFilter {
                $Identity -eq 'Domain Admins'
            }
        }

        It 'Should get members of privileged groups' {
            $Result = & $FunctionName -CheckProtectedUsers

            Should -Invoke -CommandName Get-ADGroup -ParameterFilter {
                $Identity -in @('Domain Admins', 'Enterprise Admins', 'Schema Admins')
            }
        }

        It 'Should check AccountNotDelegated property for privileged accounts' {
            $Result = & $FunctionName -CheckProtectedUsers

            Should -Invoke -CommandName Get-ADUser -ParameterFilter {
                $Properties -contains 'AccountNotDelegated'
            }
        }

        It 'Should populate PrivilegedAccountCount when CheckProtectedUsers is specified' {
            $Result = & $FunctionName -CheckProtectedUsers

            $Result.PrivilegedAccountCount | Should -Not -BeNullOrEmpty
            $Result.PrivilegedAccountCount | Should -BeGreaterThan 0
        }

        It 'Should populate VulnerablePrivilegedAccountCount when CheckProtectedUsers is specified' {
            $Result = & $FunctionName -CheckProtectedUsers

            $Result.VulnerablePrivilegedAccountCount | Should -Not -BeNullOrEmpty
        }

        It 'Should identify privileged accounts not in Protected Users group' {
            $Result = & $FunctionName -CheckProtectedUsers

            # VulnerableAdmin should be identified (not in Protected Users, not AccountNotDelegated)
            $Result.VulnerablePrivilegedAccountCount | Should -BeGreaterThan 0
        }

        It 'Should set PrivilegedAccountCount to null when CheckProtectedUsers is not specified' {
            $Result = & $FunctionName

            $Result.PrivilegedAccountCount | Should -BeNullOrEmpty
        }

    } #end Context Phase 2

    Context 'Security Assessment' {

        It 'Should set IsSecure to true when no non-DC systems have delegation' {
            # Mock Get-ADComputer to return only DC
            Mock -CommandName Get-ADComputer -MockWith {
                return @(
                    [PSCustomObject]@{
                        Name                    = 'DC01'
                        TrustedForDelegation    = $true
                        PrimaryGroupID          = 516  # Domain Controllers
                        LastLogonDate           = (Get-Date).AddDays(-1)
                        OperatingSystem         = 'Windows Server 2022'
                        Enabled                 = $true
                        CanonicalName           = 'contoso.com/Domain Controllers/DC01'
                        Description             = 'DC'
                        Created                 = (Get-Date).AddYears(-1)
                        DistinguishedName       = 'CN=DC01,OU=Domain Controllers,DC=contoso,DC=com'
                    }
                )
            }

            $Result = & $FunctionName

            $Result.IsSecure | Should -Be $true
        }

        It 'Should set IsSecure to false when non-DC systems have delegation' {
            $Result = & $FunctionName

            $Result.IsSecure | Should -Be $false
        }

        It 'Should provide recommended action for secure configuration' {
            # Mock Get-ADComputer to return only DC
            Mock -CommandName Get-ADComputer -MockWith {
                return @(
                    [PSCustomObject]@{
                        Name                    = 'DC01'
                        TrustedForDelegation    = $true
                        PrimaryGroupID          = 516
                        LastLogonDate           = (Get-Date).AddDays(-1)
                        OperatingSystem         = 'Windows Server 2022'
                        Enabled                 = $true
                        CanonicalName           = 'contoso.com/Domain Controllers/DC01'
                        Description             = 'DC'
                        Created                 = (Get-Date).AddYears(-1)
                        DistinguishedName       = 'CN=DC01,OU=Domain Controllers,DC=contoso,DC=com'
                    }
                )
            }

            $Result = & $FunctionName

            $Result.RecommendedAction | Should -Match 'Continue monitoring'
        }

        It 'Should provide recommended action for insecure configuration' {
            $Result = & $FunctionName

            $Result.RecommendedAction | Should -Match 'IMMEDIATE ACTION'
            $Result.RecommendedAction | Should -Match 'Remove unconstrained delegation'
        }

    } #end Context Security Assessment

    Context 'Export Functionality' {

        It 'Should export delegated computers to CSV when ExportPath is specified' {
            $Result = & $FunctionName -ExportPath 'C:\Logs'

            Should -Invoke -CommandName Export-Csv -Times 1 -Exactly -ParameterFilter {
                $Path -match 'UnconstrainedDelegation-Computers-\d{8}-\d{6}\.csv'
            }
        }

        It 'Should export delegated service accounts to CSV when IncludeServiceAccounts is used' {
            $Result = & $FunctionName -IncludeServiceAccounts -ExportPath 'C:\Logs'

            Should -Invoke -CommandName Export-Csv -Times 1 -Exactly -ParameterFilter {
                $Path -match 'UnconstrainedDelegation-ServiceAccounts-\d{8}-\d{6}\.csv'
            }
        }

        It 'Should export vulnerable admins to CSV when CheckProtectedUsers finds vulnerabilities' {
            $Result = & $FunctionName -CheckProtectedUsers -ExportPath 'C:\Logs'

            Should -Invoke -CommandName Export-Csv -Times 1 -Exactly -ParameterFilter {
                $Path -match 'UnconstrainedDelegation-VulnerableAdmins-\d{8}-\d{6}\.csv'
            }
        }

        It 'Should export summary report to text file' {
            $Result = & $FunctionName -ExportPath 'C:\Logs'

            Should -Invoke -CommandName Out-File -Times 1 -Exactly -ParameterFilter {
                $FilePath -match 'UnconstrainedDelegation-Summary-\d{8}-\d{6}\.txt'
            }
        }

        It 'Should create export directory if it does not exist' {
            $Result = & $FunctionName -ExportPath 'C:\NewLogs'

            Should -Invoke -CommandName New-Item -Times 1 -Exactly -ParameterFilter {
                $ItemType -eq 'Directory' -and $Path -eq 'C:\NewLogs'
            }
        }

        It 'Should populate ExportedReports array with file paths' {
            $Result = & $FunctionName -ExportPath 'C:\Logs'

            $Result.ExportedReports | Should -Not -BeNullOrEmpty
            $Result.ExportedReports.Count | Should -BeGreaterThan 0
        }

        It 'Should respect WhatIf parameter and not export reports' {
            $Result = & $FunctionName -ExportPath 'C:\Logs' -WhatIf

            Should -Invoke -CommandName Export-Csv -Times 0 -Exactly
            Should -Invoke -CommandName Out-File -Times 0 -Exactly
        }

        It 'Should include timestamp in export filenames' {
            $Result = & $FunctionName -ExportPath 'C:\Logs'

            # Verify timestamp pattern (yyyyMMdd-HHmmss)
            Should -Invoke -CommandName Out-File -Times 1 -Exactly -ParameterFilter {
                $FilePath -match '\d{8}-\d{6}'
            }
        }

        It 'Should export all report types when all switches are enabled' {
            $Result = & $FunctionName -IncludeServiceAccounts -CheckProtectedUsers -ExportPath 'C:\Logs'

            # Should export: computers, service accounts, vulnerable admins, summary = 4 files
            $Result.ExportedReports.Count | Should -BeGreaterOrEqual 4
        }

    } #end Context Export Functionality

    Context 'Error Handling' {

        It 'Should handle Get-ADDomain failures gracefully' {
            Mock -CommandName Get-ADDomain -MockWith {
                throw 'Access denied'
            }

            { & $FunctionName -ErrorAction Stop } | Should -Throw
        }

        It 'Should handle Get-ADComputer failures gracefully' {
            Mock -CommandName Get-ADComputer -MockWith {
                throw 'Insufficient permissions'
            }

            { & $FunctionName -ErrorAction Stop } | Should -Throw
        }

        It 'Should continue when Protected Users group is not found (legacy domains)' {
            Mock -CommandName Get-ADGroup -MockWith {
                param($Identity)
                if ($Identity -eq 'Protected Users') {
                    throw 'Group not found'
                }
            }

            $Result = & $FunctionName -CheckProtectedUsers -WarningVariable Warnings -WarningAction SilentlyContinue

            $Result | Should -Not -BeNullOrEmpty
        }

        It 'Should continue when individual privileged groups are not found' {
            Mock -CommandName Get-ADGroup -MockWith {
                param($Identity)
                if ($Identity -eq 'Account Operators') {
                    throw 'Group not found'
                }
                # Return mock for other groups
                return [PSCustomObject]@{
                    Name               = $Identity
                    DistinguishedName  = "CN=$Identity,CN=Users,DC=contoso,DC=com"
                    Members            = @()
                }
            }

            $Result = & $FunctionName -CheckProtectedUsers -WarningVariable Warnings -WarningAction SilentlyContinue

            $Result | Should -Not -BeNullOrEmpty
        }

        It 'Should handle export directory creation failures' {
            Mock -CommandName New-Item -MockWith {
                throw 'Access denied'
            }

            { & $FunctionName -ExportPath 'C:\ProtectedPath' -ErrorAction Stop } | Should -Throw
        }

        It 'Should continue when CSV export fails for individual files' {
            Mock -CommandName Export-Csv -MockWith {
                throw 'Disk full'
            }

            $Result = & $FunctionName -ExportPath 'C:\Logs' -WarningVariable Warnings -WarningAction SilentlyContinue

            $Result | Should -Not -BeNullOrEmpty
        }

    } #end Context Error Handling

    Context 'Remediation Guidance' {

        It 'Should recommend removing delegation from non-DC systems' {
            $Result = & $FunctionName

            $Result.RecommendedAction | Should -Match 'Remove unconstrained delegation'
        }

        It 'Should recommend migrating to constrained delegation or RBCD' {
            $Result = & $FunctionName

            $Result.RecommendedAction | Should -Match 'constrained delegation|RBCD'
        }

        It 'Should recommend monitoring for secure configurations' {
            # Mock Get-ADComputer to return only DC
            Mock -CommandName Get-ADComputer -MockWith {
                return @(
                    [PSCustomObject]@{
                        Name                    = 'DC01'
                        TrustedForDelegation    = $true
                        PrimaryGroupID          = 516
                        LastLogonDate           = (Get-Date).AddDays(-1)
                        OperatingSystem         = 'Windows Server 2022'
                        Enabled                 = $true
                        CanonicalName           = 'contoso.com/Domain Controllers/DC01'
                        Description             = 'DC'
                        Created                 = (Get-Date).AddYears(-1)
                        DistinguishedName       = 'CN=DC01,OU=Domain Controllers,DC=contoso,DC=com'
                    }
                )
            }

            $Result = & $FunctionName

            $Result.RecommendedAction | Should -Match 'monitoring'
        }

        It 'Should provide SIEM alerting guidance in recommended actions' {
            $Result = & $FunctionName

            $Result.RecommendedAction | Should -Match 'SIEM|Event|5136'
        }

    } #end Context Remediation Guidance

    Context 'Output Object Structure' {

        It 'Should have all required properties in output object' {
            $Result = & $FunctionName

            $Result | Should -HaveProperty 'PSTypeName'
            $Result | Should -HaveProperty 'DomainName'
            $Result | Should -HaveProperty 'DomainControllerCount'
            $Result | Should -HaveProperty 'NonDCComputerCount'
            $Result | Should -HaveProperty 'HighRiskSystemCount'
            $Result | Should -HaveProperty 'MediumRiskSystemCount'
            $Result | Should -HaveProperty 'LowRiskSystemCount'
            $Result | Should -HaveProperty 'ServiceAccountCount'
            $Result | Should -HaveProperty 'IsSecure'
            $Result | Should -HaveProperty 'RecommendedAction'
            $Result | Should -HaveProperty 'AuditDate'
        }

        It 'Should have correct PSTypeName' {
            $Result = & $FunctionName

            $Result.PSTypeName | Should -Be 'EguibarIT.Security.UnconstrainedDelegationAudit'
        }

        It 'Should sum risk categories to total non-DC count' {
            $Result = & $FunctionName

            $TotalRisk = $Result.HighRiskSystemCount + $Result.MediumRiskSystemCount + $Result.LowRiskSystemCount
            $TotalRisk | Should -Be $Result.NonDCComputerCount
        }

    } #end Context Output Object Structure

} #end Describe Get-UnconstrainedDelegation

} #end Describe Setup Wrapper
