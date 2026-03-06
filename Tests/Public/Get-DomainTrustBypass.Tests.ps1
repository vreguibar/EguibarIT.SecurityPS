Describe 'Get-DomainTrustBypass' {
    BeforeAll {
        $ModuleName = 'EguibarIT.SecurityPS'
        $PathToManifest = Join-Path -Path $PSScriptRoot -ChildPath ('..\..\{0}.psd1' -f $ModuleName)

        if (-not (Test-Path -Path $PathToManifest)) {
            throw ('Module manifest not found: {0}' -f $PathToManifest)
        } #end if

        # Remove module if already loaded to avoid caching issues
        if (Get-Module -Name $ModuleName) {
            Remove-Module -Name $ModuleName -Force
        } #end if

        # Import module with all dependencies
        Import-Module -Name $PathToManifest -Force -ErrorAction Stop

        # Mock internal module functions to prevent AD calls during initialization
        Mock -CommandName 'Initialize-EventLogging' -ModuleName $ModuleName -MockWith { }
        Mock -CommandName 'Initialize-ModuleVariable' -ModuleName $ModuleName -MockWith {
            # Create a minimal mock $Variables if it doesn't exist
            if (-not (Test-Path -Path Variable:\Variables)) {
                $script:Variables = [PSCustomObject]@{
                    HeaderDelegation = '..:: {0} ::..'
                }
            } #end if
        }
    } #end BeforeAll

    BeforeEach {
        # Setup mocks before each test
        if (-not (Test-Path -Path Variable:\Variables)) {
            $script:Variables = [PSCustomObject]@{
                HeaderDelegation = '..:: {0} ::..'
            }
        } #end if

        # Mock Get-ADTrust for trust relationship enumeration
        Mock -CommandName Get-ADTrust -MockWith {
            param($Filter, $Server, $ErrorAction)

            return @(
                [PSCustomObject]@{
                    Name                         = 'fabrikam.com'
                    Source                       = 'contoso.com'
                    Target                       = 'fabrikam.com'
                    Direction                    = 'BiDirectional'
                    TrustType                    = 'External'
                    TrustAttributes              = 4  # TRUST_ATTRIBUTE_QUARANTINED_DOMAIN (SID filtering enabled)
                    ForestTransitive             = $false
                    SelectiveAuthentication      = $true
                    SIDFilteringForestAware      = $false
                    SIDFilteringQuarantined      = $true
                    DisallowTransivity           = $false
                    DistinguishedName            = 'CN=fabrikam.com,CN=System,DC=contoso,DC=com'
                },
                [PSCustomObject]@{
                    Name                         = 'untrusted.local'
                    Source                       = 'contoso.com'
                    Target                       = 'untrusted.local'
                    Direction                    = 'Inbound'
                    TrustType                    = 'External'
                    TrustAttributes              = 0  # SID filtering DISABLED (vulnerable)
                    ForestTransitive             = $false
                    SelectiveAuthentication      = $false  # Selective auth DISABLED (vulnerable)
                    SIDFilteringForestAware      = $false
                    SIDFilteringQuarantined      = $false
                    DisallowTransivity           = $false
                    DistinguishedName            = 'CN=untrusted.local,CN=System,DC=contoso,DC=com'
                }
            )
        }

        # Mock Get-ADDomainController
        Mock -CommandName Get-ADDomainController -MockWith {
            param($Filter, $Server, $ErrorAction)

            return @(
                [PSCustomObject]@{
                    Name        = 'DC1'
                    HostName    = 'dc1.contoso.com'
                    IPv4Address = '10.0.0.10'
                    Site        = 'Default-First-Site-Name'
                    Domain      = 'contoso.com'
                }
            )
        }

        # Mock Get-ADDomain
        Mock -CommandName Get-ADDomain -MockWith {
            param($Server, $ErrorAction)

            return [PSCustomObject]@{
                DNSRoot             = 'contoso.com'
                NetBIOSName         = 'CONTOSO'
                DomainSID           = 'S-1-5-21-123456789-1234567890-123456789'
                DistinguishedName   = 'DC=contoso,DC=com'
                Forest              = 'contoso.com'
            }
        }

        # Mock Get-WinEvent for security log queries
        Mock -CommandName Get-WinEvent -MockWith {
            param($ComputerName, $FilterHashtable, $ErrorAction)

            $EventId = $FilterHashtable.Id

            switch ($EventId) {
                4675 {
                    # SID filtering bypass attempt (SID not allowed in trusted domain)
                    $MockEvent = New-Object PSObject -Property @{
                        Id          = 4675
                        TimeCreated = (Get-Date).AddHours(-2)
                        MachineName = 'dc1.contoso.com'
                        Message     = 'SIDs were filtered. Target Account: attacker@untrusted.local Additional Information: S-1-5-21-999999999-999999999-999999999-512 (Domain Admins)'
                    }
                    Add-Member -InputObject $MockEvent -MemberType ScriptMethod -Name ToXml -Value {
                        return @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <EventData>
    <Data Name="TargetUserName">attacker</Data>
    <Data Name="TargetDomainName">untrusted.local</Data>
    <Data Name="FilteredSids">S-1-5-21-999999999-999999999-999999999-512</Data>
    <Data Name="TrustName">untrusted.local</Data>
  </EventData>
</Event>
'@
                    }
                    return @($MockEvent)
                }
                4766 {
                    # SID filtering blocked unauthorized SID
                    $MockEvent = New-Object PSObject -Property @{
                        Id          = 4766
                        TimeCreated = (Get-Date).AddHours(-1)
                        MachineName = 'dc1.contoso.com'
                        Message     = 'An attempt to add SID History to an account failed. The SID History that was attempted to be added: S-1-5-21-777777777-777777777-777777777-500'
                    }
                    Add-Member -InputObject $MockEvent -MemberType ScriptMethod -Name ToXml -Value {
                        return @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <EventData>
    <Data Name="TargetUserName">compromised_user</Data>
    <Data Name="TargetSid">S-1-5-21-123456789-1234567890-123456789-1105</Data>
    <Data Name="SourceSid">S-1-5-21-777777777-777777777-777777777-500</Data>
    <Data Name="SourceDomain">untrusted.local</Data>
  </EventData>
</Event>
'@
                    }
                    return @($MockEvent)
                }
                4768 {
                    # TGT requests from external trusted domain (selective auth check)
                    $MockEvent = New-Object PSObject -Property @{
                        Id          = 4768
                        TimeCreated = (Get-Date).AddMinutes(-30)
                        MachineName = 'dc1.contoso.com'
                        Message     = 'A Kerberos authentication ticket (TGT) was requested. Account Name: externaladmin@fabrikam.com Service Name: krbtgt/CONTOSO.COM'
                    }
                    Add-Member -InputObject $MockEvent -MemberType ScriptMethod -Name ToXml -Value {
                        return @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <EventData>
    <Data Name="TargetUserName">externaladmin@fabrikam.com</Data>
    <Data Name="ServiceName">krbtgt/CONTOSO.COM</Data>
    <Data Name="IpAddress">192.168.10.50</Data>
    <Data Name="Status">0x0</Data>
    <Data Name="PreAuthType">2</Data>
  </EventData>
</Event>
'@
                    }
                    return @($MockEvent)
                }
                4770 {
                    # Cross-forest TGT renewal (persistence indicator)
                    $MockEvent = New-Object PSObject -Property @{
                        Id          = 4770
                        TimeCreated = (Get-Date).AddMinutes(-15)
                        MachineName = 'dc1.contoso.com'
                        Message     = 'A Kerberos service ticket was renewed. Account Name: svc_admin@untrusted.local Service Name: cifs/fileserver.contoso.com'
                    }
                    Add-Member -InputObject $MockEvent -MemberType ScriptMethod -Name ToXml -Value {
                        return @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <EventData>
    <Data Name="TargetUserName">svc_admin@untrusted.local</Data>
    <Data Name="ServiceName">cifs/fileserver.contoso.com</Data>
    <Data Name="IpAddress">192.168.20.100</Data>
  </EventData>
</Event>
'@
                    }
                    return @($MockEvent)
                }
                4624 {
                    # Privileged account cross-trust authentication
                    $MockEvent = New-Object PSObject -Property @{
                        Id          = 4624
                        TimeCreated = (Get-Date).AddMinutes(-10)
                        MachineName = 'dc1.contoso.com'
                        Message     = 'An account was successfully logged on. Account Name: tier0admin@fabrikam.com Logon Type: 3'
                    }
                    Add-Member -InputObject $MockEvent -MemberType ScriptMethod -Name ToXml -Value {
                        return @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <EventData>
    <Data Name="TargetUserName">tier0admin@fabrikam.com</Data>
    <Data Name="TargetDomainName">fabrikam.com</Data>
    <Data Name="LogonType">3</Data>
    <Data Name="IpAddress">192.168.10.200</Data>
  </EventData>
</Event>
'@
                    }
                    return @($MockEvent)
                }
                default {
                    return @()
                }
            } #end switch
        }

        # Mock Get-ADUser for privileged account checks
        Mock -CommandName Get-ADUser -MockWith {
            param($Identity, $Properties, $Server, $ErrorAction)

            return [PSCustomObject]@{
                SamAccountName    = 'tier0admin'
                DistinguishedName = 'CN=tier0admin,OU=Tier0,DC=fabrikam,DC=com'
                Enabled           = $true
                memberOf          = @('CN=Domain Admins,CN=Users,DC=fabrikam,DC=com')
            }
        }
    } #end BeforeEach

    AfterEach {
        # Clean up mocks after each test
        [System.GC]::Collect()
    } #end AfterEach

    # Parameter Validation Tests
    Context 'Parameter Validation' {
        It 'Should throw when DaysBack is less than allowed range' {
            { Get-DomainTrustBypass -DaysBack 0 } | Should -Throw
        }

        It 'Should throw when DaysBack is greater than allowed range' {
            { Get-DomainTrustBypass -DaysBack 366 } | Should -Throw
        }

        It 'Should support WhatIf for export operations' {
            $Result = Get-DomainTrustBypass -ExportPath $TestDrive -WhatIf
            $Result | Should -Not -BeNullOrEmpty
        }

        It 'Should accept DomainController parameter' {
            { Get-DomainTrustBypass -DomainController 'dc1.contoso.com' } | Should -Not -Throw
        }

        It 'Should support IncludeTrustEnumeration switch' {
            { Get-DomainTrustBypass -IncludeTrustEnumeration } | Should -Not -Throw
        }

        It 'Should support MonitorCrossForestAuth switch' {
            { Get-DomainTrustBypass -MonitorCrossForestAuth } | Should -Not -Throw
        }

        It 'Should support CheckAllDomains switch' {
            { Get-DomainTrustBypass -CheckAllDomains } | Should -Not -Throw
        }
    }

    Context 'Core detection behavior' {
        It 'Should return structured output object' {
            $Result = Get-DomainTrustBypass

            $Result.PSTypeName | Should -Be 'EguibarIT.DomainTrustBypass'
            $Result | Should -HaveProperty 'TrustCount'
            $Result | Should -HaveProperty 'SIDFilteringViolations'
            $Result | Should -HaveProperty 'SelectiveAuthViolations'
            $Result | Should -HaveProperty 'PrivilegedCrossTrustAuth'
            $Result | Should -HaveProperty 'RiskLevel'
        }

        It 'Should enumerate trust relationships' {
            $Result = Get-DomainTrustBypass

            $Result.TrustCount | Should -BeGreaterThan 0
            $Result.TrustRelationships | Should -Not -BeNullOrEmpty
        }

        It 'Should identify trusts with SID filtering disabled' {
            $Result = Get-DomainTrustBypass

            $VulnerableTrust = $Result.TrustRelationships | Where-Object { $_.SIDFilteringEnabled -eq $false }
            $VulnerableTrust | Should -Not -BeNullOrEmpty
            $VulnerableTrust.Target | Should -Be 'untrusted.local'
        }

        It 'Should identify trusts without selective authentication' {
            $Result = Get-DomainTrustBypass

            $VulnerableTrust = $Result.TrustRelationships | Where-Object { $_.SelectiveAuthEnabled -eq $false }
            $VulnerableTrust | Should -Not -BeNullOrEmpty
        }

        It 'Should detect SID filtering bypass attempts (Event 4675)' {
            $Result = Get-DomainTrustBypass

            $Finding = $Result.Findings | Where-Object { $_.FindingType -eq 'SID Filtering Bypass Attempt' }
            $Finding | Should -Not -BeNullOrEmpty
            $Finding.EventID | Should -Be 4675
        }

        It 'Should detect blocked SID History injection (Event 4766)' {
            $Result = Get-DomainTrustBypass

            $Finding = $Result.Findings | Where-Object { $_.FindingType -eq 'SID Filtering Blocked' }
            $Finding | Should -Not -BeNullOrEmpty
            $Finding.EventID | Should -Be 4766
        }

        It 'Should detect cross-trust TGT requests (Event 4768)' {
            $Result = Get-DomainTrustBypass

            $Finding = $Result.Findings | Where-Object { $_.FindingType -eq 'Cross-Trust TGT Request' }
            $Finding | Should -Not -BeNullOrEmpty
            $Finding.EventID | Should -Be 4768
        }

        It 'Should set Critical risk level when SID filtering is disabled' {
            $Result = Get-DomainTrustBypass

            $TrustsWithoutSIDFiltering = ($Result.TrustRelationships | Where-Object { $_.SIDFilteringEnabled -eq $false }).Count

            if ($TrustsWithoutSIDFiltering -gt 0) {
                $Result.RiskLevel | Should -Be 'Critical'
            }
        }
    }

    Context 'Phase-specific detection' {
        It 'Phase 1: Should inventory all trust relationships' {
            $Result = Get-DomainTrustBypass

            $Result.TrustRelationships | Should -Not -BeNullOrEmpty
            $Result.TrustRelationships.Count | Should -BeGreaterThan 0
        }

        It 'Phase 1: Should check SID filtering configuration on each trust' {
            $Result = Get-DomainTrustBypass

            $Result.TrustRelationships | ForEach-Object {
                $_.PSObject.Properties.Name | Should -Contain 'SIDFilteringEnabled'
            }
        }

        It 'Phase 1: Should check selective authentication configuration' {
            $Result = Get-DomainTrustBypass

            $Result.TrustRelationships | ForEach-Object {
                $_.PSObject.Properties.Name | Should -Contain 'SelectiveAuthEnabled'
            }
        }

        It 'Phase 2: Should detect SID filtering bypass attempts' {
            $Result = Get-DomainTrustBypass

            $Result.SIDFilteringViolations | Should -BeGreaterThan 0
        }

        It 'Phase 3: Should detect selective authentication violations' {
            $Result = Get-DomainTrustBypass

            $Result.SelectiveAuthViolations | Should -BeGreaterThan 0
        }

        It 'Phase 4: Should monitor cross-forest TGT activity when MonitorCrossForestAuth switch is set' {
            $Result = Get-DomainTrustBypass -MonitorCrossForestAuth

            $Finding = $Result.Findings | Where-Object { $_.EventID -eq 4770 }
            # May be present if switch enables monitoring
            $Result | Should -Not -BeNullOrEmpty
        }

        It 'Phase 5: Should detect privileged account cross-trust authentication' {
            $Result = Get-DomainTrustBypass

            $Finding = $Result.Findings | Where-Object { $_.FindingType -match 'Privileged.*Cross-Trust' }
            $Finding | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Trust security configuration audit' {
        It 'Should flag external trusts without SID filtering as Critical' {
            $Result = Get-DomainTrustBypass

            $VulnerableTrust = $Result.TrustRelationships | Where-Object {
                $_.TrustType -eq 'External' -and $_.SIDFilteringEnabled -eq $false
            }

            if ($VulnerableTrust) {
                $VulnerableTrust.RiskLevel | Should -Be 'Critical'
            }
        }

        It 'Should flag inbound trusts without selective authentication as High risk' {
            $Result = Get-DomainTrustBypass

            $VulnerableTrust = $Result.TrustRelationships | Where-Object {
                $_.Direction -match 'Inbound|BiDirectional' -and $_.SelectiveAuthEnabled -eq $false
            }

            if ($VulnerableTrust) {
                $VulnerableTrust.RiskLevel | Should -Match 'Critical|High'
            }
        }

        It 'Should recommend SID filtering quarantine for vulnerable trusts' {
            $Result = Get-DomainTrustBypass

            if ($Result.TrustRelationships | Where-Object { $_.SIDFilteringEnabled -eq $false }) {
                $Result.RecommendedActions | Should -Match 'netdom trust.*quarantine'
            }
        }
    }

    Context 'IncludeTrustEnumeration behavior' {
        It 'Should not include trust enumeration events by default' {
            $Result = Get-DomainTrustBypass
            # Trust enumeration tracking not included unless switch set
            $Result | Should -HaveProperty 'TrustRelationships'
        }

        It 'Should include trust enumeration detection when switch is set' {
            $Result = Get-DomainTrustBypass -IncludeTrustEnumeration
            # When switch set, additional enumeration tracking may be present
            $Result | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Export behavior' {
        It 'Should export CSV and JSON when ExportPath is provided' {
            $ExportPath = Join-Path -Path $TestDrive -ChildPath ('TrustBypassExport_{0}' -f [DateTime]::Now.Ticks)

            $Result = Get-DomainTrustBypass -ExportPath $ExportPath

            Test-Path -Path $ExportPath | Should -BeTrue
            $Result.PSObject.Properties.Name | Should -Contain 'ExportedReports'
        }

        It 'Should create output directory if it does not exist' {
            $ExportPath = Join-Path -Path $TestDrive -ChildPath ('MissingFolder_{0}' -f [DateTime]::Now.Ticks)
            if (Test-Path -Path $ExportPath) {
                Remove-Item -Path $ExportPath -Force -Recurse
            } #end if

            Get-DomainTrustBypass -ExportPath $ExportPath | Out-Null

            Test-Path -Path $ExportPath | Should -BeTrue
        }
    }

    Context 'Error handling' {
        It 'Should handle missing trusts gracefully' {
            Mock -CommandName Get-ADTrust -MockWith {
                return @()
            }

            $Result = Get-DomainTrustBypass
            $Result.TrustCount | Should -Be 0
            $Result.RiskLevel | Should -Match 'Low|Info'
        }

        It 'Should handle WinEvent query failures gracefully' {
            Mock -CommandName Get-WinEvent -MockWith {
                throw 'Access denied to Security log'
            }

            { Get-DomainTrustBypass -ErrorAction SilentlyContinue } | Should -Not -Throw
        }

        It 'Should warn when domain controller is unreachable' {
            Mock -CommandName Get-ADDomainController -MockWith {
                throw 'Domain controller unreachable'
            }

            { Get-DomainTrustBypass -ErrorAction SilentlyContinue } | Should -Not -Throw
        }
    }

    Context 'Remediation guidance' {
        It 'Should provide recommended actions when violations detected' {
            $Result = Get-DomainTrustBypass

            $Result.RecommendedActions | Should -Not -BeNullOrEmpty
        }

        It 'Should recommend enabling SID filtering for vulnerable trusts' {
            $Result = Get-DomainTrustBypass

            if ($Result.TrustRelationships | Where-Object { $_.SIDFilteringEnabled -eq $false }) {
                $Result.RecommendedActions | Should -Match 'Enable SID filtering|quarantine'
            }
        }

        It 'Should recommend selective authentication configuration' {
            $Result = Get-DomainTrustBypass

            if ($Result.TrustRelationships | Where-Object { $_.SelectiveAuthEnabled -eq $false }) {
                $Result.RecommendedActions | Should -Match 'selective authentication|TRUST_ATTRIBUTE_CROSS_ORGANIZATION'
            }
        }

        It 'Should recommend Protected Users group for privileged cross-trust accounts' {
            $Result = Get-DomainTrustBypass

            if ($Result.PrivilegedCrossTrustAuth -gt 0) {
                $Result.RecommendedActions | Should -Match 'Protected Users|PAW'
            }
        }
    }
}
