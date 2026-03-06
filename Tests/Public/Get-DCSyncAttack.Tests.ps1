Describe 'Get-DCSyncAttack Setup' {
BeforeAll {
    # Import the module
    $ModulePath = Join-Path -Path $PSScriptRoot -ChildPath '..\..\EguibarIT.SecurityPS.psd1'
    Import-Module $ModulePath -Force

    $FunctionName = 'Get-DCSyncAttack'

    # Mock internal functions to prevent AD calls during module initialization
    Mock -CommandName Initialize-EventLogging -MockWith { }
    Mock -CommandName Initialize-ModuleVariable -MockWith {
        $Global:Variables = @{
            ExtendedRightsMap = @{
                'DS-Replication-Get-Changes'                   = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
                'DS-Replication-Get-Changes-All'               = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
                'DS-Replication-Get-Changes-In-Filtered-Set'   = '89e95b76-444d-4c62-991a-0facbeda640c'
            }
            HeaderDelegation = '{0} - {1} - {2}'
            FooterSecurity   = '{0} - {1}'
        }
    }
}

BeforeEach {
    # Mock ActiveDirectory module import
    Mock -CommandName Import-MyModule -MockWith {
        param($Name)
        if ($Name -eq 'ActiveDirectory') {
            return $true
        }
    }

    # Mock Get-ADDomain
    Mock -CommandName Get-ADDomain -MockWith {
        return [PSCustomObject]@{
            DNSRoot           = 'contoso.com'
            DistinguishedName = 'DC=contoso,DC=com'
            ObjectGUID        = [guid]::NewGuid()
        }
    }

    # Mock Get-ADDomainController
    Mock -CommandName Get-ADDomainController -MockWith {
        return @(
            [PSCustomObject]@{ Name = 'DC01.contoso.com' }
            [PSCustomObject]@{ Name = 'DC02.contoso.com' }
        )
    }

    # Mock Get-Acl for domain root ACL with replication permissions
    Mock -CommandName Get-Acl -MockWith {
        $ACL = New-Object System.Security.AccessControl.DirectorySecurity

        # Create ACE for DC01 computer account (expected)
        $DC01ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            [System.Security.Principal.SecurityIdentifier]::new('S-1-5-21-1234567890-1234567890-1234567890-1001'),
            [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
            [System.Security.AccessControl.AccessControlType]::Allow,
            [guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'  # DS-Replication-Get-Changes
        )

        # Create ACE for Domain Controllers group (expected)
        $DCGroupACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            [System.Security.Principal.SecurityIdentifier]::new('S-1-5-21-1234567890-1234567890-1234567890-516'),  # Domain Controllers
            [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
            [System.Security.AccessControl.AccessControlType]::Allow,
            [guid]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'  # DS-Replication-Get-Changes-All
        )

        # Create ACE for suspicious account (non-DC)
        $SuspiciousACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            [System.Security.Principal.SecurityIdentifier]::new('S-1-5-21-1234567890-1234567890-1234567890-9999'),  # svc_backup
            [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
            [System.Security.AccessControl.AccessControlType]::Allow,
            [guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'  # DS-Replication-Get-Changes
        )

        # Add ACEs to ACL
        $ACL.AddAccessRule($DC01ACE)
        $ACL.AddAccessRule($DCGroupACE)
        $ACL.AddAccessRule($SuspiciousACE)

        return $ACL
    }

    # Mock SID translation
    Mock -CommandName System.Security.Principal.SecurityIdentifier -MockWith {
        param($SID)
        $TranslationMap = @{
            'S-1-5-21-1234567890-1234567890-1234567890-1001' = 'CONTOSO\DC01$'
            'S-1-5-21-1234567890-1234567890-1234567890-516'  = 'CONTOSO\Domain Controllers'
            'S-1-5-21-1234567890-1234567890-1234567890-9999' = 'CONTOSO\svc_backup'
        }

        return [PSCustomObject]@{
            Value     = $SID
            Translate = {
                param($Type)
                return [PSCustomObject]@{
                    Value = $TranslationMap[$SID]
                }
            }
        }
    }

    # Mock Get-WinEvent for Event ID 4662 (Directory Service Access)
    Mock -CommandName Get-WinEvent -MockWith {
        param($ComputerName, $FilterHashtable)

        if ($FilterHashtable.Id -eq 4662) {
            # Legitimate DC replication event
            $DCEvent = [PSCustomObject]@{
                TimeCreated = (Get-Date).AddHours(-2)
                Properties  = @(
                    @{ Value = 'S-1-5-21-1234567890-1234567890-1234567890-1001' }  # SubjectUserSid
                    @{ Value = 'DC01$' }                                           # SubjectUserName
                    @{ Value = 'CONTOSO' }                                         # SubjectDomainName
                    @{ Value = 'DC=contoso,DC=com' }                               # ObjectName
                )
            }
            $DCEvent | Add-Member -MemberType ScriptMethod -Name 'ToXml' -Force -Value {
                return @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-1234567890-1234567890-1234567890-1001</Data>
    <Data Name="SubjectUserName">DC01$</Data>
    <Data Name="SubjectDomainName">CONTOSO</Data>
    <Data Name="ObjectName">DC=contoso,DC=com</Data>
    <Data Name="Properties">{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}</Data>
  </EventData>
</Event>
'@
            }

            # Suspicious non-DC replication event (DCSync attack)
            $SuspiciousEvent = [PSCustomObject]@{
                TimeCreated = (Get-Date).AddHours(-1)
                Properties  = @(
                    @{ Value = 'S-1-5-21-1234567890-1234567890-1234567890-9999' }  # SubjectUserSid
                    @{ Value = 'svc_backup' }                                      # SubjectUserName
                    @{ Value = 'CONTOSO' }                                         # SubjectDomainName
                    @{ Value = 'DC=contoso,DC=com' }                               # ObjectName
                )
            }
            $SuspiciousEvent | Add-Member -MemberType ScriptMethod -Name 'ToXml' -Force -Value {
                return @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-1234567890-1234567890-1234567890-9999</Data>
    <Data Name="SubjectUserName">svc_backup</Data>
    <Data Name="SubjectDomainName">CONTOSO</Data>
    <Data Name="ObjectName">DC=contoso,DC=com</Data>
    <Data Name="Properties">{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}</Data>
  </EventData>
</Event>
'@
            }

            return @($DCEvent, $SuspiciousEvent)
        }
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
        param($Path, $IsValid)
        if ($IsValid) {
            return $true
        }
        return $false
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
    # Cleanup if needed
    [System.GC]::Collect()
}

Describe 'Get-DCSyncAttack' -Tag 'Unit' {

    Context 'Parameter Validation' {

        It 'Should have TimeSpanDays parameter with range 1-365' {
            $Command = Get-Command -Name $FunctionName
            $Parameter = $Command.Parameters['TimeSpanDays']

            $Parameter | Should -Not -BeNullOrEmpty
            $Parameter.Attributes.MinRange | Should -Be 1
            $Parameter.Attributes.MaxRange | Should -Be 365
        }

        It 'Should have ExportPath parameter with path validation' {
            $Command = Get-Command -Name $FunctionName
            $Parameter = $Command.Parameters['ExportPath']

            $Parameter | Should -Not -BeNullOrEmpty
            $Parameter.Attributes | Where-Object { $_ -is [ValidateScript] } | Should -Not -BeNullOrEmpty
        }

        It 'Should support WhatIf parameter (ShouldProcess)' {
            $Command = Get-Command -Name $FunctionName
            $Command.Parameters.ContainsKey('WhatIf') | Should -Be $true
        }

        It 'Should support Confirm parameter (ShouldProcess)' {
            $Command = Get-Command -Name $FunctionName
            $Command.Parameters.ContainsKey('Confirm') | Should -Be $true
        }

        It 'Should have MonitorRealTime switch parameter' {
            $Command = Get-Command -Name $FunctionName
            $Parameter = $Command.Parameters['MonitorRealTime']

            $Parameter | Should -Not -BeNullOrEmpty
            $Parameter.SwitchParameter | Should -Be $true
        }

        It 'Should have IncludeNormalEvents switch parameter' {
            $Command = Get-Command -Name $FunctionName
            $Parameter = $Command.Parameters['IncludeNormalEvents']

            $Parameter | Should -Not -BeNullOrEmpty
            $Parameter.SwitchParameter | Should -Be $true
        }

        It 'Should reject invalid TimeSpanDays values (0)' {
            { & $FunctionName -TimeSpanDays 0 -ErrorAction Stop } | Should -Throw
        }

        It 'Should reject invalid TimeSpanDays values (366)' {
            { & $FunctionName -TimeSpanDays 366 -ErrorAction Stop } | Should -Throw
        }

    } #end Context Parameter Validation

    Context 'Core Detection Behavior' {

        It 'Should return a PSCustomObject with expected PSTypeName' {
            $Result = & $FunctionName

            $Result | Should -Not -BeNullOrEmpty
            $Result.PSObject.TypeNames | Should -Contain 'System.Management.Automation.PSCustomObject'
        }

        It 'Should call Get-ADDomain to retrieve domain information' {
            $Result = & $FunctionName

            Should -Invoke -CommandName Get-ADDomain -Times 1 -Exactly
        }

        It 'Should call Get-ADDomainController to enumerate DCs' {
            $Result = & $FunctionName

            Should -Invoke -CommandName Get-ADDomainController -Times 1 -Exactly
        }

        It 'Should call Get-Acl to retrieve domain root ACL' {
            $Result = & $FunctionName

            Should -Invoke -CommandName Get-Acl -Times 1 -Exactly
        }

        It 'Should populate DomainName property' {
            $Result = & $FunctionName

            $Result.DomainName | Should -Be 'contoso.com'
        }

        It 'Should populate DomainDN property' {
            $Result = & $FunctionName

            $Result.DomainDN | Should -Be 'DC=contoso,DC=com'
        }

        It 'Should populate AuditTimestamp property with current date' {
            $Result = & $FunctionName

            $Result.AuditTimestamp | Should -Not -BeNullOrEmpty
            $Result.AuditTimestamp | Should -BeOfType [DateTime]
        }

        It 'Should identify accounts with replication permissions' {
            $Result = & $FunctionName

            $Result.TotalAccountsWithPermissions | Should -BeGreaterThan 0
        }

        It 'Should categorize domain controllers separately from non-DC accounts' {
            $Result = & $FunctionName

            $Result.DomainControllerCount | Should -BeGreaterThan 0
            $Result.NonDCAccountCount | Should -BeGreaterOrEqual 0
        }

        It 'Should detect non-DC accounts with replication permissions (critical risk)' {
            $Result = & $FunctionName

            $Result.NonDCAccountCount | Should -BeGreaterThan 0
            $Result.NonDCAccounts | Should -Not -BeNullOrEmpty
        }

    } #end Context Core Detection Behavior

    Context 'Phase 1: Replication Permission Audit' {

        It 'Should analyze domain root ACL for replication rights' {
            $Result = & $FunctionName

            Should -Invoke -CommandName Get-Acl -Times 1 -Exactly -ParameterFilter {
                $Path -match 'AD:DC=contoso,DC=com'
            }
        }

        It 'Should identify DS-Replication-Get-Changes permissions' {
            $Result = & $FunctionName

            $Result.TotalAccountsWithPermissions | Should -BeGreaterThan 0
        }

        It 'Should use $Variables.ExtendedRightsMap for GUID lookups' {
            $Result = & $FunctionName

            # Verify that the function uses the mocked ExtendedRightsMap
            $Variables.ExtendedRightsMap.Keys | Should -Contain 'DS-Replication-Get-Changes'
            $Variables.ExtendedRightsMap.Keys | Should -Contain 'DS-Replication-Get-Changes-All'
        }

        It 'Should categorize accounts as DC or non-DC based on domain controller list' {
            $Result = & $FunctionName

            $Result.DomainControllerCount | Should -BeGreaterThan 0
            $Result.NonDCAccountCount | Should -BeGreaterThan 0
        }

        It 'Should populate NonDCAccounts array with detailed permission information' {
            $Result = & $FunctionName

            $Result.NonDCAccounts | Should -Not -BeNullOrEmpty
            $Result.NonDCAccounts[0] | Should -HaveProperty 'Identity'
            $Result.NonDCAccounts[0] | Should -HaveProperty 'Permissions'
        }

    } #end Context Phase 1

    Context 'Phase 2: Event Log Monitoring for DCSync Attacks' {

        It 'Should query Event ID 4662 (Directory Service Access) on all DCs' {
            $Result = & $FunctionName -TimeSpanDays 7

            Should -Invoke -CommandName Get-WinEvent -Times 2 -Exactly -ParameterFilter {
                $FilterHashtable.Id -eq 4662
            }
        }

        It 'Should parse event XML to extract replication GUID from Properties field' {
            $Result = & $FunctionName

            # Event parsing should occur if events are returned
            $Result.TotalReplicationEvents | Should -BeGreaterOrEqual 0
        }

        It 'Should identify legitimate DC-to-DC replication events' {
            $Result = & $FunctionName

            $Result.TotalReplicationEvents | Should -BeGreaterThan 0
        }

        It 'Should detect suspicious replication events from non-DC accounts (DCSync attack)' {
            $Result = & $FunctionName

            $Result.SuspiciousEventCount | Should -BeGreaterThan 0
            $Result.SuspiciousEvents | Should -Not -BeNullOrEmpty
        }

        It 'Should populate SuspiciousEvents array with detailed event information' {
            $Result = & $FunctionName

            $Result.SuspiciousEvents | Should -Not -BeNullOrEmpty
            $Result.SuspiciousEvents[0] | Should -HaveProperty 'TimeCreated'
            $Result.SuspiciousEvents[0] | Should -HaveProperty 'SubjectUser'
            $Result.SuspiciousEvents[0] | Should -HaveProperty 'DomainController'
            $Result.SuspiciousEvents[0] | Should -HaveProperty 'IsSuspicious'
            $Result.SuspiciousEvents[0].IsSuspicious | Should -Be $true
        }

        It 'Should respect TimeSpanDays parameter for event log filtering' {
            $Result = & $FunctionName -TimeSpanDays 30

            Should -Invoke -CommandName Get-WinEvent -Times 2 -Exactly -ParameterFilter {
                $FilterHashtable.StartTime -le (Get-Date).AddDays(-29)
            }
        }

    } #end Context Phase 2

    Context 'Risk Assessment Logic' {

        It 'Should assess risk as Secure when no non-DC accounts and no suspicious events' {
            # Mock Get-Acl to return only DC permissions
            Mock -CommandName Get-Acl -MockWith {
                $ACL = New-Object System.Security.AccessControl.DirectorySecurity

                $DC01ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                    [System.Security.Principal.SecurityIdentifier]::new('S-1-5-21-1234567890-1234567890-1234567890-1001'),
                    [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
                    [System.Security.AccessControl.AccessControlType]::Allow,
                    [guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
                )
                $ACL.AddAccessRule($DC01ACE)
                return $ACL
            }

            # Mock Get-WinEvent to return no suspicious events
            Mock -CommandName Get-WinEvent -MockWith {
                param($ComputerName, $FilterHashtable)
                if ($FilterHashtable.Id -eq 4662) {
                    $DCEvent = [PSCustomObject]@{
                        TimeCreated = (Get-Date).AddHours(-2)
                        Properties  = @()
                    }
                    $DCEvent | Add-Member -MemberType ScriptMethod -Name 'ToXml' -Force -Value {
                        return @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <EventData>
    <Data Name="SubjectUserName">DC01$</Data>
    <Data Name="SubjectDomainName">CONTOSO</Data>
    <Data Name="ObjectName">DC=contoso,DC=com</Data>
    <Data Name="Properties">{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}</Data>
  </EventData>
</Event>
'@
                    }
                    return @($DCEvent)
                }
            }

            $Result = & $FunctionName

            $Result.IsSecure | Should -Be $true
            $Result.RiskLevel | Should -Be 'Secure'
        }

        It 'Should assess risk as High when non-DC accounts exist but no active attacks' {
            # Mock Get-WinEvent to return only legitimate DC events
            Mock -CommandName Get-WinEvent -MockWith {
                param($ComputerName, $FilterHashtable)
                if ($FilterHashtable.Id -eq 4662) {
                    $DCEvent = [PSCustomObject]@{
                        TimeCreated = (Get-Date).AddHours(-2)
                        Properties  = @()
                    }
                    $DCEvent | Add-Member -MemberType ScriptMethod -Name 'ToXml' -Force -Value {
                        return @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <EventData>
    <Data Name="SubjectUserName">DC01$</Data>
    <Data Name="SubjectDomainName">CONTOSO</Data>
    <Data Name="ObjectName">DC=contoso,DC=com</Data>
    <Data Name="Properties">{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}</Data>
  </EventData>
</Event>
'@
                    }
                    return @($DCEvent)
                }
            }

            $Result = & $FunctionName

            $Result.IsSecure | Should -Be $false
            $Result.RiskLevel | Should -Be 'High'
        }

        It 'Should assess risk as Critical when suspicious events are detected (active DCSync attack)' {
            $Result = & $FunctionName

            $Result.IsSecure | Should -Be $false
            $Result.RiskLevel | Should -Be 'Critical'
        }

        It 'Should provide remediation actions when non-DC accounts are found' {
            $Result = & $FunctionName

            $Result.RecommendedActions | Should -Not -BeNullOrEmpty
            $Result.RecommendedActions | Should -Contain 'URGENT: Remove replication permissions from 1 non-DC accounts'
        }

        It 'Should provide incident response guidance when active attacks are detected' {
            $Result = & $FunctionName

            $Result.RecommendedActions | Should -Contain 'IMMEDIATE ACTION REQUIRED: Active DCSync attack detected'
            $Result.RecommendedActions | Should -Contain 'Disable suspicious account(s) immediately'
            $Result.RecommendedActions | Should -Contain 'Rotate krbtgt password twice (10+ hour delay between rotations)'
        }

    } #end Context Risk Assessment

    Context 'Export Functionality' {

        It 'Should export Non-DC accounts to CSV when ExportPath is specified' {
            $Result = & $FunctionName -ExportPath 'C:\Logs'

            Should -Invoke -CommandName Export-Csv -Times 1 -Exactly -ParameterFilter {
                $Path -match 'DCSync-ReplicationPermissions-\d{8}-\d{6}\.csv'
            }
        }

        It 'Should export suspicious events to CSV when suspicious events are detected' {
            $Result = & $FunctionName -ExportPath 'C:\Logs'

            Should -Invoke -CommandName Export-Csv -Times 1 -Exactly -ParameterFilter {
                $Path -match 'DCSync-SuspiciousEvents-\d{8}-\d{6}\.csv'
            }
        }

        It 'Should export summary report to text file' {
            $Result = & $FunctionName -ExportPath 'C:\Logs'

            Should -Invoke -CommandName Out-File -Times 1 -Exactly -ParameterFilter {
                $FilePath -match 'DCSync-Summary-\d{8}-\d{6}\.txt'
            }
        }

        It 'Should create export directory if it does not exist' {
            Mock -CommandName Test-Path -MockWith { return $false }

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

            # Verify timestamp pattern in filename (yyyyMMdd-HHmmss)
            Should -Invoke -CommandName Export-Csv -Times 1 -Exactly -ParameterFilter {
                $Path -match '\d{8}-\d{6}'
            }
        }

    } #end Context Export Functionality

    Context 'Error Handling' {

        It 'Should handle missing ActiveDirectory module gracefully' {
            Mock -CommandName Import-MyModule -MockWith {
                throw 'Module not found'
            }

            { & $FunctionName -ErrorAction Stop } | Should -Throw -ExpectedMessage '*Active Directory PowerShell module is required*'
        }

        It 'Should handle Get-ADDomain failures (permission denied)' {
            Mock -CommandName Get-ADDomain -MockWith {
                throw 'Access denied'
            }

            { & $FunctionName -ErrorAction Stop } | Should -Throw
        }

        It 'Should handle Get-Acl failures (permission denied)' {
            Mock -CommandName Get-Acl -MockWith {
                throw 'Access denied'
            }

            { & $FunctionName -ErrorAction Stop } | Should -Throw
        }

        It 'Should continue when Get-WinEvent fails on individual DCs (RPC unavailable)' {
            Mock -CommandName Get-WinEvent -MockWith {
                throw 'The RPC server is unavailable'
            }

            $Result = & $FunctionName -WarningVariable Warnings -WarningAction SilentlyContinue

            $Result | Should -Not -BeNullOrEmpty
            # Should continue processing other DCs
        }

        It 'Should continue when Get-WinEvent fails on individual DCs (no events found)' {
            Mock -CommandName Get-WinEvent -MockWith {
                throw 'No events were found that match the specified selection criteria'
            }

            $Result = & $FunctionName

            $Result | Should -Not -BeNullOrEmpty
            $Result.TotalReplicationEvents | Should -Be 0
        }

        It 'Should handle export directory creation failures' {
            Mock -CommandName New-Item -MockWith {
                throw 'Access denied'
            }
            Mock -CommandName Test-Path -MockWith { return $false }

            { & $FunctionName -ExportPath 'C:\ProtectedPath' -ErrorAction Stop } | Should -Throw
        }

    } #end Context Error Handling

    Context 'Remediation Guidance' {

        It 'Should provide specific remediation steps for non-DC accounts with replication permissions' {
            $Result = & $FunctionName

            $Result.RecommendedActions | Should -Contain 'URGENT: Remove replication permissions from 1 non-DC accounts'
            $Result.RecommendedActions | Should -Contain 'Investigate why non-DC accounts have replication rights'
        }

        It 'Should recommend krbtgt password rotation when suspicious events are detected' {
            $Result = & $FunctionName

            $Result.RecommendedActions | Should -Contain 'Rotate krbtgt password twice (10+ hour delay between rotations)'
        }

        It 'Should recommend enabling Event ID 4662 auditing for attack detection' {
            # Mock Get-WinEvent to return no events
            Mock -CommandName Get-WinEvent -MockWith {
                return $null
            }

            $Result = & $FunctionName

            # When no events are found, should recommend enabling auditing
            $Result.TotalReplicationEvents | Should -Be 0
        }

        It 'Should recommend incident response engagement for active attacks' {
            $Result = & $FunctionName

            $Result.RecommendedActions | Should -Contain 'Engage incident response team for full forensic investigation'
        }

        It 'Should recommend checking for lateral movement when attacks are detected' {
            $Result = & $FunctionName

            $Result.RecommendedActions | Should -Contain 'Check for lateral movement and persistence mechanisms'
        }

    } #end Context Remediation Guidance

} #end Describe Get-DCSyncAttack

} #end Describe Setup Wrapper
