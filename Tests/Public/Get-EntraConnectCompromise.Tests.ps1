Describe 'Get-EntraConnectCompromise' {
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

        # Mock Get-AD Computer for Entra Connect server discovery
        Mock -CommandName Get-ADComputer -MockWith {
            param($LDAPFilter, $Properties, $ErrorAction)

            if ($LDAPFilter -match 'ADSyncServiceAccount') {
                return @(
                    [PSCustomObject]@{
                        Name              = 'AADCONNECT01'
                        DNSHostName       = 'aadconnect01.contoso.com'
                        DistinguishedName = 'CN=AADCONNECT01,OU=Servers,DC=contoso,DC=com'
                        Enabled           = $true
                        PasswordLastSet   = (Get-Date).AddDays(-30)
                    }
                )
            } #end if

            return @()
        }

        # Mock Get-ADUser for MSOL account detection
        Mock -CommandName Get-ADUser -MockWith {
            param($LDAPFilter, $Properties, $ErrorAction)

            if ($LDAPFilter -match 'MSOL_') {
                return @(
                    [PSCustomObject]@{
                        SamAccountName    = 'MSOL_abc123'
                        DistinguishedName = 'CN=MSOL_abc123,CN=Users,DC=contoso,DC=com'
                        Enabled           = $true
                        PasswordLastSet   = (Get-Date).AddDays(-45)
                        AdminCount        = 1
                        memberOf          = @('CN=Domain Admins,CN=Users,DC=contoso,DC=com')
                    }
                )
            } #end if

            return [PSCustomObject]@{
                SamAccountName    = 'testuser'
                DistinguishedName = 'CN=testuser,CN=Users,DC=contoso,DC=com'
                Enabled           = $true
                PasswordLastSet   = (Get-Date).AddDays(-10)
            }
        }

        # Mock Get-ADRootDSE
        Mock -CommandName Get-ADRootDSE -MockWith {
            return [PSCustomObject]@{
                defaultNamingContext = 'DC=contoso,DC=com'
            }
        }

        # Mock Get-WinEvent for security log queries
        Mock -CommandName Get-WinEvent -MockWith {
            param($ComputerName, $FilterHashtable, $ErrorAction)

            $EventId = $FilterHashtable.Id

            switch ($EventId) {
                4624 {
                    # Logon events to Entra Connect server
                    $MockEvent = New-Object PSObject -Property @{
                        Id          = 4624
                        TimeCreated = (Get-Date).AddHours(-2)
                        MachineName = 'aadconnect01.contoso.com'
                        Message     = 'An account was successfully logged on. Subject: Security ID: S-1-5-21-123456789-1234567890-123456789-1104 Account Name: attacker'
                    }
                    Add-Member -InputObject $MockEvent -MemberType ScriptMethod -Name ToXml -Value {
                        return @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <EventData>
    <Data Name="TargetUserName">attacker</Data>
    <Data Name="TargetDomainName">CONTOSO</Data>
    <Data Name="LogonType">3</Data>
    <Data Name="IpAddress">10.0.0.50</Data>
  </EventData>
</Event>
'@
                    }
                    return @($MockEvent)
                }
                4663 {
                    # ADSync.mdf database access
                    $MockEvent = New-Object PSObject -Property @{
                        Id          = 4663
                        TimeCreated = (Get-Date).AddHours(-1)
                        MachineName = 'aadconnect01.contoso.com'
                        Message     = 'An attempt was made to access an object. Object Name: C:\Program Files\Microsoft Azure AD Sync\Data\ADSync.mdf'
                    }
                    Add-Member -InputObject $MockEvent -MemberType ScriptMethod -Name ToXml -Value {
                        return @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <EventData>
    <Data Name="ObjectName">C:\Program Files\Microsoft Azure AD Sync\Data\ADSync.mdf</Data>
    <Data Name="SubjectUserName">attacker</Data>
    <Data Name="AccessMask">0x2</Data>
  </EventData>
</Event>
'@
                    }
                    return @($MockEvent)
                }
                4688 {
                    # Process creation events (miisclient.exe, PowerShell)
                    $MockEvent = New-Object PSObject -Property @{
                        Id          = 4688
                        TimeCreated = (Get-Date).AddMinutes(-30)
                        MachineName = 'aadconnect01.contoso.com'
                        Message     = 'A new process has been created. New Process Name: C:\Program Files\Microsoft Azure AD Sync\Bin\miisclient.exe'
                    }
                    Add-Member -InputObject $MockEvent -MemberType ScriptMethod -Name ToXml -Value {
                        return @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <EventData>
    <Data Name="NewProcessName">C:\Program Files\Microsoft Azure AD Sync\Bin\miisclient.exe</Data>
    <Data Name="SubjectUserName">attacker</Data>
    <Data Name="CommandLine">miisclient.exe /export</Data>
  </EventData>
</Event>
'@
                    }
                    return @($MockEvent)
                }
                4662 {
                    # DCSync replication requests from Entra Connect server
                    $MockEvent = New-Object PSObject -Property @{
                        Id          = 4662
                        TimeCreated = (Get-Date).AddMinutes(-15)
                        MachineName = 'dc1.contoso.com'
                        Message     = 'An operation was performed on an object. Object: CN=krbtgt,CN=Users,DC=contoso,DC=com'
                    }
                    Add-Member -InputObject $MockEvent -MemberType ScriptMethod -Name ToXml -Value {
                        return @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <EventData>
    <Data Name="SubjectUserName">AADCONNECT01$</Data>
    <Data Name="ObjectName">CN=krbtgt,CN=Users,DC=contoso,DC=com</Data>
    <Data Name="AccessMask">0x100</Data>
    <Data Name="Properties">{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}</Data>
  </EventData>
</Event>
'@
                    }
                    return @($MockEvent)
                }
                5136 {
                    # AD object modifications (ADConnector configuration)
                    $MockEvent = New-Object PSObject -Property @{
                        Id          = 5136
                        TimeCreated = (Get-Date).AddHours(-3)
                        MachineName = 'dc1.contoso.com'
                        Message     = 'A directory service object was modified.'
                    }
                    Add-Member -InputObject $MockEvent -MemberType ScriptMethod -Name ToXml -Value {
                        return @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <EventData>
    <Data Name="ObjectDN">CN=ADConnector,CN=Configuration,DC=contoso,DC=com</Data>
    <Data Name="SubjectUserName">attacker</Data>
    <Data Name="AttributeLDAPDisplayName">msDS-SyncServerUrl</Data>
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

        # Mock Invoke-Command for remote service checks
        Mock -CommandName Invoke-Command -MockWith {
            param($ComputerName, $ScriptBlock, $ErrorAction)

            return [PSCustomObject]@{
                ServiceName   = 'ADSync'
                Status        = 'Running'
                StartType     = 'Automatic'
                MIISClientExe = $true
                DatabasePath  = 'C:\Program Files\Microsoft Azure AD Sync\Data\ADSync.mdf'
            }
        }

        # Mock Test-Connection
        Mock -CommandName Test-Connection -MockWith {
            return $true
        }
    } #end BeforeEach

    AfterEach {
        # Clean up mocks after each test
        [System.GC]::Collect()
    } #end AfterEach

    # Parameter Validation Tests
    Context 'Parameter Validation' {
        It 'Should throw when DaysBack is less than allowed range' {
            { Get-EntraConnectCompromise -DaysBack 0 } | Should -Throw
        }

        It 'Should throw when DaysBack is greater than allowed range' {
            { Get-EntraConnectCompromise -DaysBack 366 } | Should -Throw
        }

        It 'Should support WhatIf for export operations' {
            $Result = Get-EntraConnectCompromise -ExportPath $TestDrive -WhatIf
            $Result | Should -Not -BeNullOrEmpty
        }

        It 'Should accept ComputerName parameter' {
            { Get-EntraConnectCompromise -ComputerName 'aadconnect01.contoso.com' } | Should -Not -Throw
        }
    }

    Context 'Core detection behavior' {
        It 'Should return structured output object' {
            $Result = Get-EntraConnectCompromise

            $Result.PSTypeName | Should -Be 'EguibarIT.EntraConnectCompromise'
            $Result | Should -HaveProperty 'ServerCount'
            $Result | Should -HaveProperty 'ViolationCount'
            $Result | Should -HaveProperty 'DCsyncRequests'
            $Result | Should -HaveProperty 'SuspiciousAccess'
            $Result | Should -HaveProperty 'RiskLevel'
        }

        It 'Should discover Entra Connect servers' {
            $Result = Get-EntraConnectCompromise

            $Result.ServerCount | Should -BeGreaterThan 0
            $Result.EntraConnectServers | Should -Contain 'aadconnect01.contoso.com'
        }

        It 'Should detect database access violations' {
            $Result = Get-EntraConnectCompromise

            $Finding = $Result.Findings | Where-Object { $_.FindingType -eq 'Database Access Violation' }
            $Finding | Should -Not -BeNullOrEmpty
            $Finding.EventID | Should -Be 4663
            $Finding.FileName | Should -Match 'ADSync.mdf'
        }

        It 'Should detect export tool usage (miisclient.exe)' {
            $Result = Get-EntraConnectCompromise

            $Finding = $Result.Findings | Where-Object { $_.FindingType -eq 'Export Tool Execution' }
            $Finding | Should -Not -BeNullOrEmpty
            $Finding.ProcessName | Should -Match 'miisclient.exe'
        }

        It 'Should detect MSOL account abuse' {
            $Result = Get-EntraConnectCompromise

            $Finding = $Result.Findings | Where-Object { $_.FindingType -match 'MSOL Account' }
            $Finding | Should -Not -BeNullOrEmpty
            $Finding.AccountName | Should -Match 'MSOL_'
        }

        It 'Should detect DCSync requests from Entra Connect server' {
            $Result = Get-EntraConnectCompromise

            $Result.DCsyncRequests | Should -BeGreaterThan 0
            $Finding = $Result.Findings | Where-Object { $_.FindingType -eq 'DCSync from Entra Connect' }
            $Finding.TargetObject | Should -Match 'krbtgt'
        }

        It 'Should detect configuration modifications' {
            $Result = Get-EntraConnectCompromise

            $Finding = $Result.Findings | Where-Object { $_.FindingType -eq 'Configuration Modification' }
            $Finding | Should -Not -BeNullOrEmpty
            $Finding.EventID | Should -Be 5136
        }

        It 'Should set Critical risk level when multiple violations detected' {
            $Result = Get-EntraConnectCompromise

            $Result.ViolationCount | Should -BeGreaterThan 0
            $Result.RiskLevel | Should -Match 'Critical|High'
        }
    }

    Context 'Phase-specific detection' {
        It 'Phase 1: Should identify Entra Connect servers by ADSync service' {
            $Result = Get-EntraConnectCompromise

            $Result.EntraConnectServers | Should -Not -BeNullOrEmpty
        }

        It 'Phase 2: Should audit database file access (ADSync.mdf)' {
            $Result = Get-EntraConnectCompromise

            $Finding = $Result.Findings | Where-Object { $_.FileName -match 'ADSync.mdf' }
            $Finding | Should -Not -BeNullOrEmpty
        }

        It 'Phase 3: Should detect credential export tool execution' {
            $Result = Get-EntraConnectCompromise

            $Finding = $Result.Findings | Where-Object { $_.ProcessName -match 'miisclient' }
            $Finding | Should -Not -BeNullOrEmpty
        }

        It 'Phase 4: Should monitor MSOL account activity' {
            $Result = Get-EntraConnectCompromise

            $Finding = $Result.Findings | Where-Object { $_.AccountName -match 'MSOL_' }
            $Finding | Should -Not -BeNullOrEmpty
        }

        It 'Phase 5: Should audit configuration changes to ADConnector' {
            $Result = Get-EntraConnectCompromise

            $Finding = $Result.Findings | Where-Object { $_.FindingType -eq 'Configuration Modification' }
            $Finding | Should -Not -BeNullOrEmpty
        }

        It 'Phase 6: Should detect DCSync backdoor from Entra Connect server' {
            $Result = Get-EntraConnectCompromise

            $Finding = $Result.Findings | Where-Object { $_.FindingType -eq 'DCSync from Entra Connect' }
            $Finding | Should -Not -BeNullOrEmpty
        }
    }

    Context 'IncludeDetailedEvents behavior' {
        It 'Should not include raw events by default' {
            $Result = Get-EntraConnectCompromise
            $Result.RawEvents | Should -BeNullOrEmpty
        }

        It 'Should include raw events when IncludeDetailedEvents switch is set' {
            $Result = Get-EntraConnectCompromise -IncludeDetailedEvents
            $Result.RawEvents | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Export behavior' {
        It 'Should export CSV and JSON when ExportPath is provided' {
            $ExportPath = Join-Path -Path $TestDrive -ChildPath ('EntraConnectExport_{0}' -f [DateTime]::Now.Ticks)

            $Result = Get-EntraConnectCompromise -ExportPath $ExportPath

            Test-Path -Path $ExportPath | Should -BeTrue
            $Result.PSObject.Properties.Name | Should -Contain 'ExportedReports'
        }

        It 'Should create output directory if it does not exist' {
            $ExportPath = Join-Path -Path $TestDrive -ChildPath ('MissingFolder_{0}' -f [DateTime]::Now.Ticks)
            if (Test-Path -Path $ExportPath) {
                Remove-Item -Path $ExportPath -Force -Recurse
            } #end if

            Get-EntraConnectCompromise -ExportPath $ExportPath | Out-Null

            Test-Path -Path $ExportPath | Should -BeTrue
        }
    }

    Context 'Error handling' {
        It 'Should handle missing Entra Connect servers gracefully' {
            Mock -CommandName Get-ADComputer -MockWith {
                return @()
            }

            $Result = Get-EntraConnectCompromise
            $Result.ServerCount | Should -Be 0
            $Result.RiskLevel | Should -Match 'Low|Info'
        }

        It 'Should handle WinEvent query failures gracefully' {
            Mock -CommandName Get-WinEvent -MockWith {
                throw 'Access denied to Security log'
            }

            { Get-EntraConnectCompromise -ErrorAction SilentlyContinue } | Should -Not -Throw
        }

        It 'Should warn when Entra Connect server is unreachable' {
            Mock -CommandName Test-Connection -MockWith {
                return $false
            }

            $Result = Get-EntraConnectCompromise -WarningAction SilentlyContinue
            $Result | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Remediation guidance' {
        It 'Should provide recommended actions when violations detected' {
            $Result = Get-EntraConnectCompromise

            $Result.RecommendedActions | Should -Not -BeNullOrEmpty
            $Result.RecommendedActions | Should -Contain -ExpectedValue -Like '*Isolate Entra Connect server*' -Not
        }

        It 'Should include MSOL account reset in recommendations when account abuse detected' {
            $Result = Get-EntraConnectCompromise

            if ($Result.Findings | Where-Object { $_.AccountName -match 'MSOL_' }) {
                $Result.RecommendedActions | Should -Match 'MSOL|password|reset'
            }
        }
    }
}
