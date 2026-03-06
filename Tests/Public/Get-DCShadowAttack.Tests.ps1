Describe 'Get-DCShadowAttack' {
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
        # Setup mocks before each test for each test iteration
        # Ensure Variables is defined for each test
        if (-not (Test-Path -Path Variable:\Variables)) {
            $script:Variables = [PSCustomObject]@{
                HeaderDelegation = '..:: {0} ::..'
            }
        } #end if

        Mock -CommandName Get-ADDomainController -ModuleName 'ActiveDirectory' -MockWith {
            return @(
                [PSCustomObject]@{
                    Name        = 'DC1'
                    HostName    = 'dc1.contoso.com'
                    IPv4Address = '10.0.0.10'
                    Site        = 'Default-First-Site-Name'
                },
                [PSCustomObject]@{
                    Name        = 'DC2'
                    HostName    = 'dc2.contoso.com'
                    IPv4Address = '10.0.0.11'
                    Site        = 'Default-First-Site-Name'
                }
            )
        }

        Mock -CommandName Get-ADComputer -ModuleName 'ActiveDirectory' -MockWith {
            return @(
                [PSCustomObject]@{
                    Name              = 'DC1'
                    DistinguishedName = 'CN=DC1,OU=Domain Controllers,DC=contoso,DC=com'
                },
                [PSCustomObject]@{
                    Name              = 'RogueDC'
                    DistinguishedName = 'CN=RogueDC,OU=Workstations,DC=contoso,DC=com'
                }
            )
        }

        Mock -CommandName Get-ADGroupMember -MockWith {
            param($Identity, $Recursive, $ErrorAction)

            return @(
                [PSCustomObject]@{ objectClass = 'user'; SamAccountName = 'admin1' },
                [PSCustomObject]@{ objectClass = 'user'; SamAccountName = 'admin2' }
            )
        }

        Mock -CommandName Get-ADUser -MockWith {
            param($Identity, $Properties, $ErrorAction)

            return [PSCustomObject]@{
                SamAccountName     = $Identity
                DistinguishedName  = 'CN={0},CN=Users,DC=contoso,DC=com' -f $Identity
                whenCreated        = (Get-Date).AddDays(-100)
                PasswordLastSet    = (Get-Date).AddDays(-20)
            }
        }

        Mock -CommandName Get-ADRootDSE -MockWith {
            return [PSCustomObject]@{
                defaultNamingContext = 'DC=contoso,DC=com'
            }
        }

        Mock -CommandName Get-ADReplicationAttributeMetadata -MockWith {
            param($Object, $Server, $ErrorAction)

            if ($Object -match 'AdminSDHolder') {
                return @(
                    [PSCustomObject]@{
                        AttributeName = 'nTSecurityDescriptor'
                        LastOriginatingChangeDirectoryServerIdentity = 'rogue-dc.contoso.com'
                        LastOriginatingChangeTime = (Get-Date).AddHours(-2)
                        Version = 8
                    }
                )
            } #end if

            return @(
                [PSCustomObject]@{
                    AttributeName = 'memberOf'
                    LastOriginatingChangeDirectoryServerIdentity = 'rogue-dc.contoso.com'
                    LastOriginatingChangeTime = (Get-Date).AddHours(-1)
                    Version = 5
                }
            )
        }

        Mock -CommandName Get-WinEvent -MockWith {
            param($ComputerName, $FilterHashtable, $ErrorAction)

            switch ($FilterHashtable.Id) {
                5137 {
                    $MockEvent5137 = New-MockObject -Type System.Diagnostics.Eventing.Reader.EventRecord
                    Add-Member -InputObject $MockEvent5137 -MemberType NoteProperty -Name TimeCreated -Value (Get-Date).AddHours(-4)
                    Add-Member -InputObject $MockEvent5137 -MemberType NoteProperty -Name Message -Value 'objectClass: server objectClass: nTDSDSA'
                    Add-Member -InputObject $MockEvent5137 -MemberType ScriptMethod -Name ToXml -Value {
                        return @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <EventData>
    <Data Name="ObjectDN">CN=ROGUE,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=contoso,DC=com</Data>
    <Data Name="ObjectClass">server</Data>
    <Data Name="SubjectUserName">attacker</Data>
  </EventData>
</Event>
'@
                    }
                    return @($MockEvent5137)
                }
                5141 {
                    $MockEvent5141 = New-MockObject -Type System.Diagnostics.Eventing.Reader.EventRecord
                    Add-Member -InputObject $MockEvent5141 -MemberType NoteProperty -Name TimeCreated -Value (Get-Date).AddHours(-3)
                    Add-Member -InputObject $MockEvent5141 -MemberType ScriptMethod -Name ToXml -Value {
                        return @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <EventData>
    <Data Name="ObjectDN">CN=ROGUE,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=contoso,DC=com</Data>
    <Data Name="SubjectUserName">attacker</Data>
  </EventData>
</Event>
'@
                    }
                    return @($MockEvent5141)
                }
                4742 {
                    $MockEvent4742 = New-MockObject -Type System.Diagnostics.Eventing.Reader.EventRecord
                    Add-Member -InputObject $MockEvent4742 -MemberType NoteProperty -Name TimeCreated -Value (Get-Date).AddHours(-2)
                    Add-Member -InputObject $MockEvent4742 -MemberType NoteProperty -Name Message -Value 'ServicePrincipalNames: GC/rogue.contoso.com E3514235-4B06-11D1-AB04-00C04FC2DCD2/rogue'
                    Add-Member -InputObject $MockEvent4742 -MemberType ScriptMethod -Name ToXml -Value {
                        return @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <EventData>
    <Data Name="TargetUserName">ROGUESRV$</Data>
    <Data Name="SubjectUserName">attacker</Data>
  </EventData>
</Event>
'@
                    }
                    return @($MockEvent4742)
                }
                4720 {
                    return @()
                }
                5136 {
                    $MockEvent5136 = New-MockObject -Type System.Diagnostics.Eventing.Reader.EventRecord
                    Add-Member -InputObject $MockEvent5136 -MemberType NoteProperty -Name TimeCreated -Value (Get-Date).AddHours(-1)
                    Add-Member -InputObject $MockEvent5136 -MemberType NoteProperty -Name Message -Value 'CN=AdminSDHolder,CN=System,DC=contoso,DC=com modified'
                    Add-Member -InputObject $MockEvent5136 -MemberType ScriptMethod -Name ToXml -Value {
                        return @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <EventData>
    <Data Name="AttributeLDAPDisplayName">nTSecurityDescriptor</Data>
    <Data Name="SubjectUserName">attacker</Data>
  </EventData>
</Event>
'@
                    }
                    return @($MockEvent5136)
                }
                default {
                    return @()
                }
            } #end switch
        }
    } #end BeforeEach

    AfterEach {
        # Clean up mocks after each test to avoid state leakage
        [System.GC]::Collect()
    } #end AfterEach

    # Parameter Validation Tests
    Context 'Parameter Validation' {
        It 'Should throw when DaysBack is less than allowed range' {
            { Get-DCShadowAttack -DaysBack 0 } | Should -Throw
        }

        It 'Should throw when DaysBack is greater than allowed range' {
            { Get-DCShadowAttack -DaysBack 366 } | Should -Throw
        }

        It 'Should support WhatIf for export operations' {
            $Result = Get-DCShadowAttack -OutputPath $TestDrive -WhatIf
            $Result | Should -Not -BeNullOrEmpty
            $Result.ExportedReports.Count | Should -Be 0
        }
    }

    Context 'Core detection behavior' {
        It 'Should return structured output object' {
            $Result = Get-DCShadowAttack

            $Result.PSTypeName | Should -Be 'EguibarIT.DCShadowAttack'
            $Result | Should -HaveProperty 'Findings'
            $Result | Should -HaveProperty 'CriticalCount'
            $Result | Should -HaveProperty 'RecommendedActions'
        }

        It 'Should detect rogue DC computer account outside Domain Controllers OU' {
            $Result = Get-DCShadowAttack
            $RogueFinding = $Result.Findings | Where-Object { $_.FindingType -eq 'Rogue DC Computer Account' }

            $RogueFinding | Should -Not -BeNullOrEmpty
            $RogueFinding.RiskLevel | Should -Be 'Critical'
        }

        It 'Should detect replication partner registration events' {
            $Result = Get-DCShadowAttack
            $Finding = $Result.Findings | Where-Object { $_.FindingType -eq 'Replication Partner Registration' }

            $Finding | Should -Not -BeNullOrEmpty
            $Finding.EventID | Should -Be 5141
        }

        It 'Should detect AdminSDHolder modifications' {
            $Result = Get-DCShadowAttack
            $Finding = $Result.Findings | Where-Object { $_.FindingType -eq 'AdminSDHolder Modification' }

            $Finding | Should -Not -BeNullOrEmpty
            $Finding.RiskLevel | Should -Be 'Critical'
        }

        It 'Should set compromise likely flag when critical findings exist' {
            $Result = Get-DCShadowAttack

            $Result.CriticalCount | Should -BeGreaterThan 0
            $Result.IsCompromiseLikely | Should -BeTrue
        }
    }

    Context 'IncludeEvents behavior' {
        It 'Should not include raw events by default' {
            $Result = Get-DCShadowAttack
            $Result.IncludedRawEvents | Should -BeNullOrEmpty
        }

        It 'Should include raw events when IncludeEvents switch is set' {
            $Result = Get-DCShadowAttack -IncludeEvents
            $Result.IncludedRawEvents | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Export behavior' {
        It 'Should export CSV and JSON when OutputPath is provided' {
            $ExportPath = Join-Path -Path $TestDrive -ChildPath ('DCShadowExport_{0}' -f [DateTime]::Now.Ticks)

            $Result = Get-DCShadowAttack -OutputPath $ExportPath

            Test-Path -Path $ExportPath | Should -BeTrue
            $Result.PSObject.Properties.Name | Should -Contain 'ExportedReports'
        }

        It 'Should create output directory if it does not exist' {
            $ExportPath = Join-Path -Path $TestDrive -ChildPath ('MissingFolder_{0}' -f [DateTime]::Now.Ticks)
            if (Test-Path -Path $ExportPath) {
                Remove-Item -Path $ExportPath -Force -Recurse
            } #end if

            Get-DCShadowAttack -OutputPath $ExportPath | Out-Null

            Test-Path -Path $ExportPath | Should -BeTrue
        }
    }

    Context 'Error handling' {
        It 'Should throw when DC baseline cannot be built' {
            Mock -CommandName Get-ADDomainController -MockWith {
                throw 'AD query failed'
            }

            { Get-DCShadowAttack } | Should -Throw
        }
    }
}
