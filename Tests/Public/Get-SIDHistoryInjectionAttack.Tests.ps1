Describe 'Get-SIDHistoryInjectionAttack' {
    BeforeAll {
        $ModuleName = 'EguibarIT.SecurityPS'
        $PathToManifest = Join-Path -Path $PSScriptRoot -ChildPath ('..\..\{0}.psd1' -f $ModuleName)

        if (-not (Test-Path -Path $PathToManifest)) {
            throw ('Module manifest not found: {0}' -f $PathToManifest)
        } #end if

        if (Get-Module -Name $ModuleName) {
            Remove-Module -Name $ModuleName -Force
        } #end if

        Import-Module -Name $PathToManifest -Force -ErrorAction Stop

        if (-not (Get-Command -Name 'Get-FunctionDisplay' -ErrorAction SilentlyContinue)) {
            function global:Get-FunctionDisplay {
                param(
                    [Parameter(Mandatory = $false)]
                    [hashtable]
                    $Hashtable,

                    [Parameter(Mandatory = $false)]
                    [switch]
                    $Verbose
                )

                return 'MockParameters'
            }
        } #end if

        if (Test-Path -Path Variable:\Variables) {
            $script:Variables = Get-Variable -Name 'Variables' -Scope Global -ValueOnly
        } else {
            $script:Variables = [ordered]@{
                HeaderSecurity = 'Header {0} {1} {2}'
                FooterSecurity = 'Footer {0} {1}'
                WellKnownSIDs  = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)
            }
            New-Variable -Name 'Variables' -Scope Global -Value $script:Variables -Force
        } #end if-else

        if ($script:Variables -is [hashtable]) {
            $script:Variables['HeaderSecurity'] = 'Header {0} {1} {2}'
            $script:Variables['FooterSecurity'] = 'Footer {0} {1}'

            if ($null -eq $script:Variables['WellKnownSIDs']) {
                $script:Variables['WellKnownSIDs'] = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)
            } #end if

            $script:Variables['WellKnownSIDs']['S-1-5-21-111-222-333-512'] = 'Domain Admins'
            $script:Variables['WellKnownSIDs']['S-1-5-21-111-222-333-518'] = 'Schema Admins'
            $script:Variables['WellKnownSIDs']['S-1-5-21-111-222-333-519'] = 'Enterprise Admins'
            $script:Variables['WellKnownSIDs']['S-1-5-21-111-222-333-500'] = 'Administrator'
        } else {
            if (-not ($script:Variables.PSObject.Properties.Name -contains 'HeaderSecurity')) {
                Add-Member -InputObject $script:Variables -MemberType NoteProperty -Name 'HeaderSecurity' -Value 'Header {0} {1} {2}'
            } else {
                $script:Variables.HeaderSecurity = 'Header {0} {1} {2}'
            } #end if-else

            if (-not ($script:Variables.PSObject.Properties.Name -contains 'FooterSecurity')) {
                Add-Member -InputObject $script:Variables -MemberType NoteProperty -Name 'FooterSecurity' -Value 'Footer {0} {1}'
            } else {
                $script:Variables.FooterSecurity = 'Footer {0} {1}'
            } #end if-else

            if (-not ($script:Variables.PSObject.Properties.Name -contains 'WellKnownSIDs') -or
                $null -eq $script:Variables.WellKnownSIDs) {
                Add-Member -InputObject $script:Variables -MemberType NoteProperty -Name 'WellKnownSIDs' -Value ([hashtable]::New([StringComparer]::OrdinalIgnoreCase)) -Force
            } #end if

            $script:Variables.WellKnownSIDs['S-1-5-21-111-222-333-512'] = 'Domain Admins'
            $script:Variables.WellKnownSIDs['S-1-5-21-111-222-333-518'] = 'Schema Admins'
            $script:Variables.WellKnownSIDs['S-1-5-21-111-222-333-519'] = 'Enterprise Admins'
            $script:Variables.WellKnownSIDs['S-1-5-21-111-222-333-500'] = 'Administrator'
        } #end if-else
    } #end BeforeAll

    BeforeEach {
        Mock -CommandName Import-MyModule -ModuleName 'EguibarIT.SecurityPS' -MockWith { return }

        Mock -CommandName Get-ADRootDSE -ModuleName 'EguibarIT.SecurityPS' -MockWith {
            return [PSCustomObject]@{
                defaultNamingContext = 'DC=contoso,DC=com'
            }
        }

        Mock -CommandName Get-ADDomain -ModuleName 'EguibarIT.SecurityPS' -MockWith {
            return [PSCustomObject]@{
                DNSRoot           = 'contoso.com'
                DistinguishedName = 'DC=contoso,DC=com'
            }
        }

        Mock -CommandName Get-ADUser -ModuleName 'EguibarIT.SecurityPS' -MockWith {
            $DomainAdminsSid = @(
                $script:Variables.WellKnownSIDs.Keys.Where({
                        $script:Variables.WellKnownSIDs[$_] -eq 'Domain Admins'
                    })
            ) | Select-Object -First 1

            return @(
                [PSCustomObject]@{
                    SamAccountName    = 'legacy.user'
                    DistinguishedName = 'CN=legacy.user,CN=Users,DC=contoso,DC=com'
                    sidHistory        = @(
                        [PSCustomObject]@{ Value = [string]$DomainAdminsSid },
                        [PSCustomObject]@{ Value = 'S-1-5-21-111-222-333-2100' }
                    )
                    whenCreated       = (Get-Date).AddDays(-200)
                    PasswordLastSet   = (Get-Date).AddDays(-30)
                    AdminCount        = 1
                }
            )
        }

        Mock -CommandName Get-ADComputer -ModuleName 'EguibarIT.SecurityPS' -MockWith {
            return @(
                [PSCustomObject]@{
                    Name              = 'WS01'
                    DistinguishedName = 'CN=WS01,OU=Workstations,DC=contoso,DC=com'
                    sidHistory        = @(
                        [PSCustomObject]@{ Value = 'S-1-5-21-111-222-333-2200' }
                    )
                    whenCreated       = (Get-Date).AddDays(-100)
                }
            )
        }

        Mock -CommandName Get-ADDomainController -ModuleName 'EguibarIT.SecurityPS' -MockWith {
            return @(
                [PSCustomObject]@{
                    Name     = 'DC1'
                    HostName = 'dc1.contoso.com'
                }
            )
        }

        Mock -CommandName Get-WinEvent -ModuleName 'EguibarIT.SecurityPS' -MockWith {
            param($ComputerName, $FilterHashtable, $ErrorAction)

            if ($FilterHashtable.Id -eq 4765) {
                                $MockEvent = [PSCustomObject]@{
                                        TimeCreated = (Get-Date).AddHours(-2)
                                }
                                Add-Member -InputObject $MockEvent -MemberType ScriptMethod -Name ToXml -Value {
                                        @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <EventData>
    <Data Name="TargetUserName">legacy.user</Data>
    <Data Name="SubjectUserName">svc.migration</Data>
    <Data Name="SidHistory">S-1-5-21-111-222-333-512</Data>
  </EventData>
</Event>
'@
                }
                return @($MockEvent)
            }

            return @()
        }

        Mock -CommandName Get-ADReplicationAttributeMetadata -ModuleName 'EguibarIT.SecurityPS' -MockWith {
            param($Object, $Server, $ShowAllLinkedValues, $ErrorAction)

            return @(
                [PSCustomObject]@{
                    AttributeName                               = 'sidHistory'
                    LastOriginatingChangeDirectoryServerIdentity = 'rogue-dc.contoso.com'
                    LastOriginatingChangeTime                   = (Get-Date).AddHours(-1)
                    Version                                     = 3
                }
            )
        }

        Mock -CommandName Get-ADTrust -ModuleName 'EguibarIT.SecurityPS' -MockWith {
            return @(
                [PSCustomObject]@{
                    Name                   = 'fabrikam.com'
                    Direction              = 'Bidirectional'
                    TrustType              = 'Forest'
                    SIDFilteringQuarantined = $false
                }
            )
        }
    } #end BeforeEach

    Context 'Parameter validation' {
        It 'Should throw when DaysBack is less than allowed range' {
            { Get-SIDHistoryInjectionAttack -DaysBack 0 -OutputPath $TestDrive } | Should -Throw
        }

        It 'Should throw when DaysBack is greater than allowed range' {
            { Get-SIDHistoryInjectionAttack -DaysBack 366 -OutputPath $TestDrive } | Should -Throw
        }
    }

    Context 'Core behavior' {
        It 'Should return structured output object' {
            $Result = Get-SIDHistoryInjectionAttack -OutputPath $TestDrive

            $Result.PSObject.TypeNames[0] | Should -Be 'EguibarIT.SIDHistoryInjectionAttack'
            $Result | Should -Not -BeNullOrEmpty
            $Result.Findings.Count | Should -BeGreaterThan 0
        }

        It 'Should detect privileged SID in SID History' {
            $Result = Get-SIDHistoryInjectionAttack -OutputPath $TestDrive
            $Finding = $Result.Findings | Where-Object { $_.FindingType -eq 'Privileged SID in SID History' }

            $Finding | Should -Not -BeNullOrEmpty
            $Finding.RiskLevel | Should -Be 'Critical'
        }

        It 'Should detect SID History metadata from unknown originating DC' {
            $Result = Get-SIDHistoryInjectionAttack -OutputPath $TestDrive
            $Finding = $Result.Findings | Where-Object { $_.FindingType -eq 'SID History Modified by Unknown DC' }

            $Finding | Should -Not -BeNullOrEmpty
            @($Finding).Count | Should -BeGreaterThan 0
            ($Finding | Select-Object -First 1).RiskLevel | Should -Be 'Critical'
        }

        It 'Should include Event 4765 findings when present' {
            $Result = Get-SIDHistoryInjectionAttack -OutputPath $TestDrive
            $EventFinding = $Result.Findings | Where-Object { $_.FindingType -eq 'SID History Modification Event' }

            $EventFinding | Should -Not -BeNullOrEmpty
            $EventFinding.EventID | Should -Be 4765
        }
    }

    Context 'Trust checks' {
        It 'Should add trust SID filtering finding when CheckTrusts is specified' {
            $Result = Get-SIDHistoryInjectionAttack -OutputPath $TestDrive -CheckTrusts
            $TrustFinding = $Result.Findings | Where-Object { $_.FindingType -eq 'SID Filtering Disabled on Trust' }

            $TrustFinding | Should -Not -BeNullOrEmpty
            $TrustFinding.RiskLevel | Should -Be 'High'
        }
    }

    Context 'Export behavior' {
        It 'Should support WhatIf and not export files' {
            $ExportPath = Join-Path -Path $TestDrive -ChildPath ('WhatIf_{0}' -f [DateTime]::Now.Ticks)

            $Result = Get-SIDHistoryInjectionAttack -OutputPath $ExportPath -WhatIf

            $Result | Should -Not -BeNullOrEmpty
            $Result.ExportedReports.Count | Should -Be 0
        }

        It 'Should export CSV and JSON when OutputPath is provided' {
            $ExportPath = Join-Path -Path $TestDrive -ChildPath ('Export_{0}' -f [DateTime]::Now.Ticks)

            $Result = Get-SIDHistoryInjectionAttack -OutputPath $ExportPath

            Test-Path -Path $ExportPath | Should -BeTrue
            $Result.ExportedReports.Count | Should -Be 2
        }
    }
}