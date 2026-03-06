Describe 'Get-MachineAccountQuota' -Tag 'Unit' {

    BeforeAll {
        $ModulePath = Join-Path -Path $PSScriptRoot -ChildPath '..\\..\\EguibarIT.SecurityPS.psd1'
        Import-Module $ModulePath -Force

        $ModuleName = 'EguibarIT.SecurityPS'
        $FunctionName = 'Get-MachineAccountQuota'

        if (-not (Get-Command -Name Get-FunctionDisplay -ErrorAction SilentlyContinue)) {
            function Get-FunctionDisplay { param($HashTable) return 'Stub Display' }
        }
    }

    BeforeEach {
        Mock -CommandName Get-FunctionDisplay -ModuleName $ModuleName -MockWith { 'Mocked Display' }

        Mock -CommandName Get-ADDomain -ModuleName $ModuleName -MockWith {
            [PSCustomObject]@{
                DNSRoot                    = 'contoso.com'
                DistinguishedName          = 'DC=contoso,DC=com'
                'ms-DS-MachineAccountQuota' = 10
            }
        }

        Mock -CommandName Get-ADDomainController -ModuleName $ModuleName -MockWith {
            @(
                [PSCustomObject]@{ HostName = 'DC01.contoso.com' },
                [PSCustomObject]@{ HostName = 'DC02.contoso.com' }
            )
        }

        Mock -CommandName Get-WinEvent -ModuleName $ModuleName -MockWith {
            $Evt = [PSCustomObject]@{ TimeCreated = (Get-Date).AddDays(-1) }
            $Evt | Add-Member -MemberType ScriptMethod -Name ToXml -Force -Value {
                @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <EventData>
    <Data Name="SamAccountName">ROGUE-WS01$</Data>
    <Data Name="SubjectUserName">jdoe</Data>
    <Data Name="SubjectDomainName">CONTOSO</Data>
    <Data Name="TargetDomainName">CONTOSO</Data>
    <Data Name="ComputerName">ROGUE-WS01$</Data>
    <Data Name="SubjectDomainName">CONTOSO</Data>
    <Data Name="TargetUserName">ROGUE-WS01$</Data>
  </EventData>
</Event>
'@
            }
            @($Evt)
        }

        Mock -CommandName Get-ADComputer -ModuleName $ModuleName -MockWith {
            @(
                [PSCustomObject]@{
                    Name                                       = 'ROGUE-WS01'
                    Created                                    = (Get-Date).AddDays(-5)
                    LastLogonDate                              = $null
                    PasswordLastSet                            = (Get-Date).AddDays(-5)
                    Enabled                                    = $true
                    CanonicalName                              = 'contoso.com/Computers/ROGUE-WS01'
                    Description                                = 'Suspicious workstation'
                    'msDS-AllowedToActOnBehalfOfOtherIdentity' = 'RBCD'
                },
                [PSCustomObject]@{
                    Name                                       = 'ROGUE-SRV02'
                    Created                                    = (Get-Date).AddDays(-3)
                    LastLogonDate                              = $null
                    PasswordLastSet                            = (Get-Date).AddDays(-3)
                    Enabled                                    = $true
                    CanonicalName                              = 'contoso.com/Computers/ROGUE-SRV02'
                    Description                                = 'Suspicious server'
                    'msDS-AllowedToActOnBehalfOfOtherIdentity' = 'RBCD'
                }
            )
        }

        Mock -CommandName Export-Csv -ModuleName $ModuleName -MockWith { }
        Mock -CommandName Out-File -ModuleName $ModuleName -MockWith { }
        Mock -CommandName Test-Path -ModuleName $ModuleName -MockWith { $true }
        Mock -CommandName New-Item -ModuleName $ModuleName -MockWith { }
        Mock -CommandName Join-Path -ModuleName $ModuleName -MockWith {
            param($Path, $ChildPath)
            "$Path\\$ChildPath"
        }
    }

    Context 'Parameter validation' {
        It 'Should expose expected parameters and WhatIf support' {
            $Command = Get-Command -Name $FunctionName
            $Command.Parameters.ContainsKey('TimeSpanDays') | Should -Be $true
            $Command.Parameters.ContainsKey('AuthorizedCreators') | Should -Be $true
            $Command.Parameters.ContainsKey('ExportPath') | Should -Be $true
            $Command.Parameters.ContainsKey('WhatIf') | Should -Be $true
        }
    }

    Context 'Audit behavior' {
        It 'Should return summary object with expected properties' {
            $Result = & $FunctionName -TimeSpanDays 30

            $Result | Should -Not -BeNullOrEmpty
            $Result.MachineAccountQuotaValue | Should -Be 10
            $Result.IsSecure | Should -Be $false
            $Result.TotalComputerAccounts | Should -Be 2
            $Result.SuspiciousComputersCount | Should -BeGreaterThan 0
        }

        It 'Should detect unauthorized computer creations' {
            $Result = & $FunctionName -TimeSpanDays 30 -AuthorizedCreators @('Domain Admins')
            $Result.UnauthorizedCreationsCount | Should -BeGreaterThan 0
        }

        It 'Should detect critical RBCD indicators' {
            $Result = & $FunctionName -TimeSpanDays 30
            $Result.CriticalRBCDCount | Should -BeGreaterThan 0
        }

        It 'Should set secure mode when MAQ equals zero' {
            Mock -CommandName Get-ADDomain -ModuleName $ModuleName -MockWith {
                [PSCustomObject]@{
                    DNSRoot                    = 'contoso.com'
                    DistinguishedName          = 'DC=contoso,DC=com'
                    'ms-DS-MachineAccountQuota' = 0
                }
            }

            $Result = & $FunctionName -TimeSpanDays 30
            $Result.IsSecure | Should -Be $true
            $Result.RecommendedAction | Should -Match 'secure|monitoring'
        }
    }

    Context 'Export behavior' {
        It 'Should export CSV and TXT reports when ExportPath is provided' {
            & $FunctionName -ExportPath 'C:\Reports' -TimeSpanDays 30 -ErrorAction SilentlyContinue
            Should -Invoke -CommandName Export-Csv -ModuleName $ModuleName -Times 2
        }

        It 'Should honor WhatIf and skip exports' {
            & $FunctionName -ExportPath 'C:\Reports' -TimeSpanDays 30 -WhatIf
            Should -Invoke -CommandName Export-Csv -ModuleName $ModuleName -Times 0 -Exactly
            Should -Invoke -CommandName Out-File -ModuleName $ModuleName -Times 0 -Exactly
        }
    }
}
