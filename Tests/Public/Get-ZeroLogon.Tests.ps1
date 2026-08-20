Describe 'Get-ZeroLogon' -Tag 'Unit' {
    BeforeAll {
        $ModulePath = Join-Path -Path $PSScriptRoot -ChildPath '..\..\EguibarIT.SecurityPS.psd1'
        Import-Module $ModulePath -Force
        $FunctionName = 'Get-ZeroLogon'
    }

    Context 'Parameter and metadata' {
        It 'Should expose the expected parameters' {
            $Command = Get-Command -Name $FunctionName
            $Command.Parameters.ContainsKey('DomainController') | Should -Be $true
            $Command.Parameters.ContainsKey('DaysBack') | Should -Be $true
            $Command.Parameters.ContainsKey('ExportPath') | Should -Be $true
        }
    }

    Context 'Detection behavior' {
        It 'Should return a risk assessment for possible ZeroLogon activity' {
            Mock -CommandName Get-WinEvent -ModuleName 'EguibarIT.SecurityPS' -MockWith {
                @(
                    [PSCustomObject]@{ TimeCreated = (Get-Date).AddMinutes(-10); Id = 4624; Message = 'An account was successfully logged on: NT AUTHORITY\SYSTEM, NetrLogon' },
                    [PSCustomObject]@{ TimeCreated = (Get-Date).AddMinutes(-5); Id = 4625; Message = 'Failed logon on DC using NULL session and NetrLogon' }
                )
            }

            $Result = & $FunctionName -DomainController 'DC01' -DaysBack 7
            $Result | Should -Not -BeNullOrEmpty
            $Result.TotalEvents | Should -Be 2
            $Result.RiskLevel | Should -Match 'Low|Medium|High|Critical'
        }
    }
}
