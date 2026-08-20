Describe 'Get-NtlmUsageInventory' -Tag 'Unit' {
    BeforeAll {
        $ModulePath = Join-Path -Path $PSScriptRoot -ChildPath '..\..\EguibarIT.SecurityPS.psd1'
        Import-Module $ModulePath -Force
        $FunctionName = 'Get-NtlmUsageInventory'
    }

    Context 'Parameter and metadata' {
        It 'Should expose the expected parameters' {
            $Command = Get-Command -Name $FunctionName
            $Command.Parameters.ContainsKey('DomainController') | Should -Be $true
            $Command.Parameters.ContainsKey('DaysBack') | Should -Be $true
            $Command.Parameters.ContainsKey('CheckAllDCs') | Should -Be $true
            $Command.Parameters.ContainsKey('ExportPath') | Should -Be $true
        }
    }

    Context 'Detection behavior' {
        It 'Should inventory NTLM usage and classify risk' {
            Mock -CommandName Get-WinEvent -ModuleName 'EguibarIT.SecurityPS' -MockWith {
                @(
                    [PSCustomObject]@{ TimeCreated = (Get-Date); Id = 8001; Message = 'NTLM authentication from 10.0.0.5' },
                    [PSCustomObject]@{ TimeCreated = (Get-Date); Id = 8002; Message = 'NTLM authentication from 10.0.0.6' },
                    [PSCustomObject]@{ TimeCreated = (Get-Date); Id = 8004; Message = 'NTLM audit event for privileged account' }
                )
            }

            $Result = & $FunctionName -DomainController 'DC01' -DaysBack 7
            $Result | Should -Not -BeNullOrEmpty
            $Result.TotalEvents | Should -Be 3
            $Result.RiskLevel | Should -Match 'Low|Medium|High|Critical'
        }
    }
}
