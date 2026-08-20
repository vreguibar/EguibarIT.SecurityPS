Describe 'Get-LapsPasswordRetrieval' -Tag 'Unit' {
    BeforeAll {
        $ModulePath = Join-Path -Path $PSScriptRoot -ChildPath '..\..\EguibarIT.SecurityPS.psd1'
        Import-Module $ModulePath -Force
        $FunctionName = 'Get-LapsPasswordRetrieval'
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
        It 'Should return LAPS inventory with a risk assessment' {
            Mock -CommandName Get-ADComputer -ModuleName 'EguibarIT.SecurityPS' -MockWith {
                @(
                    [PSCustomObject]@{
                        Name            = 'WS-01'
                        Enabled         = $true
                        'ms-Mcs-AdmPwd' = 'TestPassword!123'
                    }
                )
            }

            $Result = & $FunctionName -DomainController 'DC01' -DaysBack 7
            $Result | Should -Not -BeNullOrEmpty
            $Result[0].ComputerName | Should -Be 'WS-01'
            $Result[0].LAPSStatus | Should -Match 'Enabled|NotConfigured'
            $Result[0].RiskLevel | Should -Not -BeNullOrEmpty
        }
    }
}
