Describe 'Import-MyModule' -Tag 'Unit' {

    BeforeAll {
        $ModulePath = Join-Path -Path $PSScriptRoot -ChildPath '..\\..\\EguibarIT.SecurityPS.psd1'
        Import-Module $ModulePath -Force

        $ModuleName = 'EguibarIT.SecurityPS'
        $FunctionName = 'Import-MyModule'
        $script:FakePSModuleInfo = Get-Module -ListAvailable Microsoft.PowerShell.Management | Select-Object -First 1

        if (-not (Get-Command -Name Get-FunctionDisplay -ErrorAction SilentlyContinue)) {
            function Get-FunctionDisplay {
                param($HashTable) return 'Stub Display'
            }
        }
    }

    BeforeEach {
        Mock -CommandName Get-FunctionDisplay -ModuleName $ModuleName -MockWith { 'Mocked Display' }
        Mock -CommandName Import-Module -ModuleName $ModuleName -MockWith { $script:FakePSModuleInfo }
        Mock -CommandName Get-Module -ModuleName $ModuleName -ParameterFilter { $ListAvailable } -MockWith {
            $script:FakePSModuleInfo
        }
        Mock -CommandName Get-Module -ModuleName $ModuleName -ParameterFilter { -not $ListAvailable } -MockWith { $null }
        Mock -CommandName Test-Path -ModuleName $ModuleName -MockWith { $true }
    }

    Context 'Parameter validation' {
        It 'Should expose expected optional parameters' {
            $Command = Get-Command -Name $FunctionName
            $Command.Parameters.ContainsKey('Name') | Should -Be $true
            $Command.Parameters['Name'].Attributes.Mandatory | Should -Contain $true
            $Command.Parameters.ContainsKey('MinimumVersion') | Should -Be $true
            $Command.Parameters.ContainsKey('RequiredVersion') | Should -Be $true
            $Command.Parameters.ContainsKey('Force') | Should -Be $true
            $Command.Parameters.ContainsKey('PassThru') | Should -Be $true
        }

        It 'Should support WhatIf via ShouldProcess' {
            $Command = Get-Command -Name $FunctionName
            $Command.Parameters.ContainsKey('WhatIf') | Should -Be $true
        }
    }

    Context 'Import behavior' {
        It 'Should import module when available and not loaded' {
            & $FunctionName -Name 'ActiveDirectory'

            Should -Invoke -CommandName Get-Module -ModuleName $ModuleName -ParameterFilter { $ListAvailable } -Times 1 -Exactly
            Should -Invoke -CommandName Import-Module -ModuleName $ModuleName -Times 1
        }

        It 'Should return imported module when PassThru is specified' {
            $Result = & $FunctionName -Name 'ActiveDirectory' -PassThru

            $Result | Should -Not -BeNullOrEmpty
            $Result.Name | Should -Not -BeNullOrEmpty
        }

        It 'Should not re-import already loaded module unless Force is used' {
            Mock -CommandName Get-Module -ModuleName $ModuleName -ParameterFilter { -not $ListAvailable } -MockWith {
                $script:FakePSModuleInfo
            }

            & $FunctionName -Name 'ActiveDirectory'

            Should -Invoke -CommandName Import-Module -ModuleName $ModuleName -Times 0 -Exactly
        }

        It 'Should return currently loaded module when PassThru is specified and already loaded' {
            Mock -CommandName Get-Module -ModuleName $ModuleName -ParameterFilter { -not $ListAvailable } -MockWith {
                $script:FakePSModuleInfo
            }

            $Result = & $FunctionName -Name 'ActiveDirectory' -PassThru
            $Result.Name | Should -Not -BeNullOrEmpty
        }

        It 'Should import when Force is used even if already loaded' {
            Mock -CommandName Get-Module -ModuleName $ModuleName -ParameterFilter { -not $ListAvailable } -MockWith {
                $script:FakePSModuleInfo
            }

            & $FunctionName -Name 'ActiveDirectory' -Force

            Should -Invoke -CommandName Import-Module -ModuleName $ModuleName -Times 1
        }
    }

    Context 'Special module path handling' {
        It 'Should use specific path for GroupPolicy when not in module path' {
            Mock -CommandName Get-Module -ModuleName $ModuleName -ParameterFilter { $ListAvailable } -MockWith { $null }
            Mock -CommandName Test-Path -ModuleName $ModuleName -ParameterFilter { $Path -like '*GroupPolicy.psd1' } -MockWith { $true }

            & $FunctionName -Name 'GroupPolicy'

            Should -Invoke -CommandName Import-Module -ModuleName $ModuleName -Times 1
        }

        It 'Should not import when module is not installed and no special path found' {
            Mock -CommandName Get-Module -ModuleName $ModuleName -ParameterFilter { $ListAvailable } -MockWith { $null }
            Mock -CommandName Test-Path -ModuleName $ModuleName -MockWith { $false }

            & $FunctionName -Name 'NonExistentModule' -ErrorAction SilentlyContinue

            Should -Invoke -CommandName Import-Module -ModuleName $ModuleName -Times 0 -Exactly
        }
    }

    Context 'ShouldProcess behavior' {
        It 'Should honor WhatIf and skip import' {
            & $FunctionName -Name 'ActiveDirectory' -WhatIf

            Should -Invoke -CommandName Import-Module -ModuleName $ModuleName -Times 0 -Exactly
        }
    }
}
