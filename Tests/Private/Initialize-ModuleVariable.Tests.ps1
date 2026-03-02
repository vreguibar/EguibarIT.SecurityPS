#Requires -Module Pester

<#
    .SYNOPSIS
        Pester tests for Initialize-ModuleVariable private function

    .DESCRIPTION
        Tests the Initialize-ModuleVariable function to ensure it properly initializes
        all module variables required for the EguibarIT.SecurityPS module.

    .NOTES
        Version:         1.0
        Author:          Vicente Rodriguez Eguibar
        Creation Date:   25/Feb/2026

    .LINK
        https://github.com/vreguibar/EguibarIT
#>

BeforeAll {
    # Get module root and import the function
    $ModuleRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    $FunctionPath = Join-Path -Path $ModuleRoot -ChildPath 'Private\Initialize-ModuleVariable.ps1'

    # Dot-source the function
    . $FunctionPath

    # Mock Get-ADObject to avoid actual AD calls in tests
    Mock Get-ADObject {
        return @{
            SchemaIDGUID = [Guid]::NewGuid()
            Name         = 'MockObject'
        }
    }
}

Describe 'Initialize-ModuleVariable' {

    Context 'Parameter Validation' {

        It 'Should have a Force parameter' {
            Get-Command Initialize-ModuleVariable | Should -HaveParameter Force -Type Switch
        }

        It 'Should not require any mandatory parameters' {
            (Get-Command Initialize-ModuleVariable).Parameters.Force.Attributes.Mandatory | Should -Be $false
        }
    }

    Context 'Function Execution' {

        BeforeEach {
            # Clear the Variables hashtable before each test
            if (Get-Variable -Name 'Variables' -Scope Global -ErrorAction SilentlyContinue) {
                Remove-Variable -Name 'Variables' -Scope Global -Force
            }
        }

        It 'Should execute without errors' {
            { Initialize-ModuleVariable } | Should -Not -Throw
        }

        It 'Should create the Variables hashtable' {
            Initialize-ModuleVariable
            $Variables | Should -Not -BeNullOrEmpty
        }

        It 'Should initialize AdDN variable' {
            Initialize-ModuleVariable
            $Variables.AdDN | Should -Not -BeNullOrEmpty
        }

        It 'Should initialize DnsFqdn variable' {
            Initialize-ModuleVariable
            $Variables.DnsFqdn | Should -Not -BeNullOrEmpty
        }

        It 'Should initialize GuidMap as hashtable' {
            Initialize-ModuleVariable
            $Variables.GuidMap | Should -BeOfType [hashtable]
        }

        It 'Should initialize ExtendedRightsMap as hashtable' {
            Initialize-ModuleVariable
            $Variables.ExtendedRightsMap | Should -BeOfType [hashtable]
        }

        It 'Should initialize WellKnownSIDs as hashtable' {
            Initialize-ModuleVariable
            $Variables.WellKnownSIDs | Should -BeOfType [hashtable]
        }
    }

    Context 'Force Parameter' {

        It 'Should reinitialize when Force is used' {
            Initialize-ModuleVariable
            $initialDN = $Variables.AdDN

            Initialize-ModuleVariable -Force
            $Variables.AdDN | Should -Be $initialDN
        }
    }

    Context 'ActiveDirectory Module Availability' {

        It 'Should handle missing ActiveDirectory module gracefully' {
            Mock Get-Module { return $null } -ParameterFilter { $Name -eq 'ActiveDirectory' }
            { Initialize-ModuleVariable -WarningAction SilentlyContinue } | Should -Not -Throw
        }
    }
}
