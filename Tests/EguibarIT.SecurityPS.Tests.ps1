#Requires -Module Pester

<#
    .SYNOPSIS
        Pester tests for EguibarIT.SecurityPS module manifest and structure

    .DESCRIPTION
        This test file validates the module manifest, required files, and basic module structure
        for the EguibarIT.SecurityPS module.

    .NOTES
        Version:         1.0
        Author:          Vicente Rodriguez Eguibar
        Creation Date:   25/Feb/2026

    .LINK
        https://github.com/vreguibar/EguibarIT
#>

BeforeAll {
    # Get module root path
    $ModuleRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    $ManifestPath = Join-Path -Path $ModuleRoot -ChildPath 'EguibarIT.SecurityPS.psd1'

    # Import the module manifest
    $script:Manifest = Test-ModuleManifest -Path $ManifestPath -ErrorAction Stop
}

Describe 'EguibarIT.SecurityPS Module Structure' {

    Context 'Module Manifest' {

        It 'Should have a valid module manifest file' {
            $ManifestPath | Should -Exist
        }

        It 'Should have correct module name' {
            $Manifest.Name | Should -Be 'EguibarIT.SecurityPS'
        }

        It 'Should have a GUID' {
            $Manifest.Guid | Should -Not -BeNullOrEmpty
            $Manifest.Guid | Should -Be '8c41aca0-580f-4013-86cf-c8b1ac5bbbd7'
        }

        It 'Should have an author' {
            $Manifest.Author | Should -Not -BeNullOrEmpty
            $Manifest.Author | Should -Be 'Vicente R. Eguibar'
        }

        It 'Should have a description' {
            $Manifest.Description | Should -Not -BeNullOrEmpty
        }

        It 'Should have a valid version number' {
            $Manifest.Version | Should -Not -BeNullOrEmpty
            $Manifest.Version -as [Version] | Should -Not -BeNullOrEmpty
        }

        It 'Should require PowerShell version 5.1 or higher' {
            $Manifest.PowerShellVersion | Should -Not -BeNullOrEmpty
            [Version]$Manifest.PowerShellVersion | Should -BeGreaterOrEqual ([Version]'5.1')
        }

        It 'Should require ActiveDirectory module' {
            $Manifest.RequiredModules | Should -Contain 'ActiveDirectory'
        }

        It 'Should be compatible with Desktop and Core editions' {
            $Manifest.CompatiblePSEditions | Should -Contain 'Desktop'
            $Manifest.CompatiblePSEditions | Should -Contain 'Core'
        }

        It 'Should have security-related tags' {
            $Manifest.Tags | Should -Contain 'Security'
            $Manifest.Tags | Should -Contain 'ActiveDirectory'
            $Manifest.Tags | Should -Contain 'Audit'
        }

        It 'Should have a ProjectUri' {
            $Manifest.ProjectUri | Should -Not -BeNullOrEmpty
        }

        It 'Should have a LicenseUri' {
            $Manifest.LicenseUri | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Required Files' {

        It 'Should have a README.md file' {
            Join-Path -Path $ModuleRoot -ChildPath 'README.md' | Should -Exist
        }

        It 'Should have a LICENSE file' {
            Join-Path -Path $ModuleRoot -ChildPath 'LICENSE' | Should -Exist
        }

        It 'Should have a SECURITY.md file' {
            Join-Path -Path $ModuleRoot -ChildPath 'SECURITY.md' | Should -Exist
        }

        It 'Should have a .gitignore file' {
            Join-Path -Path $ModuleRoot -ChildPath '.gitignore' | Should -Exist
        }

        It 'Should have PSScriptAnalyzerSettings.psd1' {
            Join-Path -Path $ModuleRoot -ChildPath 'PSScriptAnalyzerSettings.psd1' | Should -Exist
        }

        It 'Should have the root module file' {
            Join-Path -Path $ModuleRoot -ChildPath 'EguibarIT.SecurityPS.psm1' | Should -Exist
        }
    }

    Context 'Folder Structure' {

        It 'Should have a Private folder' {
            Join-Path -Path $ModuleRoot -ChildPath 'Private' | Should -Exist
        }

        It 'Should have a Public folder' {
            Join-Path -Path $ModuleRoot -ChildPath 'Public' | Should -Exist
        }

        It 'Should have an Enums folder' {
            Join-Path -Path $ModuleRoot -ChildPath 'Enums' | Should -Exist
        }

        It 'Should have a Classes folder' {
            Join-Path -Path $ModuleRoot -ChildPath 'Classes' | Should -Exist
        }

        It 'Should have a Tests folder' {
            Join-Path -Path $ModuleRoot -ChildPath 'Tests' | Should -Exist
        }
    }

    Context 'Module Import' {

        It 'Should import without errors' {
            { Import-Module -Name $ManifestPath -Force -ErrorAction Stop } | Should -Not -Throw
        }

        It 'Should export Variables after import' {
            Import-Module -Name $ManifestPath -Force
            Get-Variable -Name 'Variables' -Scope Global -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }

        It 'Should export Constants after import' {
            Import-Module -Name $ManifestPath -Force
            Get-Variable -Name 'Constants' -Scope Global -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
    }
}

Describe 'Security Validation' {

    Context 'Code Quality' {

        It 'Should pass PSScriptAnalyzer checks' {
            $SettingsPath = Join-Path -Path $ModuleRoot -ChildPath 'PSScriptAnalyzerSettings.psd1'
            $AnalyzerResults = Invoke-ScriptAnalyzer -Path $ModuleRoot -Recurse -Settings $SettingsPath
            $AnalyzerResults | Should -HaveCount 0 -Because 'there should be no PSScriptAnalyzer violations'
        }
    }

    Context 'Security Patterns' {

        BeforeAll {
            $script:AllPowerShellFiles = Get-ChildItem -Path $ModuleRoot -Filter '*.ps1' -Recurse |
                Where-Object { $_.Directory.Name -notin @('Tests', 'Docs', 'Examples') }
        }

        It 'Should not contain hardcoded passwords' {
            $AllPowerShellFiles | ForEach-Object {
                $Content = Get-Content -Path $_.FullName -Raw
                $Content | Should -Not -Match 'ConvertTo-SecureString.*-AsPlainText'
            }
        }

        It 'Should not contain Invoke-Expression' {
            $AllPowerShellFiles | ForEach-Object {
                $Content = Get-Content -Path $_.FullName -Raw
                $Content | Should -Not -Match 'Invoke-Expression'
            }
        }

        It 'Should not contain hardcoded credentials' {
            $AllPowerShellFiles | ForEach-Object {
                $Content = Get-Content -Path $_.FullName -Raw
                $Content | Should -Not -Match 'password\s*=\s*[''"][^''"]+'
            }
        }
    }
}
