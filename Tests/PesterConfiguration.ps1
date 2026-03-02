<#
    .SYNOPSIS
        Pester configuration file for EguibarIT.SecurityPS module

    .DESCRIPTION
        This file defines the standard Pester configuration for running tests
        against the EguibarIT.SecurityPS module. It includes settings for:
        - Test discovery and execution
        - Code coverage analysis
        - Output formatting
        - Test result exports

    .NOTES
        Version:         1.0
        Author:          Vicente Rodriguez Eguibar
        Creation Date:   25/Feb/2026

    .LINK
        https://github.com/vreguibar/EguibarIT

    .EXAMPLE
        # Run all tests with this configuration
        Invoke-Pester -Configuration (.\Tests\PesterConfiguration.ps1)

    .EXAMPLE
        # Run tests with code coverage
        $Config = .\Tests\PesterConfiguration.ps1 -CodeCoverage
        Invoke-Pester -Configuration $Config
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [switch]$CodeCoverage
)

# Get module root directory
$ModuleRoot = Split-Path -Path $PSScriptRoot -Parent

# Create Pester configuration
$PesterConfig = New-PesterConfiguration

#region Run Configuration
$PesterConfig.Run.Path = $PSScriptRoot
$PesterConfig.Run.Exit = $false
$PesterConfig.Run.PassThru = $true
#endregion

#region Filter Configuration
# Include all tests by default
$PesterConfig.Filter.Tag = @()
$PesterConfig.Filter.ExcludeTag = @()
#endregion

#region Output Configuration
$PesterConfig.Output.Verbosity = 'Detailed'
#endregion

#region Should Configuration
$PesterConfig.Should.ErrorAction = 'Stop'
#endregion

#region TestResult Configuration
$PesterConfig.TestResult.Enabled = $true
$PesterConfig.TestResult.OutputFormat = 'NUnitXml'
$PesterConfig.TestResult.OutputPath = Join-Path -Path $ModuleRoot -ChildPath 'TestResults\TestResults.xml'
#endregion

#region CodeCoverage Configuration
if ($CodeCoverage) {
    $PesterConfig.CodeCoverage.Enabled = $true
    $PesterConfig.CodeCoverage.Path = @(
        (Join-Path -Path $ModuleRoot -ChildPath 'Private\*.ps1'),
        (Join-Path -Path $ModuleRoot -ChildPath 'Public\*.ps1')
    )
    $PesterConfig.CodeCoverage.OutputFormat = 'JaCoCo'
    $PesterConfig.CodeCoverage.OutputPath = Join-Path -Path $ModuleRoot -ChildPath 'TestResults\Coverage.xml'
}
#endregion

# Ensure TestResults directory exists
$TestResultsPath = Join-Path -Path $ModuleRoot -ChildPath 'TestResults'
if (-not (Test-Path -Path $TestResultsPath)) {
    New-Item -Path $TestResultsPath -ItemType Directory -Force | Out-Null
}

# Return the configuration
return $PesterConfig
