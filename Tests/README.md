# Tests Directory

This directory contains Pester tests for the `EguibarIT.SecurityPS` module.

## Structure

    Tests/
    ├── EguibarIT.SecurityPS.Tests.ps1    # Module-level tests
    ├── PesterConfiguration.ps1            # Pester configuration
    ├── Private/                           # Tests for private functions
    │   └── Initialize-ModuleVariable.Tests.ps1
    └── Public/                            # Tests for public functions (to be added)

## Running Tests

### Run All Tests

    Invoke-Pester -Path .\Tests\

### Run Module Tests Only

    Invoke-Pester -Path .\Tests\EguibarIT.SecurityPS.Tests.ps1

### Run with Code Coverage

    $Config = .\Tests\PesterConfiguration.ps1 -CodeCoverage
    Invoke-Pester -Configuration $Config

### Run Specific Test File

    Invoke-Pester -Path .\Tests\Private\Initialize-ModuleVariable.Tests.ps1

## Test Organization

- **Module Tests** (`EguibarIT.SecurityPS.Tests.ps1`): Validates module manifest, structure, and imports
- **Private Function Tests** (`Private\*.Tests.ps1`): Unit tests for internal helper functions
- **Public Function Tests** (`Public\*.Tests.ps1`): Integration tests for exported functions

## Test Standards

All tests should follow these conventions:

1. **Naming**: `FunctionName.Tests.ps1`
2. **Structure**: Use `Describe`, `Context`, and `It` blocks
3. **BeforeAll/BeforeEach**: Set up test environment
4. **AfterAll/AfterEach**: Clean up resources
5. **Mocking**: Mock external dependencies (AD cmdlets, etc.)
6. **Coverage**: Aim for >80% code coverage

## Example Test Template

```powershell
#Requires -Module Pester

BeforeAll {
    $ModuleRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    $FunctionPath = Join-Path -Path $ModuleRoot -ChildPath 'Public\Get-MyFunction.ps1'
    . $FunctionPath
}

Describe 'Get-MyFunction' {
    Context 'Parameter Validation' {
        It 'Should have mandatory parameters' {
            Get-Command Get-MyFunction | Should -HaveParameter Identity -Mandatory
        }
    }

    Context 'Function Execution' {
        It 'Should execute without errors' {
            { Get-MyFunction -Identity 'Test' } | Should -Not -Throw
        }
    }
}
```

## Security Testing

Security-focused tests are included in `EguibarIT.SecurityPS.Tests.ps1`:

- No hardcoded credentials
- No plaintext passwords
- No `Invoke-Expression` usage
- PSScriptAnalyzer compliance

## CI/CD Integration

These tests are designed to run in automated pipelines:

- GitHub Actions
- Azure DevOps
- Jenkins
- GitLab CI

## Resources

- [Pester Documentation](https://pester.dev/)
- [PowerShell Best Practices](https://poshcode.gitbook.io/powershell-practice-and-style/)
- [Module Testing Guide](https://github.com/vreguibar/EguibarIT)
