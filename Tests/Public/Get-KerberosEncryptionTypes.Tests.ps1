Describe 'Get-KerberosEncryptionTypes' -Tag 'Unit' {
    BeforeAll {
        $ModulePath = Join-Path -Path $PSScriptRoot -ChildPath '..\..\EguibarIT.SecurityPS.psd1'
        Import-Module $ModulePath -Force
        $FunctionName = 'Get-KerberosEncryptionTypes'
    }

    BeforeEach {
        Mock -CommandName Get-ADUser -ModuleName 'EguibarIT.SecurityPS' -MockWith {
            @(
                [PSCustomObject]@{
                    SamAccountName = 'svc_legacy'
                    Name = 'svc_legacy'
                    ObjectClass = 'user'
                    Enabled = $true
                    'msDS-SupportedEncryptionTypes' = 0x04
                },
                [PSCustomObject]@{
                    SamAccountName = 'svc_modern'
                    Name = 'svc_modern'
                    ObjectClass = 'user'
                    Enabled = $true
                    'msDS-SupportedEncryptionTypes' = 0x1C
                }
            )
        }

        Mock -CommandName Get-ADComputer -ModuleName 'EguibarIT.SecurityPS' -MockWith {
            @(
                [PSCustomObject]@{
                    SamAccountName = 'sql01$'
                    Name = 'sql01'
                    ObjectClass = 'computer'
                    Enabled = $true
                    'msDS-SupportedEncryptionTypes' = 0x10
                }
            )
        }
    }

    Context 'Parameter and metadata' {
        It 'Should expose the expected parameters' {
            $Command = Get-Command -Name $FunctionName
            $Command.Parameters.ContainsKey('ObjectType') | Should -Be $true
            $Command.Parameters.ContainsKey('DomainController') | Should -Be $true
            $Command.Parameters.ContainsKey('IncludeDisabled') | Should -Be $true
            $Command.Parameters.ContainsKey('ExportPath') | Should -Be $true
        }
    }

    Context 'Detection behavior' {
        It 'Should identify weak Kerberos encryption settings' {
            $Result = & $FunctionName -ObjectType 'User'
            $Result | Should -Not -BeNullOrEmpty

            $WeakResult = $Result | Where-Object { $_.SamAccountName -eq 'svc_legacy' }
            $WeakResult | Should -Not -BeNullOrEmpty
            $WeakResult[0].WeakEncryptionEnabled | Should -Be $true
            $WeakResult[0].RiskLevel | Should -Be 'High'
        }

        It 'Should include supported encryption types in the output' {
            $Result = & $FunctionName -ObjectType 'User'
            $Entry = $Result | Where-Object { $_.SamAccountName -eq 'svc_modern' }
            $Entry[0].SupportedEncryptionTypes | Should -Contain 'AES128_HMAC_SHA1_96'
            $Entry[0].SupportedEncryptionTypes | Should -Contain 'AES256_HMAC_SHA1_96'
        }
    }
}
