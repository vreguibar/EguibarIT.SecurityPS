Describe 'Find-GPPPasswords' -Tag 'Unit' {

    BeforeAll {
        $ModulePath = Join-Path -Path $PSScriptRoot -ChildPath '..\\..\\EguibarIT.SecurityPS.psd1'
        Import-Module $ModulePath -Force

        $ModuleName = 'EguibarIT.SecurityPS'
        $FunctionName = 'Find-GPPPasswords'

        if (-not (Get-Command -Name Get-FunctionDisplay -ErrorAction SilentlyContinue)) {
            function Get-FunctionDisplay { param($HashTable) return 'Stub Display' }
        }
        if (-not (Get-Command -Name Decrypt-GPPPassword -ErrorAction SilentlyContinue)) {
            function Decrypt-GPPPassword { param([string]$EncryptedPassword) return 'stub' }
        }

        $script:CanResolveDomain = $true
        try {
            [void][System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        } catch {
            $script:CanResolveDomain = $false
        }
    }

    BeforeEach {
        Mock -CommandName Get-FunctionDisplay -ModuleName $ModuleName -MockWith { 'Mocked Display' }
        Mock -CommandName Test-Path -ModuleName $ModuleName -MockWith { $true }
        Mock -CommandName New-Item -ModuleName $ModuleName -MockWith { [PSCustomObject]@{ FullName = 'C:\Logs' } }
        Mock -CommandName Get-ChildItem -ModuleName $ModuleName -MockWith {
            @(
                [PSCustomObject]@{
                    FullName      = 'C:\Temp\Groups.xml'
                    Name          = 'Groups.xml'
                    CreationTime  = (Get-Date).AddYears(-2)
                    LastWriteTime = (Get-Date).AddDays(-10)
                }
            )
        }
        Mock -CommandName Get-Content -ModuleName $ModuleName -MockWith {
            '<User userName="svc_admin" cpassword="ENC123" />'
        }
        Mock -CommandName Decrypt-GPPPassword -ModuleName $ModuleName -MockWith { 'P@ssw0rd!' }
        Mock -CommandName Remove-Item -ModuleName $ModuleName -MockWith { }
        Mock -CommandName Export-Csv -ModuleName $ModuleName -MockWith { }
        Mock -CommandName ConvertTo-Json -ModuleName $ModuleName -MockWith { '{"value":"x"}' }
        Mock -CommandName Out-File -ModuleName $ModuleName -MockWith { }
    }

    Context 'Parameter validation' {
        It 'Should have expected parameters and WhatIf support' {
            $Command = Get-Command -Name $FunctionName
            $Command.Parameters.ContainsKey('ExportReport') | Should -Be $true
            $Command.Parameters.ContainsKey('DecryptPasswords') | Should -Be $true
            $Command.Parameters.ContainsKey('DeleteFiles') | Should -Be $true
            $Command.Parameters.ContainsKey('ExportPath') | Should -Be $true
            $Command.Parameters.ContainsKey('WhatIf') | Should -Be $true
        }
    }

    Context 'Core behavior' {
        It 'Should return expected output shape when findings exist' -Skip:(-not $script:CanResolveDomain) {
            $Result = & $FunctionName

            $Result | Should -Not -BeNullOrEmpty
            $Result.PSTypeName | Should -Be 'EguibarIT.Security.GPPPasswordAudit'
            $Result.PasswordFilesFound | Should -Be 1
            $Result.IsSecure | Should -Be $false
            $Result.RiskLevel | Should -Be 'Critical'
            $Result.PasswordsDecrypted | Should -Be $true
        }

        It 'Should not decrypt password when DecryptPasswords is false' -Skip:(-not $script:CanResolveDomain) {
            & $FunctionName -DecryptPasswords:$false
            Should -Invoke -CommandName Decrypt-GPPPassword -Times 0 -Exactly
        }

        It 'Should call deletion path when DeleteFiles is used' -Skip:(-not $script:CanResolveDomain) {
            & $FunctionName -DeleteFiles -Confirm:$false
            Should -Invoke -CommandName Remove-Item -Times 1
        }

        It 'Should export CSV JSON and TXT when ExportReport is used' -Skip:(-not $script:CanResolveDomain) {
            $Result = & $FunctionName -ExportReport -ExportPath 'C:\Reports'

            Should -Invoke -CommandName Export-Csv -Times 1
            Should -Invoke -CommandName Out-File -Times 2
            $Result.ReportsExported.Count | Should -BeGreaterThan 0
        }

        It 'Should honor WhatIf for delete operation' -Skip:(-not $script:CanResolveDomain) {
            & $FunctionName -DeleteFiles -WhatIf
            Should -Invoke -CommandName Remove-Item -Times 0 -Exactly
        }
    }

    Context 'Secure path' {
        It 'Should report secure when no cpassword is found' -Skip:(-not $script:CanResolveDomain) {
            Mock -CommandName Get-Content -ModuleName $ModuleName -MockWith { '<Root><NoPassword /></Root>' }

            $Result = & $FunctionName
            $Result.PasswordFilesFound | Should -Be 0
            $Result.IsSecure | Should -Be $true
            $Result.RiskLevel | Should -Be 'None'
        }
    }
}
