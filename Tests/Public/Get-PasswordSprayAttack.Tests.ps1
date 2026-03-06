Describe 'Get-PasswordSprayAttack' -Tag 'Unit' {

    BeforeAll {
        $ModulePath = Join-Path -Path $PSScriptRoot -ChildPath '..\\..\\EguibarIT.SecurityPS.psd1'
        Import-Module $ModulePath -Force

        $ModuleName = 'EguibarIT.SecurityPS'
        $FunctionName = 'Get-PasswordSprayAttack'
        $script:BaseArgs = @{
            DomainController = 'DC01'
            ExcludeSourceIPs = @('203.0.113.254')
        }

        if (-not (Get-Command -Name Get-FunctionDisplay -ErrorAction SilentlyContinue)) {
            function Get-FunctionDisplay { param($HashTable) return 'Stub Display' }
        }
    }

    BeforeEach {
        Mock -CommandName Get-FunctionDisplay -ModuleName $ModuleName -MockWith { 'Mocked Display' }
        Mock -CommandName Get-ADDomainController -ModuleName $ModuleName -MockWith {
            [PSCustomObject]@{ HostName = 'DC01.contoso.com' }
        }

                Mock -CommandName Get-WinEvent -ModuleName $ModuleName -MockWith {
            param($FilterHashtable)
            if ($FilterHashtable.Id -eq 4625) {
                $Events = @()
                1..12 | ForEach-Object {
                    $Evt = [PSCustomObject]@{ TimeCreated = (Get-Date).AddMinutes(-$_) }
                    $AccountName = 'user{0}' -f $_
                                        $Evt | Add-Member -MemberType NoteProperty -Name XmlData -Force -Value (@"
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <EventData>
        <Data Name="TargetUserName">$AccountName</Data>
        <Data Name="IpAddress">10.10.10.50</Data>
        <Data Name="WorkstationName">WK01</Data>
        <Data Name="LogonType">3</Data>
        <Data Name="Status">0xC000006A</Data>
    </EventData>
</Event>
"@)
                                        $Evt | Add-Member -MemberType ScriptMethod -Name ToXml -Force -Value {
                                                return $this.XmlData
                                        }
                    $Events += $Evt
                }
                return $Events
            }

            if ($FilterHashtable.Id -eq 4771) {
                return @()
            }

            if ($FilterHashtable.Id -eq 4624) {
                $Success = [PSCustomObject]@{ TimeCreated = (Get-Date).AddMinutes(-1) }
                $Success | Add-Member -MemberType ScriptMethod -Name ToXml -Force -Value {
                    @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <EventData>
    <Data Name="TargetUserName">user1</Data>
    <Data Name="IpAddress">10.10.10.50</Data>
  </EventData>
</Event>
'@
                }
                return @($Success)
            }
        }

        Mock -CommandName Export-Csv -ModuleName $ModuleName -MockWith { }
        Mock -CommandName Test-Path -ModuleName $ModuleName -MockWith { $true }
        Mock -CommandName New-Item -ModuleName $ModuleName -MockWith { }
    }

    Context 'Parameters and metadata' {
        It 'Should expose expected parameters and WhatIf support' {
            $Command = Get-Command -Name $FunctionName
            $Command.Parameters.ContainsKey('DomainController') | Should -Be $true
            $Command.Parameters.ContainsKey('TimeSpanMinutes') | Should -Be $true
            $Command.Parameters.ContainsKey('FailureThreshold') | Should -Be $true
            $Command.Parameters.ContainsKey('ExcludeSourceIPs') | Should -Be $true
            $Command.Parameters.ContainsKey('ExportPath') | Should -Be $true
            $Command.Parameters.ContainsKey('WhatIf') | Should -Be $true
        }
    }

    Context 'Detection behavior' {
        It 'Should detect password spray when unique account threshold is reached' {
            $Result = & $FunctionName @script:BaseArgs -FailureThreshold 10

            $Result | Should -Not -BeNullOrEmpty
            $Result.DetectionType | Should -Be 'PasswordSpray'
            $Result.SourceIP | Should -Be '10.10.10.50'
            $Result.UniqueTargetAccounts | Should -BeGreaterOrEqual 10
        }

        It 'Should not detect when source IP is excluded' {
            $Result = & $FunctionName -DomainController 'DC01' -FailureThreshold 10 -ExcludeSourceIPs '10.10.10.50'
            $Result | Should -BeNullOrEmpty
        }

        It 'Should discover a domain controller if not provided' {
            & $FunctionName -FailureThreshold 10 -ExcludeSourceIPs '203.0.113.254'
            Should -Invoke -CommandName Get-ADDomainController -ModuleName $ModuleName -Times 1
        }

        It 'Should skip duplicate domain controller in pipeline' {
            @('DC01','DC01') | & $FunctionName -FailureThreshold 10 -ExcludeSourceIPs '203.0.113.254' | Out-Null
            Should -Invoke -CommandName Get-WinEvent -ModuleName $ModuleName -ParameterFilter { $FilterHashtable.Id -eq 4625 } -Times 1
        }
    }

    Context 'Export behavior' {
        It 'Should export main and detailed csv reports' {
            & $FunctionName @script:BaseArgs -FailureThreshold 10 -ExportPath 'C:\Reports\PasswordSpray.csv'
            Should -Invoke -CommandName Export-Csv -ModuleName $ModuleName -Times 2
        }

        It 'Should honor WhatIf and skip export' {
            & $FunctionName @script:BaseArgs -FailureThreshold 10 -ExportPath 'C:\Reports\PasswordSpray.csv' -WhatIf
            Should -Invoke -CommandName Export-Csv -ModuleName $ModuleName -Times 0 -Exactly
        }
    }
}
