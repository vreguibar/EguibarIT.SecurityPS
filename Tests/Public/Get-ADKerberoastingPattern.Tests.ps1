Describe 'Get-ADKerberoastingPattern' -Tag 'Unit' {

    BeforeAll {
        $ModulePath = Join-Path -Path $PSScriptRoot -ChildPath '..\\..\\EguibarIT.SecurityPS.psd1'
        Import-Module $ModulePath -Force

        $ModuleName = 'EguibarIT.SecurityPS'
        $FunctionName = 'Get-ADKerberoastingPattern'

        if (-not (Get-Command -Name Get-FunctionDisplay -ErrorAction SilentlyContinue)) {
            function Get-FunctionDisplay {
                param($HashTable) return 'Stub Display'
            }
        }
    }

    BeforeEach {
        Mock -CommandName Get-FunctionDisplay -ModuleName $ModuleName -MockWith { 'Mocked Display' }
        Mock -CommandName Get-ADDomainController -ModuleName $ModuleName -MockWith {
            [PSCustomObject]@{ HostName = 'DC01.contoso.com' }
        }

        Mock -CommandName Get-WinEvent -ModuleName $ModuleName -MockWith {
            $Events = @()
            1..12 | ForEach-Object {
                $EventObj = [PSCustomObject]@{ TimeCreated = (Get-Date).AddMinutes(-$_) }
                $EventObj | Add-Member -MemberType ScriptMethod -Name ToXml -Force -Value {
                    @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <EventData>
    <Data Name="TargetDomainName">CONTOSO</Data>
    <Data Name="TargetUserName">svc_sql</Data>
    <Data Name="ServiceName">MSSQLSvc/sql01.contoso.com:1433</Data>
    <Data Name="IpAddress">10.10.10.25</Data>
    <Data Name="TicketEncryptionType">0x17</Data>
    <Data Name="TicketOptions">0x40810000</Data>
  </EventData>
</Event>
'@
                }
                $Events += $EventObj
            }
            return $Events
        }

        Mock -CommandName Export-Csv -ModuleName $ModuleName -MockWith { }
        Mock -CommandName Test-Path -ModuleName $ModuleName -MockWith { $true }
        Mock -CommandName New-Item -ModuleName $ModuleName -MockWith { }
    }

    Context 'Parameter and metadata' {
        It 'Should expose expected parameters' {
            $Command = Get-Command -Name $FunctionName
            $Command.Parameters.ContainsKey('DomainController') | Should -Be $true
            $Command.Parameters.ContainsKey('TimeSpanMinutes') | Should -Be $true
            $Command.Parameters.ContainsKey('ThresholdCount') | Should -Be $true
            $Command.Parameters.ContainsKey('ExportPath') | Should -Be $true
            $Command.Parameters.ContainsKey('HoneypotSPNs') | Should -Be $true
            $Command.Parameters.ContainsKey('WhatIf') | Should -Be $true
        }
    }

    Context 'Detection behavior' {
        It 'Should return kerberoasting detections above threshold' {
            $Result = & $FunctionName -DomainController 'DC01' -ThresholdCount 10

            $Result | Should -Not -BeNullOrEmpty
            $Result[0].DetectionType | Should -Be 'Kerberoasting'
            $Result[0].RequestCount | Should -BeGreaterOrEqual 10
            $Result[0].Severity | Should -BeIn @('Low', 'Medium', 'High', 'Critical')
        }

        It 'Should include recommended actions' {
            $Result = & $FunctionName -DomainController 'DC01' -ThresholdCount 10
            $Result[0].RecommendedActions | Should -Not -BeNullOrEmpty
        }

        It 'Should return no detections when threshold is too high' {
            {
                & $FunctionName -DomainController 'DC01' -ThresholdCount 100 -ErrorAction Stop
            } | Should -Throw
        }

        It 'Should discover domain controller when not provided' {
            & $FunctionName -ThresholdCount 10
            Should -Invoke -CommandName Get-ADDomainController -ModuleName $ModuleName -Times 1
        }
    }

    Context 'Honeypot detection' {
        It 'Should detect honeypot SPN access as critical' {
            $Result = & $FunctionName -DomainController 'DC01' -ThresholdCount 10 -HoneypotSPNs 'MSSQLSvc/sql01.contoso.com*'
            $Honeypot = $Result | Where-Object { $_.DetectionType -eq 'HoneypotAccess' }
            $Honeypot | Should -Not -BeNullOrEmpty
            $Honeypot[0].Severity | Should -Be 'Critical'
        }
    }

    Context 'Export behavior' {
        It 'Should export suspicious events when ExportPath is set' {
            & $FunctionName -DomainController 'DC01' -ThresholdCount 10 -ExportPath 'C:\Reports\Kerberoast.csv'
            Should -Invoke -CommandName Export-Csv -ModuleName $ModuleName -Times 1
        }

        It 'Should honor WhatIf and skip export' {
            & $FunctionName -DomainController 'DC01' -ThresholdCount 10 -ExportPath 'C:\Reports\Kerberoast.csv' -WhatIf
            Should -Invoke -CommandName Export-Csv -ModuleName $ModuleName -Times 0 -Exactly
        }
    }
}
