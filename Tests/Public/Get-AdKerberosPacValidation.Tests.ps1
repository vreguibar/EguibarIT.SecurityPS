Describe 'Get-AdKerberosPacValidation' -Tag 'Unit' {
    BeforeAll {
        $ModulePath = Join-Path -Path $PSScriptRoot -ChildPath '..\..\EguibarIT.SecurityPS.psd1'
        Import-Module $ModulePath -Force
        $FunctionName = 'Get-AdKerberosPacValidation'
    }

    BeforeEach {
        Mock -CommandName Get-ADDomainController -ModuleName 'EguibarIT.SecurityPS' -MockWith {
            [PSCustomObject]@{ HostName = 'DC01.contoso.com' }
        }

        Mock -CommandName Get-WinEvent -ModuleName 'EguibarIT.SecurityPS' -MockWith {
            $Events = @()

            $SafeEvent = [PSCustomObject]@{ TimeCreated = (Get-Date).AddMinutes(-2) }
            $SafeEvent | Add-Member -MemberType ScriptMethod -Name ToXml -Force -Value {
                @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <EventData>
    <Data Name="TargetUserName">legitimateuser</Data>
    <Data Name="ServiceName">LDAP/DC01.contoso.com</Data>
    <Data Name="TicketEncryptionType">0x12</Data>
    <Data Name="Status">0x0</Data>
    <Data Name="IpAddress">::ffff:10.0.0.10</Data>
  </EventData>
</Event>
'@
            }

            $UnsafeEvent = [PSCustomObject]@{ TimeCreated = (Get-Date).AddMinutes(-1) }
            $UnsafeEvent | Add-Member -MemberType ScriptMethod -Name ToXml -Force -Value {
                @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <EventData>
    <Data Name="TargetUserName">svc_admin</Data>
    <Data Name="ServiceName">LDAP/DC01.contoso.com</Data>
    <Data Name="TicketEncryptionType">0x17</Data>
    <Data Name="Status">0x1F</Data>
    <Data Name="IpAddress">::ffff:10.0.0.50</Data>
  </EventData>
</Event>
'@
            }

            $Events += $SafeEvent
            $Events += $UnsafeEvent
            return $Events
        }
    }

    Context 'Parameter and metadata' {
        It 'Should expose the expected parameters' {
            $Command = Get-Command -Name $FunctionName
            $Command.Parameters.ContainsKey('DomainController') | Should -Be $true
            $Command.Parameters.ContainsKey('TimeSpanMinutes') | Should -Be $true
            $Command.Parameters.ContainsKey('MinimumIssueCount') | Should -Be $true
            $Command.Parameters.ContainsKey('ServiceName') | Should -Be $true
            $Command.Parameters.ContainsKey('ExportPath') | Should -Be $true
            $Command.Parameters.ContainsKey('WhatIf') | Should -Be $true
        }
    }

    Context 'Validation behavior' {
        It 'Should report PAC validation failures as critical findings' {
            $Result = & $FunctionName -DomainController 'DC01' -TimeSpanMinutes 60

            $Result | Should -Not -BeNullOrEmpty
            $Result[0].ValidationState | Should -Be 'Failure'
            $Result[0].Severity | Should -Be 'Critical'
            $Result[0].StatusCode | Should -Be '0x1F'
        }

        It 'Should include recommended remediation guidance' {
            $Result = & $FunctionName -DomainController 'DC01' -TimeSpanMinutes 60
            $Result[0].RecommendedActions | Should -Not -BeNullOrEmpty
            $Result[0].RecommendedActions -join ' ' | Should -Match 'PAC|validation|Kerberos'
        }
    }
}
