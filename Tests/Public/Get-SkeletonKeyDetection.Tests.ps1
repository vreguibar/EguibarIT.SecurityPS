Describe 'Get-SkeletonKeyDetection' {
    BeforeAll {
        $ModuleName = 'EguibarIT.SecurityPS'
        $PathToManifest = Join-Path -Path $PSScriptRoot -ChildPath ('..\..\{0}.psd1' -f $ModuleName)

        if (-not (Test-Path -Path $PathToManifest)) {
            throw ('Module manifest not found: {0}' -f $PathToManifest)
        } #end if

        if (Get-Module -Name $ModuleName) {
            Remove-Module -Name $ModuleName -Force
        } #end if

        Import-Module -Name $PathToManifest -Force -ErrorAction Stop

        if (-not (Get-Command -Name 'Get-FunctionDisplay' -ErrorAction SilentlyContinue)) {
            function global:Get-FunctionDisplay {
                param(
                    [Parameter(Mandatory = $false)]
                    [hashtable]
                    $Hashtable,

                    [Parameter(Mandatory = $false)]
                    [switch]
                    $Verbose
                )

                return 'MockParameters'
            }
        } #end if

        if (Test-Path -Path Variable:\Variables) {
            $script:Variables = Get-Variable -Name 'Variables' -Scope Global -ValueOnly
        } else {
            $script:Variables = [ordered]@{
                HeaderSecurity = 'Header {0} {1} {2}'
                FooterSecurity = 'Footer {0} {1}'
            }
            New-Variable -Name 'Variables' -Scope Global -Value $script:Variables -Force
        } #end if-else

        if ($script:Variables -is [hashtable]) {
            $script:Variables['HeaderSecurity'] = 'Header {0} {1} {2}'
            $script:Variables['FooterSecurity'] = 'Footer {0} {1}'
        } else {
            if (-not ($script:Variables.PSObject.Properties.Name -contains 'HeaderSecurity')) {
                Add-Member -InputObject $script:Variables -MemberType NoteProperty -Name 'HeaderSecurity' -Value 'Header {0} {1} {2}'
            } else {
                $script:Variables.HeaderSecurity = 'Header {0} {1} {2}'
            } #end if-else

            if (-not ($script:Variables.PSObject.Properties.Name -contains 'FooterSecurity')) {
                Add-Member -InputObject $script:Variables -MemberType NoteProperty -Name 'FooterSecurity' -Value 'Footer {0} {1}'
            } else {
                $script:Variables.FooterSecurity = 'Footer {0} {1}'
            } #end if-else
        } #end if-else
    } #end BeforeAll

    BeforeEach {
        Mock -CommandName Import-MyModule -ModuleName 'EguibarIT.SecurityPS' -MockWith { return }

        Mock -CommandName Get-ADDomainController -ModuleName 'EguibarIT.SecurityPS' -MockWith {
            return @(
                [PSCustomObject]@{
                    Name     = 'DC1'
                    HostName = 'dc1.contoso.com'
                }
            )
        }

        Mock -CommandName Invoke-Command -ModuleName 'EguibarIT.SecurityPS' -MockWith {
            param($ComputerName, $ScriptBlock, $ErrorAction)

            $ScriptText = [string]$ScriptBlock

            if ($ScriptText -match 'Get-ComputerInfo') {
                return [PSCustomObject]@{
                    CredentialGuardConfigured = $false
                    CredentialGuardRunning    = $false
                }
            }

            if ($ScriptText -match 'AuditReceivingNTLMTraffic') {
                return $false
            }

            return $null
        }

        Mock -CommandName Get-Service -ModuleName 'EguibarIT.SecurityPS' -MockWith {
            param($ComputerName, $Name, $ErrorAction)

            if ($Name -eq 'Sysmon64') {
                return [PSCustomObject]@{
                    Name   = 'Sysmon64'
                    Status = 'Running'
                }
            }

            return $null
        }

        Mock -CommandName Get-WinEvent -ModuleName 'EguibarIT.SecurityPS' -MockWith {
            param($ComputerName, $FilterHashtable, $LogName, $FilterXPath, $MaxEvents, $ErrorAction)

            if ($null -ne $FilterHashtable -and $FilterHashtable.Id -eq 10) {
                $Event10 = [PSCustomObject]@{
                    TimeCreated = (Get-Date).AddHours(-1)
                }
                Add-Member -InputObject $Event10 -MemberType ScriptMethod -Name ToXml -Value {
                    @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <EventData>
    <Data Name="SourceImage">C:\Tools\mimikatz.exe</Data>
    <Data Name="SourceUser">contoso\attacker</Data>
    <Data Name="TargetImage">C:\Windows\System32\lsass.exe</Data>
    <Data Name="GrantedAccess">0x1FFFFF</Data>
  </EventData>
</Event>
'@
                }
                return @($Event10)
            }

            if ($null -ne $FilterHashtable -and $FilterHashtable.Id -eq 7045) {
                $Event7045 = [PSCustomObject]@{
                    TimeCreated = (Get-Date).AddHours(-2)
                }
                Add-Member -InputObject $Event7045 -MemberType ScriptMethod -Name ToXml -Value {
                    @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <EventData>
    <Data Name="ServiceName">PSEXESVC</Data>
    <Data Name="ImagePath">C:\Users\Public\temp\payload.exe</Data>
    <Data Name="AccountName">LocalSystem</Data>
  </EventData>
</Event>
'@
                }
                return @($Event7045)
            }

            if ($null -ne $FilterHashtable -and $FilterHashtable.Id -eq 4624) {
                [System.Collections.ArrayList]$Events4624 = @()
                [string[]]$Users = @('user1', 'user2', 'user3', 'user4', 'user5')
                foreach ($User in $Users) {
                    $Event4624 = [PSCustomObject]@{
                        TimeCreated = (Get-Date).AddMinutes(-10)
                    }
                    Add-Member -InputObject $Event4624 -MemberType ScriptMethod -Name ToXml -Value {
                        @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <EventData>
    <Data Name="TargetUserName">{USER}</Data>
    <Data Name="IpAddress">10.10.10.20</Data>
  </EventData>
</Event>
'@ -replace '{USER}', $this.PSObject.Properties['MockUser'].Value
                    }
                    Add-Member -InputObject $Event4624 -MemberType NoteProperty -Name MockUser -Value $User
                    [void]$Events4624.Add($Event4624)
                } #end foreach
                return $Events4624
            }

            if ($LogName -eq 'Microsoft-Windows-NTLM/Operational') {
                $Event8004 = [PSCustomObject]@{
                    TimeCreated = (Get-Date).AddMinutes(-5)
                }
                Add-Member -InputObject $Event8004 -MemberType ScriptMethod -Name ToXml -Value {
                    @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <EventData>
    <Data>admin.svc</Data>
  </EventData>
</Event>
'@
                }
                return @($Event8004)
            }

            return @()
        }
    } #end BeforeEach

    Context 'Parameter validation' {
        It 'Should throw when DaysBack is less than allowed range' {
            { Get-SkeletonKeyDetection -DaysBack 0 -OutputPath $TestDrive } | Should -Throw
        }

        It 'Should throw when DaysBack is greater than allowed range' {
            { Get-SkeletonKeyDetection -DaysBack 366 -OutputPath $TestDrive } | Should -Throw
        }
    }

    Context 'Core behavior' {
        It 'Should return structured output object' {
            $Result = Get-SkeletonKeyDetection -OutputPath $TestDrive

            $Result.PSObject.TypeNames[0] | Should -Be 'EguibarIT.SkeletonKeyDetection'
            $Result.TotalFindings | Should -BeGreaterThan 0
            $Result.CriticalCount | Should -BeGreaterThan 0
        }

        It 'Should include Credential Guard finding when disabled' {
            $Result = Get-SkeletonKeyDetection -OutputPath $TestDrive
            $Finding = $Result.Findings | Where-Object { $_.FindingType -eq 'Credential Guard Not Enabled' }

            $Finding | Should -Not -BeNullOrEmpty
            ($Finding | Select-Object -First 1).RiskLevel | Should -Be 'Critical'
        }

        It 'Should include LSASS memory access finding from Event 10' {
            $Result = Get-SkeletonKeyDetection -OutputPath $TestDrive
            $Finding = $Result.Findings | Where-Object { $_.FindingType -eq 'LSASS Memory Access' }

            $Finding | Should -Not -BeNullOrEmpty
            ($Finding | Select-Object -First 1).EventID | Should -Be 10
        }

        It 'Should include suspicious service installation finding from Event 7045' {
            $Result = Get-SkeletonKeyDetection -OutputPath $TestDrive
            $Finding = $Result.Findings | Where-Object { $_.FindingType -eq 'Suspicious Service Installation' }

            $Finding | Should -Not -BeNullOrEmpty
            ($Finding | Select-Object -First 1).EventID | Should -Be 7045
        }

        It 'Should include multiple users from single IP anomaly' {
            $Result = Get-SkeletonKeyDetection -OutputPath $TestDrive
            $Finding = $Result.Findings | Where-Object { $_.FindingType -eq 'Multiple Users from Single IP' }

            $Finding | Should -Not -BeNullOrEmpty
            ($Finding | Select-Object -First 1).UniqueUserCount | Should -BeGreaterThan 4
        }

        It 'Should include NTLM auditing disabled finding' {
            $Result = Get-SkeletonKeyDetection -OutputPath $TestDrive
            $Finding = $Result.Findings | Where-Object { $_.FindingType -eq 'NTLM Auditing Disabled' }

            $Finding | Should -Not -BeNullOrEmpty
            ($Finding | Select-Object -First 1).RiskLevel | Should -Be 'Medium'
        }
    }

    Context 'Scope and export behavior' {
        It 'Should query all DCs when CheckAllDCs is specified' {
            $Result = Get-SkeletonKeyDetection -OutputPath $TestDrive -CheckAllDCs

            $Result.CheckedAllDomainControllers | Should -BeTrue
            $Result.DomainControllersScanned | Should -BeGreaterThan 0
        }

        It 'Should support WhatIf and avoid report file creation' {
            $ExportPath = Join-Path -Path $TestDrive -ChildPath ('WhatIf_{0}' -f [DateTime]::Now.Ticks)
            $Result = Get-SkeletonKeyDetection -OutputPath $ExportPath -WhatIf

            $Result | Should -Not -BeNullOrEmpty
            $Result.ExportedReports.Count | Should -Be 0
        }

        It 'Should export CSV and JSON when OutputPath is provided' {
            $ExportPath = Join-Path -Path $TestDrive -ChildPath ('Export_{0}' -f [DateTime]::Now.Ticks)
            $Result = Get-SkeletonKeyDetection -OutputPath $ExportPath

            Test-Path -Path $ExportPath | Should -BeTrue
            $Result.ExportedReports.Count | Should -Be 2
        }
    }
}