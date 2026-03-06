Describe 'Get-SilverTicketDetection Setup' {
BeforeAll {
    # Import the module
    $ModulePath = Join-Path -Path $PSScriptRoot -ChildPath '..\..\EguibarIT.SecurityPS.psd1'
    Import-Module $ModulePath -Force

    $FunctionName = 'Get-SilverTicketDetection'

    # Mock internal functions
    Mock -CommandName Initialize-EventLogging -MockWith { }
    Mock -CommandName Initialize-ModuleVariable -MockWith {
        $Global:Variables = @{
            HeaderSecurity = '{0} - {1} - {2}'
            FooterSecurity = '{0} - {1}'
        }
    }
}

BeforeEach {
    # Mock Import-MyModule
    Mock -CommandName Import-MyModule -MockWith {
        return $true
    }

    # Mock Get-ADDomain
    Mock -CommandName Get-ADDomain -MockWith {
        return [PSCustomObject]@{
            DNSRoot     = 'contoso.com'
            PDCEmulator = 'DC01.contoso.com'
        }
    }

    # Mock Get-ADDomainController
    Mock -CommandName Get-ADDomainController -MockWith {
        return @(
            [PSCustomObject]@{ Name = 'DC01' },
            [PSCustomObject]@{ Name = 'DC02' }
        )
    }

    # Mock Get-ADComputer for auto-discovery and stale computer accounts
    Mock -CommandName Get-ADComputer -MockWith {
        param($Filter, $Properties)

        if ($Properties -contains 'ServicePrincipalName') {
            # SQL servers
            return @(
                [PSCustomObject]@{
                    Name                 = 'SQLPROD01'
                    ServicePrincipalName = @('MSSQLSvc/SQLPROD01.contoso.com:1433')
                },
                [PSCustomObject]@{
                    Name                 = 'SQLPROD02'
                    ServicePrincipalName = @('MSSQLSvc/SQLPROD02.contoso.com:1433')
                }
            )
        } elseif ($Filter -match 'FILE|FS') {
            # File servers
            return @(
                [PSCustomObject]@{ Name = 'FILESERVER01' }
            )
        } elseif ($Properties -contains 'PasswordLastSet') {
            # Stale computer accounts
            return @(
                [PSCustomObject]@{
                    Name            = 'STALEPC01'
                    PasswordLastSet = (Get-Date).AddDays(-45)
                },
                [PSCustomObject]@{
                    Name            = 'STALEPC02'
                    PasswordLastSet = (Get-Date).AddDays(-90)
                }
            )
        } else {
            return @()
        }
    }

    # Mock Get-ADUser for service account audit
    Mock -CommandName Get-ADUser -MockWith {
        param($Filter, $Properties)

        if ($Properties -contains 'ServicePrincipalName') {
            # Return service accounts
            return @(
                #gMSA with modern encryption
                [PSCustomObject]@{
                    SamAccountName                  = 'svc_gmsa_sql$'
                    ServicePrincipalName            = @('MSSQLSvc/SQLPROD01.contoso.com:1433')
                    PasswordLastSet                 = (Get-Date).AddDays(-1)
                    PasswordNeverExpires            = $false
                    ObjectClass                     = 'msDS-GroupManagedServiceAccount'
                    MemberOf                        = @()
                    'msDS-SupportedEncryptionTypes' = 0x1C  # AES128/256 + DES
                },
                # High-risk service account: Domain Admin + old password
                [PSCustomObject]@{
                    SamAccountName                  = 'svc_admin'
                    ServicePrincipalName            = @('CIFS/FILESERVER01.contoso.com')
                    PasswordLastSet                 = (Get-Date).AddDays(-400)
                    PasswordNeverExpires            = $true
                    ObjectClass                     = 'user'
                    MemberOf                        = @('CN=Domain Admins,CN=Users,DC=contoso,DC=com')
                    'msDS-SupportedEncryptionTypes' = 0x04  # RC4 only
                },
                # Medium-risk service account: old password, no gMSA
                [PSCustomObject]@{
                    SamAccountName                  = 'svc_backup'
                    ServicePrincipalName            = @('HOST/BACKUPSERVER.contoso.com')
                    PasswordLastSet                 = (Get-Date).AddDays(-120)
                    PasswordNeverExpires            = $false
                    ObjectClass                     = 'user'
                    MemberOf                        = @()
                    'msDS-SupportedEncryptionTypes' = 0x1C
                }
            )
        } else {
            # User verification during event analysis
            $FilterString = $Filter.ToString()
            if ($FilterString -match 'legitimate|admin') {
                return [PSCustomObject]@{
                    SamAccountName = 'legitimateuser'
                }
            } else {
                return $null  # Non-existent user
            }
        }
    }

    # Mock Get-WinEvent for Event 4769 (Service ticket requests)
    Mock -CommandName Get-WinEvent -MockWith {
        param($ComputerName, $FilterHashtable)

        if ($FilterHashtable.Id -eq 4769) {
            # Return service ticket events
            $Event1 = [PSCustomObject]@{
                TimeCreated = (Get-Date).AddMinutes(-10)
                Id          = 4769
            }

            $Event2 = [PSCustomObject]@{
                TimeCreated = (Get-Date).AddMinutes(-5)
                Id          = 4769
            }

            $Event3 = [PSCustomObject]@{
                TimeCreated = (Get-Date).AddMinutes(-3)
                Id          = 4769
            }

            # Normal service ticket
            $Event1 | Add-Member -MemberType ScriptMethod -Name 'ToXml' -Force -Value {
                return @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <EventData>
    <Data Name="TargetUserName">legitimateuser</Data>
    <Data Name="ServiceName">MSSQLSvc/SQLPROD01.contoso.com:1433</Data>
    <Data Name="TicketEncryptionType">0x12</Data>
    <Data Name="Status">0x0</Data>
    <Data Name="IpAddress">::ffff:192.168.1.50</Data>
  </EventData>
</Event>
'@
            }

            # Deleted user service ticket (CRITICAL)
            $Event2 | Add-Member -MemberType ScriptMethod -Name 'ToXml' -Force -Value {
                return @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <EventData>
    <Data Name="TargetUserName">deleteduser</Data>
    <Data Name="ServiceName">CIFS/FILESERVER01.contoso.com</Data>
    <Data Name="TicketEncryptionType">0x17</Data>
    <Data Name="Status">0x0</Data>
    <Data Name="IpAddress">::ffff:192.168.1.99</Data>
  </EventData>
</Event>
'@
            }

            # PAC validation failure (CRITICAL)
            $Event3 | Add-Member -MemberType ScriptMethod -Name 'ToXml' -Force -Value {
                return @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <EventData>
    <Data Name="TargetUserName">testuser</Data>
    <Data Name="ServiceName">LDAP/DC01.contoso.com</Data>
    <Data Name="TicketEncryptionType">0x12</Data>
    <Data Name="Status">0x1F</Data>
    <Data Name="IpAddress">::ffff:192.168.1.100</Data>
  </EventData>
</Event>
'@
            }

            return @($Event1, $Event2, $Event3)

        } elseif ($FilterHashtable.Id -eq 4624) {
            # Logon events
            $LogonEvent = [PSCustomObject]@{
                TimeCreated = (Get-Date).AddMinutes(-2)
                Id          = 4624
            }

            # Logon without matching service ticket
            $LogonEvent | Add-Member -MemberType ScriptMethod -Name 'ToXml' -Force -Value {
                return @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <EventData>
    <Data Name="TargetUserName">suspicioususer</Data>
    <Data Name="LogonType">3</Data>
    <Data Name="IpAddress">::ffff:192.168.1.200</Data>
  </EventData>
</Event>
'@
            }

            return @($LogonEvent)
        }
    }

    # Mock Get-FunctionDisplay
    Mock -CommandName Get-FunctionDisplay -MockWith {
        return 'Mocked Display'
    }

    # Mock Export-Csv
    Mock -CommandName Export-Csv -MockWith { }

    # Mock Test-Path
    Mock -CommandName Test-Path -MockWith {
        param($Path, $PathType)
        if ($PathType -eq 'Container' -or $Path -match '\\$') {
            return $false  # Directory doesn't exist
        }
        return $true
    }

    # Mock New-Item
    Mock -CommandName New-Item -MockWith {
        param($Path, $ItemType)
        return [PSCustomObject]@{
            FullName = $Path
        }
    }

    # Mock Start-Process
    Mock -CommandName Start-Process -MockWith { }
}

AfterEach {
    # Cleanup
    [System.GC]::Collect()
}

Describe 'Get-SilverTicketDetection' -Tag 'Unit' {

    Context 'Parameter Validation' {

        It 'Should have TargetServers parameter as string array' {
            $Command = Get-Command -Name $FunctionName
            $Parameter = $Command.Parameters['TargetServers']

            $Parameter | Should -Not -BeNullOrEmpty
            $Parameter.ParameterType.Name | Should -Match 'String\[\]'
        }

        It 'Should have ServiceTypes parameter with default values' {
            $Command = Get-Command -Name $FunctionName
            $Parameter = $Command.Parameters['ServiceTypes']

            $Parameter | Should -Not -BeNullOrEmpty
            $Parameter.Attributes.Where({ $_ -is [PSDefaultValue] }) | Should -Not -BeNullOrEmpty
        }

        It 'Should have Hours parameter with valid range 1-720' {
            $Command = Get-Command -Name $FunctionName
            $Parameter = $Command.Parameters['Hours']

            $Parameter | Should -Not -BeNullOrEmpty
            $Parameter.Attributes.Where({ $_ -is [ValidateRange] }).MinRange | Should -Be 1
            $Parameter.Attributes.Where({ $_ -is [ValidateRange] }).MaxRange | Should -Be 720
        }

        It 'Should have ExportPath parameter with ValidateScript' {
            $Command = Get-Command -Name $FunctionName
            $Parameter = $Command.Parameters['ExportPath']

            $Parameter | Should -Not -BeNullOrEmpty
            $Parameter.Attributes.Where({ $_ -is [ValidateScript] }) | Should -Not -BeNullOrEmpty
        }

        It 'Should have IncludeServiceAccountAudit switch parameter' {
            $Command = Get-Command -Name $FunctionName
            $Parameter = $Command.Parameters['IncludeServiceAccountAudit']

            $Parameter | Should -Not -BeNullOrEmpty
            $Parameter.SwitchParameter | Should -Be $true
        }

        It 'Should have BaselineMode switch parameter' {
            $Command = Get-Command -Name $FunctionName
            $Parameter = $Command.Parameters['BaselineMode']

            $Parameter | Should -Not -BeNullOrEmpty
            $Parameter.SwitchParameter | Should -Be $true
        }

        It 'Should have Remediate switch parameter' {
            $Command = Get-Command -Name $FunctionName
            $Parameter = $Command.Parameters['Remediate']

            $Parameter | Should -Not -BeNullOrEmpty
            $Parameter.SwitchParameter | Should -Be $true
        }

        It 'Should support WhatIf parameter (ShouldProcess)' {
            $Command = Get-Command -Name $FunctionName
            $Command.Parameters.ContainsKey('WhatIf') | Should -Be $true
        }

    } #end Context Parameter Validation

    Context 'Core Detection Behavior' {

        It 'Should return a PSCustomObject' {
            $Result = & $FunctionName

            $Result | Should -Not -BeNullOrEmpty
            $Result | Should -BeOfType [PSCustomObject]
        }

        It 'Should call Get-ADDomain to retrieve domain information' {
            $Result = & $FunctionName

            Should -Invoke -CommandName Get-ADDomain -Times 1 -Exactly
        }

        It 'Should auto-discover target servers when TargetServers is empty' {
            $Result = & $FunctionName

            Should -Invoke -CommandName Get-ADDomainController -Times 1 -Exactly
            $Result.TargetServerCount | Should -BeGreaterThan 0
        }

        It 'Should use provided TargetServers when specified' {
            $Result = & $FunctionName -TargetServers 'SQLPROD01', 'SQLPROD02'

            $Result.TargetServerCount | Should -Be 2
        }

        It 'Should populate DomainName property' {
            $Result = & $FunctionName

            $Result.DomainName | Should -Be 'contoso.com'
        }

        It 'Should populate PdcEmulator property' {
            $Result = & $FunctionName

            $Result.PdcEmulator | Should -Match 'DC01'
        }

        It 'Should populate AuditTimestamp with current date' {
            $Result = & $FunctionName

            $Result.AuditTimestamp | Should -Not -BeNullOrEmpty
            $Result.AuditTimestamp | Should -BeOfType [DateTime]
        }

        It 'Should populate TimeWindowHours from Hours parameter' {
            $Result = & $FunctionName -Hours 48

            $Result.TimeWindowHours | Should -Be 48
        }

        It 'Should populate ServiceTypeCount from ServiceTypes parameter' {
            $Result = & $FunctionName -ServiceTypes 'MSSQLSvc', 'CIFS'

            $Result.ServiceTypeCount | Should -Be 2
        }

    } #end Context Core Detection Behavior

    Context 'Phase 1: Service Account Security Audit' {

        It 'Should query service accounts with SPN' {
            $Result = & $FunctionName

            Should -Invoke -CommandName Get-ADUser -ParameterFilter {
                $Properties -contains 'ServicePrincipalName'
            }
        }

        It 'Should populate ServiceAccountAudit array' {
            $Result = & $FunctionName

            $Result.ServiceAccountAudit | Should -Not -BeNullOrEmpty
            $Result.ServiceAccountAudit.Count | Should -BeGreaterThan 0
        }

        It 'Should detect gMSA accounts correctly' {
            $Result = & $FunctionName

            $GmsaAccount = $Result.ServiceAccountAudit | Where-Object { $_.SamAccountName -match '\$' }
            $GmsaAccount.IsGMSA | Should -Be $true
        }

        It 'Should calculate password age for service accounts' {
            $Result = & $FunctionName

            $Result.ServiceAccountAudit[0] | Should -HaveProperty 'PasswordAge_Days'
            $Result.ServiceAccountAudit[0].PasswordAge_Days | Should -BeGreaterOrEqual 0
        }

        It 'Should categorize service accounts by risk level' {
            $Result = & $FunctionName

            $CriticalAccount = $Result.ServiceAccountAudit | Where-Object { $_.RiskLevel -eq 'CRITICAL' }
            $CriticalAccount | Should -Not -BeNullOrEmpty
        }

        It 'Should flag Domain Admin service accounts as high risk' {
            $Result = & $FunctionName

            $DomainAdminSvc = $Result.ServiceAccountAudit | Where-Object { $_.IsDomainAdmin -eq $true }
            $DomainAdminSvc | Should -Not -BeNullOrEmpty
            $DomainAdminSvc.RiskLevel | Should -BeIn @('CRITICAL', 'HIGH')
        }

        It 'Should detect RC4 encryption support' {
            $Result = & $FunctionName

            $RC4Account = $Result.ServiceAccountAudit | Where-Object { $_.RC4_Enabled -eq $true }
            $RC4Account | Should -Not -BeNullOrEmpty
        }

        It 'Should recommend gMSA migration for high-risk accounts' {
            $Result = & $FunctionName

            $HighRiskAccount = $Result.ServiceAccountAudit | Where-Object { $_.RiskLevel -in @('HIGH', 'CRITICAL') }
            $HighRiskAccount.Recommendation | Should -Match 'gMSA|rotate'
        }

        It 'Should populate HighRiskServiceAccountCount property' {
            $Result = & $FunctionName

            $Result.HighRiskServiceAccountCount | Should -BeGreaterThan 0
        }

    } #end Context Phase 1

    Context 'Phase 2: Event 4624/4769 Missing Service Ticket Correlation' {

        It 'Should query Event 4769 (Service ticket requests)' {
            $Result = & $FunctionName -TargetServers 'SQLPROD01'

            Should -Invoke -CommandName Get-WinEvent -ParameterFilter {
                $FilterHashtable.Id -eq 4769
            }
        }

        It 'Should query Event 4624 (Logon events) for target servers' {
            $Result = & $FunctionName -TargetServers 'SQLPROD01'

            Should -Invoke -CommandName Get-WinEvent -ParameterFilter {
                $FilterHashtable.Id -eq 4624
            }
        }

        It 'Should correlate logons with service ticket requests' {
            $Result = & $FunctionName -TargetServers 'SQLPROD01'

            # Should detect missing service ticket for suspicioususer
            $Result.MissingServiceTicketFindings | Should -Not -BeNullOrEmpty
        }

        It 'Should populate MissingServiceTicketCount property' {
            $Result = & $FunctionName -TargetServers 'SQLPROD01'

            $Result.MissingServiceTicketCount | Should -BeGreaterThan 0
        }

        It 'Should flag non-existent user logons as CRITICAL' {
            $Result = & $FunctionName -TargetServers 'SQLPROD01'

            $CriticalLogon = $Result.MissingServiceTicketFindings | Where-Object {
                $_.Severity -eq 'CRITICAL'
            }
            # Suspicioususer does not exist in our mock
            $CriticalLogon | Should -Not -BeNullOrEmpty
        }

    } #end Context Phase 2

    Context 'Phase 3: Event 4769 Service Ticket Anomaly Analysis' {

        It 'Should detect service tickets for non-existent users' {
            $Result = & $FunctionName

            $NonExistentAnomaly = $Result.ServiceTicketAnomalies | Where-Object {
                $_.AnomalyType -match 'Non-Existent'
            }
            $NonExistentAnomaly | Should -Not -BeNullOrEmpty
        }

        It 'Should flag RC4 encryption in service tickets as MEDIUM' {
            $Result = & $FunctionName

            $RC4Anomaly = $Result.ServiceTicketAnomalies | Where-Object {
                $_.AnomalyType -match 'RC4' -and $_.Severity -eq 'MEDIUM'
            }
            $RC4Anomaly | Should -Not -BeNullOrEmpty
        }

        It 'Should detect PAC validation failures as CRITICAL' {
            $Result = & $FunctionName

            $PACAnomaly = $Result.ServiceTicketAnomalies | Where-Object {
                $_.AnomalyType -match 'PAC' -and $_.Severity -eq 'CRITICAL'
            }
            $PACAnomaly | Should -Not -BeNullOrEmpty
        }

        It 'Should populate ServiceTicketAnomalyCount property' {
            $Result = & $FunctionName

            $Result.ServiceTicketAnomalyCount | Should -BeGreaterThan 0
        }

        It 'Should add CRITICAL service ticket anomalies to Detections' {
            $Result = & $FunctionName

            $CriticalDetection = $Result.Detections | Where-Object {
                $_.DetectionType -match 'Service Ticket' -and $_.Severity -eq 'CRITICAL'
            }
            $CriticalDetection | Should -Not -BeNullOrEmpty
        }

    } #end Context Phase 3

    Context 'Phase 4: Computer Account Silver Ticket Indicators' {

        It 'Should detect stale computer account passwords' {
            $Result = & $FunctionName

            Should -Invoke -CommandName Get-ADComputer -ParameterFilter {
                $Properties -contains 'PasswordLastSet'
            }
        }

        It 'Should populate ComputerAccountAnomalyCount property' {
            $Result = & $FunctionName -TargetServers 'SQLPROD01'

            $Result.ComputerAccountAnomalyCount | Should -BeGreaterOrEqual 0
        }

    } #end Context Phase 4

    Context 'Phase 5: Behavioral Baseline Advisory' {

        It 'Should populate BehavioralBaselineRecommendations array' {
            $Result = & $FunctionName

            $Result.BehavioralBaselineRecommendations | Should -Not -BeNullOrEmpty
            $Result.BehavioralBaselineRecommendations.Count | Should -BeGreaterThan 0
        }

        It 'Should recommend UEBA/SIEM integration' {
            $Result = & $FunctionName

            $Result.BehavioralBaselineRecommendations -join ' ' | Should -Match 'UEBA|SIEM|Sentinel|Splunk'
        }

        It 'Should include baseline mode advisory when enabled' {
            $Result = & $FunctionName -BaselineMode

            $Result.BehavioralBaselineRecommendations -join ' ' | Should -Match 'Baseline mode'
        }

        It 'Should report stale computer account count' {
            $Result = & $FunctionName

            $Result.BehavioralBaselineRecommendations -join ' ' | Should -Match 'Stale computer'
        }

    } #end Context Phase 5

    Context 'BaselineMode Behavior' {

        It 'Should set BaselineMode property when switch is used' {
            $Result = & $FunctionName -BaselineMode

            $Result.BaselineMode | Should -Be $true
        }

        It 'Should suppress adding detections to Detections array in baseline mode' {
            $Result = & $FunctionName -BaselineMode

            $Result.TotalDetections | Should -Be 0
        }

        It 'Should still populate anomaly arrays in baseline mode' {
            $Result = & $FunctionName -BaselineMode

            $Result.ServiceTicketAnomalies.Count | Should -BeGreaterThan 0
        }

        It 'Should modify RecommendedActions in baseline mode' {
            $Result = & $FunctionName -BaselineMode

            $Result.RecommendedActions -join ' ' | Should -Match 'Baseline mode'
        }

    } #end Context BaselineMode

    Context 'Risk Assessment and Severity' {

        It 'Should categorize findings by severity (Critical/High/Medium)' {
            $Result = & $FunctionName

            $Result.CriticalDetections | Should -BeGreaterOrEqual 0
            $Result.HighDetections | Should -BeGreaterOrEqual 0
            $Result.MediumDetections | Should -BeGreaterOrEqual 0
        }

        It 'Should calculate TotalDetections correctly' {
            $Result = & $FunctionName

            $Result.TotalDetections | Should -BeGreaterThan 0
        }

        It 'Should set IsSecure to false when critical or high findings exist' {
            $Result = & $FunctionName

            $Result.IsSecure | Should -Be $false
        }

        It 'Should set RiskLevel based on highest severity finding' {
            $Result = & $FunctionName

            $Result.RiskLevel | Should -BeIn @('Critical', 'High', 'Medium', 'Secure')
        }

        It 'Should populate RecommendedActions based on risk level' {
            $Result = & $FunctionName

            $Result.RecommendedActions | Should -Not -BeNullOrEmpty
            $Result.RecommendedActions.Count | Should -BeGreaterThan 0
        }

    } #end Context Risk Assessment

    Context 'Export Functionality' {

        It 'Should export Detections to CSV when findings exist' {
            $Result = & $FunctionName -ExportPath 'C:\Reports'

            Should -Invoke -CommandName Export-Csv -ParameterFilter {
                $Path -match 'SilverTicket-Detections-\d{8}-\d{6}\.csv'
            }
        }

        It 'Should export ServiceAccountAudit when IncludeServiceAccountAudit is specified' {
            $Result = & $FunctionName -ExportPath 'C:\Reports' -IncludeServiceAccountAudit

            Should -Invoke -CommandName Export-Csv -ParameterFilter {
                $Path -match 'SilverTicket-ServiceAccountAudit-\d{8}-\d{6}\.csv'
            }
        }

        It 'Should export ServiceTicketAnomalies to CSV' {
            $Result = & $FunctionName -ExportPath 'C:\Reports'

            Should -Invoke -CommandName Export-Csv -ParameterFilter {
                $Path -match 'SilverTicket-4769Anomalies-\d{8}-\d{6}\.csv'
            }
        }

        It 'Should create export directory if it does not exist' {
            $Result = & $FunctionName -ExportPath 'C:\NewReports'

            Should -Invoke -CommandName New-Item -ParameterFilter {
                $ItemType -eq 'Directory' -and $Path -eq 'C:\NewReports'
            }
        }

        It 'Should populate ExportedReports array with file paths' {
            $Result = & $FunctionName -ExportPath 'C:\Reports'

            $Result.ExportedReports | Should -Not -BeNullOrEmpty
            $Result.ExportedReports.Count | Should -BeGreaterThan 0
        }

        It 'Should respect WhatIf parameter and not export reports' {
            $Result = & $FunctionName -ExportPath 'C:\Reports' -WhatIf

            Should -Invoke -CommandName Export-Csv -Times 0 -Exactly
        }

        It 'Should include timestamp in export filenames (yyyyMMdd-HHmmss)' {
            $Result = & $FunctionName -ExportPath 'C:\Reports'

            Should -Invoke -CommandName Export-Csv -ParameterFilter {
                $Path -match '\d{8}-\d{6}'
            }
        }

    } #end Context Export Functionality

    Context 'Remediation Guidance' {

        It 'Should recommend service account password rotation when critical findings detected' {
            $Result = & $FunctionName

            if ($Result.CriticalDetections -gt 0) {
                $Result.RecommendedActions -join ' ' | Should -Match 'rotate|password'
            }
        }

        It 'Should recommend PAC validation enforcement when anomalies detected' {
            $Result = & $FunctionName

            if ($Result.ServiceTicketAnomalyCount -gt 0) {
                $Result.RecommendedActions -join ' ' | Should -Match 'PAC'
            }
        }

        It 'Should include service account hardening guidance when IncludeServiceAccountAudit is used' {
            $Result = & $FunctionName -IncludeServiceAccountAudit

            $Result.RecommendedActions -join ' ' | Should -Match 'gMSA|hardening'
        }

        It 'Should open remediation URL when Remediate switch is used with critical findings' {
            $Result = & $FunctionName -Remediate

            if ($Result.CriticalDetections -gt 0) {
                Should -Invoke -CommandName Start-Process -Times 1 -Exactly
            }
        }

        It 'Should not open remediation URL in baseline mode' {
            $Result = & $FunctionName -BaselineMode -Remediate

            Should -Invoke -CommandName Start-Process -Times 0 -Exactly
        }

    } #end Context Remediation Guidance

    Context 'Error Handling' {

        It 'Should handle Get-ADDomain failures gracefully' {
            Mock -CommandName Get-ADDomain -MockWith {
                throw 'Access denied'
            }

            { & $FunctionName -ErrorAction Stop } | Should -Throw
        }

        It 'Should handle Get-WinEvent failures for individual servers' {
            Mock -CommandName Get-WinEvent -MockWith {
                throw 'RPC server is unavailable'
            }

            $Result = & $FunctionName -TargetServers 'SQLPROD01' -WarningAction SilentlyContinue

            $Result | Should -Not -BeNullOrEmpty
        }

        It 'Should continue when service account query fails' {
            Mock -CommandName Get-ADUser -MockWith {
                if ($Properties -contains 'ServicePrincipalName') {
                    return @()
                }
                return $null
            }

            $Result = & $FunctionName

            $Result | Should -Not -BeNullOrEmpty
        }

    } #end Context Error Handling

    Context 'Output Object Structure' {

        It 'Should have all required properties in output object' {
            $Result = & $FunctionName

            $Result | Should -HaveProperty 'DomainName'
            $Result | Should -HaveProperty 'PdcEmulator'
            $Result | Should -HaveProperty 'BaselineMode'
            $Result | Should -HaveProperty 'TotalDetections'
            $Result | Should -HaveProperty 'IsSecure'
            $Result | Should -HaveProperty 'RiskLevel'
            $Result | Should -HaveProperty 'ServiceAccountAudit'
            $Result | Should -HaveProperty 'Detections'
        }

        It 'Should include phase-specific counts' {
            $Result = & $FunctionName

            $Result | Should -HaveProperty 'HighRiskServiceAccountCount'
            $Result | Should -HaveProperty 'MissingServiceTicketCount'
            $Result | Should -HaveProperty 'ServiceTicketAnomalyCount'
            $Result | Should -HaveProperty 'ComputerAccountAnomalyCount'
        }

        It 'Should include phase-specific data arrays' {
            $Result = & $FunctionName

            $Result | Should -HaveProperty 'MissingServiceTicketFindings'
            $Result | Should -HaveProperty 'ServiceTicketAnomalies'
            $Result | Should -HaveProperty 'ComputerAccountAnomalies'
            $Result | Should -HaveProperty 'BehavioralBaselineRecommendations'
        }

    } #end Context Output Object Structure

} #end Describe Get-SilverTicketDetection

} #end Describe Setup Wrapper
