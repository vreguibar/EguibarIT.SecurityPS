Describe 'Get-GoldenTicketDetection Setup' {
BeforeAll {
    # Import the module
    $ModulePath = Join-Path -Path $PSScriptRoot -ChildPath '..\..\EguibarIT.SecurityPS.psd1'
    Import-Module $ModulePath -Force

    $FunctionName = 'Get-GoldenTicketDetection'

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
            DNSRoot      = 'contoso.com'
            PDCEmulator  = 'DC01.contoso.com'
            Forest       = 'contoso.com'
        }
    }

    # Mock Get-ADForest
    Mock -CommandName Get-ADForest -MockWith {
        return [PSCustomObject]@{
            Name    = 'contoso.com'
            Domains = @('contoso.com', 'child.contoso.com')
        }
    }

    # Mock Get-ADUser for krbtgt queries
    Mock -CommandName Get-ADUser -MockWith {
        param($Identity, $Filter, $Server, $Properties)

        if ($Identity -eq 'krbtgt') {
            # krbtgt account with password age based on server
            if ($Server -eq 'contoso.com') {
                return [PSCustomObject]@{
                    SamAccountName       = 'krbtgt'
                    DistinguishedName    = 'CN=krbtgt,CN=Users,DC=contoso,DC=com'
                    PasswordLastSet      = (Get-Date).AddDays(-200)  # HIGH risk
                    PasswordNeverExpires = $false
                }
            } elseif ($Server -eq 'child.contoso.com') {
                return [PSCustomObject]@{
                    SamAccountName       = 'krbtgt'
                    DistinguishedName    = 'CN=krbtgt,CN=Users,DC=child,DC=contoso,DC=com'
                    PasswordLastSet      = (Get-Date).AddDays(-60)  # LOW risk
                    PasswordNeverExpires = $false
                }
            }
        } elseif ($Filter) {
            # Return existing user for normal accounts
            $FilterString = $Filter.ToString()
            if ($FilterString -match 'legitimate|admin') {
                return [PSCustomObject]@{
                    SamAccountName    = 'legitimateuser'
                    DistinguishedName = 'CN=LegitimateUser,CN=Users,DC=contoso,DC=com'
                    Enabled           = $true
                }
            } else {
                # Non-existent user
                return $null
            }
        }
    }

    # Mock Get-WinEvent for Event 4768 (TGT requests)
    Mock -CommandName Get-WinEvent -MockWith {
        param($ComputerName, $FilterHashtable)

        if ($FilterHashtable.Id -eq 4768) {
            # Return 2 events: legitimate user + non-existent user
            $Event1 = [PSCustomObject]@{
                TimeCreated = (Get-Date).AddMinutes(-30)
                Id          = 4768
                Properties  = @(
                    'legitimateuser',  # TargetUserName
                    '0x40810010',      # TicketOptions
                    '0x12',            # TicketEncryptionType (AES256)
                    '::ffff:192.168.1.50'  # IpAddress
                )
            }

            $Event2 = [PSCustomObject]@{
                TimeCreated = (Get-Date).AddMinutes(-15)
                Id          = 4768
                Properties  = @(
                    'deleteduser',      # Non-existent account
                    '0x40810010',
                    '0x17',             # RC4 encryption (suspicious)
                    '::ffff:192.168.1.99'
                )
            }

            # Add ToXml method
            $Event1 | Add-Member -MemberType ScriptMethod -Name 'ToXml' -Force -Value {
                return @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <EventData>
    <Data Name="TargetUserName">legitimateuser</Data>
    <Data Name="TicketOptions">0x40810010</Data>
    <Data Name="TicketEncryptionType">0x12</Data>
    <Data Name="IpAddress">::ffff:192.168.1.50</Data>
  </EventData>
</Event>
'@
            }

            $Event2 | Add-Member -MemberType ScriptMethod -Name 'ToXml' -Force -Value {
                return @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <EventData>
    <Data Name="TargetUserName">deleteduser</Data>
    <Data Name="TicketOptions">0x40810010</Data>
    <Data Name="TicketEncryptionType">0x17</Data>
    <Data Name="IpAddress">::ffff:192.168.1.99</Data>
  </EventData>
</Event>
'@
            }

            return @($Event1, $Event2)

        } elseif ($FilterHashtable.Id -eq 4624) {
            # Logon event for user without prior TGT
            $EventLogon = [PSCustomObject]@{
                TimeCreated = (Get-Date).AddMinutes(-5)
                Id          = 4624
                Properties  = @()
            }

            $EventLogon | Add-Member -MemberType ScriptMethod -Name 'ToXml' -Force -Value {
                return @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <EventData>
    <Data Name="TargetUserName">suspicioususer</Data>
    <Data Name="LogonType">3</Data>
    <Data Name="IpAddress">::ffff:192.168.1.100</Data>
  </EventData>
</Event>
'@
            }

            return @($EventLogon)

        } elseif ($FilterHashtable.Id -eq 4769) {
            # Service ticket request for non-existent user
            $EventService = [PSCustomObject]@{
                TimeCreated = (Get-Date).AddMinutes(-10)
                Id          = 4769
                Properties  = @()
            }

            $EventService | Add-Member -MemberType ScriptMethod -Name 'ToXml' -Force -Value {
                return @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <EventData>
    <Data Name="TargetUserName">deleteduser</Data>
    <Data Name="ServiceName">cifs/fileserver.contoso.com</Data>
    <Data Name="TicketEncryptionType">0x17</Data>
    <Data Name="IpAddress">::ffff:192.168.1.99</Data>
  </EventData>
</Event>
'@
            }

            return @($EventService)

        } elseif ($FilterHashtable.Id -eq 4672) {
            # Privileged access for non-existent user
            $EventPriv = [PSCustomObject]@{
                TimeCreated = (Get-Date).AddMinutes(-8)
                Id          = 4672
                Properties  = @()
            }

            $EventPriv | Add-Member -MemberType ScriptMethod -Name 'ToXml' -Force -Value {
                return @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <EventData>
    <Data Name="SubjectUserName">deleteduser</Data>
  </EventData>
</Event>
'@
            }

            return @($EventPriv)
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
        return $false  # Directory doesn't exist
    }

    # Mock New-Item
    Mock -CommandName New-Item -MockWith {
        param($Path, $ItemType, $Force)
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

Describe 'Get-GoldenTicketDetection' -Tag 'Unit' {

    Context 'Parameter Validation' {

        It 'Should have DomainController parameter' {
            $Command = Get-Command -Name $FunctionName
            $Parameter = $Command.Parameters['DomainController']

            $Parameter | Should -Not -BeNullOrEmpty
            $Parameter.ParameterType.Name | Should -Be 'String'
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

        It 'Should have IncludeKrbtgtRotation switch parameter' {
            $Command = Get-Command -Name $FunctionName
            $Parameter = $Command.Parameters['IncludeKrbtgtRotation']

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

        It 'Should support Confirm parameter (ShouldProcess)' {
            $Command = Get-Command -Name $FunctionName
            $Command.Parameters.ContainsKey('Confirm') | Should -Be $true
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

        It 'Should call Get-ADForest for cross-domain krbtgt audit' {
            $Result = & $FunctionName

            Should -Invoke -CommandName Get-ADForest -Times 1 -Exactly
        }

        It 'Should populate DomainName property' {
            $Result = & $FunctionName

            $Result.DomainName | Should -Be 'contoso.com'
        }

        It 'Should populate DomainController property' {
            $Result = & $FunctionName

            $Result.DomainController | Should -Match 'DC01'
        }

        It 'Should populate AuditTimestamp with current date' {
            $Result = & $FunctionName

            $Result.AuditTimestamp | Should -Not -BeNullOrEmpty
            $Result.AuditTimestamp | Should -BeOfType [DateTime]
        }

        It 'Should use PDC Emulator when DomainController is not specified' {
            $Result = & $FunctionName

            $Result.DomainController | Should -Be 'DC01.contoso.com'
        }

        It 'Should use specified DomainController when provided' {
            $Result = & $FunctionName -DomainController 'DC02.contoso.com'

            $Result.DomainController | Should -Be 'DC02.contoso.com'
        }

        It 'Should populate TimeWindowHours from Hours parameter' {
            $Result = & $FunctionName -Hours 48

            $Result.TimeWindowHours | Should -Be 48
        }

    } #end Context Core Detection Behavior

    Context 'Phase 1: krbtgt Password Age Audit' {

        It 'Should query krbtgt account for each forest domain' {
            $Result = & $FunctionName

            # Should query krbtgt for 2 domains
            Should -Invoke -CommandName Get-ADUser -Times 2 -Exactly -ParameterFilter {
                $Identity -eq 'krbtgt'
            }
        }

        It 'Should check PasswordLastSet property for krbtgt accounts' {
            $Result = & $FunctionName

            Should -Invoke -CommandName Get-ADUser -ParameterFilter {
                $Identity -eq 'krbtgt' -and $Properties -contains 'PasswordLastSet'
            }
        }

        It 'Should populate KrbtgtAudit array with password age details' {
            $Result = & $FunctionName

            $Result.KrbtgtAudit | Should -Not -BeNullOrEmpty
            $Result.KrbtgtAudit.Count | Should -BeGreaterThan 0
        }

        It 'Should categorize krbtgt password age by risk level' {
            $Result = & $FunctionName

            $HighRiskKrbtgt = $Result.KrbtgtAudit | Where-Object { $_.RiskLevel -eq 'HIGH' }
            $HighRiskKrbtgt | Should -Not -BeNullOrEmpty
        }

        It 'Should add CRITICAL/HIGH krbtgt findings to Detections array' {
            $Result = & $FunctionName

            $Result.KrbtgtCriticalOrHighCount | Should -BeGreaterThan 0
        }

        It 'Should provide rotation recommendation for aged krbtgt passwords' {
            $Result = & $FunctionName

            $HighRiskKrbtgt = $Result.KrbtgtAudit | Where-Object { $_.RiskLevel -in @('HIGH', 'CRITICAL') }
            $HighRiskKrbtgt[0].Recommendation | Should -Match 'Rotate krbtgt'
        }

    } #end Context Phase 1

    Context 'Phase 2: Event 4768 TGT Anomaly Analysis' {

        It 'Should query Event 4768 (TGT requests) from domain controller' {
            $Result = & $FunctionName

            Should -Invoke -CommandName Get-WinEvent -Times 1 -Exactly -ParameterFilter {
                $FilterHashtable.Id -eq 4768
            }
        }

        It 'Should detect TGT requests for non-existent users' {
            $Result = & $FunctionName

            $Result.TgtAnomalies | Where-Object { $_.AnomalyType -match 'Non-Existent' } | Should -Not -BeNullOrEmpty
        }

        It 'Should flag RC4 encryption usage as suspicious' {
            $Result = & $FunctionName

            $RC4Anomaly = $Result.TgtAnomalies | Where-Object { $_.EncryptionType -match 'RC4' }
            $RC4Anomaly | Should -Not -BeNullOrEmpty
        }

        It 'Should populate TgtAnomalyCount property' {
            $Result = & $FunctionName

            $Result.TgtAnomalyCount | Should -BeGreaterThan 0
        }

        It 'Should add CRITICAL TGT anomalies to Detections array' {
            $Result = & $FunctionName

            $CriticalTgtDetection = $Result.Detections | Where-Object {
                $_.DetectionType -match 'TGT' -and $_.Severity -eq 'CRITICAL'
            }
            $CriticalTgtDetection | Should -Not -BeNullOrEmpty
        }

    } #end Context Phase 2

    Context 'Phase 3: Event 4624/4768 Missing TGT Correlation' {

        It 'Should query Event 4624 (Logon) events' {
            $Result = & $FunctionName

            Should -Invoke -CommandName Get-WinEvent -Times 1 -Exactly -ParameterFilter {
                $FilterHashtable.Id -eq 4624
            }
        }

        It 'Should correlate logon events with preceding TGT requests' {
            $Result = & $FunctionName

            # suspicioususer logged in without TGT
            $Result.MissingTgtCorrelations | Should -Not -BeNullOrEmpty
        }

        It 'Should detect logons without preceding TGT requests (Golden Ticket indicator)' {
            $Result = & $FunctionName

            $MissingTgt = $Result.MissingTgtCorrelations | Where-Object { $_.Username -eq 'suspicioususer' }
            $MissingTgt | Should -Not -BeNullOrEmpty
        }

        It 'Should populate MissingTgtCorrelationCount property' {
            $Result = & $FunctionName

            $Result.MissingTgtCorrelationCount | Should -BeGreaterThan 0
        }

        It 'Should add missing TGT correlations to Detections array' {
            $Result = & $FunctionName

            $MissingTgtDetection = $Result.Detections | Where-Object {
                $_.DetectionType -match 'Missing TGT'
            }
            $MissingTgtDetection | Should -Not -BeNullOrEmpty
        }

        It 'Should flag non-existent user logons as CRITICAL' {
            Mock -CommandName Get-ADUser -MockWith {
                param($Identity, $Filter)
                if ($Filter -and $Filter.ToString() -match 'suspicioususer') {
                    return $null  # Non-existent
                }
            }

            $Result = & $FunctionName

            $CriticalLogon = $Result.MissingTgtCorrelations | Where-Object { $_.Severity -eq 'CRITICAL' }
            $CriticalLogon | Should -Not -BeNullOrEmpty
        }

    } #end Context Phase 3

    Context 'Phase 4: Event 4769 Service Ticket Anomaly Analysis' {

        It 'Should query Event 4769 (Service ticket requests)' {
            $Result = & $FunctionName

            Should -Invoke -CommandName Get-WinEvent -Times 1 -Exactly -ParameterFilter {
                $FilterHashtable.Id -eq 4769
            }
        }

        It 'Should detect service tickets for non-existent users' {
            $Result = & $FunctionName

            $ServiceAnomaly = $Result.ServiceTicketAnomalies | Where-Object {
                $_.AnomalyType -match 'Non-Existent'
            }
            $ServiceAnomaly | Should -Not -BeNullOrEmpty
        }

        It 'Should flag RC4 encryption in service tickets' {
            $Result = & $FunctionName

            $RC4Service = $Result.ServiceTicketAnomalies | Where-Object {
                $_.EncryptionType -match 'RC4'
            }
            $RC4Service | Should -Not -BeNullOrEmpty
        }

        It 'Should populate ServiceTicketAnomalyCount property' {
            $Result = & $FunctionName

            $Result.ServiceTicketAnomalyCount | Should -BeGreaterThan 0
        }

        It 'Should add CRITICAL service ticket anomalies to Detections array' {
            $Result = & $FunctionName

            $CriticalService = $Result.Detections | Where-Object {
                $_.DetectionType -match 'Service Ticket' -and $_.Severity -eq 'CRITICAL'
            }
            $CriticalService | Should -Not -BeNullOrEmpty
        }

    } #end Context Phase 4

    Context 'Phase 5: Event 4672 Privilege Anomaly Analysis' {

        It 'Should query Event 4672 (Privileged access) events' {
            $Result = & $FunctionName

            Should -Invoke -CommandName Get-WinEvent -Times 1 -Exactly -ParameterFilter {
                $FilterHashtable.Id -eq 4672
            }
        }

        It 'Should detect privileges assigned to non-existent users' {
            $Result = & $FunctionName

            $PrivAnomaly = $Result.PrivilegeAnomalies | Where-Object {
                $_.AnomalyType -match 'Non-Existent'
            }
            $PrivAnomaly | Should -Not -BeNullOrEmpty
        }

        It 'Should populate PrivilegeAnomalyCount property' {
            $Result = & $FunctionName

            $Result.PrivilegeAnomalyCount | Should -BeGreaterThan 0
        }

        It 'Should add privilege anomalies to Detections array' {
            $Result = & $FunctionName

            $PrivDetection = $Result.Detections | Where-Object {
                $_.DetectionType -match 'Privilege Escalation'
            }
            $PrivDetection | Should -Not -BeNullOrEmpty
        }

    } #end Context Phase 5

    Context 'Risk Assessment and Severity' {

        It 'Should categorize findings by severity (Critical/High/Medium)' {
            $Result = & $FunctionName

            $Result.CriticalDetections | Should -BeGreaterOrEqual 0
            $Result.HighDetections | Should -BeGreaterOrEqual 0
            $Result.MediumDetections | Should -BeGreaterOrEqual 0
        }

        It 'Should calculate TotalDetections as sum of all findings' {
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

        It 'Should set RiskLevel to Critical when CRITICAL detections exist' {
            $Result = & $FunctionName

            if ($Result.CriticalDetections -gt 0) {
                $Result.RiskLevel | Should -Be 'Critical'
            }
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

            Should -Invoke -CommandName Export-Csv -Times 1 -Exactly -ParameterFilter {
                $Path -match 'GoldenTicket-Detections-\d{8}-\d{6}\.csv'
            }
        }

        It 'Should export krbtgt audit to CSV' {
            $Result = & $FunctionName -ExportPath 'C:\Reports'

            Should -Invoke -CommandName Export-Csv -Times 1 -Exactly -ParameterFilter {
                $Path -match 'GoldenTicket-krbtgt-Audit-\d{8}-\d{6}\.csv'
            }
        }

        It 'Should create export directory if it does not exist' {
            $Result = & $FunctionName -ExportPath 'C:\NewReports'

            Should -Invoke -CommandName New-Item -Times 1 -Exactly -ParameterFilter {
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

        It 'Should recommend krbtgt rotation when critical findings detected' {
            $Result = & $FunctionName

            if ($Result.CriticalDetections -gt 0) {
                $Result.RecommendedActions -join ' ' | Should -Match 'krbtgt'
            }
        }

        It 'Should include rotation guidance when IncludeKrbtgtRotation is specified' {
            $Result = & $FunctionName -IncludeKrbtgtRotation

            $Result.RecommendedActions -join ' ' | Should -Match 'New-KrbtgtKeys'
        }

        It 'Should open remediation URL when Remediate switch is used with critical findings' {
            $Result = & $FunctionName -Remediate

            if ($Result.CriticalDetections -gt 0) {
                Should -Invoke -CommandName Start-Process -Times 1 -Exactly
            }
        }

        It 'Should not open URL when no critical findings exist' {
            # Mock to return no critical detections
            Mock -CommandName Get-WinEvent -MockWith {
                return @()
            }

            $Result = & $FunctionName -Remediate

            If ($Result.CriticalDetections -eq 0) {
                Should -Invoke -CommandName Start-Process -Times 0 -Exactly
            }
        }

        It 'Should recommend incident response for critical severity' {
            $Result = & $FunctionName

            if ($Result.CriticalDetections -gt 0) {
                $Result.RecommendedActions -join ' ' | Should -Match 'incident response|forensic'
            }
        }

    } #end Context Remediation Guidance

    Context 'Error Handling' {

        It 'Should handle Get-ADDomain failures gracefully' {
            Mock -CommandName Get-ADDomain -MockWith {
                throw 'Access denied'
            }

            { & $FunctionName -ErrorAction Stop } | Should -Throw
        }

        It 'Should handle Get-ADForest failures gracefully' {
            Mock -CommandName Get-ADForest -MockWith {
                throw 'Access denied'
            }

            { & $FunctionName -ErrorAction Stop } | Should -Throw
        }

        It 'Should continue when krbtgt query fails for individual domain' {
            Mock -CommandName Get-ADUser -MockWith {
                param($Identity, $Server)
                if ($Server -eq 'child.contoso.com') {
                    throw 'Domain unreachable'
                }
                return [PSCustomObject]@{
                    SamAccountName       = 'krbtgt'
                    PasswordLastSet      = (Get-Date).AddDays(-100)
                    PasswordNeverExpires = $false
                }
            }

            $Result = & $FunctionName -WarningVariable Warnings -WarningAction SilentlyContinue

            $Result | Should -Not -BeNullOrEmpty
        }

        It 'Should handle Get-WinEvent failures gracefully (no events found)' {
            Mock -CommandName Get-WinEvent -MockWith {
                return @()
            }

            $Result = & $FunctionName

            $Result | Should -Not -BeNullOrEmpty
            $Result.TotalDetections | Should -BeGreaterOrEqual 0
        }

        It 'Should provide error message when ActiveDirectory module is missing' {
            Mock -CommandName Import-MyModule -MockWith {
                throw 'Module not found'
            }

            { & $FunctionName -ErrorAction Stop } | Should -Throw -ExceptionType 'System.Management.Automation.ActionPreferenceStopException'
        }

    } #end Context Error Handling

    Context 'Output Object Structure' {

        It 'Should have all required properties in output object' {
            $Result = & $FunctionName

            $Result | Should -HaveProperty 'DomainName'
            $Result | Should -HaveProperty 'DomainController'
            $Result | Should -HaveProperty 'TotalDetections'
            $Result | Should -HaveProperty 'CriticalDetections'
            $Result | Should -HaveProperty 'IsSecure'
            $Result | Should -HaveProperty 'RiskLevel'
            $Result | Should -HaveProperty 'KrbtgtAudit'
            $Result | Should -HaveProperty 'Detections'
        }

        It 'Should include phase-specific counts' {
            $Result = & $FunctionName

            $Result | Should -HaveProperty 'KrbtgtCriticalOrHighCount'
            $Result | Should -HaveProperty 'TgtAnomalyCount'
            $Result | Should -HaveProperty 'MissingTgtCorrelationCount'
            $Result | Should -HaveProperty 'ServiceTicketAnomalyCount'
            $Result | Should -HaveProperty 'PrivilegeAnomalyCount'
        }

        It 'Should include phase-specific data arrays' {
            $Result = & $FunctionName

            $Result.TgtAnomalies | Should -Not -BeNullOrEmpty
            $Result.MissingTgtCorrelations | Should -Not -BeNullOrEmpty
            $Result.ServiceTicketAnomalies | Should -Not -BeNullOrEmpty
            $Result.PrivilegeAnomalies | Should -Not -BeNullOrEmpty
        }

    } #end Context Output Object Structure

} #end Describe Get-GoldenTicketDetection

} #end Describe Setup Wrapper
