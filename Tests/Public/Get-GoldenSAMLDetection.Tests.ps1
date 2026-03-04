BeforeAll {
    # Module import and setup
    $ModuleName = 'EguibarIT.SecurityPS'
    $FunctionName = 'Get-GoldenSAMLDetection'
    $PathToManifest = [System.IO.Path]::Combine('..', '..', "$ModuleName.psd1")

    if (Test-Path -Path $PathToManifest) {
        Import-Module -Name $PathToManifest -Force -ErrorAction Stop
    } #end if

    # Define test variables
    $TestExportPath = [System.IO.Path]::Combine($TestDrive, 'GoldenSAML-Test.csv')

    # Mock dependencies for AD FS commands
    Mock -CommandName Get-Service -MockWith {
        param($Name, $ErrorAction)
        if ($Name -eq 'ADFS') {
            return [PSCustomObject]@{
                Name   = 'ADFS'
                Status = 'Running'
            }
        } #end if
        return $null
    }

    Mock -CommandName Import-Module -MockWith { } -ParameterFilter { $Name -eq 'ADFS' }

    Mock -CommandName Get-AdfsProperties -MockWith {
        return [PSCustomObject]@{
            AutoCertificateRollover = $true
        }
    }

    Mock -CommandName Get-AdfsCertificate -MockWith {
        param($CertificateType, $ErrorAction)
        return @(
            [PSCustomObject]@{
                Thumbprint = 'ABC123DEF456'
                NotBefore  = (Get-Date).AddDays(-365)
                NotAfter   = (Get-Date).AddDays(365)
                IsPrimary  = $true
            }
        )
    }

    Mock -CommandName Get-AdfsRelyingPartyTrust -MockWith {
        return @(
            [PSCustomObject]@{
                Name              = 'TestRPT'
                LastMonitoredTime = (Get-Date).AddDays(-30)
                ModificationTime  = (Get-Date).AddDays(-30)
            }
        )
    }

    Mock -CommandName Get-WinEvent -MockWith {
        param($FilterHashtable, $ErrorAction)
        return @()
    }

    Mock -CommandName Get-ChildItem -MockWith {
        return @()
    } -ParameterFilter { $Path -eq 'Cert:\LocalMachine\My' }

    Mock -CommandName Export-Csv -MockWith { }
    Mock -CommandName Out-File -MockWith { }
    Mock -CommandName New-Item -MockWith { }
    Mock -CommandName Test-Path -MockWith { return $true }
}

Describe 'Get-GoldenSAMLDetection' {

    Context 'Parameter Validation' {

        BeforeAll {
            $Command = Get-Command -Name $FunctionName
        } #end BeforeAll

        It 'Should have the correct parameter attributes for Hours' {
            $Command | Should -HaveParameter -ParameterName 'Hours'
            $Command.Parameters['Hours'].ParameterType.Name | Should -Be 'Int32'
            $Command.Parameters['Hours'].Attributes.TypeId.Name | Should -Contain 'ValidateRangeAttribute'
        } #end It

        It 'Should have the correct parameter attributes for ExportPath' {
            $Command | Should -HaveParameter -ParameterName 'ExportPath'
            $Command.Parameters['ExportPath'].ParameterType.Name | Should -Be 'String'
        } #end It

        It 'Should have the correct parameter attributes for IncludeEvents' {
            $Command | Should -HaveParameter -ParameterName 'IncludeEvents'
            $Command.Parameters['IncludeEvents'].ParameterType.Name | Should -Be 'SwitchParameter'
        } #end It

        It 'Should have SupportsShouldProcess enabled' {
            $Command.CmdletBinding.SupportsShouldProcess | Should -Be $true
        } #end It

        It 'Should validate Hours parameter range' {
            { & $FunctionName -Hours 0 } | Should -Throw
            { & $FunctionName -Hours 10000 } | Should -Throw
        } #end It

    } #end Context

    Context 'Function Documentation' {

        BeforeAll {
            $Help = Get-Help -Name $FunctionName -Full
        } #end BeforeAll

        It 'Should have proper help documentation' {
            $Help.Synopsis | Should -Not -BeNullOrEmpty
            $Help.Description | Should -Not -BeNullOrEmpty
            $Help.Examples.Count | Should -BeGreaterThan 0
        } #end It

        It 'Should include MITRE ATT&CK reference' {
            $Help.Description.Text | Should -Match 'T1606.002'
        } #end It

        It 'Should document all five detection phases' {
            $Help.Description.Text | Should -Match 'Phase 1'
            $Help.Description.Text | Should -Match 'Phase 2'
            $Help.Description.Text | Should -Match 'Phase 3'
            $Help.Description.Text | Should -Match 'Phase 4'
            $Help.Description.Text | Should -Match 'Phase 5'
        } #end It

        It 'Should include input/output metadata' {
            $Help.Inputs.Name | Should -Not -BeNullOrEmpty
            $Help.ReturnValues.ReturnValue.Type.Name | Should -Be 'PSCustomObject'
        } #end It

        It 'Should include version information in notes' {
            $Help.AlertSet.Alert.Text | Should -Match 'Version'
            $Help.AlertSet.Alert.Text | Should -Match 'DateModified'
        } #end It

    } #end Context

    Context 'Functionality - AD FS Present Scenario' {

        BeforeAll {
            Mock -CommandName Get-Service -MockWith {
                param($Name, $ErrorAction)
                if ($Name -eq 'ADFS') {
                    return [PSCustomObject]@{ Name = 'ADFS'; Status = 'Running' }
                } #end if
                return $null
            }
        } #end BeforeAll

        It 'Should return a summary object with correct properties' {
            $Result = & $FunctionName -Hours 24

            $Result | Should -Not -BeNullOrEmpty
            $Result.PSTypeNames[0] | Should -Be 'EguibarIT.GoldenSAMLDetection'
            $Result.ScanDate | Should -Not -BeNullOrEmpty
            $Result.WindowHours | Should -Be 24
            $Result.ADFSPresent | Should -BeOfType [bool]
            $Result.FindingsCount | Should -BeOfType [int]
            $Result.IsSecure | Should -BeOfType [bool]
        } #end It

        It 'Should detect AD FS when service is running' {
            $Result = & $FunctionName -Hours 24

            $Result.ADFSPresent | Should -Be $true
        } #end It

        It 'Should check AutoCertificateRollover status' {
            & $FunctionName -Hours 24 | Out-Null

            Should -Invoke -CommandName Get-AdfsProperties -Times 1 -Exactly
        } #end It

        It 'Should retrieve token-signing certificates' {
            & $FunctionName -Hours 24 | Out-Null

            Should -Invoke -CommandName Get-AdfsCertificate -Times 1 -Exactly
        } #end It

        It 'Should query relying party trusts' {
            & $FunctionName -Hours 24 | Out-Null

            Should -Invoke -CommandName Get-AdfsRelyingPartyTrust -Times 1 -Exactly
        } #end It

    } #end Context

    Context 'Functionality - AD FS Not Present Scenario' {

        BeforeAll {
            Mock -CommandName Get-Service -MockWith {
                return $null
            }
        } #end BeforeAll

        It 'Should handle systems without AD FS installed' {
            $Result = & $FunctionName -Hours 24

            $Result.ADFSPresent | Should -Be $false
            Should -Invoke -CommandName Get-AdfsCertificate -Times 0
            Should -Invoke -CommandName Get-AdfsRelyingPartyTrust -Times 0
        } #end It

    } #end Context

    Context 'Functionality - Certificate Hygiene Detection' {

        It 'Should flag expiring certificates as HIGH severity' {
            Mock -CommandName Get-AdfsCertificate -MockWith {
                return @(
                    [PSCustomObject]@{
                        Thumbprint = 'EXPIRING123'
                        NotBefore  = (Get-Date).AddDays(-365)
                        NotAfter   = (Get-Date).AddDays(15)  # Expires in 15 days
                        IsPrimary  = $true
                    }
                )
            }

            $Result = & $FunctionName -Hours 24

            $Result.HighSeverityCount | Should -BeGreaterThan 0
            $Result.DetailedFindings | Where-Object { $_.FindingType -eq 'Cert:ExpiringSoon' } | Should -Not -BeNullOrEmpty
        } #end It

        It 'Should flag very old certificates as MEDIUM severity' {
            Mock -CommandName Get-AdfsCertificate -MockWith {
                return @(
                    [PSCustomObject]@{
                        Thumbprint = 'OLDCERT456'
                        NotBefore  = (Get-Date).AddDays( - (365 * 4))  # 4 years old
                        NotAfter   = (Get-Date).AddDays(365)
                        IsPrimary  = $true
                    }
                )
            }

            $Result = & $FunctionName -Hours 24

            $Result.MediumSeverityCount | Should -BeGreaterThan 0
            $Result.DetailedFindings | Where-Object { $_.FindingType -eq 'Cert:VeryOld' } | Should -Not -BeNullOrEmpty
        } #end It

        It 'Should flag disabled AutoCertificateRollover as HIGH severity' {
            Mock -CommandName Get-AdfsProperties -MockWith {
                return [PSCustomObject]@{
                    AutoCertificateRollover = $false
                }
            }

            $Result = & $FunctionName -Hours 24

            $Result.HighSeverityCount | Should -BeGreaterThan 0
            $Result.DetailedFindings | Where-Object { $_.FindingType -eq 'Config:AutoCertificateRolloverDisabled' } | Should -Not -BeNullOrEmpty
        } #end It

        It 'Should flag multiple primary certificates as HIGH severity' {
            Mock -CommandName Get-AdfsCertificate -MockWith {
                return @(
                    [PSCustomObject]@{ Thumbprint = 'PRIMARY1'; NotBefore = (Get-Date).AddDays(-365); NotAfter = (Get-Date).AddDays(365); IsPrimary = $true },
                    [PSCustomObject]@{ Thumbprint = 'PRIMARY2'; NotBefore = (Get-Date).AddDays(-180); NotAfter = (Get-Date).AddDays(365); IsPrimary = $true }
                )
            }

            $Result = & $FunctionName -Hours 24

            $Result.HighSeverityCount | Should -BeGreaterThan 0
            $Result.DetailedFindings | Where-Object { $_.FindingType -eq 'Cert:MultiplePrimaries' } | Should -Not -BeNullOrEmpty
        } #end It

    } #end Context

    Context 'Functionality - Event Log Analysis' {

        It 'Should analyze AD FS Admin event logs when IncludeEvents is specified' {
            Mock -CommandName Get-WinEvent -MockWith {
                param($FilterHashtable)
                if ($FilterHashtable.LogName -eq 'AD FS/Admin') {
                    return @(
                        [PSCustomObject]@{
                            Id               = 123
                            Message          = 'Token-signing certificate was updated'
                            TimeCreated      = Get-Date
                            LevelDisplayName = 'Information'
                        }
                    )
                } #end if
                return @()
            }

            $Result = & $FunctionName -Hours 24 -IncludeEvents

            $Result.DetailedFindings | Where-Object { $_.FindingType -eq 'ADFS:AdminLogMatch' } | Should -Not -BeNullOrEmpty
        } #end It

        It 'Should analyze Security event logs for private key access (Event 4663)' {
            Mock -CommandName Get-WinEvent -MockWith {
                param($FilterHashtable)
                if ($FilterHashtable.Id -eq 4663) {
                    $EventXml = @'
<Event>
  <EventData>
    <Data Name="SubjectUserName">TestUser</Data>
    <Data Name="SubjectDomainName">CONTOSO</Data>
    <Data Name="ObjectName">C:\\ProgramData\\Microsoft\\Crypto\\RSA\\MachineKeys\\testkey</Data>
  </EventData>
</Event>
'@
                    return @(
                        [PSCustomObject]@{
                            Id          = 4663
                            Message     = 'Private key accessed'
                            TimeCreated = Get-Date
                            ToXml       = { return $EventXml }
                        }
                    )
                } #end if
                return @()
            }

            $Result = & $FunctionName -Hours 24

            $Result.HighSeverityCount | Should -BeGreaterThan 0
            $Result.DetailedFindings | Where-Object { $_.FindingType -eq 'Security:4663-MachineKeys' } | Should -Not -BeNullOrEmpty
        } #end It

    } #end Context

    Context 'Export Functionality' {

        It 'Should support -WhatIf without creating files' {
            & $FunctionName -Hours 24 -ExportPath $TestExportPath -WhatIf

            Should -Invoke -CommandName Export-Csv -Times 0
            Should -Invoke -CommandName Out-File -Times 0
        } #end It

        It 'Should export CSV and JSON when findings exist' {
            Mock -CommandName Get-AdfsProperties -MockWith {
                return [PSCustomObject]@{ AutoCertificateRollover = $false }
            }

            $Result = & $FunctionName -Hours 24 -ExportPath $TestExportPath

            if ($Result.FindingsCount -gt 0) {
                Should -Invoke -CommandName Export-Csv -Times 1 -Exactly
                Should -Invoke -CommandName Out-File -Times 1 -Exactly  # JSON export
            } #end if
        } #end It

        It 'Should create export directory if it does not exist' {
            Mock -CommandName Test-Path -MockWith { return $false }

            & $FunctionName -Hours 24 -ExportPath $TestExportPath

            Should -Invoke -CommandName New-Item -ParameterFilter { $ItemType -eq 'Directory' }
        } #end It

        It 'Should return exported file paths in summary object' {
            Mock -CommandName Get-AdfsProperties -MockWith {
                return [PSCustomObject]@{ AutoCertificateRollover = $false }
            }

            $Result = & $FunctionName -Hours 24 -ExportPath $TestExportPath

            if ($Result.FindingsCount -gt 0) {
                $Result.ExportedFiles | Should -Not -BeNullOrEmpty
                $Result.ExportedFiles.Count | Should -BeGreaterThan 0
            } #end if
        } #end It

    } #end Context

    Context 'Error Handling' {

        It 'Should handle AD FS module import failures gracefully' {
            Mock -CommandName Import-Module -MockWith {
                throw 'Module not found'
            } -ParameterFilter { $Name -eq 'ADFS' }

            { & $FunctionName -Hours 24 } | Should -Not -Throw
            Should -Invoke -CommandName Write-Warning
        } #end It

        It 'Should handle missing event logs gracefully' {
            Mock -CommandName Get-WinEvent -MockWith {
                throw 'Log not found'
            }

            { & $FunctionName -Hours 24 } | Should -Not -Throw
        } #end It

        It 'Should handle certificate retrieval failures' {
            Mock -CommandName Get-AdfsCertificate -MockWith {
                throw 'Certificate store unavailable'
            }

            { & $FunctionName -Hours 24 } | Should -Not -Throw
        } #end It

        It 'Should handle relying party trust enumeration failures' {
            Mock -CommandName Get-AdfsRelyingPartyTrust -MockWith {
                throw 'Access denied'
            }

            { & $FunctionName -Hours 24 } | Should -Not -Throw
            Should -Invoke -CommandName Write-Warning
        } #end It

    } #end Context

    Context 'Performance' {

        It 'Should complete within acceptable time with default parameters' {
            $Threshold = 5  # seconds
            $Measure = Measure-Command {
                & $FunctionName -Hours 24
            }

            $Measure.TotalSeconds | Should -BeLessThan $Threshold
        } #end It

    } #end Context

    Context 'Security and Compliance' {

        It 'Should include MITRE ATT&CK technique in all findings' {
            Mock -CommandName Get-AdfsProperties -MockWith {
                return [PSCustomObject]@{ AutoCertificateRollover = $false }
            }

            $Result = & $FunctionName -Hours 24

            foreach ($Finding in $Result.DetailedFindings) {
                $Finding.MITRE_Technique | Should -Be 'T1606.002'
            } #end foreach
        } #end It

        It 'Should provide remediation recommendations for all findings' {
            Mock -CommandName Get-AdfsProperties -MockWith {
                return [PSCustomObject]@{ AutoCertificateRollover = $false }
            }

            $Result = & $FunctionName -Hours 24

            foreach ($Finding in $Result.DetailedFindings) {
                $Finding.Recommendation | Should -Not -BeNullOrEmpty
            } #end foreach
        } #end It

        It 'Should correctly assess security posture (IsSecure property)' {
            # No high/medium severity findings
            Mock -CommandName Get-AdfsProperties -MockWith {
                return [PSCustomObject]@{ AutoCertificateRollover = $true }
            }

            $Result = & $FunctionName -Hours 24

            if ($Result.HighSeverityCount -eq 0 -and $Result.MediumSeverityCount -eq 0) {
                $Result.IsSecure | Should -Be $true
            } #end if
        } #end It

    } #end Context

} #end Describe

AfterAll {
    Remove-Module -Name $ModuleName -Force -ErrorAction SilentlyContinue
}
