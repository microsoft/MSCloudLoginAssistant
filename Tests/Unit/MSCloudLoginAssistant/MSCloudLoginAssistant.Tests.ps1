[CmdletBinding()]
param(
    [Parameter()]
    [string]
    $CmdletModule = (Join-Path -Path $PSScriptRoot `
            -ChildPath "..\Stubs\Stubs.psm1" `
            -Resolve)
)

Import-Module -Name (Join-Path -Path $PSScriptRoot `
        -ChildPath "..\UnitTestHelper.psm1" `
        -Resolve)

$Global:DscHelper = New-MSCloudLoginAssistantUnitTestHelper `
    -StubModule $CmdletModule `
    -SubModulePath "..\MSCloudLoginAssistant\MSCloudLoginAssistant.psm1"
Describe -Name $Global:DscHelper.DescribeHeader -Fixture {
    InModuleScope -ModuleName $Global:DscHelper.ModuleName -ScriptBlock {
        Invoke-Command -ScriptBlock $Global:DscHelper.InitializeScript -NoNewScope

        $secpasswd = ConvertTo-SecureString "test@password1" -AsPlainText -Force
        $GlobalAdminAccount = New-Object System.Management.Automation.PSCredential ("tenantadmin", $secpasswd)


        Mock -CommandName Close-SessionsAndReturnError -MockWith {

        }

        # Test contexts
        Context -Name "Connecting to Azure for the first time" -Fixture {
            $CallNumber = 0
            Mock -CommandName Invoke-Expression -MockWith {
                if ($CallNumber -eq 0)
                {
                    $CallNumber++
                }
            }

            $testParams = @{
                Platform        = "Azure"
                CloudCredential = $GlobalAdminAccount
            }

            It 'Should Call the Login Method successfully' {
                Test-MSCloudLogin @testParams | Assert-MockCalled -CommandName Invoke-Expression
            }
        }

        Context -Name "Connecting to AzureAD for the first time" -Fixture {
            $CallNumber = 0
            Mock -CommandName Invoke-Expression -MockWith {
                if ($CallNumber -eq 0)
                {
                    $CallNumber++
                }
            }

            $testParams = @{
                Platform        = "AzureAD"
                CloudCredential = $GlobalAdminAccount
            }

            It 'Should Call the Login Method successfully' {
                Test-MSCloudLogin @testParams | Assert-MockCalled -CommandName Invoke-Expression
            }
        }

        Context -Name "Connecting to SharePointOnline for the first time" -Fixture {
            $CallNumber = 0
            Mock -CommandName Invoke-Expression -MockWith {
                if ($CallNumber -eq 0)
                {
                    $CallNumber++
                }
            }

            Mock -CommandName Get-AzureADDomain -MockWith {
                return @{
                    Name      = "contoso.onmicrosoft.com"
                    IsInitial = $true
                }
            }

            $testParams = @{
                Platform        = "SharePointOnline"
                CloudCredential = $GlobalAdminAccount
            }

            It 'Should Call the Login Method successfully' {
                Test-MSCloudLogin @testParams | Assert-MockCalled -CommandName Invoke-Expression
            }
        }

        Context -Name "Connecting to ExchangeOnline for the first time" -Fixture {
            $CallNumber = 0
            Mock -CommandName Invoke-Expression -MockWith {
                if ($CallNumber -eq 0)
                {
                    $CallNumber++
                }
            }

            Mock -CommandName Get-PSSession -MockWith {

            }

            Mock -CommandName New-PSSession -MockWith {
                return @{

                }
            }

            Mock -CommandName Import-PSSession -MockWith {

            }

            Mock -CommandName Get-NetTCPCOnnection -MockWith {
                return @{
                    RemotePort = 443
                    State      = "Idle"
                }
            }

            $testParams = @{
                Platform        = "ExchangeOnline"
                CloudCredential = $GlobalAdminAccount
            }

            It 'Should Call the Login Method successfully' {
                Test-MSCloudLogin @testParams | Should Be $null
            }
        }

        Context -Name "Connecting to SecurityComplianceCenter for the first time" -Fixture {
            $CallNumber = 0
            Mock -CommandName Invoke-Expression -MockWith {
                if ($CallNumber -eq 0)
                {
                    $CallNumber++
                }
            }

            Mock -CommandName Get-PSSession -MockWith {

            }

            Mock -CommandName New-PSSession -MockWith {
                return @{

                }
            }

            Mock -CommandName Import-PSSession -MockWith {
                return "C:\projects\mscloudloginassistant\Modules\MSCloudLoginAssistant\MSCloudLoginAssistant.psm1"
            }

            $testParams = @{
                Platform        = "SecurityComplianceCenter"
                CloudCredential = $GlobalAdminAccount
            }

            It 'Should Call the Login Method successfully' {
                Test-MSCloudLogin @testParams | Should Be $null
            }
        }

        Context -Name "Connecting to MSOnline for the first time" -Fixture {
            $CallNumber = 0
            Mock -CommandName Invoke-Expression -MockWith {
                if ($CallNumber -eq 0)
                {
                    $CallNumber++
                }
            }

            $testParams = @{
                Platform        = "MSOnline"
                CloudCredential = $GlobalAdminAccount
            }

            It 'Should Call the Login Method successfully' {
                Test-MSCloudLogin @testParams | Assert-MockCalled -CommandName Invoke-Expression
            }
        }

        Context -Name "Connecting to PnP for the first time" -Fixture {
            $CallNumber = 0
            Mock -CommandName Invoke-Expression -MockWith {
                if ($CallNumber -eq 0)
                {
                    $CallNumber++
                }
            }

            Mock -CommandName Get-AzureADDomain -MockWith {
                return @{
                    Name      = "contoso.onmicrosoft.com"
                    IsInitial = $true
                }
            }

            Mock -CommandName Get-PnPConnection -MockWith {
                return @{
                    Url = "https://contoso-admin.sharepoint.com"
                }
            }

            $testParams = @{
                Platform        = "PnP"
                CloudCredential = $GlobalAdminAccount
            }

            It 'Should Call the Login Method successfully' {
                Test-MSCloudLogin @testParams | Assert-MockCalled -CommandName Invoke-Expression
            }
        }

        Context -Name "Connecting to MicrosoftTeams for the first time" -Fixture {
            $CallNumber = 0
            Mock -CommandName Invoke-Expression -MockWith {
                if ($CallNumber -eq 0)
                {
                    $CallNumber++
                }
            }

            $testParams = @{
                Platform        = "MicrosoftTeams"
                CloudCredential = $GlobalAdminAccount
            }

            It 'Should Call the Login Method successfully' {
                Test-MSCloudLogin @testParams | Assert-MockCalled -CommandName Invoke-Expression
            }
        }

        Context -Name "Connecting to MicrosoftTeams for the second time" -Fixture {
            $CallNumber = 0
            Mock -CommandName Invoke-Expression -MockWith {
                if ($CallNumber -eq 0)
                {
                    $CallNumber++
                }
            }
            Mock -CommandName Get-CsTeamsCallingPolicy -MockWith {
                "Success"
            }

            $testParams = @{
                Platform        = "MicrosoftTeams"
                CloudCredential = $GlobalAdminAccount
            }

            It 'Should Call the Login Method successfully but not attempt reconnect' {
                Test-MSCloudLogin @testParams | Assert-MockCalled -CommandName Get-PSSession -Times 0
            }
        }
    }
}

Invoke-Command -ScriptBlock $Global:DscHelper.CleanupScript -NoNewScope

