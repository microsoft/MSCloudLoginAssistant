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

        # Test contexts
        Context -Name "Connecting to Azure for the first time" -Fixture {
            $CallNumber = 0
            Mock -CommandName Invoke-Expression -MockWith{
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
            Mock -CommandName Invoke-Expression -MockWith{
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
            Mock -CommandName Invoke-Expression -MockWith{
                if ($CallNumber -eq 0)
                {
                    $CallNumber++
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
            Mock -CommandName Invoke-Expression -MockWith{
                if ($CallNumber -eq 0)
                {
                    $CallNumber++
                }
            }

            $testParams = @{
                Platform        = "ExchangeOnline"
                CloudCredential = $GlobalAdminAccount
            }

            It 'Should Call the Login Method successfully' {
                Test-MSCloudLogin @testParams | Assert-MockCalled -CommandName Invoke-Expression
            }
        }

        Context -Name "Connecting to SecurityComplianceCenter for the first time" -Fixture {
            $CallNumber = 0
            Mock -CommandName Invoke-Expression -MockWith{
                if ($CallNumber -eq 0)
                {
                    $CallNumber++
                }
            }

            $testParams = @{
                Platform        = "SecurityComplianceCenter"
                CloudCredential = $GlobalAdminAccount
            }

            It 'Should Call the Login Method successfully' {
                Test-MSCloudLogin @testParams | Assert-MockCalled -CommandName Invoke-Expression
            }
        }

        Context -Name "Connecting to MSOnline for the first time" -Fixture {
            $CallNumber = 0
            Mock -CommandName Invoke-Expression -MockWith{
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
            Mock -CommandName Invoke-Expression -MockWith{
                if ($CallNumber -eq 0)
                {
                    $CallNumber++
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
            Mock -CommandName Invoke-Expression -MockWith{
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
    }
}

Invoke-Command -ScriptBlock $Global:DscHelper.CleanupScript -NoNewScope

