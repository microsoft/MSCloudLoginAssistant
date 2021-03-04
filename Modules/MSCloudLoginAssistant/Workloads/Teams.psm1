function Connect-MSCloudLoginTeams
{
    [CmdletBinding()]
    param()

    if ($Global:UseApplicationIdentity)
    {    
        if($Global:appIdentityParams.CertificateThumbprint) 
        {

            # this monstrosity is required because the Connect-MicrosoftTeams cmdlet only supports the TeamsEnvironment name parameter 
            # with the user credentials. From the codebase i belive that this is a bug. Until they fix it we work around the issue by 
            # rewriting the default environment
            if(!$Global:TeamsEnvironmentRedirected)
            {          
                # if (-not ([System.Management.Automation.PSTypeName]'Microsoft.Open.Teams.CommonLibrary.AzureRmProfileProvider').Type)
                # {
                #     [array]$MsTeamsModules = Get-Module -ListAvailable | Where-Object {$_.name -eq "MicrosoftTeams"}
                #     if ($MsTeamsModules.count -eq 0)
                #     {
                #         Throw "Can't find MicrosoftTeams DLL. Please Import the module MicrosoftTeams before connecting with MSCloudLoginAssistant"
                #     }
                #     $TeamsConnectDDLL= Join-Path (($MsTeamsModules | Sort-Object version -Descending | Select-Object -first 1).Path | split-Path) Microsoft.TeamsCmdlets.PowerShell.Connect.dll
                #     Add-Type -Path $TeamsConnectDDLL | Out-Null
                # }
                
                # we get the azureAD env name becase that is what is used in the background of the teams module
                $envName = Get-PsModuleAzureEnvironmentName -AzureCloudEnvironmentName $Global:appIdentityParams.AzureCloudEnvironmentName -Platform "AzureAD";
                $graphEndpoint = Get-AzureEnvironmentEndpoint -AzureCloudEnvironmentName $Global:appIdentityParams.AzureCloudEnvironmentName -EndpointName "MsGraphEndpointResourceId"
                $defaultTeamsAzureEnv = [Microsoft.Open.Teams.CommonLibrary.AzureEnvironment+EnvironmentName]::AzureCloud
                $actualTeamsEnvName = [Microsoft.Open.Teams.CommonLibrary.AzureEnvironment+EnvironmentName]$envName
                [Microsoft.Open.Teams.CommonLibrary.AzureRmProfileProvider]::Instance.Profile.Environments[$defaultTeamsAzureEnv] = [Microsoft.Open.Teams.CommonLibrary.AzureRmProfileProvider]::Instance.Profile.Environments[$actualTeamsEnvName]
                [Microsoft.Open.Teams.CommonLibrary.AzureRmProfileProvider]::Instance.Profile.Environments[$defaultTeamsAzureEnv].Endpoints[[Microsoft.Open.Teams.CommonLibrary.Endpoint]::MsGraphEndpointResourceId] = $graphEndpoint
                $Global:TeamsEnvironmentRedirected = $true
            }
                        
            Connect-MicrosoftTeams -TenantId $Global:appIdentityParams.Tenant -ApplicationId $Global:appIdentityParams.AppId -CertificateThumbprint $Global:appIdentityParams.CertificateThumbprint -ErrorAction Stop | Out-Null
        }
        else
        {
            throw "The MicrosoftTeams Platform does not support connecting with application secret"
        }
    }
    elseif ($null -ne $Global:o365Credential)
    {
        if ($Global:o365Credential.UserName.Split('@')[1] -like '*.de')
        {
            $Global:CloudEnvironment = 'Germany'
            Write-Warning 'Microsoft Teams is not supported in the Germany Cloud'
            return
        }
        Import-Module -Name 'MicrosoftTeams' -Force

        Test-MSCloudLogin -Platform AzureAD -CloudCredential $Global:o365Credential
        if ($Global:IsMFAAuth)
        {
            Connect-MSCloudLoginTeamsMFA -EnvironmentName $Global:CloudEnvironment
        }
        try 
        {
            Connect-MicrosoftTeams -Credential $Global:o365Credential -ErrorAction Stop | Out-Null
        }
        catch
        {
            if ($_.Exception -like '*unknown_user_type: Unknown User Type*')
            {
                $Global:CloudEnvironment = 'GCCHigh'

                try
                {
                    Connect-MicrosoftTeams -TeamsEnvironmentName 'TeamsGCCH' -Credential $Global:o365Credential -ErrorAction Stop | Out-Null
                }
                catch
                {
                    try
                    {
                        Connect-MicrosoftTeams -TeamsEnvironmentName 'TeamsDOD' -Credential $Global:o365Credential -ErrorAction Stop | Out-Null
                        $Global:CloudEnvironment = 'DoD'
                    }
                    catch
                    {
                        throw $_
                    }
                }
            }
            elseif ($_.Exception -like '*AADSTS50076*')
            {
                Connect-MSCloudLoginTeamsMFA -EnvironmentName $Global:CloudEnvironment
            }
            else
            {
                throw $_
            }
        }
    }
    else
    {
        try 
        {
            Connect-MicrosoftTeams -ErrorAction Stop | Out-Null
        }
        catch
        {
            throw $_
        }
    }
    return
}

function Connect-MSCloudLoginTeamsMFA
{
    [CmdletBinding()]
    param(
        [Parameter()]
        [System.String]
        $EnvironmentName
    )

    try
    {
        if ($EnvironmentName -eq 'GCCHigh')
        {
            Connect-MicrosoftTeams -AccountId $Global:o365Credential.UserName -TeamsEnvironmentName 'TeamsGCCH' -ErrorAction Stop | Out-Null
        }
        elseif ($Environment -eq 'DoD')
        {
            Connect-MicrosoftTeams -AccountId $Global:o365Credential.UserName -TeamsEnvironmentName 'TeamsDOD' -ErrorAction Stop | Out-Null
        }
        else
        {
            Connect-MicrosoftTeams -AccountId $Global:o365Credential.UserName  -ErrorAction Stop | Out-Null
        }
        $Global:IsMFAAuth = $true
    }
    catch
    {
        throw $_
    }
}