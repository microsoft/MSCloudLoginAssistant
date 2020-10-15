function Connect-MSCloudLoginTeams
{
    [CmdletBinding()]
    param()

    if ($Global:UseApplicationIdentity)
    {    
        if($Global:appIdentityParams.CertificateThumbprint) 
        {
            $envName = Get-PsModuleAzureEnvironmentName -AzureCloudEnvironmentName $Global:appIdentityParams.AzureCloudEnvironmentName -Platform "MicrosoftTeams";
            if(![string]::IsNullOrWhitespace($envName)) 
            {
                Connect-MicrosoftTeams -TenantId $Global:appIdentityParams.Tenant -ApplicationId $Global:appIdentityParams.AppId -CertificateThumbprint $Global:appIdentityParams.CertificateThumbprint -ErrorAction Stop  -TeamsEnvironmentName $envName | Out-Null
            }
            else
            {
                Connect-MicrosoftTeams -TenantId $Global:appIdentityParams.Tenant -ApplicationId $Global:appIdentityParams.AppId -CertificateThumbprint $Global:appIdentityParams.CertificateThumbprint -ErrorAction Stop | Out-Null                   
            }            
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