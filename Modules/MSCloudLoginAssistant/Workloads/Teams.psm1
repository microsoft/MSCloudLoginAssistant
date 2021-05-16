function Connect-MSCloudLoginTeams
{
    [CmdletBinding()]
    param(
        [Parameter()]
        [System.String]
        $ApplicationId,

        [Parameter()]
        [System.String]
        $TenantId,

        [Parameter()]
        [System.String]
        $CertificateThumbprint
    )
    if ($Global:MSCloudLoginTeamsConnected)
    {
        return
    }
    if (-not [String]::IsNullOrEmpty($ApplicationId) -and `
        -not [String]::IsNullOrEmpty($TenantId) -and `
        -not [String]::IsNullOrEmpty($CertificateThumbprint))
    {
        Write-Verbose -Message "Connecting to Microsoft Teams using AzureAD Application {$ApplicationId}"
        try
        {
            Connect-MicrosoftTeams -ApplicationId $ApplicationId -TenantId $TenantId -CertificateThumbprint $CertificateThumbprint | Out-Null
            $Global:MSCloudLoginTeamsConnected = $true
        }
        catch
        {
            throw $_
        }
    }
    elseif ($null -ne $Global:o365Credential)
    {
        if ($null -eq $Global:CloudEnvironmentInfo)
        {
            $Global:CloudEnvironmentInfo = Get-CloudEnvironmentInfo -Credentials $Global:o365Credential
        }
        if ($Global:CloudEnvironmentInfo.cloud_instance_name -eq 'microsoftonline.de')
        {
            $Global:CloudEnvironment = 'Germany'
            Write-Warning 'Microsoft Teams is not supported in the Germany Cloud'
            return
        }
        if ($Global:IsMFAAuth)
        {        
            Connect-MSCloudLoginTeamsMFA -EnvironmentName $Global:CloudEnvironment
        }
        try
        {
            Connect-MicrosoftTeams -Credential $Global:o365Credential -ErrorAction Stop | Out-Null
            $Global:MSCloudLoginTeamsConnected = $true
        }
        catch
        {
            if ($_.Exception -like '*unknown_user_type: Unknown User Type*')
            {
                $Global:CloudEnvironment = 'GCCHigh'

                try
                {
                    Connect-MicrosoftTeams -TeamsEnvironmentName 'TeamsGCCH' -Credential $Global:o365Credential -ErrorAction Stop | Out-Null
                    $Global:MSCloudLoginTeamsConnected = $true
                }
                catch
                {
                    try
                    {
                        Connect-MicrosoftTeams -TeamsEnvironmentName 'TeamsDOD' -Credential $Global:o365Credential -ErrorAction Stop | Out-Null
                        $Global:MSCloudLoginTeamsConnected = $true
                        $Global:CloudEnvironment = 'DoD'
                    }
                    catch
                    {
                        $Global:MSCloudLoginTeamsConnected = $false
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
                $Global:MSCloudLoginTeamsConnected = $false
                throw $_
            }
        }
    }
    else
    {
        try
        {
            Connect-MicrosoftTeams -ErrorAction Stop | Out-Null
            $Global:MSCloudLoginTeamsConnected = $true
        }
        catch
        {
            $Global:MSCloudLoginTeamsConnected = $false
            throw $_
        }
    }    
    Import-Module MicrosoftTeams -Force -Global
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
        $Global:MSCloudLoginTeamsConnected = $True
    }
    catch
    {
        $Global:MSCloudLoginTeamsConnected = $false
        throw $_
    }
}
