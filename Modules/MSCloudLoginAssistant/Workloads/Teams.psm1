function Connect-MSCloudLoginTeams
{
    [CmdletBinding()]
    param()

    $VerbosePreference = 'SilentlyContinue'

    if ($Global:MSCloudLoginConnectionProfile.Teams.Connected)
    {
        return
    }

    $TeamsEnvironmentName

    if ($Global:MSCloudLoginConnectionProfile.Teams.AuthenticationType -eq 'ServicePrincipalWithThumbprint')
    {
        Write-Verbose -Message "Connecting to Microsoft Teams using AzureAD Application {$($Global:MSCloudLoginConnectionProfile.Teams.ApplicationId)}"
        try
        {
            $ConnectionParams = @{
                ApplicationId         = $Global:MSCloudLoginConnectionProfile.Teams.ApplicationId
                TenantId              = $Global:MSCloudLoginConnectionProfile.Teams.TenantId
                CertificateThumbprint = $Global:MSCloudLoginConnectionProfile.Teams.CertificateThumbprint
            }

            if ($Global:MSCloudLoginConnectionProfile.Teams.EnvironmentName -eq 'AzureUSGovernment')
            {
                $ConnectionParams.Add("TeamsEnvironmentName", 'TeamsGCCH')
            }

            Connect-MicrosoftTeams @ConnectionParams | Out-Null
            $Global:MSCloudLoginConnectionProfile.Teams.ConnectedDateTime         = [System.DateTime]::Now.ToString()
            $Global:MSCloudLoginConnectionProfile.Teams.MultiFactorAuthentication = $false
            $Global:MSCloudLoginConnectionProfile.Teams.Connected                 = $true
        }
        catch
        {
            $Global:MSCloudLoginConnectionProfile.Teams.Connected = $false
            throw $_
        }
    }
    elseif ($Global:MSCloudLoginConnectionProfile.Teams.AuthenticationType -eq 'Credentials')
    {
        if ($Global:MSCloudLoginConnectionProfile.Teams.EnvironmentName -eq 'AzureGermany')
        {
            Write-Warning 'Microsoft Teams is not supported in the Germany Cloud'
            $Global:MSCloudLoginConnectionProfile.Teams.Connected = $false
            return
        }

        try
        {
            $ConnectionParams = @{
                Credential = $Global:MSCloudLoginConnectionProfile.Teams.Credentials
            }

            if ($Global:MSCloudLoginConnectionProfile.Teams.EnvironmentName -eq 'AzureUSGovernment')
            {
                $ConnectionParams.Add("TeamsEnvironmentName", 'TeamsGCCH')
            }

            Connect-MicrosoftTeams @ConnectionParams -ErrorAction Stop | Out-Null
            $Global:MSCloudLoginConnectionProfile.Teams.ConnectedDateTime         = [System.DateTime]::Now.ToString()
            $Global:MSCloudLoginConnectionProfile.Teams.MultiFactorAuthentication = $false
            $Global:MSCloudLoginConnectionProfile.Teams.Connected                 = $true
        }
        catch
        {
            if ($_.Exception -like '*AADSTS50076*' -or $_.Exception -eq 'One or more errors occurred.')
            {
                Connect-MSCloudLoginTeamsMFA
            }
            else
            {
                $Global:MSCloudLoginConnectionProfile.Teams.Connected = $false
                throw $_
            }
        }
    }
    Import-Module MicrosoftTeams -Force -Global
    return
}

function Connect-MSCloudLoginTeamsMFA
{
    [CmdletBinding()]
    param()

    try
    {
        $ConnectionParams = @{}
        if ($Global:MSCloudLoginConnectionProfile.Teams.EnvironmentName -eq 'AzureUSGovernment')
        {
            $ConnectionParams.Add("TeamsEnvironmentName", "TeamsGCCH")
        }
        Disconnect-MicrosoftTeams | Out-Null
        Connect-MicrosoftTeams @ConnectionParams -ErrorAction Stop | Out-Null
        $Global:MSCloudLoginConnectionProfile.Teams.ConnectedDateTime         = [System.DateTime]::Now.ToString()
        $Global:MSCloudLoginConnectionProfile.Teams.MultiFactorAuthentication = $true
        $Global:MSCloudLoginConnectionProfile.Teams.Connected                 = $true
    }
    catch
    {
        $Global:MSCloudLoginConnectionProfile.Teams.Connected = $false
        throw $_
    }
}
