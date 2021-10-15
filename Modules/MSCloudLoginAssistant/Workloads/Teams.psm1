function Connect-MSCloudLoginTeams
{
    [CmdletBinding()]
    param()

    $VerbosePreference  = 'SilentlyContinue'
    $WarningPreference  = 'SilentlyContinue'
    $ProgressPreference = 'SilentlyContinue'

    Write-Verbose -Message "Trying to get the Get-CsTeamsCallingPolicy command from within MSCloudLoginAssistant"
    $Global:currentErrorPreference = $ErrorActionPreference
    $Global:ErrorActionPreference = 'SilentlyContinue'
    try
    {
        if ($psversiontable.PSVersion.Major -ge 7)
        {
            Write-Verbose -Message "Using PowerShell 7 or above. Loading the MicrosoftTeams module using Windows PowerShell."
            Import-Module MicrosoftTeams -UseWindowsPowerShell -Global | Out-Null
        }
        $results = Get-CsTeamsCallingPolicy

        if ($null -ne $results)
        {
            Write-Verbose -Message "Succeeded"
            $Global:MSCloudLoginConnectionProfile.ExchangeOnline.Connected = $true
            return
        }
    }
    catch
    {
        Write-Verbose -Message "Failed"
    }
    $Global:ErrorActionPreference = $currentErrorPreference

    if ($Global:MSCloudLoginConnectionProfile.Teams.Connected)
    {
        Write-Verbose -Message "Already connected to Microsoft Teams. Not attempting to re-connect."
        return
    }

    [array]$activeSessions = Get-PSSession | Where-Object -FilterScript { $_.Name -like '*SfBPowerShellSessionViaTeamsModule*' -and $_.State -eq 'Opened' }

    if ($activeSessions.Length -ge 1)
    {
        Write-Verbose -Message "Found {$($activeSessions.Length)} existing Microsoft Teams Session"
        Write-Verbose -Message ($activeSessions | Out-String)
        $ProxyModule = Import-PSSession $activeSessions[0] `
                -DisableNameChecking `
                -AllowClobber
        Write-Verbose -Message "Imported session into $ProxyModule"
        Import-Module $ProxyModule -Global | Out-Null
        $Global:MSCloudLoginConnectionProfile.Teams.Connected = $true
        Write-Verbose "Reloaded the Microsoft Teams Module"
        return
    }
    Write-Verbose -Message 'No Active Connections to Microsoft Teams were found.'

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

            Write-Verbose -Message "Connecting to Microsoft Teams using credentials."
            Write-Verbose -Message "Params: $($ConnectionParams | Out-String)"
            Write-Verbose -Message "User: $($Global:MSCloudLoginConnectionProfile.Teams.Credentials.Username)"
            Connect-MicrosoftTeams @ConnectionParams -ErrorAction Stop | Out-Null
            $Global:MSCloudLoginConnectionProfile.Teams.ConnectedDateTime         = [System.DateTime]::Now.ToString()
            $Global:MSCloudLoginConnectionProfile.Teams.MultiFactorAuthentication = $false
            $Global:MSCloudLoginConnectionProfile.Teams.Connected                 = $true
        }
        catch
        {
            Write-Verbose -Message "Error from Non-MFA Logic Path: $_"
            if ($_.Exception -like '*AADSTS50076*' -or $_.Exception -eq 'One or more errors occurred.')
            {
                Connect-MSCloudLoginTeamsMFA
            }
            else
            {
                $Global:MSCloudLoginConnectionProfile.Teams.Connected = $false
                Write-Verbose -Message $_
                throw $_
            }
        }
    }
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
        Write-Verbose -Message "Disconnecting from Microsoft Teams"
        Disconnect-MicrosoftTeams | Out-Null

        Write-Verbose -Message "Connecting to Microsoft Teams using MFA credentials"
        Connect-MicrosoftTeams @ConnectionParams -ErrorAction Stop | Out-Null
        $Global:MSCloudLoginConnectionProfile.Teams.ConnectedDateTime         = [System.DateTime]::Now.ToString()
        $Global:MSCloudLoginConnectionProfile.Teams.MultiFactorAuthentication = $true
        $Global:MSCloudLoginConnectionProfile.Teams.Connected                 = $true
    }
    catch
    {
        Write-Verbose -Message "Error from MFA logic Path: $_"
        $Global:MSCloudLoginConnectionProfile.Teams.Connected = $false
        throw $_
    }
}
