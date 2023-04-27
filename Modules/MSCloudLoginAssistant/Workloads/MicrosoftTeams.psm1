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
            $Global:MSCloudLoginConnectionProfile.MicrosoftTeams.Connected = $true
            return
        }
    }
    catch
    {
        Write-Verbose -Message "Failed"
        $Global:MSCloudLoginConnectionProfile.MicrosoftTeams.Connected = $false
    }
    $Global:ErrorActionPreference = $currentErrorPreference

    if ($Global:MSCloudLoginConnectionProfile.MicrosoftTeams.Connected)
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
        $Global:MSCloudLoginConnectionProfile.MicrosoftTeams.Connected = $true
        Write-Verbose "Reloaded the Microsoft Teams Module"
        return
    }
    Write-Verbose -Message 'No Active Connections to Microsoft Teams were found.'

    if ($Global:MSCloudLoginConnectionProfile.MicrosoftTeams.AuthenticationType -eq 'ServicePrincipalWithThumbprint')
    {
        Write-Verbose -Message "Connecting to Microsoft Teams using AzureAD Application {$($Global:MSCloudLoginConnectionProfile.MicrosoftTeams.ApplicationId)}"
        try
        {
            $ConnectionParams = @{
                ApplicationId         = $Global:MSCloudLoginConnectionProfile.MicrosoftTeams.ApplicationId
                TenantId              = $Global:MSCloudLoginConnectionProfile.MicrosoftTeams.TenantId
                CertificateThumbprint = $Global:MSCloudLoginConnectionProfile.MicrosoftTeams.CertificateThumbprint
            }

            if ($Global:MSCloudLoginConnectionProfile.MicrosoftTeams.EnvironmentName -eq 'AzureUSGovernment')
            {
                $ConnectionParams.Add("TeamsEnvironmentName", 'TeamsGCCH')
            }
            elseif ($Global:MSCloudLoginConnectionProfile.MicrosoftTeams.EnvironmentName -eq 'USGovernmentDoD')
            {
                $ConnectionParams.Add("TeamsEnvironmentName", 'TeamsDOD')
            }
            elseif ($Global:MSCloudLoginConnectionProfile.MicrosoftTeams.EnvironmentName -eq 'AzureChinaCloud')
            {
                $ConnectionParams.Add("TeamsEnvironmentName", 'TeamsChina')
            }

            Connect-MicrosoftTeams @ConnectionParams | Out-Null
            $Global:MSCloudLoginConnectionProfile.MicrosoftTeams.ConnectedDateTime         = [System.DateTime]::Now.ToString()
            $Global:MSCloudLoginConnectionProfile.MicrosoftTeams.MultiFactorAuthentication = $false
            $Global:MSCloudLoginConnectionProfile.MicrosoftTeams.Connected                 = $true
        }
        catch
        {
            $Global:MSCloudLoginConnectionProfile.MicrosoftTeams.Connected = $false
            throw $_
        }
    }
    elseif ($Global:MSCloudLoginConnectionProfile.MicrosoftTeams.AuthenticationType -eq 'Credentials')
    {
        if ($Global:MSCloudLoginConnectionProfile.MicrosoftTeams.EnvironmentName -eq 'AzureGermany')
        {
            Write-Warning 'Microsoft Teams is not supported in the Germany Cloud'
            $Global:MSCloudLoginConnectionProfile.MicrosoftTeams.Connected = $false
            return
        }

        try
        {
            $ConnectionParams = @{
                Credential = $Global:MSCloudLoginConnectionProfile.MicrosoftTeams.Credentials
            }

            if ($Global:MSCloudLoginConnectionProfile.MicrosoftTeams.EnvironmentName -eq 'AzureUSGovernment')
            {
                $ConnectionParams.Add("TeamsEnvironmentName", 'TeamsGCCH')
            }

            if ($Global:MSCloudLoginConnectionProfile.MicrosoftTeams.EnvironmentName -eq 'USGovernmentDoD')
            {
                $ConnectionParams.Add("TeamsEnvironmentName", 'TeamsDOD')
            }

            Write-Verbose -Message "Connecting to Microsoft Teams using credentials."
            Write-Verbose -Message "Params: $($ConnectionParams | Out-String)"
            Write-Verbose -Message "User: $($Global:MSCloudLoginConnectionProfile.MicrosoftTeams.Credentials.Username)"
            Connect-MicrosoftTeams @ConnectionParams -ErrorAction Stop
            $Global:MSCloudLoginConnectionProfile.MicrosoftTeams.ConnectedDateTime         = [System.DateTime]::Now.ToString()
            $Global:MSCloudLoginConnectionProfile.MicrosoftTeams.MultiFactorAuthentication = $false
            $Global:MSCloudLoginConnectionProfile.MicrosoftTeams.Connected                 = $true
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
                $Global:MSCloudLoginConnectionProfile.MicrosoftTeams.Connected = $false
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
        if ($Global:MSCloudLoginConnectionProfile.MicrosoftTeams.EnvironmentName -eq 'AzureUSGovernment')
        {
            $ConnectionParams.Add("TeamsEnvironmentName", "TeamsGCCH")
        }
        if ($Global:MSCloudLoginConnectionProfile.MicrosoftTeams.EnvironmentName -eq 'USGovernmentDoD')
        {
            $ConnectionParams.Add("TeamsEnvironmentName", 'TeamsDOD')
        }
        Write-Verbose -Message "Disconnecting from Microsoft Teams"
        Disconnect-MicrosoftTeams | Out-Null

        Write-Verbose -Message "Connecting to Microsoft Teams using MFA credentials"
        Connect-MicrosoftTeams @ConnectionParams -ErrorAction Stop | Out-Null
        $Global:MSCloudLoginConnectionProfile.MicrosoftTeams.ConnectedDateTime         = [System.DateTime]::Now.ToString()
        $Global:MSCloudLoginConnectionProfile.MicrosoftTeams.MultiFactorAuthentication = $true
        $Global:MSCloudLoginConnectionProfile.MicrosoftTeams.Connected                 = $true
    }
    catch
    {
        Write-Verbose -Message "Error from MFA logic Path: $_"
        $Global:MSCloudLoginConnectionProfile.MicrosoftTeams.Connected = $false
        throw $_
    }
}
