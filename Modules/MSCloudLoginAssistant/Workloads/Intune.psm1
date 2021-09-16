function Connect-MSCloudLoginIntune
{
    [CmdletBinding()]
    param()

    $ProgressPreference = 'SilentlyContinue'
    $WarningPreference  = 'SilentlyContinue'
    $VerbosePreference  = 'SilentlyContinue'

    if ($Global:MSCloudLoginConnectionProfile.Intune.Connected)
    {
        return
    }

    if ($Global:MSCloudLoginConnectionProfile.Intune.AuthenticationType -eq 'Credentials')
    {
        try
        {
            Update-MSGraphEnvironment -AuthUrl 'https://login.microsoftonline.com/common/' `
                -GraphResourceId $Global:MSCloudLoginConnectionProfile.Intune.GraphResourceId `
                -GraphBaseUrl $Global:MSCloudLoginConnectionProfile.Intune.GraphBaseUrl

            Connect-MSGraph -Credential $Global:MSCloudLoginConnectionProfile.Intune.Credentials | Out-Null
            $Global:MSCloudLoginConnectionProfile.Intune.ConnectedDateTime         = [System.DateTime]::Now.ToString()
            $Global:MSCloudLoginConnectionProfile.Intune.MultiFactorAuthentication = $false
            $Global:MSCloudLoginConnectionProfile.Intune.Connected                 = $true
        }
        catch
        {
            # If the Intune PowerShell application has not yet been granted access to the tenant
            if ($_.Exception -like '*The user or administrator has not consented to use the application with ID*')
            {
                Write-Verbose "The Intune PowerShell Azure AD Application has not bee granted consent. Launching an interactive prompt to request consent.'"
                Connect-MSGraph -AdminConsent | Out-Null
                $Global:MSCloudLoginConnectionProfile.Intune.ConnectedDateTime         = [System.DateTime]::Now.ToString()
                $Global:MSCloudLoginConnectionProfile.Intune.MultiFactorAuthentication = $false
                $Global:MSCloudLoginConnectionProfile.Intune.Connected                 = $true
            }
            elseif ($_.Exception -like '*Due to a configuration change made by your administrator*')
            {
                Write-Verbose "The specified user account requires MFA. Launching interactive prompt.'"
                Connect-MSGraph | Out-Null
                $Global:MSCloudLoginConnectionProfile.Intune.ConnectedDateTime         = [System.DateTime]::Now.ToString()
                $Global:MSCloudLoginConnectionProfile.Intune.MultiFactorAuthentication = $true
                $Global:MSCloudLoginConnectionProfile.Intune.Connected                 = $true
            }
            else
            {
                $Global:MSCloudLoginConnectionProfile.Intune.Connected = $false
                throw $_
            }
        }
    }
    else
    {
        $WarningPreference = 'SilentlyContinue'
        try
        {
            Update-MSGraphEnvironment -AuthUrl $Global:MSCloudLoginConnectionProfile.Intune.AuthorizationUrl `
                -GraphResourceId $Global:MSCloudLoginConnectionProfile.Intune.GraphResourceId `
                -GraphBaseUrl $Global:MSCloudLoginConnectionProfile.Intune.GraphBaseUrl `
                -AppID $Global:MSCloudLoginConnectionProfile.Intune.ApplicationId
            Connect-MSGraph -ClientSecret $Global:MSCloudLoginConnectionProfile.Intune.ApplicationSecret | Out-Null
        }
        catch
        {
            $Global:MSCloudLoginConnectionProfile.Intune.Connected = $false
            throw $_
        }
    }
}
