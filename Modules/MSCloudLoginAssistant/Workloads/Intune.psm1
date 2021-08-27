function Connect-MSCloudLoginIntune
{
    [CmdletBinding()]
    Param(
        [Parameter()]
        [System.String]
        $ApplicationId,

        [Parameter()]
        [System.String]
        $TenantId,

        [Parameter()]
        [System.String]
        $ApplicationSecret,

        [Parameter()]
        [System.Management.Automation.PSCredential]
        $Credential
    )

    if ($null -ne $Credential)
    {
        $ApplicationID = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"
        $tenantId = $Credential.Username.Split('@')[1]
        try
        {
            Connect-MSGraph -Credential $Credential | Out-Null
        }
        catch
        {
            # If the Intune PowerShell application has not yet been granted access to the tenant
            if ($_.Exception -like '*The user or administrator has not consented to use the application with ID*')
            {
                Write-Verbose "The AzureAD Application {$ApplicationID} has not bee granted consent. Launching an interactive prompt to request consent.'"
                Connect-MSGraph -AdminConsent | Out-Null
            }
            elseif ($_.Exception -like '*Due to a configuration change made by your administrator*')
            {
                Write-Verbose "The specified user account requires MFA. Launching interactive prompt.'"
                Connect-MSGraph -AdminConsent | Out-Null
            }
            elseif ($_.Exception -like '*Unknown User Type*')
            {
                Write-Verbose "The AzureAD Application {$ApplicationID} has not bee granted consent. Launching an interactive prompt to request consent.'"
                Update-MSGraphEnvironment -AuthUrl "https://login.microsoftonline.us/common/oauth/v2.0/authorize/$tenantId" `
                    -GraphResourceId "https://graph.microsoft.us/" `
                    -GraphBaseUrl "https://graph.microsoft.us"
                try
                {
                    Connect-MSGraph -Credential $Credential | Out-Null
                }
                catch
                {
                    if ($_.Exception -like '*AADSTS50076: Due to a configuration change made by your administrator*')
                    {
                        # The account has MFA
                        Connect-MSGraph | Out-Null
                    }
                }
            }
        }
    }
    else
    {
        $WarningPreference = 'SilentlyContinue'
        try
        {
            Update-MSGraphEnvironment -AppID $ApplicationId `
                -AuthUrl "https://login.microsoftonline.com/oauth2/v2.0/token/$tenantId" | Out-Null
            Connect-MSGraph -ClientSecret $ApplicationSecret | Out-Null
        }
        catch
        {
            Update-MSGraphEnvironment -AppID $ApplicationId `
                -AuthUrl "https://login.microsoftonline.us/oauth2/v2.0/token/$tenantId" `
                    -GraphResourceId "https://graph.microsoft.us/" `
                    -GraphBaseUrl "https://graph.microsoft.us" | Out-Null
            Connect-MSGraph -ClientSecret $ApplicationSecret | Out-Null
        }
    }
}
