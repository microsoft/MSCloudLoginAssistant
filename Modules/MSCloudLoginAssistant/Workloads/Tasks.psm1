function Connect-MSCloudLoginTasks
{
    [CmdletBinding()]
    param()

    $ProgressPreference = 'SilentlyContinue'
    $WarningPreference = 'SilentlyContinue'
    $VerbosePreference = 'SilentlyContinue'

    if ($Global:MSCloudLoginConnectionProfile.Tasks.AuthenticationType -eq 'CredentialsWithApplicationId' -or
        $Global:MSCloudLoginConnectionProfile.Tasks.AuthenticationType -eq 'Credentials')
    {
        Write-Verbose -Message 'Will try connecting with user credentials'
        Connect-MSCloudLoginTasksWithUser
    }
    elseif ($Global:MSCloudLoginConnectionProfile.Tasks.AuthenticationType -eq 'ServicePrincipalWithSecret')
    {
        Write-Verbose -Message 'Will try connecting with Application Secret'
        Connect-MSCloudLoginTasksWithAppSecret
    }
}

function Connect-MSCloudLoginTasksWithUser
{
    [CmdletBinding()]
    param()

    $tenantid = $Global:MSCloudLoginConnectionProfile.Tasks.Credentials.UserName.Split('@')[1]
    $username = $Global:MSCloudLoginConnectionProfile.Tasks.Credentials.UserName
    $password = $Global:MSCloudLoginConnectionProfile.Tasks.Credentials.GetNetworkCredential().password

    $clientId = '9ac8c0b3-2c30-497c-b4bc-cadfe9bd6eed'
    $uri = "https://login.microsoftonline.com/{0}/oauth2/token" -f $tenantid
    $body = "resource=https://tasks.office.com/&client_id=$clientId&grant_type=password&username={1}&password={0}" -f [System.Web.HttpUtility]::UrlEncode($password), $username

    # Request token through ROPC
    $managementToken = Invoke-RestMethod $uri `
        -Method POST `
        -Body $body `
        -ContentType "application/x-www-form-urlencoded" `
        -ErrorAction SilentlyContinue

    $Global:MSCloudLoginConnectionProfile.Tasks.AccessToken = $managementToken.token_type.ToString() + ' ' + $managementToken.access_token.ToString()
}

function Connect-MSCloudLoginTasksWithAppSecret
{
    [CmdletBinding()]
    param()


    $uri = "https://login.microsoftonline.com/{0}/oauth2/token" -f $Global:MSCloudLoginConnectionProfile.Tasks.TenantId
    $body = "resource=https://tasks.office.com/&client_id=$($Global:MSCloudLoginConnectionProfile.Tasks.ApplicationId)&client_secret=$($Global:MSCloudLoginConnectionProfile.Tasks.ApplicationSecret)&grant_type=client_credentials"

    # Request token through ROPC
    $managementToken = Invoke-RestMethod $uri `
        -Method POST `
        -Body $body `
        -ContentType "application/x-www-form-urlencoded" `
        -ErrorAction SilentlyContinue

    $Global:MSCloudLoginConnectionProfile.Tasks.AccessToken = $managementToken.token_type.ToString() + ' ' + $managementToken.access_token.ToString()
}

