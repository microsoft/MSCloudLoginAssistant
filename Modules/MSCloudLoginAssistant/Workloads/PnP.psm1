function Connect-MSCloudLoginPnP
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $False)]
        [System.String]
        $ConnectionUrl
    )
    $clientid = "9bc3ab49-b65d-410a-85ad-de819febfddc"
    $RedirectURI = "https://oauth.spops.microsoft.com/"

    if ([string]::IsNullOrEmpty($Global:SPOAdminUrl))
    {
        $Global:SPOAdminUrl = Get-SPOAdminUrl -CloudCredential $CloudCredential
    }

    if ([string]::IsNullOrEmpty($ConnectionUrl))
    {
        $Global:SPOConnectionUrl = $Global:SPOAdminUrl
    }
    else
    {
        $Global:SPOConnectionUrl = $ConnectionUrl
    }
    Write-Verbose -Message "`$Global:SPOConnectionUrl is $Global:SPOConnectionUrl."

    
    Write-Host "Environment:" $Global:CloudEnvironment
    Write-Host "MFA:" $Global:IsMFAAuth
    Write-Host "Url:" $Global:SPOConnectionUrl
    try
    {
        Connect-PnPOnline -Url $Global:SPOConnectionUrl -Credentials $Global:o365Credential
        Write-Verbose "Connected to PnP {$($Global:SPOConnectionUrl) using regular authentication"
        $Global:IsMFAAuth = $false
    }
    catch
    {
        if ($_.Exception -like '*Microsoft.SharePoint.Client.ServerUnauthorizedAccessException*' -or `
            $_.Exception -like '*The remote server returned an error: (401) Unauthorized.*')
        {
            $Global:MSCloudLoginAzurePnPConnected = $false
            throw [System.Exception] "Specified account does not have access to connect to the site. $_"
        }
        elseif ($_.Exception -like "*The remote name could not be resolved:*" -and ($Global:CloudEnvironment -eq 'USGovernment' -or `
            $Global:CloudEnvironment -eq 'GCCHigh') -and !$Global:IsMFAAuth)
        {
            # We are most likely dealing with a GCC High environment, we need to change the connection url to *.us
            $Global:SPOConnectionUrl = $Global:SPOConnectionUrl.Replace('.com', '.us')
            Connect-PnPOnline -Url $Global:SPOConnectionUrl -Credentials $Global:o365Credential
            $Global:IsMFAAuth = $false
            $Global:CloudEnvironment = 'GCCHigh'
        }
        elseif ($_.Exception -like '*The sign-in name or password does not match one in the Microsoft account system*')
        {
            # This error means that the account was trying to connect using MFA.
            try
            {
                $AuthHeader = Get-AuthHeader -UserPrincipalName $Global:o365Credential.UserName `
                    -ResourceURI $Global:SPOConnectionUrl -clientID $clientID -RedirectURI $RedirectURI
                $AccessToken = $AuthHeader.split(" ")[1]
                Connect-PnPOnline -Url $Global:SPOConnectionUrl -AccessToken $AccessToken
                $Global:IsMFAAuth = $true
                $Global:MSCloudLoginAzurePnPConnected = $true
            }
            catch
            {
                $Global:MSCloudLoginAzurePnPConnected = $false
                throw $_
            }
        }
    }
    return
}