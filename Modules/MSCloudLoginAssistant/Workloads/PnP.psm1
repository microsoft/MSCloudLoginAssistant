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

    if (!$Global:UseApplicationIdentity -and $null -eq $Global:o365Credential)
    {
       $Global:o365Credential = Get-Credential -Message "Cloud Credential"
    }

    if([string]::IsNullOrEmpty($ConnectionUrl))
    {
        $Global:SPOConnectionUrl =  Get-SPOAdminUrl -CloudCredential $Global:o365Credential
    }
    else
    {
        $Global:SPOConnectionUrl = $ConnectionUrl
    }
    Write-Verbose -Message "`$Global:SPOConnectionUrl is $Global:SPOConnectionUrl."

    try
    {
        if($Global:UseApplicationIdentity)
        {
            $envName = Get-PsModuleAzureEnvironmentName -AzureCloudEnvironmentName $Global:appIdentityParams.AzureCloudEnvironmentName -Platform "PnP"
            if($Global:appIdentityParams.CertificateThumbprint)
            {
                Connect-PnPOnline -Url $Global:SPOConnectionUrl -Tenant $Global:appIdentityParams.Tenant -ClientId $Global:appIdentityParams.AppId -Thumbprint $Global:appIdentityParams.CertificateThumbprint -AzureEnvironment $envName
                Write-Verbose "Connected to PnP {$($Global:SPOConnectionUrl) using application identity with certificate thumbprint"
            }
            else
            {
                Connect-PnPOnline -Url $Global:SPOConnectionUrl -AppId $Global:appIdentityParams.AppId -AppSecret $Global:appIdentityParams.AppSecret -AzureEnvironment $envName
                Write-Verbose "Connected to PnP {$($Global:SPOConnectionUrl) using application identity with application secret"
            }
        }
        else
        {
            Connect-PnPOnline -Url $Global:SPOConnectionUrl -Credentials $Global:o365Credential
            Write-Verbose "Connected to PnP {$($Global:SPOConnectionUrl) using regular authentication"
        }

        $Global:IsMFAAuth = $false
    }
    catch
    {
        if($Global:UseApplicationIdentity)
        {
            throw $_
        }
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
                $adminUrl = Get-SPOAdminUrl -CloudCredential $Global:o365Credential
                $AuthHeader = Get-AuthHeader -UserPrincipalName $Global:o365Credential.UserName `
                    -ResourceURI $adminUrl -clientID $clientID -RedirectURI $RedirectURI
                $AccessToken = $AuthHeader.split(" ")[1]
                Connect-PnPOnline -Url $Global:SPOConnectionUrl -UseWebLogin
                $Global:IsMFAAuth = $true
            }
            catch
            {
                throw $_
            }
        }
    }
    return
}
