function Connect-MSCloudLoginPnP
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $False)]
        [System.String]
        $ConnectionUrl,

        [Parameter()]
        [System.String]
        $ApplicationId,

        [Parameter()]
        [System.String]
        $TenantId,

        [Parameter()]
        [System.String]
        $CertificateThumbprint,

        [Parameter()]
        [SecureString]
        $CertificatePassword,

        [Parameter()]
        [System.String]
        $CertificatePath
    )
    $clientid = "9bc3ab49-b65d-410a-85ad-de819febfddc"
    $RedirectURI = "https://oauth.spops.microsoft.com/"

    if (-not [String]::IsNullOrEmpty($CertificateThumbprint) -and (-not[String]::IsNullOrEmpty($CertificatePassword) -or
            -not[String]::IsNullOrEmpty($CertificatePath))
    )
    {
        throw "Cannot specific both a Certificate Thumbprint and Certificate Path and Password"
    }

    if ($null -eq $Global:o365Credential -and [String]::IsNullOrEmpty($ApplicationId))
    {
        $Global:o365Credential = Get-Credential -Message "Cloud Credential"
    }

    if ([string]::IsNullOrEmpty($ConnectionUrl))
    {
        if (-not [string]::IsNullOrEmpty($Global:SPOAdminUrl))
        {
            $Global:SPOConnectionUrl = $Global:SPOAdminUrl
        }
        else
        {
            if ($null -ne $Global:o365Credential)
            {
                $Global:SPOAdminUrl = Get-SPOAdminUrl -CloudCredential $Global:o365Credential
            }
            else
            {
                if ($TenantId.Contains("onmicrosoft"))
                {
                    $domain = $TenantId.Split(".")[0]
                    $Global:SPOAdminUrl = "https://$domain-admin.sharepoint.com"
                }
                else
                {
                    throw "TenantID must be in format contoso.onmicrosoft.com"
                }
            }
        }
        $Global:SPOConnectionUrl = $Global:SPOAdminUrl
    }
    else
    {
        $Global:SPOConnectionUrl = $ConnectionUrl
    }
    Write-Verbose -Message "`$Global:SPOConnectionUrl is $Global:SPOConnectionUrl."
    # Explicitly import the required module(s) in case there is cmdlet ambiguity with other modules e.g. SharePointPnPPowerShell2013
    Import-Module -Name PnP.PowerShell -DisableNameChecking -Force

    try
    {
        if (-not [String]::IsNullOrEmpty($ApplicationId) -and `
                -not [String]::IsNullOrEmpty($TenantId) -and `
                -not [String]::IsNullOrEmpty($CertificateThumbprint) -and `
                - [String]::IsNullOrEmpty($CertificatePath)
        )
        {
            Connect-PnPOnline -Url $Global:SPOConnectionUrl `
                -ClientId $ApplicationId `
                -Tenant $tenantId `
                -Thumbprint $CertificateThumbprint
            Write-Verbose "Connected to PnP {$($Global:SPOConnectionUrl) using application authentication"
            $Global:IsMFAAuth = $false
        }
        elseif (-not [String]::IsNullOrEmpty($ApplicationId) -and `
                -not [String]::IsNullOrEmpty($TenantId) -and `
                -not [String]::IsNullOrEmpty($CertificatePassword) -and `
                -not [String]::IsNullOrEmpty($CertificatePath))
        {
            Connect-PnPOnline -Url $Global:SPOConnectionUrl `
                -ClientId $ApplicationId `
                -Tenant $tenantId `
                -CertificatePassword $CertificatePassword `
                -CertificatePath $CertificatePath
            Write-Verbose "Connected to PnP {$($Global:SPOConnectionUrl) using application authentication"
            $Global:IsMFAAuth = $false
        }
        else
        {
            if ($Global:CloudEnvironment -eq 'GCCHigh')
            {
                $Global:SPOConnectionUrl = $Global:SPOConnectionUrl.Replace('.com', '.us')
                Connect-PnPOnline -Url $Global:SPOConnectionUrl -Credentials $Global:o365Credential
                $Global:IsMFAAuth = $false
                $Global:CloudEnvironment = 'GCCHigh'
                Write-Verbose "Connected to PnP {$($Global:SPOConnectionUrl) using regular authentication"
                $Global:IsMFAAuth = $false
            }
            else
            {
                Connect-PnPOnline -Url $Global:SPOConnectionUrl `
                    -Credentials $Global:o365Credential
                Write-Verbose "Connected to PnP {$($Global:SPOConnectionUrl) using regular authentication"
                $Global:IsMFAAuth = $false
            }
        }
    }
    catch
    {
        if ($_.Exception -like '*AADSTS50076*')
        {
            try
            {
                if ($Global:CloudEnvironment -eq 'GCCHigh')
                {
                    $Global:SPOConnectionUrl = $Global:SPOConnectionUrl.Replace('.com', '.us')
                    Connect-PnPOnline -Url $Global:SPOConnectionUrl -UseWebLogin
                    $Global:IsMFAAuth = $true
                    $Global:MSCloudLoginAzurePnPConnected = $true
                }
                else
                {
                    Connect-PnPOnline -Url $Global:SPOConnectionUrl -UseWebLogin
                    $Global:IsMFAAuth = $true
                    $Global:MSCloudLoginAzurePnPConnected = $true
                }
            }
            catch
            {
                $Global:MSCloudLoginAzurePnPConnected = $false
                throw $_
            }
        }
        elseif ($_.Exception -like '*The sign-in name or password does not match one in the Microsoft account system*')
        {
            # This error means that the account was trying to connect using MFA.
            try
            {
                if ($null -eq $Global:SPOAdminUrl)
                {
                    $Global:SPOAdminUrl = Get-SPOAdminUrl -CloudCredential $Global:o365Credential
                }
                Write-Verbose "Trying to acquire AccessToken"
                $AuthHeader = Get-AuthHeader -UserPrincipalName $Global:o365Credential.UserName `
                    -ResourceURI $Global:SPOAdminUrl -clientID $clientID -RedirectURI $RedirectURI
                $AccessToken = $AuthHeader.split(" ")[1]
                Write-Verbose "Access Token = $AccessToken"
                if ($null -ne $AccessToken)
                {
                    Connect-PnPOnline -Url $Global:SPOConnectionUrl -AccessToken $AccessToken
                }
                else
                {
                    Connect-PnPOnline -Url $Global:SPOConnectionUrl -UseWebLogin
                }
                $Global:IsMFAAuth = $true
                $Global:MSCloudLoginAzurePnPConnected = $true
            }
            catch
            {
                Write-Verbose "Error acquiring AccessToken: $_.Exception"
                try
                {
                    Connect-PnPOnline -Url $Global:SPOConnectionUrl -UseWebLogin
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
        elseif ($_.Exception -like "*AADSTS65001: The user or administrator has not consented to use the application with ID*")
        {
            Write-Error "The PnP.PowerShell Azure AD Application has not been granted access for this tenant. Please run 'Register-PnPManagementShellAccess' to grant access and try again after."
        }
    }
    return
}
