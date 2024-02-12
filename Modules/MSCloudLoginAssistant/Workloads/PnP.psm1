function Connect-MSCloudLoginPnP
{
    [CmdletBinding()]
    param(
        [boolean]
        $ForceRefreshConnection = $false
    )

    $ProgressPreference = 'SilentlyContinue'
    $WarningPreference  = 'SilentlyContinue'
    $VerbosePreference  = 'SilentlyContinue'

    if ($Global:MSCloudLoginConnectionProfile.PnP.Connected)
    {
        Write-Verbose 'Already connected to PnP, not attempting to authenticate.'
        return
    }

    $requiresWindowsPowerShell = $false
    if ($psversiontable.PSVersion.Major -ge 7)
    {
        try
        {
            Get-PnPAlert -ErrorAction 'Stop' | Out-Null
            Write-Verbose -Message 'Retrieved results from the command. Not re-connecting to PnP.'
            $Global:MSCloudLoginConnectionProfile.PnP.Connected = $true
            return
        }
        catch
        {
            Write-Verbose -Message "Couldn't get results back from the command"
            Write-Verbose -Message 'Using PowerShell 7 or above. Loading the PnP.PowerShell module using Windows PowerShell.'
            try
            {
                Import-Module PnP.PowerShell -UseWindowsPowerShell -Global -Force -ErrorAction Stop | Out-Null
            }
            catch
            {
                $requiresWindowsPowerShell = $true
            }

        }
    }

    if ($requiresWindowsPowerShell)
    {
        throw "Powershell 7+ was detected. We need to load the PnP.PowerShell module using the -UseWindowsPowerShell switch which requires the module to be installed under C:\Program Files\WindowsPowerShell\Modules. You can either move the module to that location or use PowerShell 5.1 to install the modules using 'Install-Module Pnp.PowerShell -Force -Scope AllUsers'."
    }

    if ([string]::IsNullOrEmpty($Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl))
    {
        if (-not [string]::IsNullOrEmpty($Global:MSCloudLoginConnectionProfile.PnP.AdminUrl))
        {
            $Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl = $Global:MSCloudLoginConnectionProfile.PnP.AdminUrl
        }
        else
        {
            if ($Global:MSCloudLoginConnectionProfile.PnP.AuthenticationType -eq 'Credentials' -and `
                    -not $Global:MSCloudLoginConnectionProfile.PnP.AdminUrl)
            {
                $adminUrl = Get-SPOAdminUrl -Credential $Global:MSCloudLoginConnectionProfile.PnP.Credentials
                if ([String]::IsNullOrEmpty($adminUrl) -eq $false)
                {
                    $Global:MSCloudLoginConnectionProfile.PnP.AdminUrl = $adminUrl
                    $Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl = $Global:MSCloudLoginConnectionProfile.PnP.AdminUrl
                }
                else
                {
                    throw 'Unable to retrieve SharePoint Admin Url. Check if the Graph can be contacted successfully.'
                }
            }
            else
            {
                if ($Global:MSCloudLoginConnectionProfile.PnP.TenantId.Contains('onmicrosoft'))
                {
                    $domain = $Global:MSCloudLoginConnectionProfile.PnP.TenantId.Replace('.onmicrosoft.', '-admin.sharepoint.')
                    if (-not $Global:MSCloudLoginConnectionProfile.PnP.AdminUrl)
                    {
                        $Global:MSCloudLoginConnectionProfile.PnP.AdminUrl = "https://$domain"
                    }
                    $Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl = ("https://$domain").Replace('-admin', '')
                }
                elseif ($Global:MSCloudLoginConnectionProfile.PnP.TenantId.Contains('.onmschina.'))
                {
                    $domain = $Global:MSCloudLoginConnectionProfile.PnP.TenantId.Replace('.partner.onmschina.', '-admin.sharepoint.')
                    if (-not $Global:MSCloudLoginConnectionProfile.PnP.AdminUrl)
                    {
                        $Global:MSCloudLoginConnectionProfile.PnP.AdminUrl = "https://$domain"
                    }
                    $Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl = ("https://$domain").Replace('-admin', '')
                }
                else
                {
                    throw 'TenantId must be in format contoso.onmicrosoft.com'
                }
            }
        }
    }
    elseif ([string]::IsNullOrEmpty($Global:MSCloudLoginConnectionProfile.PnP.AdminUrl))
    {
        $Global:MSCloudLoginConnectionProfile.PnP.AdminUrl = $Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl
    }

    try
    {
        if (-not $Global:MSCloudLoginConnectionProfile.PnP.Connected)
        {
            if ($Global:MSCloudLoginConnectionProfile.PnP.AuthenticationType -eq 'ServicePrincipalWithThumbprint')
            {
                if ($Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl)
                {
                    Write-Information -Message 'Connecting with Service Principal - Thumbprint'
                    Write-Information -Message "URL: $($Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl)"
                    Write-Information -Message "ConnectionUrl: $($Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl)"
                    Connect-PnPOnline -Url $Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl `
                        -ClientId $Global:MSCloudLoginConnectionProfile.PnP.ApplicationId `
                        -Tenant $Global:MSCloudLoginConnectionProfile.PnP.TenantId `
                        -Thumbprint $Global:MSCloudLoginConnectionProfile.PnP.CertificateThumbprint `
                        -AzureEnvironment $Global:MSCloudLoginConnectionProfile.PnP.PnPAzureEnvironment | Out-Null
                }
                elseif ($Global:MSCloudLoginConnectionProfile.PnP.AdminUrl)
                {
                    Write-Information -Message 'Connecting with Service Principal - Thumbprint'
                    Write-Information -Message "URL: $($Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl)"
                    Write-Information -Message "AdminUrl: $($Global:MSCloudLoginConnectionProfile.PnP.AdminUrl)"

                    $tenantIdValue = $Global:MSCloudLoginConnectionProfile.PnP.TenantId
                    if ($Global:MSCloudLoginConnectionProfile.PnP.EnvironmentName -eq 'AzureChinaCloud')
                    {
                        $tenantIdValue = $Global:MSCloudLoginConnectionProfile.PnP.TenantGUID
                    }

                    Connect-PnPOnline -Url $Global:MSCloudLoginConnectionProfile.PnP.AdminUrl `
                        -ClientId $Global:MSCloudLoginConnectionProfile.PnP.ApplicationId `
                        -Tenant $tenantIdValue `
                        -Thumbprint $Global:MSCloudLoginConnectionProfile.PnP.CertificateThumbprint `
                        -AzureEnvironment $Global:MSCloudLoginConnectionProfile.PnP.PnPAzureEnvironment | Out-Null
                }

                $Global:MSCloudLoginConnectionProfile.PnP.ConnectedDateTime = [System.DateTime]::Now.ToString()
                $Global:MSCloudLoginConnectionProfile.PnP.MultiFactorAuthentication = $false
                $Global:MSCloudLoginConnectionProfile.PnP.Connected = $true
            }
            elseif ($Global:MSCloudLoginConnectionProfile.PnP.AuthenticationType -eq 'ServicePrincipalWithPath')
            {
                if ($Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl)
                {
                    Write-Information -Message 'Connecting with Service Principal - Path'
                    Write-Information -Message "URL: $($Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl)"
                    Write-Information -Message "ConnectionUrl: $($Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl)"
                    Connect-PnPOnline -Url $Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl `
                        -ClientId $Global:MSCloudLoginConnectionProfile.PnP.ApplicationId `
                        -Tenant $Global:MSCloudLoginConnectionProfile.PnP.TenantId `
                        -CertificatePassword $Global:MSCloudLoginConnectionProfile.PnP.CertificatePassword `
                        -CertificatePath $Global:MSCloudLoginConnectionProfile.PnP.CertificatePath `
                        -AzureEnvironment $Global:MSCloudLoginConnectionProfile.PnP.PnPAzureEnvironment
                }
                else
                {
                    Write-Information -Message 'Connecting with Service Principal - Path'
                    Write-Information -Message "URL: $($Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl)"
                    Write-Information -Message "AdminUrl: $($Global:MSCloudLoginConnectionProfile.PnP.AdminUrl)"
                    Connect-PnPOnline -Url $Global:MSCloudLoginConnectionProfile.PnP.AdminUrl `
                        -ClientId $Global:MSCloudLoginConnectionProfile.PnP.ApplicationId `
                        -Tenant $Global:MSCloudLoginConnectionProfile.PnP.TenantId `
                        -CertificatePassword $Global:MSCloudLoginConnectionProfile.PnP.CertificatePassword `
                        -CertificatePath $Global:MSCloudLoginConnectionProfile.PnP.CertificatePath `
                        -AzureEnvironment $Global:MSCloudLoginConnectionProfile.PnP.PnPAzureEnvironment
                }

                $Global:MSCloudLoginConnectionProfile.PnP.ConnectedDateTime = [System.DateTime]::Now.ToString()
                $Global:MSCloudLoginConnectionProfile.PnP.MultiFactorAuthentication = $false
                $Global:MSCloudLoginConnectionProfile.PnP.Connected = $true
            }
            elseif ($Global:MSCloudLoginConnectionProfile.PnP.AuthenticationType -eq 'ServicePrincipalWithSecret')
            {
                if ($Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl -or $ForceRefreshConnection)
                {
                    Write-Information -Message 'Connecting with Service Principal - Secret'
                    Write-Information -Message "URL: $($Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl)"
                    Write-Information -Message "ConnectionUrl: $($Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl)"
                    Connect-PnPOnline -Url $Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl `
                        -ClientId $Global:MSCloudLoginConnectionProfile.PnP.ApplicationId `
                        -ClientSecret $Global:MSCloudLoginConnectionProfile.PnP.ApplicationSecret `
                        -AzureEnvironment $Global:MSCloudLoginConnectionProfile.PnP.PnPAzureEnvironment `
                        -WarningAction 'Ignore'
                }
                else
                {
                    Write-Information -Message 'Connecting with Service Principal - Secret'
                    Write-Information -Message "URL: $($Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl)"
                    Write-Information -Message "AdminUrl: $($Global:MSCloudLoginConnectionProfile.PnP.AdminUrl)"
                    Connect-PnPOnline -Url $Global:MSCloudLoginConnectionProfile.PnP.AdminUrl `
                        -ClientId $Global:MSCloudLoginConnectionProfile.PnP.ApplicationId `
                        -ClientSecret $Global:MSCloudLoginConnectionProfile.PnP.ApplicationSecret `
                        -AzureEnvironment $Global:MSCloudLoginConnectionProfile.PnP.PnPAzureEnvironment `
                        -WarningAction 'Ignore'
                }
                $Global:MSCloudLoginConnectionProfile.PnP.ConnectedDateTime = [System.DateTime]::Now.ToString()
                $Global:MSCloudLoginConnectionProfile.PnP.MultiFactorAuthentication = $false
                $Global:MSCloudLoginConnectionProfile.PnP.Connected = $true
            }
            elseif ($Global:MSCloudLoginConnectionProfile.PnP.AuthenticationType -eq 'CredentialsWithTenantId')
            {
                throw "You cannot specify TenantId with Credentials when connecting to PnP."
            }
            elseif ($Global:MSCloudLoginConnectionProfile.PnP.AuthenticationType -eq 'Credentials')
            {
                if ($Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl -or $ForceRefreshConnection)
                {
                    Write-Information -Message 'Connecting with Credentials'
                    Write-Information -Message "URL: $($Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl)"
                    Write-Information -Message "ConnectionUrl: $($Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl)"
                    Connect-PnPOnline -Url $Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl `
                        -Credentials $Global:MSCloudLoginConnectionProfile.PnP.Credentials `
                        -AzureEnvironment $Global:MSCloudLoginConnectionProfile.PnP.PnPAzureEnvironment
                }
                else
                {
                    Write-Information -Message 'Connecting with Credentials'
                    Write-Information -Message "URL: $($Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl)"
                    Write-Information -Message "AdminUrl: $($Global:MSCloudLoginConnectionProfile.PnP.AdminUrl)"
                    Connect-PnPOnline -Url $Global:MSCloudLoginConnectionProfile.PnP.AdminUrl `
                        -Credentials $Global:MSCloudLoginConnectionProfile.PnP.Credentials `
                        -AzureEnvironment $Global:MSCloudLoginConnectionProfile.PnP.PnPAzureEnvironment
                }

                $Global:MSCloudLoginConnectionProfile.PnP.ConnectedDateTime = [System.DateTime]::Now.ToString()
                $Global:MSCloudLoginConnectionProfile.PnP.MultiFactorAuthentication = $false
                $Global:MSCloudLoginConnectionProfile.PnP.Connected = $true
            }
            elseif ($Global:MSCloudLoginConnectionProfile.PnP.AuthenticationType -eq 'Identity')
            {
                if ($Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl)
                {
                    $connectionURL = $Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl
                }
                else
                {
                    $connectionURL = $Global:MSCloudLoginConnectionProfile.PnP.AdminUrl
                }

                if ('AzureAutomation/' -eq $env:AZUREPS_HOST_ENVIRONMENT)
                {
                    $url = $env:IDENTITY_ENDPOINT
                    $headers = New-Object 'System.Collections.Generic.Dictionary[[String],[String]]'
                    $headers.Add('X-IDENTITY-HEADER', $env:IDENTITY_HEADER)
                    $headers.Add('Metadata', 'True')
                    $body = @{resource = $connectionURL }
                    $oauth2 = Invoke-RestMethod $url -Method 'POST' -Headers $headers -ContentType 'application/x-www-form-urlencoded' -Body $body
                    $accessToken = $oauth2.access_token
                }
                elseif('http://localhost:40342' -eq $env:IMDS_ENDPOINT)
                {
                    #Get endpoint for Azure Arc Connected Device
                    $apiVersion = "2020-06-01"
                    $resource = "https://$resourceEndpoint"
                    $endpoint = "{0}?resource={1}&api-version={2}" -f $env:IDENTITY_ENDPOINT,$resource,$apiVersion
                    $secretFile = ""
                    try
                    {
                        Invoke-WebRequest -Method GET -Uri $endpoint -Headers @{Metadata='True'} -UseBasicParsing
                    }
                    catch
                    {
                        $wwwAuthHeader = $_.Exception.Response.Headers["WWW-Authenticate"]
                        if ($wwwAuthHeader -match "Basic realm=.+")
                        {
                            $secretFile = ($wwwAuthHeader -split "Basic realm=")[1]
                        }
                    }
                    $secret = Get-Content -Raw $secretFile
                    $response = Invoke-WebRequest -Method GET -Uri $endpoint -Headers @{Metadata='True'; Authorization="Basic $secret"} -UseBasicParsing
                    if ($response)
                    {
                        $accessToken = (ConvertFrom-Json -InputObject $response.Content).access_token
                    }
                }
                else
                {
                    # Get correct endopint for AzureVM
                    $oauth2 = Invoke-RestMethod -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=$ConnectionURL" -Headers @{Metadata = 'true' }
                    $accessToken = $oauth2.access_token

                }

                Connect-PnPOnline -Url $connectionURL `
                    -AccessToken $accessToken `
                    -AzureEnvironment $Global:MSCloudLoginConnectionProfile.PnP.PnPAzureEnvironment `
                    -WarningAction 'Ignore'

                $Global:MSCloudLoginConnectionProfile.PnP.ConnectedDateTime = [System.DateTime]::Now.ToString()
                $Global:MSCloudLoginConnectionProfile.PnP.MultiFactorAuthentication = $false
                $Global:MSCloudLoginConnectionProfile.PnP.Connected = $true
            }
            elseif ($Global:MSCloudLoginConnectionProfile.PnP.AuthenticationType -eq 'AccessToken')
            {
                $Ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($Global:MSCloudLoginConnectionProfile.PnP.AccessTokens[0])
                $AccessTokenValue = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($Ptr)
                [System.Runtime.InteropServices.Marshal]::ZeroFreeCoTaskMemUnicode($Ptr)
                if ($Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl -or $ForceRefreshConnection)
                {
                    Write-Information -Message 'Connecting with AccessToken'
                    Write-Information -Message "URL: $($Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl)"
                    Write-Information -Message "ConnectionUrl: $($Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl)"
                    Connect-PnPOnline -Url $Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl `
                        -AccessToken $AccessTokenValue `
                        -AzureEnvironment $Global:MSCloudLoginConnectionProfile.PnP.PnPAzureEnvironment
                }
                else
                {
                    Write-Information -Message 'Connecting with AccessToken'
                    Write-Information -Message "URL: $($Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl)"
                    Write-Information -Message "AdminUrl: $($Global:MSCloudLoginConnectionProfile.PnP.AdminUrl)"
                    Connect-PnPOnline -Url $Global:MSCloudLoginConnectionProfile.PnP.AdminUrl `
                        -AccessToken $AccessTokenValue `
                        -AzureEnvironment $Global:MSCloudLoginConnectionProfile.PnP.PnPAzureEnvironment
                }

                $Global:MSCloudLoginConnectionProfile.PnP.ConnectedDateTime = [System.DateTime]::Now.ToString()
                $Global:MSCloudLoginConnectionProfile.PnP.MultiFactorAuthentication = $false
                $Global:MSCloudLoginConnectionProfile.PnP.Connected = $true
            }
        }
    }
    catch
    {
        if ($_.Exception -like '*AADSTS50076*')
        {
            try
            {
                Connect-PnPOnline -Url $Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl `
                    -Interactive
                $Global:MSCloudLoginConnectionProfile.PnP.ConnectedDateTime = [System.DateTime]::Now.ToString()
                $Global:MSCloudLoginConnectionProfile.PnP.MultiFactorAuthentication = $true
                $Global:MSCloudLoginConnectionProfile.PnP.Connected = $true
            }
            catch
            {
                try
                {
                    Connect-PnPOnline -Url $Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl -UseWebLogin
                    $Global:MSCloudLoginConnectionProfile.PnP.ConnectedDateTime = [System.DateTime]::Now.ToString()
                    $Global:MSCloudLoginConnectionProfile.PnP.MultiFactorAuthentication = $true
                    $Global:MSCloudLoginConnectionProfile.PnP.Connected = $true
                }
                catch
                {
                    $Global:MSCloudLoginConnectionProfile.PnP.Connected = $false
                    throw $_
                }
            }
        }
        elseif ($_.Exception -like '*The sign-in name or password does not match one in the Microsoft account system*')
        {
            # This error means that the account was trying to connect using MFA.
            try
            {
                Write-Verbose 'Trying to acquire AccessToken'
                $AuthHeader = Get-AuthHeader -UserPrincipalName $Global:MSCloudLoginConnectionProfile.PnP.Credentials.UserName `
                    -ResourceURI $Global:MSCloudLoginConnectionProfile.PnP.AdminUrl `
                    -clientId $Global:MSCloudLoginConnectionProfile.PnP.ClientId `
                    -RedirectURI $Global:MSCloudLoginConnectionProfile.PnP.RedirectURI
                $Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl.AccessToken = $AuthHeader.split(' ')[1]

                Write-Verbose "Access Token = $($Global:MSCloudLoginConnectionProfile.PnP.AccessToken)"
                if ($null -ne $Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl.AccessToken)
                {
                    if ($Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl)
                    {
                        Connect-PnPOnline -Url $Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl `
                            -AccessToken $Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl.AccessToken
                    }
                    else
                    {
                        Connect-PnPOnline -Url $Global:MSCloudLoginConnectionProfile.PnP.AdminUrl `
                            -AccessToken $Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl.AccessToken
                    }
                }
                else
                {
                    if ($Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl)
                    {
                        Connect-PnPOnline -Url $Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl `
                            -Interactive
                    }
                    else
                    {
                        Connect-PnPOnline -Url $Global:MSCloudLoginConnectionProfile.PnP.AdminUrl `
                            -Interactive
                    }
                }
                $Global:MSCloudLoginConnectionProfile.PnP.ConnectedDateTime = [System.DateTime]::Now.ToString()
                $Global:MSCloudLoginConnectionProfile.PnP.MultiFactorAuthentication = $true
                $Global:MSCloudLoginConnectionProfile.PnP.Connected = $true
            }
            catch
            {
                Write-Verbose "Error acquiring AccessToken: $($_.Exception.Message)"
                try
                {
                    Connect-PnPOnline -Url $Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl `
                        -Interactive
                    $Global:MSCloudLoginConnectionProfile.PnP.ConnectedDateTime = [System.DateTime]::Now.ToString()
                    $Global:MSCloudLoginConnectionProfile.PnP.MultiFactorAuthentication = $true
                    $Global:MSCloudLoginConnectionProfile.PnP.Connected = $true
                }
                catch
                {
                    $Global:MSCloudLoginConnectionProfile.PnP.Connected = $false
                    throw $_
                }
            }
        }
        elseif ($_.Exception -like '*AADSTS65001: The user or administrator has not consented to use the application with ID*')
        {
            try
            {
                Register-PnPManagementShellAccess
                Connect-PnPOnline -UseWebLogin -Url $Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl
                $Global:MSCloudLoginConnectionProfile.PnP.Connected = $true
                $Global:MSCloudLoginConnectionProfile.PnP.ConnectedDateTime = [System.DateTime]::Now.ToString()
            }
            catch
            {
                throw "The PnP.PowerShell Azure AD Application has not been granted access for this tenant. Please run 'Register-PnPManagementShellAccess' to grant access and try again after."
            }
        }
        else
        {
            $Global:MSCloudLoginConnectionProfile.PnP.connected = $false

            $message = "An error has occurred $($_.Exception.Message)"
            throw $message
        }
    }
    return
}
