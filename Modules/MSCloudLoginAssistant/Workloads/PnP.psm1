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

    if ($psversiontable.PSVersion.Major -ge 7)
    {
        try
        {
            Get-PnPAlert -ErrorAction 'Stop' | Out-Null
            Write-Verbose -Message "Retrieved results from the command. Not re-connecting to PnP."
            $Global:MSCloudLoginConnectionProfile.PnP.Connected = $true
            return
        }
        catch
        {
            Write-Verbose -Message "Couldn't get results back from the command"
            Write-Verbose -Message "Using PowerShell 7 or above. Loading the PnP.PowerShell module using Windows PowerShell."
            if ($psversiontable.PSVersion.Major -ge 7)
            {
                Import-Module PnP.PowerShell -UseWindowsPowerShell -Global -Force | Out-Null
            }
        }
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
                $Global:MSCloudLoginConnectionProfile.PnP.AdminUrl      = Get-SPOAdminUrl -Credential $Global:MSCloudLoginConnectionProfile.PnP.Credentials
                $Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl = $Global:MSCloudLoginConnectionProfile.PnP.AdminUrl
            }
            else
            {
                if ($Global:MSCloudLoginConnectionProfile.PnP.TenantId.Contains("onmicrosoft"))
                {
                    $domain = $Global:MSCloudLoginConnectionProfile.PnP.TenantId.Replace(".onmicrosoft.", "-admin.sharepoint.")
                    if (-not $Global:MSCloudLoginConnectionProfile.PnP.AdminUrl)
                    {
                        $Global:MSCloudLoginConnectionProfile.PnP.AdminUrl = "https://$domain"
                    }
                    $Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl = "https://$domain"
                }
                else
                {
                    throw "TenantId must be in format contoso.onmicrosoft.com"
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
        if ($Global:MSCloudLoginConnectionProfile.PnP.AuthenticationType -eq 'ServicePrincipalWithThumbprint')
        {
            if (-not $Url)
            {
                Write-Information -Message "Connecting with Service Principal - Thumbprint"
                Write-Information -Message "URL: $Url"
                Write-Information -Message "ConnectionUrl: $($Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl)"
                Connect-PnPOnline -Url $Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl `
                    -ClientId $Global:MSCloudLoginConnectionProfile.PnP.ApplicationId `
                    -Tenant $Global:MSCloudLoginConnectionProfile.PnP.TenantId `
                    -Thumbprint $Global:MSCloudLoginConnectionProfile.PnP.CertificateThumbprint `
                    -AzureEnvironment $Global:MSCloudLoginConnectionProfile.PnP.PnPAzureEnvironment | Out-Null
            }
            elseif ($Global:MSCloudLoginConnectionProfile.PnP.AdminUrl)
            {
                Write-Information -Message "Connecting with Service Principal - Thumbprint"
                Write-Information -Message "URL: $Url"
                Write-Information -Message "AdminUrl: $($Global:MSCloudLoginConnectionProfile.PnP.AdminUrl)"
                Connect-PnPOnline -Url $Global:MSCloudLoginConnectionProfile.PnP.AdminUrl `
                    -ClientId $Global:MSCloudLoginConnectionProfile.PnP.ApplicationId `
                    -Tenant $Global:MSCloudLoginConnectionProfile.PnP.TenantId `
                    -Thumbprint $Global:MSCloudLoginConnectionProfile.PnP.CertificateThumbprint `
                    -AzureEnvironment $Global:MSCloudLoginConnectionProfile.PnP.PnPAzureEnvironment | Out-Null
            }

            $Global:MSCloudLoginConnectionProfile.PnP.ConnectedDateTime         = [System.DateTime]::Now.ToString()
            $Global:MSCloudLoginConnectionProfile.PnP.MultiFactorAuthentication = $false
            $Global:MSCloudLoginConnectionProfile.PnP.Connected                 = $true
        }
        elseif ($Global:MSCloudLoginConnectionProfile.PnP.AuthenticationType -eq 'ServicePrincipalWithPath')
        {
            if ($Url)
            {
                Write-Information -Message "Connecting with Service Principal - Path"
                Write-Information -Message "URL: $Url"
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
                Write-Information -Message "Connecting with Service Principal - Path"
                Write-Information -Message "URL: $Url"
                Write-Information -Message "AdminUrl: $($Global:MSCloudLoginConnectionProfile.PnP.AdminUrl)"
                Connect-PnPOnline -Url $Global:MSCloudLoginConnectionProfile.PnP.AdminUrl `
                    -ClientId $Global:MSCloudLoginConnectionProfile.PnP.ApplicationId `
                    -Tenant $Global:MSCloudLoginConnectionProfile.PnP.TenantId `
                    -CertificatePassword $Global:MSCloudLoginConnectionProfile.PnP.CertificatePassword `
                    -CertificatePath $Global:MSCloudLoginConnectionProfile.PnP.CertificatePath `
                    -AzureEnvironment $Global:MSCloudLoginConnectionProfile.PnP.PnPAzureEnvironment
            }

            $Global:MSCloudLoginConnectionProfile.PnP.ConnectedDateTime         = [System.DateTime]::Now.ToString()
            $Global:MSCloudLoginConnectionProfile.PnP.MultiFactorAuthentication = $false
            $Global:MSCloudLoginConnectionProfile.PnP.Connected                 = $true
        }
        elseif ($Global:MSCloudLoginConnectionProfile.PnP.AuthenticationType -eq 'ServicePrincipalWithSecret')
        {
            if ($Url)
            {
                Write-Information -Message "Connecting with Service Principal - Secret"
                Write-Information -Message "URL: $Url"
                Write-Information -Message "ConnectionUrl: $($Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl)"
                Connect-PnPOnline -Url $Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl `
                    -ClientId $Global:MSCloudLoginConnectionProfile.PnP.ApplicationId `
                    -ClientSecret $Global:MSCloudLoginConnectionProfile.PnP.ApplicationSecret `
                    -AzureEnvironment $Global:MSCloudLoginConnectionProfile.PnP.PnPAzureEnvironment `
                    -WarningAction 'Ignore'
            }
            else
            {
                Write-Information -Message "Connecting with Service Principal - Secret"
                Write-Information -Message "URL: $Url"
                Write-Information -Message "AdminUrl: $($Global:MSCloudLoginConnectionProfile.PnP.AdminUrl)"
                Connect-PnPOnline -Url $Global:MSCloudLoginConnectionProfile.PnP.AdminUrl `
                    -ClientId $Global:MSCloudLoginConnectionProfile.PnP.ApplicationId `
                    -ClientSecret $Global:MSCloudLoginConnectionProfile.PnP.ApplicationSecret `
                    -AzureEnvironment $Global:MSCloudLoginConnectionProfile.PnP.PnPAzureEnvironment `
                    -WarningAction 'Ignore'
            }
            $Global:MSCloudLoginConnectionProfile.PnP.ConnectedDateTime         = [System.DateTime]::Now.ToString()
            $Global:MSCloudLoginConnectionProfile.PnP.MultiFactorAuthentication = $false
            $Global:MSCloudLoginConnectionProfile.PnP.Connected                 = $true
        }
        elseif ($Global:MSCloudLoginConnectionProfile.PnP.AuthenticationType -eq 'Credentials')
        {
            if ($Url)
            {
                Write-Information -Message "Connecting with Credentials"
                Write-Information -Message "URL: $Url"
                Write-Information -Message "ConnectionUrl: $($Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl)"
                Connect-PnPOnline -Url $Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl `
                    -Credentials $Global:MSCloudLoginConnectionProfile.PnP.Credentials `
                    -AzureEnvironment $Global:MSCloudLoginConnectionProfile.PnP.PnPAzureEnvironment
            }
            else
            {
                Write-Information -Message "Connecting with Credentials"
                Write-Information -Message "URL: $Url"
                Write-Information -Message "AdminUrl: $($Global:MSCloudLoginConnectionProfile.PnP.AdminUrl)"
                Connect-PnPOnline -Url $Global:MSCloudLoginConnectionProfile.PnP.AdminUrl `
                    -Credentials $Global:MSCloudLoginConnectionProfile.PnP.Credentials `
                    -AzureEnvironment $Global:MSCloudLoginConnectionProfile.PnP.PnPAzureEnvironment
            }

            $Global:MSCloudLoginConnectionProfile.PnP.ConnectedDateTime         = [System.DateTime]::Now.ToString()
            $Global:MSCloudLoginConnectionProfile.PnP.MultiFactorAuthentication = $false
            $Global:MSCloudLoginConnectionProfile.PnP.Connected                 = $true
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
                $Global:MSCloudLoginConnectionProfile.PnP.ConnectedDateTime         = [System.DateTime]::Now.ToString()
                $Global:MSCloudLoginConnectionProfile.PnP.MultiFactorAuthentication = $true
                $Global:MSCloudLoginConnectionProfile.PnP.Connected                 = $true
            }
            catch
            {
                try
                {
                    Connect-PnPOnline -Url $Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl -UseWebLogin
                    $Global:MSCloudLoginConnectionProfile.PnP.ConnectedDateTime         = [System.DateTime]::Now.ToString()
                    $Global:MSCloudLoginConnectionProfile.PnP.MultiFactorAuthentication = $true
                    $Global:MSCloudLoginConnectionProfile.PnP.Connected                 = $true
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
                Write-Verbose "Trying to acquire AccessToken"
                $AuthHeader = Get-AuthHeader -UserPrincipalName $Global:MSCloudLoginConnectionProfile.PnP.Credentials.UserName `
                    -ResourceURI $Global:MSCloudLoginConnectionProfile.PnP.AdminUrl `
                    -clientID $Global:MSCloudLoginConnectionProfile.PnP.ClientId `
                    -RedirectURI $Global:MSCloudLoginConnectionProfile.PnP.RedirectURI
                $Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl.AccessToken = $AuthHeader.split(" ")[1]

                Write-Verbose "Access Token = $($Global:MSCloudLoginConnectionProfile.PnP.AccessToken)"
                if ($null -ne $Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl.AccessToken)
                {
                    if ($Url)
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
                    if ($Url)
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
                $Global:MSCloudLoginConnectionProfile.PnP.ConnectedDateTime         = [System.DateTime]::Now.ToString()
                $Global:MSCloudLoginConnectionProfile.PnP.MultiFactorAuthentication = $true
                $Global:MSCloudLoginConnectionProfile.PnP.Connected                 = $true
            }
            catch
            {
                Write-Verbose "Error acquiring AccessToken: $($_.Exception.Message)"
                try
                {
                    Connect-PnPOnline -Url $Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl `
                        -Interactive
                    $Global:MSCloudLoginConnectionProfile.PnP.ConnectedDateTime         = [System.DateTime]::Now.ToString()
                    $Global:MSCloudLoginConnectionProfile.PnP.MultiFactorAuthentication = $true
                    $Global:MSCloudLoginConnectionProfile.PnP.Connected                 = $true
                }
                catch
                {
                    $Global:MSCloudLoginConnectionProfile.PnP.Connected = $false
                    throw $_
                }
            }
        }
        elseif ($_.Exception -like "*AADSTS65001: The user or administrator has not consented to use the application with ID*")
        {
            try
            {
                Register-PnPManagementShellAccess
                Connect-PnPOnline -UseWebLogin -Url $Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl
                $Global:MSCloudLoginConnectionProfile.PnP.Connected                 = $true
                $Global:MSCloudLoginConnectionProfile.PnP.ConnectedDateTime         = [System.DateTime]::Now.ToString()
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
