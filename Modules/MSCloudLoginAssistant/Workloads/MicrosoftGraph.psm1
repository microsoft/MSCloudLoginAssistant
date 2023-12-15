function Connect-MSCloudLoginMicrosoftGraph
{
    [CmdletBinding()]
    param()

    $ProgressPreference = 'SilentlyContinue'
    $WarningPreference = 'SilentlyContinue'
    $VerbosePreference = 'SilentlyContinue'

    # If the current profile is not the same we expect, make the switch.
    if ($Global:MSCloudLoginConnectionProfile.MicrosoftGraph.Connected)
    {
        if (($Global:MSCloudLoginConnectionProfile.MicrosoftGraph.AuthenticationType -eq 'ServicePrincipalWithSecret' `
                    -or $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.AuthenticationType -eq 'Identity') `
                -and (Get-Date -Date $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.ConnectedDateTime) -lt [System.DateTime]::Now.AddMinutes(-50))
        {
            Write-Verbose -Message 'Token is about to expire, renewing'

            $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.Connected = $false
        }
        elseif ($null -eq (Get-MgContext))
        {
            $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.Connected = $false
        }
        else
        {
            return
        }
    }

    if ($Global:MSCloudLoginConnectionProfile.MicrosoftGraph.AuthenticationType -eq 'CredentialsWithApplicationId' -or
        $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.AuthenticationType -eq 'Credentials')
    {
        Write-Verbose -Message 'Will try connecting with user credentials'
        Connect-MSCloudLoginMSGraphWithUser
    }
    elseif ($Global:MSCloudLoginConnectionProfile.MicrosoftGraph.AuthenticationType -eq 'CredentialsWithTenantId')
    {
        Write-Verbose -Message 'Will try connecting with user credentials and Tenant Id'
        Connect-MSCloudLoginMSGraphWithUser -TenantId $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.TenantId
    }
    elseif ($Global:MSCloudLoginConnectionProfile.MicrosoftGraph.AuthenticationType -eq 'Identity')
    {
        Write-Verbose 'Connecting with managed identity'

        $resourceEndpoint = ($Global:MSCloudLoginConnectionProfile.MicrosoftGraph.ResourceUrl -split '/')[2]
        if ('AzureAutomation/' -eq $env:AZUREPS_HOST_ENVIRONMENT)
        {
            $url = $env:IDENTITY_ENDPOINT
            $headers = New-Object 'System.Collections.Generic.Dictionary[[String],[String]]'
            $headers.Add('X-IDENTITY-HEADER', $env:IDENTITY_HEADER)
            $headers.Add('Metadata', 'True')
            $body = @{resource = "https://$resourceEndPoint/" }
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
            $oauth2 = Invoke-RestMethod -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2F$($resourceEndpoint)%2F" -Headers @{Metadata = 'true' }
            $accessToken = $oauth2.access_token

        }

        $accessToken = $accessToken | ConvertTo-SecureString -AsPlainText -Force
        Connect-MgGraph -AccessToken $accessToken -Environment $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.GraphEnvironment
        $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.ConnectedDateTime = [System.DateTime]::Now.ToString()
        $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.MultiFactorAuthentication = $false
        $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.Connected = $true
        $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.TenantId = (Get-MgContext).TenantId
    }
    else
    {
        try
        {
            if ($Global:MSCloudLoginConnectionProfile.MicrosoftGraph.AuthenticationType -eq 'ServicePrincipalWithThumbprint')
            {
                try
                {
                    Connect-MgGraph -ClientId $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.ApplicationId `
                        -TenantId $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.TenantId `
                        -CertificateThumbprint $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.CertificateThumbprint `
                        -Environment $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.GraphEnvironment `
                        -ErrorAction Stop | Out-Null
                }
                catch
                {
                    # Check into the localmachine store
                    $cert = Get-ChildItem "Cert:\LocalMachine\My\$($Global:MSCloudLoginConnectionProfile.MicrosoftGraph.CertificateThumbprint)"
                    Connect-MgGraph -ClientId $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.ApplicationId `
                        -TenantId $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.TenantId `
                        -Environment $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.GraphEnvironment `
                        -Certificate $cert | Out-Null
                }
                $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.ConnectedDateTime = [System.DateTime]::Now.ToString()
                $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.MultiFactorAuthentication = $false
                $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.Connected = $true
            }
            else
            {
                Request-MSGraphOauthToken

                Write-Verbose -Message 'Connecting to Microsoft Graph'
                try
                {
                    Connect-MgGraph -AccessToken $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.AccessToken | Out-Null
                }
                catch
                {
                    throw $_
                }

                $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.ConnectedDateTime = [System.DateTime]::Now.ToString()
                $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.MultiFactorAuthentication = $false
                $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.Connected = $true
            }

            Write-Verbose -Message 'Connected'
        }
        catch
        {
            Write-Verbose -Message $_
            throw $_
        }
    }
}

function Request-MSGraphOauthToken
{
    [CmdletBinding()]
    Param(
    )

    $body = @{
        client_id     = $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.ApplicationId
        client_secret = $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.ApplicationSecret
        client_info   = 1
        scope         = $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.Scope
        grant_type    = 'client_credentials'
    }

    Write-Verbose -Message 'Requesting Access Token for Microsoft Graph'
    try
    {
        $OAuthReq = Invoke-RestMethod -Uri $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.TokenUrl `
            -Method Post -Body $body
    }
    catch
    {
        throw $_
    }

    if (![String]::IsNullOrEmpty($OAuthReq.access_token))
    {
        $secureOAuth = ConvertTo-SecureString $OAuthReq.access_token -AsPlainText -Force
        $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.AccessToken = $secureOAuth
        Write-Verbose -Message 'Acquired token for Microsoft Graph'
    }
    else
    {
        $Message = 'Could not acquire token to connect to Microsoft Graph, aborting'
        Write-Verbose -Message $Message
        throw $Message
    }
}

function Connect-MSCloudLoginMSGraphWithUser
{
    [CmdletBinding()]
    Param(
        [Parameter()]
        [System.String]
        $TenantId
    )

    if ($Global:MSCloudLoginConnectionProfile.MicrosoftGraph.Credentials.UserName -ne (Get-MgContext).Account)
    {
        Write-Verbose -Message "The current account that is connect doesn't match the one we're trying to authenticate with. Disconnecting from Graph."
        try
        {
            Disconnect-MgGraph -ErrorAction Stop | Out-Null
        }
        catch
        {
            Write-Verbose -Message 'No connections to Microsoft Graph were found.'
        }
    }

    if ([System.String]::IsNullOrEmpty($Global:MSCloudLoginConnectionProfile.MicrosoftGraph.ApplicationId))
    {
        $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.ApplicationId = '14d82eec-204b-4c2f-b7e8-296a70dab67e'
    }

    $TenantId = $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.Credentials.Username.Split('@')[1]
    $url = $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.TokenUrl
    $body = @{
        scope      = $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.Scope
        grant_type = 'password'
        username   = $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.Credentials.Username
        password   = $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.Credentials.GetNetworkCredential().Password
        client_id  = $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.ApplicationId
    }
    Write-Verbose -Message 'Requesting Access Token for Microsoft Graph'

    try
    {
        $OAuthReq = Invoke-RestMethod -Uri $url -Method Post -Body $body
        $AccessToken = ConvertTo-SecureString $OAuthReq.access_token -AsPlainText -Force

        Write-Verbose -Message "Connecting to Microsoft Graph - Environment {$($Global:MSCloudLoginConnectionProfile.MicrosoftGraph.GraphEnvironment)}"

        # Domain.Read.All permission Scope is required to get the domain name for the SPO Admin Center.
        if ([System.String]::IsNullOrEmpty($Global:MSCloudLoginConnectionProfile.MicrosoftGraph.TenantId))
        {
            Connect-MgGraph -AccessToken $AccessToken `
                -Environment $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.GraphEnvironment | Out-Null
        }
        else
        {
            Connect-MgGraph -AccessToken $AccessToken `
                -TenantId $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.TenantId `
                -Environment $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.GraphEnvironment | Out-Null
        }
        $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.ConnectedDateTime = [System.DateTime]::Now.ToString()
        $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.MultiFactorAuthentication = $false
        $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.Connected = $true
        $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.AccessToken = $AccessToken
    }
    catch
    {
        if ($_.Exception -like 'System.Net.WebException: The remote server returned an error: (400) Bad Request.*' -and `
            (Assert-IsNonInteractiveShell) -eq $true)
        {
            $warningPref = $WarningPreference
            $WarningPreference = 'Continue'
            Write-Warning -Message "Unable to retrieve AccessToken. Have you registered the 'Microsoft Graph PowerShell' application already? Please run 'Connect-MgGraph -Scopes Domain.Read.All' and logon using '$($Global:MSCloudLoginConnectionProfile.MicrosoftGraph.Credentials.Username)'"
            $WarningPreference = $warningPref
            return
        }

        try
        {
            Write-Verbose -Message 'Attempting to connect without specifying the Environment'
            Connect-MgGraph -AccessToken $AccessToken | Out-Null
            $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.ConnectedDateTime = [System.DateTime]::Now.ToString()
            $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.MultiFactorAuthentication = $false
            $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.Connected = $true
            $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.AccessToken = $AccessToken
        }
        catch
        {
            Write-Verbose -Message "Error connecting - $_"
            Write-Verbose -Message 'Connecting to Microsoft Graph interactively'

            try
            {
                Connect-MgGraph -Environment $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.GraphEnvironment `
                    -TenantId $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.TenantId `
                    -ClientId $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.ApplicationId `
                    -Scopes 'Domain.Read.All' -ErrorAction 'Stop' | Out-Null
                $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.Connected = $true
            }
            catch
            {
                $err = $_
                if ($err -like '*\.graph\GraphContext.json*')
                {
                    $pathStart = $err.ToString().IndexOf("to file at '", 0) + 12
                    $pathEnd = $err.ToString().IndexOf("'", $pathStart)
                    $path = $err.ToString().Substring($pathStart, $pathEnd - $pathStart)

                    New-Item $path -Force | Out-Null
                    Connect-MgGraph -Environment $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.GraphEnvironment `
                        -TenantId $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.TenantId `
                        -ClientId $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.ApplicationId `
                        -Scopes 'Domain.Read.All' | Out-Null
                    $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.Connected = $true
                }

                if ($err.Exception.Message -eq 'Device code terminal timed-out after 120 seconds. Please try again.')
                {
                    throw 'Unable to connect to the Microsoft Graph. Please make sure the app permissions are setup correctly. Please run Update-M365DSCAllowedGraphScopes.'
                }
            }
        }
    }
}
