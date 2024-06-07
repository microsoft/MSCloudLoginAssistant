function Connect-MSCloudLoginMSCommerce
{
    [CmdletBinding()]
    param()

    $ProgressPreference = 'SilentlyContinue'
    $WarningPreference = 'SilentlyContinue'
    $VerbosePreference = 'SilentlyContinue'

    # If the current profile is not the same we expect, make the switch.
    if ($Global:MSCloudLoginConnectionProfile.MSCommerce.Connected)
    {
        if (($Global:MSCloudLoginConnectionProfile.MSCommerce.AuthenticationType -eq 'ServicePrincipalWithSecret' `
                    -or $Global:MSCloudLoginConnectionProfile.MSCommerce.AuthenticationType -eq 'Identity') `
                -and (Get-Date -Date $Global:MSCloudLoginConnectionProfile.MSCommerce.ConnectedDateTime) -lt [System.DateTime]::Now.AddMinutes(-50))
        {
            Write-Verbose -Message 'Token is about to expire, renewing'

            $Global:MSCloudLoginConnectionProfile.MSCommerce.Connected = $false
        }
        elseif ($null -eq (Get-MgContext))
        {
            $Global:MSCloudLoginConnectionProfile.MSCommerce.Connected = $false
        }
        else
        {
            return
        }
    }

    $Global:MSCloudLoginConnectionProfile.MSCommerce.AccessTokens = @()
    $azureCloudInstanceArg = @{}
    if ($this.EnvironmentName)
    {
        $azureCloudInstanceArg.AzureCloudInstance = $this.EnvironmentName
    }

    Import-Module MSCommerce -Global
    #Connect-MSCommerce not used, it provides token-acquisition as below but with next to no options.
    # it is required to call the other MSCommerce-cmdlets/functions with an explicit token:
    # $Global:MSCloudLoginConnectionProfile.MSCommerce.AccessTokens[0]

    if ($Global:MSCloudLoginConnectionProfile.MSCommerce.AuthenticationType -eq 'CredentialsWithApplicationId' -or
        $Global:MSCloudLoginConnectionProfile.MSCommerce.AuthenticationType -eq 'Credentials')
    {
        Write-Verbose -Message 'Will try connecting with user credentials'
        Connect-MSCloudLoginMSCommerceWithUser
    }
    elseif ($Global:MSCloudLoginConnectionProfile.MSCommerce.AuthenticationType -eq 'CredentialsWithTenantId')
    {
        Write-Verbose -Message 'Will try connecting with user credentials and Tenant Id'
        Connect-MSCloudLoginMSCommerceWithUser -TenantId $Global:MSCloudLoginConnectionProfile.MSCommerce.TenantId
    }
    elseif ($Global:MSCloudLoginConnectionProfile.MSCommerce.AuthenticationType -eq 'Identity')
    {
        Write-Verbose 'Connecting with managed identity'

        $resourceEndpoint = ($Global:MSCloudLoginConnectionProfile.MSCommerce.ResourceUrl -split '/')[2]
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

        #$accessToken = $accessToken | ConvertTo-SecureString -AsPlainText -Force

        $Global:MSCloudLoginConnectionProfile.MSCommerce.ConnectedDateTime = [System.DateTime]::Now.ToString()
        $Global:MSCloudLoginConnectionProfile.MSCommerce.MultiFactorAuthentication = $false
        $Global:MSCloudLoginConnectionProfile.MSCommerce.Connected = $true
        $Global:MSCloudLoginConnectionProfile.MSCommerce.AccessTokens += $accessToken
    }
    else
    {
        try
        {
            if ($Global:MSCloudLoginConnectionProfile.MSCommerce.AuthenticationType -eq 'ServicePrincipalWithThumbprint')
            {
                # Get certificate from CurrentUser or Localmachine
                $cert = Get-ChildItem -Path "Cert:\*$($Global:MSCloudLoginConnectionProfile.MSCommerce.CertificateThumbprint)" -Recurse
                $token = Get-MsalToken -ClientId $Global:MSCloudLoginConnectionProfile.ApplicationId `
                    -TenantId $Global:MSCloudLoginConnectionProfile.MSCommerce.TenantId `
                    -Certificate $cert `
                    -Scopes $Global:MSCloudLoginConnectionProfile.MSCommerce.Scope `
                    @azureCloudInstanceArg
                $Global:MSCloudLoginConnectionProfile.MSCommerce.ConnectedDateTime = [System.DateTime]::Now.ToString()
                $Global:MSCloudLoginConnectionProfile.MSCommerce.MultiFactorAuthentication = $false
                $Global:MSCloudLoginConnectionProfile.MSCommerce.Connected = $true
                $Global:MSCloudLoginConnectionProfile.MSCommerce.AccessTokens += $token.AccessToken
            }
            elseif($Global:MSCloudLoginConnectionProfile.MSCommerce.AuthenticationType -eq 'ServicePrincipalWithSecret')
            {
                Write-Verbose -Message 'Connecting to MSCommerce with ApplicationSecret'
                $secStringPassword = ConvertTo-SecureString -String $Global:MSCloudLoginConnectionProfile.MSCommerce.ApplicationSecret -AsPlainText -Force
                #$userName = $Global:MSCloudLoginConnectionProfile.MSCommerce.ApplicationId
                #[pscredential]$credObject = New-Object System.Management.Automation.PSCredential ($userName, $secStringPassword)
                $token = Get-MsalToken -ClientId $Global:MSCloudLoginConnectionProfile.ApplicationId ´
                    -TenantId $Global:MSCloudLoginConnectionProfile.MSCommerce.TenantId `
                    -ClientSecret $secStringPassword
                    -Scopes $Global:MSCloudLoginConnectionProfile.MSCommerce.Scope `
                    @azureCloudInstanceArg
                $Global:MSCloudLoginConnectionProfile.MSCommerce.ConnectedDateTime = [System.DateTime]::Now.ToString()
                $Global:MSCloudLoginConnectionProfile.MSCommerce.MultiFactorAuthentication = $false
                $Global:MSCloudLoginConnectionProfile.MSCommerce.Connected = $true
                $Global:MSCloudLoginConnectionProfile.MSCommerce.AccessTokens += $token.AccessToken
            }
            elseif($Global:MSCloudLoginConnectionProfile.MSCommerce.AuthenticationType -eq 'AccessToken')
            {
                Write-Verbose -Message 'Connecting to MSCommerce with AccessToken'
                $Global:MSCloudLoginConnectionProfile.MSCommerce.ConnectedDateTime = [System.DateTime]::Now.ToString()
                $Global:MSCloudLoginConnectionProfile.MSCommerce.MultiFactorAuthentication = $false
                $Global:MSCloudLoginConnectionProfile.MSCommerce.Connected = $true
                $Global:MSCloudLoginConnectionProfile.MSCommerce.TenantId = (Get-JWTPayload -AccessToken $Global:MSCloudLoginConnectionProfile.MSCommerce.AccessTokens[0]).tid
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

function Connect-MSCloudLoginMSCommerceWithUser
{
    [CmdletBinding()]

    <# initial attempt. Doesn't fly
    $sessionState = $PSCmdlet.SessionState
    $msCommerceToken = $sessionState.PSVariable.GetValue('token')
    if ($null -ne $msCommerceToken)
    {
        # decode JWT to enable identifying authenticated user
        $tokenPayload = Get-JWTPayload -AccessToken $msCommerceToken
    }
    if ($null -ne $msCommerceToken -and  $Global:MSCloudLoginConnectionProfile.MSCommerce.Credentials.UserName -ne $tokenPayLoad.upn)
    {
        Write-Verbose -Message "The current account that is connected doesn't match the one we're trying to authenticate with."
    }
    #>

    try
    {
        #Connect-MSCommerce # won't work - DSC-resource expects token to be stored in $Global:MSCloudLoginConnectionProfile.MSCommerce.AccessTokens[0]

        $token = Get-MsalToken -ClientId '3d5cffa9-04da-4657-8cab-c7f074657cad' `
        -UserCredential $Global:MSCloudLoginConnectionProfile.MSCommerce.Credentials `
        -RedirectUri 'http://localhost/m365/commerce' `
        -Scopes $Global:MSCloudLoginConnectionProfile.MSCommerce.Scope `
        @azureCloudInstanceArg

        $Global:MSCloudLoginConnectionProfile.MSCommerce.ConnectedDateTime = [System.DateTime]::Now.ToString()
        $Global:MSCloudLoginConnectionProfile.MSCommerce.MultiFactorAuthentication = $true
        $Global:MSCloudLoginConnectionProfile.MSCommerce.Connected = $true
        $Global:MSCloudLoginConnectionProfile.MSCommerce.AccessTokens += $token.AccessToken
    }
    catch
    {
        if ($_.Exception -like 'System.Net.WebException: The remote server returned an error: (400) Bad Request.*' -and `
            (Assert-IsNonInteractiveShell) -eq $true)
        {
            $warningPref = $WarningPreference
            $WarningPreference = 'Continue'
            Write-Warning -Message "Unable to retrieve AccessToken. Have you registered the 'M365 License Manager' application already? Please run 'Connect-MSCommerce' and logon using '$($Global:MSCloudLoginConnectionProfile.MSCommerce.Credentials.Username)'"
            $WarningPreference = $warningPref
            return
        }
        else
        {
            throw "Terminating error connecting to MSCommerce: $($_.Eception.Message)"
        }
    }
}
