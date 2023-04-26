function Connect-MSCloudLoginMicrosoftGraph
{
    [CmdletBinding()]
    param()

    $ProgressPreference = 'SilentlyContinue'
    $WarningPreference = 'SilentlyContinue'
    $VerbosePreference = 'SilentlyContinue'

    # If the current profile is not the same we expect, make the switch.
    $currentProfile = (Get-MgProfile).Name
    Write-Verbose -Message "Current Profile: $currentProfile"
    Write-Verbose -Message "Requested Profile: $($Global:MSCloudLoginConnectionProfile.MicrosoftGraph.ProfileName)"
    if ($Global:MSCloudLoginConnectionProfile.MicrosoftGraph.ProfileName -ne $currentProfile)
    {
        Write-Verbose -Message "There are currently {$((Get-ChildItem function: | Measure-Object).Count) functions}"
        Write-Verbose -Message 'Removing Graph Modules from Runspace'
        Remove-Module Microsoft.Graph.* -Force
        Write-Verbose -Message "There are now {$((Get-ChildItem function: | Measure-Object).Count) functions}"

        Write-Verbose -Message 'Switching to Beta profile'
        Select-MgProfile $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.ProfileName | Out-Null
        Write-Verbose -Message "There are {$((Get-ChildItem function: | Measure-Object).Count) functions}"
        $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.Connected = $false
    }

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
    elseif ($Global:MSCloudLoginConnectionProfile.MicrosoftGraph.AuthenticationType -eq 'Identity')
    {
        Write-Verbose 'Connecting with managed identity'
        # Get correct endopint based on provided environment
        $resourceEndpoint = ($Global:MSCloudLoginConnectionProfile.MicrosoftGraph.ResourceUrl -split '/')[2]
        $oauth2 = Invoke-RestMethod -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2F$($resourceEndpoint)%2F" -Headers @{Metadata = 'true' }
        $accessToken = $oauth2.access_token

        Connect-MgGraph -AccessToken $accessToken `
            -Environment $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.GraphEnvironment
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

                Connect-MgGraph -AccessToken $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.AccessToken | Out-Null
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
    $OAuthReq = Invoke-RestMethod -Uri $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.TokenUrl `
        -Method Post -Body $body

    $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.AccessToken = $OAuthReq.access_token
    $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.ConnectedDateTime = [System.DateTime]::Now.ToString()
    $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.MultiFactorAuthentication = $false
    $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.Connected = $true

    Write-Verbose -Message 'Acquired token for Microsoft Graph'
}

function Connect-MSCloudLoginMSGraphWithUser
{
    [CmdletBinding()]
    Param()

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
        $AccessToken = $OAuthReq.access_token

        Write-Verbose -Message "Connecting to Microsoft Graph - Environment {$($Global:MSCloudLoginConnectionProfile.MicrosoftGraph.GraphEnvironment)}"

        # Domain.Read.All permission Scope is required to get the domain name for the SPO Admin Center.
        $authParams = @{
            AccessToken = $AccessToken
            Environment = $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.GraphEnvironment
        }

        if (-not [System.String]::IsNullOrEmpty($Global:MSCloudLoginConnectionProfile.MicrosoftGraph.TenantId))
        {
            $authParams.Add('TenantId', $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.TenantId)
        }
        Connect-MgGraph @authParams | Out-Null
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
            $authParams = @{
                AccessToken = $AccessToken
            }

            if (-not [System.String]::IsNullOrEmpty($Global:MSCloudLoginConnectionProfile.MicrosoftGraph.TenantId))
            {
                $authParams.Add('TenantId', $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.TenantId)
            }
            Connect-MgGraph @authParams | Out-Null
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

function Invoke-MSCloudLoginMicrosoftGraphAPI
{
    [CmdletBinding()]
    [OutputType([System.String])]
    Param(
        [Parameter(Mandatory = $true)]
        [System.String]
        $Uri,

        [Parameter()]
        [System.String]
        $Body,

        [Parameter()]
        [System.Collections.Hashtable]
        $Headers,

        [Parameter()]
        [System.String]
        $Method,

        [Parameter()]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter()]
        [System.String]
        $ApplicationId,

        [Parameter()]
        [System.UInt32]
        $CallCount = 1
    )
    Connect-MSCloudLoginMSGraphWithUser

    $requestHeaders = @{
        'Authorization' = 'Bearer ' + $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.AccessToken
        'Content-Type'  = 'application/json;charset=utf-8'
    }
    foreach ($key in $Headers.Keys)
    {
        Write-Verbose -Message "    $key = $($requestHeaders.$key)"
        $requestHeaders.Add($key, $Headers.$key)
    }

    Write-Verbose -Message "URI: $Uri"
    Write-Verbose -Message "Method: $Method"
    $requestParams = @{
        Method      = $Method
        Uri         = $Uri
        Headers     = $requestHeaders
        ContentType = 'application/json;charset=utf-8'
    }
    if (-not [System.String]::IsNullOrEmpty($Body))
    {
        $requestParams.Add('Body', $Body)
        Write-Verbose -Message "Body: $Body"
    }

    try
    {
        $Result = Invoke-RestMethod @requestParams
    }
    catch
    {
        Write-Verbose -Message $_
        if ($_.Exception -like '*The remote server returned an error: (401) Unauthorized.*')
        {
            if ($CallCount -eq 1)
            {
                Write-Verbose -Message 'This is the first time the method is called. Wait 10 seconds and retry the call.'
                Start-Sleep -Seconds 10
            }
            else
            {
                $newSleepTime = 10 * $CallCount
                Write-Verbose -Message "The Access Token expired, waiting {$newSleepTime} and then regenerating a new one."
                $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.AccessToken = $null
            }
            $CallCount++
            try
            {
                $PSBoundParameters.Remove('CallCount') | Out-Null
            }
            catch
            {
                Write-Verbose -Message 'CallCount was not already specified.'
            }

            # Check for a max CallCount to prevent call depth issues
            if ($CallCount -ge 12)
            {
                throw $_
            }

            return (Invoke-MSCloudLoginMicrosoftGraphAPI @PSBoundParameters -CallCount $CallCount)
        }
        elseif ($_ -like '*Too many requests*' -and $CallCount -lt 12)
        {
            Write-Host "Too many request, waiting $(10*$callCount) seconds" -ForegroundColor Magenta
            $newSleepTime = 10 * $CallCount
            Start-Sleep -Seconds $newSleepTime
            Invoke-MSCloudLoginMicrosoftGraphAPI -Uri $Uri -Body $Body -Headers $Headers -Method $Method -Credential $Credential `
                -ApplicationId $ApplicationId -CallCount ($CallCount + 1)
        }
        else
        {
            throw $_
        }
    }
    return $result
}
