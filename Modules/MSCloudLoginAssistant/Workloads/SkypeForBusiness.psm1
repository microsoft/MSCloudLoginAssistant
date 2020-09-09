function Connect-MSCloudLoginSkypeForBusiness
{
    [CmdletBinding()]
    param(
        [Parameter()]
        [System.String]
        $Prefix
    )
    if ($null -eq $Global:SfBOAccessToken)
    {
        if ($null -eq $Global:o365Credential)
        {
            $Global:o365Credential = Get-Credential -Message "Cloud Credential"
        }
        if ($Global:o365Credential.UserName.Split('@')[1] -like '*.de')
        {
            $Global:CloudEnvironment = 'Germany'
            Write-Warning 'Microsoft Teams is not supported in the Germany Cloud'
            return
        }
    }

    try
    {
        if ($null -eq $Global:SkypeModule -and $null -eq (Get-Command Get-CsTeamsClientConfiguration -EA SilentlyContinue))
        {
            Write-Verbose -Message "Creating a new Session to Skype for Business Servers"
            $ErrorActionPreference = "Stop"

            if ($null -eq $Global:SfBOAccessToken)
            {
                $adminDomain = $Global:o365Credential.UserName.Split('@')[1]

                if (-not $adminDomain.ToLower().EndsWith(".onmicrosoft.com"))
                {
                    Connect-MSCloudLoginAzureAD
                    [array]$domains = Get-AzureADDomain | Where-Object -FilterScript {$_.Name -like '*.onmicrosoft.com'}
                    $adminDomain = $domains[0].Name
                }
                $targetUri = Get-SkypeForBusinessServiceEndpoint -TargetDomain $adminDomain
                $appAuthInfo = Get-SkypeForBusinessAccessInfo -PowerShellEndpointUri $targetUri

                $clientId = $appAuthInfo.ClientID
                $authUri = $appAuthInfo.AuthUrl

                $Global:SfBODomain = $adminDomain
                $Global:SfBOTargetUri = $targetUri
            }
            try
            {
                if ($null -eq $Global:SfBOAccessToken)
                {
                    $AccessToken = Get-AccessToken -TargetUri $targetUri -ClientID $clientId `
                        -AuthUri $authUri `
                        -Credentials $Global:o365Credential
                    $Global:SfBOAccessToken = $AccessToken
                }
                else
                {
                    $AccessToken = $Global:SfBOAccessToken
                }
                Write-Verbose -Message "AccessToken = $AccessToken"
                $networkCreds = [System.Net.NetworkCredential]::new("", $AccessToken)
                $secPassword = $networkCreds.SecurePassword
                $user = "oauth"
                $cred = [System.Management.Automation.PSCredential]::new($user, $secPassword)
            }
            catch
            {
                Write-Verbose -Message "An error occured trying to get the access token."
                throw $_
            }

            $queryStr = "AdminDomain=$($Global:SfBODomain)"

            $ConnectionUri = [UriBuilder]$Global:SfBOTargetUri
            $ConnectionUri.Query = $queryStr

            $psSessionName = "SfBPowerShellSession"
            $ConnectorVersion = "7.0.2374.2"
            $SessionOption = New-PSSessionOption
            $SessionOption.ApplicationArguments = @{ }
            $SessionOption.ApplicationArguments['X-MS-Client-Version'] = $ConnectorVersion
            $SessionOption.NoMachineProfile = $true
            $Global:SkypeSession = New-PSSession -Name $psSessionName -ConnectionUri $ConnectionUri.Uri `
                -Credential $cred -Authentication Basic -SessionOption $SessionOption
            $Global:SkypeModule = Import-PSSession $Global:SkypeSession
            $IPMOParameters = @{}
            if ($PSBoundParameters.containskey("Prefix"))
            {
                $IPMOParameters.add("Prefix",$prefix)
            }
            Import-Module $Global:SkypeModule -Global @IPMOParameters | Out-Null
        }
        else
        {
            Write-Verbose "Session to Skype For Business Servers already existed"
        }
        return
    }
    catch
    {
        if ($_.Exception -like '*Connecting to remote server*')
        {
            Write-Host $_
            Write-Verbose -Message "The connection requires MFA. Attempting to connect with Multi-Factor."
            $adminDomain = $Global:o365Credential.UserName.Split('@')[1]
            $targetUri = Get-SkypeForBusinessServiceEndpoint -TargetDomain $adminDomain
            $RedirectURI = "urn:ietf:wg:oauth:2.0:oob";
            $clientId = '1950a258-227b-4e31-a9cf-717495945fc2'
            $Global:ADALServicePoint = New-ADALServiceInfo -TenantName $adminDomain -UserPrincipalName $Global:o365Credential.UserName
            $authResult = $null
            try
            {
                $authResult = $Global:ADALServicePoint.authContext.AcquireTokenAsync($targetUri.OriginalString, $clientId, [Uri]$RedirectURI, $Global:ADALServicePoint.platformParam.PromptBehavior, $Global:ADALServicePoint.userId, "", "")
            }
            catch
            {
                $authResult = $Global:ADALServicePoint.authContext.AcquireTokenAsync($targetUri.OriginalString, $clientId, [Uri]$RedirectURI, $Global:ADALServicePoint.platformParam, $Global:ADALServicePoint.userId)
            }

            $token = $authResult.result.AccessToken
            $networkCreds = [System.Net.NetworkCredential]::new("", $token)
            $secPassword = $networkCreds.SecurePassword
            $user = "oauth"
            $cred = [System.Management.Automation.PSCredential]::new($user, $secPassword)
            $queryStr = "AdminDomain=$adminDomain"

            $ConnectionUri = [UriBuilder]$targetUri
            $ConnectionUri.Query = $queryStr

            $psSessionName = "SfBPowerShellSession"
            $ConnectorVersion = "7.0.2374.2"
            $SessionOption = New-PSSessionOption
            $SessionOption.ApplicationArguments = @{ }
            $SessionOption.ApplicationArguments['X-MS-Client-Version'] = $ConnectorVersion
            $SessionOption.NoMachineProfile = $true
            $Global:SkypeSession = New-PSSession -Name $psSessionName -ConnectionUri $ConnectionUri.Uri `
                -Credential $cred -Authentication Basic -SessionOption $SessionOption
            $Global:SkypeModule = Import-PSSession $Global:SkypeSession
            $IPMOParameters = @{}
            if ($PSBoundParameters.containskey("Prefix"))
            {
                $IPMOParameters.add("Prefix",$prefix)
            }
            Import-Module $Global:SkypeModule -Global @IPMOParameters | Out-Null
        }
        else
        {
            Write-Error $_
            throw $_
        }
    }
}

function Get-MSCloudLoginSfBOAccessToken
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.String]
        $ApplicationId,

        [Parameter(Mandatory = $true)]
        [System.String]
        $TenantId
    )

    $redirectUri = 'https://Microsoft365DSC.com';
    $resourceName = Get-SkypeForBusinessServiceEndpoint -TargetDomain $TenantId

    $url = 'https://login.microsoftonline.com/common/oauth2/authorize?';
    $url += 'response_type=token';
    $url += '&client_id=' + $ApplicationId;
    $url += '&redirect_uri=' + $redirectUri;
    $url += '&resource=' + $resourceName;

    $ie = New-Object -com internetexplorer.application;
    $ie.visible = $true;
    $ie.navigate($url);

    while ($ie.LocationUrl -notlike "*#access_token=*"){}

    $start = $ie.LocationUrl.ToString().IndexOf("#access_token=", 0) + 14
    $end = $ie.LocationUrl.ToString().IndexOf("&token_type", $start)
    $Global:SfBOAccessToken = $ie.LocationUrl.ToString().Substring($start, $end-$start)
    $ie.Quit()
}

function Get-MSCloudLoginSfBOAccessTokenDelegated
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.String]
        $ApplicationId,

        [Parameter(Mandatory = $true)]
        [System.String]
        $TenantId,

        [Parameter(Mandatory = $true)]
        [System.String]
        $ClientSecret,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $Credentials
    )
    $Global:SfBODomain = $TenantId
    $Global:SFBOTargetUri = Get-SkypeForBusinessServiceEndpoint -TargetDomain $Global:SfBODomain
    $url = "https://login.microsoftonline.com/$($Global:SfBODomain)/oauth2/token"
    $body = "client_id=$ApplicationId&client_secret=$ClientSecret&grant_type=password&resource=$($Global:SfBOTargetUri)&username=$($Credentials.Username)&password=$($Credentials.GetNetworkCredential().Password)&scope=user_impersonation"
    $response = Invoke-RestMethod -Method POST -Uri $url -Body $body
    $Global:SfBOAccessToken = $response.access_token
}

function Get-SkypeForBusinessAccessInfo
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Uri]
        $PowerShellEndpointUri
    )

    try
    {
        $response = [System.Net.HttpWebResponse] ([System.Net.HttpWebRequest] [System.Net.WebRequest]::Create($PowerShellEndpointUri)).GetResponse();
    }
    catch [System.Net.WebException]
    {
        $response = ([System.Net.WebException]$_.Exception).Response
    }
    $header = $response.Headers["WWW-Authenticate"]

    # Get ClientID
    $start = $header.IndexOf("client_id=") + 11
    $end = $header.IndexOf("`"", $start)

    $clientId = $null
    if ($end -gt $start)
    {
        $clientId = $header.Substring($start, $end - $start)
    }

    # Get Auth Url
    $start = $header.IndexOf("authorization_uri=") + 19
    $end = $header.IndexOf("`"", $start)

    $authUrl = $null
    if ($end -gt $start)
    {
        $authUrl = $header.Substring($start, $end - $start)
    }

    $result = @{
        ClientID = $clientId
        AuthUrl  = $authUrl
    }
    return $result
}

function Get-SkypeForBusinessServiceEndpoint
{
    [CmdletBinding()]
    [OutputType([Uri])]
    param(
        [Parameter(Mandatory = $true)]
        [System.String]
        $TargetDomain
    )
    $overrideDiscoveryUri = "http://lyncdiscover." + $TargetDomain;
    $desiredLink = "External/RemotePowerShell";
    $liveIdUrl = $overrideDiscoveryUri.ToString() + "?Domain=" + $TargetDomain

    $xml = Get-RTCXml -Url $liveIdUrl
    $root = $xml.AutodiscoverResponse.Root

    $domain = $root.Link | Where-Object -FilterScript { $_.Token -eq 'domain' }
    if ($null -eq $domain)
    {
        $redirect = $root.Link | Where-Object -FilterScript { $_.Token -eq 'redirect' }

        if ($null -eq $redirect)
        {
            throw "Could not properly retrieve the Skype for Business service endpoint for $TargetDomain"
        }

        while ($null -ne $redirect)
        {
            $xml = Get-RTCXml -Url $redirect.href
            $root = $xml.AutodiscoverResponse.Root
            $domain = $root.Link | Where-Object -FilterScript { $_.Token -eq 'domain' }
            if ($null -eq $domain)
            {
                $redirect = $root.Link | Where-Object -FilterScript { $_.Token -eq 'redirect' }
            }
            else
            {
                $redirect = $null
            }
        }
    }
    else
    {
        throw "Could not identify the Domain for target {$TargetDomain}"
    }
    $xml = Get-RTCXml -Url $domain.href
    $endpoint = $xml.AutodiscoverResponse.Domain.Link | Where-Object -FilterScript { $_.token -eq $desiredLink }
    $endpointUrl = $endpoint.href.Replace("/OcsPowershellLiveId", "/OcsPowershellOAuth")
    return [Uri]::new($endpointUrl)
}

function Get-RTCXml
{
    [CmdletBinding()]
    [OutputType([Xml])]
    param(
        [Parameter(Mandatory = $true)]
        [System.String]
        $Url
    )

    $request = [System.Net.WebRequest]::Create($Url);
    $request.set_Accept("application/vnd.microsoft.rtc.autodiscover+xml;v=1");
    $response = $request.GetResponse()
    $arg = [System.IO.StreamReader]::new($response.GetResponseStream()).ReadToEnd();
    $xml = [Xml]$arg
    return $xml
}
