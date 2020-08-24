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
                $Global:SfBODomain = $adminDomain
                $Global:SfBOTargerUri = $targetUri
                $targetUri = Get-SkypeForBusinessServiceEndpoint -TargetDomain $adminDomain
                $appAuthInfo = Get-SkypeForBusinessAccessInfo -PowerShellEndpointUri $targetUri

                $clientId = $appAuthInfo.ClientID
                $authUri = $appAuthInfo.AuthUrl
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

            $queryStr = "AdminDomain=$Global:SfBODomain"

            $ConnectionUri = [UriBuilder]($Global:SfBOTargetUri)
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
            throw $_
        }
    }
}

function Get-MSCloudLoginSkypeForBusinessOnlineAccessToken
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
