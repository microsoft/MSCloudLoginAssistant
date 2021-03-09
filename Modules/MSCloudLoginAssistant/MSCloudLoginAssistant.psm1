<#
.SYNOPSIS
    The Test-MSCloudLogin function is used to assist with checking authentication status of and logging in to various Microsoft Cloud services, such as Azure, SharePoint Online, and SharePoint PnP.
.EXAMPLE
    Test-MSCloudLogin -Platform AzureAD -Verbose
.EXAMPLE
    Test-MSCloudLogin -Platform PnP
.PARAMETER Platform
    The Platform parameter specifies which cloud service for which we are testing the login state. Possible values are Azure, AzureAD, SharePointOnline, ExchangeOnline, SecurityComplianceCenter, MSOnline, PnP, PowerPlatforms, MicrosoftTeams, and SkypeForBusiness.
.NOTES
    Created & maintained by Brian Lalancette (@brianlala), 2019-2020.
.LINK
    https://github.com/Microsoft/MSCloudLoginAssistant
#>

function Test-MSCloudLogin
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet("Azure", "AzureAD", "SharePointOnline", "ExchangeOnline", `
                "SecurityComplianceCenter", "MSOnline", "PnP", "PowerPlatforms", `
                "MicrosoftTeams", "SkypeForBusiness", "MicrosoftGraph", "Intune")]
        [System.String]
        $Platform,

        [Parameter()]
        [System.String]
        $ConnectionUrl,

        [Parameter()]
        [Alias("o365Credential")]
        [System.Management.Automation.PSCredential]
        $CloudCredential,

        [Parameter()]
        [Switch]
        $UseModernAuth
    )

    # If we specified the CloudCredential parameter then set the global o365Credential object to its value
    if ($null -ne $CloudCredential)
    {
        $Global:o365Credential = $CloudCredential
        $Global:DomainName = $Global:o365Credential.UserName.Split('@')[1]
    }

    if ($null -eq $Global:UseModernAuth)
    {
        $Global:UseModernAuth = $UseModernAuth.IsPresent
    }

    if ($Global:appIdentityParams.AppSecret -and !$Global:appIdentityParams.ServicePrincipalCredentials)
    {
        $secpasswd = ConvertTo-SecureString $Global:appIdentityParams.AppSecret -AsPlainText -Force
        $spCreds = New-Object System.Management.Automation.PSCredential ($Global:appIdentityParams.AppId, $secpasswd)

        # required for the Azure workload, it works by supplying the credentials(appid, appsecret) and setting the -ServicePrincipal switch
        $Global:appIdentityParams.ServicePrincipalCredentials = $spCreds
    }

    try
    {
        switch ($Platform)
        {
            'Azure'
            {
                Connect-MSCloudLoginAzure
            }
            'AzureAD'
            {
                Connect-MSCloudLoginAzureAD
            }
            'SharePointOnline'
            {
                Connect-MSCloudLoginSharePointOnline
            }
            'ExchangeOnline'
            {
                Connect-MSCloudLoginExchangeOnline
            }
            'MicrosoftGraph'
            {
                Connect-MSCloudLoginMicrosoftGraph
            }
            'Intune'
            {                
                Connect-MSCloudLoginIntune
            }
            'SecurityComplianceCenter'
            {
                Connect-MSCloudLoginSecurityCompliance
            }
            'MSOnline'
            {
                Connect-MSCloudLoginMSOnline
            }
            'PnP'
            {
                Connect-MSCloudLoginPnP -ConnectionUrl $ConnectionUrl
            }
            'MicrosoftTeams'
            {
                Connect-MSCloudLoginTeams
            }
            'SkypeForBusiness'
            {
                Connect-MSCloudLoginSkypeForBusiness
            }
            'PowerPlatforms'
            {
                Connect-MSCloudLoginPowerPlatform
            }
        }
        Set-Variable -Scope Global "MSCloudLogin${Platform}Connected" -Value $True
        Set-Variable -Scope Global "MSCloudLogin${Platform}ConnectionFaulted" -Value $False
    }
    catch
    {
        Set-Variable -Scope Global "MSCloudLogin${Platform}Connected" -Value $False
        Set-Variable -Scope Global "MSCloudLogin${Platform}ConnectionFaulted" -Value $True
        throw $_
    }
}

function Get-SPOAdminUrl
{
    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter()]
        [System.Management.Automation.PSCredential]
        $CloudCredential
    )

    if (![string]::IsNullOrEmpty($Global:SPOAdminUrl))
    {
        return $Global:SPOAdminUrl
    }

    $rootSiteUrl = Get-SPORootSiteUrl -CloudCredential $CloudCredential
    $adminUrl = $rootSiteUrl.Insert($rootSiteUrl.IndexOf(".sharepoint"), "-admin")
    $Global:SPOAdminUrl = $adminUrl

    return $Global:SPOAdminUrl
}

function Get-SPORootSiteUrl
{
    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter()]
        [System.Management.Automation.PSCredential]
        $CloudCredential
    )

    if (![string]::IsNullOrEmpty($Global:SPORootSiteUrl))
    {
        return $Global:SPORootSiteUrl
    }

    if ($Global:UseApplicationIdentity)
    {
        Write-Verbose -Message "Retrieving SharePoint Online root site url with MS graph api..."

        $graphEndpoint = Get-AzureEnvironmentEndpoint -AzureCloudEnvironmentName $Global:appIdentityParams.AzureCloudEnvironmentName -EndpointName MsGraphEndpointResourceId
        $spRootUrl = Get-AzureEnvironmentEndpoint -AzureCloudEnvironmentName $Global:appIdentityParams.AzureCloudEnvironmentName -EndpointName SharePointRootUrl -AllowEmpty
        if (![string]::IsNullOrEmpty($spRootUrl))
        {
            $Global:SPORootSiteUrl = $spRootUrl.TrimEnd('/')
            return $Global:SPORootSiteUrl
        }
        try
        {
            $accessToken = Get-AppIdentityAccessToken -TargetUri $graphEndpoint
            [Hashtable] $headers = @{}
            $Headers["Authorization"] = "Bearer $accessToken";
            $tenantId = $Global:appIdentityParams.Tenant
            $response = Invoke-WebRequest -Uri "$graphEndpoint/v1.0/$tenantId/sites/root?`$select=sitecollection" -Headers $headers -Method Get -UseBasicParsing -UserAgent "SysKitTrace"
        }
        catch
        {
            #unfortunately, application permissions are not working so we will use our fallback delegated user
            $accessToken = Get-OnBehalfOfAccessToken -TargetUri $graphEndpoint
            [Hashtable] $headers = @{}
            $Headers["Authorization"] = "Bearer $accessToken";
            $tenantId = $Global:appIdentityParams.Tenant
            $response = Invoke-WebRequest -Uri "$graphEndpoint/v1.0/$tenantId/sites/root?`$select=sitecollection" -Headers $headers -Method Get -UseBasicParsing -UserAgent "SysKitTrace"
        }


        $json = ConvertFrom-Json $response.Content
        $hostname = $json.siteCollection.hostname
        $Global:SPORootSiteUrl = "https://" + $hostname
    }
    else
    {
        Write-Verbose -Message "Connection to Azure AD is required to automatically determine SharePoint Online root site URL..."
        Test-MSCloudLogin -Platform AzureAD -CloudCredential $CloudCredential


        Write-Verbose -Message "Getting SharePoint Online root site URL..."
        $defaultDomain = Get-AzureADDomain | Where-Object { $_.Name -like "*.onmicrosoft.com" -and $_.IsInitial -eq $true } # We don't use IsDefault here because the default could be a custom domain

        if ($null -eq $defaultDomain)
        {
            $defaultDomain = Get-AzureADDomain | Where-Object { $_.Name -like "*.onmicrosoft.de" -and $_.IsInitial -eq $true }
            $domain = '.onmicrosoft.de'
            $tenantName = $defaultDomain[0].Name.Replace($domain, '')
            if ($Global:CloudEnvironment -eq 'Germany')
            {
                $spoRootSiteUrl = "https://$tenantName.sharepoint.de"
            }
            elseif ($Global:CloudEnvironment -eq 'GCCHigh')
            {
                $spoRootSiteUrl = "https://$tenantName.sharepoint.us"
            }
            Write-Verbose -Message "SharePoint Online root site URL is $spoRootSiteUrl"
            $Global:SPORootSiteUrl = $spoRootSiteUrl
        }
        else
        {
            $domain = '.onmicrosoft.com'
            $tenantName = $defaultDomain[0].Name.Replace($domain, '')
            $extension = 'sharepoint.com'
            if ($Global:CloudEnvironment -eq 'Germany')
            {
                $extension = 'sharepoint.de'
            }
            elseif ($Global:CloudEnvironment -eq 'GCCHigh')
            {
                $extension = 'sharepoint.us'
            }
            $spoRootSiteUrl = "https://$tenantName.$extension"
            Write-Verbose -Message "SharePoint Online root site URL is $spoRootSiteUrl"
            $Global:SPORootSiteUrl = $spoRootSiteUrl
        }
    }
    return $Global:SPORootSiteUrl
}

function Get-TenantLoginEndPoint
{
    [CmdletBinding()]
    [OutputType([System.String])]
    Param(
        [Parameter(Mandatory = $True)]
        [System.String]
        $TenantName,

        [Parameter()]
        [System.String]
        $AzureCloudEnvironmentName
    )
    $TenantInfo = @{}

    $loginEndpoint = Get-AzureEnvironmentEndpoint -AzureCloudEnvironmentName $AzureCloudEnvironmentName -EndpointName ActiveDirectory
    $wellKnownDiscoveryEndpoint = "$($loginEndpoint)$TenantName/.well-known/openid-configuration"
    $webrequest = Invoke-WebRequest -Uri $wellKnownDiscoveryEndpoint -UseBasicParsing
    if ($webrequest.StatusCode -eq 200)
    {
        $TenantInfo = $webrequest.Content | ConvertFrom-Json
    }
    return $TenantInfo
}

function Init-ApplicationIdentity
{
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [System.String]
        $AppId,

        [Parameter()]
        [System.String]
        $AppSecret,

        [Parameter()]
        [System.String]
        $CertificateThumbprint,

        [Parameter()]
        [System.String]
        $Tenant,

        [Parameter()]
        [System.String]
        $TokenCacheLocation,

        [Parameter()]
        [System.Byte[]]
        $TokenCacheEntropy,

        [Parameter()]
        [ValidateSet("CurrentUser", "LocalMachine")]
        [System.String]
        $TokenCacheDataProtectionScope,

        [Parameter()]
        [System.String]
        $OnBehalfOfUserPrincipalName,

        [Parameter()]
        [System.String]
        $AzureCloudEnvironmentName
    )

    Init-ApplicationIdentityCore -Tenant $Tenant `
        -AppId $AppId `
        -AppSecret $AppSecret `
        -CertificateThumbprint $CertificateThumbprint `
        -TokenCacheLocation $TokenCacheLocation `
        -TokenCacheEntropy $TokenCacheEntropy `
        -TokenCacheDataProtectionScope  $TokenCacheDataProtectionScope `
        -OnBehalfOfUserPrincipalName $OnBehalfOfUserPrincipalName `
        -AzureCloudEnvironmentName $AzureCloudEnvironmentName `
        -Force
}

function Init-ApplicationIdentityCore
{
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [System.String]
        $AppId,

        [Parameter()]
        [System.String]
        $AppSecret,

        [Parameter()]
        [System.String]
        $CertificateThumbprint,

        [Parameter()]
        [System.String]
        $Tenant,

        [Parameter()]
        [System.String]
        $TokenCacheLocation,

        [Parameter()]
        [System.Byte[]]
        $TokenCacheEntropy,

        [Parameter()]
        [ValidateSet("CurrentUser", "LocalMachine")]
        [System.String]
        $TokenCacheDataProtectionScope,

        [Parameter()]
        [Switch]
        $Force,

        [Parameter()]
        [System.String]
        $OnBehalfOfUserPrincipalName,

        [Parameter()]
        [System.String]
        $AzureCloudEnvironmentName
    )
    if ($null -eq $Global:UseApplicationIdentity -or $Force)
    {
        $Global:UseApplicationIdentity = $null -ne $Global:appIdentityParams -or ![string]::IsNullOrEmpty($AppId) -or ![string]::IsNullOrEmpty($AppSecret) -or ![string]::IsNullOrEmpty($CertificateThumbprint)
    }

    if ($Global:UseApplicationIdentity -and !$Global:appIdentityParams -or $Force)
    {
        if (!$AppId -or (!$AppSecret -and !$CertificateThumbprint))
        {
            throw "When connecting with an application identity the ApplicationId and the AppSecret or CertificateThumbprint parameters must be provided"
        }

        if (-not $Tenant)
        {
            throw "The tenant must be specified when connecting with an application identity"
        }

        if (!$AzureCloudEnvironmentName)
        {
            $AzureCloudEnvironmentName = "AzureCloud"
        }

        $Global:appIdentityParams = @{
            AppId                         = $AppId
            AppSecret                     = $AppSecret
            CertificateThumbprint         = $CertificateThumbprint
            Tenant                        = $Tenant
            OnBehalfOfUserPrincipalName   = $OnBehalfOfUserPrincipalName
            TokenCacheLocation            = $TokenCacheLocation
            TokenCacheEntropy             = $TokenCacheEntropy
            TokenCacheDataProtectionScope = $TokenCacheDataProtectionScope
            AzureCloudEnvironmentName     = $AzureCloudEnvironmentName
        }
    }


    if ($null -eq $Global:ADALAppIndentiyServicePoint -or $null -eq $Global:ADALAppOnBehalfServicePoint -or $Force)
    {
        Import-Module AzureAD
        
        # use a persisted token cache for user tokens so we can always have a token for a user and multiple resources based on the refresh token
        $Global:ADALAppOnBehalfServicePoint = New-ADALServiceInfo -TenantName $Tenant -TokenCacheEntropy $TokenCacheEntropy -TokenCacheLocation $TokenCacheLocation -TokenCacheDataProtectionScope $TokenCacheDataProtectionScope -AzureCloudEnvironmentName $AzureCloudEnvironmentName

        # no need to use a persisted token cache for the app identity tokens
        $Global:ADALAppIndentiyServicePoint = New-ADALServiceInfo -TenantName $Tenant -AzureCloudEnvironmentName $AzureCloudEnvironmentName
    }
}

function Grant-OnBehalfConsent
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false)]
        [System.String]
        $UserPrincipalName
    )

    if ($null -eq $Global:ADALAppOnBehalfServicePoint)
    {
        throw "Please use Init-ApplicationIdentity before using this command"
    }

    $userIdentifier = [Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier]::AnyUser
    if ($UserPrincipalName)
    {
        $userIdentifier = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList $UserPrincipalName, "OptionalDisplayableId"
    }
    elseif ($Global:appIdentityParams.OnBehalfOfUserPrincipalName)
    {
        $userIdentifier = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList $Global:appIdentityParams.OnBehalfOfUserPrincipalName, "OptionalDisplayableId"
    }
    $PromptBehavior = [Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior]::Always
    # i believe we need to use always to prompt for consent
    $platformParams = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList $PromptBehavior
    $authRes = $Global:ADALAppOnBehalfServicePoint.authContext.AcquireTokenAsync($Global:appIdentityParams.Appid, $Global:appIdentityParams.AppId, [Uri]::new("urn:ietf:wg:oauth:2.0:oob"), $platformParams, $userIdentifier)

    Write-Host $authRes.Result.AccessToken
}

function New-ADALServiceInfo
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [System.String]
        $TenantName,

        [Parameter(Mandatory = $false)]
        [System.String]
        $UserPrincipalName,

        [Parameter(Mandatory = $false)]
        [System.String]
        $TokenCacheLocation,

        [Parameter(Mandatory = $false)]
        [System.Byte[]]
        $TokenCacheEntropy,

        [Parameter()]
        [ValidateSet("", "CurrentUser", "LocalMachine")]
        [System.String]
        $TokenCacheDataProtectionScope,

        [Parameter()]
        [System.String]
        $AzureCloudEnvironmentName
    )
    $AzureADDLL = Get-AzureADDLL
    if ([string]::IsNullOrEmpty($AzureADDLL))
    {
        Throw "Can't find Azure AD DLL"
        Exit
    }

    if (-not ([System.Management.Automation.PSTypeName]'Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext').Type)
    {
        Add-Type -Path $AzureADDLL | Out-Null
    }

    $TenantInfo = Get-TenantLoginEndPoint -TenantName $TenantName -AzureCloudEnvironmentName $AzureCloudEnvironmentName
    if ([string]::IsNullOrEmpty($TenantInfo))
    {
        Throw "Can't find Tenant Login Endpoint"
        Exit
    }
    else
    {
        [string] $authority = $TenantInfo.authorization_endpoint
    }
    $PromptBehavior = [Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior]::Auto
    $Service = @{}
    $tokenCacheInstance = $null
    if ($TokenCacheLocation)
    {
        $absPath = [System.IO.Path]::GetFullPath( [System.IO.Path]::Combine($PSScriptRoot, $TokenCacheLocation))
        $tokenCacheInstance = Get-PersistedTokenCacheInstance -FilePath $absPath -TokenCacheEntropy $TokenCacheEntropy -TokenCacheDataProtectionScope $TokenCacheDataProtectionScope
    }
    $Service["authContext"] = [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext]::new($authority, $false, $tokenCacheInstance)
    $Service["platformParam"] = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList $PromptBehavior

    if ($UserPrincipalName)
    {
        $Service["userId"] = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList $UserPrincipalName, "OptionalDisplayableId"
    }
    return $Service
}



function Get-AuthHeader
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [System.String]
        $UserPrincipalName,
        [Parameter(Mandatory = $True)]
        [Alias("RessourceURI")] # For backward compat with anything using the misspelled parameter
        $ResourceURI,
        [Parameter(Mandatory = $True)]
        $clientId,
        [Parameter(Mandatory = $True)]
        [System.String]
        $RedirectURI
    )
    if ($null -eq $Global:ADALServicePoint)
    {
        $TenantName = $UserPrincipalName.split("@")[1]
        $Global:ADALServicePoint = New-ADALServiceInfo -TenantName $TenantName -UserPrincipalName $UserPrincipalName
    }

    try
    {
        Write-Debug "Looking for a refresh token"
        $authResult = $Global:ADALServicePoint.authContext.AcquireTokenSilentAsync($ResourceURI, $clientId)
        if ($null -eq $authResult.result)
        {
            $RedirectURI = [System.Uri]::new($RedirectURI)
            $authResult = $Global:ADALServicePoint.authContext.AcquireTokenAsync($ResourceURI, $clientId, $RedirectURI, $Global:ADALServicePoint.platformParam, $Global:ADALServicePoint.userId)
        }
        $AuthHeader = $authResult.result.CreateAuthorizationHeader()
    }
    catch
    {
        Throw "Can't create Authorization header: $_"
    }
    Return $AuthHeader
}

function Get-OnBehalfOfAccessToken
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True)]
        $TargetUri,

        [Parameter(Mandatory = $False)]
        $UserPrincipalName
    )

    $authResult = Get-OnBehalfOfAuthResult -TargetUri $TargetUri -UserPrincipalName $UserPrincipalName
    return $authResult.AccessToken
}

function Get-OnBehalfOfAuthResult
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True)]
        $TargetUri,

        [Parameter(Mandatory = $False)]
        $UserPrincipalName
    )

    if ($null -eq $Global:ADALAppOnBehalfServicePoint)
    {
        throw "Please use Init-ApplicationIdentity before using this command"
    }

    $AzureADDLL = Get-AzureADDLL
    if ([string]::IsNullOrEmpty($AzureADDLL))
    {
        throw "Can't find Azure AD DLL"
    }

    if (-not ([System.Management.Automation.PSTypeName]'Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext').Type)
    {
        Add-Type -Path $AzureADDLL | Out-Null
    }

    if (!$Global:appIdentityParams.CertificateThumbprint)
    {
        throw "Only certificate auth currently implemented"
    }
    $thumbprint = $Global:appIdentityParams.CertificateThumbprint

    $cert = Get-ChildItem -path "Cert:\*$thumbprint" -Recurse | Where-Object { $_.HasPrivateKey } | Select-Object -First 1

    if ($UserPrincipalName)
    {
        $userIdentifier = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList $UserPrincipalName, "OptionalDisplayableId"
    }
    elseif ($Global:appIdentityParams.OnBehalfOfUserPrincipalName)
    {
        $userIdentifier = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList $Global:appIdentityParams.OnBehalfOfUserPrincipalName, "OptionalDisplayableId"
    }
    else
    {
        throw "Cannot retrieve access token on behalf of no user"
    }
    $certAssertion = [Microsoft.IdentityModel.Clients.ActiveDirectory.ClientAssertionCertificate]::new($Global:appIdentityParams.AppId, $cert)
    $authResultTask = $Global:ADALAppOnBehalfServicePoint.authContext.AcquireTokenSilentAsync($TargetUri.ToString(), $certAssertion, $userIdentifier)

    # will force an exception to be thrown Result unlike C# will not throw an exception
    try
    {
        $authResultTask.Wait()
    }
    catch
    {
        $message = "Could not get access token for user " + $UserPrincipalName
        Write-Verbose $message
        throw  $_
    }

    return $authResultTask.Result
}

function Get-AppIdentityAccessToken
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True)]
        $TargetUri
    )

    $authResult = Get-AppIdentityAuthResult -TargetUri $TargetUri
    return $authResult.AccessToken
}

function Get-AppIdentityAuthResult
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True)]
        $TargetUri
    )

    if ($null -eq $Global:ADALAppIndentiyServicePoint)
    {
        throw "Please use Init-ApplicationIdentity before using this command"
    }

    if (-not ([System.Management.Automation.PSTypeName]'Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext').Type)
    {
        $AzureADDLL = Get-AzureADDLL
        if ([string]::IsNullOrEmpty($AzureADDLL))
        {
            throw "Can't find Azure AD DLL"
        }
        Add-Type -Path $AzureADDLL | Out-Null
    }

    if (!$Global:appIdentityParams.CertificateThumbprint)
    {
        throw "Only certificate auth currently implemented"
    }
    $thumbprint = $Global:appIdentityParams.CertificateThumbprint

    $cert = Get-ChildItem -path "Cert:\*$thumbprint" -Recurse | Where-Object { $_.HasPrivateKey } | Select-Object -First 1
    $certAssertion = [Microsoft.IdentityModel.Clients.ActiveDirectory.ClientAssertionCertificate]::new($Global:appIdentityParams.AppId, $cert)
    $authResultTask = $Global:ADALAppIndentiyServicePoint.authContext.AcquireTokenAsync($TargetUri.ToString(), $certAssertion)

    # will force an exception to be thrown Result unlike C# will not throw an exception
    try
    {
        $authResultTask.Wait()
    }
    catch
    {
        $message = "Could not get access token for user " + $UserPrincipalName
        Write-Verbose $message
        throw  $_
    }

    return $authResultTask.Result
}

function Get-AccessToken
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True)]
        $TargetUri,

        [Parameter(Mandatory = $True)]
        $AuthUri,

        [Parameter(Mandatory = $True)]
        $ClientId,

        [Parameter(Mandatory = $False)]
        [System.Management.Automation.PSCredential]
        $Credentials
    )

    try
    {
        Write-Verbose "There was no existing Access Token for $ClientId. Requesting a new one from $TargetUri"

        $jobName = "AcquireTokenAsync" + (New-Guid).ToString()
        Start-Job -Name $jobName -ScriptBlock {
            Param(
                [Parameter(Mandatory = $True)]
                $TargetUri,

                [Parameter(Mandatory = $True)]
                $AuthUri,

                [Parameter(Mandatory = $True)]
                $ClientId,

                [Parameter(Mandatory = $False)]
                [System.Management.Automation.PSCredential]
                $Credentials
            )
            # Load AAD Assemblies
            $AzureADDLL = Get-AzureADDLL
            if ([string]::IsNullOrEmpty($AzureADDLL))
            {
                throw "Can't find Azure AD DLL"
            }

            if (-not ([System.Management.Automation.PSTypeName]'Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext').Type)
            {
                Add-Type -Path $AzureADDLL | Out-Null
            }

            $UserPasswordCreds = [Microsoft.IdentityModel.Clients.ActiveDirectory.UserPasswordCredential]::new($Credentials.UserName, $Credentials.Password)
            $context = [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext]::new($AuthUri, $false, [Microsoft.IdentityModel.Clients.ActiveDirectory.TokenCache]::DefaultShared)
            $authResult = $context.AcquireTokenSilentAsync($TargetUri, $ClientId)

            if ($null -eq $authResult.result)
            {
                $authResult = [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContextIntegratedAuthExtensions]::AcquireTokenAsync($context, $targetUri, $ClientId, $UserPasswordCreds)
            }
            $token = $authResult.result.AccessToken
            return $token
        } -ArgumentList @($targetUri, $AuthUri, $ClientId, $Credentials) | Out-Null
        $job = Get-Job | Where-Object -FilterScript { $_.Name -eq $jobName }
        do
        {
            Start-Sleep -Seconds 1
        } while ($job.JobStateInfo.State -ne "Completed")
        $AccessToken = Receive-Job -Name $jobName
        Write-Verbose "Token Found --> $AccessToken"
        return $AccessToken
    }
    catch
    {
        throw $_
    }
}

function Get-SkypeForBusinessServiceEndpoint
{
    [CmdletBinding()]
    [OutputType([Uri])]
    param(
        [Parameter(Mandatory = $true)]
        [System.String]
        $TargetDomain,

        [Parameter()]
        [System.String]
        $OverrideDiscoveryUri
    )
    if (!$OverrideDiscoveryUri)
    {
        $OverrideDiscoveryUri = "http://lyncdiscover." + $TargetDomain;
    }
    $desiredLink = "External/RemotePowerShell";
    $liveIdUrl = $OverrideDiscoveryUri.ToString() + "?Domain=" + $TargetDomain

    $xml = Get-RTCXml -Url $liveIdUrl
    if (!$xml)
    {
        Write-Verbose "Did not find anything @ $OverrideDiscoveryUri, will try with initial domain"
        Test-MSCloudLogin -Platform AzureAD
        $tenantDomains = Get-AzureADDomain
        $initialDomain = ($tenantDomains | Where-Object -FilterScript { $_.IsInitial }).Name
        $OverrideDiscoveryUri = "http://lyncdiscover." + $initialDomain;
        $liveIdUrl = $OverrideDiscoveryUri.ToString() + "?Domain=" + $initialDomain
        $xml = Get-RTCXml -Url $liveIdUrl

        if (!$xml)
        {
            $defaultDomain = ($tenantDomains | Where-Object -FilterScript { $_.IsDefault }).Name
            $OverrideDiscoveryUri = "http://lyncdiscover." + $defaultDomain;
            $liveIdUrl = $OverrideDiscoveryUri.ToString() + "?Domain=" + $defaultDomain
            $xml = Get-RTCXml -Url $liveIdUrl
        }
    }

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

    $xml = Get-RTCXml -Url $domain.href
    $endpoint = $xml.AutodiscoverResponse.Domain.Link | Where-Object -FilterScript { $_.token -eq $desiredLink }
    if (!$endpoint)
    {
        $hybrid = $xml.AutodiscoverResponse.Domain.Link | Where-Object -FilterScript { $_.token -eq 'Hybrid' }
        return Get-SkypeForBusinessServiceEndpoint -TargetDomain $TargetDomain -OverrideDiscoveryUri $hybrid.href
    }

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

    $xml = $null
    try
    {
        $request = [System.Net.WebRequest]::Create($Url);
        $request.set_Accept("application/vnd.microsoft.rtc.autodiscover+xml;v=1");
        $response = $request.GetResponse()
        $arg = [System.IO.StreamReader]::new($response.GetResponseStream()).ReadToEnd();
        $xml = [Xml]$arg
    }
    catch
    {
        Write-Verbose $_
    }
    return $xml
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

function Get-PowerPlatformTokenInfo
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.String]
        $Audience,

        [Parameter()]
        [System.Management.Automation.PSCredential]
        $Credentials
    )

    $jobName = 'AcquireTokenAsync' + (New-Guid).ToString()
    Start-Job -Name $jobName -ScriptBlock {
        Param(
            [Parameter(Mandatory = $true)]
            [System.Management.Automation.PSCredential]
            $O365Credentials,

            [Parameter(Mandatory = $true)]
            [System.String]
            $Audience
        )
        try
        {
            $WarningPreference = 'SilentlyContinue'
            Import-Module -Name 'Microsoft.PowerApps.Administration.PowerShell' -Force
            $loginEndpoint = Get-AzureEnvironmentEndpoint -AzureCloudEnvironmentName $Global:appIdentityParams.AzureCloudEnvironmentName -EndpointName ActiveDirectory
            $authContext = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext($loginEndpoint + "common");
            $credential = [Microsoft.IdentityModel.Clients.ActiveDirectory.UserCredential]::new($O365Credentials.Username, $O365Credentials.Password)
            $authResult = $authContext.AcquireToken($Audience, "1950a258-227b-4e31-a9cf-717495945fc2", $credential);

            $JwtToken = $authResult.IdToken
            $tokenSplit = $JwtToken.Split(".")
            $claimsSegment = $tokenSplit[1].Replace(" ", "+");

            $mod = $claimsSegment.Length % 4
            if ($mod -gt 0)
            {
                $paddingCount = 4 - $mod;
                for ($i = 0; $i -lt $paddingCount; $i++)
                {
                    $claimsSegment += "="
                }
            }
            $decodedClaimsSegment = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($claimsSegment))
            $claims = ConvertFrom-Json $decodedClaimsSegment
        }
        catch
        {
            $_ | Out-File "$env:temp\MSCloudLoginAssistant_Error.txt"
        }
        return @{
            JwtToken     = $JwtToken
            Claims       = $claims
            RefreshToken = $authResult.RefreshToken
            AccessToken  = $authResult.AccessToken
            ExpiresOn    = $authResult.ExpiresOn
        }
    } -ArgumentList @($Credentials, $Audience) | Out-Null

    $job = Get-Job | Where-Object -FilterScript { $_.Name -eq $jobName }
    do
    {
        Start-Sleep -Seconds 1
    } while ($job.JobStateInfo.State -ne "Completed")
    $TokenInfo = Receive-Job -Name $jobName
    return $TokenInfo
}




$onAssemblyResolveEventHandler = [ResolveEventHandler] {
    param($sender, $e)

    Write-Verbose "ResolveEventHandler: Attempting FullName resolution of $($e.Name)"
    foreach ($assembly in [System.AppDomain]::CurrentDomain.GetAssemblies())
    {
        if ($assembly.FullName -eq $e.Name)
        {
            Write-Host "Successful FullName resolution of $($e.Name)"
            return $assembly
        }
    }

    Write-Verbose "ResolveEventHandler: Attempting name-only resolution of $($e.Name)"
    foreach ($assembly in [System.AppDomain]::CurrentDomain.GetAssemblies())
    {
        # Get just the name from the FullName (no version)
        $assemblyName = $assembly.FullName.Substring(0, $assembly.FullName.IndexOf(", "))

        if ($e.Name.StartsWith($($assemblyName + ",")))
        {

            Write-Verbose "Successful name-only (no version) resolution of $assemblyName"
            return $assembly
        }
    }

    return $null
}

$anyDllVersionResolutionEnabled = $false

function Enable-AppDomainLoadAnyVersionResolution
{
    if ($Script:anyDllVersionResolutionEnabled)
    {
        return
    }

    $Script:anyDllVersionResolutionEnabled = $true

    [System.AppDomain]::CurrentDomain.add_AssemblyResolve($onAssemblyResolveEventHandler)
}


function Disable-AppDomainLoadAnyVersionResolution
{
    if (!$Script:anyDllVersionResolutionEnabled)
    {
        return
    }

    $Script:anyDllVersionResolutionEnabled = $false
    [System.AppDomain]::CurrentDomain.remove_AssemblyResolve($onAssemblyResolveEventHandler)
}


function Get-AzureEnvironmentEndpoint
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.String]
        $AzureCloudEnvironmentName,

        [Parameter(Mandatory = $true)]
        [System.String]
        $EndpointName,

        [Switch]
        $AllowEmpty
    )

    Ensure-AzureCloudEnvironmentsFromConfigFile

    if (!$Global:AzureCloudEnvironments.$AzureCloudEnvironmentName)
    {
        throw "The $AzureCloudEnvironmentName environment is not registered."
    }

    if (!$Global:AzureCloudEnvironments.$AzureCloudEnvironmentName.Endpoints.$EndpointName -and !$AllowEmpty)
    {
        throw "$AzureCloudEnvironments is not registered for the $EndpointName cloud environment."
    }

    return $AzureCloudEnvironments.$AzureCloudEnvironmentName.Endpoints.$EndpointName
}

function Ensure-AzureCloudEnvironmentsFromConfigFile
{
    if (!$Global:AzureCloudEnvironments)
    {
        $configFilePath = Join-Path -Path $PSScriptRoot -ChildPath "azureEnvironments.json"
        $Global:AzureCloudEnvironments = Get-Content -Path $configFilePath | ConvertFrom-Json
    }
}

function Get-PsModuleAzureEnvironmentName
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.String]
        $AzureCloudEnvironmentName,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Azure", "AzureAD", "SharePointOnline", "ExchangeOnline", `
                "SecurityComplianceCenter", "MSOnline", "PnP", "PowerPlatforms", `
                "MicrosoftTeams", "SkypeForBusiness", "MicrosoftGraph")]
        [System.String]
        $Platform
    )

    Ensure-AzureCloudEnvironmentsFromConfigFile

    if (!$Global:AzureCloudEnvironments.$AzureCloudEnvironmentName)
    {
        throw "The $AzureCloudEnvironmentName environment is not registered."
    }

    if (!$Global:AzureCloudEnvironments.$AzureCloudEnvironmentName.PsModuleEnvironmentNames.$Platform)
    {
        throw "$AzureCloudEnvironments does not have a Ps Module name defined for the $Platform platform."
    }

    return $Global:AzureCloudEnvironments.$AzureCloudEnvironmentName.PsModuleEnvironmentNames.$Platform
}

function Get-MSCloudLoginOrganizationName
{
    param(
        [Parameter(Mandatory = $true)]
        [System.String]
        $ApplicationId,

        [Parameter(Mandatory = $true)]
        [System.String]
        $TenantId,

        [Parameter(Mandatory = $true)]
        [System.String]
        $CertificateThumbprint
    )

    Test-MSCloudLogin -Platform AzureAD

    $domain = Get-AzureADDomain  | where-object { $_.IsInitial -eq $True } | select Name

    if ($null -ne $domain)
    {

        return $domain.Name
    }
}
