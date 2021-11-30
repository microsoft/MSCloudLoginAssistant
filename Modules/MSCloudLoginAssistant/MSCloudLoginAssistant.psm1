<#
.SYNOPSIS
    The Test-MSCloudLogin function is used to assist with checking authentication status of and logging in to various Microsoft Cloud services, such as Azure, SharePoint Online, and SharePoint PnP.
.EXAMPLE
    Test-MSCloudLogin -Platform AzureAD -Verbose
.EXAMPLE
    Test-MSCloudLogin -Platform PnP
.PARAMETER Platform
    The Platform parameter specifies which cloud service for which we are testing the login state. Possible values are Azure, AzureAD, SharePointOnline, ExchangeOnline, SecurityComplianceCenter, MSOnline, PnP, PowerPlatforms, MicrosoftTeams, MicrosoftGraph and SkypeForBusiness.
.NOTES
    Created & maintained by the Microsoft365DSC Team, 2019-2020. (@BrianLala & @NikCharlebois)
.LINK
    https://github.com/Microsoft/MSCloudLoginAssistant
#>
function Test-MSCloudLogin
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet("Azure", "AzureAD", `
                "ExchangeOnline", "Intune", `
                "SecurityComplianceCenter", "PnP", "PowerPlatforms", `
                "MicrosoftTeams", "MicrosoftGraph")]
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
        [System.String]
        $ApplicationId,

        [Parameter()]
        [System.String]
        $TenantId,

        [Parameter()]
        [System.String]
        $ApplicationSecret,

        [Parameter()]
        [System.String]
        $CertificateThumbprint,

        [Parameter()]
        [Switch]
        $UseModernAuth,

        [Parameter()]
        [SecureString]
        $CertificatePassword,

        [Parameter()]
        [System.String]
        $CertificatePath,

        [Parameter()]
        [System.Boolean]
        $SkipModuleReload = $false,

        [Parameter()]
        [System.String]
        [ValidateSet("v1.0", "beta")]
        $ProfileName = "v1.0"
    )
    $parametersToPass = $PSBoundParameters
    $parametersToPass.Add("Workload", $Platform)
    $parametersToPass.Remove("Platform") | Out-Null

    $parametersToPass.Add("Credential", $CloudCredential)
    $parametersToPass.Remove("CloudCredential") | Out-Null

    $parametersToPass.Add("Url", $ConnectionUrl)
    $parametersToPass.Remove("ConnectionUrl") | Out-Null

    Connect-M365Tenant @parametersToPass
}
function Connect-M365Tenant
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet("Azure", "AzureAD", `
                "ExchangeOnline", "Intune", `
                "SecurityComplianceCenter", "PnP", "PowerPlatforms", `
                "MicrosoftTeams", "MicrosoftGraph")]
        [System.String]
        $Workload,

        [Parameter()]
        [System.String]
        $Url,

        [Parameter()]
        [Alias("o365Credential")]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter()]
        [System.String]
        $ApplicationId,

        [Parameter()]
        [System.String]
        $TenantId,

        [Parameter()]
        [System.String]
        $ApplicationSecret,

        [Parameter()]
        [System.String]
        $CertificateThumbprint,

        [Parameter()]
        [Switch]
        $UseModernAuth,

        [Parameter()]
        [SecureString]
        $CertificatePassword,

        [Parameter()]
        [System.String]
        $CertificatePath,

        [Parameter()]
        [System.Boolean]
        $SkipModuleReload = $false,

        [Parameter()]
        [System.String]
        [ValidateSet("v1.0", "beta")]
        $ProfileName = "v1.0"
    )

    $VerbosePreference = 'SilentlyContinue'

    if ($null -eq $Global:MSCloudLoginConnectionProfile)
    {
        $Global:MSCloudLoginConnectionProfile = New-Object MSCloudLoginConnectionProfile
    }

    Write-Verbose -Message "Trying to connect to platform {$Workload}"
    switch ($Workload)
    {
        'Azure'
        {
            $Global:MSCloudLoginConnectionProfile.Azure.Credentials           = $Credential
            $Global:MSCloudLoginConnectionProfile.Azure.ApplicationId         = $ApplicationId
            $Global:MSCloudLoginConnectionProfile.Azure.ApplicationSecret     = $ApplicationSecret
            $Global:MSCloudLoginConnectionProfile.Azure.TenantId              = $TenantId
            $Global:MSCloudLoginConnectionProfile.Azure.CertificateThumbprint = $CertificateThumbprint

            if ($null -eq $UseModernAuth)
            {
                $Global:MSCloudLoginConnectionProfile.Azure.UseModernAuthentication = $UseModernAuth.IsPresent
            }
            $Global:MSCloudLoginConnectionProfile.Azure.Connect()
        }
        'AzureAD'
        {
            $Global:MSCloudLoginConnectionProfile.AzureAD.Credentials           = $Credential
            $Global:MSCloudLoginConnectionProfile.AzureAD.ApplicationId         = $ApplicationId
            $Global:MSCloudLoginConnectionProfile.AzureAD.ApplicationSecret     = $ApplicationSecret
            $Global:MSCloudLoginConnectionProfile.AzureAD.TenantId              = $TenantId
            $Global:MSCloudLoginConnectionProfile.AzureAD.CertificateThumbprint = $CertificateThumbprint
            $Global:MSCloudLoginConnectionProfile.AzureAD.Connect()
        }
        'ExchangeOnline'
        {
            $Global:MSCloudLoginConnectionProfile.ExchangeOnline.Credentials           = $Credential
            $Global:MSCloudLoginConnectionProfile.ExchangeOnline.ApplicationId         = $ApplicationId
            $Global:MSCloudLoginConnectionProfile.ExchangeOnline.ApplicationSecret     = $ApplicationSecret
            $Global:MSCloudLoginConnectionProfile.ExchangeOnline.TenantId              = $TenantId
            $Global:MSCloudLoginConnectionProfile.ExchangeOnline.CertificateThumbprint = $CertificateThumbprint
            $Global:MSCloudLoginConnectionProfile.ExchangeOnline.SkipModuleReload      = $SkipModuleReload
            $Global:MSCloudLoginConnectionProfile.ExchangeOnline.Connect()
        }
        'Intune'
        {
            $Global:MSCloudLoginConnectionProfile.Intune.Credentials           = $Credential
            $Global:MSCloudLoginConnectionProfile.Intune.ApplicationId         = $ApplicationId
            $Global:MSCloudLoginConnectionProfile.Intune.ApplicationSecret     = $ApplicationSecret
            $Global:MSCloudLoginConnectionProfile.Intune.TenantId              = $TenantId
            $Global:MSCloudLoginConnectionProfile.Intune.CertificateThumbprint = $CertificateThumbprint
            $Global:MSCloudLoginConnectionProfile.Intune.Connect()
        }
        'MicrosoftGraph'
        {
            $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.Credentials           = $Credential
            $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.ApplicationId         = $ApplicationId
            $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.ApplicationSecret     = $ApplicationSecret
            $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.TenantId              = $TenantId
            $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.CertificateThumbprint = $CertificateThumbprint
            $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.ProfileName           = $ProfileName
            $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.Connect()
        }
        'MicrosoftTeams'
        {
            $Global:MSCloudLoginConnectionProfile.Teams.Credentials           = $Credential
            $Global:MSCloudLoginConnectionProfile.Teams.ApplicationId         = $ApplicationId
            $Global:MSCloudLoginConnectionProfile.Teams.ApplicationSecret     = $ApplicationSecret
            $Global:MSCloudLoginConnectionProfile.Teams.TenantId              = $TenantId
            $Global:MSCloudLoginConnectionProfile.Teams.CertificateThumbprint = $CertificateThumbprint
            $Global:MSCloudLoginConnectionProfile.Teams.CertificatePath       = $CertificatePath
            $Global:MSCloudLoginConnectionProfile.Teams.CertificatePassword   = $CertificatePassword
            $Global:MSCloudLoginConnectionProfile.Teams.Connect()
        }
        'PnP'
        {
            $Global:MSCloudLoginConnectionProfile.PnP.Credentials           = $Credential
            $Global:MSCloudLoginConnectionProfile.PnP.ApplicationId         = $ApplicationId
            $Global:MSCloudLoginConnectionProfile.PnP.ApplicationSecret     = $ApplicationSecret
            $Global:MSCloudLoginConnectionProfile.PnP.TenantId              = $TenantId
            $Global:MSCloudLoginConnectionProfile.PnP.CertificateThumbprint = $CertificateThumbprint
            $Global:MSCloudLoginConnectionProfile.PnP.CertificatePath       = $CertificatePath
            $Global:MSCloudLoginConnectionProfile.PnP.CertificatePassword   = $CertificatePassword

            # Mark as disconnected if we are trying to connect to a different url then we previously connected to.
            if ($Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl -ne $Url -or `
                -not $Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl -and `
                $Url -or (-not $Url -and -not $Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl))
            {
                $ForceRefresh = $false
                if ($Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl -ne $Url)
                {
                    $ForceRefresh = $true
                }
                $Global:MSCloudLoginConnectionProfile.PnP.Connected     = $false
                $Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl = $Url
                $Global:MSCloudLoginConnectionProfile.PnP.Connect($ForceRefresh)
            }
            else
            {
                try
                {
                    $contextUrl = (Get-PnPContext).Url
                    if ($contextUrl -ne $Url)
                    {
                        $ForceRefresh = $true
                        $Global:MSCloudLoginConnectionProfile.PnP.Connected     = $false
                        if ($url)
                        {
                            $Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl = $Url
                        }
                        else
                        {
                            $Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl = $Global:MSCloudLoginConnectionProfile.PnP.AdminUrl
                        }
                        $Global:MSCloudLoginConnectionProfile.PnP.Connect($ForceRefresh)
                    }
                }
                catch
                {
                    Write-Information -Message "Couldn't acquire PnP Context"
                }
            }

            # If the AdminUrl is empty and a URL was provided, assume that the url
            # provided is the admin center;
            if (-not $Global:MSCloudLoginConnectionProfile.PnP.AdminUrl -and $Url)
            {
                $Global:MSCloudLoginConnectionProfile.PnP.AdminUrl = $Url
            }
        }
        'PowerPlatforms'
        {
            $Global:MSCloudLoginConnectionProfile.PowerPlatform.Credentials           = $Credential
            $Global:MSCloudLoginConnectionProfile.PowerPlatform.ApplicationId         = $ApplicationId
            $Global:MSCloudLoginConnectionProfile.PowerPlatform.TenantId              = $TenantId
            $Global:MSCloudLoginConnectionProfile.PowerPlatform.CertificateThumbprint = $CertificateThumbprint
            $Global:MSCloudLoginConnectionProfile.PowerPlatform.Connect()
        }
        'SecurityComplianceCenter'
        {
            $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.Credentials           = $Credential
            $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.ApplicationId         = $ApplicationId
            $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.ApplicationSecret     = $ApplicationSecret
            $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.TenantId              = $TenantId
            $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.CertificateThumbprint = $CertificateThumbprint
            $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.CertificatePath       = $CertificatePath
            $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.CertificatePassword   = $CertificatePassword
            $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.SkipModuleReload      = $SkipModuleReload
            $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.Connect()
        }
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
        $Credential
    )
    Write-Verbose -Message "Connection to Microsoft Graph is required to automatically determine SharePoint Online admin URL..."
    try
    {
        $defaultDomain = Get-MgDomain -ErrorAction Stop| Where-Object { $_.Id -like "*.onmicrosoft.com" -and $_.IsInitial -eq $true } # We don't use IsDefault here because the default could be a custom domain
        if (-not $defaultDomain)
        {
            Connect-M365Tenant -Workload 'MicrosoftGraph' -Credential $Credential
            [Array]$defaultDomain = Get-MgDomain | Where-Object { $_.Id -like "*.onmicrosoft.com" -and $_.IsInitial -eq $true } # We don't use IsDefault here because the default could be a custom domain
        }
    }
    catch
    {
        Connect-M365Tenant -Workload 'MicrosoftGraph' -Credential $Credential
        try
        {
            [Array]$defaultDomain = Get-MgDomain -ErrorAction Stop | Where-Object { $_.Id -like "*.onmicrosoft.com" -and $_.IsInitial -eq $true }
        }
        catch
        {
            Write-Verbose -Message "Requesting access to read information about the domain"
            Connect-MgGraph -Scopes Domain.Read.All
            [Array]$defaultDomain = Get-MgDomain | Where-Object { $_.Id -like "*.onmicrosoft.com" -and $_.IsInitial -eq $true }
        }
    }

    $Global:CloudEnvironmentInfo = Get-CloudEnvironmentInfo -Credentials $Credential `
        -ApplicationId $ApplicationId `
        -TenantId $TenantId `
        -CertificateThumbprint $CertificateThumbprint
    if ($Global:CloudEnvironmentInfo.tenant_region_scope -eq 'USGov')
    {
        $Global:CloudEnvironment = 'GCCHigh'
    }

    if ($null -eq $defaultDomain)
    {
        if ($Global:CloudEnvironment -eq 'Germany')
        {
            [Array]$defaultDomain = Get-MgDomain | Where-Object { $_.Id -like "*.onmicrosoft.de" -and $_.IsInitial -eq $true }
            $domain = '.onmicrosoft.de'
            $tenantName = $defaultDomain.Id.Replace($domain, '')
            $spoAdminUrl = "https://$tenantName-admin.sharepoint.de"
        }
        elseif ($Global:CloudEnvironment -eq 'GCCHigh')
        {
            [Array]$defaultDomain = Get-MgDomain | Where-Object { $_.Id -like "*.onmicrosoft.us" -and $_.IsInitial -eq $true }
            $domain = '.onmicrosoft.us'
            $tenantName = $defaultDomain.Id.Replace($domain, '')
            $spoAdminUrl = "https://$tenantName-admin.sharepoint.us"
        }
        Write-Verbose -Message "SharePoint Online admin URL is $spoAdminUrl"
        return $spoAdminUrl
    }
    else
    {
        $domain = '.onmicrosoft.com'
        $tenantName = $defaultDomain.Id.Replace($domain, '')
        $extension = 'sharepoint.com'
        if ($Global:CloudEnvironment -eq 'Germany')
        {
            $extension = 'sharepoint.de'
        }
        elseif ($Global:CloudEnvironment -eq 'GCCHigh')
        {
            $extension = 'sharepoint.us'
        }
        $spoAdminUrl = "https://$tenantName-admin.$extension"
        Write-Verbose -Message "SharePoint Online admin URL is $spoAdminUrl"
        return $spoAdminUrl
    }
}

function Get-AzureADDLL
{
    [CmdletBinding()]
    [OutputType([System.String])]
    param(
    )
    [array]$AzureADModules = Get-Module -ListAvailable | Where-Object { $_.name -eq "AzureADPreview" }

    if ($AzureADModules.count -eq 0)
    {
        Throw "Can't find Azure AD DLL. Install the module manually 'Install-Module AzureADPreview'"
    }
    else
    {
        $AzureDLL = Join-Path (($AzureADModules | Sort-Object version -Descending | Select-Object -first 1).Path | Split-Path) Microsoft.IdentityModel.Clients.ActiveDirectory.dll
        return $AzureDLL
    }

}

function Get-TenantLoginEndPoint
{
    [CmdletBinding()]
    [OutputType([System.String])]
    Param(
        [Parameter(Mandatory = $True)]
        [System.String]
        $TenantName,
        [Parameter(Mandatory = $false)]
        [System.String]
        [ValidateSet('MicrosoftOnline', 'EvoSTS')]
        $LoginSource = "EvoSTS"
    )
    $TenantInfo = @{ }
    if ($LoginSource -eq "EvoSTS")
    {
        $webrequest = Invoke-WebRequest -Uri https://login.windows.net/$($TenantName)/.well-known/openid-configuration -UseBasicParsing
    }
    else
    {
        $webrequest = Invoke-WebRequest -Uri https://login.microsoftonline.com/$($TenantName)/.well-known/openid-configuration -UseBasicParsing
    }
    if ($webrequest.StatusCode -eq 200)
    {
        $TenantInfo = $webrequest.Content | ConvertFrom-Json
    }
    return $TenantInfo
}

function New-ADALServiceInfo
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [System.String]
        $TenantName,

        [Parameter(Mandatory = $True)]
        [System.String]
        $UserPrincipalName,

        [Parameter(Mandatory = $false)]
        [System.String]
        [ValidateSet('MicrosoftOnline', 'EvoSTS')]
        $LoginSource = "EvoSTS"
    )
    $AzureADDLL = Get-AzureADDLL
    if ([string]::IsNullOrEmpty($AzureADDLL))
    {
        Throw "Can't find Azure AD DLL"
        Exit
    }
    else
    {
        Write-Verbose -Message "AzureADDLL: $AzureADDLL"
        $tMod = [System.Reflection.Assembly]::LoadFrom($AzureADDLL)
    }

    $TenantInfo = Get-TenantLoginEndPoint -TenantName $TenantName
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
    $Service = @{ }
    $Service["authContext"] = [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext]::new($authority, $false)
    $Service["platformParam"] = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList $PromptBehavior
    $Service["userId"] = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList $UserPrincipalName, "OptionalDisplayableId"

    Write-Verbose -Message "Current Assembly for AD AuthenticationContext: $([Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext].Assembly | Out-String)"

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
            $authResult = $Global:ADALServicePoint.authContext.AcquireTokenAsync($ResourceURI, $clientId, $RedirectURI, $Global:ADALServicePoint.platformParam, $Global:ADALServicePoint.userId, "", "")
        }
        $AuthHeader = $authResult.result.CreateAuthorizationHeader()
    }
    catch
    {
        Throw "Can't create Authorization header: $_"
    }
    Return $AuthHeader
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
        $AzureADDLL = Get-AzureADDLL
        if ([string]::IsNullOrEmpty($AzureADDLL))
        {
            throw "Can't find Azure AD DLL"
        }
        [System.Reflection.Assembly]::LoadFrom($AzureADDLL) | Out-Null

        $context = [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext]::new($AuthUri, $false, [Microsoft.IdentityModel.Clients.ActiveDirectory.TokenCache]::DefaultShared)

        Write-Verbose -Message "AuthURI = $AuthURI"
        Write-Verbose -Message "TargetURI = $TargetUri"
        Write-Verbose -Message "ClientID = $ClientID"
        Write-Verbose -Message "Content = $context"
        $authResult = $context.AcquireTokenSilentAsync($TargetUri, $ClientId)
        $AccessToken = $authResult.result.AccessToken

        if ([System.String]::IsNullOrEmpty($AccessToken))
        {
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
                    $Credentials,

                    [Parameter(Mandatory = $true)]
                    [System.String]
                    $AzureADDLL
                )
                try
                {
                    [System.Reflection.Assembly]::LoadFrom($AzureADDLL) | Out-Null

                    $UserPasswordCreds = [Microsoft.IdentityModel.Clients.ActiveDirectory.UserPasswordCredential]::new($Credentials.UserName, $Credentials.Password)
                    $context = [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext]::new($AuthUri, $false, [Microsoft.IdentityModel.Clients.ActiveDirectory.TokenCache]::DefaultShared)
                    $authResult = $context.AcquireTokenSilentAsync($TargetUri, $ClientId)

                    if ($null -eq $authResult.result)
                    {
                        $authResult = [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContextIntegratedAuthExtensions]::AcquireTokenAsync($context, $targetUri, $ClientId, $UserPasswordCreds)
                    }
                    $token = $authResult.result.AccessToken
                    return $token
                }
                catch
                {
                    Write-Host "Error {Get-AccessToken}: $_"
                    return $null
                }
            } -ArgumentList @($targetUri, $AuthUri, $ClientId, $Credentials, $AzureADDLL) | Out-Null
            $job = Get-Job | Where-Object -FilterScript { $_.Name -eq $jobName }
            do
            {
                Start-Sleep -Seconds 1
            } while ($job.JobStateInfo.State -ne "Completed")
            $AccessToken = Receive-Job -Name $jobName
        }
        Write-Verbose "Token Found --> $AccessToken"
        return $AccessToken
    }
    catch
    {
        Write-Verbose $_
        throw $_
    }
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
            $authContext = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext("https://login.windows.net/common");
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

function Test-MSCloudLoginCommand
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    Param(
        [Parameter(Mandatory = $true)]
        [System.String]
        $Command
    )

    try
    {
        $testResult = Invoke-Command $Command
        return $true
    }
    catch
    {
        return $false
    }
}

function Get-CloudEnvironmentInfo
{
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter()]
        [System.Management.Automation.PSCredential]
        $Credentials,

        [Parameter()]
        [System.String]
        $ApplicationId,

        [Parameter()]
        [System.String]
        $TenantId,

        [Parameter()]
        [System.String]
        $CertificateThumbprint
    )

    try
    {
        if ($null -ne $Credentials)
        {
            $tenantName = $Credentials.UserName.Split('@')[1]
        }
        else
        {
            $tenantName = Get-MSCloudLoginOrganizationName -ApplicationId $ApplicationId `
                -TenantId $TenantId `
                -CertificateThumbprint $CertificateThumbprint
        }
        $response = Invoke-WebRequest -Uri "https://login.microsoftonline.com/$tenantName/v2.0/.well-known/openid-configuration" -Method Get -UseBasicParsing

        $content = $response.Content
        $result = ConvertFrom-Json $content
        return $result
    }
    catch
    {
        throw $_
    }
}

function Get-TenantDomain
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

    Connect-M365Tenant -Workload MicrosoftGraph -ApplicationId $ApplicationId -TenantId $TenantId -CertificateThumbprint $CertificateThumbprint

    $domain = Get-MgDomain  | where-object { $_.IsInitial -eq $True }

    if ($null -ne $domain)
    {
        return $domain.Id.split(".")[0]
    }
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

    Connect-M365Tenant -Workload MicrosoftGraph -ApplicationId $ApplicationId -TenantId $TenantId -CertificateThumbprint $CertificateThumbprint

    try
    {
        $domain = Get-MgDomain -ErrorAction Stop | where-object { $_.IsInitial -eq $True }

        if ($null -ne $domain)
        {
            return $domain.Id
        }
    }
    catch
    {
        Write-Verbose -Message "Couldn't get domain. Using TenantId instead"
        return $TenantId
    }
}
