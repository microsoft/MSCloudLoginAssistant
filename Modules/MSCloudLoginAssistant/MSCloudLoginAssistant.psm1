<#
.SYNOPSIS
    The Test-MSCloudLogin function is used to assist with logging in to various Microsoft Cloud services, such as Azure, SharePoint Online, and SharePoint PnP.
.EXAMPLE
    Test-MSCloudLogin -Platform AzureAD -Verbose
.EXAMPLE
    Test-MSCloudLogin -Platform PnP
.PARAMETER Platform
    The Platform parameter specifies which cloud service for which we are testing the login state. Possible values are Azure, AzureAD, SharePointOnline, ExchangeOnline, SecurityComplianceCenter, MSOnline, PnP, PowerPlatforms, MicrosoftTeams, and SkypeForBusiness.
.NOTES
    Created & maintained by Brian Lalancette (@brianlala), 2019.
.LINK
    https://github.com/Microsoft/MSCloudLoginAssistant
#>

function Test-MSCloudLogin
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateSet("Azure","AzureAD","SharePointOnline","ExchangeOnline", `
                     "SecurityComplianceCenter","MSOnline","PnP","PowerPlatforms", `
                     "MicrosoftTeams","SkypeForBusiness")]
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
    }

    if ($null -eq $Global:UseModernAuth)
    {
        $Global:UseModernAuth = $UseModernAuth.IsPresent
    }

    $Global:DomainName = $Global:o365Credential.UserName.Split('@')[1]

    switch ($Platform)
    {
        'Azure'
        {
            Connect-MSCloudLoginAzure
            return
        }
        'AzureAD'
        {
            Connect-MSCloudLoginAzureAD
            return
        }
        'SharePointOnline'
        {
            $moduleName = "Microsoft.Online.SharePoint.PowerShell"
            if ([string]::IsNullOrEmpty($ConnectionUrl))
            {
                $Global:spoAdminUrl = Get-SPOAdminUrl -CloudCredential $CloudCredential
            }
            else
            {
                $Global:spoAdminUrl = $ConnectionUrl
            }
            $testCmdlet = "Get-SPOSite";
            $exceptionStringMFA = "sign-in name or password does not match one in the Microsoft account system";
            $clientid = "9bc3ab49-b65d-410a-85ad-de819febfddc";
            $ResourceURI = $Global:spoAdminUrl;
            $RedirectURI = "urn:ietf:wg:oauth:2.0:oob";
            $connectCmdlet = "Connect-SPOService";
            $connectCmdletArgs = "-Url $Global:spoAdminUrl -Credential `$Global:o365Credential";
            $connectCmdletMfaRetryArgs = $connectCmdletArgs.Replace("-Credential `$Global:o365Credential","");
            $variablePrefix = "spo"
        }
        'ExchangeOnline'
        {
            Connect-MSCloudLoginExchangeOnline
            return
        }
        'SecurityComplianceCenter'
        {
            Connect-MSCloudLoginSecurityCompliance
            return
        }
        'MSOnline'
        {
            Connect-MSCloudLoginMSOnline
            return
        }
        'PnP'
        {
            Connect-MSCloudLoginPnP -ConnectionUrl $ConnectionUrl
            return
        }
        'MicrosoftTeams'
        {
            Connect-MSCloudLoginTeams
            return
        }
        'SkypeForBusiness'
        {
            Connect-MSCloudLoginSkypeForBusiness
            return
        }
        'PowerPlatforms'
        {
            $moduleName = "Microsoft.PowerApps.Administration.PowerShell"
            $WarningPreference = 'SilentlyContinue'
            Import-Module -Name $moduleName -Global -ErrorAction SilentlyContinue -Force | Out-Null
            $WarningPreference = 'Continue'
            if ($null -eq $Global:currentSession -or $global:currentSession.loggedIn -eq $false -or `
                $global:currentSession.expiresOn -lt (Get-Date))
            {
                $tenantName = $Global:o365Credential.UserName.Split('@')[1]
                $tenantInfo = Get-TenantLoginEndPoint -TenantName $tenantName
                $tenantId = $tenantInfo.issuer.Replace("https://", "").Split('/')[1]
                $Endpoint = 'prod'

                if ($tenantInfo.tenant_region_sub_scope -eq 'GCC')
                {
                    $Endpoint = 'usgov'
                }
                $ManagementAudience = "https://management.azure.com/"
                $TokenInfoManagement = Get-PowerPlatformTokenInfo -Audience $ManagementAudience -Credentials $Global:o365Credential
                $Global:currentSession = @{
                    loggedIn = $true;
                    idToken = $TokenInfoManagement.JwtToken;
                    upn = $TokenInfoManagement.Claims.upn;
                    tenantId = $tenantId;
                    userId = $TokenInfoManagement.Claims.oid;
                    refreshToken = $TokenInfoManagement.RefreshToken;
                    expiresOn = (Get-Date).AddHours(8);
                    resourceTokens = @{
                        $ManagementAudience = @{
                            accessToken = $TokenInfoManagement.AccessToken;
                            expiresOn = $TokenInfoManagement.ExpiresOn.DateTime;
                        }
                    };
                    selectedEnvironment = "~default";
                    flowEndpoint =
                        switch ($Endpoint)
                        {
                            "prod"      { "api.flow.microsoft.com" }
                            "usgov"     { "gov.api.flow.microsoft.us" }
                            "usgovhigh" { "high.api.flow.microsoft.us" }
                            "preview"   { "preview.api.flow.microsoft.com" }
                            "tip1"      { "tip1.api.flow.microsoft.com"}
                            "tip2"      { "tip2.api.flow.microsoft.com" }
                            default     { throw "Unsupported endpoint '$Endpoint'"}
                        };
                    powerAppsEndpoint =
                        switch ($Endpoint)
                        {
                            "prod"      { "api.powerapps.com" }
                            "usgov"     { "gov.api.powerapps.us" }
                            "usgovhigh" { "high.api.powerapps.us" }
                            "preview"   { "preview.api.powerapps.com" }
                            "tip1"      { "tip1.api.powerapps.com"}
                            "tip2"      { "tip2.api.powerapps.com" }
                            default     { throw "Unsupported endpoint '$Endpoint'"}
                        };
                    bapEndpoint =
                        switch ($Endpoint)
                        {
                            "prod"      { "api.bap.microsoft.com" }
                            "usgov"     { "gov.api.bap.microsoft.us" }
                            "usgovhigh" { "high.api.bap.microsoft.us" }
                            "preview"   { "preview.api.bap.microsoft.com" }
                            "tip1"      { "tip1.api.bap.microsoft.com"}
                            "tip2"      { "tip2.api.bap.microsoft.com" }
                            default     { throw "Unsupported endpoint '$Endpoint'"}
                        };
                    graphEndpoint =
                        switch ($Endpoint)
                        {
                            "prod"      { "graph.windows.net" }
                            "usgov"     { "graph.windows.net" }
                            "usgovhigh" { "graph.windows.net" }
                            "preview"   { "graph.windows.net" }
                            "tip1"      { "graph.windows.net"}
                            "tip2"      { "graph.windows.net" }
                            default     { throw "Unsupported endpoint '$Endpoint'"}
                        };
                    cdsOneEndpoint =
                        switch ($Endpoint)
                        {
                            "prod"      { "api.cds.microsoft.com" }
                            "usgov"     { "gov.api.cds.microsoft.us" }
                            "usgovhigh" { "high.api.cds.microsoft.us" }
                            "preview"   { "preview.api.cds.microsoft.com" }
                            "tip1"      { "tip1.api.cds.microsoft.com"}
                            "tip2"      { "tip2.api.cds.microsoft.com" }
                            default     { throw "Unsupported endpoint '$Endpoint'"}
                        };
                };

                $Route = "https://{bapEndpoint}/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments/~default?`$expand=permissions&api-version={apiVersion}" `

                $uri = $Route `
                    | ReplaceMacro -Macro "{apiVersion}"  -Value $ApiVersion `
                    | ReplaceMacro -Macro "{flowEndpoint}" -Value $global:currentSession.flowEndpoint `
                    | ReplaceMacro -Macro "{powerAppsEndpoint}" -Value $global:currentSession.powerAppsEndpoint `
                    | ReplaceMacro -Macro "{bapEndpoint}" -Value $global:currentSession.bapEndpoint `
                    | ReplaceMacro -Macro "{graphEndpoint}" -Value $global:currentSession.graphEndpoint `
                    | ReplaceMacro -Macro "{cdsOneEndpoint}" -Value $global:currentSession.cdsOneEndpoint;

                $hostMapping = @{
                    "management.azure.com"        = "https://management.azure.com/";
                    "api.powerapps.com"           = "https://service.powerapps.com/";
                    "tip1.api.powerapps.com"      = "https://service.powerapps.com/";
                    "tip2.api.powerapps.com"      = "https://service.powerapps.com/";
                    "graph.windows.net"           = "https://graph.windows.net/";
                    "api.bap.microsoft.com"       = "https://service.powerapps.com/";
                    "tip1.api.bap.microsoft.com"  = "https://service.powerapps.com/";
                    "tip2.api.bap.microsoft.com"  = "https://service.powerapps.com/";
                    "api.flow.microsoft.com"      = "https://service.flow.microsoft.com/";
                    "tip1.api.flow.microsoft.com" = "https://service.flow.microsoft.com/";
                    "tip2.api.flow.microsoft.com" = "https://service.flow.microsoft.com/";
                    "gov.api.bap.microsoft.us"    = "https://gov.service.powerapps.us/";
                    "high.api.bap.microsoft.us"   = "https://high.service.powerapps.us/";
                    "gov.api.powerapps.us"        = "https://gov.service.powerapps.us/";
                    "high.api.powerapps.us"       = "https://high.service.powerapps.us/";
                    "gov.api.flow.microsoft.us"   = "https://gov.service.flow.microsoft.us/";
                    "high.api.flow.microsoft.us"  = "https://high.service.flow.microsoft.us/";
                }

                $uriObject = New-Object System.Uri($Uri)
                $uriObjectHost = $uriObject.Host
                $ServiceAudience = $hostMapping[$uriObjectHost]
                $TokenInfoService = Get-PowerPlatformTokenInfo -Audience $ServiceAudience -Credentials $Global:o365Credential
                $ServiceResourceToken = @{
                    accessToken = $TokenInfoService.AccessToken;
                    expiresOn = $TokenInfoService.ExpiresOn.DateTime;
                }
                $Global:currentSession.resourceTokens.Add($ServiceAudience, $ServiceResourceToken)
            }
            return
        }
    }

    New-Variable -Name $variablePrefix"LoginSucceeded" -Value $false -Scope Global -Option AllScope -Force
    Write-Debug -Message `$$variablePrefix"LoginSucceeded is '$(Get-Variable -Name $($variablePrefix+"LoginSucceeded") -ValueOnly -Scope Global -ErrorAction SilentlyContinue)'."
    try
    {
        Write-Verbose -Message "Checking $Platform login..."
        # Run a simple command to check if we are logged in
        Write-Debug -Message "Running '$testCmdlet -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null'"
        Invoke-Expression -Command "$testCmdlet -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null"
        if ($? -eq $false)
        {
            throw
        }
        elseif ($Platform -eq "PnP")
        {
            $CurrentPnPConnection = (Get-PnPConnection).Url
            if ($ConnectionUrl -ne $CurrentPnPConnection)
            {
                throw "PnP requires you to reconnect to new location using $connectCmdlet"
            }
            else
            {
                Write-Verbose -Message "You are already logged in to $Platform."
            }
        }
        else
        {
            Write-Debug -Message "'$testCmdlet -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null' succeeded."
            Write-Verbose -Message "You are already logged in to $Platform."
        }
    }
    catch
    {
        if ($_.Exception -like "*$connectCmdlet*" -or $_.Exception -like "*The access token expiry*" -or `
            $_.Exception -like "*Authentication_ExpiredToken*")
        {
            Write-Debug -Message "Running '$testCmdlet' failed on initial attempt."
            try
            {
                # Prompt for Windows-style credentials if we don't already have a credential object and not logging into Azure
                if ($null -eq $Global:o365Credential -and $Platform -ne "Azure")
                {
                    Write-Host -ForegroundColor Cyan " - Prompting for Microsoft Online credentials..."
                    $Global:o365Credential = Get-Credential -Message "Please enter your credentials for MS Online Services:"
                    if ($null -eq $Global:o365Credential)
                    {
                        throw "Microsoft Online credentials must be supplied."
                    }
                    Write-Verbose -Message "Will now attempt to use credential for '$($Global:o365Credential.UserName)'..."
                }
                if ($_.Exception -like "*The access token expiry*")
                {
                    throw
                }
                if ($Global:UseModernAuth -eq $True)
                {
                    throw
                }
                Write-Verbose -Message "Running '$connectCmdlet -ErrorAction Stop $connectCmdletArgs -ErrorVariable `$err | Out-Null'"
                Invoke-Expression -Command "$connectCmdlet -ErrorAction Stop $connectCmdletArgs -ErrorVariable `$err | Out-Null"
                if ($? -eq $false -or $err)
                {
                    throw
                }
                else
                {
                    New-Variable -Name $variablePrefix"LoginSucceeded" -Value $true -Scope Global -Option AllScope -Force
                    Write-Debug -Message `$$variablePrefix"LoginSucceeded is now '$(Get-Variable -Name $($variablePrefix+"LoginSucceeded") -ValueOnly -Scope Global -ErrorAction SilentlyContinue)'."
                }
            }
            catch
            {
                Write-Debug -Message "Login using '$connectCmdlet' and '$connectCmdletArgs' failed on initial attempt."
                if ($_.Exception -like "*User canceled authentication*")
                {
                    throw "User canceled authentication"
                }
                elseif ($_.Exception -like "*The user name or password is incorrect*" -or $_.Exception -like "*ID3242*")
                {
                    throw  "Bad credentials were supplied"
                }
                elseif (($_.Exception -like "*$exceptionStringMFA*") -or `
                        ($_.Exception -like "*Sequence contains no elements*") -or `
                        ($_.Exception -like "*System.Reflection.TargetInvocationException: Exception has been thrown*" -and $Platform -eq "PNP") -or `
                        ($_.Exception -like "*or the web site does not support SharePoint Online credentials*" -and $Platform -eq "SharePointOnline") -or `
                        ($_.Exception -like "*The access token expiry*" -and $Platform -eq "Azure") -or `
                        $Global:UseModernAuth -eq $True)
                {
                    Write-Verbose -Message "The specified account is configured for Multi-Factor Authentication. Please re-enter your credentials."

                    try
                    {
                        Write-Debug -Message "Replacing connection parameters '$connectCmdletArgs' with '$connectCmdletMfaRetryArgs'..."
                        if ($Platform -ne "SharePointOnline" -and $Platform -ne "MicrosoftTeams")
                        {
                            $AuthHeader = Get-AuthHeader -UserPrincipalName $Global:o365Credential.UserName -ResourceURI $ResourceURI -clientID $clientID -RedirectURI $RedirectURI
                            $AuthToken = $AuthHeader.split(" ")[1]
                        }
                        Invoke-Expression -Command "$connectCmdlet -ErrorAction Stop $connectCmdletMfaRetryArgs | Out-Null"
                        if ($? -eq $false)
                        {
                            throw
                        }
                        else
                        {
                            New-Variable -Name $variablePrefix"LoginSucceeded" -Value $true -Scope Global -Option AllScope -Force
                            Write-Debug $variablePrefix"LoginSucceeded is now '$(Get-Variable -Name $($variablePrefix+"LoginSucceeded") -ValueOnly -Scope Global -ErrorAction SilentlyContinue)'."
                            $Global:UseModernAuth = $True
                        }
                    }
                    catch
                    {
                        Write-Debug -Message "Login using '$connectCmdlet' and '$connectCmdletMfaRetryArgs' failed."
                        Write-Host -ForegroundColor Red $_.Exception
                        throw $_
                    }
                }
                elseif (($Platform -eq 'AzureAD' -and $_.Exception -like '*unknown_user_type*') -or `
                        ($Platform -eq 'MSOnline' -and $_.Exception -like '*Bad username or password*'))
                {
                    $originalArgs = $connectCmdletArgs

                    $paramName = "-AzureEnvironmentName"
                    if ($Platform -eq 'MSOnline')
                    {
                        $paramName = '-AzureEnvironment'
                    }

                    # Try connecting to other Azure Clouds
                    try
                    {
                        $connectCmdletArgs = $originalArgs + " $paramName AzureChinaCloud"
                        Invoke-Expression -Command "$connectCmdlet -ErrorAction Stop $connectCmdletArgs -ErrorVariable `$err | Out-Null"
                        $Global:CloudEnvironment = 'China'
                    }
                    catch
                    {
                        try
                        {
                            $connectCmdletArgs = $originalArgs + " $paramName AzureUSGovernment"
                            Invoke-Expression -Command "$connectCmdlet -ErrorAction Stop $connectCmdletArgs -ErrorVariable `$err | Out-Null"
                            $Global:CloudEnvironment = 'USGovernment'
                        }
                        catch
                        {
                            if ($_.Exception -like '*AADSTS50076: Due to a configuration change made by your administrator*' -and `
                            $Platform -eq 'AzureAD')
                            {
                                try
                                {
                                    Connect-AzureAD -AzureEnvironmentName AzureUSGovernment -AccountId $Global:o365Credential.UserName | Out-Null
                                    $Global:CloudEnvironment = "GCCHigh"
                                    $Global:IsMFAAuth = $true
                                }
                                catch
                                {
                                    throw $_
                                }
                            }
                            else
                            {
                                try {
                                    $connectCmdletArgs = $originalArgs + " $paramName AzureGermanyCloud"
                                    Invoke-Expression -Command "$connectCmdlet -ErrorAction Stop $connectCmdletArgs -ErrorVariable `$err | Out-Null"
                                    $Global:CloudEnvironment = 'Germany'
                                }
                                catch {
                                    throw $_
                                }
                            }
                        }
                    }
                }
                elseif ($Platform -eq 'MicrosoftTeams' -and $_.Exception -like '*unknown_user_type*')
                {
                    $originalArgs = $connectCmdletArgs

                    $paramName = "-TeamsEnvironmentName"

                    # Try connecting to other Azure Clouds
                    try
                    {
                        $connectCmdletArgs = $originalArgs + " $paramName TeamsGCCH"
                        Invoke-Expression -Command "$connectCmdlet -ErrorAction Stop $connectCmdletArgs -ErrorVariable `$err | Out-Null"
                    }
                    catch
                    {
                        try
                        {
                            $connectCmdletArgs = $originalArgs + " $paramName TeamsDOD"
                            Invoke-Expression -Command "$connectCmdlet -ErrorAction Stop $connectCmdletArgs -ErrorVariable `$err | Out-Null"
                        }
                        catch
                        {
                            try
                            {
                                $connectCmdletArgs = $originalArgs + " $paramName TeamsGCCH"
                                Invoke-Expression -Command "$connectCmdlet -ErrorAction Stop $connectCmdletArgs -ErrorVariable `$err | Out-Null"
                            }
                            catch
                            {
                                throw $_
                            }
                        }
                    }
                }
                elseif (($Platform -eq 'SharePointOnline' -and $_.Exception -like '*Could not connect to SharePoint Online*') -or `
                        ($Platform -eq 'PnP' -and $_.Exception -like '*The remote name could not be resolved*'))
                {
                    try
                    {
                        $connectCmdletArgs = $connectCmdletArgs.Replace(".sharepoint.com", ".sharepoint.us")
                        Invoke-Expression -Command "$connectCmdlet -ErrorAction Stop $connectCmdletArgs -ErrorVariable `$err | Out-Null"
                    }
                    catch
                    {
                        if ($_.Exception -like '*The sign-in name or password does not match one in the Microsoft account system*')
                        {
                            $connectCmdletArgs = $connectCmdletArgs.Replace("-Credential `$Global:o365Credential", '')
                            $connectCmdletArgs = $connectCmdletArgs.Replace("-Credentials `$Global:o365Credential", '')
                            Invoke-Expression -Command "$connectCmdlet -ErrorAction Stop $connectCmdletArgs -ErrorVariable `$err | Out-Null"
                        }
                        else
                        {
                            throw $_
                        }
                    }
                }
                else
                {
                    Write-Host -ForegroundColor Red $_.Exception
                    throw $_
                }
            }
        }
        elseif ($_.Exception -like "*Unable to acquire token for tenant*")
        {
            Write-Host -ForegroundColor Red $_.Exception
        }
        elseif ($_.Exception -like "*null array*")
        {
            # Do nothing
        }
        elseif ($_.Exception -like "*$testCmdlet*")
        {
            # If the exception contains the name of the cmdlet we're trying to run, we probably don't have the required module installed yet
            throw "It appears you don't have the module for '$Platform' installed, or it isn't loaded.`nPlease install/load the module and try again. `nYou can quickly and easily install the '$moduleName' module with: `n`"Install-Module -Name $moduleName`""
        }
        elseif ($_.Exception -like "*this.Client.SubscriptionId*" -and $Platform -eq "Azure")
        {
            throw "It appears there are no Azure subscriptions associated with the account '$($Global:o365Credential.UserName)'."
        }
        else
        {
            Write-Host -ForegroundColor Red $_.Exception
        }
    }
    finally
    {
        if (Get-Variable -Name $variablePrefix"LoginSucceeded" -ValueOnly -Scope "Global")
        {
            Write-Verbose -Message " - Successfully logged in to $Platform."
            # Extra step needed if we're logging into Azure - in case we have multiple subs we need to prompt for one
            if ($Platform -eq "Azure")
            {
                [array]$subscriptions = Get-AzSubscription -WarningAction Continue
                # Prompt for a subscription in case we have more than one
                if ($subscriptions.Count -gt 1)
                {
                    Write-Host -ForegroundColor Cyan " - Prompting for Azure subscription..."
                    $Global:subscriptionDetails = Get-AzSubscription -WarningAction SilentlyContinue | Sort-Object Name | Out-GridView -Title "Select ONE subscription..." -PassThru
                    if ($null -eq $subscriptionDetails)
                    {
                        throw " - A subscription must be selected."
                    }
                    elseif ($subscriptionDetails.Count -gt 1)
                    {
                        throw " - Please select *only one* subscription."
                    }
                    Write-Host -ForegroundColor White " - Setting active subscription to '$($Global:subscriptionDetails.Name)'..."
                    Set-AzContext -Subscription $Global:subscriptionDetails.Id
                }
            }

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
        $CloudCredential
    )

    Write-Verbose -Message "Connection to Azure AD is required to automatically determine SharePoint Online admin URL..."
    Test-MSCloudLogin -Platform AzureAD -CloudCredential $CloudCredential
    Write-Verbose -Message "Getting SharePoint Online admin URL..."
    $defaultDomain = Get-AzureADDomain | Where-Object {$_.Name -like "*.onmicrosoft.com" -and $_.IsInitial -eq $true} # We don't use IsDefault here because the default could be a custom domain

    if ($null -eq $defaultDomain)
    {
        $defaultDomain = Get-AzureADDomain | Where-Object {$_.Name -like "*.onmicrosoft.de" -and $_.IsInitial -eq $true}
        $domain = '.onmicrosoft.de'
        $tenantName = $defaultDomain[0].Name.Replace($domain, '')
        if ($Global:CloudEnvironment -eq 'Germany')
        {
            $spoAdminUrl = "https://$tenantName-admin.sharepoint.de"
        }
        elseif ($Global:CloudEnvironment -eq 'GCCHigh')
        {
            $spoAdminUrl = "https://$tenantName-admin.sharepoint.us"
        }
        Write-Verbose -Message "SharePoint Online admin URL is $spoAdminUrl"
        return $spoAdminUrl
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
    [array]$AzureADModules = Get-Module -ListAvailable | Where-Object {$_.name -eq "AzureAD"}
    if ($AzureADModules.count -eq 0)
    {
        Throw "Can't find Azure AD DLL. Install the module manually 'Install-Module AzureAD'"
    }
    else
    {
        $AzureDLL = Join-Path (($AzureADModules | Sort-Object version -Descending | Select-Object -first 1).Path | split-Path) Microsoft.IdentityModel.Clients.ActiveDirectory.dll
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
        [ValidateSet('MicrosoftOnline','EvoSTS')]
        $LoginSource = "EvoSTS"
    )
    $TenantInfo = @{}
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
        [ValidateSet('MicrosoftOnline','EvoSTS')]
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
    $Service = @{}
    $Service["authContext"] = [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext]::new($authority, $false)
    $Service["platformParam"] = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList $PromptBehavior
    $Service["userId"] = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList $UserPrincipalName, "OptionalDisplayableId"
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
            Write-Debug "Creating a new Token"
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
        } -ArgumentList @($targetUri, $AuthUri, $ClientId, $Credentials) | Out-Null
        $job = Get-Job | Where-Object -FilterScript {$_.Name -eq $jobName}
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
        $TargetDomain
    )
    $overrideDiscoveryUri = "http://lyncdiscover." + $TargetDomain;
    $desiredLink = "External/RemotePowerShell";
    $liveIdUrl = $overrideDiscoveryUri.ToString() + "?Domain=" + $TargetDomain

    $xml = Get-RTCXml -Url $liveIdUrl
    $root = $xml.AutodiscoverResponse.Root

    $domain = $root.Link | Where-Object -FilterScript {$_.Token -eq 'domain'}
    if ($null -eq $domain)
    {
        $redirect = $root.Link | Where-Object -FilterScript {$_.Token -eq 'redirect'}

        if ($null -eq $redirect)
        {
            throw "Could not properly retrieve the Skype for Business service endpoint for $TargetDomain"
        }

        while ($null -ne $redirect)
        {
            $xml = Get-RTCXml -Url $redirect.href
            $root = $xml.AutodiscoverResponse.Root
            $domain = $root.Link | Where-Object -FilterScript {$_.Token -eq 'domain'}
            if ($null -eq $domain)
            {
                $redirect = $root.Link | Where-Object -FilterScript {$_.Token -eq 'redirect'}
            }
            else
            {
                $redirect = $null
            }
        }
    }
    $xml = Get-RTCXml -Url $domain.href
    $endpoint = $xml.AutodiscoverResponse.Domain.Link | Where-Object -FilterScript {$_.token -eq $desiredLink}
    $endpointUrl = $endpoint.href.Replace("/OcsPowershellLiveId","/OcsPowershellOAuth")
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
        $clientId = $header.Substring($start, $end-$start)
    }

    # Get Auth Url
    $start = $header.IndexOf("authorization_uri=") + 19
    $end = $header.IndexOf("`"", $start)

    $authUrl = $null
    if ($end -gt $start)
    {
        $authUrl = $header.Substring($start, $end-$start)
    }

    $result = @{
        ClientID = $clientId
        AuthUrl = $authUrl
    }
    return $result
}

function Get-MicrosoftTeamsAzureName
{
    [CmdletBinding()]
    [OutputType([System.String])]
    param(
        [Parameter()]
        [System.String]
        [ValidateSet('TeamsCloud', 'TeamsGCCH', 'TeamsDOD')]
        $TeamsEnvironmentName
    )

    if ($null -eq $TeamsEnvironmentName)
    {
        return "AzureCloud"
    }
    return $TeamsEnvironmentName
}

function Get-MicrosoftTeamsAzureEnvironmentName
{
    [CmdletBinding()]
    [OutputType([System.String])]
    param(
        [Parameter(Mandatory = $true)]
        [System.String]
        [ValidateSet('TeamsCloud', 'TeamsGCCH', 'TeamsDOD')]
        $TeamsEnvironmentName
    )

    if ($TeamsEnvironmentName -eq 'AzureCloud')
    {
        return 'AzureCloud'
    }
    return 'AzureUSGovernment'
}

function Get-MicrosoftTeamsMSGraphEndPoint
{
    [CmdletBinding()]
    [OutPutType([System.String])]
    param(
        [Parameter(Mandatory = $true)]
        [System.String]
        [ValidateSet('TeamsCloud', 'TeamsGCCH', 'TeamsDOD')]
        $TeamsEnvironmentName
    )

    if ($TeamsEnvironmentName -eq 'TeamsCloud')
    {
        return "https://graph.microsoft.com"
    }
    elseif ($TeamsEnvironmentName -eq 'TeamsGCCH')
    {
        return "https://graph.microsoft.us"
    }
    return "https://dod-graph.microsoft.us"
}

function Get-PowerPlatformTokenInfo
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [System.String]
        $Audience,

        [Parameter()]
        [System.Management.Automation.PSCredential]
        $Credentials
    )

    $jobName = 'AcquireTokenAsync' + (New-Guid).ToString()
    Start-Job -Name $jobName -ScriptBlock {
        Param(
            [Parameter(Mandatory=$true)]
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

    $job = Get-Job | Where-Object -FilterScript {$_.Name -eq $jobName}
    do
    {
        Start-Sleep -Seconds 1
    } while ($job.JobStateInfo.State -ne "Completed")
    $TokenInfo = Receive-Job -Name $jobName
    return $TokenInfo
}
