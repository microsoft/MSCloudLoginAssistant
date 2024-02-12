function Connect-M365Tenant
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet('ExchangeOnline', `
                'SecurityComplianceCenter', 'PnP', 'PowerPlatforms', `
                'MicrosoftTeams', 'MicrosoftGraph', 'Tasks')]
        [System.String]
        $Workload,

        [Parameter()]
        [System.String]
        $Url,

        [Parameter()]
        [Alias('o365Credential')]
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
        [Switch]
        $Identity,

        [Parameter()]
        [SecureString[]]
        $AccessTokens
    )

    $VerbosePreference = 'SilentlyContinue'

    $workloadInternalName = $Workload

    if ($Workload -eq 'MicrosoftTeams')
    {
        $workloadInternalName = 'Teams'
    }
    elseif ($Workload -eq 'PowerPlatforms')
    {
        $workloadInternalName = 'PowerPlatform'
    }

    if ($null -eq $Global:MSCloudLoginConnectionProfile)
    {
        $Global:MSCloudLoginConnectionProfile = New-Object MSCloudLoginConnectionProfile
    }
    # Only validate the parameters if we are not already connected
    elseif ( $Global:MSCloudLoginConnectionProfile.$workloadInternalName.Connected `
            -and (Compare-InputParametersForChange -CurrentParamSet $PSBoundParameters))
    {
        Write-Verbose -Message 'Resetting connection profile'
        $Global:MSCloudLoginConnectionProfile.$workloadInternalName.Connected = $false
    }

    Write-Verbose -Message "Trying to connect to platform {$Workload}"
    switch ($Workload)
    {
        'ExchangeOnline'
        {
            $Global:MSCloudLoginConnectionProfile.ExchangeOnline.Credentials = $Credential
            $Global:MSCloudLoginConnectionProfile.ExchangeOnline.ApplicationId = $ApplicationId
            $Global:MSCloudLoginConnectionProfile.ExchangeOnline.ApplicationSecret = $ApplicationSecret
            $Global:MSCloudLoginConnectionProfile.ExchangeOnline.TenantId = $TenantId
            $Global:MSCloudLoginConnectionProfile.ExchangeOnline.CertificateThumbprint = $CertificateThumbprint
            $Global:MSCloudLoginConnectionProfile.ExchangeOnline.SkipModuleReload = $SkipModuleReload
            $Global:MSCloudLoginConnectionProfile.ExchangeOnline.AccessTokens = $AccessTokens
            $Global:MSCloudLoginConnectionProfile.ExchangeOnline.Identity = $Identity
            $Global:MSCloudLoginConnectionProfile.ExchangeOnline.Connect()
        }
        'MicrosoftGraph'
        {
            $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.Credentials = $Credential
            $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.ApplicationId = $ApplicationId
            $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.ApplicationSecret = $ApplicationSecret
            $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.TenantId = $TenantId
            $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.CertificateThumbprint = $CertificateThumbprint
            $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.AccessTokens = $AccessTokens
            $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.Identity = $Identity
            $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.Connect()
        }
        'MicrosoftTeams'
        {
            $Global:MSCloudLoginConnectionProfile.Teams.Credentials = $Credential
            $Global:MSCloudLoginConnectionProfile.Teams.ApplicationId = $ApplicationId
            $Global:MSCloudLoginConnectionProfile.Teams.ApplicationSecret = $ApplicationSecret
            $Global:MSCloudLoginConnectionProfile.Teams.TenantId = $TenantId
            $Global:MSCloudLoginConnectionProfile.Teams.CertificateThumbprint = $CertificateThumbprint
            $Global:MSCloudLoginConnectionProfile.Teams.CertificatePath = $CertificatePath
            $Global:MSCloudLoginConnectionProfile.Teams.CertificatePassword = $CertificatePassword
            $Global:MSCloudLoginConnectionProfile.Teams.AccessTokens = $AccessTokens
            $Global:MSCloudLoginConnectionProfile.Teams.Identity = $Identity
            $Global:MSCloudLoginConnectionProfile.Teams.Connect()
        }
        'PnP'
        {
            $Global:MSCloudLoginConnectionProfile.PnP.Credentials = $Credential
            $Global:MSCloudLoginConnectionProfile.PnP.ApplicationId = $ApplicationId
            $Global:MSCloudLoginConnectionProfile.PnP.ApplicationSecret = $ApplicationSecret
            $Global:MSCloudLoginConnectionProfile.PnP.TenantId = $TenantId
            $Global:MSCloudLoginConnectionProfile.PnP.CertificateThumbprint = $CertificateThumbprint
            $Global:MSCloudLoginConnectionProfile.PnP.CertificatePath = $CertificatePath
            $Global:MSCloudLoginConnectionProfile.PnP.AccessTokens = $AccessTokens
            $Global:MSCloudLoginConnectionProfile.PnP.Identity = $Identity
            $Global:MSCloudLoginConnectionProfile.PnP.CertificatePassword = $CertificatePassword

            # Mark as disconnected if we are trying to connect to a different url then we previously connected to.
            if ($Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl -ne $Url -or `
                    -not $Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl -and `
                    $Url -or (-not $Url -and -not $Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl))
            {
                $ForceRefresh = $false
                if ($Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl -ne $Url -and `
                    -not [System.String]::IsNullOrEmpty($url))
                {
                    $ForceRefresh = $true
                }
                $Global:MSCloudLoginConnectionProfile.PnP.Connected = $false
                $Global:MSCloudLoginConnectionProfile.PnP.ConnectionUrl = $Url
                $Global:MSCloudLoginConnectionProfile.PnP.Connect($ForceRefresh)
            }
            else
            {
                try
                {
                    $contextUrl = (Get-PnPContext).Url
                    if ([System.String]::IsNullOrEmpty($url))
                    {
                        $Url = $Global:MSCloudLoginConnectionProfile.PnP.AdminUrl
                        if (-not $Url.EndsWith('/') -and $contextUrl.EndsWith('/'))
                        {
                            $Url += '/'
                        }
                    }
                    if ($contextUrl -ne $Url)
                    {
                        $ForceRefresh = $true
                        $Global:MSCloudLoginConnectionProfile.PnP.Connected = $false
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
                    Write-Information -MessageData "Couldn't acquire PnP Context"
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
            $Global:MSCloudLoginConnectionProfile.PowerPlatform.Credentials = $Credential
            $Global:MSCloudLoginConnectionProfile.PowerPlatform.ApplicationId = $ApplicationId
            $Global:MSCloudLoginConnectionProfile.PowerPlatform.TenantId = $TenantId
            $Global:MSCloudLoginConnectionProfile.PowerPlatform.CertificateThumbprint = $CertificateThumbprint
            $Global:MSCloudLoginConnectionProfile.PowerPlatform.ApplicationSecret = $ApplicationSecret
            $Global:MSCloudLoginConnectionProfile.PowerPlatform.AccessTokens = $AccessTokens
            $Global:MSCloudLoginConnectionProfile.PowerPlatform.Connect()
        }
        'SecurityComplianceCenter'
        {
            $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.Credentials = $Credential
            $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.ApplicationId = $ApplicationId
            $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.ApplicationSecret = $ApplicationSecret
            $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.TenantId = $TenantId
            $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.CertificateThumbprint = $CertificateThumbprint
            $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.CertificatePath = $CertificatePath
            $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.CertificatePassword = $CertificatePassword
            $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.AccessTokens = $AccessTokens
            $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.SkipModuleReload = $SkipModuleReload
            $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.Connect()
        }
        'Tasks'
        {
            $Global:MSCloudLoginConnectionProfile.Tasks.Credentials = $Credential
            $Global:MSCloudLoginConnectionProfile.Tasks.ApplicationId = $ApplicationId
            $Global:MSCloudLoginConnectionProfile.Tasks.ApplicationSecret = $ApplicationSecret
            $Global:MSCloudLoginConnectionProfile.Tasks.TenantId = $TenantId
            $Global:MSCloudLoginConnectionProfile.Tasks.CertificateThumbprint = $CertificateThumbprint
            $Global:MSCloudLoginConnectionProfile.Tasks.CertificatePath = $CertificatePath
            $Global:MSCloudLoginConnectionProfile.Tasks.CertificatePassword = $CertificatePassword
            $Global:MSCloudLoginConnectionProfile.Tasks.AccessTokens = $AccessTokens
            $Global:MSCloudLoginConnectionProfile.Tasks.Connect()
        }
    }
}

<#
.SYNOPSIS
    This functions compares the authentication parameters for a change compared to the currently used parameters.
.DESCRIPTION
    This functions compares the authentication parameters for a change compared to the currently used parameters.
    It is used to determine if a new connection needs to be made.
.OUTPUTS
    Boolean. Compare-InputParametersForChange returns $true if something changed, $false otherwise.
.EXAMPLE
    Compare-InputParametersForChange -CurrentParamSet $PSBoundParameters
#>
function Compare-InputParametersForChange
{
    param (
        [Parameter()]
        [System.Collections.Hashtable]
        $CurrentParamSet
    )

    $currentParameters = $currentParamSet

    if ($null -ne $currentParameters['Credential'].UserName)
    {
        $currentParameters.Add('UserName', $currentParameters['Credential'].UserName)
    }
    $currentParameters.Remove('Credential') | Out-Null
    $currentParameters.Remove('SkipModuleReload') | Out-Null
    $currentParameters.Remove('UseModernAuth') | Out-Null
    $currentParameters.Remove('ProfileName') | Out-Null
    $currentParameters.Remove('Verbose') | Out-Null

    $globalParameters = @{}

    $workloadProfile = $Global:MSCloudLoginConnectionProfile

    if ($null -eq $workloadProfile)
    {
        # No Workload profile yet, so we need to connect
        # This should not happen, but just in case
        # We are not able to detect a change, so we return $false
        return $false
    }
    else
    {
        $workload = $currentParameters['Workload']

        if ($Workload -eq 'MicrosoftTeams')
        {
            $workloadInternalName = 'Teams'
        }
        elseif ($Workload -eq 'PowerPlatforms')
        {
            $workloadInternalName = 'PowerPlatform'
        }
        else
        {
            $workloadInternalName = $workload
        }
        $workloadProfile = $Global:MSCloudLoginConnectionProfile.$workloadInternalName
    }

    # Clean the global Params
    if (-not [System.String]::IsNullOrEmpty($workloadProfile.TenantId))
    {
        $globalParameters.Add('TenantId', $workloadProfile.TenantId)
    }
    if (-not [System.String]::IsNullOrEmpty($workloadProfile.Credentials.UserName))
    {
        $globalParameters.Add('UserName', $workloadProfile.Credentials.UserName)

        # If the tenant id is part of the username, we need to remove it from the global parameters
        if ($workloadInternalName -eq 'MicrosoftGraph' `
                -and $globalParameters.ContainsKey('TenantId') `
                -and $globalParameters.TenantId -eq $workloadProfile.Credentials.UserName.Split('@')[1])
        {
            $globalParameters.Remove('TenantId') | Out-Null
        }
    }
    if ($workloadInternalName -eq 'PNP' -and $currentParameters.ContainsKey("Url") -and `
        -not [System.String]::IsNullOrEmpty($currentParameters.Url))
    {
        $globalParameters.Add('Url', $workloadProfile.ConnectionUrl)
    }

    # This is the global graph application id. If it is something different, it means that we should compare the parameters
    if (-not [System.String]::IsNullOrEmpty($workloadProfile.ApplicationId) `
            -and -not($workloadInternalName -eq 'MicrosoftGraph' -and $workloadProfile.ApplicationId -eq '14d82eec-204b-4c2f-b7e8-296a70dab67e'))
    {
        $globalParameters.Add('ApplicationId', $workloadProfile.ApplicationId)
    }

    if (-not [System.String]::IsNullOrEmpty($workloadProfile.ApplicationSecret))
    {
        $globalParameters.Add('ApplicationSecret', $workloadProfile.ApplicationSecret)
    }
    if (-not [System.String]::IsNullOrEmpty($workloadProfile.CertificateThumbprint))
    {
        $globalParameters.Add('CertificateThumbprint', $workloadProfile.CertificateThumbprint)
    }
    if (-not [System.String]::IsNullOrEmpty($workloadProfile.CertificatePassword))
    {
        $globalParameters.Add('CertificatePassword', $workloadProfile.CertificatePassword)
    }
    if (-not [System.String]::IsNullOrEmpty($workloadProfile.CertificatePath))
    {
        $globalParameters.Add('CertificatePath', $workloadProfile.CertificatePath)
    }
    if ($workloadProfile.Identity)
    {
        $globalParameters.Add('Identity', $workloadProfile.Identity)
    }

    # Clean the current parameters

    # Remove the workload, as we don't need to compare that
    $currentParameters.Remove('Workload') | Out-Null

    if ([System.String]::IsNullOrEmpty($currentParameters.ApplicationId))
    {
        $currentParameters.Remove('ApplicationId') | Out-Null
    }
    if ([System.String]::IsNullOrEmpty($currentParameters.TenantId))
    {
        $currentParameters.Remove('TenantId') | Out-Null
    }
    if ([System.String]::IsNullOrEmpty($currentParameters.ApplicationSecret))
    {
        $currentParameters.Remove('ApplicationSecret') | Out-Null
    }
    if ([System.String]::IsNullOrEmpty($currentParameters.CertificateThumbprint))
    {
        $currentParameters.Remove('CertificateThumbprint') | Out-Null
    }
    if ([System.String]::IsNullOrEmpty($currentParameters.CertificatePassword))
    {
        $currentParameters.Remove('CertificatePassword') | Out-Null
    }
    if ([System.String]::IsNullOrEmpty($currentParameters.CertificatePath))
    {
        $currentParameters.Remove('CertificatePath') | Out-Null
    }
    if ($currentParameters.ContainsKey('Identity') -and -not ($currentParameters.Identity))
    {
        $currentParameters.Remove('Identity') | Out-Null
    }

    if ($null -ne $globalParameters)
    {
        $diffKeys = Compare-Object -ReferenceObject @($currentParameters.Keys) -DifferenceObject @($globalParameters.Keys) -PassThru
        $diffValues = Compare-Object -ReferenceObject @($currentParameters.Values) -DifferenceObject @($globalParameters.Values) -PassThru
    }

    if ($null -eq $diffKeys -and $null -eq $diffValues)
    {
        # no differences were found
        return $false
    }

    # We found differences, so we need to connect
    return $true
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
    Write-Verbose -Message 'Connection to Microsoft Graph is required to automatically determine SharePoint Online admin URL...'
    try
    {
        $result = Invoke-MgGraphRequest -Uri /v1.0/sites/root -ErrorAction SilentlyContinue
        $weburl = $result.webUrl
        if (-not $weburl)
        {
            Connect-M365Tenant -Workload 'MicrosoftGraph' -Credential $Credential
            $weburl = (Invoke-MgGraphRequest -Uri /v1.0/sites/root).webUrl
        }
    }
    catch
    {
        Connect-M365Tenant -Workload 'MicrosoftGraph' -Credential $Credential
        try
        {
            $weburl = (Invoke-MgGraphRequest -Uri /v1.0/sites/root).webUrl
        }
        catch
        {
            if (Assert-IsNonInteractiveShell -eq $false)
            {
                # Only run interactive command when Exporting
                Write-Verbose -Message 'Requesting access to read information about the domain'
                Connect-MgGraph -Scopes Sites.Read.All -ErrorAction 'Stop'
                $weburl = (Invoke-MgGraphRequest -Uri /v1.0/sites/root).webUrl
            }
            else
            {
                if ($_.Exception.Message -eq 'Insufficient privileges to complete the operation.')
                {
                    throw "The Graph application does not have the correct permissions to access Domains. Make sure you run 'Connect-MgGraph -Scopes Sites.Read.All' first!"
                }
            }
        }
    }

    if ($null -eq $weburl)
    {
        throw 'Unable to retrieve SPO Admin URL. Please check connectivity and if you have the Sites.Read.All permission.'
    }

    $spoAdminUrl = $webUrl -replace '^https:\/\/(\w*)\.', 'https://$1-admin.'
    Write-Verbose -Message "SharePoint Online admin URL is $spoAdminUrl"
    return $spoAdminUrl
}

function Get-AzureADDLL
{
    [CmdletBinding()]
    [OutputType([System.String])]
    param(
    )
    [array]$AzureADModules = Get-Module -ListAvailable | Where-Object { $_.name -eq 'AzureADPreview' }

    if ($AzureADModules.count -eq 0)
    {
        Throw "Can't find Azure AD DLL. Install the module manually 'Install-Module AzureADPreview'"
    }
    else
    {
        $AzureDLL = Join-Path (($AzureADModules | Sort-Object version -Descending | Select-Object -First 1).Path | Split-Path) Microsoft.IdentityModel.Clients.ActiveDirectory.dll
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
        $LoginSource = 'EvoSTS'
    )
    $TenantInfo = @{ }
    if ($LoginSource -eq 'EvoSTS')
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
    [OutputType([System.Collections.HashTable])]
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
        $LoginSource = 'EvoSTS'
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
    $Service['authContext'] = [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext]::new($authority, $false)
    $Service['platformParam'] = New-Object 'Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters' -ArgumentList $PromptBehavior
    $Service['userId'] = New-Object 'Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier' -ArgumentList $UserPrincipalName, 'OptionalDisplayableId'

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
        [Alias('RessourceURI')] # For backward compat with anything using the misspelled parameter
        $ResourceURI,
        [Parameter(Mandatory = $True)]
        $clientId,
        [Parameter(Mandatory = $True)]
        [System.String]
        $RedirectURI
    )
    if ($null -eq $Global:ADALServicePoint)
    {
        $TenantName = $UserPrincipalName.split('@')[1]
        $Global:ADALServicePoint = New-ADALServiceInfo -TenantName $TenantName -UserPrincipalName $UserPrincipalName
    }

    try
    {
        Write-Debug 'Looking for a refresh token'
        $authResult = $Global:ADALServicePoint.authContext.AcquireTokenSilentAsync($ResourceURI, $clientId)
        if ($null -eq $authResult.result)
        {
            $RedirectURI = [System.Uri]::new($RedirectURI)
            $authResult = $Global:ADALServicePoint.authContext.AcquireTokenAsync($ResourceURI, $clientId, $RedirectURI, $Global:ADALServicePoint.platformParam, $Global:ADALServicePoint.userId, '', '')
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
            $jobName = 'AcquireTokenAsync' + (New-Guid).ToString()
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
                    Write-Verbose -Message "Error {Get-AccessToken}: $_"
                    return $null
                }
            } -ArgumentList @($targetUri, $AuthUri, $ClientId, $Credentials, $AzureADDLL) | Out-Null
            $job = Get-Job | Where-Object -FilterScript { $_.Name -eq $jobName }
            do
            {
                Start-Sleep -Seconds 1
            } while ($job.JobStateInfo.State -ne 'Completed')
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
            $authContext = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext('https://login.windows.net/common')
            $credential = [Microsoft.IdentityModel.Clients.ActiveDirectory.UserCredential]::new($O365Credentials.Username, $O365Credentials.Password)
            $authResult = $authContext.AcquireToken($Audience, '1950a258-227b-4e31-a9cf-717495945fc2', $credential)

            $JwtToken = $authResult.IdToken
            $tokenSplit = $JwtToken.Split('.')
            $claimsSegment = $tokenSplit[1].Replace(' ', '+')

            $mod = $claimsSegment.Length % 4
            if ($mod -gt 0)
            {
                $paddingCount = 4 - $mod
                for ($i = 0; $i -lt $paddingCount; $i++)
                {
                    $claimsSegment += '='
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
    } while ($job.JobStateInfo.State -ne 'Completed')
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
        $ApplicationSecret,

        [Parameter()]
        [System.String]
        $CertificateThumbprint,

        [Parameter()]
        [switch]
        $Identity
    )

    try
    {
        if ($null -ne $Credentials)
        {
            $tenantName = $Credentials.UserName.Split('@')[1]
        }
        elseif (-not [string]::IsNullOrEmpty($TenantId))
        {
            $tenantName = $TenantId
        }
        elseif ($Identity.IsPresent)
        {
            return
        }
        else
        {
            throw 'TenantId or Credentials must be provided'
        }
        ## endpoint will work with TenantId or tenantName
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

function Get-MSCloudLoginTenantDomain
{
    param(
        [Parameter()]
        [System.String]
        $ApplicationId,

        [Parameter()]
        [System.String]
        $TenantId,

        [Parameter()]
        [System.String]
        $CertificateThumbprint,

        [Parameter()]
        [switch]
        $Identity,

        [Parameter()]
        [SecureString[]]
        $AccessTokens
    )

    if (-not [string]::IsNullOrEmpty($ApplicationId))
    {
        Connect-M365Tenant -Workload MicrosoftGraph `
            -ApplicationId $ApplicationId `
            -TenantId $TenantId `
            -CertificateThumbprint $CertificateThumbprint
    }
    elseif ($Identity.IsPresent)
    {
        Connect-M365Tenant -Workload MicrosoftGraph `
            -Identity `
            -TenantId $TenantId
    }
    elseif ($null -ne $AccessTokens)
    {
        Connect-M365Tenant -Workload MicrosoftGraph `
            -AccessTokens $AccessTokens
    }

    try
    {
        $domain = Get-MgDomain | Where-Object { $_.IsInitial -eq $True }
    }
    catch
    {
        $domain = Get-MgBetaDomain | Where-Object { $_.IsInitial -eq $True }
    }

    if ($null -ne $domain)
    {
        return $domain.Id.split('.')[0]
    }
}

function Get-MSCloudLoginOrganizationName
{
    param(
        [Parameter()]
        [System.String]
        $ApplicationId,

        [Parameter()]
        [System.String]
        $TenantId,

        [Parameter()]
        [System.String]
        $CertificateThumbprint,

        [Parameter()]
        [System.String]
        $ApplicationSecret,

        [Parameter()]
        [switch]
        $Identity,

        [Parameter()]
        [SecureString[]]
        $AccessTokens
    )
    try
    {
        if (-not [string]::IsNullOrEmpty($ApplicationId) -and -not [System.String]::IsNullOrEmpty($CertificateThumbprint))
        {
            Connect-M365Tenant -Workload MicrosoftGraph -ApplicationId $ApplicationId -TenantId $TenantId -CertificateThumbprint $CertificateThumbprint
        }
        elseif (-not [string]::IsNullOrEmpty($ApplicationId) -and -not [System.String]::IsNullOrEmpty($ApplicationSecret))
        {
            Connect-M365Tenant -Workload MicrosoftGraph -ApplicationId $ApplicationId -TenantId $TenantId -ApplicationSecret $ApplicationSecret
        }
        elseif ($Identity.IsPresent)
        {
            Connect-M365Tenant -Workload MicrosoftGraph -Identity -TenantId $TenantId
        }
        elseif ($null -ne $AccessTokens)
        {
            Connect-M365Tenant -Workload MicrosoftGraph -AccessTokens $AccessTokens
        }
        $domain = Get-MgDomain -ErrorAction Stop | Where-Object { $_.IsInitial -eq $True }

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

function Assert-IsNonInteractiveShell
{
    # Test each Arg for match of abbreviated '-NonInteractive' command.
    $NonInteractive = [Environment]::GetCommandLineArgs() | Where-Object { $_ -like '-NonI*' }

    if ([Environment]::UserInteractive -and -not $NonInteractive)
    {
        # We are in an interactive shell.
        return $false
    }

    return $true
}
