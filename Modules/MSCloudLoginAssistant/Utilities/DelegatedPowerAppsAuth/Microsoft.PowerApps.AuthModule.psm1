$local:ErrorActionPreference = "Stop"

<#
If(Get-Module -ListAvailable -Name (Join-Path (Split-Path $script:MyInvocation.MyCommand.Path) "Microsoft.PowerApps.RestClientModule.psm1"))
{
	Write-Host "Module loaded"
}
else
{
	Import-Module (Join-Path (Split-Path $script:MyInvocation.MyCommand.Path) "Microsoft.PowerApps.RestClientModule.psm1") -NoClobber #-Force
}
#>
#[Reflection.Assembly]::LoadFile("$(Split-Path $script:MyInvocation.MyCommand.Path)\Microsoft.IdentityModel.Clients.ActiveDirectory.dll") | Out-Null
#[Reflection.Assembly]::LoadFile("$(Split-Path $script:MyInvocation.MyCommand.Path)\Microsoft.IdentityModel.Clients.ActiveDirectory.WindowsForms.dll") | Out-Null

function Get-JwtTokenClaims
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [string]$JwtToken
    )

    $tokenSplit = $JwtToken.Split(".")
    $claimsSegment = $tokenSplit[1].Replace(" ", "+").Replace("-", "+").Replace('_', '/');
    
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

    return ConvertFrom-Json $decodedClaimsSegment
}

function Add-PowerAppsAccount
{
    <#
    .SYNOPSIS
    Add PowerApps account.
    .DESCRIPTION
    The Add-PowerAppsAccount cmdlet logins the user or application account and save login information to cache. 
    Use Get-Help Add-PowerAppsAccount -Examples for more detail.
    .PARAMETER Audience
    The service audience which is used for login.
    .PARAMETER Endpoint
    The serivce endpoint which to call. The value can be "prod","preview","tip1", "tip2", "usgov", "dod", or "usgovhigh".
    .PARAMETER Username
    The user name used for login.
    .PARAMETER Password
    The password for the user.
    .PARAMETER TenantID
    The tenant Id of the user or application.
    .PARAMETER CertificateThumbprint
    The certificate thumbprint of the application.
    .PARAMETER ClientSecret
    The client secret of the application.
    .PARAMETER SecureClientSecret
    The secure client secret of the application.
    .PARAMETER ApplicationId
    The application Id.
    .EXAMPLE
    Add-PowerAppsAccount
    Login to "prod" endpoint.
    .EXAMPLE
    Add-PowerAppsAccount -Endpoint "prod" -Username "username@test.onmicrosoft.com" -Password "password"
    Login to "prod" for user "username@test.onmicrosoft.com" by using password "password"
    .EXAMPLE
    Add-PowerAppsAccount `
      -Endpoint "tip1" `
      -TenantID 1a1fbe33-1ff4-45b2-90e8-4628a5112345 `
      -ClientSecret ABCDE]NO_8:YDLp0J4o-:?=K9cmipuF@ `
      -ApplicationId abcdebd6-e62c-4f68-ab74-b046579473ad
    Login to "tip1" for application abcdebd6-e62c-4f68-ab74-b046579473ad in tenant 1a1fbe33-1ff4-45b2-90e8-4628a5112345 by using client secret.
    .EXAMPLE
    Add-PowerAppsAccount `
      -Endpoint "tip1" `
      -TenantID 1a1fbe33-1ff4-45b2-90e8-4628a5112345 `
      -CertificateThumbprint 12345137C1B2D4FED804DB353D9A8A18465C8027 `
      -ApplicationId 08627eb8-8eba-4a9a-8c49-548266012345
    Login to "tip1" for application 08627eb8-8eba-4a9a-8c49-548266012345 in tenant 1a1fbe33-1ff4-45b2-90e8-4628a5112345 by using certificate.
    #>
    [CmdletBinding()]
    param
    (
        [string] $Audience = "https://management.azure.com/",

        [Parameter(Mandatory = $false)]
        [ValidateSet("prod","preview","tip1", "tip2", "usgov", "usgovhigh", "dod")]
        [string]$Endpoint = "prod",

        [string]$Username = $null,

        [SecureString]$Password = $null,

        [string]$TenantID = $null,

        [string]$CertificateThumbprint = $null,

        [string]$ClientSecret = $null,

        [SecureString]$SecureClientSecret = $null,

        [string]$ApplicationId = "1950a258-227b-4e31-a9cf-717495945fc2"
    )

        

    if(!$Username)
    {
        $Username = $Global:appIdentityParams.OnBehalfOfUserPrincipalName
    }
    $authResult = Get-OnBehalfOfAuthResult -TargetUri $Audience -UserPrincipalName $Username -ErrorAction Stop
    
    # connecting with our Trace app identity logic
    # because we use a different ADAL dll version and it wont work otherwise
    # unfotunately powerapps still dont support this
    # https://powerusers.microsoft.com/t5/Power-Apps-Governance-and/Add-PowerAppsAccount-using-ClientSecret-in-PowerApps-PowerShell/td-p/660323
    #$authResult = Get-AppIdentityAuthResult -TargetUri $Audience    
    
    $claims = Get-JwtTokenClaims -JwtToken $authResult.AccessToken

    # original code, we want our own sice we are using a cert in a different location
    # and also cause we use a different version of the ADAL dll
    # $authContext = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext("https://login.windows.net/common");
    # $redirectUri = New-Object System.Uri("urn:ietf:wg:oauth:2.0:oob");

    # if (![string]::IsNullOrWhiteSpace($TenantID) -and ![string]::IsNullOrWhiteSpace($CertificateThumbprint))
    # {
    #     $AuthUri = "https://login.windows.net/$TenantID/oauth2/authorize"
    #     $clientCertificate = Get-Item -Path Cert:\CurrentUser\My\$CertificateThumbprint
    #     $authenticationContext = New-Object -TypeName Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext -ArgumentList $AuthUri
    #     $certificateCredential = New-Object -TypeName Microsoft.IdentityModel.Clients.ActiveDirectory.ClientAssertionCertificate -ArgumentList ($ApplicationId, $clientCertificate)
    #     $authResult = $authenticationContext.AcquireToken($Audience, $certificateCredential)
    #     $claims = Get-JwtTokenClaims -JwtToken $authResult.AccessToken
    # }
    # elseif (![string]::IsNullOrWhiteSpace($ClientSecret) -or $SecureClientSecret -ne $null)
    # {
    #     $AuthUri = "https://login.windows.net/$TenantID/oauth2/authorize"
    #     $authContext = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext($AuthUri)

    #     if ($SecureClientSecret -ne $null)
    #     {
    #         $credential = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.ClientCredential($ApplicationId, $SecureClientSecret)
    #     }
    #     else
    #     {
    #         $credential = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.ClientCredential($ApplicationId, $ClientSecret)
    #     }

    #     $authResult = $authContext.AcquireToken($Audience, $credential)
    #     $claims = Get-JwtTokenClaims -JwtToken $authResult.AccessToken
    # }
    # elseif ($Username -ne $null -and $Password -ne $null)
    # {
    #     $credential = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.UserCredential($Username, $Password)
    #     $authResult = $authContext.AcquireToken($Audience, $ApplicationId, $credential);
    #     $claims = Get-JwtTokenClaims -JwtToken $authResult.IdToken
    # }
    # else {
    #     $authResult = $authContext.AcquireToken($Audience, $ApplicationId, $redirectUri, 1);
    #     $claims = Get-JwtTokenClaims -JwtToken $authResult.IdToken
    # }

    $global:currentSession = @{
        loggedIn = $true;
        idToken = $authResult.IdToken;
        upn = $claims.upn;
        tenantId = $claims.tid;
        userId = $claims.oid;
        applicationId = $claims.appid;
        certificateThumbprint = $CertificateThumbprint;
        clientSecret = $ClientSecret;
        secureClientSecret = $SecureClientSecret;
        refreshToken = $authResult.RefreshToken;
        expiresOn = (Get-Date).AddHours(8);
        resourceTokens = @{
            $Audience = @{
                accessToken = $authResult.AccessToken;
                expiresOn = $authResult.ExpiresOn;
            }
        };
        selectedEnvironment = "~default";
        flowEndpoint = 
            switch ($Endpoint)
            {
                "prod"      { "api.flow.microsoft.com" }
                "usgov"     { "gov.api.flow.microsoft.us" }
                "usgovhigh" { "high.api.flow.microsoft.us" }
                "dod"       { "api.flow.appsplatform.us" }
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
                "dod"       { "api.apps.appsplatform.us" }
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
                "dod"       { "api.bap.appsplatform.us" }
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
                "dod"       { "graph.windows.net" }
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
                "dod"       { "dod.gov.api.cds.microsoft.us" }
                "preview"   { "preview.api.cds.microsoft.com" }
                "tip1"      { "tip1.api.cds.microsoft.com"}
                "tip2"      { "tip2.api.cds.microsoft.com" }
                default     { throw "Unsupported endpoint '$Endpoint'"}
            };
    };
}

function Test-PowerAppsAccount
{
    <#
    .SYNOPSIS
    Test PowerApps account.
    .DESCRIPTION
    The Test-PowerAppsAccount cmdlet checks cache and calls Add-PowerAppsAccount if user account is not in cache.
    Use Get-Help Test-PowerAppsAccount -Examples for more detail.
    .EXAMPLE
    Test-PowerAppsAccount
    Check if user account is cached.
    #>
    [CmdletBinding()]
    param
    (
    )

    if (-not $global:currentSession)
    {
        Add-PowerAppsAccount
    }
}

function Remove-PowerAppsAccount
{
    <#
    .SYNOPSIS
    Remove PowerApps account.
    .DESCRIPTION
    The Remove-PowerAppsAccount cmdlet removes the user or application login information from cache.
    Use Get-Help Remove-PowerAppsAccount -Examples for more detail.
    .EXAMPLE
    Remove-PowerAppsAccount
    Removes the login information from cache.
    #>
    [CmdletBinding()]
    param
    (
    )

    if ($global:currentSession -ne $null -and $global:currentSession.upn -ne $null)
    {
        Write-Verbose "Logging out $($global:currentSession.upn)"
    }
    else
    {
        Write-Verbose "No user logged in"
    }

    $global:currentSession = @{
        loggedIn = $false;
    };
}

function Get-JwtToken
{
    <#
    .SYNOPSIS
    Get user login token.
    .DESCRIPTION
    The Get-JwtToken cmdlet get the user or application login information from cache. It will call Add-PowerAppsAccount if login token expired.
    Use Get-Help Get-JwtToken -Examples for more detail.
    .EXAMPLE
    Get-JwtToken "https://service.powerapps.com/"
    Get login token for PowerApps "prod".
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [string] $Audience
    )

    if ($global:currentSession -eq $null)
    {
        $global:currentSession = @{
            loggedIn = $false;
        };
    }

    $authResult = Get-OnBehalfOfAuthResult -TargetUri $Audience -UserPrincipalName $global:currentSession.upn -ErrorAction Stop

    # app identity wont work with powerapps
    # https://powerusers.microsoft.com/t5/Power-Apps-Governance-and/Add-PowerAppsAccount-using-ClientSecret-in-PowerApps-PowerShell/td-p/660323
    # $authResult = Get-AppIdentityAuthResult -TargetUri $Audience        
    
    $global:currentSession.resourceTokens[$Audience] = @{
        accessToken = $authResult.AccessToken;
        expiresOn = $authResult.ExpiresOn;
    }

    $accessToken = $global:currentSession.resourceTokens[$Audience].accessToken
    return $accessToken
}

function Invoke-OAuthDialog
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [string] $ConsentLinkUri
    )


    $output = @{}

    return $output
}


function Get-TenantDetailsFromGraph
{
    <#
    .SYNOPSIS
    Get my organization tenant details from graph.
    .DESCRIPTION
    The Get-TenantDetailsFromGraph function calls graph and gets my organization tenant details. 
    Use Get-Help Get-TenantDetailsFromGraph -Examples for more detail.
    .PARAMETER GraphApiVersion
    Graph version to call. The default version is "1.6".
    .EXAMPLE
    Get-TenantDetailsFromGraph
    Get my organization tenant details from graph by calling graph service in version 1.6.
    #>
    param
    (
        [string]$GraphApiVersion = "1.6"
    )

    process 
    {
        $TenantIdentifier = "myorganization"

        $route = "https://{graphEndpoint}/{tenantIdentifier}/tenantDetails`?api-version={graphApiVersion}" `
        | ReplaceMacro -Macro "{tenantIdentifier}" -Value $TenantIdentifier `
        | ReplaceMacro -Macro "{graphApiVersion}" -Value $GraphApiVersion;

        $graphResponse = InvokeApi -Method GET -Route $route
        
        if ($graphResponse.value -ne $null)
        {
            CreateTenantObject -TenantObj $graphResponse.value
        }
        else
        {
            return $graphResponse
        }
    }
}

#Returns users or groups from Graph
#wrapper on top of https://msdn.microsoft.com/en-us/library/azure/ad/graph/api/users-operations & https://msdn.microsoft.com/en-us/library/azure/ad/graph/api/groups-operations 
function Get-UsersOrGroupsFromGraph(
)
{
    <#
    .SYNOPSIS
    Returns users or groups from Graph.
    .DESCRIPTION
    The Get-UsersOrGroupsFromGraph function calls graph and gets users or groups from Graph. 
    Use Get-Help Get-UsersOrGroupsFromGraph -Examples for more detail.
    .PARAMETER ObjectId
    User objec Id.
    .PARAMETER SearchString
    Search string.
    .PARAMETER GraphApiVersion
    Graph version to call. The default version is "1.6".
    .EXAMPLE
    Get-UsersOrGroupsFromGraph -ObjectId "12345ba9-805f-43f8-98f7-34fa34aa51a7"
    Get user with user object Id "12345ba9-805f-43f8-98f7-34fa34aa51a7" from graph by calling graph service in version 1.6.
    .EXAMPLE
    Get-UsersOrGroupsFromGraph -SearchString "gfd"
    Get users who's UserPrincipalName starting with "gfd" from graph by calling graph service in version 1.6.
    #>
    [CmdletBinding(DefaultParameterSetName="Id")]
    param
    (
        [Parameter(Mandatory = $true, ParameterSetName = "Id")]
        [string]$ObjectId,

        [Parameter(Mandatory = $true, ParameterSetName = "Search")]
        [string]$SearchString,

        [Parameter(Mandatory = $false, ParameterSetName = "Search")]
        [Parameter(Mandatory = $false, ParameterSetName = "Id")]
        [string]$GraphApiVersion = "1.6"
    )

    Process
    {
        if (-not [string]::IsNullOrWhiteSpace($ObjectId))
        {
            $userGraphUri = "https://graph.windows.net/myorganization/users/{userId}`?&api-version={graphApiVersion}" `
            | ReplaceMacro -Macro "{userId}" -Value $ObjectId `
            | ReplaceMacro -Macro "{graphApiVersion}" -Value $GraphApiVersion;

            $userGraphResponse = InvokeApi -Route $userGraphUri -Method GET
            
            If($userGraphResponse.StatusCode -eq $null)
            {
                CreateUserObject -UserObj $userGraphResponse
            }

            $groupsGraphUri = "https://graph.windows.net/myorganization/groups/{groupId}`?api-version={graphApiVersion}" `
            | ReplaceMacro -Macro "{groupId}" -Value $ObjectId `
            | ReplaceMacro -Macro "{graphApiVersion}" -Value $GraphApiVersion;

            $groupGraphResponse = InvokeApi -Route $groupsGraphUri -Method GET

            If($groupGraphResponse.StatusCode -eq $null)
            {
                CreateGroupObject -GroupObj $groupGraphResponse
            }
        }
        else 
        {
            $userFilter = "startswith(userPrincipalName,'$SearchString') or startswith(displayName,'$SearchString')"
    
            $userGraphUri = "https://graph.windows.net/myorganization/users`?`$filter={filter}&api-version={graphApiVersion}" `
            | ReplaceMacro -Macro "{filter}" -Value $userFilter `
            | ReplaceMacro -Macro "{graphApiVersion}" -Value $GraphApiVersion;

            $userGraphResponse = InvokeApi -Route $userGraphUri -Method GET
    
            foreach($user in $userGraphResponse.value)
            {
                CreateUserObject -UserObj $user
            }

            $groupFilter = "startswith(displayName,'$SearchString')"
    
            $groupsGraphUri = "https://graph.windows.net/myorganization/groups`?`$filter={filter}&api-version={graphApiVersion}" `
            | ReplaceMacro -Macro "{filter}" -Value $groupFilter `
            | ReplaceMacro -Macro "{graphApiVersion}" -Value $GraphApiVersion;

            $groupsGraphResponse = InvokeApi -Route $groupsGraphUri -Method GET
    
            foreach($group in $groupsGraphResponse.value)
            {
                CreateGroupObject -GroupObj $group
            }    
        }
    }
}


function CreateUserObject
{
    param
    (
        [Parameter(Mandatory = $true)]
        [object]$UserObj
    )

    return New-Object -TypeName PSObject `
        | Add-Member -PassThru -MemberType NoteProperty -Name ObjectType -Value $UserObj.objectType `
        | Add-Member -PassThru -MemberType NoteProperty -Name ObjectId -Value $UserObj.objectId `
        | Add-Member -PassThru -MemberType NoteProperty -Name UserPrincipalName -Value $UserObj.userPrincipalName `
        | Add-Member -PassThru -MemberType NoteProperty -Name Mail -Value $UserObj.mail `
        | Add-Member -PassThru -MemberType NoteProperty -Name DisplayName -Value $UserObj.displayName `
        | Add-Member -PassThru -MemberType NoteProperty -Name AssignedLicenses -Value $UserObj.assignedLicenses `
        | Add-Member -PassThru -MemberType NoteProperty -Name AssignedPlans -Value $UserObj.assignedLicenses `
        | Add-Member -PassThru -MemberType NoteProperty -Name Internal -Value $UserObj;
}

function CreateGroupObject
{
    param
    (
        [Parameter(Mandatory = $true)]
        [object]$GroupObj
    )

    return New-Object -TypeName PSObject `
        | Add-Member -PassThru -MemberType NoteProperty -Name ObjectType -Value $GroupObj.objectType `
        | Add-Member -PassThru -MemberType NoteProperty -Name Objectd -Value $GroupObj.objectId `
        | Add-Member -PassThru -MemberType NoteProperty -Name Mail -Value $GroupObj.mail `
        | Add-Member -PassThru -MemberType NoteProperty -Name DisplayName -Value $GroupObj.displayName `
        | Add-Member -PassThru -MemberType NoteProperty -Name Internal -Value $GroupObj;
}


function CreateTenantObject
{
    param
    (
        [Parameter(Mandatory = $true)]
        [object]$TenantObj
    )

    return New-Object -TypeName PSObject `
        | Add-Member -PassThru -MemberType NoteProperty -Name ObjectType -Value $TenantObj.objectType `
        | Add-Member -PassThru -MemberType NoteProperty -Name TenantId -Value $TenantObj.objectId `
        | Add-Member -PassThru -MemberType NoteProperty -Name Country -Value $TenantObj.countryLetterCode `
        | Add-Member -PassThru -MemberType NoteProperty -Name Language -Value $TenantObj.preferredLanguage `
        | Add-Member -PassThru -MemberType NoteProperty -Name DisplayName -Value $TenantObj.displayName `
        | Add-Member -PassThru -MemberType NoteProperty -Name Domains -Value $TenantObj.verifiedDomains `
        | Add-Member -PassThru -MemberType NoteProperty -Name Internal -Value $TenantObj;
}
