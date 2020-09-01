function Connect-MSCloudLoginMicrosoftGraph
{
    [CmdletBinding()]
    param(
    )


    if(!(Get-Module Microsoft.Graph.Authentication))
    {
        Import-Module -Name Microsoft.Graph.Authentication -DisableNameChecking -Force | out-null
    }

    if($Global:UseApplicationIdentity)
    {
        try
        {
            Enable-AppDomainLoadAnyVersionResolution
            if(!('Microsoft.Graph.AuthenticateRequestAsyncDelegate' -as [Type]))
            {
                $rootDir = [System.IO.Path]::GetDirectoryName((Get-Module Microsoft.Graph.Authentication).Path).TrimEnd('\')
                $graphCoreAssemblyPath  = $rootDir +"\bin\Microsoft.Graph.Core.dll"
                Add-Type -Path $graphCoreAssemblyPath
            }

            # the official Connect-Graph cmdlet does not support certificates ouside the my personal store for the current user
            # and for delegated access it only supports device code auth
            # since we already have the authentication context that we can use to authenticate to graph
            # we redirect it by replacing the auth implementation in runtime
            [SysKit.MsGraphAuthModulePatching.MsGraphAuthModulePatcher]::DoPatching([Microsoft.Graph.AuthenticateRequestAsyncDelegate]{
                param(
                    [Parameter()]
                    [System.Net.Http.HttpRequestMessage]
                    $request
                )

                $token = Get-OnBehalfOfAccessToken -TargetUri "https://graph.microsoft.com"
                $request.Headers.Authorization = [System.Net.Http.Headers.AuthenticationHeaderValue]::new("Bearer", $token)
                return [System.Threading.Tasks.Task]::CompletedTask
            })
        }
        finally
        {
            Disable-AppDomainLoadAnyVersionResolution
        }

        # we will not be using the official Connect-Graph cmdlet. 
        # the auth process has been redirected by the code above
        # but we do need to fill some static data just in case that Connect-Graph internally does 
        # Connect-Graph -ClientId $Global:appIdentityParams.AppId -TenantId $Global:appIdentityParams.Tenant `
        #     -CertificateThumbprint $Global:appIdentityParams.CertificateThumbprint

        $authContext = [Microsoft.Graph.PowerShell.Authentication.AuthContext]::new()
        $authContext.TenantId = $Global:appIdentityParams.Tenant
        $authContext.ClientId = $Global:appIdentityParams.AppId
        $authContext.AuthType = [Microsoft.Graph.PowerShell.Authentication.AuthenticationType]::Delegated


        [Microsoft.Graph.PowerShell.Authentication.GraphSession]::Instance.AuthContext = $authContext

        Write-Verbose "Connected to MicrosoftGraph using application identity with certificate thumbprint"
    }
    else
    {
        throw "Not implemented"
    }
}

function Connect-MSCloudLoginMSGraphWithUser
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $CloudCredential,

        [Parameter()]
        [System.String]
        $ApplicationId = "14d82eec-204b-4c2f-b7e8-296a70dab67e" #PoSh Graph SDK
    )
    if ($null -eq $Global:MSCloudLoginGraphAccessToken)
    {
        $azuretenantADName = $CloudCredential.UserName.Split('@')[1]

        #Authority to Azure AD Tenant
        $AzureADAuthority = "https://login.microsoftonline.com/$azuretenantADName/oauth2/v2.0/authorize"

        #Resource URI to the Microsoft Graph
        $resourceURL = "https://graph.microsoft.com/"

        # Create UserCredential object
        $accessToken = Get-AccessToken -TargetUri $resourceUrl `
            -AuthUri $AzureADAuthority `
            -ClientId $ApplicationId `
            -Credentials $CloudCredential
        $Global:MSCloudLoginGraphAccessToken = $accessToken
    }
}

function Connect-MSCloudLoginMSGraphWithServicePrincipal
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [System.String]
        $ApplicationId,

        [Parameter(Mandatory = $true)]
        [System.String]
        $TenantId,

        [Parameter(Mandatory = $true)]
        [System.String]
        $ApplicationSecret
    )

    $url = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $body = "client_id=$ApplicationId&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default&client_secret=$ApplicationSecret&grant_type=client_credentials"
    $response = Invoke-RestMethod -Method POST -Uri $url -Body $body
    $Global:MSCloudLoginGraphAccessToken = $response.access_token
}

function Connect-MSCloudLoginMSGraphWithServicePrincipalDelegated
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [System.String]
        $ApplicationId,

        [Parameter(Mandatory = $true)]
        [System.String]
        $TenantId,

        [Parameter(Mandatory = $true)]
        [System.String]
        $ApplicationSecret,

        [Parameter(Mandatory = $true)]
        [System.String]
        $Scope
    )

    $url = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/authorize?"
    $body = "client_id=$ApplicationId&scope=$scope&client_secret=$ApplicationSecret&response_type=code"
    $response = Invoke-RestMethod -Method GET -Uri ($url + $body)
    $Global:MSCloudLoginGraphAccessToken = $response.access_token
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
        $CloudCredential,

        [Parameter()]
        [System.String]
        $ApplicationId,

        [Parameter()]
        [System.UInt32]
        $CallCount = 1
    )

    $accessToken = Get-OnBehalfOfAccessToken -TargetUri "https://graph.microsoft.com"
    $requestHeaders = @{
        "Authorization" = "Bearer " + $accessToken
        "Content-Type" = "application/json"
    }
    foreach ($key in $Headers.Keys)
    {
        Write-Verbose -Message "    $key = $($requestHeaders.$key)"
        $requestHeaders.Add($key, $Headers.$key)
    }

    Write-Verbose -Message "URI: $Uri"
    Write-Verbose -Message "Method: $Method"
    $requestParams = @{
        Method  = $Method
        Uri     = $Uri
        Headers = $requestHeaders
    }
    if (-not [System.String]::IsNullOrEmpty($Body))
    {
        $requestParams.Add("Body", $Body)
        Write-Verbose -Message "Body: $Body"
    }

    # In the original MSCloudLogin code there was error handling here that was related to  authentication
    # the error handling with retry makes no sense, maybe retry for transient errors but this was for auth
    # so the code was removed but this comment remains here if anybody wonders why the difference
    
    $Result = Invoke-RestMethod @requestParams
    
    return $result
}
