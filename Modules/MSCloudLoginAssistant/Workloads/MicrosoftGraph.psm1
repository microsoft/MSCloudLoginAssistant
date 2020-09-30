function Connect-MSCloudLoginMicrosoftGraph
{
    [CmdletBinding()]
    param(
        [Parameter()]
        [System.Management.Automation.PsCredential]
        $CloudCredential,

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
    if ($null -ne $CloudCredential)
    {
        Connect-MSCloudLoginMSGraphWithUser -CloudCredential $CloudCredential `
            -ApplicationId $ApplicationId
    }
    else
    {
        try
        {
            Write-Verbose $ApplicationId
            Write-Verbose $TenantId
            Write-Verbose $CertificateThumbprint

            Import-Module -Name Microsoft.Graph.Authentication -DisableNameChecking -Force | out-null
            Connect-Graph -ClientId $ApplicationId -TenantId $TenantId `
            -CertificateThumbprint $CertificateThumbprint | Out-Null
            Write-Verbose -Message "Connected"
        }
        catch
        {
            Write-Verbose -Message $_
            throw $_
        }
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
        $ApplicationId #PoSh Graph SDK
    )

    if ([System.String]::IsNullOrEmpty($ApplicationId))
    {
        $ApplicationId = "14d82eec-204b-4c2f-b7e8-296a70dab67e"
    }
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
    Connect-MSCloudLoginMSGraphWithUser -CloudCredential $CloudCredential `
        -ApplicationId $ApplicationId

    $requestHeaders = @{
        "Authorization" = "Bearer " + $Global:MSCloudLoginGraphAccessToken
        "Content-Type" = "application/json;charset=utf-8"
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
        ContentType = "application/json;charset=utf-8"
    }
    if (-not [System.String]::IsNullOrEmpty($Body))
    {
        $requestParams.Add("Body", $Body)
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
                Write-Verbose -Message "This is the first time the method is called. Wait 10 seconds and retry the call."
                Start-Sleep -Seconds 10
            }
            else
            {
                $newSleepTime = 10 * $CallCount
                Write-Verbose -Message "The Access Token expired, waiting {$newSleepTime} and then regenerating a new one."
                $Global:MSCloudLoginGraphAccessToken = $null
            }
            $CallCount++
            try
            {
                $PSBoundParameters.Remove("CallCount") | Out-Null
            }
            catch
            {
                Write-Verbose -Message "CallCount was not already specified."
            }
            return (Invoke-MSCloudLoginMicrosoftGraphAPI @PSBoundParameters -CallCount $CallCount)
        }
        elseif ($_ -like '*Too many requests*' -and $CallCount -lt 12)
        {
            Write-Host "Too many request, waiting $(10*$callCount) seconds" -ForegroundColor Magenta
            $newSleepTime = 10 * $CallCount
            Start-Sleep -Seconds $newSleepTime
            Invoke-MSCloudLoginMicrosoftGraphAPI -Uri $Uri -Body $Body -Headers $Headers -Method $Method -CloudCredential $CloudCredential `
                -ApplicationId $ApplicationId -CallCount ($CallCount+1)
        }
        else
        {
            Write-Host "Why here???" -ForegroundColor Cyan
            throw $_
        }
    }
    return $result
}
