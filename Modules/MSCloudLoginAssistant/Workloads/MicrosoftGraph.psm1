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
        Connect-MSCloudLoginGraphWithCredentials -CloudCredential $CloudCredential `
            -ApplicationId $ApplicationId
    }
    try
    {
        Write-Verbose "ICI"
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

function Connect-MSCloudLoginMicrosoftGraphWithCredential
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

function Invoke-MSCloudLoginMicrosoftGraphAPI
{
    [CmdletBinding()]
    [OutputType([System.String])]
    Param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $CloudCredential,

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
        [System.String]
        $ApplicationId,

        [Parameter()]
        [System.UInt32]
        $CallCount = 1
    )
    Connect-MSCloudLoginMicrosoftGraphWithCredential -CloudCredential $CloudCredential
    $requestHeaders = @{
        "Authorization" = "Bearer " + $Global:MSCloudLoginGraphAccessToken
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

    try
    {
        $Result = Invoke-RestMethod @requestParams
    }
    catch
    {
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
        throw $_
    }
    return $result
}
