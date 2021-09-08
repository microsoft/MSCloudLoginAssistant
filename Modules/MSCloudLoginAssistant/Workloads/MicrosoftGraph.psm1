function Connect-MSCloudLoginMicrosoftGraph
{
    [CmdletBinding()]
    param()

    $ProgressPreference = 'SilentlyContinue'
    $WarningPreference  = 'SilentlyContinue'
    $VerbosePreference  = 'SilentlyContinue'
    if ($Global:MSCloudLoginConnectionProfile.MicrosoftGraph.Connected)
    {
        return
    }

    Select-MgProfile $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.ProfileName | Out-Null

    if ($Global:MSCloudLoginConnectionProfile.MicrosoftGraph.AuthenticationType -eq 'CredentialsWithApplicationId')
    {
        Connect-MSCloudLoginMSGraphWithUser
    }
    else
    {
        try
        {
            if ($Global:MSCloudLoginConnectionProfile.MicrosoftGraph.AuthenticationType -eq 'ServicePrincipalWithThumbprint')
            {
                Connect-MgGraph -ClientId $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.ApplicationId `
                    -TenantId $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.TenantId `
                    -CertificateThumbprint $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.CertificateThumbprint | Out-Null
                $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.ConnectedDateTime         = [Sytem.DateTime]::Now.ToString()
                $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.MultiFactorAuthentication = $false
                $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.Connected                 = $true
            }
            else
            {
                $body = @{
                    scope = $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.Scope
                    grant_type = "client_credentials"
                    client_secret = $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.ApplicationSecret
                    client_info = 1
                    client_id = $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.ApplicationId
                }
                Write-Verbose -Message "Requesting Access Token for Microsoft Graph"
                $OAuthReq = Invoke-RestMethod -Uri $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.TokenUrl `
                    -Method Post -Body $body
                $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.AccessToken = $OAuthReq.access_token

                Write-Verbose -Message "Connecting to Microsoft Graph"
                Connect-MgGraph -AccessToken $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.AccessToken | Out-Null
                $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.ConnectedDateTime         = [Sytem.DateTime]::Now.ToString()
                $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.MultiFactorAuthentication = $false
                $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.Connected                 = $true
            }
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
    Param()

    if ([System.String]::IsNullOrEmpty($Global:MSCloudLoginConnectionProfile.MicrosoftGraph.ApplicationId))
    {
        $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.ApplicationId = "14d82eec-204b-4c2f-b7e8-296a70dab67e"
    }

    $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.AccessToken = Get-AccessToken `
        -TargetUri $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.ResourceUrl `
        -AuthUri $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.UserTokenUrl `
        -ClientId $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.ApplicationId `
        -Credentials $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.Credentials

    Connect-MGGraph -AccessToken $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.AccessToken | Out-Null
    $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.ConnectedDateTime         = [System.DateTime]::Now.ToString()
    $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.MultiFactorAuthentication = $false
    $Global:MSCloudLoginConnectionProfile.MicrosoftGraph.Connected                 = $true
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
        $Credential,

        [Parameter()]
        [System.String]
        $ApplicationId,

        [Parameter()]
        [System.UInt32]
        $CallCount = 1
    )
    Connect-MSCloudLoginMSGraphWithUser

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
            Invoke-MSCloudLoginMicrosoftGraphAPI -Uri $Uri -Body $Body -Headers $Headers -Method $Method -Credential $Credential `
                -ApplicationId $ApplicationId -CallCount ($CallCount+1)
        }
        else
        {
            throw $_
        }
    }
    return $result
}
