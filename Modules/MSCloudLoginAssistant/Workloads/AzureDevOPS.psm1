function Connect-MSCloudLoginAzureDevOPS
{
    [CmdletBinding()]
    param()

    $WarningPreference = 'SilentlyContinue'
    $InformationPreference = 'SilentlyContinue'
    $ProgressPreference = 'SilentlyContinue'
    $VerbosePreference = 'SilentlyContinue'

    if ($Global:MSCloudLoginConnectionProfile.AzureDevOPS.AuthenticationType -eq 'ServicePrincipalWithThumbprint')
    {
        Write-Verbose -Message "Attempting to connect to Azure DevOPS using AAD App {$ApplicationID}"
        try
        {
            Connect-MSCloudLoginAzureDevOPSWithCertificateThumbprint

            $Global:MSCloudLoginConnectionProfile.AzureDevOPS.ConnectedDateTime = [System.DateTime]::Now.ToString()
            $Global:MSCloudLoginConnectionProfile.AzureDevOPS.Connected = $true
            $Global:MSCloudLoginConnectionProfile.AzureDevOPS.MultiFactorAuthentication = $false
            Write-Verbose -Message "Successfully connected to Azure DevOPS using AAD App {$ApplicationID}"
        }
        catch
        {
            throw $_
        }
    }
    elseif ($Global:MSCloudLoginConnectionProfile.AzureDevOPS.AuthenticationType -eq 'CredentialsWithApplicationId' -or
                $Global:MSCloudLoginConnectionProfile.AzureDevOPS.AuthenticationType -eq 'Credentials' -or
                $Global:MSCloudLoginConnectionProfile.AzureDevOPS.AuthenticationType -eq 'CredentialsWithTenantId')
    {
        Write-Verbose -MEssage "Attempting to connecto to Azure DevOPS using Credentials."
        Connect-MSCloudAzureDevOPSWithUser
        Write-Verbose -Message "Successfully connected to Azure DevOPS using Credentials"
    }
    else
    {
        throw "Specified authentication method is not supported."
    }
}
function Connect-MSCloudAzureDevOPSWithUser
{
    [CmdletBinding()]
    param()

    if ([System.String]::IsNullOrEmpty($Global:MSCloudLoginConnectionProfile.AzureDevOPS.TenantId))
    {
        $tenantid = $Global:MSCloudLoginConnectionProfile.AzureDevOPS.Credentials.UserName.Split('@')[1]
    }
    else
    {
        $tenantId = $Global:MSCloudLoginConnectionProfile.AzureDevOPS.TenantId
    }
    $username = $Global:MSCloudLoginConnectionProfile.AzureDevOPS.Credentials.UserName
    $password = $Global:MSCloudLoginConnectionProfile.AzureDevOPS.Credentials.GetNetworkCredential().password

    $clientId = '1950a258-227b-4e31-a9cf-717495945fc2'
    $uri = "$($Global:MSCloudLoginConnectionProfile.AzureDevOPS.AuthorizationUrl)/organizations/oauth2/token"
    $Body = @{
        grant_type   = 'password'
        # Client id below is for Azure PowerShell
        client_id    = '1950a258-227b-4e31-a9cf-717495945fc2'
        username     = $username
        password     = $password
        resource     = "499b84ac-1321-427f-aa17-267ca6975798"
    }
    try
    {
        $managementToken = Invoke-RestMethod $uri `
            -Method POST `
            -Body $Body `
            -ContentType 'application/x-www-form-urlencoded' `
            -ErrorAction SilentlyContinue

        $Global:MSCloudLoginConnectionProfile.AzureDevOPS.AccessToken = $managementToken.token_type.ToString() + ' ' + $managementToken.access_token.ToString()
        $Global:MSCloudLoginConnectionProfile.AzureDevOPS.Connected = $true
        $Global:MSCloudLoginConnectionProfile.AzureDevOPS.ConnectedDateTime = [System.DateTime]::Now.ToString()
    }
    catch
    {
        if ($_.ErrorDetails.Message -like "*AADSTS50076*")
        {
            Write-Verbose -Message "Account used required MFA"
            Connect-MSCloudLoginAzureDevOPSWithUserMFA
        }
    }
}
function Connect-MSCloudAzureDevOPSWithUserMFA
{
    [CmdletBinding()]
    param()

    if ([System.String]::IsNullOrEmpty($Global:MSCloudLoginConnectionProfile.AzureDevOPS.TenantId))
    {
        $tenantid = $Global:MSCloudLoginConnectionProfile.AzureDevOPS.Credentials.UserName.Split('@')[1]
    }
    else
    {
        $tenantId = $Global:MSCloudLoginConnectionProfile.AzureDevOPS.TenantId
    }
    $clientId = '499b84ac-1321-427f-aa17-267ca6975798'
    $deviceCodeUri = "$($Global:MSCloudLoginConnectionProfile.AzureDevOPS.AuthorizationUrl)/$tenantId/oauth2/devicecode"

    $body = @{
        client_id = $clientId
        resource  = $Global:MSCloudLoginConnectionProfile.AzureDevOPS.AdminUrl
    }
    $DeviceCodeRequest = Invoke-RestMethod $deviceCodeUri `
            -Method POST `
            -Body $body

    Write-Host "`r`n$($DeviceCodeRequest.message)" -ForegroundColor Yellow

    $TokenRequestParams = @{
        Method = 'POST'
        Uri    = "$($Global:MSCloudLoginConnectionProfile.AzureDevOPS.AuthorizationUrl)/$TenantId/oauth2/token"
        Body   = @{
            grant_type = "urn:ietf:params:oauth:grant-type:device_code"
            code       = $DeviceCodeRequest.device_code
            client_id  = $clientId
        }
    }
    $TimeoutTimer = [System.Diagnostics.Stopwatch]::StartNew()
    while ([string]::IsNullOrEmpty($managementToken.access_token))
    {
        if ($TimeoutTimer.Elapsed.TotalSeconds -gt 300)
        {
            throw 'Login timed out, please try again.'
        }
        $managementToken = try
        {
            Invoke-RestMethod @TokenRequestParams -ErrorAction Stop
        }
        catch
        {
            $Message = $_.ErrorDetails.Message | ConvertFrom-Json
            if ($Message.error -ne "authorization_pending")
            {
                throw
            }
        }
        Start-Sleep -Seconds 1
    }
    $Global:MSCloudLoginConnectionProfile.AzureDevOPS.AccessToken = $managementToken.token_type.ToString() + ' ' + $managementToken.access_token.ToString()
    $Global:MSCloudLoginConnectionProfile.AzureDevOPS.Connected = $true
    $Global:MSCloudLoginConnectionProfile.AzureDevOPS.MultiFactorAuthentication = $true
    $Global:MSCloudLoginConnectionProfile.AzureDevOPS.ConnectedDateTime = [System.DateTime]::Now.ToString()
}

function Connect-MSCloudLoginAzureDevOPSWithCertificateThumbprint
{
    [CmdletBinding()]
    Param()
    $WarningPreference = 'SilentlyContinue'
    $ProgressPreference = 'SilentlyContinue'
    $VerbosePreference = 'SilentlyContinue'

    Write-Verbose -Message 'Attempting to connect to Azure DevOPS using CertificateThumbprint'
    $tenantId = $Global:MSCloudLoginConnectionProfile.AzureDevOPS.TenantId

    try
    {
        Write-Verbose -Message "Retrieving certificate in CurrentUser\My\$($Global:MSCloudLoginConnectionProfile.AzureDevOPS.CertificateThumbprint)"
        $Certificate = Get-Item "Cert:\CurrentUser\My\$($Global:MSCloudLoginConnectionProfile.AzureDevOPS.CertificateThumbprint)" -ErrorAction SilentlyContinue

        if ($null -eq $Certificate)
        {
            Write-Verbose 'Certificate not found in CurrentUser\My, trying LocalMachine\My'
            Write-Verbose -Message "Retrieving certificate in LocalMachine\My\$($Global:MSCloudLoginConnectionProfile.AzureDevOPS.CertificateThumbprint)"
            $Certificate = Get-ChildItem "Cert:\LocalMachine\My\$($Global:MSCloudLoginConnectionProfile.AzureDevOPS.CertificateThumbprint)" -ErrorAction SilentlyContinue

            if ($null -eq $Certificate)
            {
                throw 'Certificate not found in LocalMachine\My nor CurrentUser\My'
            }
        }
        # Create base64 hash of certificate
        $CertificateBase64Hash = [System.Convert]::ToBase64String($Certificate.GetCertHash())

        # Create JWT timestamp for expiration
        $StartDate = (Get-Date '1970-01-01T00:00:00Z' ).ToUniversalTime()
        $JWTExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End (Get-Date).ToUniversalTime().AddMinutes(2)).TotalSeconds
        $JWTExpiration = [math]::Round($JWTExpirationTimeSpan, 0)

        # Create JWT validity start timestamp
        $NotBeforeExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End ((Get-Date).ToUniversalTime())).TotalSeconds
        $NotBefore = [math]::Round($NotBeforeExpirationTimeSpan, 0)

        # Create JWT header
        $JWTHeader = @{
            alg = 'RS256'
            typ = 'JWT'
            # Use the CertificateBase64Hash and replace/strip to match web encoding of base64
            x5t = $CertificateBase64Hash -replace '\+', '-' -replace '/', '_' -replace '='
        }

        # Create JWT payload
        $JWTPayLoad = @{
            # What endpoint is allowed to use this JWT
            aud = "$($Global:MSCloudLoginConnectionProfile.AzureDevOPS.AuthorizationUrl)/$TenantId/oauth2/token"

            # Expiration timestamp
            exp = $JWTExpiration

            # Issuer = your application
            iss = $Global:MSCloudLoginConnectionProfile.AzureDevOPS.ApplicationID

            # JWT ID: random guid
            jti = [guid]::NewGuid()

            # Not to be used before
            nbf = $NotBefore

            # JWT Subject
            sub = $Global:MSCloudLoginConnectionProfile.AzureDevOPS.ApplicationID
        }

        # Convert header and payload to base64
        $JWTHeaderToByte = [System.Text.Encoding]::UTF8.GetBytes(($JWTHeader | ConvertTo-Json))
        $EncodedHeader = [System.Convert]::ToBase64String($JWTHeaderToByte)

        $JWTPayLoadToByte = [System.Text.Encoding]::UTF8.GetBytes(($JWTPayload | ConvertTo-Json))
        $EncodedPayload = [System.Convert]::ToBase64String($JWTPayLoadToByte)

        # Join header and Payload with "." to create a valid (unsigned) JWT
        $JWT = $EncodedHeader + '.' + $EncodedPayload

        # Get the private key object of your certificate
        $PrivateKey = ([System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate))

        # Define RSA signature and hashing algorithm
        $RSAPadding = [Security.Cryptography.RSASignaturePadding]::Pkcs1
        $HashAlgorithm = [Security.Cryptography.HashAlgorithmName]::SHA256

        # Create a signature of the JWT
        $Signature = [Convert]::ToBase64String(
            $PrivateKey.SignData([System.Text.Encoding]::UTF8.GetBytes($JWT), $HashAlgorithm, $RSAPadding)
        ) -replace '\+', '-' -replace '/', '_' -replace '='

        # Join the signature to the JWT with "."
        $JWT = $JWT + '.' + $Signature

        # Create a hash with body parameters
        $Body = @{
            client_id             = $Global:MSCloudLoginConnectionProfile.AzureDevOPS.ApplicationID
            client_assertion      = $JWT
            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            scope                 = $Global:MSCloudLoginConnectionProfile.AzureDevOPS.Scope
            grant_type            = 'client_credentials'
        }

        $Url = "$($Global:MSCloudLoginConnectionProfile.AzureDevOPS.AuthorizationUrl)/$TenantId/oauth2/v2.0/token"

        # Use the self-generated JWT as Authorization
        $Header = @{
            Authorization = "Bearer $JWT"
        }

        # Splat the parameters for Invoke-Restmethod for cleaner code
        $PostSplat = @{
            ContentType = 'application/x-www-form-urlencoded'
            Method      = 'POST'
            Body        = $Body
            Uri         = $Url
            Headers     = $Header
        }

        $Request = Invoke-RestMethod @PostSplat

        # View access_token
        $Global:MSCloudLoginConnectionProfile.AzureDevOPS.AccessToken = 'Bearer ' + $Request.access_token
        Write-Verbose -Message 'Successfully connected to the Azure DevOPS API using Certificate Thumbprint'
    }
    catch
    {
        throw $_
    }}
