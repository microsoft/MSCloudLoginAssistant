function Connect-MSCloudLoginWhiteboard
{
    [CmdletBinding()]
    param()

    $WarningPreference = 'SilentlyContinue'
    $InformationPreference = 'SilentlyContinue'
    $ProgressPreference = 'SilentlyContinue'
    $VerbosePreference = 'SilentlyContinue'

    if ($Global:MSCloudLoginConnectionProfile.Whiteboard.Connected)
    {
        return
    }

    if ($Global:MSCloudLoginConnectionProfile.Whiteboard.AuthenticationType -eq 'Credentials')
    {
        Connect-MSCloudLoginWhiteboardWithCredential
    }
    elseif ($Global:MSCloudLoginConnectionProfile.Whiteboard.AuthenticationType -eq 'ServicePrincipalWithSecret')
    {
        Connect-MsCloudLoginWhiteboardWithAppSecret
    }
    elseif ($Global:MSCloudLoginConnectionProfile.Whiteboard.AuthenticationType -eq 'ServicePrincipalWithThumbprint')
    {
        Connect-MSCloudLoginWhiteboardWithCertificateThumbprint
    }
}

function Connect-MSCloudLoginWhiteboardWithCredential
{
    [CmdletBinding()]
    Param()
    $WarningPreference = 'SilentlyContinue'
    $ProgressPreference = 'SilentlyContinue'
    $VerbosePreference = 'SilentlyContinue'

    Write-Verbose -Message "Attempting to connect to Whiteboard using Credentials"
    $tenantId = $Global:MSCloudLoginConnectionProfile.Whiteboard.TenantId
    if ([System.String]::IsNullOrEmpty($tenantId))
    {
        $tenantId = $Global:MSCloudLoginConnectionProfile.Whiteboard.Credentials.Username.Split('@')[1]
    }

    try
    {
        $uri = "https://login.microsoftonline.com/{0}/oauth2/token" -f $tenantId
        $body = "resource=https://$($Global:MSCloudLoginConnectionProfile.Whiteboard.ResourceUrl)/" +
                "&client_id=$($Global:MSCloudLoginConnectionProfile.Whiteboard.WhiteboardAppId)" +
                "&grant_type=password&username={1}&password={0}" -f [System.Web.HttpUtility]::UrlEncode($Global:MSCloudLoginConnectionProfile.Whiteboard.Credentials.GetNetworkCredential().password), $Global:MSCloudLoginConnectionProfile.Whiteboard.Credentials.UserName

        # Request token through ROPC
        $managementToken = Invoke-RestMethod $uri `
            -Method POST `
            -Body $body `
            -ContentType "application/x-www-form-urlencoded" `
            -ErrorAction SilentlyContinue

        $Global:MSCloudLoginConnectionProfile.Whiteboard.AccessToken = $managementToken.token_type.ToString() + ' ' + $managementToken.access_token.ToString()

        $Global:MSCloudLoginConnectionProfile.Whiteboard.ConnectedDateTime = [System.DateTime]::Now.ToString()
        $Global:MSCloudLoginConnectionProfile.Whiteboard.Connected = $true
        Write-Verbose -Message "Successfully connected to Whiteboard using Credentials"
    }
    catch
    {
        throw $_
    }
}

function Connect-MSCloudLoginWhiteboardWithAppSecret
{
    [CmdletBinding()]
    Param()
    $WarningPreference = 'SilentlyContinue'
    $ProgressPreference = 'SilentlyContinue'
    $VerbosePreference = 'SilentlyContinue'

    Write-Verbose -Message "Attempting to connect to Whiteboard using App Secret"
    $tenantId = $Global:MSCloudLoginConnectionProfile.Whiteboard.TenantId

    try
    {
        $uri = "https://login.microsoftonline.com/{0}/oauth2/token" -f $tenantId
        $body = "resource=https://$($Global:MSCloudLoginConnectionProfile.Whiteboard.ResourceUrl)/" +
                "&client_id=$($Global:MSCloudLoginConnectionProfile.Whiteboard.ApplicationId)" +
                "&client_secret=$($Global:MSCloudLoginConnectionProfile.Whiteboard.ApplicationSecret)" +
                "&grant_type=client_credentials"

        # Request token through ROPC
        $managementToken = Invoke-RestMethod $uri `
            -Method POST `
            -Body $body `
            -ContentType "application/x-www-form-urlencoded" `
            -ErrorAction SilentlyContinue

        $Global:MSCloudLoginConnectionProfile.Whiteboard.AccessToken = $managementToken.token_type.ToString() + ' ' + $managementToken.access_token.ToString()

        $Global:MSCloudLoginConnectionProfile.Whiteboard.ConnectedDateTime = [System.DateTime]::Now.ToString()
        $Global:MSCloudLoginConnectionProfile.Whiteboard.Connected = $true
        Write-Verbose -Message "Successfully connected to Whiteboard using App Secret"
    }
    catch
    {
        throw $_
    }
}

function Connect-MSCloudLoginWhiteboardWithCertificateThumbprint
{
    [CmdletBinding()]
    Param()
    $WarningPreference = 'SilentlyContinue'
    $ProgressPreference = 'SilentlyContinue'
    $VerbosePreference = 'SilentlyContinue'

    Write-Verbose -Message "Attempting to connect to Whiteboard using CertificateThumbprint"
    $tenantId = $Global:MSCloudLoginConnectionProfile.Whiteboard.TenantId

    try
    {
        $Certificate = Get-Item "Cert:\CurrentUser\My\$($Global:MSCloudLoginConnectionProfile.Whiteboard.CertificateThumbprint)"
        $Scope = "https://whiteboard.microsoft.com/.default"

        # Create base64 hash of certificate
        $CertificateBase64Hash = [System.Convert]::ToBase64String($Certificate.GetCertHash())

        # Create JWT timestamp for expiration
        $StartDate = (Get-Date "1970-01-01T00:00:00Z" ).ToUniversalTime()
        $JWTExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End (Get-Date).ToUniversalTime().AddMinutes(2)).TotalSeconds
        $JWTExpiration = [math]::Round($JWTExpirationTimeSpan,0)

        # Create JWT validity start timestamp
        $NotBeforeExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End ((Get-Date).ToUniversalTime())).TotalSeconds
        $NotBefore = [math]::Round($NotBeforeExpirationTimeSpan,0)

        # Create JWT header
        $JWTHeader = @{
            alg = "RS256"
            typ = "JWT"
            # Use the CertificateBase64Hash and replace/strip to match web encoding of base64
            x5t = $CertificateBase64Hash -replace '\+','-' -replace '/','_' -replace '='
        }

        # Create JWT payload
        $JWTPayLoad = @{
            # What endpoint is allowed to use this JWT
            aud = "https://login.microsoftonline.com/$TenantId/oauth2/token"

            # Expiration timestamp
            exp = $JWTExpiration

            # Issuer = your application
            iss = $Global:MSCloudLoginConnectionProfile.Whiteboard.ApplicationID

            # JWT ID: random guid
            jti = [guid]::NewGuid()

            # Not to be used before
            nbf = $NotBefore

            # JWT Subject
            sub = $Global:MSCloudLoginConnectionProfile.Whiteboard.ApplicationID
        }

        # Convert header and payload to base64
        $JWTHeaderToByte = [System.Text.Encoding]::UTF8.GetBytes(($JWTHeader | ConvertTo-Json))
        $EncodedHeader = [System.Convert]::ToBase64String($JWTHeaderToByte)

        $JWTPayLoadToByte =  [System.Text.Encoding]::UTF8.GetBytes(($JWTPayload | ConvertTo-Json))
        $EncodedPayload = [System.Convert]::ToBase64String($JWTPayLoadToByte)

        # Join header and Payload with "." to create a valid (unsigned) JWT
        $JWT = $EncodedHeader + "." + $EncodedPayload

        # Get the private key object of your certificate
        $PrivateKey = ([System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate))

        # Define RSA signature and hashing algorithm
        $RSAPadding = [Security.Cryptography.RSASignaturePadding]::Pkcs1
        $HashAlgorithm = [Security.Cryptography.HashAlgorithmName]::SHA256

        # Create a signature of the JWT
        $Signature = [Convert]::ToBase64String(
            $PrivateKey.SignData([System.Text.Encoding]::UTF8.GetBytes($JWT),$HashAlgorithm,$RSAPadding)
        ) -replace '\+','-' -replace '/','_' -replace '='

        # Join the signature to the JWT with "."
        $JWT = $JWT + "." + $Signature

        # Create a hash with body parameters
        $Body = @{
            client_id = $Global:MSCloudLoginConnectionProfile.Whiteboard.ApplicationID
            client_assertion = $JWT
            client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            scope = $Global:MSCloudLoginConnectionProfile.Whiteboard.Scope
            grant_type = "client_credentials"

        }

        $Url = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

        # Use the self-generated JWT as Authorization
        $Header = @{
            Authorization = "Bearer $JWT"
        }

        # Splat the parameters for Invoke-Restmethod for cleaner code
        $PostSplat = @{
            ContentType = 'application/x-www-form-urlencoded'
            Method = 'POST'
            Body = $Body
            Uri = $Url
            Headers = $Header
        }

        $Request = Invoke-RestMethod @PostSplat

        # View access_token
        $Global:MSCloudLoginConnectionProfile.Whiteboard.AccessToken = "Bearer " + $Request.access_token
        $URI = "https://whiteboard.microsoft.com/api/v1.0/whiteboards/enabled"
        $results = Invoke-RestMethod -ContentType "application/json;odata.metadata=full" `
                -Headers @{"Accept"="application/json"; "Authorization"=$Global:MSCloudLoginConnectionProfile.Whiteboard.AccessToken; "Accept-Charset"="UTF-8"; "OData-Version"="4.0;NetFx"; "OData-MaxVersion"="4.0;NetFx"} `
                -Method GET `
                $Uri
        Write-Verbose -Message "Successfully connected to Whiteboard using Certificate Thumbprint"
    }
    catch
    {
        throw $_
    }
}
