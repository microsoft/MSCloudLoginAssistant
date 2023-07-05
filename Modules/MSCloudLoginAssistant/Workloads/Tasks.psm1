function Connect-MSCloudLoginTasks
{
    [CmdletBinding()]
    param()

    $ProgressPreference = 'SilentlyContinue'
    $WarningPreference = 'SilentlyContinue'
    $VerbosePreference = 'SilentlyContinue'

    if ($Global:MSCloudLoginConnectionProfile.Tasks.AuthenticationType -eq 'CredentialsWithApplicationId' -or
        $Global:MSCloudLoginConnectionProfile.Tasks.AuthenticationType -eq 'Credentials')
    {
        Write-Verbose -Message 'Will try connecting with user credentials'
        Connect-MSCloudLoginTasksWithUser
    }
    elseif ($Global:MSCloudLoginConnectionProfile.Tasks.AuthenticationType -eq 'ServicePrincipalWithSecret')
    {
        Write-Verbose -Message 'Will try connecting with Application Secret'
        Connect-MSCloudLoginTasksWithAppSecret
    }
    elseif ($Global:MSCloudLoginConnectionProfile.Tasks.AuthenticationType -eq 'ServicePrincipalWithThumbprint')
    {
        Write-Verbose -Message 'Will try connecting with Application Secret'
        Connect-MSCloudLoginTasksWithCertificateThumbprint
    }
}

function Connect-MSCloudLoginTasksWithUser
{
    [CmdletBinding()]
    param()

    $tenantid = $Global:MSCloudLoginConnectionProfile.Tasks.Credentials.UserName.Split('@')[1]
    $username = $Global:MSCloudLoginConnectionProfile.Tasks.Credentials.UserName
    $password = $Global:MSCloudLoginConnectionProfile.Tasks.Credentials.GetNetworkCredential().password

    $clientId = '9ac8c0b3-2c30-497c-b4bc-cadfe9bd6eed'
    $uri = "https://login.microsoftonline.com/{0}/oauth2/token" -f $tenantid
    $body = "resource=https://tasks.office.com/&client_id=$clientId&grant_type=password&username={1}&password={0}" -f [System.Web.HttpUtility]::UrlEncode($password), $username

    # Request token through ROPC
    $managementToken = Invoke-RestMethod $uri `
        -Method POST `
        -Body $body `
        -ContentType "application/x-www-form-urlencoded" `
        -ErrorAction SilentlyContinue

    $Global:MSCloudLoginConnectionProfile.Tasks.AccessToken = $managementToken.token_type.ToString() + ' ' + $managementToken.access_token.ToString()
}

function Connect-MSCloudLoginTasksWithAppSecret
{
    [CmdletBinding()]
    param()


    $uri = "https://login.microsoftonline.com/{0}/oauth2/token" -f $Global:MSCloudLoginConnectionProfile.Tasks.TenantId
    $body = "resource=https://tasks.office.com/&client_id=$($Global:MSCloudLoginConnectionProfile.Tasks.ApplicationId)&client_secret=$($Global:MSCloudLoginConnectionProfile.Tasks.ApplicationSecret)&grant_type=client_credentials"

    # Request token through ROPC
    $managementToken = Invoke-RestMethod $uri `
        -Method POST `
        -Body $body `
        -ContentType "application/x-www-form-urlencoded" `
        -ErrorAction SilentlyContinue

    $Global:MSCloudLoginConnectionProfile.Tasks.AccessToken = $managementToken.token_type.ToString() + ' ' + $managementToken.access_token.ToString()
}

function Connect-MSCloudLoginTasksWithCertificateThumbprint
{
    [CmdletBinding()]
    Param()
    $WarningPreference = 'SilentlyContinue'
    $ProgressPreference = 'SilentlyContinue'
    $VerbosePreference = 'SilentlyContinue'

    Write-Verbose -Message "Attempting to connect to Whiteboard using CertificateThumbprint"
    $tenantId = $Global:MSCloudLoginConnectionProfile.Tasks.TenantId

    try
    {
        $Certificate = Get-Item "Cert:\CurrentUser\My\$($Global:MSCloudLoginConnectionProfile.Tasks.CertificateThumbprint)"

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
            iss = $Global:MSCloudLoginConnectionProfile.Tasks.ApplicationID

            # JWT ID: random guid
            jti = [guid]::NewGuid()

            # Not to be used before
            nbf = $NotBefore

            # JWT Subject
            sub = $Global:MSCloudLoginConnectionProfile.Tasks.ApplicationID
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
            client_id = $Global:MSCloudLoginConnectionProfile.Tasks.ApplicationID
            client_assertion = $JWT
            client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            scope = $Global:MSCloudLoginConnectionProfile.Tasks.Scope
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
        $Global:MSCloudLoginConnectionProfile.Tasks.AccessToken = "Bearer " + $Request.access_token
        Write-Verbose -Message "Successfully connected to the Tasks API using Certificate Thumbprint"
    }
    catch
    {
        throw $_
    }
}
