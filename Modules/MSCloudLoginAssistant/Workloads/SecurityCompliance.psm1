function Connect-MSCloudLoginSecurityCompliance
{
    [CmdletBinding()]
    param()
    if ($Global:UseApplicationIdentity -and $null -eq $Global:o365Credential)
    {
        throw "The SecurityComplianceCenter Platform does not support connecting with application identity."
    }

    $WarningPreference = 'SilentlyContinue'
    $ProgressPreference = 'SilentlyContinue'
    $InformationPreference = 'Continue'

    $authorizationUrl = Get-AzureEnvironmentEndpoint -AzureCloudEnvironmentName $Global:appIdentityParams.AzureCloudEnvironmentName -EndpointName ActiveDirectory
    $authorizationUrl += "common"
    $ConnectionUrl = Get-AzureEnvironmentEndpoint -AzureCloudEnvironmentName $Global:appIdentityParams.AzureCloudEnvironmentName -EndpointName SecurityAndCompliancePsConnection
    $uriObj = [Uri]::new($ConnectionUrl)
    $scHost = $uriObj.Host

    $maxConnectionsSearchString = "Fail to create a runspace because you have exceeded the maximum number of connections allowed"

    Ensure-RemotePsSession -RemoteSessionName "Security and Compliance" `
        -TestModuleLoadedCommand "Get-ComplianceSearch" `
        -MaxConnectionsMessageSearchString $maxConnectionsSearchString `
        -ExistingSessionPredicate { ($_.ComputerName -like '*.ps.compliance.protection*' -or $_.ComputerName -like "*$scHost*" ) } `
        -CreateSessionScriptBlock {

        # for some reason this hangs in Trace, leaving as a reminder
        # Connect-ExchangeOnline  -Credential $Global:o365Credential `
        #     -ShowBanner:$false `
        #     -ShowProgress:$false `
        #     -ConnectionUri $ConnectionUrl `
        #     -AzureADAuthorizationEndpointUri $authorizationUrl `
        #     -Verbose:$false | Out-Null

        # Connect-IPPSSession -Credential $Global:o365Credential `
        #     -ConnectionUri $ConnectionUrl `
        #     -AzureADAuthorizationEndpointUri $authorizationUrl `
        #     -
        #     -Verbose:$false -ErrorAction Stop | Out-Null


        # there are issues using the official Connect-IPPSSession cmdlet at least when used from Trace, so we do the auth process and connection manually
        # the issues are most likely because all of the various versions of ADAL(?) between all of the modules used within Trace
        $pwdCreds = [Microsoft.IdentityModel.Clients.ActiveDirectory.UserPasswordCredential]::new($Global:o365Credential.UserName, $Global:o365Credential.Password)
        $resourceId = $ConnectionUrl
        $defaultPsClientId = "fb78d390-0c51-40cd-8e17-fdbfab77341b"

        if ($resourceId -match "ps.compliance.protection")
        {
            $uri = [Uri]::new($resourceId)
            $actualResourceIdHost = $uri.Host -replace "((\w)+\.)?ps.compliance.protection", "ps.compliance.protection"
            $resourceId = $uri.Scheme + [Uri]::SchemeDelimiter + $actualResourceIdHost
        }

        $task = [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContextIntegratedAuthExtensions]::AcquireTokenAsync($Global:ADALAppOnBehalfServicePoint.authContext, $resourceId, $defaultPsClientId, $pwdCreds)
        $task.Wait()
        $res = $task.Result

        $authHeader = "Bearer $($res.AccessToken)"
        $scPwd = [securestring]::new()
        $authHeader.ToCharArray()  | ForEach-Object { $scPwd.AppendChar($_) }
        $scOAuthCreds = [PSCredential]::new($Global:o365Credential.UserName, $scPwd)

        $connectionUrl = $connectionUrl + "?BasicAuthToOAuthConversion=True"
        $session = New-PSSession -ConfigurationName "Microsoft.Exchange" `
            -ConnectionUri $ConnectionUrl `
            -Credential $scOAuthCreds `
            -Authentication Basic `
            -ErrorAction Stop `
            -AllowRedirection

        $module = Import-PSSession $session  `
            -ErrorAction SilentlyContinue `
            -AllowClobber

        Import-Module $module -Global | Out-Null
    }
}
