function Connect-MSCloudLoginExchangeOnline
{
    [CmdletBinding()]
    param()
    $WarningPreference = 'SilentlyContinue'
    $ProgressPreference = 'SilentlyContinue'

    $ExoEnvName = Get-PsModuleAzureEnvironmentName -AzureCloudEnvironmentName $Global:appIdentityParams.AzureCloudEnvironmentName -Platform "ExchangeOnline"
    $ApplicationId = $Global:appIdentityParams.AppId
    $TenantId = $Global:appIdentityParams.Tenant
    $CertificateThumbprint = $Global:appIdentityParams.CertificateThumbprint
    $authorizationUrl = Get-AzureEnvironmentEndpoint -AzureCloudEnvironmentName $Global:appIdentityParams.AzureCloudEnvironmentName -EndpointName ActiveDirectory
    $authorizationUrl += "common"
    $psConnectionUri = Get-AzureEnvironmentEndpoint -AzureCloudEnvironmentName $Global:appIdentityParams.AzureCloudEnvironmentName -EndpointName ExchangePsConnection
    $uriObj = [Uri]::new($psConnectionUri)
    $exchangeHost = $uriObj.Host

    
    $maxConnectionsSearchString = "Fail to create a runspace because you have exceeded the maximum number of connections allowed"
    
    Ensure-RemotePsSession -RemoteSessionName "Exchange Online" `
        -TestModuleLoadedCommand "Get-AcceptedDomain" `
        -MaxConnectionsMessageSearchString $maxConnectionsSearchString `
        -ExistingSessionPredicate { ($_.ComputerName -like '*outlook.office*' -or $_.ComputerName -like "*$exchangeHost*" ) } `
        -CreateSessionScriptBlock {

        $Organization = Get-MSCloudLoginOrganizationName -ApplicationId $ApplicationId `
            -TenantId $TenantId `
            -CertificateThumbprint $CertificateThumbprint
            
        Connect-ExchangeOnline -AppId $ApplicationId `
            -Organization $Organization `
            -CertificateThumbprint $CertificateThumbprint `
            -ShowBanner:$false `
            -ShowProgress:$false `
            -ConnectionUri $psConnectionUri `
            -AzureADAuthorizationEndpointUri $AuthorizationUrl `
            -ExchangeEnvironmentName $ExoEnvName `
            -Verbose:$false | Out-Null
    }
}
