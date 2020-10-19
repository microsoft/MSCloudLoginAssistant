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
    $psConnectionUri =  Get-AzureEnvironmentEndpoint -AzureCloudEnvironmentName $Global:appIdentityParams.AzureCloudEnvironmentName -EndpointName ExchangePsConnection
    $uriObj = [Uri]::new($psConnectionUri)
    $exchangeHost = $uriObj.Host
    [array]$activeSessions = Get-PSSession | Where-Object -FilterScript { ($_.ComputerName -like '*outlook.office*' -or $_.ComputerName -like "*$exchangeHost*" ) -and $_.State -eq 'Opened'}
    if ($activeSessions.Length -ge 1)
    {
        Write-Verbose -Message "Found {$($activeSessions.Length)} existing Exchange Online Session"
        $command = Get-Command "Get-AcceptedDomain" -ErrorAction 'SilentlyContinue'
        if ($null -ne $command)
        {
            return
        }
        $EXOModule = Import-PSSession $activeSessions[0] -DisableNameChecking -AllowClobber
        Import-Module $EXOModule -Global | Out-Null
        return
    }
    Write-Verbose -Message "No active Exchange Online session found."   
   
    #endregion
    if (-not [String]::IsNullOrEmpty($ApplicationId) -and `
        -not [String]::IsNullOrEmpty($TenantId) -and `
        -not [String]::IsNullOrEmpty($CertificateThumbprint))
    {
        Write-Verbose -Message "Attempting to connect to Exchange Online using AAD App {$ApplicationID}"
        try
        {
            $Organization = Get-MSCloudLoginOrganizationName -ApplicationId $ApplicationId `
                -TenantId $TenantId `
                -CertificateThumbprint $CertificateThumbprint
            $CurrentVerbosePreference = $VerbosePreference
            $CurrentInformationPreference = $InformationPreference
            $CurrentWarningPreference = $WarningPreference
            $VerbosePreference = "SilentlyContinue"
            $InformationPreference = "SilentlyContinue"
            $WarningPreference = "SilentlyContinue"
            Connect-ExchangeOnline -AppId $ApplicationId `
                -Organization $Organization `
                -CertificateThumbprint $CertificateThumbprint `
                -ShowBanner:$false `
                -ShowProgress:$false `
                -ConnectionUri $psConnectionUri `
                -AzureADAuthorizationEndpointUri $AuthorizationUrl `
                -ExchangeEnvironmentName $ExoEnvName `
                -Verbose:$false | Out-Null
            $VerbosePreference = $CurrentVerbosePreference
            $InformationPreference = $CurrentInformationPreference
            $WarningPreference = $CurrentWarningPreference
            Write-Verbose -Message "Successfully connected to Exchange Online using AAD App {$ApplicationID}"
        }
        catch
        {
            throw $_
        }
    }
    else
    {
    }
}
