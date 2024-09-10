function Connect-MSCloudLoginAzure
{
    [CmdletBinding()]
    param()

    $WarningPreference = 'SilentlyContinue'
    $InformationPreference = 'SilentlyContinue'
    $ProgressPreference = 'SilentlyContinue'
    $VerbosePreference = 'SilentlyContinue'

    if ($Global:MSCloudLoginConnectionProfile.Azure.AuthenticationType -eq 'ServicePrincipalWithThumbprint')
    {
        Write-Verbose -Message "Attempting to connect to Azure using AAD App {$ApplicationID}"
        try
        {
            Write-Verbose -Message "Azure Connection Profile = $($Global:MSCloudLoginConnectionProfile.Azure | Out-String)"
            try
            {
                Connect-AzAccount -ApplicationId $Global:MSCloudLoginConnectionProfile.Azure.ApplicationId `
                                -TenantId $Global:MSCloudLoginConnectionProfile.Azure.TenantId `
                                -CertificateThumbprint $Global:MSCloudLoginConnectionProfile.Azure.CertificateThumbprint `
                                -Environment $Global:MSCloudLoginConnectionProfile.Azure.EnvironmentName | Out-Null
            }
            catch
            {
                Write-Verbose $_
            }
            $Global:MSCloudLoginConnectionProfile.Azure.ConnectedDateTime = [System.DateTime]::Now.ToString()
            $Global:MSCloudLoginConnectionProfile.Azure.Connected = $true
            $Global:MSCloudLoginConnectionProfile.Azure.MultiFactorAuthentication = $false
            Write-Verbose -Message "Successfully connected to Azure using AAD App {$ApplicationID}"
        }
        catch
        {
            throw $_
        }
    }
    elseif ($Global:MSCloudLoginConnectionProfile.Azure.AuthenticationType -eq 'CredentialsWithApplicationId' -or
                $Global:MSCloudLoginConnectionProfile.Azure.AuthenticationType -eq 'Credentials' -or
                $Global:MSCloudLoginConnectionProfile.Azure.AuthenticationType -eq 'CredentialsWithTenantId')
    {
        try
        {
            if ([System.String]::IsNullOrEmpty($Global:MSCloudLoginConnectionProfile.Azure.TenantId))
            {
                $Global:MSCloudLoginConnectionProfile.Azure.TenantId = $Global:MSCloudLoginConnectionProfile.Azure.Credentials.UserName.Split('@')[1]
            }
            Write-Verbose -Message "Attempting to connect to Azure using Credentials"
            Connect-AzAccount -Credential $Global:MSCloudLoginConnectionProfile.Azure.Credentials `
                              -Environment $Global:MSCloudLoginConnectionProfile.Azure.EnvironmentName `
                              -ErrorAction Stop | Out-Null
            $Global:MSCloudLoginConnectionProfile.Azure.ConnectedDateTime = [System.DateTime]::Now.ToString()
            $Global:MSCloudLoginConnectionProfile.Azure.Connected = $true
            $Global:MSCloudLoginConnectionProfile.Azure.MultiFactorAuthentication = $false
            Write-Verbose -Message "Successfully connected to Azure using Credentials"
        }
        catch
        {
            try
            {
                Write-Verbose -Message "Attempting to connect to Azure using Credentials (MFA)"
                Connect-AzAccount
                $Global:MSCloudLoginConnectionProfile.Azure.ConnectedDateTime = [System.DateTime]::Now.ToString()
                $Global:MSCloudLoginConnectionProfile.Azure.Connected = $true
                $Global:MSCloudLoginConnectionProfile.Azure.MultiFactorAuthentication = $true
                Write-Verbose -Message "Successfully connected to Azure using Credentials (MFA)"
            }
            catch
            {
                throw $_
            }
        }
    }
    elseif ($Global:MSCloudLoginConnectionProfile.Azure.AuthenticationType -eq 'AccessTokens')
    {
        Write-Verbose -Message "Attempting to connect to Azure using Access Token"
        Connect-AzAccount -Tenant $Global:MSCloudLoginConnectionProfile.Azure.TenantId `
                          -Environment $Global:MSCloudLoginConnectionProfile.Azure.EnvironmentName `
                          -AccessToken $Global:MSCloudLoginConnectionProfile.Azure.AccessTokens | Out-Null
        $Global:MSCloudLoginConnectionProfile.Azure.ConnectedDateTime = [System.DateTime]::Now.ToString()
        $Global:MSCloudLoginConnectionProfile.Azure.Connected = $true
        $Global:MSCloudLoginConnectionProfile.Azure.MultiFactorAuthentication = $false
        Write-Verbose -Message "Successfully connected to Azure using Access Token"
    }
    elseif ($Global:MSCloudLoginConnectionProfile.Azure.AuthenticationType -eq 'Identity')
    {
        Write-Verbose -Message 'Attempting to connect to Azure using Managed Identity'
        try
        {
            if ($NULL -eq $Global:MSCloudLoginConnectionProfile.OrganizationName)
            {
                $Global:MSCloudLoginConnectionProfile.OrganizationName = Get-MSCloudLoginOrganizationName -Identity
            }

            Connect-AzAccount-TenantId $Global:MSCloudLoginConnectionProfile.OrganizationName `
                -Identity `
                -EnvironmentName $Global:MSCloudLoginConnectionProfile.Azure.EnvironmentName | Out-Null

            $Global:MSCloudLoginConnectionProfile.ExchangeOnline.ConnectedDateTime = [System.DateTime]::Now.ToString()
            $Global:MSCloudLoginConnectionProfile.ExchangeOnline.Connected = $false
            $Global:MSCloudLoginConnectionProfile.ExchangeOnline.MultiFactorAuthentication = $false
            Write-Verbose -Message 'Successfully connected to Azure using Managed Identity'
        }
        catch
        {
            throw $_
        }
    }
    else
    {
        throw "Specified authentication method is not supported."
    }
}
