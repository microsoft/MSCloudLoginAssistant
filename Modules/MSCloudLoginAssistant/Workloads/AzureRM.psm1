function Connect-MSCloudLoginAzureRM
{
    [CmdletBinding()]
    param()

    $WarningPreference = 'SilentlyContinue'
    $InformationPreference = 'SilentlyContinue'
    $ProgressPreference = 'SilentlyContinue'
    $VerbosePreference = 'SilentlyContinue'

    if ($Global:MSCloudLoginConnectionProfile.AzureRM.AuthenticationType -eq 'Credentials')
    {
        Write-Verbose -Message "Attempting to connect to AzureRM using Credentials"

        try
        {
            Connect-AzAccount -Credential $MSCloudLoginConnectionProfile.AzureRM.Credential
        }
        catch
        {

        }
        $Global:MSCloudLoginConnectionProfile.AzureDevOPS.ConnectedDateTime = [System.DateTime]::Now.ToString()
        $Global:MSCloudLoginConnectionProfile.AzureDevOPS.Connected = $true
        $Global:MSCloudLoginConnectionProfile.AzureDevOPS.MultiFactorAuthentication = $false
        Write-Verbose -Message "Successfully connected to AzureRM using Credentials"
    }
    elseif ($Global:MSCloudLoginConnectionProfile.AzureRM.AuthenticationType -eq 'ServicePrincipalWithThumbprint')
    {
        Write-Verbose -Message "Attempting to connect to AzureRM using AAD App {$ApplicationID}"
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
    else
    {
        throw "Specified authentication method is not supported."
    }
}
