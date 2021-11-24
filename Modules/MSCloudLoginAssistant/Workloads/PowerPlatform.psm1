function Connect-MSCloudLoginPowerPlatform
{
    [CmdletBinding()]
    param()

    $VerbosePreference = 'SilentlyContinue'
    $WarningPreference = 'SilentlyContinue'

    if($Global:MSCloudLoginConnectionProfile.PowerPlatform.Connected)
    {
        return
    }

    try
    {
        if ($psversiontable.PSVersion.Major -ge 7)
        {
            Write-Verbose -Message "Using PowerShell 7 or above. Loading the Microsoft.PowerApps.Administration.PowerShell module using Windows PowerShell."
            Import-Module Microsoft.PowerApps.Administration.PowerShell -UseWindowsPowerShell -Global -DisableNameChecking | Out-Null
        }
        if ($Global:MSCloudLoginConnectionProfile.PowerPlatform.EnvironmentName -eq 'AzureGermany')
        {
            Write-Warning 'Microsoft PowerPlatform is not supported in the Germany Cloud'
            return
        }

        switch ($Global:MSCloudLoginConnectionProfile.PowerPlatform.EnvironmentName)
        {
            'AzureUSGovernment'{
                $Global:MSCloudLoginConnectionProfile.PowerPlatform.Endpoint = 'usgovhigh'
            }
        }

        if ($Global:MSCloudLoginConnectionProfile.PowerPlatform.AuthenticationType -eq 'ServicePrincipalWithThumbprint')
        {
            Add-PowerAppsAccount -ApplicationId $Global:MSCloudLoginConnectionProfile.PowerPlatform.ApplicationId `
                -TenantId $Global:MSCloudLoginConnectionProfile.PowerPlatform.TenantId `
                -CertificateThumbprint $Global:MSCloudLoginConnectionProfile.PowerPlatform.CertificateThumbprint `
                -Endpoint $Global:MSCloudLoginConnectionProfile.PowerPlatform.Endpoint `
                -ErrorAction Stop | Out-Null
            $Global:MSCloudLoginConnectionProfile.PowerPlatform.ConnectedDateTime         = [System.DateTime]::Now.ToString()
            $Global:MSCloudLoginConnectionProfile.PowerPlatform.MultiFactorAuthentication = $false
            $Global:MSCloudLoginConnectionProfile.PowerPlatform.Connected                 = $true
        }
        else
        {
            Add-PowerAppsAccount -UserName $Global:MSCloudLoginConnectionProfile.PowerPlatform.Credentials.UserName `
                -Password $Global:MSCloudLoginConnectionProfile.PowerPlatform.Credentials.Password `
                -Endpoint $Global:MSCloudLoginConnectionProfile.PowerPlatform.Endpoint `
                -ErrorAction Stop | Out-Null
            $Global:MSCloudLoginConnectionProfile.PowerPlatform.ConnectedDateTime         = [System.DateTime]::Now.ToString()
            $Global:MSCloudLoginConnectionProfile.PowerPlatform.MultiFactorAuthentication = $false
            $Global:MSCloudLoginConnectionProfile.PowerPlatform.Connected                 = $true
        }
    }
    catch
    {
        if ($_.Exception -like '*unknown_user_type: Unknown User Type*')
        {
            try
            {
                if ($Global:MSCloudLoginConnectionProfile.PowerPlatform.AuthenticationType -eq 'ServicePrincipalWithThumbprint')
                {
                    Add-PowerAppsAccount -ApplicationId $Global:MSCloudLoginConnectionProfile.PowerPlatform.ApplicationId `
                        -TenantId Global:MSCloudLoginConnectionProfile.PowerPlatform.$TenantId `
                        -CertificateThumbprint $Global:MSCloudLoginConnectionProfile.PowerPlatform.CertificateThumbprint `
                        -EndPoint 'preview' `
                        -ErrorAction Stop | Out-Null
                    $Global:MSCloudLoginConnectionProfile.PowerPlatform.ConnectedDateTime         = [System.DateTime]::Now.ToString()
                    $Global:MSCloudLoginConnectionProfile.PowerPlatform.MultiFactorAuthentication = $false
                    $Global:MSCloudLoginConnectionProfile.PowerPlatform.Connected                 = $true
                }
                else
                {
                    Add-PowerAppsAccount -UserName $Global:MSCloudLoginConnectionProfile.PowerPlatform.Credentials.UserName `
                        -Password $Global:MSCloudLoginConnectionProfile.PowerPlatform.Credentials.Password `
                        -EndPoint 'preview' `
                        -ErrorAction Stop | Out-Null

                    $Global:MSCloudLoginConnectionProfile.PowerPlatform.ConnectedDateTime         = [System.DateTime]::Now.ToString()
                    $Global:MSCloudLoginConnectionProfile.PowerPlatform.MultiFactorAuthentication = $false
                    $Global:MSCloudLoginConnectionProfile.PowerPlatform.Connected                 = $true
                }
            }
            catch
            {
                Connect-MSCloudLoginPowerPlatformMFA
            }
        }
        elseif ($_.Exception -like '*AADSTS50076: Due to a configuration change made by your administrator*')
        {
            Connect-MSCloudLoginPowerPlatformMFA
        }
        elseif ($_.Exception -like '*Cannot find an overload for "UserCredential"*')
        {
            Connect-MSCloudLoginPowerPlatformMFA
        }
        else
        {
            $Global:MSCloudLoginConnectionProfile.PowerPlatform.Connected = $false
            throw $_
        }
    }
    return
}

function Connect-MSCloudLoginPowerPlatformMFA
{
    [CmdletBinding()]
    param()
    try
    {
        Test-PowerAppsAccount

        $Global:MSCloudLoginConnectionProfile.PowerPlatform.ConnectedDateTime         = [System.DateTime]::Now.ToString()
        $Global:MSCloudLoginConnectionProfile.PowerPlatform.MultiFactorAuthentication = $true
        $Global:MSCloudLoginConnectionProfile.PowerPlatform.Connected                 = $true
    }
    catch
    {
        $Global:MSCloudLoginConnectionProfile.PowerPlatform.Connected = $false
        throw $_
    }
    return
}
