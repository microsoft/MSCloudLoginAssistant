function Connect-MSCloudLoginPowerPlatform
{
    [CmdletBinding()]
    param(
        [Parameter()]
        [System.String]
        $ApplicationId,

        [Parameter()]
        [System.String]
        $TenantId,

        [Parameter()]
        [System.String]
        $CertificateThumbprint
    )
    try
    {
        if (-not [String]::IsNullOrEmpty($ApplicationId) -and `
        -not [String]::IsNullOrEmpty($TenantId) -and `
        -not [String]::IsNullOrEmpty($CertificateThumbprint))
        {
            if ($TenantId -like '*.de')
            {
                $Global:CloudEnvironment = 'Germany'
                Write-Warning 'Microsoft PowerPlatform is not supported in the Germany Cloud'
                return
            }
            Add-PowerAppsAccount -ApplicationId $ApplicationId `
                -TenantId $TenantId `
                -CertificateThumbprint $CertificateThumbprint `
                -ErrorAction Stop | Out-Null
            $Global:MSCloudLoginPowerPlatformConnected = $true
        }
        else
        {
            if ($Global:o365Credential.UserName.Split('@')[1] -like '*.de')
            {
                $Global:CloudEnvironment = 'Germany'
                Write-Warning 'Microsoft PowerPlatform is not supported in the Germany Cloud'
                return
            }
            Add-PowerAppsAccount -UserName $Global:o365credential.UserName `
                -Password $Global:o365Credential.Password `
                -ErrorAction Stop | Out-Null
            $Global:MSCloudLoginPowerPlatformConnected = $true
        }
    }
    catch
    {
        if ($_.Exception -like '*unknown_user_type: Unknown User Type*')
        {
            try
            {
                if (-not [String]::IsNullOrEmpty($ApplicationId) -and `
                -not [String]::IsNullOrEmpty($TenantId) -and `
                -not [String]::IsNullOrEmpty($CertificateThumbprint))
                {
                    Add-PowerAppsAccount -ApplicationId $ApplicationId `
                        -TenantId $TenantId `
                        -CertificateThumbprint $CertificateThumbprint `
                        -EndPoint 'usgov' `
                        -ErrorAction Stop | Out-Null
                    $Global:MSCloudLoginPowerPlatformConnected = $true
                }
                else
                {
                    Add-PowerAppsAccount -UserName $Global:o365credential.UserName `
                        -Password $Global:o365Credential.Password `
                        -EndPoint 'usgov' `
                        -ErrorAction Stop | Out-Null
                    $Global:MSCloudLoginPowerPlatformConnected = $true
                }
            }
            catch
            {
                try
                {
                    if (-not [String]::IsNullOrEmpty($ApplicationId) -and `
                    -not [String]::IsNullOrEmpty($TenantId) -and `
                    -not [String]::IsNullOrEmpty($CertificateThumbprint))
                    {
                        Add-PowerAppsAccount -ApplicationId $ApplicationId `
                            -TenantId $TenantId `
                            -CertificateThumbprint $CertificateThumbprint `
                            -EndPoint 'usgovhigh' `
                            -ErrorAction Stop | Out-Null
                        $Global:MSCloudLoginPowerPlatformConnected = $true
                    }
                    else
                    {
                        Add-PowerAppsAccount -UserName $Global:o365credential.UserName `
                            -Password $Global:o365Credential.Password `
                            -EndPoint 'usgovhigh' `
                            -ErrorAction Stop | Out-Null
                        $Global:MSCloudLoginPowerPlatformConnected = $true
                    }
                }
                catch
                {
                    try
                    {
                        if (-not [String]::IsNullOrEmpty($ApplicationId) -and `
                        -not [String]::IsNullOrEmpty($TenantId) -and `
                        -not [String]::IsNullOrEmpty($CertificateThumbprint))
                        {
                            Add-PowerAppsAccount -ApplicationId $ApplicationId `
                                -TenantId $TenantId `
                                -CertificateThumbprint $CertificateThumbprint `
                                -EndPoint 'preview' `
                                -ErrorAction Stop | Out-Null
                            $Global:MSCloudLoginPowerPlatformConnected = $true
                        }
                        else
                        {
                            Add-PowerAppsAccount -UserName $Global:o365credential.UserName `
                                -Password $Global:o365Credential.Password `
                                -EndPoint 'preview' `
                                -ErrorAction Stop | Out-Null
                            $Global:MSCloudLoginPowerPlatformConnected = $true
                        }
                    }
                    catch
                    {
                        Connect-MSCloudLoginPowerPlatformMFA
                    }
                }
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
            $Global:MSCloudLoginPowerPlatformConnected = $false
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
        $Global:MSCloudLoginPowerPlatformConnected = $true
    }
    catch
    {
        $Global:MSCloudLoginPowerPlatformConnected = $false
        throw $_
    }
    return
}
