function Connect-MSCloudLoginPowerPlatform
{
    [CmdletBinding()]
    param()
    if($Global:UseApplicationIdentity -and $null -eq $Global:o365Credential)
    {
        throw "The PowerPlatforms Platform does not support connecting with application identity."
    }

    try
    {
        if ($null -eq $Global:o365Credential)
        {
            Add-PowerAppsAccount -ErrorAction Stop | Out-Null
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
                Add-PowerAppsAccount -UserName $Global:o365credential.UserName `
                    -Password $Global:o365Credential.Password `
                    -EndPoint 'usgov' `
                    -ErrorAction Stop | Out-Null
                $Global:MSCloudLoginPowerPlatformConnected = $true
            }
            catch
            {
                try
                {
                    Add-PowerAppsAccount -UserName $Global:o365credential.UserName `
                        -Password $Global:o365Credential.Password `
                        -EndPoint 'usgovhigh' `
                        -ErrorAction Stop | Out-Null
                    $Global:MSCloudLoginPowerPlatformConnected = $true
                }
                catch
                {
                    try
                    {
                        Add-PowerAppsAccount -UserName $Global:o365credential.UserName `
                            -Password $Global:o365Credential.Password `
                            -EndPoint 'preview' `
                            -ErrorAction Stop | Out-Null
                        $Global:MSCloudLoginPowerPlatformConnected = $true
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
        Add-PowerAppsAccount
        $Global:MSCloudLoginPowerPlatformConnected = $true
    }
    catch
    {
        $Global:MSCloudLoginPowerPlatformConnected = $false
        throw $_
    }
    return
}