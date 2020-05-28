function Connect-MSCloudLoginPowerPlatform
{
    [CmdletBinding()]
    param()
    if ($null -eq $Global:o365Credential)
    {
        $Global:o365Credential = Get-Credential -Message "Cloud Credential"
    }

    #region Get Connection Info
    if ($null -eq $Global:EnvironmentName)
    {
        $Global:EnvironmentName = Get-CloudEnvironment -Credentials $Global:o365Credential
    }
    Write-Verbose -Message "Detected Azure Environment: $EnvironmentName"

    $ConnectionUrl = $null
    switch ($Global:EnvironmentName)
    {
        "AzureCloud" {
            $EndPoint = 'https://outlook.office365.com/powershell-liveid/'
        }
        "AzureUSGovernment" {
            $EndPoint = 'https://outlook.office365.us/powershell-liveid/'
        }
        "AzureGermanCloud" {
            $EndPoint = 'https://outlook.office.de/powershell-liveid/'
        }
    }
    #endregion

    #region Load ADAL context
    <#Import-Module 'Microsoft.PowerApps.Administration.PowerShell' -Force | Out-Null
    $module = Get-Module 'Microsoft.PowerApps.Administration.PowerShell'
    $ADALBinaryPath = $module.Path.Replace("Microsoft.PowerApps.Administration.Powershell.psm1", "Microsoft.IdentityModel.Clients.ActiveDirectory.dll");
    [System.Reflection.Assembly]::LoadFrom($ADALBinaryPath) | Out-Null#>
    #endregion
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
