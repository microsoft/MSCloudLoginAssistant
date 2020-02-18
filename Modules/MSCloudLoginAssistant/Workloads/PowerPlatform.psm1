function Connect-MSCloudLoginPowerPlatform
{
    [CmdletBinding()]
    param()
    if($Global:UseApplicationIdentity -and $null -eq $Global:o365Credential -and $null -eq $global:appIdentityParams.OnBehalfOfUserPrincipalName)
    {
        throw "The PowerPlatforms Platform does not support connecting with application identity."
    }

    try
    {
        if($Global:UseApplicationIdentity)
        {
            Connect-MSCloudLoginPowerPlatformDelegated
        }
        elseif ($null -eq $Global:o365Credential)
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

function Connect-MSCloudLoginPowerPlatformDelegated
{
    [CmdletBinding()]
    param()
    try
    {
        $userprincipalNameToUse = ""
        if($null -eq $Global:o365Credential)
        {
            $userprincipalNameToUse = $global:appIdentityParams.OnBehalfOfUserPrincipalName
        }
        else
        {
            $userprincipalNameToUse = $Global:o365Credential.UserName
        }


        if($global:currentSession.customModuleLoaded)
        {
            return;
        }

        $mod=Get-Module Microsoft.PowerApps.AuthModule -All
        if($mod)
        {
            Remove-Module $mod
        }

        # importing a module from within a module is not really recommended
        # but ours is a special case since we want to override the auth module of the power apps module
        # this is also why we set the -global flag
        Import-Module "$PSScriptRoot\..\Utilities\DelegatedPowerAppsAuth\Microsoft.PowerApps.AuthModule.psm1" -Force -Global
        Add-PowerAppsAccount -UserName $userprincipalNameToUse
        $Global:MSCloudLoginPowerPlatformConnected = $true
    }
    catch
    {
        $Global:MSCloudLoginPowerPlatformConnected = $false
        throw $_
    }
    return
}