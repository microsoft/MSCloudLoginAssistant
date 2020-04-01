function Connect-MSCloudLoginAzureADPreview
{
    [CmdletBinding()]
    param()
    try 
    {
        Connect-AzureAD -Credential $Global:o365Credential -ErrorAction Stop | Out-Null
        $Global:IsMFAAuth = $false
        $Global:MSCloudLoginAzureADPreviewConnected = $true
    }
    catch
    {
        if ($_.Exception -like '*unknown_user_type: Unknown User Type*')
        {
            try
            {
                Import-Module "AzureADPreview" -Prefix "AADP"
                Connect-AADPAzureAD -Credential $Global:o365Credential -AzureEnvironmentName AzureGermanyCloud -ErrorAction Stop| Out-Null
                $Global:IsMFAAuth = $false
                $Global:MSCloudLoginAzureADPreviewConnected = $true
                $Global:CloudEnvironment = 'Germany'
            }
            catch
            {
                if ($_.Exception -like '*AADSTS50076*')
                {
                    Connect-MSCloudLoginAzureADPreviewMFA
                }
                elseif ($_.Exception -like '*unknown_user_type*')
                {
                    $Global:CloudEnvironment = 'GCCHigh'
                    Connect-MSCloudLoginAzureADPreviewMFA
                }
                else
                {
                    $Global:MSCloudLoginAzureADPreviewConnected = $false
                    throw $_
                }
            }
        }
        elseif ($_.Exception -like '*AADSTS50076*')
        {
            Connect-MSCloudLoginAzureADPreviewMFA
        }
        else
        {
            $Global:MSCloudLoginAzureADPreviewConnected = $false
            throw $_
        }
    }
    return
}

function Connect-MSCloudLoginAzureADPreviewMFA
{
    [CmdletBinding()]
    param()

    # We are using an MFA enabled account. Need to call Azure AD
    try
    {
        if ($null -ne $Global:o365Credential)
        {
            if ($Global:o365Credential.UserName.Split('@')[1] -like '*.de')
            {
                $EnvironmentName = 'AzureGermanyCloud'
                $Global:CloudEnvironment = 'Germany'
            }
            else
            {
                $EnvironmentName = 'AzureCloud'
            }
            Connect-AADPAzureAD -AccountId $Global:o365Credential.UserName -AzureEnvironmentName $EnvironmentName -ErrorAction Stop | Out-Null
            $Global:IsMFAAuth = $true
            $Global:MSCloudLoginAzureADPreviewConnected = $true
        }
        else
        {
            Connect-AADPAzureAD -ErrorAction Stop | Out-Null
            $Global:MSCloudLoginAzureADPreviewConnected = $true
        }
    }
    catch
    {
        try
        {
            Connect-AADPAzureAD -AccountId $Global:o365Credential.UserName -AzureEnvironmentName AzureUSGovernment -ErrorAction Stop| Out-Null
            $Global:IsMFAAuth = $true
            $Global:MSCloudLoginAzureADPreviewConnected = $true

            if ($Global:CloudEnvironment -ne 'GCCHigh')
            {
                $Global:CloudEnvironment = 'USGovernment'
            }
        }
        catch
        {
            $Global:MSCloudLoginAzureADPreviewConnected = $false
            throw $_
        }
    }
    return
}