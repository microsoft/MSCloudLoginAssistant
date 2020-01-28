function Connect-MSCloudLoginAzureAD
{
    [CmdletBinding()]
    param()
    try 
    {
        Connect-AzureAD -Credential $Global:o365Credential -ErrorAction Stop | Out-Null
        $Global:IsMFAAuth = $false
        $Global:MSCloudLoginAzureADConnected = $true
    }
    catch
    {
        if ($_.Exception -like '*unknown_user_type: Unknown User Type*')
        {
            try
            {
                Connect-AzureAD -Credential $Global:o365Credential -AzureEnvironmentName AzureGermanyCloud -ErrorAction Stop| Out-Null
                $Global:IsMFAAuth = $false
                $Global:MSCloudLoginAzureADConnected = $true
                $Global:CloudEnvironment = 'Germany'
            }
            catch
            {
                if ($_.Exception -like '*AADSTS50076*')
                {
                    Connect-MSCloudLoginAzureADMFA
                }
                elseif ($_.Exception -like '*unknown_user_type*')
                {
                    $Global:CloudEnvironment = 'GCCHigh'
                    Connect-MSCloudLoginAzureADMFA
                }
                else
                {
                    $Global:MSCloudLoginAzureADConnected = $false
                    throw $_
                }
            }
        }
        elseif ($_.Exception -like '*AADSTS50076*')
        {
            Connect-MSCloudLoginAzureADMFA
        }
        else
        {
            $Global:MSCloudLoginAzureADConnected = $false
            throw $_
        }
    }
    return
}

function Connect-MSCloudLoginAzureADMFA
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
            Connect-AzureAD -AccountId $Global:o365Credential.UserName -AzureEnvironmentName $EnvironmentName -ErrorAction Stop | Out-Null
            $Global:IsMFAAuth = $true
            $Global:MSCloudLoginAzureADConnected = $true
        }
        else
        {
            Connect-AzureAD -ErrorAction Stop | Out-Null
            $Global:MSCloudLoginAzureADConnected = $true
        }
    }
    catch
    {
        try
        {
            Connect-AzureAD -AccountId $Global:o365Credential.UserName -AzureEnvironmentName AzureUSGovernment -ErrorAction Stop| Out-Null
            $Global:IsMFAAuth = $true
            $Global:MSCloudLoginAzureADConnected = $true

            if ($Global:CloudEnvironment -ne 'GCCHigh')
            {
                $Global:CloudEnvironment = 'USGovernment'
            }
        }
        catch
        {
            $Global:MSCloudLoginAzureADConnected = $false
            throw $_
        }
    }
    return
}