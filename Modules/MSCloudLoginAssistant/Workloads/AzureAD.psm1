function Connect-MSCloudLoginAzureAD
{
    [CmdletBinding()]
    param()
    try 
    {
        if ($Global:UseApplicationIdentity)
        {
            if($Global:appIdentityParams.CertificateThumbprint) 
            {
                
                Write-Verbose "Parameters to be used to connect to AzureAD: -TenantId $($Global:appIdentityParams.Tenant) -ApplicationId $($Global:appIdentityParams.AppId) -CertificateThumbprint $($Global:appIdentityParams.CertificateThumbprint)"  
                Connect-AzureAD -TenantId $Global:appIdentityParams.Tenant -ApplicationId $Global:appIdentityParams.AppId -CertificateThumbprint $Global:appIdentityParams.CertificateThumbprint -ErrorAction Stop | Out-Null         
                Write-Verbose "Connected to AzureAD using application identity with certificate thumbprint"            
            }
            else
            {                
                # actually it probably can do so by getting the access token manually, but for now we want it to work with the certificate
                throw "The AzureAD Platform does not support connecting with application secret"
            }            
        }
        else
        {
            Connect-AzureAD -Credential $Global:o365Credential -ErrorAction Stop | Out-Null
            Write-Verbose "Connected to AzureAD using regular authentication"
        }
        
        $Global:IsMFAAuth = $false
    }
    catch
    {
        if ($Global:UseApplicationIdentity)
        {
            throw $_
        }        
        if ($_.Exception -like '*unknown_user_type: Unknown User Type*')
        {
            try
            {
                Connect-AzureAD -Credential $Global:o365Credential -AzureEnvironmentName AzureGermanyCloud -ErrorAction Stop| Out-Null
                $Global:IsMFAAuth = $false                
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
        }
        else
        {
            Connect-AzureAD -ErrorAction Stop | Out-Null            
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
            throw $_
        }
    }
    return
}