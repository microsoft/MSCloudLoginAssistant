function Connect-MSCloudLoginAzureAD
{
    [CmdletBinding()]
    param()

    if ($Global:MSCloudLoginConnectionProfile.AzureAD.Connected)
    {
        return
    }

    # Explicitly import the required module(s) in case there is cmdlet ambiguity with other modules e.g. SharePointPnPPowerShell2013
    Import-Module -Name AzureADPreview -DisableNameChecking -Force

    if ($Global:MSCloudLoginConnectionProfile.AzureAD.AuthenticationType -eq 'ServicePrincipalWithThumbprint')
    {
        Write-Verbose -Message "Connecting to AzureAD using Application {$ApplicationId}"
        try
        {
            Connect-AzureAD -ApplicationId $Global:MSCloudLoginConnectionProfile.AzureAD.ApplicationId `
                            -TenantId $Global:MSCloudLoginConnectionProfile.AzureAD.TenantId `
                            -CertificateThumbprint $Global:MSCloudLoginConnectionProfile.AzureAD.CertificateThumbprint | Out-Null
            $Global:MSCloudLoginConnectionProfile.AzureAD.ConnectedDateTime         = [System.DateTime]::Now.ToString()
            $Global:MSCloudLoginConnectionProfile.AzureAD.MultiFactorAuthentication = $false
            $Global:MSCloudLoginConnectionProfile.AzureAD.Connected                 = $true
        }
        catch
        {
            throw $_
        }
    }
    elseif ($Global:MSCloudLoginConnectionProfile.AzureAD.AuthenticationType -eq "Credentials")
    {
        try
        {
            Connect-AzureAD -Credential $Global:MSCloudLoginConnectionProfile.AzureAD.Credentials `
                            -AzureEnvironmentName $Global:MSCloudLoginConnectionProfile.AzureAD.EnvironmentName -ErrorAction Stop | Out-Null
            $Global:MSCloudLoginConnectionProfile.AzureAD.ConnectedDateTime         = [System.DateTime]::Now.ToString()
            $Global:MSCloudLoginConnectionProfile.AzureAD.MultiFactorAuthentication = $false
            $Global:MSCloudLoginConnectionProfile.AzureAD.Connected                 = $true
        }
        catch
        {
            if ($_.Exception -like '*AADSTS50076*' -or $_.Exception -like '*unknown_user_type*')
            {
                Connect-MSCloudLoginAzureADMFA
            }
            else
            {
                $Global:MSCloudLoginConnectionProfile.AzureAD.Connected = $false
                throw $_
            }
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
        Connect-AzureAD -AccountId $Global:MSCloudLoginConnectionProfile.AzureAD.Credentials.UserName `
            -AzureEnvironmentName $Global:MSCloudLoginConnectionProfile.AzureAD.EnvironmentName -ErrorAction Stop | Out-Null
        $Global:MSCloudLoginConnectionProfile.AzureAD.ConnectedDateTime         = [System.DateTime]::Now.ToString()
        $Global:MSCloudLoginConnectionProfile.AzureAD.MultiFactorAuthentication = $true
        $Global:MSCloudLoginConnectionProfile.AzureAD.Connected                 = $true
    }
    catch
    {
        $Global:MSCloudLoginConnectionProfile = $false
        throw $_
    }
    return
}
