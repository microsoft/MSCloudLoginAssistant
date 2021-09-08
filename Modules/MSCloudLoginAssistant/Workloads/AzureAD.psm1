function Connect-MSCloudLoginAzureAD
{
    [CmdletBinding()]
    param()
    $VerbosePreference = 'SilentlyContinue'

    Write-Verbose -Message "AZUREAD WHOAMI: $(whoami)"

    Write-Verbose -Message "Connection Profile: $($Global:MSCloudLoginConnectionProfile.AzureAD | Out-String)"
    if ($Global:MSCloudLoginConnectionProfile.AzureAD.Connected)
    {
        Write-Verbose -Message "Already connected to AzureAD"
        return
    }

    try
    {
        $commandResult = Get-AzureADSubscribedSku -ErrorAction 'Stop'
        Write-Verbose -Message "Retrieved results from the command. Not re-connecting to AzureAD"
        $Global:MSCloudLoginConnectionProfile.AzureAD.Connected = $true
        return
    }
    catch
    {
        Write-Verbose -Message "Couldn't get results back from the command"
    }

    if ($Global:MSCloudLoginConnectionProfile.AzureAD.AuthenticationType -eq 'ServicePrincipalWithThumbprint')
    {
        Write-Verbose -Message "Connecting to AzureAD using Application {$($Global:MSCloudLoginConnectionProfile.AzureAD.ApplicationId)}"
        try
        {
            Write-Verbose -Message "Connecting with Thumbprint"
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
            Write-Verbose -Message "Connecting with Credentials"
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
