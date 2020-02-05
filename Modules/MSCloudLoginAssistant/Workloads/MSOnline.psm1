function Connect-MSCloudLoginMSOnline
{
    [CmdletBinding()]
    param()
    if($Global:UseApplicationIdentity -and $null -eq $Global:o365Credential)
    {
        throw "The MSOnline Platform does not support connecting with application identity."
    }
    
    if ($null -ne $Global:o365Credential)
    {
        Test-MSCloudLogin -Platform AzureAD -CloudCredential $Global:o365Credential
        if ($Global:IsMFAAuth)
        {
            Connect-MSCloudLoginMSOnlineMFA
            return
        }
        try
        {
            $InformationPreference ='SilentlyContinue'
            $EnvironmentName = 'AzureCloud'
            
            if ($Global:o365Credential.UserName.Split('@')[1] -like '*.de')
            {
                $Global:CloudEnvironment = 'Germany'
                $EnvironmentName = 'AzureGermanyCloud'
            }

            Connect-MsolService -Credential $Global:o365Credential -AzureEnvironment $EnvironmentName -ErrorAction Stop | Out-Null
            $Global:MSCloudLoginMSOnlineConnected = $true
            $Global:IsMFAAuth = $false
        }
        catch
        {
            if ($_.Exception -like '*Authentication Error: Bad username or password.*')
            {
                try
                {
                    Connect-MsolService -Credential $Global:o365Credential -AzureEnvironment 'AzureUSGovernmentCloud' -ErrorAction Stop | Out-Null
                    $Global:MSCloudLoginMSOnlineConnected = $true
                    $Global:IsMFAAuth = $false
                }
                catch
                {
                    $Global:MSCloudLoginMSOnlineConnected = $false
                    throw $_
                }
            }
            else
            {
                $Global:MSCloudLoginMSOnlineConnected = $false
                throw $_
            }
        }
    }
    else
    {
        try
        {
            Connect-MsolService | Out-Null
            $Global:MSCloudLoginMSOnlineConnected = $true
        }
        catch
        {
            $Global:MSCloudLoginMSOnlineConnected = $false
            throw $_
        }
    }
    return
}

function Connect-MSCloudLoginMSOnlineMFA
{
    [CmdletBinding()]
    param()

    try
    {
        $clientID = "1b730954-1685-4b74-9bfd-dac224a7b894";
        $ResourceURI = "https://graph.windows.net";
        $RedirectURI = "urn:ietf:wg:oauth:2.0:oob";
        $AuthHeader = Get-AuthHeader -UserPrincipalName $Global:o365Credential.UserName `
            -ResourceURI $ResourceURI -clientID $clientID -RedirectURI $RedirectURI
        $AccessToken = $AuthHeader.split(" ")[1]
        Connect-MsolService -AdGraphAccessToken $AccessToken
        $Global:MSCloudLoginMSOnlineConnected = $true
        $Global:IsMFAAuth = $true
    }
    catch
    {
        $Global:MSCloudLoginMSOnlineConnected = $false
        throw $_
    }
}