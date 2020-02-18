function Connect-MSCloudLoginSharePointOnline
{
    [CmdletBinding()]
    param()
    if($Global:UseApplicationIdentity -and $null -eq $Global:o365Credential)
    {
        throw "The SharePointOnline Platform does not support connecting with application identity."
    }
    
    try
    {        
        if ($null -ne $Global:o365Credential)
        {
            if ([string]::IsNullOrEmpty($ConnectionUrl))
            {
                $Global:spoAdminUrl = Get-SPOAdminUrl -CloudCredential $Global:o365Credential
            }
            else
            {
                $Global:spoAdminUrl = $ConnectionUrl
            }
            if ($Global:IsMFAAuth)
            {
                Connect-MSCloudLoginSharePointOnlineMFA
                return
            }
            Connect-SPOService -Credential $Global:o365Credential -Url $Global:spoAdminUrl
            $Global:MSCloudLoginSharePointOnlineConnected = $true
            $Global:IsMFAAuth = $false
        }
        else
        {
            $Global:spoAdminUrl = Get-SPOAdminUrl
            Connect-SPOService -Url $Global:spoAdminUrl
            $Global:MSCloudLoginSharePointOnlineConnected = $true
        }
    }
    catch
    {
        if ($_.Exception -like '*The sign-in name or password does not match one in the Microsoft account system*')
        {
            Connect-MSCloudLoginSharePointOnlineMFA
            return
        }
        else
        {
            $Global:MSCloudLoginSharePointOnlineConnected = $false
            throw $_
        }
    }
    return
}

function Connect-MSCloudLoginSharePointOnlineMFA
{
    [CmdletBinding()]
    param()

    try
    {
        $EnvironmentName = 'Default'
        if ($Global:o365Credential.UserName.Split('@')[1] -like '*.de')
        {
            $Global:CloudEnvironment = 'Germany'
            $EnvironmentName = 'Germany'
        }
        elseif ($Global:CloudEnvironment -eq 'GCCHigh')
        {
            $EnvironmentName = 'ITAR'
        }
        Connect-SPOService -Url $Global:spoAdminUrl -Region $EnvironmentName
        $Global:MSCloudLoginSharePointOnlineConnected = $true
        $Global:IsMFAAuth = $true
    }
    catch
    {
        $Global:MSCloudLoginSharePointOnlineConnected = $false
        throw $_
    }
    return
}