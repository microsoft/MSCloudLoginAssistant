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
            
            if (!$Global:UseApplicationIdentity -and $Global:IsMFAAuth)
            {
                Connect-MSCloudLoginSharePointOnlineMFA
                return
            }
            Connect-SPOService -Credential $Global:o365Credential -Url $Global:spoAdminUrl
            $Global:IsMFAAuth = $false
        }
        else
        {
            $Global:spoAdminUrl = Get-SPOAdminUrl
            Connect-SPOService -Url $Global:spoAdminUrl
        }
    }
    catch
    {
        if ($Global:UseApplicationIdentity)
        {
            throw $_
        }
        if ($_.Exception -like '*The sign-in name or password does not match one in the Microsoft account system*')
        {
            Connect-MSCloudLoginSharePointOnlineMFA
            return
        }
        else
        {
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
        $Global:IsMFAAuth = $true
    }
    catch
    {
        throw $_
    }
    return
}