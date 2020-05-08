function Connect-MSCloudLoginExchangeOnline
{
    [CmdletBinding()]
    param(
        [Parameter()]
        [System.String]
        $Prefix
    )
    if ($null -eq $Global:o365Credential)
    {
        $Global:o365Credential = Get-Credential -Message "Cloud Credential"
    }

    try
    {
        if ($null -eq $Global:MSCloudLoginEXOConnected -or -not $Global:MSCloudLoginEXOConnected)
        {
`           Connect-ExchangeOnline -Credential $Global:o365Credential -ShowBanner:$false -ShowProgress:$false | Out-Null
            $Global:MSCloudLoginEXOConnected = $true
        }
    }
    catch
    {
        if ($_.Exception -like '*you must use multi-factor authentication to access*')
        {
            try
            {
                Connect-ExchangeOnline -UserPrincipalName $Global:o365Credential.UserName -ShowBanner:$false -ShowProgress:$false | Out-Null
                $Global:MSCloudLoginEXOConnected = $true
            }
            catch
            {
                throw $_
            }
        }
        else
        {
            throw $_
        }
    }
}
