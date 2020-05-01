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
`           Connect-ExchangeOnline -Credential $Global:o365Credential | Out-Null
            $Global:MSCloudLoginEXOConnected = $true
        }
    }
    catch
    {
        throw $_
    }
}
