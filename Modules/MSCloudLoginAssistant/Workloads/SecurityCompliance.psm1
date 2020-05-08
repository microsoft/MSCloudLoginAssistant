function Connect-MSCloudLoginSecurityCompliance
{
    [CmdletBinding()]
    param(
        [Parameter()]
        [System.String]$Prefix
    )

    if ($null -eq $Global:o365Credential)
    {
        $Global:o365Credential = Get-Credential -Message "Cloud Credential"
    }

    try
    {
        if ($null -eq $Global:MSCloudLoginSCConnected -or -not $Global:MSCloudLoginSCConnected)
        {
`           Connect-IPPSSession -Credential $Global:o365Credential | Out-Null
            $Global:MSCloudLoginSCConnected = $true
        }
    }
    catch
    {
        if ($_.Exception -like '*you must use multi-factor authentication to access*')
        {
            try
            {
                Connect-IPPSSession -UserPrincipalName $Global:o365Credential.UserName | Out-Null
                $Global:MSCloudLoginSCConnected = $true
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
