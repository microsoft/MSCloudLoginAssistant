function Connect-MSCloudLoginSkypeForBusiness
{
    [CmdletBinding()]
    param(
        [Parameter()]
        [System.String]
        $Prefix
    )
    if ($null -eq $Global:SfBOAccessToken)
    {
        if ($null -eq $Global:o365Credential)
        {
            $Global:o365Credential = Get-Credential -Message "Cloud Credential"
        }
        if ($Global:o365Credential.UserName.Split('@')[1] -like '*.de')
        {
            $Global:CloudEnvironment = 'Germany'
            Write-Warning 'Microsoft Teams is not supported in the Germany Cloud'
            return
        }
    }

    try
    {
        if ($null -eq $Global:SkypeModule -and $null -eq (Get-Command Get-CsTeamsClientConfiguration -EA SilentlyContinue))
        {
            Write-Verbose -Message "Creating a new Session to Skype for Business Servers"
            $Global:SkypeSession = New-CsOnlineSession -Credential $Global:o365Credential `
                -ErrorAction Stop
            $Global:SkypeModule = Import-PSSession $Global:SkypeSession
            $IPMOParameters = @{}
            if ($PSBoundParameters.containskey("Prefix"))
            {
                $IPMOParameters.add("Prefix",$prefix)
            }
            Import-Module $Global:SkypeModule -Global @IPMOParameters | Out-Null
        }
        else
        {
            Write-Verbose "Session to Skype For Business Servers already existed"
        }
        return
    }
    catch
    {
        if ($_.Exception -like '*Connecting to remote server*' -or `
            $_.Exception -like '*Due to a configuration change made by your*')
        {
            Write-Verbose -Message "The connection requires MFA. Attempting to connect with Multi-Factor."

            $Global:SkypeSession = New-CsOnlineSession
            $Global:SkypeModule = Import-PSSession $Global:SkypeSession
            $IPMOParameters = @{}
            if ($PSBoundParameters.containskey("Prefix"))
            {
                $IPMOParameters.add("Prefix",$prefix)
            }
            Import-Module $Global:SkypeModule -Global @IPMOParameters | Out-Null
        }
        else
        {
            Write-Error $_
            throw $_
        }
    }
}
