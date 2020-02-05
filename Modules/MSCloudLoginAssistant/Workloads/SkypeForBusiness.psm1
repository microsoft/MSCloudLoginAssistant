function Connect-MSCloudLoginSkypeForBusiness
{
    [CmdletBinding()]
    param()
    if($Global:UseApplicationIdentity -and $null -eq $Global:o365Credential)
    {
        throw "The SkypeForBusiness Platform does not support connecting with application identity."
    }
    
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

    try
    {
        if ($null -eq $Global:SkypeModule -and $null -eq (Get-command Get-CsTeamsClientConfiguration -EA SilentlyContinue))
        {
            Write-Verbose "Creating a new Session to Skype for Business Servers"
            $ErrorActionPreference = "Stop"

            $adminDomain = $Global:o365Credential.UserName.Split('@')[1]
            $targetUri = Get-SkypeForBusinessServiceEndpoint -TargetDomain $adminDomain
            $appAuthInfo = Get-SkypeForBusinessAccessInfo -PowerShellEndpointUri $targetUri

            $clientId = $appAuthInfo.ClientID
            $authUri = $appAuthInfo.AuthUrl
            try
            {
                $AccessToken = Get-AccessToken -TargetUri $targetUri -ClientID $clientId `
                    -AuthUri $authUri `
                    -Credentials $Global:o365Credential
                $networkCreds = [System.Net.NetworkCredential]::new("", $AccessToken)
                $secPassword = $networkCreds.SecurePassword
                $user = "oauth"
                $cred = [System.Management.Automation.PSCredential]::new($user, $secPassword)
            }
            catch
            {
                throw $_
            }

            $queryStr = "AdminDomain=$adminDomain"

            $ConnectionUri = [UriBuilder]$targetUri
            $ConnectionUri.Query = $queryStr

            $psSessionName = "SfBPowerShellSession"
            $ConnectorVersion = "7.0.2374.2"
            $SessionOption = New-PsSessionOption
            $SessionOption.ApplicationArguments = @{}
            $SessionOption.ApplicationArguments['X-MS-Client-Version'] = $ConnectorVersion
            $SessionOption.NoMachineProfile = $true
            $Global:SkypeSession = New-PSSession -Name $psSessionName -ConnectionUri $ConnectionUri.Uri `
                -Credential $cred -Authentication Basic -SessionOption $SessionOption
            $Global:SkypeModule = Import-PSSession $Global:SkypeSession
            Import-Module $Global:SkypeModule -Global | Out-Null
        }
        else
        {
            Write-Verbose "Session to Skype For Business Servers already existed"
        }
        return
    }
    catch
    {
        if ($_.Exception -like '*Connecting to remote server*')
        {
            $adminDomain = $Global:o365Credential.UserName.Split('@')[1]
            $targetUri = Get-SkypeForBusinessServiceEndpoint -TargetDomain $adminDomain
            $RedirectURI = "urn:ietf:wg:oauth:2.0:oob";
            $clientId = '1950a258-227b-4e31-a9cf-717495945fc2'
            $Global:ADALServicePoint = New-ADALServiceInfo -TenantName $adminDomain -UserPrincipalName $Global:o365Credential.UserName
            $authResult = $Global:ADALServicePoint.authContext.AcquireTokenAsync($targetUri, $clientId, $RedirectURI, $Global:ADALServicePoint.platformParam, $Global:ADALServicePoint.userId)

            $token = $authResult.result.AccessToken
            $networkCreds = [System.Net.NetworkCredential]::new("", $token)
            $secPassword = $networkCreds.SecurePassword
            $user = "oauth"
            $cred = [System.Management.Automation.PSCredential]::new($user, $secPassword)
            $queryStr = "AdminDomain=$adminDomain"

            $ConnectionUri = [UriBuilder]$targetUri
            $ConnectionUri.Query = $queryStr

            $psSessionName = "SfBPowerShellSession"
            $ConnectorVersion = "7.0.2374.2"
            $SessionOption = New-PsSessionOption
            $SessionOption.ApplicationArguments = @{}
            $SessionOption.ApplicationArguments['X-MS-Client-Version'] = $ConnectorVersion
            $SessionOption.NoMachineProfile = $true
            $Global:SkypeSession = New-PSSession -Name $psSessionName -ConnectionUri $ConnectionUri.Uri `
                -Credential $cred -Authentication Basic -SessionOption $SessionOption
            $Global:SkypeModule = Import-PSSession $Global:SkypeSession
            Import-Module $Global:SkypeModule -Global | Out-Null
        }
        else
        {
            throw $_
        }
    }
}