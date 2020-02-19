function Connect-MSCloudLoginSkypeForBusiness
{
    [CmdletBinding()]
    param()
    if($Global:UseApplicationIdentity -and $null -eq $Global:o365Credential -and $null -eq $global:appIdentityParams.OnBehalfOfUserPrincipalName)
    {
        throw "The SkypeForBusiness Platform does not support connecting with application identity."
    }
    
    if (!$Global:UseApplicationIdentity -and $null -eq $Global:o365Credential)
    {
       $Global:o365Credential = Get-Credential -Message "Cloud Credential"
    }
    
    $userprincipalNameToUse = ""    
    if($null -eq $Global:o365Credential)
    {
        $userprincipalNameToUse = $global:appIdentityParams.OnBehalfOfUserPrincipalName
    }
    else
    {        
        $userprincipalNameToUse = $Global:o365Credential.UserName           
    }

    $adminDomain = $userprincipalNameToUse.Split('@')[1]
    if ($userprincipalNameToUse.Split('@')[1] -like '*.de')
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
            
            $targetUri = Get-SkypeForBusinessServiceEndpoint -TargetDomain $adminDomain
               
            try
            {
                if($Global:UseApplicationIdentity)
                {
                    # we don't call Get-SkypeForBusinessAccessInfo
                    # in the application identity use case we have our own clientId
                    # disregarded the $authuri for now since it would mean that the authentication context would not be global any more
                    $AccessToken = Get-OnBehalfOfAccessToken -TargetUri $targetUri -UserPrincipalName $userprincipalNameToUse
                }
                else
                {
                    $appAuthInfo = Get-SkypeForBusinessAccessInfo -PowerShellEndpointUri $targetUri
                    $clientId = $appAuthInfo.ClientID
                    $authUri = $appAuthInfo.AuthUrl
                    $AccessToken = Get-AccessToken -TargetUri $targetUri -ClientID $clientId `
                        -AuthUri $authUri `
                        -Credentials $Global:o365Credential
                }
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
        # for application identity we do not want to retry, not sure how it would help since the call would be identical to the one above
        if ($_.Exception -like '*Connecting to remote server*' -and !$Global:UseApplicationIdentity)
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