function Connect-MSCloudLoginSkypeForBusiness
{
    [CmdletBinding()]
    param()
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
            $appAuthInfo = Get-SkypeForBusinessAccessInfo -PowerShellEndpointUri $targetUri
            $RedirectURI = "urn:ietf:wg:oauth:2.0:oob";

            $clientId = $appAuthInfo.ClientID
            $authUri = 'https://login.windows.net/common/oauth2/authorize'
            Write-Host $clientId
            Write-Host $targetUri
            Write-Host $authUri
            $psSessionName = "SfBPowerShellSession"
            $AuthHeader = Get-AuthHeader -UserPrincipalName $Global:o365Credential.UserName `
                -RessourceURI $AuthUri `
                -clientID $clientID `
                -RedirectURI $targetUri
            $Password = ConvertTo-SecureString -AsPlainText $AuthHeader -Force
            $Ctoken = New-Object System.Management.Automation.PSCredential -ArgumentList $Global:o365Credential.UserName, $Password
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
                -Credential $Ctoken -Authentication Basic -SessionOption $SessionOption
            $Global:SkypeModule = Import-PSSession $Global:SkypeSession
        }
        else
        {
            throw $_
        }
    }
}