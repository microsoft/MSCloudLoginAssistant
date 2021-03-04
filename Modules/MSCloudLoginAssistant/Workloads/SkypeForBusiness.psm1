function Connect-MSCloudLoginSkypeForBusiness
{
    [CmdletBinding()]
    param()
    if ($Global:UseApplicationIdentity -and $null -eq $Global:o365Credential -and $null -eq $global:appIdentityParams.OnBehalfOfUserPrincipalName)
    {
        throw "The SkypeForBusiness Platform does not support connecting with application identity."
    }

    if (!$Global:UseApplicationIdentity -and $null -eq $Global:o365Credential)
    {
        $Global:o365Credential = Get-Credential -Message "Cloud Credential"
    }

    $userprincipalNameToUse = ""
    if ($null -eq $Global:o365Credential)
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


    # Skype for Business actually has a cool cmdlet inside of the MicrosoftTeams module named New-CsOnlineSession
    # unfortunately I could not get it to work with the application identity so we remain like this
    # There is probably a way to achieve it with the application identity but I do not want to risk breaking things, atleast for the time being
    # hope to revisit it in the future

    $maxConnectionsSearchString = "The maximum number of concurrent shells"
    
    Ensure-RemotePsSession -RemoteSessionName "Skype For Business" `
        -TestModuleLoadedCommand "Get-CsTeamsClientConfiguration" `
        -MaxConnectionsMessageSearchString $maxConnectionsSearchString `
        -ExistingSessionPredicate { $_.Name -like 'SfBPowerShellSession*' } `
        -MaxAttempts 15 `
        -CreateSessionScriptBlock {

        $ErrorActionPreference = "Stop"

        $targetUri = Get-SkypeForBusinessServiceEndpoint -TargetDomain $adminDomain

        # we don't call Get-SkypeForBusinessAccessInfo
        # in the application identity use case we have our own clientId
        # disregarded the $authuri for now since it would mean that the authentication context would not be global any more
        $AccessToken = Get-OnBehalfOfAccessToken -TargetUri $targetUri -UserPrincipalName $userprincipalNameToUse

        $networkCreds = [System.Net.NetworkCredential]::new("", $AccessToken)
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


        # leaving the global variables just in case some cmdlet uses them
        $Global:SkypeSession = New-PSSession -Name $psSessionName -ConnectionUri $ConnectionUri.Uri `
            -Credential $cred -Authentication Basic -SessionOption $SessionOption
        $Global:SkypeModule = Import-PSSession $Global:SkypeSession
        Import-Module $Global:SkypeModule -Global | Out-Null
    }
}
