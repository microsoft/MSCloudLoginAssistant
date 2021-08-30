function Connect-MSCloudLoginExchangeOnline
{
    [CmdletBinding()]
    param()

    $WarningPreference  = 'SilentlyContinue'
    $ProgressPreference = 'SilentlyContinue'

    if ($Global:MSCloudLoginConnectionProfile.ExchangeOnline.Connected)
    {
        return
    }

    [array]$activeSessions = Get-PSSession | Where-Object -FilterScript {$_.ComputerName -like '*outlook.office*' -and $_.State -eq 'Opened'}
    if ($activeSessions.Length -ge 1)
    {
        Write-Verbose -Message "Found {$($activeSessions.Length)} existing Exchange Online Session"
        $command = Get-Command "Get-AcceptedDomain" -ErrorAction 'SilentlyContinue'
        if ($null -ne $command)
        {
            $Global:MSCloudLoginConnectionProfile.ExchangeOnline.Connected = $true
            return
        }
        $EXOModule = Import-PSSession $activeSessions[0] -DisableNameChecking -AllowClobber
        Import-Module $EXOModule -Global | Out-Null
        return
    }
    Write-Verbose -Message "No active Exchange Online session found."

    #endregion
    Write-Verbose -Message "ConnectionUrl = $ConnectionUrl"
    Write-Verbose -Message "AuthorizationUrl = $AuthorizationUrl"
    if ($Global:MSCloudLoginConnectionProfile.ExchangeOnline.$AuthenticationType -eq 'ServicePrincipalWithThumbprint')
    {
        Write-Verbose -Message "Attempting to connect to Exchange Online using AAD App {$ApplicationID}"
        try
        {
            $Global:MSCloudLoginConnectionProfile.OrganizationName = Get-MSCloudLoginOrganizationName `
                -ApplicationId $Global:MSCloudLoginConnectionProfile.ExchangeOnline.ApplicationId `
                -TenantId $Global:MSCloudLoginConnectionProfile.ExchangeOnline.TenantId `
                -CertificateThumbprint $Global:MSCloudLoginConnectionProfile.ExchangeOnline.CertificateThumbprint

            Connect-ExchangeOnline -AppId $Global:MSCloudLoginConnectionProfile.ExchangeOnline.ApplicationId `
                -Organization $Global:MSCloudLoginConnectionProfile.ExchangeOnline.Organization `
                -CertificateThumbprint $Global:MSCloudLoginConnectionProfile.ExchangeOnline.CertificateThumbprint `
                -ShowBanner:$false `
                -ShowProgress:$false `
                -ConnectionUri $Global:MSCloudLoginConnectionProfile.ExchangeOnline.ConnectionUrl `
                -AzureADAuthorizationEndpointUri $Global:MSCloudLoginConnectionProfile.ExchangeOnline.AuthorizationUrl `
                -Verbose:$false | Out-Null

            $Global:MSCloudLoginConnectionProfile.ExchangeOnline.ConnectedDateTime         = [System.DateTime]::Now.ToString()
            $Global:MSCloudLoginConnectionProfile.ExchangeOnline.Connected                 = $true
            $Global:MSCloudLoginConnectionProfile.ExchangeOnline.MultiFactorAuthentication = $false
            Write-Verbose -Message "Successfully connected to Exchange Online using AAD App {$ApplicationID}"
        }
        catch
        {
            throw $_
        }
    }
    elseif ($Global:MSCloudLoginConnectionProfile.ExchangeOnline.AuthenticationType -eq 'Credentials')
    {
        try
        {
            Write-Verbose -Message "Attempting to connect to Exchange Online using Credentials without MFA"

            Connect-ExchangeOnline -Credential $Global:MSCloudLoginConnectionProfile.ExchangeOnline.Credentials `
                -ShowProgress:$false `
                -ShowBanner:$false `
                -ConnectionUri $Global:MSCloudLoginConnectionProfile.ExchangeOnline.ConnectionUrl `
                -AzureADAuthorizationEndpointUri $Global:MSCloudLoginConnectionProfile.ExchangeOnline.AuthorizationUrl `
                -Verbose:$false -ErrorAction Stop | Out-Null
            $Global:MSCloudLoginConnectionProfile.ExchangeOnline.ConnectedDateTime         = [System.DateTime]::Now.ToString()
            $Global:MSCloudLoginConnectionProfile.ExchangeOnline.Connected                 = $true
            $Global:MSCloudLoginConnectionProfile.ExchangeOnline.MultiFactorAuthentication = $false
            Write-Verbose -Message "Successfully connected to Exchange Online using Credentials without MFA"
        }
        catch
        {
            if ($_.Exception -like '*you must use multi-factor authentication to access*')
            {
                Connect-MSCloudLoginExchangeOnlineMFA -Credentials $Global:MSCloudLoginConnectionProfile.ExchangeOnline.Credentials `
                    -ConnectionUrl $Global:MSCloudLoginConnectionProfile.ExchangeOnline.ConnectionUrl
            }
            else
            {
                $Global:MSCloudLoginConnectionProfile.ExchangeOnline.Connected = $false
                throw $_
            }
        }
    }
}

function Connect-MSCloudLoginExchangeOnlineMFA
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PSCredential]
        $Credentials,

        [Parameter(Mandatory=$true)]
        [System.String]
        $ConnectionUrl
    )
    $WarningPreference = 'SilentlyContinue'
    $ProgressPreference = 'SilentlyContinue'

    try
    {
        Write-Verbose -Message "Creating a new ExchangeOnline Session using MFA"
        Connect-ExchangeOnline -UserPrincipalName $Global:MSCloudLoginConnectionProfile.ExchangeOnline.Credentials.UserName `
            -ShowBanner:$false `
            -ShowProgress:$false `
            -ConnectionUri $Global:MSCloudLoginConnectionProfile.ExchangeOnline.ConnectionUrl `
            -AzureADAuthorizationEndpointUri $Global:MSCloudLoginConnectionProfile.ExchangeOnline.AuthorizationUrl `
            -Verbose:$false | Out-Null

        $Global:MSCloudLoginConnectionProfile.ExchangeOnline.ConnectedDateTime         = [System.DateTime]::Now.ToString()
        $Global:MSCloudLoginConnectionProfile.ExchangeOnline.Connected                 = $true
        $Global:MSCloudLoginConnectionProfile.ExchangeOnline.MultiFactorAuthentication = $true
        Write-Verbose -Message "Successfully connected to Exchange Online using credentials with MFA"
    }
    catch
    {
        throw $_
    }
}
