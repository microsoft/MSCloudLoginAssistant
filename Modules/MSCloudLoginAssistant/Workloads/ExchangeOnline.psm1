function Connect-MSCloudLoginExchangeOnline
{
    [CmdletBinding()]
    param()

    $WarningPreference = 'SilentlyContinue'
    $InformationPreference = 'SilentlyContinue'
    $ProgressPreference = 'SilentlyContinue'
    $VerbosePreference = 'SilentlyContinue'

    Write-Verbose -Message 'Trying to get the Get-AcceptedDomain command from within MSCloudLoginAssistant'
    try
    {
        Get-AcceptedDomain -ErrorAction Stop
        Write-Verbose -Message 'Succeeded'
        $Global:MSCloudLoginConnectionProfile.ExchangeOnline.Connected = $true
        return
    }
    catch
    {
        Write-Verbose -Message 'Failed'
    }

    if ($Global:MSCloudLoginConnectionProfile.ExchangeOnline.Connected -and `
            $Global:MSCloudLoginConnectionProfile.ExchangeOnline.SkipModuleReload)
    {
        $Global:MSCloudLoginConnectionProfile.ExchangeOnline.Connected = $true
        return
    }

    Write-Verbose -Message "Loaded Modules: $(Get-Module | Select-Object Name)"
    $loadedModules = Get-Module
    $AlreadyLoadedEXOProxyModules = $loadedModules | Where-Object -FilterScript { $_.ExportedCommands.Keys.Contains('Get-AcceptedDomain') }
    foreach ($loadedModule in $AlreadyLoadedEXOProxyModules)
    {
        Write-Verbose -Message "Removing module {$($loadedModule.Name)} from current EXO session"
        Remove-Module $loadedModule.Name -Force -Verbose:$false | Out-Null
    }

    [array]$activeSessions = Get-PSSession | Where-Object -FilterScript { $_.ComputerName -like '*outlook.office*' -and $_.State -eq 'Opened' }
    Write-Verbose -Message "Active Sessions: $($activeSessions | Out-String)"
    if ($activeSessions.Length -ge 1)
    {
        Write-Verbose -Message "Found {$($activeSessions.Length)} existing Exchange Online Session"
        $ProxyModule = Import-PSSession $activeSessions[0] `
            -DisableNameChecking `
            -AllowClobber
        Write-Verbose -Message "Imported session into $ProxyModule"
        Import-Module $ProxyModule -Global `
            -Verbose:$false | Out-Null
        $Global:MSCloudLoginConnectionProfile.ExchangeOnline.Connected = $true
        Write-Verbose 'Reloaded the Exchange Module'
        return
    }
    Write-Verbose -Message 'No active Exchange Online session found.'

    # Make sure we disconnect from any existing connections
    Disconnect-ExchangeOnline -Confirm:$false

    if ($Global:MSCloudLoginConnectionProfile.ExchangeOnline.AuthenticationType -eq 'ServicePrincipalWithThumbprint')
    {
        Write-Verbose -Message "Attempting to connect to Exchange Online using AAD App {$ApplicationID}"
        try
        {
            if ($NULL -eq $Global:MSCloudLoginConnectionProfile.OrganizationName)
            {
                $Global:MSCloudLoginConnectionProfile.OrganizationName = Get-MSCloudLoginOrganizationName `
                    -ApplicationId $Global:MSCloudLoginConnectionProfile.ExchangeOnline.ApplicationId `
                    -TenantId $Global:MSCloudLoginConnectionProfile.ExchangeOnline.TenantId `
                    -CertificateThumbprint $Global:MSCloudLoginConnectionProfile.ExchangeOnline.CertificateThumbprint
            }

            Connect-ExchangeOnline -AppId $Global:MSCloudLoginConnectionProfile.ExchangeOnline.ApplicationId `
                -Organization $Global:MSCloudLoginConnectionProfile.OrganizationName `
                -CertificateThumbprint $Global:MSCloudLoginConnectionProfile.ExchangeOnline.CertificateThumbprint `
                -ShowBanner:$false `
                -ShowProgress:$false `
                -ExchangeEnvironmentName $Global:MSCloudLoginConnectionProfile.ExchangeOnline.ExchangeEnvironmentName `
                -Verbose:$false `
                -SkipLoadingCmdletHelp | Out-Null

            $Global:MSCloudLoginConnectionProfile.ExchangeOnline.ConnectedDateTime = [System.DateTime]::Now.ToString()
            $Global:MSCloudLoginConnectionProfile.ExchangeOnline.Connected = $true
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
            Write-Verbose -Message 'Attempting to connect to Exchange Online using Credentials without MFA'

            Connect-ExchangeOnline -Credential $Global:MSCloudLoginConnectionProfile.ExchangeOnline.Credentials `
                -ShowProgress:$false `
                -ShowBanner:$false `
                -ExchangeEnvironmentName $Global:MSCloudLoginConnectionProfile.ExchangeOnline.ExchangeEnvironmentName `
                -Verbose:$false `
                -ErrorAction Stop `
                -SkipLoadingCmdletHelp | Out-Null
            $Global:MSCloudLoginConnectionProfile.ExchangeOnline.ConnectedDateTime = [System.DateTime]::Now.ToString()
            $Global:MSCloudLoginConnectionProfile.ExchangeOnline.Connected = $true
            $Global:MSCloudLoginConnectionProfile.ExchangeOnline.MultiFactorAuthentication = $false
            Write-Verbose -Message 'Successfully connected to Exchange Online using Credentials without MFA'
        }
        catch
        {
            if ($_.Exception -like '*you must use multi-factor authentication to access*')
            {
                Connect-MSCloudLoginExchangeOnlineMFA -Credentials $Global:MSCloudLoginConnectionProfile.ExchangeOnline.Credentials
            }
            else
            {
                $Global:MSCloudLoginConnectionProfile.ExchangeOnline.Connected = $false
                throw $_
            }
        }
    }
    elseif ($Global:MSCloudLoginConnectionProfile.ExchangeOnline.AuthenticationType -eq 'CredentialsWithTenantId')
    {
        try
        {
            Write-Verbose -Message 'Attempting to connect to Exchange Online using Credentials without MFA'

            Connect-ExchangeOnline -Credential $Global:MSCloudLoginConnectionProfile.ExchangeOnline.Credentials `
                -ShowProgress:$false `
                -ShowBanner:$false `
                -DelegatedOrganization $Global:MSCloudLoginConnectionProfile.ExchangeOnline.TenantId `
                -ExchangeEnvironmentName $Global:MSCloudLoginConnectionProfile.ExchangeOnline.ExchangeEnvironmentName `
                -Verbose:$false `
                -ErrorAction Stop `
                -SkipLoadingCmdletHelp | Out-Null
            $Global:MSCloudLoginConnectionProfile.ExchangeOnline.ConnectedDateTime = [System.DateTime]::Now.ToString()
            $Global:MSCloudLoginConnectionProfile.ExchangeOnline.Connected = $true
            $Global:MSCloudLoginConnectionProfile.ExchangeOnline.MultiFactorAuthentication = $false
            Write-Verbose -Message 'Successfully connected to Exchange Online using Credentials & TenantId without MFA'
        }
        catch
        {
            if ($_.Exception -like '*you must use multi-factor authentication to access*')
            {
                Connect-MSCloudLoginExchangeOnlineMFA -Credentials $Global:MSCloudLoginConnectionProfile.ExchangeOnline.Credentials `
                    -TenantId $Global:MSCloudLoginConnectionProfile.ExchangeOnline.TenantId
            }
            else
            {
                $Global:MSCloudLoginConnectionProfile.ExchangeOnline.Connected = $false
                throw $_
            }
        }
    }
    elseif ($Global:MSCloudLoginConnectionProfile.ExchangeOnline.AuthenticationType -eq 'Identity')
    {
        Write-Verbose -Message 'Attempting to connect to Exchange Online using Managed Identity'
        try
        {
            if ($NULL -eq $Global:MSCloudLoginConnectionProfile.OrganizationName)
            {
                $Global:MSCloudLoginConnectionProfile.OrganizationName = Get-MSCloudLoginTenantDomain -Identity
            }

            Connect-ExchangeOnline -AppId $Global:MSCloudLoginConnectionProfile.ExchangeOnline.ApplicationId `
                -Organization $Global:MSCloudLoginConnectionProfile.OrganizationName `
                -ManagedIdentity `
                -ShowBanner:$false `
                -ShowProgress:$false `
                -ExchangeEnvironmentName $Global:MSCloudLoginConnectionProfile.ExchangeOnline.ExchangeEnvironmentName `
                -Verbose:$false `
                -SkipLoadingCmdletHelp | Out-Null

            $Global:MSCloudLoginConnectionProfile.ExchangeOnline.ConnectedDateTime = [System.DateTime]::Now.ToString()
            $Global:MSCloudLoginConnectionProfile.ExchangeOnline.Connected = $false
            $Global:MSCloudLoginConnectionProfile.ExchangeOnline.MultiFactorAuthentication = $true
            Write-Verbose -Message 'Successfully connected to Exchange Online using Managed Identity'
        }
        catch
        {
            throw $_
        }
    }
    elseif ($Global:MSCloudLoginConnectionProfile.ExchangeOnline.AuthenticationType -eq 'AccessToken')
    {
        Write-Verbose -Message "Connecting to EXO with AccessToken"
        try
        {
            $AccessTokenValue = $Global:MSCloudLoginConnectionProfile.ExchangeOnline.AccessTokens[0]
            if ($AccessTokenValue.GetType().Name -eq 'SecureString')
            {
                $Ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($AccessTokenValue)
                $AccessTokenValue = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($Ptr)
                [System.Runtime.InteropServices.Marshal]::ZeroFreeCoTaskMemUnicode($Ptr)
            }
            Connect-ExchangeOnline -AccessToken $AccessTokenValue `
                -Organization $Global:MSCloudLoginConnectionProfile.ExchangeOnline.TenantId `
                -ShowBanner:$false `
                -ShowProgress:$false `
                -ExchangeEnvironmentName $Global:MSCloudLoginConnectionProfile.ExchangeOnline.ExchangeEnvironmentName `
                -Verbose:$false `
                -SkipLoadingCmdletHelp | Out-Null

            $Global:MSCloudLoginConnectionProfile.ExchangeOnline.ConnectedDateTime = [System.DateTime]::Now.ToString()
            $Global:MSCloudLoginConnectionProfile.ExchangeOnline.Connected = $false
            $Global:MSCloudLoginConnectionProfile.ExchangeOnline.MultiFactorAuthentication = $false
            Write-Verbose -Message 'Successfully connected to Exchange Online using Access Token'
        }
        catch
        {
            throw $_
        }
    }
}

function Connect-MSCloudLoginExchangeOnlineMFA
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $Credentials,

        [Parameter()]
        [System.String]
        $TenantId
    )
    $WarningPreference = 'SilentlyContinue'
    $ProgressPreference = 'SilentlyContinue'
    $VerbosePreference = 'SilentlyContinue'

    try
    {
        if ([System.String]::IsNullOrEmpty($TenantId))
        {
            Write-Verbose -Message 'Creating a new ExchangeOnline Session using MFA'
            Connect-ExchangeOnline -UserPrincipalName $Global:MSCloudLoginConnectionProfile.ExchangeOnline.Credentials.UserName `
                -ShowBanner:$false `
                -ShowProgress:$false `
                -ExchangeEnvironmentName $Global:MSCloudLoginConnectionProfile.ExchangeOnline.ExchangeEnvironmentName `
                -Verbose:$false `
                -SkipLoadingCmdletHelp | Out-Null
            Write-Verbose -Message 'Successfully connected to Exchange Online using credentials with MFA'
        }
        else
        {
            Write-Verbose -Message 'Creating a new ExchangeOnline Session using MFA with Credentials and TenantId'
            Connect-ExchangeOnline -UserPrincipalName $Global:MSCloudLoginConnectionProfile.ExchangeOnline.Credentials.UserName `
                -ShowBanner:$false `
                -ShowProgress:$false `
                -DelegatedOrganization $TenantId `
                -ExchangeEnvironmentName $Global:MSCloudLoginConnectionProfile.ExchangeOnline.ExchangeEnvironmentName `
                -Verbose:$false `
                -SkipLoadingCmdletHelp | Out-Null
            Write-Verbose -Message 'Successfully connected to Exchange Online using credentials and tenantId with MFA'
        }
        $Global:MSCloudLoginConnectionProfile.ExchangeOnline.ConnectedDateTime = [System.DateTime]::Now.ToString()
        $Global:MSCloudLoginConnectionProfile.ExchangeOnline.Connected = $true
        $Global:MSCloudLoginConnectionProfile.ExchangeOnline.MultiFactorAuthentication = $true

    }
    catch
    {
        throw $_
    }
}
