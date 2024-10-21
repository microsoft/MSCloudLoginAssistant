function Connect-MSCloudLoginExchangeOnline
{
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]
        $SkipPSSessionEvaluation
    )

    $WarningPreference = 'SilentlyContinue'
    $InformationPreference = 'SilentlyContinue'
    $ProgressPreference = 'SilentlyContinue'
    $VerbosePreference = 'SilentlyContinue'

    Write-Verbose -Message 'Trying to get the Get-AcceptedDomain command from within MSCloudLoginAssistant'

    if ($Global:MSCloudLoginConnectionProfile.ExchangeOnline.CmdletsToLoad.Count -eq 0)
    {
        $loadAllCmdlets = $true
    }

    if ($Global:MSCloudLoginCurrentLoadedModule -eq "EXO")
    {
        try
        {
            Get-AcceptedDomain -ErrorAction Stop

            if (-not $loadAllCmdlets)
            {
                $missingCommands = $Global:MSCloudLoginConnectionProfile.ExchangeOnline.CmdletsToLoad | Where-Object -FilterScript {
                    $Global:MSCloudLoginConnectionProfile.ExchangeOnline.LoadedCmdlets -notcontains $_
                }
            }

            # $missingCommands is null if no missing commands are found
            if ($Global:MSCloudLoginConnectionProfile.ExchangeOnline.LoadedAllCmdlets -or (-not $loadAllCmdlets -and $null -eq $missingCommands))
            {
                Write-Verbose -Message 'Succeeded'
                $Global:MSCloudLoginConnectionProfile.ExchangeOnline.Connected = $true
                return
            }
        }
        catch
        {
            Write-Verbose -Message 'Failed'
        }
    }

    if ($Global:MSCloudLoginConnectionProfile.ExchangeOnline.Connected -and `
            $Global:MSCloudLoginConnectionProfile.ExchangeOnline.SkipModuleReload)
    {
        $Global:MSCloudLoginConnectionProfile.ExchangeOnline.Connected = $true
        return
    }

    Write-Verbose -Message "Loaded Modules: $(Get-Module | Select-Object -ExpandProperty Name)"
    $alreadyLoadedEXOProxyModules = Get-Module | Where-Object -FilterScript { $_.ExportedCommands.Keys.Contains('Get-AcceptedDomain') }
    foreach ($loadedModule in $alreadyLoadedEXOProxyModules)
    {
        Write-Verbose -Message "Removing module {$($loadedModule.Name)} from current EXO session"
        Remove-Module $loadedModule.Name -Force -Verbose:$false | Out-Null
    }

    [array]$activeSessions = Get-PSSession | Where-Object -FilterScript { $_.ComputerName -like '*outlook.office*' -and $_.State -eq 'Opened' }
    Write-Verbose -Message "Active Sessions: $($activeSessions | Out-String)"
    if (-not $SkipPSSessionEvaluation -and $activeSessions.Length -ge 1)
    {
        Write-Verbose -Message "Found {$($activeSessions.Length)} existing Exchange Online Session"
        $ProxyModule = Import-PSSession $activeSessions[0] `
            -DisableNameChecking `
            -AllowClobber
        Write-Verbose -Message "Imported session into $ProxyModule"
        Import-Module $ProxyModule -Global `
            -Verbose:$false | Out-Null
        $Global:MSCloudLoginConnectionProfile.ExchangeOnline.Connected = $true
        Write-Verbose -Message 'Reloaded the Exchange Module'

        # Rerun the function to make sure we have all the necessary commands loaded
        # but prevent an infinite loop by skipping the PSSession evaluation
        Connect-MSCloudLoginExchangeOnline -SkipPSSessionEvaluation
        return
    }
    Write-Verbose -Message 'No active Exchange Online session found.'

    # Make sure we disconnect from any existing connections
    Disconnect-ExchangeOnline -Confirm:$false
    $CommandName = @{}
    if ($Global:MSCloudLoginConnectionProfile.ExchangeOnline.CmdletsToLoad.Count -gt 0)
    {
        # Make sure we have the Get-AcceptedDomain command available
        if ($Global:MSCloudLoginConnectionProfile.ExchangeOnline.CmdletsToLoad -notcontains 'Get-AcceptedDomain')
        {
            $Global:MSCloudLoginConnectionProfile.ExchangeOnline.CmdletsToLoad += 'Get-AcceptedDomain'
        }
        # Include the previously loaded commands, if available
        $combinedCmdlets = ($Global:MSCloudLoginConnectionProfile.ExchangeOnline.CmdletsToLoad + $Global:MSCloudLoginConnectionProfile.ExchangeOnline.LoadedCmdlets) | Select-Object -Unique
        $CommandName.Add('CommandName', $combinedCmdlets)
        Write-Verbose -Message "Commands to load: $($CommandName.CommandName -join ',')"
    }

    if ($Global:MSCloudLoginConnectionProfile.ExchangeOnline.AuthenticationType -eq 'ServicePrincipalWithThumbprint')
    {
        Write-Verbose -Message "Attempting to connect to Exchange Online using AAD App {$ApplicationID}"
        try
        {
            if ($null -eq $Global:MSCloudLoginConnectionProfile.OrganizationName)
            {
                $Global:MSCloudLoginConnectionProfile.OrganizationName = Get-MSCloudLoginOrganizationName `
                    -ApplicationId $Global:MSCloudLoginConnectionProfile.ExchangeOnline.ApplicationId `
                    -TenantId $Global:MSCloudLoginConnectionProfile.ExchangeOnline.TenantId `
                    -CertificateThumbprint $Global:MSCloudLoginConnectionProfile.ExchangeOnline.CertificateThumbprint
            }

            if ($null -ne $Global:MSCloudLoginConnectionProfile.ExchangeOnline.Endpoints -and `
                $null -ne $Global:MSCloudLoginConnectionProfile.ExchangeOnline.Endpoints.ConnectionUri -and `
                $null -ne $Global:MSCloudLoginConnectionProfile.ExchangeOnline.Endpoints.AzureADAuthorizationEndpointUri)
            {
                Write-Verbose -Message "Connecting by endpoints URI"
                Connect-ExchangeOnline -AppId $Global:MSCloudLoginConnectionProfile.ExchangeOnline.ApplicationId `
                    -Organization $Global:MSCloudLoginConnectionProfile.OrganizationName `
                    -CertificateThumbprint $Global:MSCloudLoginConnectionProfile.ExchangeOnline.CertificateThumbprint `
                    -ShowBanner:$false `
                    -ShowProgress:$false `
                    -ConnectionUri $Global:MSCloudLoginConnectionProfile.ExchangeOnline.Endpoints.ConnectionUri `
                    -AzureADAuthorizationEndpointUri $Global:MSCloudLoginConnectionProfile.ExchangeOnline.Endpoints.AzureADAuthorizationEndpointUri `
                    -Verbose:$false `
                    -SkipLoadingCmdletHelp `
                    @CommandName | Out-Null
            }
            else
            {
                Write-Verbose -Message "Connecting by environment name"
                Connect-ExchangeOnline -AppId $Global:MSCloudLoginConnectionProfile.ExchangeOnline.ApplicationId `
                    -Organization $Global:MSCloudLoginConnectionProfile.OrganizationName `
                    -CertificateThumbprint $Global:MSCloudLoginConnectionProfile.ExchangeOnline.CertificateThumbprint `
                    -ShowBanner:$false `
                    -ShowProgress:$false `
                    -ExchangeEnvironmentName $Global:MSCloudLoginConnectionProfile.ExchangeOnline.ExchangeEnvironmentName `
                    -Verbose:$false `
                    -SkipLoadingCmdletHelp `
                    @CommandName | Out-Null
            }

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
                -SkipLoadingCmdletHelp `
                @CommandName | Out-Null
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
                -SkipLoadingCmdletHelp `
                @CommandName | Out-Null
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
                $Global:MSCloudLoginConnectionProfile.OrganizationName = Get-MSCloudLoginOrganizationName -Identity
            }

            Connect-ExchangeOnline -AppId $Global:MSCloudLoginConnectionProfile.ExchangeOnline.ApplicationId `
                -Organization $Global:MSCloudLoginConnectionProfile.OrganizationName `
                -ManagedIdentity `
                -ShowBanner:$false `
                -ShowProgress:$false `
                -ExchangeEnvironmentName $Global:MSCloudLoginConnectionProfile.ExchangeOnline.ExchangeEnvironmentName `
                -Verbose:$false `
                -SkipLoadingCmdletHelp `
                @CommandName | Out-Null

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
    elseif ($Global:MSCloudLoginConnectionProfile.ExchangeOnline.AuthenticationType -eq 'AccessTokens')
    {
        Write-Verbose -Message "Connecting to EXO with AccessTokens"
        try
        {
            $AccessTokenValue = $Global:MSCloudLoginConnectionProfile.ExchangeOnline.AccessTokens[0]
            if ($AccessTokenValue.GetType().Name -eq 'PSCredential')
            {
                $Ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($AccessTokenValue.Password)
                $AccessTokenValue = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($Ptr)
                [System.Runtime.InteropServices.Marshal]::ZeroFreeCoTaskMemUnicode($Ptr)
            }
            Connect-ExchangeOnline -AccessToken $AccessTokenValue `
                -Organization $Global:MSCloudLoginConnectionProfile.ExchangeOnline.TenantId `
                -ShowBanner:$false `
                -ShowProgress:$false `
                -ExchangeEnvironmentName $Global:MSCloudLoginConnectionProfile.ExchangeOnline.ExchangeEnvironmentName `
                -Verbose:$false `
                -SkipLoadingCmdletHelp `
                @CommandName | Out-Null

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
    else
    {
        Write-Verbose -Message 'No valid authentication type found'
        throw 'No valid authentication type found'
    }
    $Global:MSCloudLoginCurrentLoadedModule = "EXO"

    # Usually the tmpEXO* modules, but it might also be from another PSSession
    $loadedEXOProxyModule = Get-Module | Where-Object -FilterScript { $_.ExportedCommands.Keys.Contains('Get-AcceptedDomain') }
    $loadedEXOModule = Get-Module -Name 'ExchangeOnlineManagement'
    $Global:MSCloudLoginConnectionProfile.ExchangeOnline.LoadedCmdlets = $loadedEXOProxyModule.ExportedCommands.Keys + $loadedEXOModule.ExportedCommands.Keys
    if ($loadAllCmdlets)
    {
        $Global:MSCloudLoginConnectionProfile.ExchangeOnline.LoadedAllCmdlets = $true
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
                -SkipLoadingCmdletHelp `
                @CommandName | Out-Null
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
                -SkipLoadingCmdletHelp `
                @CommandName | Out-Null
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
