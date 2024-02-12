function Connect-MSCloudLoginSecurityCompliance
{
    [CmdletBinding()]
    param()

    $WarningPreference = 'SilentlyContinue'
    $InformationPreference = 'SilentlyContinue'
    $ProgressPreference = 'SilentlyContinue'
    $VerbosePreference = 'SilentlyContinue'

    Write-Verbose -Message 'Trying to get the Get-ComplianceSearch command from within MSCloudLoginAssistant'
    try
    {
        Get-ComplianceSearch -ErrorAction Stop
        Write-Verbose -Message 'Succeeded'
        $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.Connected = $true
        return
    }
    catch
    {
        Write-Verbose -Message 'Failed'
    }

    Write-Verbose -Message "Connection Profile: $($Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter | Out-String)"
    if ($Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.Connected -and `
            $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.SkipModuleReload)
    {
        return
    }

    $loadedModules = Get-Module
    Write-Verbose -Message "The following modules are already loaded: $loadedModules"

    $AlreadyLoadedSCProxyModules = $loadedModules | Where-Object -FilterScript { $_.ExportedCommands.Keys.Contains('Get-ComplianceSearch') }
    foreach ($loadedModule in $AlreadyLoadedSCProxyModules)
    {
        Write-Verbose -Message "Removing module {$($loadedModule.Name)} from current S+C session"
        Remove-Module $loadedModule.Name -Force -Verbose:$false | Out-Null
    }

    [array]$activeSessions = Get-PSSession | Where-Object -FilterScript { $_.ComputerName -like '*ps.compliance.protection*' -and $_.State -eq 'Opened' }

    if ($activeSessions.Length -ge 1)
    {
        Write-Verbose -Message "Found {$($activeSessions.Length)} existing Security and Compliance Session"
        $ProxyModule = Import-PSSession $activeSessions[0] `
            -DisableNameChecking `
            -AllowClobber `
            -Verbose:$false
        Write-Verbose -Message "Imported session into $ProxyModule"
        Import-Module $ProxyModule -Global `
            -Verbose:$false | Out-Null
        $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.Connected = $true
        Write-Verbose 'Reloaded the Security & Compliance Module'
        return
    }
    Write-Verbose -Message 'No Active Connections to Security & Compliance were found.'
    #endregion

    if ($Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.AuthenticationType -eq 'ServicePrincipalWithThumbprint')
    {
        Write-Verbose -Message "Attempting to connect to Security and Compliance using AAD App {$($Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.ApplicationID)}"
        try
        {
            Write-Verbose -Message 'Connecting to Security & Compliance with Service Principal and Certificate Thumbprint'

            switch ($Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.EnvironmentName)
            {
                {$_ -eq "AzureUSGovernment" -or $_ -eq "AzureDOD"}
                {
                    Connect-IPPSSession -AppId $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.ApplicationId `
                        -CertificateThumbprint $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.CertificateThumbprint `
                        -Organization $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.TenantId `
                        -ConnectionUri $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.ConnectionUrl `
                        -AzureADAuthorizationEndpointUri $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.AzureADAuthorizationEndpointUri `
                        -ErrorAction Stop  `
                        -ShowBanner:$false | Out-Null
                    $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.ConnectedDateTime = [System.DateTime]::Now.ToString()
                    $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.MultiFactorAuthentication = $false
                    $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.Connected = $true
                }
                Default
                {
                    Connect-IPPSSession -AppId $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.ApplicationId `
                        -CertificateThumbprint $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.CertificateThumbprint `
                        -Organization $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.TenantId `
                        -ErrorAction Stop  `
                        -ShowBanner:$false | Out-Null
                    $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.ConnectedDateTime = [System.DateTime]::Now.ToString()
                    $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.MultiFactorAuthentication = $false
                    $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.Connected = $true
                }
            }
        }
        catch
        {
            $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.Connected = $false
            throw $_
        }
    }
    elseif ($Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.AuthenticationType -eq 'ServicePrincipalWithPath')
    {
        try
        {
            Write-Verbose -Message 'Connecting to Security & Compliance with Service Principal and Certificate Path'
            switch ($Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.EnvironmentName)
            {
                {$_ -eq "AzureUSGovernment" -or $_ -eq "AzureDOD"}
                {
                    Connect-IPPSSession -AppId $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.ApplicationId `
                        -CertificateFilePath $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.CertificatePath `
                        -Organization $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.TenantId `
                        -CertificatePassword $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.CertificatePassword `
                        -ConnectionUri $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.ConnectionUri `
                        -AzureADAuthorizationEndpointUri $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.AzureADAuthorizationEndpointUri  `
                        -ShowBanner:$false | Out-Null
                    $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.ConnectedDateTime = [System.DateTime]::Now.ToString()
                    $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.MultiFactorAuthentication = $false
                    $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.Connected = $true
                }
                Default
                {
                    Connect-IPPSSession -AppId $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.ApplicationId `
                        -CertificateFilePath $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.CertificatePath `
                        -Organization $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.TenantId `
                        -CertificatePassword $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.CertificatePassword `
                        -ShowBanner:$false | Out-Null
                    $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.ConnectedDateTime = [System.DateTime]::Now.ToString()
                    $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.MultiFactorAuthentication = $false
                    $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.Connected = $true
                }
            }
        }
        catch
        {
            $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.Connected = $false
            throw $_
        }
    }
    elseif ($Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.AuthenticationType -eq 'CredentialsWithTenantId')
    {
        try
        {
            $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.AuthorizationUrl = `
                $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.AuthorizationUrl.Replace('/organizations', "/$($Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.TenantId)")
            Write-Verbose -Message 'Connecting to Security & Compliance with Credentials & TenantId'
            Connect-IPPSSession -Credential $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.Credentials `
                -ConnectionUri $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.ConnectionUrl `
                -AzureADAuthorizationEndpointUri $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.AuthorizationUrl `
                -Verbose:$false -ErrorAction Stop  `
                -DelegatedOrganization $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.TenantId `
                -ShowBanner:$false | Out-Null
            $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.ConnectedDateTime = [System.DateTime]::Now.ToString()
            $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.MultiFactorAuthentication = $false
            $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.Connected = $true
        }
        catch
        {
            Write-Verbose -Message "Could not connect connect IPPSSession with Credentials & TenantId: {$($_.Exception)}"
            Connect-MSCloudLoginSecurityComplianceMFA -TenantId $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.TenantId
        }
    }
    elseif($Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.AuthenticationType -eq 'AccessToken')
    {
        Write-Verbose -Message 'Connecting to Security & Compliance with Access Token'
        Connect-M365Tenant -Workload 'ExchangeOnline' `
                           -AccessTokens $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.AccessTokens `
                           -TenantId $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.TenantId
        $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.ConnectedDateTime = [System.DateTime]::Now.ToString()
        $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.MultiFactorAuthentication = $false
        $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.Connected = $true
    }
    else
    {
        try
        {
            Write-Verbose -Message 'Connecting to Security & Compliance with Credentials'
            Connect-IPPSSession -Credential $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.Credentials `
                -ConnectionUri $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.ConnectionUrl `
                -AzureADAuthorizationEndpointUri $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.AuthorizationUrl `
                -Verbose:$false -ErrorAction Stop  `
                -ShowBanner:$false | Out-Null
            $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.ConnectedDateTime = [System.DateTime]::Now.ToString()
            $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.MultiFactorAuthentication = $false
            $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.Connected = $true
        }
        catch
        {
            Write-Verbose -Message "Could not connect connect IPPSSession with Credentials: {$($_.Exception)}"
            Connect-MSCloudLoginSecurityComplianceMFA
        }
    }
}

function Connect-MSCloudLoginSecurityComplianceMFA
{
    [CmdletBinding()]
    param(
        [Parameter()]
        [System.String]
        $TenantId
    )

    $WarningPreference = 'SilentlyContinue'
    $ProgressPreference = 'SilentlyContinue'
    $InformationPreference = 'SilentlyContinue'
    try
    {
        Write-Verbose -Message 'Creating a new Security and Compliance Session using MFA'
        if ($Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.EnvironmentName -eq 'AzureCloud')
        {
            if ([System.String]::IsNullOrEmpty($TenantId))
            {
                Connect-IPPSSession -UserPrincipalName $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.Credentials.UserName `
                    -Verbose:$false  `
                    -ShowBanner:$false | Out-Null
            }
            else
            {
                Connect-IPPSSession -UserPrincipalName $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.Credentials.UserName `
                    -Verbose:$false  `
                    -DelegatedOrganization $TenantId `
                    -ShowBanner:$false | Out-Null
            }
        }
        else
        {
            if ([System.String]::IsNullOrEmpty($TenantId))
            {
                Connect-IPPSSession -UserPrincipalName $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.Credentials.UserName `
                    -ConnectionUri $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.ConnectionUrl `
                    -Verbose:$false  `
                    -ShowBanner:$false | Out-Null
            }
            else
            {
                Connect-IPPSSession -UserPrincipalName $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.Credentials.UserName `
                    -ConnectionUri $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.ConnectionUrl `
                    -Verbose:$false `
                    -DelegatedOrganization $TenantId `
                    -ShowBanner:$false | Out-Null
            }
        }
        Write-Verbose -Message 'New Session with MFA created successfully'
        $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.ConnectedDateTime = [System.DateTime]::Now.ToString()
        $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.MultiFactorAuthentication = $false
        $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.Connected = $true
    }
    catch
    {
        $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.Connected = $false
        throw $_
    }
}
