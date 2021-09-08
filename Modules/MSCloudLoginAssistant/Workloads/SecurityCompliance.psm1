function Connect-MSCloudLoginSecurityCompliance
{
    [CmdletBinding()]
    param()

    $WarningPreference     = 'SilentlyContinue'
    $InformationPreference = 'SilentlyContinue'
    $ProgressPreference    = 'SilentlyContinue'
    $VerbosePreference     = 'SilentlyContinue'

    Write-Verbose -Message "Trying to get the Get-ComplianceSearch command from within MSCloudLoginAssistant"
    try
    {
        Get-ComplianceSearch -ErrorAction Stop
        Write-Verbose -Message "Succeeded"
        $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.Connected = $true
        return
    }
    catch
    {
        Write-Verbose -Message "Failed"
    }

    Write-Verbose -Message "Connection Profile: $($Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter | Out-String)"
    if ($Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.Connected -and `
        $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.SkipModuleReload)
    {
        return
    }

    $loadedModules = Get-Module
    Write-Verbose -Message "The following modules are already loaded: $loadedModules"

    $AlreadyLoadedSCProxyModules = $loadedModules | Where-Object -FilterScript {$_.ExportedCommands.Keys.Contains('Get-ComplianceSearch')}
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
            -Verbose:$false| Out-Null
        $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.Connected = $true
        Write-Verbose "Reloaded the Security & Compliance Module"
        return
    }
    Write-Verbose -Message 'No Active Connections to Security & Compliance were found.'
    #endregion

    if ($Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.AuthenticationType -eq 'ServicePrincipalWithThumbprint')
    {
        Write-Verbose -Message "Attempting to connect to Security and Compliance using AAD App {$($Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.ApplicationID)}"
        try
        {
            # TODO - When Security & Compliance supports CBA
            throw "Security and COmpliance doesn't yet support authenticating with a Service Principal"
        }
        catch
        {
            $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.Connected = $false
            throw $_
        }
    }
    else
    {
        try
        {
            Write-Verbose -Message "Connecting to Security & Compliance with Credentials"
            Connect-IPPSSession -Credential $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.Credentials `
                -ConnectionUri $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.ConnectionUrl `
                -AzureADAuthorizationEndpointUri $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.AuthorizationUrl `
                -Verbose:$false -ErrorAction Stop | Out-Null
            $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.ConnectedDateTime         = [System.DateTime]::Now.TOString()
            $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.MultiFactorAuthentication = $false
            $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.Connected                 = $true
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
    param()

    $WarningPreference     = 'SilentlyContinue'
    $ProgressPreference    = 'SilentlyContinue'
    $InformationPreference = 'SilentlyContinue'
    try
    {
        Write-Verbose -Message "Creating a new Security and Compliance Session using MFA"
        if ($Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.EnvironmentName -eq 'AzureCloud')
        {
            Connect-IPPSSession -UserPrincipalName $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.Credentials.UserName `
                 -Verbose:$false | Out-Null
        }
        else
        {
            Connect-IPPSSession -UserPrincipalName $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.Credentials.UserName `
                -ConnectionUri $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.ConnectionUrl `
                -Verbose:$false | Out-Null
        }
        Write-Verbose -Message "New Session with MFA created successfully"
        $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.ConnectedDateTime         = [System.DateTime]::Now.TOString()
        $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.MultiFactorAuthentication = $false
        $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.Connected                 = $true
    }
    catch
    {
        $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.Connected = $false
        throw $_
    }
}
