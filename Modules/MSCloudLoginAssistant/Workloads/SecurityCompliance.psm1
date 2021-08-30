function Connect-MSCloudLoginSecurityCompliance
{
    [CmdletBinding()]
    param()

    $WarningPreference     = 'SilentlyContinue'
    $ProgressPreference    = 'SilentlyContinue'
    $InformationPreference = 'SilentlyContinue'
    $ProgressPreference    = 'SilentlyContinue'

    if ($Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.Connected)
    {
        return
    }

    # Write-Verbose "$(Get-Runspace | Out-String)"
    [array]$activeSessions = Get-PSSession | Where-Object -FilterScript { $_.ComputerName -like '*ps.compliance.protection*' -and $_.State -eq 'Opened' }

    if ($activeSessions.Length -ge 1)
    {
        Write-Verbose -Message "Found {$($activeSessions.Length)} existing Security and Compliance Session"
        $command = Get-Command "Get-ComplianceSearch" -ErrorAction 'SilentlyContinue'
        if ($null -ne $command -and $Global:MSCloudLoginConnectionProfile.SecurityComplianceCenter.SkipModuleReload -eq $true)
        {
            return
        }
        $SCModule = Import-PSSession $activeSessions[0] -DisableNameChecking -AllowClobber
        Import-Module $SCModule -Global | Out-Null
        return
    }
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
