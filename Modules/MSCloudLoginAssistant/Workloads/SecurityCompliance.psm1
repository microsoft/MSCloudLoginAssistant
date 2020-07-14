function Connect-MSCloudLoginSecurityCompliance
{
    [CmdletBinding()]
    param(
        [Parameter()]
        [System.String]
        $ApplicationId,

        [Parameter()]
        [System.String]
        $TenantId,

        [Parameter()]
        [System.String]
        $CertificateThumbprint,

        [Parameter()]
        [SecureString]
        $CertificatePassword,

        [Parameter()]
        [System.String]
        $CertificatePath,

        [Parameter()]
        [System.Boolean]
        $SkipModuleReload = $false
    )
    $WarningPreference = 'SilentlyContinue'
    $ProgressPreference = 'SilentlyContinue'
    [array]$activeSessions = Get-PSSession | Where-Object -FilterScript {$_.ComputerName -like '*.ps.compliance.protection*' -and $_.State -eq 'Opened'}
    if ($activeSessions.Length -ge 1)
    {
        Write-Verbose -Message "Found {$($activeSessions.Length)} existing Security and Compliance Session"
        if ($SkipModuleReload)
        {
            $command = Get-Command "Get-ComplianceSearch" -ErrorAction 'SilentlyContinue'
            if ($null -ne $command)
            {
                return
            }
        }
        $SCModule = Import-PSSession $activeSessions[0] -DisableNameChecking -AllowClobber
        Import-Module $SCModule -Global | Out-Null
        return
    }

    #region Get Connection Info
    if ($null -eq $Global:CloudEnvironmentInfo)
    {
        $Global:CloudEnvironmentInfo = Get-CloudEnvironmentInfo -Credentials $Global:o365Credential `
            -ApplicationId $ApplicationId `
            -TenantId $TenantId `
            -CertificateThumbprint $CertificateThumbprint
    }

    switch ($Global:CloudEnvironmentInfo.cloud_instance_name)
    {
        "microsoftonline.com" {
            $ConnectionUrl = 'https://ps.compliance.protection.outlook.com/powershell-liveid/'
            $AuthorizationUrl = 'https://login.microsoftonline.com/common'
        }
        "microsoftonline.us" {
            $ConnectionUrl = 'https://ps.compliance.protection.office365.us/powershell-liveid/'
            $AuthorizationUrl = 'https://login.microsoftonline.us/common'
        }
        "microsoftonline.de" {
            $ConnectionUrl = 'https://ps.compliance.protection.outlook.de/powershell-liveid/'
            $AuthorizationUrl = 'https://login.microsoftonline.de/common'
        }
    }
    Write-Verbose -Message "ConnectionUrl = $ConnectionUrl"
    Write-Verbose -Message "AuthorizationUrl = $AuthorizationUrl"
    #endregion

    if (-not [String]::IsNullOrEmpty($ApplicationId) -and `
        -not [String]::IsNullOrEmpty($TenantId) -and `
        -not [String]::IsNullOrEmpty($CertificateThumbprint))
    {
        Write-Verbose -Message "Attempting to connect to Security and Compliance using AAD App {$ApplicationID}"
        try
        {
            # TODO - When Security & COmpliance supports CBA
        }
        catch
        {
            throw $_
        }
    }
    else
    {
        try
        {
            $CurrentVerbosePreference = $VerbosePreference
            $CurrentInformationPreference = $InformationPreference
            $CurrentWarningPreference = $WarningPreference
            $VerbosePreference = "SilentlyContinue"
            $InformationPreference = "SilentlyContinue"
            $WarningPreference = "SilentlyContinue"
            Connect-IPPSSession -Credential $Global:o365Credential `
                -ConnectionUri $ConnectionUrl `
                -Verbose:$false | Out-Null
            $VerbosePreference = $CurrentVerbosePreference
            $InformationPreference = $CurrentInformationPreference
            $WarningPreference = $CurrentWarningPreference
        }
        catch
        {
            Write-Verbose -Message "Could not connect connect IPPSSession with Credentials: {$($_.Exception)}"
            Connect-MSCloudLoginSecurityComplianceMFA -CloudCredential $Global:o365Credential `
                -ConnectionUrl $ConnectionUrl `
                -AuthorizationUrl $AuthorizationUrl
        }
    }
}

function Connect-MSCloudLoginSecurityComplianceMFA
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PSCredential]
        $CloudCredential,

        [Parameter(Mandatory=$true)]
        [System.String]
        $ConnectionUrl,

        [Parameter(Mandatory=$true)]
        [System.String]
        $AuthorizationUrl
    )
    try
    {
        Write-Verbose -Message "Creating a new Security and Compliance Session using MFA"
        $CurrentVerbosePreference = $VerbosePreference
        $CurrentInformationPreference = $InformationPreference
        $CurrentWarningPreference = $WarningPreference
        $VerbosePreference = "SilentlyContinue"
        $InformationPreference = "SilentlyContinue"
        $WarningPreference = "SilentlyContinue"
        Connect-IPPSSession -UserPrincipalName $CloudCredential.UserName `
            -ConnectionUri $ConnectionUrl `
            -AzureADAuthorizationEndpointUri $AuthorizationUrl -Verbose:$false | Out-Null
        $VerbosePreference = $CurrentVerbosePreference
        $InformationPreference = $CurrentInformationPreference
        $WarningPreference = $CurrentWarningPreference
        Write-Verbose -Message "New Session with MFA created successfully"
        $Global:MSCloudLoginSCConnected = $true
    }
    catch
    {
        throw $_
    }
}
