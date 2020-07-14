function Connect-MSCloudLoginExchangeOnline
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
        [System.String]
        $Prefix,

        [Parameter()]
        [System.String]
        $SkipModuleReload = $false
    )
    $WarningPreference = 'SilentlyContinue'
    $ProgressPreference = 'SilentlyContinue'
    [array]$activeSessions = Get-PSSession | Where-Object -FilterScript {$_.ComputerName -like '*outlook.office*' -and $_.State -eq 'Opened'}
    if ($activeSessions.Length -ge 1)
    {
        Write-Verbose -Message "Found {$($activeSessions.Length)} existing Exchange Online Session"
        if ($SkipModuleReload)
        {
            $command = Get-Command "Get-AcceptedDomain" -ErrorAction 'SilentlyContinue'
            if ($null -ne $command)
            {
                return
            }
        }
        $EXOModule = Import-PSSession $activeSessions[0] -DisableNameChecking -AllowClobber
        Import-Module $EXOModule -Global | Out-Null
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

    $ConnectionUrl = $null
    switch ($Global:CloudEnvironmentInfo.cloud_instance_name)
    {
        "microsoftonline.com" {
            $ConnectionUrl = 'https://outlook.office365.com/powershell-liveid/'
        }
        "microsoftonline.us" {
            $ConnectionUrl = 'https://outlook.office365.us/powershell-liveid/'
        }
        "microsoftonline.de" {
            $ConnectionUrl = 'https://outlook.office.de/powershell-liveid/'
        }
    }
    #endregion
    Write-Verbose -Message "ConnectionUrl = $ConnectionUrl"
    Write-Verbose -Message "AuthorizationUrl = $AuthorizationUrl"
    if (-not [String]::IsNullOrEmpty($ApplicationId) -and `
        -not [String]::IsNullOrEmpty($TenantId) -and `
        -not [String]::IsNullOrEmpty($CertificateThumbprint))
    {
        Write-Verbose -Message "Attempting to connect to Exchange Online using AAD App {$ApplicationID}"
        try
        {
            $Organization = Get-MSCloudLoginOrganizationName -ApplicationId $ApplicationId `
                -TenantId $TenantId `
                -CertificateThumbprint $CertificateThumbprint
            $CurrentVerbosePreference = $VerbosePreference
            $CurrentInformationPreference = $InformationPreference
            $CurrentWarningPreference = $WarningPreference
            $VerbosePreference = "SilentlyContinue"
            $InformationPreference = "SilentlyContinue"
            $WarningPreference = "SilentlyContinue"
            Connect-ExchangeOnline -AppId $ApplicationId `
                -Organization $Organization `
                -CertificateThumbprint $CertificateThumbprint `
                -ShowBanner:$false `
                -ShowProgress:$false `
                -ConnectionUri $ConnectionUrl `
                -Verbose:$false | Out-Null
            $VerbosePreference = $CurrentVerbosePreference
            $InformationPreference = $CurrentInformationPreference
            $WarningPreference = $CurrentWarningPreference
            Write-Verbose -Message "Successfully connected to Exchange Online using AAD App {$ApplicationID}"
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
            Write-Verbose -Message "Attempting to connect to Exchange Online using Credentials without MFA"
            $CurrentVerbosePreference = $VerbosePreference
            $CurrentInformationPreference = $InformationPreference
            $CurrentWarningPreference = $WarningPreference
            $VerbosePreference = "SilentlyContinue"
            $InformationPreference = "SilentlyContinue"
            $WarningPreference = "SilentlyContinue"
            Connect-ExchangeOnline -Credential $Global:o365Credential `
                -ShowProgress:$false `
                -ShowBanner:$false `
                -ConnectionUri $ConnectionUrl `
                -Verbose:$false | Out-Null
            $VerbosePreference = $CurrentVerbosePreference
            $InformationPreference = $CurrentInformationPreference
            $WarningPreference = $CurrentWarningPreference
            Write-Verbose -Message "Successfully connected to Exchange Online using Credentials without MFA"
        }
        catch
        {
            if ($_.Exception -like '*you must use multi-factor authentication to access*')
            {
                Connect-MSCloudLoginExchangeOnlineMFA -Credentials $Global:o365Credential -ConnectionUrl $ConnectionUrl
            }
            else
            {
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
    try
    {
        Write-Verbose -Message "Creating a new ExchangeOnline Session using MFA"
        $CurrentVerbosePreference = $VerbosePreference
        $CurrentInformationPreference = $InformationPreference
        $CurrentWarningPreference = $WarningPreference
        $VerbosePreference = "SilentlyContinue"
        $InformationPreference = "SilentlyContinue"
        $WarningPreference = "SilentlyContinue"
        Connect-ExchangeOnline -UserPrincipalName $Credentials.UserName `
            -ShowBanner:$false `
            -ShowProgress:$false `
            -ConnectionUri $ConnectionUrl -Verbose:$false | Out-Null
        $VerbosePreference = $CurrentVerbosePreference
        $InformationPreference = $CurrentInformationPreference
        $WarningPreference = $CurrentWarningPreference
        Write-Verbose -Message "Successfully connected to Exchange Online using credentials with MFA"
        $Global:MSCloudLoginEXOConnected = $true
    }
    catch
    {
        throw $_
    }
}
