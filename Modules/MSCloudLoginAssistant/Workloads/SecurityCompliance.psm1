function Connect-MSCloudLoginSecurityCompliance
{
    [CmdletBinding()]
    param(
        [Parameter()]
        [System.String]$Prefix
    )
    if ($null -eq $Global:o365Credential)
    {
        $Global:o365Credential = Get-Credential -Message "Cloud Credential"
    }

    #region Get Connection Info
    if ($null -eq $Global:EnvironmentName)
    {
        $Global:EnvironmentName = Get-CloudEnvironment -Credentials $Global:o365Credential
    }
    Write-Verbose -Message "Detected Azure Environment: $EnvironmentName"

    $ConnectionUrl = $null
    $AuthorizationUrl = $null
    switch ($Global:EnvironmentName)
    {
        "AzureCloud" {
            $ConnectionUrl = 'https://ps.compliance.protection.outlook.com/powershell-liveid/'
            $AuthorizationUrl = 'https://login.microsoftonline.com/common'
        }
        "AzureUSGovernment" {
            $ConnectionUrl = 'https://ps.compliance.protection.office365.us/powershell-liveid/'
            $AuthorizationUrl = 'https://login.microsoftonline.us/common'
        }
        "AzureGermanCloud" {
            $ConnectionUrl = 'https://ps.compliance.protection.outlook.de/powershell-liveid/'
            $AuthorizationUrl = 'https://login.microsoftonline.de/common'
        }
    }
    #endregion

    try
    {
        Write-Verbose -Message "Uses Modern Auth: $($Global:UseModernAuth)"
        $ExistingSession = Get-PSSession | Where-Object -FilterScript {$_.ConfigurationName -eq 'Microsoft.Exchange' -and $_.ComputerName -like '*ps.compliance.protection.*'}

        if ($null -ne $ExistingSession -and $ExistingSession.State -ne 'Opened')
        {
            Write-Verbose -Message "An existing session that is not opened was found {$($ExistingSession.Name)}. Closing it."
            $ExistingSession | Remove-PSSession
            $ExistingSession = $null
        }

        if ($null -ne $ExistingSession)
        {
            Write-Verbose -Message "Re-using existing Session: $($ExistingSession.Name)"
        }
        else
        {
            if ($Global:UseModernAuth)
            {
                Connect-MSCloudLoginSecurityComplianceMFA -Credentials $Global:o365Credential `
                    -ConnectionUrl $ConnectionUrl `
                    -AuthorizationUrl $AuthorizationUrl
            }
            else
            {
                Write-Verbose -Message "Attempting to create a new session to Security and Compliance Center - Non-MFA"

                $previousVerbose = $VerbosePreference
                $previousWarning = $WarningPreference
                $WarningPreference = 'SilentlyContinue'
                $VerbosePreference = 'SilentlyContinue'

                try
                {
                    $ExistingSession = New-PSSession -ConfigurationName Microsoft.Exchange `
                        -ConnectionUri $ConnectionUrl `
                        -Credential $o365Credential `
                        -Authentication Basic `
                        -AllowRedirection -ErrorAction 'Stop'
                    $SCModule = Import-PSSession $ExistingSession -DisableNameChecking -AllowClobber -Verbose:$false

                    $IPMOParameters = @{}
                    if ($PSBoundParameters.containskey("Prefix"))
                    {
                        $IPMOParameters.add("Prefix",$prefix)
                    }
                    Import-Module $SCModule -Global @IPMOParameters -Verbose:$false | Out-Null
                }
                catch
                {
                    Connect-MSCloudLoginSecurityComplianceMFA -Credentials $Global:o365Credential `
                        -ConnectionUrl $ConnectionUrl `
                        -AuthorizationUrl $AuthorizationUrl
                }
                $WarningPreference = $previousWarning
                $VerbosePreference = $previousVerbose
            }
        }
    }
    catch
    {
        if ($_.Exception -like '*you must use multi-factor authentication to access*')
        {
            Connect-MSCloudLoginSecurityComplianceeMFA -Credentials $Global:o365Credential `
                -ConnectionUrl $ConnectionUrl `
                -AuthorizationUrl $AuthorizationUrl
        }
        else
        {
            throw $_
        }
    }
}

function Connect-MSCloudLoginSecurityComplianceMFA
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PSCredential]
        $Credentials,

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
        Connect-IPPSSession -UserPrincipalName $Credentials.UserName `
            -ConnectionUri $ConnectionUrl `
            -AzureADAuthorizationEndpointUri $AuthorizationUrl -Verbose:$false | Out-Null
        $Global:MSCloudLoginSCConnected = $true
    }
    catch
    {
        throw $_
    }
}
