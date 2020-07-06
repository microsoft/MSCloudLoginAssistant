function Connect-MSCloudLoginSecurityCompliance
{
    [CmdletBinding()]
    param(
        [Parameter()]
        [System.Management.Automation.PSCredential]
        $CloudCredential
    )
    if ($null -eq $CloudCredential)
    {
        Write-Verbose -Message "Credential is null. Prompting user to provide it."
        $CloudCredential = Get-Credential -Message "Cloud Credential"
    }

    #region Get Connection Info
    if ($null -eq $Global:CloudEnvironmentInfo)
    {
        $Global:CloudEnvironmentInfo = Get-CloudEnvironmentInfo -Credentials $Global:o365Credential
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
        else
        {
            Write-Verbose -Message "No existing connections to Security and Compliance were detected."
        }

        if ($null -ne $ExistingSession)
        {
            Write-Verbose -Message "Re-using existing Session: $($ExistingSession.Name)"
        }
        else
        {
            if ($Global:UseModernAuth)
            {
                Write-Verbose -Message "Calling into the Connect-MSCloudLoginSecurityComplianceMFA method"
                Connect-MSCloudLoginSecurityComplianceMFA -CloudCredential $CloudCredential `
                    -ConnectionUrl $ConnectionUrl `
                    -AuthorizationUrl $AuthorizationUrl
            }
            else
            {
                Write-Verbose -Message "Attempting to create a new session to Security and Compliance Center - Non-MFA"

                try
                {
                    $previousVerbose = $VerbosePreference
                    $previousWarning = $WarningPreference

                    $WarningPreference = 'SilentlyContinue'
                    $VerbosePreference = 'SilentlyContinue'
                    $ExistingSession = New-PSSession -ConfigurationName Microsoft.Exchange `
                        -ConnectionUri $ConnectionUrl `
                        -Credential $o365Credential `
                        -Authentication Basic `
                        -AllowRedirection -ErrorAction 'Stop'
                    $VerbosePreference = $previousPreference
                    $WarningPreference = $previousPreference
                    Write-Verbose -Message "New Session created successfully"

                    $WarningPreference = 'SilentlyContinue'
                    $VerbosePreference = 'SilentlyContinue'
                    $SCModule = Import-PSSession $ExistingSession -DisableNameChecking -AllowClobber -Verbose:$false
                    $VerbosePreference = $previousPreference
                    $WarningPreference = $previousPreference

                    Write-Verbose -Message "Session imported successfully"
                    $IPMOParameters = @{}
                    if ($PSBoundParameters.containskey("Prefix"))
                    {
                        $IPMOParameters.add("Prefix",$prefix)
                    }

                    $WarningPreference = 'SilentlyContinue'
                    $VerbosePreference = 'SilentlyContinue'
                    Import-Module $SCModule -Global @IPMOParameters -Verbose:$false | Out-Null
                    $VerbosePreference = $previousPreference
                    $WarningPreference = $previousPreference
                    Write-Verbose -Message "Module imported successfully"
                }
                catch
                {
                    if ($_.Exception -like '*Access is denied*')
                    {
                        try
                        {
                            Write-Verbose -Message "UserName:$($CloudCredential.UserName)"
                            Write-Verbose -Message "Getting an access denied error. Trying to connect with IPPSSession"
                            Connect-IPPSSession -Credential $CloudCredential -Verbose:$false | Out-Null
                        }
                        catch
                        {
                            Write-Verbose -Message "Could not connect connect IPPSSession with Credentials: {$($_.Exception)}"
                            Connect-MSCloudLoginSecurityComplianceMFA -CloudCredential $CloudCredential `
                                -ConnectionUrl $ConnectionUrl `
                                -AuthorizationUrl $AuthorizationUrl
                        }
                    }
                    else
                    {
                        Write-Verbose -Message "An Error occured, calling into the MFA method: {$($_.Exception)}"
                        Connect-MSCloudLoginSecurityComplianceMFA -CloudCredential $CloudCredential `
                            -ConnectionUrl $ConnectionUrl `
                            -AuthorizationUrl $AuthorizationUrl
                    }
                }
            }
        }
    }
    catch
    {
        Write-Verbose -Message "An Error occured. Details: {$($_.Exception)}"
        if ($_.Exception -like '*you must use multi-factor authentication to access*')
        {
            Write-Verbose -Message "Calling into the MFA function since we received a message that it was required."
            Connect-MSCloudLoginSecurityComplianceeMFA -CloudCredential $CloudCredential `
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
        Connect-IPPSSession -UserPrincipalName $CloudCredential.UserName `
            -ConnectionUri $ConnectionUrl `
            -AzureADAuthorizationEndpointUri $AuthorizationUrl -Verbose:$false | Out-Null
        Write-Verbose -Message "New Session with MFA created successfully"
        $Global:MSCloudLoginSCConnected = $true
    }
    catch
    {
        throw $_
    }
}
