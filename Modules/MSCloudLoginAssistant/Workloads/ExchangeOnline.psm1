function Connect-MSCloudLoginExchangeOnline
{
    [CmdletBinding()]
    param(
        [Parameter()]
        [System.String]
        $Prefix
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
    switch ($Global:EnvironmentName)
    {
        "AzureCloud" {
            $ConnectionUrl = 'https://outlook.office365.com/powershell-liveid/'
        }
        "AzureUSGovernment" {
            $ConnectionUrl = 'https://outlook.office365.us/powershell-liveid/'
        }
        "AzureGermanCloud" {
            $ConnectionUrl = 'https://outlook.office.de/powershell-liveid/'
        }
    }
    #endregion

    try
    {
        Write-Verbose -Message "Uses Modern Auth: $($Global:UseModernAuth)"
        $ExistingSession = Get-PSSession | Where-Object -FilterScript {$_.ConfigurationName -eq 'Microsoft.Exchange' -and $_.ComputerName -like 'outlook.*'}

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
                Connect-MSCloudLoginExchangeOnlineMFA -Credentials $Global:o365Credential -ConnectionUrl $ConnectionUrl
            }
            else
            {
                Write-Verbose -Message "Attempting to create a new session to Exchange Online - Non-MFA"

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
                    $EXOModule = Import-PSSession $ExistingSession -DisableNameChecking -AllowClobber -Verbose:$false

                    $IPMOParameters = @{}
                    if ($PSBoundParameters.containskey("Prefix"))
                    {
                        $IPMOParameters.add("Prefix",$prefix)
                    }
                    Import-Module $EXOModule -Global @IPMOParameters -Verbose:$false | Out-Null
                }
                catch
                {
                    Connect-MSCloudLoginExchangeOnlineMFA -Credentials $Global:o365Credential -ConnectionUrl $ConnectionUrl
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
            Connect-MSCloudLoginExchangeOnlineMFA -Credentials $Global:o365Credential -ConnectionUrl $ConnectionUrl
        }
        else
        {
            throw $_
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
        Connect-ExchangeOnline -UserPrincipalName $Credentials.UserName `
            -ShowBanner:$false `
            -ShowProgress:$false `
            -ConnectionUri $ConnectionUrl -Verbose:$false | Out-Null
        $Global:MSCloudLoginEXOConnected = $true
    }
    catch
    {
        throw $_
    }
}
