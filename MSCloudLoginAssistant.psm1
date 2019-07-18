<#
.SYNOPSIS
    The Test-MSCloudLogin function is used to assist with logging in to various Microsoft Cloud services, such as Azure, SharePoint Online, and SharePoint PnP.
.EXAMPLE
    Test-MSCloudLogin -Platform AzureAD -Verbose
.EXAMPLE
    Test-MSCloudLogin -Platform PnP
.PARAMETER Platform
    The Platform parameter specifies which cloud service for which we are testing the login state. Possible values are Azure, AzureAD, SharePointOnline, ExchangeOnline, MSOnline, and PnP.
.NOTES
    Created & maintained by Brian Lalancette (@brianlala), 2019.
.LINK
    https://github.com/brianlala/MSCloudLoginAssistant
#>

function Test-MSCloudLogin
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateSet("Azure","AzureAD","SharePointOnline","ExchangeOnline","SecurityComplianceCenter","MSOnline","PnP","MicrosoftTeams")]
        [System.String]
        $Platform,

        [Parameter()]
        [System.String]
        $ConnectionUrl,

        [Parameter()]
        [Alias("o365Credential")]
        [System.Management.Automation.PSCredential]
        $CloudCredential
    )

    # If we specified the CloudCredential parameter then set the global o365Credential object to its value
    if ($null -ne $CloudCredential)
    {
        $Global:o365Credential = $CloudCredential
    }
    switch ($Platform)
    {
        'Azure'
        {
            $testCmdlet = "Get-AzResource";
            $exceptionStringMFA = "AADSTS";
            $connectCmdlet = "Connect-AzAccount";
            $connectCmdletArgs = "-Credential `$Global:o365Credential";
            $connectCmdletMfaRetryArgs = "";
            $variablePrefix = "az"
        }
        'AzureAD'
        {
            $testCmdlet = "Get-AzureADUser";
            $exceptionStringMFA = "AADSTS";
            $connectCmdlet = "Connect-AzureAD";
            $connectCmdletArgs = "-Credential `$Global:o365Credential";
            $connectCmdletMfaRetryArgs = "-AccountId `$Global:o365Credential.UserName"
            $variablePrefix = "aad"
        }
        'SharePointOnline'
        {
            if ([string]::IsNullOrEmpty($ConnectionUrl))
            {
                $Global:spoAdminUrl = Get-SPOAdminUrl;
            }
            else
            {
                $Global:spoAdminUrl = $ConnectionUrl
            }
            $testCmdlet = "Get-SPOSite";
            $exceptionStringMFA = "sign-in name or password does not match one in the Microsoft account system";
            $connectCmdlet = "Connect-SPOService";
            $connectCmdletArgs = "-Url $Global:spoAdminUrl -Credential `$Global:o365Credential";
            $connectCmdletMfaRetryArgs = $connectCmdletArgs.Replace("-Credential `$Global:o365Credential","");
            $variablePrefix = "spo"
        }
        'ExchangeOnline'
        {
            $VerbosePreference = 'SilentlyContinue'
            $WarningPreference = "Continue"
            $ClosedOrBrokenSessions = Get-PSSession -ErrorAction SilentlyContinue | Where-Object -FilterScript { $_.State -ne 'Opened' }
            if ($ClosedOrBrokenSessions)
            {
                Write-Verbose -Message "Found Existing Unusable Session(s)."
                foreach ($SessionToBeClosed in $ClosedOrBrokenSessions)
                {
                    Write-Verbose -Message "Closing Session: $(($SessionToBeClosed).InstanceId)"
                    $SessionToBeClosed | Remove-PSSession
                }
            }

            $Global:OpenExchangeSession = Get-PSSession -Name 'ExchangeOnline' -ErrorAction SilentlyContinue | Where-Object -FilterScript { $_.State -eq 'Opened' }
            if ($null -eq $Global:OpenExchangeSession)
            {
                try
                {
                    $PowerShellConnections = Get-NetTCPConnection | Where-Object -FilterScript { $_.OwningProcess -eq $PID -and $_.RemotePort -eq '443' -and $_.State -ne 'Established' }

                    while ($PowerShellConnections)
                    {
                        Write-Verbose -Message "This process is using the following connections in a non-Established state: $($PowerShellConnections | Out-String)"
                        Write-Verbose -Message "Waiting for closing connections to close..."
                        Get-PSSession -Name 'ExchangeOnline' -ErrorAction SilentlyContinue | Remove-PSSession
                        Start-Sleep -seconds 1
                        $CheckConnectionsWithoutKillingWhileLoop = Get-NetTCPConnection | Where-Object -FilterScript { $_.OwningProcess -eq $PID -and $_.RemotePort -eq '443' -and $_.State -ne 'Established' }
                        if (-not $CheckConnectionsWithoutKillingWhileLoop)
                        {
                            Write-Verbose -Message "Connections have closed.  Waiting 5 more seconds..."
                            Start-Sleep -seconds 5
                            $PowerShellConnections = Get-NetTCPConnection | Where-Object -FilterScript { $_.OwningProcess -eq $PID -and $_.RemotePort -eq '443' -and $_.State -ne 'Established' }
                        }
                    }

                    if ($Global:ExchangeOnlineSession.State -eq "Closed")
                    {
                        Remove-PSSession $Global:ExchangeOnlineSession
                        $Global:ExchangeOnlineSession = $null
                    }

                    while ($null -eq $Global:ExchangeOnlineSession)
                    {
                        Write-Verbose -Message "Creating new EXO Session"
                        $Global:ExchangeOnlineSession = New-PSSession -Name 'ExchangeOnline' -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $O365Credential -Authentication Basic -AllowRedirection -ErrorAction SilentlyContinue

                        if ($null -eq $Global:ExchangeOnlineSession)
                        {
                            Write-Warning "Exceeded max number of connections. Waiting 60 seconds"
                            Start-Sleep 60
                        }
                    }
                    if ($null -eq $Global:ExchangeOnlineModules)
                    {
                        Write-Verbose -Message "Importing all commands into the EXO Session"
                        $Global:ExchangeOnlineModules = Import-PSSession $Global:ExchangeOnlineSession -AllowClobber
                        Import-Module $Global:ExchangeOnlineModules -Global | Out-Null
                    }
                }
                catch
                {
                    $ExceptionMessage = $_.Exception
                    $Error.Clear()
                    $VerbosePreference = 'SilentlyContinue'
                    if ($ExceptionMessage -imatch 'Please wait for [0-9]* seconds')
                    {
                        Write-Verbose -Message "Waiting for available runspace..."
                        [regex]$WaitTimePattern = 'Please wait for [0-9]* seconds'
                        $WaitTimePatternMatch = (($WaitTimePattern.Match($ExceptionMessage)).Value | Select-String -Pattern '[0-9]*' -AllMatches )
                        $WaitTimeInSeconds = ($WaitTimePatternMatch | ForEach-Object {$_.Matches} | Where-Object -FilterScript { $_.Value -NotLike $null }).Value
                        Write-Verbose -Message "Waiting for requested $WaitTimeInSeconds seconds..."
                        Start-Sleep -Seconds ($WaitTimeInSeconds + 1)
                        try
                        {
                            Write-Verbose -Message "Opening New ExchangeOnline Session."
                            $PowerShellConnections = Get-NetTCPConnection | Where-Object -FilterScript { $_.OwningProcess -eq $PID -and $_.RemotePort -eq '443' -and $_.State -ne 'Established' }
                            while ($PowerShellConnections)
                            {
                                Write-Verbose -Message "This process is using the following connections in a non-Established state: $($PowerShellConnections | Out-String)"
                                Write-Verbose -Message "Waiting for closing connections to close..."
                                Get-PSSession -Name 'ExchangeOnline' -ErrorAction SilentlyContinue | Remove-PSSession
                                Start-Sleep -seconds 1
                                $CheckConnectionsWithoutKillingWhileLoop = Get-NetTCPConnection | Where-Object -FilterScript { $_.OwningProcess -eq $PID -and $_.RemotePort -eq '443' -and $_.State -ne 'Established' }
                                if (-not $CheckConnectionsWithoutKillingWhileLoop)
                                {
                                    Write-Verbose -Message "Connections have closed.  Waiting 5 more seconds..."
                                    Start-Sleep -seconds 5
                                    $PowerShellConnections = Get-NetTCPConnection | Where-Object -FilterScript { $_.OwningProcess -eq $PID -and $_.RemotePort -eq '443' -and $_.State -ne 'Established' }
                                }
                            }
                            $VerbosePreference = 'SilentlyContinue'
                            $Global:ExchangeOnlineSession = $null
                            while (-not $Global:ExchangeOnlineSession)
                            {
                                $Global:ExchangeOnlineSession = New-PSSession -Name 'ExchangeOnline' -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $O365Credential -Authentication Basic -AllowRedirection -ErrorAction SilentlyContinue
                            }
                            $Global:ExchangeOnlineModules = Import-PSSession $Global:ExchangeOnlineSession -AllowClobber -ErrorAction SilentlyContinue
                            $ExchangeOnlineModuleImport = Import-Module $ExchangeOnlineModules -Global -ErrorAction SilentlyContinue
                        }
                        catch
                        {
                            $VerbosePreference = 'SilentlyContinue'
                            $WarningPreference = "SilentlyContinue"
                            $Global:ExchangeOnlineSession = $null
                            Close-SessionsAndReturnError -ExceptionMessage $_.Exception
                            $Message = "Can't open Exchange Online session from Connect-ExchangeOnline"
                            New-Office365DSCLogEntry -Error $_ -Message $Message
                        }
                    }
                    else
                    {
                        Write-Verbose $_.Exception
                        $VerbosePreference = 'SilentlyContinue'
                        Get-PSSession -Name 'ExchangeOnline' -ErrorAction SilentlyContinue | Remove-PSSession
                        Write-Verbose -Message "Exchange Online connection failed."
                        Write-Verbose -Message "Waiting 60 seconds..."
                        Start-Sleep -Seconds 60
                        try
                        {
                            Write-Verbose -Message "Opening New ExchangeOnline Session."
                            $VerbosePreference = 'SilentlyContinue'
                            Get-PSSession -Name 'ExchangeOnline' -ErrorAction SilentlyContinue | Remove-PSSession -ErrorAction SilentlyContinue
                            $Global:ExchangeOnlineSession = New-PSSession -Name 'ExchangeOnline' -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $O365Credential -Authentication Basic -AllowRedirection
                            $Global:ExchangeOnlineModules = Import-PSSession $Global:ExchangeOnlineSession -AllowClobber -ErrorAction SilentlyContinue
                            $ExchangeOnlineModuleImport = Import-Module $ExchangeOnlineModules -Global -ErrorAction SilentlyContinue
                        }
                        catch
                        {
                            $VerbosePreference = 'SilentlyContinue'
                            $WarningPreference = "SilentlyContinue"
                            $Global:ExchangeOnlineSession = $null
                            Close-SessionsAndReturnError -ExceptionMessage $_.Exception
                        }
                    }
                }
            }
            else
            {
                Write-Verbose -Message "Using Existing ExchangeOnline Session."
                $Global:OpenExchangeSession = Get-PSSession -Name 'ExchangeOnline' -ErrorAction SilentlyContinue | Where-Object -FilterScript { $_.State -eq 'Opened' }
                $VerbosePreference = 'SilentlyContinue'
                $WarningPreference = "SilentlyContinue"
            }
            return
        }
        'SecurityComplianceCenter'
        {
            $Global:SessionSecurityCompliance = Get-PSSession | Where-Object{$_.ComputerName -like "*.ps.compliance.protection.outlook.com"}
            if ($null -eq $Global:SessionSecurityCompliance)
            {
                Write-Verbose -Message "Session to Security & Compliance already exists, re-using existing session"
                $Global:SessionSecurityCompliance = New-PSSession -ConfigurationName "Microsoft.Exchange" `
                    -ConnectionUri https://ps.compliance.protection.outlook.com/powershell-liveid/ `
                    -Credential $O365Credential `
                    -Authentication Basic `
                    -AllowRedirection

                $Global:SCModule = Import-PSSession $Global:SessionSecurityCompliance  `
                    -ErrorAction SilentlyContinue `
                    -AllowClobber

                Import-Module $Global:SCModule -Global | Out-Null
            }
            return
        }
        'MSOnline'
        {
            $testCmdlet = "Get-MsolUser";
            $exceptionStringMFA = "AADSTS";
            $connectCmdlet = "Connect-MsolService";
            $connectCmdletArgs = "-Credential `$Global:o365Credential";
            $connectCmdletMfaRetryArgs = "";
            $variablePrefix = "msol"
        }
        'PnP'
        {
            $Global:spoAdminUrl = Get-SPOAdminUrl;
            if ([string]::IsNullOrEmpty($ConnectionUrl))
            {
                # If we haven't specified a ConnectionUrl, just make the connection URL central admin
                $Global:ConnectionUrl = $Global:spoAdminUrl
            }
            else
            {
                $Global:ConnectionUrl = $ConnectionUrl
            }
            Write-Verbose -Message "`$Global:ConnectionUrl is $Global:ConnectionUrl."
            $testCmdlet = "Get-PnPSite";
            $exceptionStringMFA = "sign-in name or password does not match one in the Microsoft account system";
            $connectCmdlet = "Connect-PnPOnline";
            $connectCmdletArgs = "-Url `$Global:ConnectionUrl -Credentials `$Global:o365Credential";
            $connectCmdletMfaRetryArgs = $connectCmdletArgs.Replace("-Credentials `$Global:o365Credential","-UseWebLogin");
            $variablePrefix = "pnp"
        }
        'MicrosoftTeams'
        {
            # Need to force-import this for some reason as of 1.0.0
            Import-Module MicrosoftTeams -Force
            $testCmdlet = "Get-Team";
            $exceptionStringMFA = "AADSTS";
            $connectCmdlet = "Connect-MicrosoftTeams";
            $connectCmdletArgs = "-Credential `$Global:o365Credential";
            $connectCmdletMfaRetryArgs = "-AccountId `$Global:o365Credential.UserName";
            $variablePrefix = "teams"
        }
    }

    New-Variable -Name $variablePrefix"LoginSucceeded" -Value $false -Scope Global -Option AllScope -Force
    Write-Debug -Message `$$variablePrefix"LoginSucceeded is '$(Get-Variable -Name $($variablePrefix+"LoginSucceeded") -ValueOnly -Scope Global -ErrorAction SilentlyContinue)'."
    try
    {
        Write-Verbose -Message "Checking $Platform login..."
        # Run a simple command to check if we are logged in
        Write-Debug -Message "Running '$testCmdlet -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null'"
        Invoke-Expression -Command "$testCmdlet -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null"
        if ($? -eq $false)
        {
            throw
        }
        elseif ($Platform -eq "PnP")
        {
            $CurrentPnPConnection = (Get-PnPConnection).Url
            if ($ConnectionUrl -ne $CurrentPnPConnection)
            {
                throw "PnP requires you to reconnect to new location using $connectCmdlet"
            }
            else
            {
                Write-Verbose -Message "You are already logged in to $Platform."
            }
        }
        else
        {
            Write-Debug -Message "'$testCmdlet -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null' succeeded."
            Write-Verbose -Message "You are already logged in to $Platform."
        }
    }
    catch
    {
        if ($_.Exception -like "*$connectCmdlet*")
        {
            Write-Debug -Message "Running '$testCmdlet' failed on initial attempt."
            try
            {
                # Prompt for Windows-style credentials if we don't already have a credential object
                if ($null -eq $Global:o365Credential)
                {
                    Write-Host -ForegroundColor Cyan " - Prompting for Microsoft Online credentials..."
                    $Global:o365Credential = Get-Credential -Message "Please enter your credentials for MS Online Services:"
                    if ($null -eq $Global:o365Credential)
                    {
                        throw "Microsoft Online credentials must be supplied."
                    }
                    Write-Verbose -Message "Will now attempt to use credential for '$($Global:o365Credential.UserName)'..."
                }
                Write-Verbose -Message "Running '$connectCmdlet -ErrorAction Stop $connectCmdletArgs -ErrorVariable `$err | Out-Null'"
                Invoke-Expression -Command "$connectCmdlet -ErrorAction Stop $connectCmdletArgs -ErrorVariable `$err | Out-Null"
                if ($? -eq $false -or $err)
                {
                    throw
                }
                else
                {
                    New-Variable -Name $variablePrefix"LoginSucceeded" -Value $true -Scope Global -Option AllScope -Force
                    Write-Debug -Message `$$variablePrefix"LoginSucceeded is now '$(Get-Variable -Name $($variablePrefix+"LoginSucceeded") -ValueOnly -Scope Global -ErrorAction SilentlyContinue)'."
                }
            }
            catch
            {
                Write-Debug -Message "Login using '$connectCmdlet' and '$connectCmdletArgs' failed on initial attempt."
                if ($_.Exception -like "*User canceled authentication*")
                {
                    throw "User canceled authentication"
                }
                elseif ($_.Exception -like "*The user name or password is incorrect*" -or $_.Exception -like "*ID3242*")
                {
                    throw  "Bad credentials were supplied"
                }
                elseif ($_.Exception -like "*$exceptionStringMFA*" -or $_.Exception -like "*Sequence contains no elements*")
                {
                    Write-Verbose -Message "The specified account is configured for Multi-Factor Authentication. Please re-enter your credentials."
                    Write-Host -ForegroundColor Green " - Prompting for credentials with MFA for $Platform"
                    try
                    {
                        Write-Debug -Message "Replacing connection parameters '$connectCmdletArgs' with '$connectCmdletMfaRetryArgs'..."
                        Invoke-Expression -Command "$connectCmdlet -ErrorAction Stop $connectCmdletMfaRetryArgs | Out-Null"
                        if ($? -eq $false)
                        {
                            throw
                        }
                        else
                        {
                            New-Variable -Name $variablePrefix"LoginSucceeded" -Value $true -Scope Global -Option AllScope -Force
                            Write-Debug $variablePrefix"LoginSucceeded is now '$(Get-Variable -Name $($variablePrefix+"LoginSucceeded") -ValueOnly -Scope Global -ErrorAction SilentlyContinue)'."
                        }
                    }
                    catch
                    {
                        Write-Debug -Message "Login using '$connectCmdlet' and '$connectCmdletMfaRetryArgs' failed."
                        Write-Host -ForegroundColor Red $_.Exception
                        throw "No/invalid credentials were provided, or another error occurred logging on to $Platform."
                    }
                }
                else
                {
                    Write-Host -ForegroundColor Red $_.Exception
                    throw "No/invalid credentials were provided, or another error occurred logging on to $Platform."
                }
            }
        }
        elseif ($_.Exception -like "*Unable to acquire token for tenant*")
        {
           Write-Host -ForegroundColor Red $_.Exception
        }
        elseif ($_.Exception -like "*null array*")
        {
            # Do nothing
        }
        elseif ($_.Exception -like "*$testCmdlet*")
        {
            # If the exception contains the name of the cmdlet we're trying to run, we probably don't have the required module installed yet
            Write-Error -Message "It appears you don't have the '$Platform' module installed, or it isn't loaded. Please install/load the module and try again."
        }
        elseif ($_.Exception -like "*this.Client.SubscriptionId*" -and $Platform -eq "Azure")
        {
            throw "It appears there are no Azure subscriptions associated with the account '$($Global:o365Credential.UserName)'."
        }
        else
        {
            Write-Host -ForegroundColor Red $_.Exception
        }
    }
    finally
    {
        if (Get-Variable -Name $variablePrefix"LoginSucceeded" -ValueOnly -Scope "Global")
        {
            Write-Verbose -Message " - Successfully logged in to $Platform."
            # Extra step needed if we're logging into Azure - in case we have multiple subs we need to prompt for one
            if ($Platform -eq "Azure")
            {
                [array]$subscriptions = Get-AzSubscription -WarningAction Continue
                # Prompt for a subscription in case we have more than one
                if ($subscriptions.Count -gt 1)
                {
                    Write-Host -ForegroundColor Cyan " - Prompting for Azure subscription..."
                    $Global:subscriptionDetails = Get-AzSubscription -WarningAction SilentlyContinue | Sort-Object Name | Out-GridView -Title "Select ONE subscription..." -PassThru
                    if ($null -eq $subscriptionDetails)
                    {
                        throw " - A subscription must be selected."
                    }
                    elseif ($subscriptionDetails.Count -gt 1)
                    {
                        throw " - Please select *only one* subscription."
                    }
                    Write-Host -ForegroundColor White " - Setting active subscription to '$($Global:subscriptionDetails.Name)'..."
                    Set-AzContext -Subscription $Global:subscriptionDetails.Id
                }
            }

        }
    }
}

function Get-SPOAdminUrl
{
    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
    )

    Write-Verbose -Message "Connection to Azure AD is required to automatically determine SharePoint Online admin URL..."
    Test-MSCloudLogin -Platform AzureAD
    Write-Verbose -Message "Getting SharePoint Online admin URL..."
    $defaultDomain = Get-AzureADDomain | Where-Object {$_.Name -like "*.onmicrosoft.com" -and $_.IsInitial -eq $true} # We don't use IsDefault here because the default could be a custom domain
    $tenantName = $defaultDomain[0].Name -replace ".onmicrosoft.com",""
    $spoAdminUrl = "https://$tenantName-admin.sharepoint.com"
    Write-Verbose -Message "SharePoint Online admin URL is $spoAdminUrl"
    return $spoAdminUrl
}
