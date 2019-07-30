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
    https://github.com/Microsoft/MSCloudLoginAssistant
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
        $CloudCredential,

        [Parameter()]
        [Switch]
        $UseModernAuth
    )

    # If we specified the CloudCredential parameter then set the global o365Credential object to its value
    if ($null -ne $CloudCredential)
    {
        $Global:o365Credential = $CloudCredential
    }
    if($null -eq $Global:UseModernAuth){
        $Global:UseModernAuth = $UseModernAuth.IsPresent
    }
    switch ($Platform)
    {
        'Azure'
        {
            $testCmdlet = "Get-AzResource";
            $exceptionStringMFA = "AADSTS";
            $clientid = "1950a258-227b-4e31-a9cf-717495945fc2";
            $RessourceURI = "https://management.core.windows.net";
            $RedirectURI = "urn:ietf:wg:oauth:2.0:oob";
            $connectCmdlet = "Connect-AzAccount";
            $connectCmdletArgs = "-Credential `$Global:o365Credential";
            $connectCmdletMfaRetryArgs = "-AccessToken `$AuthToken -AccountId `$global:o365Credential.UserName";
            $variablePrefix = "az"
        }
        'AzureAD'
        {
            $testCmdlet = "Get-AzureADUser";
            $exceptionStringMFA = "AADSTS";
            $clientid = "1b730954-1685-4b74-9bfd-dac224a7b894";
            $RessourceURI = "https://graph.windows.net";
            $RedirectURI = "urn:ietf:wg:oauth:2.0:oob";
            $connectCmdlet = "Connect-AzureAD";
            $connectCmdletArgs = "-Credential `$Global:o365Credential";
            $connectCmdletMfaRetryArgs = "-AadAccessToken `$AuthToken -AccountId `$global:o365Credential.UserName"
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
            $clientid = "9bc3ab49-b65d-410a-85ad-de819febfddc";
            $RessourceURI = $Global:spoAdminUrl;
            $RedirectURI = "urn:ietf:wg:oauth:2.0:oob";
            $connectCmdlet = "Connect-SPOService";
            $connectCmdletArgs = "-Url $Global:spoAdminUrl -Credential `$Global:o365Credential";
            $connectCmdletMfaRetryArgs = $connectCmdletArgs.Replace("-Credential `$Global:o365Credential","");
            $variablePrefix = "spo"
        }
        'ExchangeOnline'
        {  
            $VerbosePreference = 'SilentlyContinue'
            $WarningPreference = "Continue"
            $clientid = "a0c73c16-a7e3-4564-9a95-2bdf47383716";
            $RessourceURI = "https://outlook.office365.com";
            $RedirectURI = "urn:ietf:wg:oauth:2.0:oob";
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
                    $PowerShellConnections = Get-NetTCPConnection | Where-Object -FilterScript { $_.RemotePort -eq '443' -and $_.State -ne 'Established' }

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

                        try
                        {
                            $Global:ExchangeOnlineSession = New-PSSession -Name 'ExchangeOnline' -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $O365Credential -Authentication Basic -AllowRedirection -ErrorAction Stop
                        }
                        catch
                        {
                            try {
                                $AuthHeader = Get-AuthHeader -UserPrincipalName $Global:o365Credential.UserName -RessourceURI $RessourceURI -clientID $clientID -RedirectURI $RedirectURI
                                $Password = ConvertTo-SecureString -AsPlainText $AuthHeader -Force
                                $Ctoken = New-Object System.Management.Automation.PSCredential -ArgumentList $Global:o365Credential.UserName, $Password
                                $Global:ExchangeOnlineSession = New-PSSession -ConfigurationName Microsoft.Exchange `
                                -ConnectionUri https://outlook.office365.com/PowerShell-LiveId?BasicAuthToOAuthConversion=true `
                                -Credential $Ctoken `
                                -Authentication Basic `
                                -ErrorAction Stop `
                                -AllowRedirection
                                $Global:UseModernAuth = $True
                            }
                            catch {
                                if ($_ -like '*Connecting to remote server *Access is denied.*')
                                {
                                    Throw "The provided account doesn't have admin access to Exchange Online."
                                }
                            }
                            
                        }

                        if ($null -eq $Global:ExchangeOnlineSession)
                        {
                            Write-Warning "Exceeded max number of connections. Waiting 60 seconds"
                            Start-Sleep 60
                        }
                    }
                    if ($null -eq $Global:ExchangeOnlineModules)
                    {
                        Write-Verbose -Message "Importing all commands into the EXO Session"
                        $WarningPreference = 'silentlycontinue'
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
                                try {
                                    $Global:ExchangeOnlineSession = New-PSSession -Name 'ExchangeOnline' -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $O365Credential -Authentication Basic -AllowRedirection -ErrorAction Stop
                                }
                                catch {
                                    $AuthHeader = Get-AuthHeader -UserPrincipalName $Global:o365Credential.UserName -RessourceURI $RessourceURI -clientID $clientID -RedirectURI $RedirectURI
                                    $Password = ConvertTo-SecureString -AsPlainText $AuthHeader -Force
                                    $Ctoken = New-Object System.Management.Automation.PSCredential -ArgumentList $Global:o365Credential.UserName, $Password
                                    $Global:ExchangeOnlineSession = New-PSSession -ConfigurationName Microsoft.Exchange `
                                    -ConnectionUri https://outlook.office365.com/PowerShell-LiveId?BasicAuthToOAuthConversion=true `
                                    -Credential $Ctoken `
                                    -Authentication Basic `
                                    -AllowRedirection `
                                    -ErrorAction SilentlyContinue
                                    $Global:UseModernAuth = $True
                                }
                                
                            }
                            $WarningPreference='silentlycontinue'
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
                            $WarningPreference='silentlycontinue'
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
            $WarningPreference='silentlycontinue'
            $Global:SessionSecurityCompliance = Get-PSSession | Where-Object{$_.ComputerName -like "*.ps.compliance.protection.outlook.com" -and $_.State -eq "Opened"}
            #Try Catch doesn't work even with $Global:ErrorActionPreference = "stop"
            if ($null -eq $Global:SessionSecurityCompliance)
            {
                try
                {
                    Write-Verbose -Message "Session to Security & Compliance no working session found, creating a new one"
                    $Global:SessionSecurityCompliance = New-PSSession -ConfigurationName "Microsoft.Exchange" `
                    -ConnectionUri https://ps.compliance.protection.outlook.com/powershell-liveid/ `
                    -Credential $O365Credential `
                    -Authentication Basic `
                    -ErrorAction Stop `
                    -AllowRedirection               
                }
                catch
                {
                    $clientid = "a0c73c16-a7e3-4564-9a95-2bdf47383716";
                    $RessourceURI = "https://ps.compliance.protection.outlook.com";
                    $RedirectURI = "urn:ietf:wg:oauth:2.0:oob";
                    $AuthHeader = Get-AuthHeader -UserPrincipalName $Global:o365Credential.UserName -RessourceURI $RessourceURI -clientID $clientID -RedirectURI $RedirectURI
                    $Password = ConvertTo-SecureString -AsPlainText $AuthHeader -Force
                    $Ctoken = New-Object System.Management.Automation.PSCredential -ArgumentList $Global:o365Credential.UserName, $Password
                    $Global:SessionSecurityCompliance = New-PSSession -ConfigurationName Microsoft.Exchange `
                    -ConnectionUri https://ps.compliance.protection.outlook.com/powershell-liveid?BasicAuthToOAuthConversion=true `
                    -Credential $Ctoken `
                    -Authentication Basic `
                    -AllowRedirection
                    $Global:UseModernAuth = $True
                }
            }
            else 
            {
                Write-Verbose -Message "Session to Security & Compliance already exists, re-using existing session"
            }
            $WarningPreference='silentlycontinue'
            if ($null -eq $Global:SCModule)
            {
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
            $clientid = "1b730954-1685-4b74-9bfd-dac224a7b894";
            $RessourceURI = "https://graph.windows.net";
            $RedirectURI = "urn:ietf:wg:oauth:2.0:oob";
            $connectCmdlet = "Connect-MsolService";
            $connectCmdletArgs = "-Credential `$Global:o365Credential";
            $connectCmdletMfaRetryArgs = "-AdGraphAccessToken `$AuthToken";
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
            $clientid = "9bc3ab49-b65d-410a-85ad-de819febfddc";
            $RessourceURI = $Global:ConnectionUrl;
            $RedirectURI = "https://oauth.spops.microsoft.com/";
            $connectCmdlet = "Connect-PnPOnline";
            $connectCmdletArgs = "-Url `$Global:ConnectionUrl -Credentials `$Global:o365Credential";
            $connectCmdletMfaRetryArgs = "-AccessToken `$AuthToken";
            $variablePrefix = "pnp"
        }
        'MicrosoftTeams'
        {
            # Need to force-import this for some reason as of 1.0.0
            Import-Module MicrosoftTeams -Force
            $testCmdlet = "Get-Team";
            $exceptionStringMFA = "AADSTS";
            $clientid = "12128f48-ec9e-42f0-b203-ea49fb6af367";
            $RessourceURI = "https://graph.windows.net";
            $RedirectURI = "https://teamscmdlet.microsoft.com";
            $connectCmdlet = "Connect-MicrosoftTeams";
            $connectCmdletArgs = "-Credential `$Global:o365Credential";
            #$connectCmdletMfaRetryArgs = "-AadAccessToken `$AuthToken -AccountId `$Global:o365Credential.UserName";
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
        if ($_.Exception -like "*$connectCmdlet*" -or $_.Exception -like "*The access token expiry*")
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
                if($_.Exception -like "*The access token expiry*")
                {
                    throw
                }
                if($Global:UseModernAuth -eq $True)
                {
                    throw
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
                elseif ($_.Exception -like "*$exceptionStringMFA*" -or `
                        $_.Exception -like "*Sequence contains no elements*" -or `
                        ($_.Exception -like "*System.Reflection.TargetInvocationException: Exception has been thrown*" -and $Platform -eq "PNP") -or `
                        ($_.Exception -like "*or the web site does not support SharePoint Online credentials*" -and $Platform -eq "SharePointOnline") -or `
                        ($_.Exception -like "*The access token expiry*" -and $Platform -eq "Azure") -or `
                        $Global:UseModernAuth -eq $True)
                {
                    Write-Verbose -Message "The specified account is configured for Multi-Factor Authentication. Please re-enter your credentials."
                    Write-Host -ForegroundColor Green " - Prompting for credentials with MFA for $Platform"
                    try
                    {
                        Write-Debug -Message "Replacing connection parameters '$connectCmdletArgs' with '$connectCmdletMfaRetryArgs'..."
                        if($Platform -ne "SharePointOnline" -and $Platform -ne "MicrosoftTeams"){
                            $AuthHeader = Get-AuthHeader -UserPrincipalName $Global:o365Credential.UserName -RessourceURI $RessourceURI -clientID $clientID -RedirectURI $RedirectURI
                            $AuthToken = $AuthHeader.split(" ")[1]
                        }
                        Invoke-Expression -Command "$connectCmdlet -ErrorAction Stop $connectCmdletMfaRetryArgs | Out-Null"
                        if ($? -eq $false)
                        {
                            throw
                        }
                        else
                        {
                            New-Variable -Name $variablePrefix"LoginSucceeded" -Value $true -Scope Global -Option AllScope -Force
                            Write-Debug $variablePrefix"LoginSucceeded is now '$(Get-Variable -Name $($variablePrefix+"LoginSucceeded") -ValueOnly -Scope Global -ErrorAction SilentlyContinue)'."
                            $Global:UseModernAuth = $True
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

function Get-AzureADDLL
{
    [CmdletBinding()]
    [OutputType([System.String])]
    param(
    )
    [array]$AzureADModules = Get-Module -ListAvailable | Where-Object{$_.name -eq "AzureAD" -or $_.name -eq "AzureADPreview"}
    if($AzureADModules.count -eq 0)
    {
        Throw "Can't find Azure AD DLL. Install the module manually 'Install-Module AzureAD'"
    }
    else
    {
        $AzureDLL = Join-Path (($AzureADModules | Sort-Object version -Descending | Select-Object -first 1).Path | split-Path) Microsoft.IdentityModel.Clients.ActiveDirectory.dll
        Return $AzureDLL
    }

}

function Get-TenantLoginEndPoint
{
    [CmdletBinding()]
    [OutputType([System.String])]
    Param(
        [Parameter(Mandatory = $True)]
        [System.String]
        $TenantName,
        [Parameter(Mandatory = $false)]
        [System.String]
        [ValidateSet('MicrosoftOnline','EvoSTS')]
        $LoginSource = "EvoSTS"
    )
    $TenantInfo = @{}
    if($LoginSource -eq "EvoSTS")
    {
        $webrequest = Invoke-WebRequest -Uri https://login.windows.net/$($TenantName)/.well-known/openid-configuration -UseBasicParsing
    }
    else {
        $webrequest = Invoke-WebRequest -Uri https://login.microsoftonline.com/$($TenantName)/.well-known/openid-configuration -UseBasicParsing
    }
    if($webrequest.StatusCode -eq 200){
        $webrequest.content.replace("{","").replace("}","").split(",") | ForEach-Object { if($_ -like '*:*'){ $TenantInfo[(($_.split(":")[0]).replace('"',''))]= ($_.substring($($_.split(":")[0]).length +1)).replace('"','') } }
    }
    Return $TenantInfo
}

function New-ADALServiceInfo
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [System.String]
        $TenantName,
        [Parameter(Mandatory = $True)]
        [System.String]
        $UserPrincipalName,
        [Parameter(Mandatory = $false)]
        [System.String]
        [ValidateSet('MicrosoftOnline','EvoSTS')]
        $LoginSource = "EvoSTS"
    )
    $AzureADDLL = Get-AzureADDLL
    if([string]::IsNullOrEmpty($AzureADDLL))
    {
        Throw "Can't find Azure AD DLL"
        Exit
    }
    else
    {
        $tMod = [System.Reflection.Assembly]::LoadFrom($AzureADDLL)
    }
    $TenantInfo = Get-TenantLoginEndPoint -TenantName $TenantName
    if([string]::IsNullOrEmpty($TenantInfo))
    {
        Throw "Can't find Tenant Login Endpoint"
        Exit
    }
    else
    {
        [string] $authority = $($TenantInfo.get_item("authorization_endpoint"))
    }
    $PromptBehavior = [Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior]::Auto
    $Service=@{}
    $Service["authContext"] = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority   
    $Service["platformParam"] = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList $PromptBehavior
    $Service["userId"] = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList $UserPrincipalName, "OptionalDisplayableId"
    Return $Service
}

function Get-AuthHeader
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [System.String]
        $UserPrincipalName,
        [Parameter(Mandatory = $True)]
        $RessourceURI,
        [Parameter(Mandatory = $True)]
        $clientId,
        [Parameter(Mandatory = $True)]
        [System.String]
        $RedirectURI
    )
    if($null -eq $Global:ADALServicePoint)
    {
        $TenantName = $UserPrincipalName.split("@")[1]
        $Global:ADALServicePoint = New-ADALServiceInfo -TenantName $TenantName -UserPrincipalName $UserPrincipalName
    }
    
    try{
        Write-Debug "Looking for a refresh token"
        $authResult = $Global:ADALServicePoint.authContext.AcquireTokenSilentAsync($RessourceURI, $clientId)
        if($null -eq $authResult.result)
        {
            Write-Debug "Creating a new Token"
            $authResult = $Global:ADALServicePoint.authContext.AcquireTokenAsync($RessourceURI, $clientId, $RedirectURI, $Global:ADALServicePoint.platformParam, $Global:ADALServicePoint.userId)
        }
        $AuthHeader=$authResult.result.CreateAuthorizationHeader()
        }
    catch{
        Throw "Can't create Authorization header"
    }
    Return $AuthHeader
}
