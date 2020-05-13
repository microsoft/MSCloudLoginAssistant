function Connect-MSCloudLoginAzure
{
    [CmdletBinding()]
    param
    (
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

    if ($null -eq $Global:UseModernAuth)
    {
        $Global:UseModernAuth = $UseModernAuth.IsPresent
    }
    $exceptionStringMFA = "AADSTS";
    $clientid = "1950a258-227b-4e31-a9cf-717495945fc2";
    $ResourceURI = "https://management.core.windows.net";
    $RedirectURI = "urn:ietf:wg:oauth:2.0:oob";
    ##$connectCmdlet = "Connect-AzAccount";

    # Explicitly import the required module(s) in case there is cmdlet ambiguity with other modules e.g. SharePointPnPPowerShell2013
    Import-Module -Name Az -DisableNameChecking -Force

    $global:azLoginSucceeded = $false
    try
    {
        Write-Verbose -Message "Checking Azure login..."
        # Run a simple command to check if we are logged in
        Get-AzResource -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
        if ($? -eq $false)
        {
            throw
        }
        else
        {
            Write-Verbose -Message "You are already logged in to Azure."
        }
    }
    catch
    {
        if ($_.Exception -like "*Connect-AzAccount*" -or $_.Exception -like "*The access token expiry*" -or `
            $_.Exception -like "*Authentication_ExpiredToken*")
        {
            Write-Debug -Message "Running 'Get-AzResource' failed on initial attempt."
            try
            {
                # Prompt for Windows-style credentials if we don't already have a credential object and not logging into Azure
                if ($_.Exception -like "*The access token expiry*")
                {
                    throw
                }
                if ($Global:UseModernAuth -eq $True)
                {
                    throw
                }
                Write-Verbose -Message "Running 'Connect-AzAccount -ErrorAction Stop -ErrorVariable `$err | Out-Null'"
                Connect-AzAccount -ErrorAction Stop -ErrorVariable `$err | Out-Null
                if ($? -eq $false -or $err)
                {
                    throw
                }
                else
                {
                    $global:azLoginSucceeded = $true
                }
            }
            catch
            {
                Write-Debug -Message "Login using 'Connect-AzAccount' failed on initial attempt."
                if ($_.Exception -like "*User canceled authentication*")
                {
                    throw "User canceled authentication"
                }
                elseif ($_.Exception -like "*The user name or password is incorrect*" -or $_.Exception -like "*ID3242*")
                {
                    throw  "Bad credentials were supplied"
                }
                elseif (($_.Exception -like "*$exceptionStringMFA*") -or `
                        ($_.Exception -like "*Sequence contains no elements*") -or `
                        ($_.Exception -like "*The access token expiry*") ##-or `
                        ##$Global:UseModernAuth -eq $True
                        )
                {
                    Write-Verbose -Message "The specified account is configured for Multi-Factor Authentication. Please re-enter your credentials."

                    try
                    {
                        $AuthHeader = Get-AuthHeader -UserPrincipalName $Global:o365Credential.UserName -ResourceURI $ResourceURI -clientID $clientID -RedirectURI $RedirectURI
                        $AuthToken = $AuthHeader.split(" ")[1]
                        Connect-AzAccount -ErrorAction Stop -AccessToken $AuthToken -AccountId $global:o365Credential.UserName | Out-Null
                        if ($? -eq $false)
                        {
                            throw
                        }
                        else
                        {
                            $global:azLoginSucceeded = $true
                            $Global:UseModernAuth = $True
                        }
                    }
                    catch
                    {
                        Write-Debug -Message "Login using 'Connect-AzAccount' and '-AccessToken $AuthToken -AccountId $($global:o365Credential.UserName)' failed."
                        Write-Host -ForegroundColor Red $_.Exception
                        throw $_
                    }
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
        elseif ($_.Exception -like "*Get-AzResource*")
        {
            # If the exception contains the name of the cmdlet we're trying to run, we probably don't have the required module installed yet
            throw "It appears you don't have the module for Azure installed, or it isn't loaded.`nPlease install/load the module and try again. `nYou can quickly and easily install the 'Az' module with: `n`"Install-Module -Name Az`""
        }
        elseif ($_.Exception -like "*this.Client.SubscriptionId*")
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
        if ($global:azLoginSucceeded)
        {
            Write-Verbose -Message " - Successfully logged in to Azure."
            # Needed when we're logging into Azure - in case we have multiple subs we need to prompt for one
            [array]$subscriptions = Get-AzSubscription -WarningAction Continue
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
                Set-AzContext -Subscription $Global:subscriptionDetails.Id -Name $Global:subscriptionDetails.Name -Force
            }
        }
    }
}
