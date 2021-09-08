function Connect-MSCloudLoginAzure
{
    [CmdletBinding()]
    param
    ()
    $WarningPreference = 'SilentlyContinue'
    $VerbosePreference = 'SilentlyContinue'

    # Explicitly import the required module(s) in case there is cmdlet ambiguity with other modules e.g. SharePointPnPPowerShell2013
    Import-Module -Name Az.Accounts -DisableNameChecking -Force

    if ($Global:MSCloudLoginConnectionProfile.Azure.Connected)
    {
        return
    }
    else
    {
        try
        {
            $method = Get-AzSubscription -ErrorAction stop
            if ($null -ne $method)
            {
                $Global:MSCloudLoginConnectionProfile.Azure.Connected = $true
                $Global:MSCloudLoginConnectionProfile.Azure.ConnectedDateTime = [System.DateTime]::Now.ToString()
                return
            }
        }
        catch
        {
            Write-Verbose "Could not find existing connection to Azure"
        }
        Get-AzContext | Remove-AzContext -Force | Out-Null
    }

    try
    {
        if ($Global:MSCloudLoginConnectionProfile.Azure.AuthenticationType -eq 'Credentials')
        {
            Connect-AzAccount -Credential $Global:MSCloudLoginConnectionProfile.Azure.Credentials `
                -Environment $Global:MSCloudLoginConnectionProfile.Azure.EnvironmentName `
                -ErrorAction Stop | Out-Null
            $Global:MSCloudLoginConnectionProfile.Azure.ConnectedDateTime         = [System.DateTime]::Now.ToString()
            $Global:MSCloudLoginConnectionProfile.Azure.MultiFactorAuthentication = $false
            $Global:MSCloudLoginConnectionProfile.Azure.Connected                 = $true
        }
        elseif ($Global:MSCloudLoginConnectionProfile.Azure.AuthenticationType -eq 'ServicePrincipalWithThumbprint')
        {
            Connect-AzAccount -ApplicationId $Global:MSCloudLoginConnectionProfile.Azure.ApplicationId `
                -Tenant $Global:MSCloudLoginConnectionProfile.Azure.TenantId `
                -CertificateThumbprint $Global:MSCloudLoginConnectionProfile.Azure.CertificateThumbprint `
                -Environment $Global:MSCloudLoginConnectionProfile.Azure.EnvironmentName `
                -ErrorAction Stop | Out-Null
            $Global:MSCloudLoginConnectionProfile.Azure.ConnectedDateTime         = [System.DateTime]::Now.ToString()
            $Global:MSCloudLoginConnectionProfile.Azure.MultiFactorAuthentication = $false
            $Global:MSCloudLoginConnectionProfile.Azure.Connected                 = $true
        }
        elseif ($Global:MSCloudLoginConnectionProfile.Azure.AuthenticationType -eq 'Interactive')
        {
            Connect-AzAccount -ErrorAction Stop | Out-Null
            $Global:MSCloudLoginConnectionProfile.Azure.ConnectedDateTime         = [System.DateTime]::Now.ToString()
            $Global:MSCloudLoginConnectionProfile.Azure.Connected                 = $true
        }
    }
    catch
    {
        Write-Debug -Message "Login using 'Connect-AzAccount' failed on initial attempt."
        if ($_.Exception -like "*User canceled authentication*")
        {
            $Global:MSCloudLoginConnectionProfile.Azure.Connected = $false
            throw "User canceled authentication"
        }
        elseif ($_.Exception -like "*The user name or password is incorrect*" -or $_.Exception -like "*ID3242*")
        {
            $Global:MSCloudLoginConnectionProfile.Azure.Connected = $false
            throw  "Bad credentials were supplied"
        }
        elseif (($_.Exception -like "*AADSTS*") -or `
                ($_.Exception -like "*Sequence contains no elements*") -or `
                ($_.Exception -like "*The access token expiry*") -or `
                ($_.Exception -like '*You must use multi-factor authentication*'))
        {
            Write-Verbose -Message "The specified account is configured for Multi-Factor Authentication. Please re-enter your credentials."

            try
            {
                $AuthHeader = Get-AuthHeader -UserPrincipalName $Global:MSCloudLoginConnectionProfile.Azure.Credentials.UserName `
                    -ResourceURI $Global:MSCloudLoginConnectionProfile.Azure.ResourceURI `
                    -ClientID $Global:MSCloudLoginConnectionProfile.Azure.ClientId `
                    -RedirectURI $Global:MSCloudLoginConnectionProfile.Azure.RedirectURI
                $AuthToken = $AuthHeader.split(" ")[1]
                Connect-AzAccount -ErrorAction Stop -AccessToken $AuthToken `
                    -AccountId $Global:MSCloudLoginConnectionProfile.Azure.Credentials.UserName | Out-Null

                $Global:MSCloudLoginConnectionProfile.Azure.ConnectedDateTime         = [System.DateTime]::Now.ToString()
                $Global:MSCloudLoginConnectionProfile.Azure.MultiFactorAuthentication = $true
                $Global:MSCloudLoginConnectionProfile.Azure.Connected                 = $true
            }
            catch
            {
                Write-Debug -Message "Login using 'Connect-AzAccount' and '-AccessToken $AuthToken -AccountId $($Global:MSCloudLoginConnectionProfile.Azure.Credentials.UserName)' failed."
                Write-Host -ForegroundColor Red $_.Exception
                $Global:MSCloudLoginConnectionProfile.Azure.Connected = $false
                throw $_
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
            $Global:MSCloudLoginConnectionProfile.Azure.Connected = $false
            throw "It appears you don't have the module for Azure installed, or it isn't loaded.`nPlease install/load the module and try again. `nYou can quickly and easily install the 'Az' module with: `n`"Install-Module -Name Az`""
        }
        elseif ($_.Exception -like "*this.Client.SubscriptionId*")
        {
            $Global:MSCloudLoginConnectionProfile.Azure.Connected = $false
            throw "It appears there are no Azure subscriptions associated with the account '$($Global:MSCloudLoginConnectionProfile.Azure.Credentials.UserName)'."
        }
        else
        {
            Write-Host -ForegroundColor Red $_.Exception
        }
    }
    finally
    {
        if ($Global:MSCloudLoginConnectionProfile.Azure.Connected)
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
