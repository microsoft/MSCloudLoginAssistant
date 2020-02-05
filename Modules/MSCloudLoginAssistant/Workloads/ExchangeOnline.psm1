function Connect-MSCloudLoginExchangeOnline
{
    [CmdletBinding()]
    param()
    if($Global:UseApplicationIdentity -and $null -eq $Global:o365Credential)
    {
        throw "The Exchange Platform does not support connecting with application identity."
    }
    
    if ($null -eq $Global:o365Credential)
    {
       $Global:o365Credential = Get-Credential -Message "Cloud Credential"
    }
    $VerbosePreference = 'SilentlyContinue'
    $WarningPreference = "Continue"
    $clientid = "a0c73c16-a7e3-4564-9a95-2bdf47383716";
    $ResourceURI = "https://outlook.office365.com";
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

    $Global:OpenExchangeSession = Get-PSSession -Name 'ExchangeOnline' `
        -ErrorAction SilentlyContinue | `
            Where-Object -FilterScript { $_.State -eq 'Opened' }
    if ($null -eq $Global:OpenExchangeSession)
    {
        try
        {
            $PowerShellConnections = Get-NetTCPConnection | `
                Where-Object -FilterScript { `
                    $_.RemotePort -eq '443' -and $_.State -ne 'Established' `
                }

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
                $TenantName = $Global:o365Credential.UserName.split("@")[1]
                $TenantInfo = Get-TenantLoginEndPoint -TenantName $TenantName

                if ($TenantInfo -like '*login.microsoftonline.us*')
                {
                    $Global:CloudEnvironment = 'USGovernment'
                    $ResourceURI = 'https://outlook.office365.us'
                }
                elseif ($TenantInfo -like '*login.microsoftonline.com*')
                {
                    $Global:CloudEnvironment = 'Public'
                    $ResourceURI = 'https://outlook.office365.com'
                }
                elseif ($TenantInfo -like '*login.microsoftonline.de*')
                {
                    $Global:CloudEnvironment = 'Germany'
                    $ResourceURI = 'https://outlook.office.de'
                }

                try
                {
                    $Global:ExchangeOnlineSession = New-PSSession -Name 'ExchangeOnline' -ConfigurationName Microsoft.Exchange -ConnectionUri "$ResourceURI/powershell-liveid/" -Credential $O365Credential -Authentication Basic -AllowRedirection -ErrorAction Stop
                    $Global:IsMFAAuth = $false
                }
                catch
                {
                    try
                    {
                        $AuthHeader = Get-AuthHeader -UserPrincipalName $Global:o365Credential.UserName -RessourceURI $ResourceURI -clientID $clientID -RedirectURI $RedirectURI
                        $Password = ConvertTo-SecureString -AsPlainText $AuthHeader -Force
                        $Ctoken = New-Object System.Management.Automation.PSCredential -ArgumentList $Global:o365Credential.UserName, $Password
                        $Global:ExchangeOnlineSession = New-PSSession -ConfigurationName Microsoft.Exchange `
                            -ConnectionUri "$ResourceURI/PowerShell-LiveId?BasicAuthToOAuthConversion=true" `
                            -Credential $Ctoken `
                            -Authentication Basic `
                            -ErrorAction Stop `
                            -AllowRedirection
                        $Global:UseModernAuth = $True
                        $Global:IsMFAAuth = $True
                    }
                    catch
                    {
                        if ($_ -like '*Connecting to remote server *Access is denied.*')
                        {
                            Throw "The provided account doesn't have admin access to Exchange Online."
                        }
                    }
                }
            }
            if ($null -eq $Global:ExchangeOnlineModules)
            {
                Write-Verbose -Message "Importing all commands into the EXO Session"
                $WarningPreference = 'SilentlyContinue'
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

                $WaitTimePatternMatch = (($WaitTimePattern.Match($ExceptionMessage)).Value | `
                    Select-String -Pattern '[0-9]*' -AllMatches)

                $WaitTimeInSeconds = ($WaitTimePatternMatch | ForEach-Object {$_.Matches} | Where-Object -FilterScript { $_.Value -NotLike $null }).Value
                Write-Verbose -Message "Waiting for requested $WaitTimeInSeconds seconds..."
                Start-Sleep -Seconds ($WaitTimeInSeconds + 1)
                try
                {
                    Test-MSCloudLogin -Platform 'ExchangeOnline' -CloudCredential $Global:o365Credential
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
                throw $_
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