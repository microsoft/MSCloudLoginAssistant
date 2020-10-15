function Connect-MSCloudLoginSecurityCompliance
{
    [CmdletBinding()]
    param()
    if($Global:UseApplicationIdentity -and $null -eq $Global:o365Credential)
    {
        throw "The SecurityComplianceCenter Platform does not support connecting with application identity."
    }
    
    if ($null -eq $Global:o365Credential)
    {
       $Global:o365Credential = Get-Credential -Message "Cloud Credential"
    }
    $moduleName = "O365SecurityAndComplianceShell"
    $WarningPreference = 'SilentlyContinue'
    $InformationPreference = 'Continue'
    $ConnectionUrl = Get-AzureEnvironmentEndpoint -AzureCloudEnvironmentName $Global:appIdentityParams.AzureCloudEnvironmentName -EndpointName SecurityAndCompliancePsConnection
    $Global:SessionSecurityCompliance = Get-PSSession | `
        Where-Object { `
            ($_.ComputerName -like "*ps.compliance.protection.outlook.com" -or `
            $_.ComputerName -like "*ps.compliance.protection.office365.us" -or `
            $_.ComputerName -like "*ps.compliance.protection.outlook.de") `
            -and $_.State -eq "Opened"`
        }


    if ($null -eq $Global:SessionSecurityCompliance)
    {
        try
        {
            try
            {
                Write-Verbose -Message "Session to Security & Compliance no working session found, creating a new one"
                $Global:SessionSecurityCompliance = New-PSSession -ConfigurationName "Microsoft.Exchange" `
                -ConnectionUri $ConnectionUrl `
                -Credential $O365Credential `
                -Authentication Basic `
                -ErrorAction Stop `
                -AllowRedirection
            }
            catch
            {
                throw $_

                # we do not have correct different Cloud support, so best not to use this logic
                # it only leads to confusion
                # If the connection failed against either the Public or Germany clouds, then attempt to connect
                # to the GCC Cloud.
                # try
                # {
                #     $CloudEnvironment = "GCC"
                #     Write-Verbose -Message "Session to Security & Compliance no working session found, creating a new one"
                #     $Global:SessionSecurityCompliance = New-PSSession -ConfigurationName "Microsoft.Exchange" `
                #         -ConnectionUri 'https://ps.compliance.protection.office365.us/powershell-liveid/' `
                #         -Credential $O365Credential `
                #         -Authentication Basic `
                #         -ErrorAction Stop `
                #         -AllowRedirection
                # }
                # catch
                # {
                #     throw $_
                # }
            }
        }
        catch
        {
            if ($_.ErrorDetails.ToString().Contains('Fail to create a runspace because you have exceeded the maximum number of connections allowed' -and `
                $CloudEnvironment -ne 'Germany'))
            {
                $counter = 1
                while ($null -eq $Global:SessionSecurityCompliance -and $counter -le 10)
                {
                    try
                    {
                        $InformationPreference = "Continue"
                        Write-Information -Message "[$counter/10] Too many existing workspaces. Waiting an additional 60 seconds for sessions to free up."
                        Start-Sleep -Seconds 60
                        try
                        {
                            $Global:SessionSecurityCompliance = New-PSSession -ConfigurationName "Microsoft.Exchange" `
                                -ConnectionUri $ConnectionUrl `
                                -Credential $O365Credential `
                                -Authentication Basic `
                                -ErrorAction Stop `
                                -AllowRedirection
                        }
                        catch
                        {
                            try
                            {
                                $Global:SessionSecurityCompliance = New-PSSession -ConfigurationName "Microsoft.Exchange" `
                                    -ConnectionUri 'https://ps.compliance.protection.office365.us/powershell-liveid/' `
                                    -Credential $O365Credential `
                                    -Authentication Basic `
                                    -ErrorAction Stop `
                                    -AllowRedirection
                            }
                            catch
                            {
                                throw $_
                            }
                        }
                        $InformationPreference = "SilentlyContinue"
                    }
                    catch
                    {}
                    $counter ++
                }
            }
            else
            {
                # SC cannot use our own app identity or delegate so
                # we only allow app passwords for Security & compliance
                # if the connection fails we do not want to fallback to Modern authentication since
                # the script is very likely to be executing within a non interactive environment
                if($Global:UseApplicationIdentity)
                {
                    throw $_
                }
                try
                {
                    $clientid = "a0c73c16-a7e3-4564-9a95-2bdf47383716";
                    $ResourceURI = "https://ps.compliance.protection.outlook.com";
                    $NewConnectionUrl = $ConnectionUrl + '?BasicAuthToOAuthConversion=true'
                    if ($O365Credential.UserName -like '*.onmicrosoft.de')
                    {
                        $ResourceURI = "https://ps.compliance.protection.outlook.de";
                    }
                    $RedirectURI = "urn:ietf:wg:oauth:2.0:oob";
                    $AuthHeader = Get-AuthHeader -UserPrincipalName $Global:o365Credential.UserName `
                                                  -ResourceURI $ResourceURI -clientID $clientID `
                                                  -RedirectURI $RedirectURI

                    $Password = ConvertTo-SecureString -AsPlainText $AuthHeader -Force

                    $Ctoken = New-Object System.Management.Automation.PSCredential -ArgumentList $Global:o365Credential.UserName, $Password
                    $Global:SessionSecurityCompliance = New-PSSession -ConfigurationName Microsoft.Exchange `
                        -ConnectionUri $NewConnectionUrl `
                        -Credential $Ctoken `
                        -Authentication Basic `
                        -AllowRedirection
                    if ($null -eq $Global:SessionSecurityCompliance)
                    {
                        $Global:SessionSecurityCompliance = New-PSSession -ConfigurationName Microsoft.Exchange `
                            -ConnectionUri https://ps.compliance.protection.office365.us/powershell-liveid/?BasicAuthToOAuthConversion=true `
                            -Credential $Ctoken `
                            -Authentication Basic `
                            -AllowRedirection
                    }
                    $Global:UseModernAuth = $True
                }
                catch
                {
                    throw $_
                }
            }
        }
    }
    else
    {
        Write-Verbose -Message "Session to Security & Compliance already exists, re-using existing session"
    }
    $WarningPreference = 'SilentlyContinue'
    if ($null -eq $Global:SCModule)
    {
        $Global:SCModule = Import-PSSession $Global:SessionSecurityCompliance  `
            -ErrorAction SilentlyContinue `
            -AllowClobber

        Import-Module $Global:SCModule -Global | Out-Null
    }
    return
}