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
    $Global:SessionSecurityCompliance = Get-PSSession | `
        Where-Object { `
            ($_.ComputerName -like "*ps.compliance.protection.outlook.com" -or `
            $_.ComputerName -like "*ps.compliance.protection.office365.us" -or `
            $_.ComputerName -like "*ps.compliance.protection.outlook.de") `
            -and $_.State -eq "Opened"`
        }

    $CloudEnvironment = "Public"
    $ConnectionUrl = 'https://ps.compliance.protection.outlook.com/powershell-liveid/'

    # If the CloudCredential received matches the pattern '*.onmicrosoft.de' we assume that we are
    # trying to connect to the Germany cloud.
    if ($O365Credential.UserName -like '*.onmicrosoft.de')
    {
        $CloudEnvironment = "Germany"
        $ConnectionUrl = 'https://ps.compliance.protection.outlook.de/powershell-liveid/'
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
                # If the connection failed against either the Public or Germany clouds, then attempt to connect
                # to the GCC Cloud.
                try
                {
                    $CloudEnvironment = "GCC"
                    Write-Verbose -Message "Session to Security & Compliance no working session found, creating a new one"
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