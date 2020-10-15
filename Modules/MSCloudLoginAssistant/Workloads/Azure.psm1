function Connect-MSCloudLoginAzure
{
    [CmdletBinding()]
    param()
    try
    {        
        if (!$Global:UseApplicationIdentity -and $null -ne $Global:o365Credential)
        {
            Connect-AzAccount -Credential $Global:o365Credential -ErrorAction Stop | Out-Null            
        }        
        elseif ($Global:UseApplicationIdentity)
        {
            $envName = Get-PsModuleAzureEnvironmentName -AzureCloudEnvironmentName $Global:appIdentityParams.AzureCloudEnvironmentName -Platform "Azure";
            if($Global:appIdentityParams.CertificateThumbprint) 
            {
                Connect-AzAccount -ApplicationId $Global:appIdentityParams.AppId -Tenant $Global:appIdentityParams.Tenant -CertificateThumbprint $Global:appIdentityParams.CertificateThumbprint  -Environment $envName -ErrorAction Stop | Out-Null
                Write-Verbose "Connected to Azure using application identity with certificate thumbprint"            
            }
            else
            {
                Connect-AzAccount -Credential $Global:appIdentityParams.ServicePrincipalCredentials -Tenant $Global:appIdentityParams.Tenant -ServicePrincipal -Environment $envName -ErrorAction Stop | Out-Null
                Write-Verbose "Connected to Azure using application identity with application secret"            
            }
        }
        else
        {
            Connect-AzAccount -ErrorAction Stop | Out-Null
        }
    }
    catch 
    {
        if ($Global:UseApplicationIdentity)
        {            
            throw $_
        }
        if ($_.Exception -like '*unknown_user_type: Unknown User Type*')
        {
            if ($Global:o365Credential.UserName.Split('@')[1] -like '*.de')
            {
                $EnvironmentName = 'AzureGermanCloud'
                $Global:CloudEnvironment = 'Germany'
            }
            else
            {
                $EnvironmentName = 'AzureCloud'
                $Global:CloudEnvironment = 'Public'
            }
            try
            {
                Connect-AzAccount -Credential $Global:o365Credential -Environment $EnvironmentName -ErrorAction Stop | Out-Null                
                $Global:IsMFAAuth = $false
            }
            catch
            {
                if ($_.Exception -like '*Due to a configuration change made by your administrator*')
                {
                    Connect-MSCloudLoginAzureMFA -EnvironmentName $EnvironmentName
                }
                elseif ($_.Exception -like '*unknown_user_type*')
                {
                    $Global:CloudEnvironment = 'GCCHigh'
                    Connect-MSCloudLoginAzureMFA -EnvironmentName 'GCCHigh'
                }
                else
                {                    
                    throw $_
                }
            }
        }
        else
        {
            if ($_.Exception -like '*Due to a configuration change made by your administrator*')
            {
                Connect-MSCloudLoginAzureMFA -EnvironmentName 'AzureCloud'
            }
            else
            {                
                throw $_
            }
        }
    }

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
    return
}

function Connect-MSCloudLoginAzureMFA
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.String]
        $EnvironmentName
    )

    $clientID = "1950a258-227b-4e31-a9cf-717495945fc2"
    $ResourceURI = "https://management.core.windows.net"
    if ($EnvironmentName -eq 'AzureGermanCloud')
    {
        $ResourceURI = 'https://management.core.cloudapi.de/'
    }
    elseif ($EnvironmentName -eq 'GCCHigh')
    {
        $ResourceURI = 'https://management.core.usgovcloudapi.net/'
        $EnvironmentName = 'AzureUSGovernment'
    }
    $RedirectURI = "urn:ietf:wg:oauth:2.0:oob"
    try
    {
        $AuthHeader = Get-AuthHeader -UserPrincipalName $Global:o365Credential.UserName `
            -ResourceURI $ResourceURI -clientID $clientID -RedirectURI $RedirectURI
        $AccessToken = $AuthHeader.split(" ")[1]
        Connect-AzAccount -AccountId $Global:o365Credential.UserName -Environment $EnvironmentName -AccessToken $AccessToken -ErrorAction Stop | Out-Null
        $Global:IsMFAAuth = $true        
    }
    catch
    {        
        throw $_
    }
    return
}