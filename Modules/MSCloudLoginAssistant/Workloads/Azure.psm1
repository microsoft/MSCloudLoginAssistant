function Connect-MSCloudLoginAzure
{
    [CmdletBinding()]
    param()
    try
    {
        Connect-AzAccount -Credential $Global:o365Credential -ErrorAction Stop | Out-Null
        $Global:MSCloudLoginAzureConnected = $True
    }
    catch 
    {
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
                $Global:MSCloudLoginAzureConnected = $True
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
                    $Global:MSCloudLoginAzureConnected = $False
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
                $Global:MSCloudLoginAzureConnected = $false
                throw $_
            }
        }
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
        $Global:MSCloudLoginAzureConnected = $True
    }
    catch
    {
        $Global:MSCloudLoginAzureConnected = $False
        throw $_
    }
    return
}