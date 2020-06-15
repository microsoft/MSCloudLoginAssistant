function Get-MSCloudLoginPlannerAuthResults
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $Credentials
    )

    #region Get Connection Info
    $EnvironmentInfo = Get-MSCloudLoginPlannerEnvironmentInfo -Credentials $Credentials
    $authUrl = $EnvironmentInfo.authUrl
    $resource = $EnvironmentInfo.resource
    #endregion

    $clientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    $authentiationContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authUrl, $False

    $authenticationResult = Get-AccessToken -AuthUri $authURl `
      -ClientId $clientId -Credentials $Credentials `
      -TargetUri $resource
    return $authenticationResult
}

function Get-MSCloudLoginPlannerEnvironmentInfo
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $Credentials
    )

    $info = Get-CloudEnvironmentInfo -Credentials $Credentials
    Write-Verbose -Message "Detected Azure Environment: $EnvironmentName"

    $result = $null
    switch ($info.cloud_instance_name)
    {
        'microsoftonline.com'{
            $result = @{
                authUrl = "https://login.microsoftonline.com/common"
                resource = "https://tasks.office.com"
            }
        }
        "microsoftonline.us" {
            $result = @{
                authUrl = "https://login.microsoftonline.us/common"
                resource = "https://tasks.office365.us"
            }
        }
    }
    return $result
}
