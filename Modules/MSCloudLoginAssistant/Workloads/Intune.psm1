function Connect-MSCloudLoginIntune
{
    [CmdletBinding()]
    param(
    )


    if (!(Get-Module Microsoft.Graph.Intune))
    {
        Import-Module -Name Microsoft.Graph.Intune -DisableNameChecking -Force | out-null
    }

    if ($Global:UseApplicationIdentity)
    {       
        try
        {
            Enable-AppDomainLoadAnyVersionResolution
            if (!('Microsoft.Intune.PowerShellGraphSDK.PowerShellCmdlets.ODataCmdletBase' -as [Type]))
            {
                $rootDir = [System.IO.Path]::GetDirectoryName((Get-Module Microsoft.Graph.Intune).Path).TrimEnd('\')
                $intunePsSdkPath = $rootDir + "\bin\Microsoft.Intune.PowerShellGraphSDK.dll"
                Add-Type -Path $intunePsSdkPath
            }
            
            # the official Connect-MSGraph cmdlet does not support Application Identity auth, it's not implemented even though there are signs that it was considered
            # since we already have our authentication context we can that use to authenticate to graph with the application identity
            # unfortunately there is a bit of hacking involved by dynamically patching some methods in the Intune PowerShell SDK dll
            [SysKit.MsGraphAuthModulePatching.MsGraphIntuneAuthModulePatcher]::DoPatching([SysKit.MsGraphAuthModulePatching.MsGraphIntuneAuthDelegate] {
                    $graphEndpoint = Get-AzureEnvironmentEndpoint -AzureCloudEnvironmentName $Global:appIdentityParams.AzureCloudEnvironmentName -EndpointName MsGraphEndpointResourceId
                    $authResult = Get-AppIdentityAuthResult -TargetUri $graphEndpoint

                    $result = New-Object 'SysKit.MsGraphAuthModulePatching.MsGraphIntuneAuthResult'

                    $result.AccessTokenType = "Bearer"
                    $result.AccessToken = $authResult.AccessToken
                    $result.ExpiresOn = $authResult.ExpiresOn

                    return $result                    
                })
        }
        finally
        {
            Disable-AppDomainLoadAnyVersionResolution
        }

        Write-Verbose "Connected to Intune using application identity with certificate thumbprint"
    }
    else
    {
        throw "Not implemented"
    }
}