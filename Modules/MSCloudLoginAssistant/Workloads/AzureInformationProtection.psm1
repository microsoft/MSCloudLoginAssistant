function Connect-MSCloudLoginAzureInformationProtection
{
    [CmdletBinding()]
    param(
        [Parameter()]
        [System.Management.Automation.PSCredential]
        $Credential
    )
    $WarningPreference = 'SilentlyContinue'
    $ProgressPreference = 'SilentlyContinue'

    Connect-AIPService -Credential $Credential | Out-Null
}
