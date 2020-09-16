function Connect-MSCloudLoginAzureInformationProtection
{
    [CmdletBinding()]
    param(
        [Parameter()]
        [System.Management.Automation.PSCredential]
        $CloudCredentials
    )
    $WarningPreference = 'SilentlyContinue'
    $ProgressPreference = 'SilentlyContinue'

    Connect-AIPService -Credential $CloudCredentials
}