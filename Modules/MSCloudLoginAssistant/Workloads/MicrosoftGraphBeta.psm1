function Connect-MSCloudLoginMicrosoftGraphBeta
{
    [CmdletBinding()]
    param(
        [Parameter()]
        [System.String]
        $ApplicationId,

        [Parameter()]
        [System.String]
        $TenantId,

        [Parameter()]
        [System.String]
        $CertificateThumbprint
    )
    try
    {
        Import-Module -Name Microsoft.Graph.Authentication -DisableNameChecking -Force | out-null
        Connect-Graph -ClientId $ApplicationId -TenantId $TenantId `
            -CertificateThumbprint $CertificateThumbprint | Out-Null
        # BETA
        Select-MgProfile 'Beta' | Out-Null
        Write-Verbose -Message "Connected"
    }
    catch
    {
        Write-Verbose -Message $_
        throw $_
    }
}
