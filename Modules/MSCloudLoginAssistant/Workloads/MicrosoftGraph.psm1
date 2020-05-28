function Connect-MSCloudLoginMicrosoftGraph
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.String]
        $ApplicationId,

        [Parameter(Mandatory = $true)]
        [System.String]
        $TenantId,

        [Parameter(Mandatory = $true)]
        [System.String]
        $CertificateThumbprint
    )
$VerbosePreference = 'Continue'
    try
    {
        Write-Verbose "ICI"
        Write-Verbose $ApplicationId
        Write-Verbose $TenantId
        Write-Verbose $CertificateThumbprint

        Import-Module -Name Microsoft.Graph.Authentication -DisableNameChecking -Force | out-null
        Connect-Graph -ClientId $ApplicationId -TenantId $TenantId -CertificateThumbprint $CertificateThumbprint
        Write-Verbose "Connected"
    }
    catch
    {
        Write-Verbose -Message $_
        throw $_
    }
}
