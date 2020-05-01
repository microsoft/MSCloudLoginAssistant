function Connect-MicrosoftGraph
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

    try
    {
        Connect-Graph -ClientId $ApplicationId -TenantId $TenantId -CertificateThumbprint $CertificateThumbprint
    }
    catch
    {
        throw $_
    }
}
