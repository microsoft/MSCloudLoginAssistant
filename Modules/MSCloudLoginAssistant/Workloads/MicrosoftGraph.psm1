function Connect-MicrosoftGraph
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.String]
        $ApplicationID,

        [Parameter(Mandatory = $true)]
        [System.String]
        $TenantId,

        [Parameter(Mandatory = $true)]
        [System.String]
        $CertificateThumbprint
    )

    try
    {
        Connect-Graph -ClientId $ApplicationId -TenantId $TenantId -CertificateThumbprint $CertificateThumbprint -ErrorAction Stop | Out-Null
    }
    catch
    {
        throw $_
    }
}
