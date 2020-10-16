function Connect-MSCloudLoginIntune
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $CloudCredential
    )

    $ApplicationID = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"
    try
    {
        Connect-MSGraph -Credential $CloudCredential | Out-Null
    }
    catch
    {
        # If the Intune PowerShell application has not yet been granted access to the tenant
        if ($_.Exception -like '*The user or administrator has not consented to use the application with ID*')
        {
            Write-Verbose "The AzureAD Application {$ApplicationID} has not bee granted consent. Launching an interactive prompt to request consent.'"
            Connect-MSGraph -AdminConsent | Out-Null
        }
        elseif ($_.Exception -like '*Due to a configuration change made by your administrator*')
        {
            Write-Verbose "The specified user account requires MFA. Launching interactive prompt.'"
            Connect-MSGraph -AdminConsent | Out-Null
        }
    }
}