function Invoke-Expression
{
    [CmdletBinding()]
    param (
        [Parameter()]
        [String]
        $Command
    )
}

function Get-AzureADDomain
{
    [CmdletBinding()]
    param (
        [Parameter()]
        [String]
        $Identity
    )
}

function Get-PSSession
{
    [CmdletBinding()]
    param (
        [Parameter()]
        [String]
        $Name
    )
}

function Remove-PSSession
{
    [CmdletBinding()]
    param (
        [Parameter()]
        [String]
        $Name
    )
}

function Import-PSSession
{
    [CmdletBinding()]
    param (
        [Parameter()]
        [String]
        $Name,

        [Parameter()]
        [Switch]
        $AllowClobber
    )
}

function Close-SessionsAndReturnError
{
    [CmdletBinding()]
    param (
        [Parameter()]
        [String]
        $ExceptionMessage
    )
}


function New-PSSession
{
    [CmdletBinding()]
    param (
        [Parameter()]
        [String]
        $Name,

        [Parameter()]
        [String]
        $ConfigurationName,

        [Parameter()]
        [String]
        $ConnectionUri,

        [Parameter()]
        [String]
        $Authentication,

        [Parameter()]
        [Switch]
        $AllowRedirection,

        [Parameter()]
        [System.Management.Automation.PSCredential]
        $Credential
    )
}

function Get-NetTCPConnection
{
    [CmdletBinding()]
    param (
        [Parameter()]
        [String]
        $LocalAddress,

        [Parameter()]
        [UInt16]
        $LocalPort
    )
}
