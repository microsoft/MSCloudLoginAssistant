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
