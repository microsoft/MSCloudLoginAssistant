class MSCloudLoginConnectionProfile
{
    [string]
    $CreatedTime

    [string]
    $OrganizationName

    [ExchangeOnline]
    $ExchangeOnline

    [MicrosoftGraph]
    $MicrosoftGraph

    [PnP]
    $PnP

    [PowerPlatform]
    $PowerPlatform

    [SecurityComplianceCenter]
    $SecurityComplianceCenter

    [Tasks]
    $Tasks

    [Teams]
    $Teams

    MSCloudLoginConnectionProfile()
    {
        $this.CreatedTime = [System.DateTime]::Now.ToString()

        # Workloads Object Creation
        $this.ExchangeOnline = New-Object ExchangeOnline
        $this.MicrosoftGraph = New-Object MicrosoftGraph
        $this.PnP = New-Object PnP
        $this.PowerPlatform = New-Object PowerPlatform
        $this.SecurityComplianceCenter = New-Object SecurityComplianceCenter
        $this.Tasks = New-Object Tasks
        $this.Teams = New-Object Teams
    }
}

class Workload
{
    [string]
    [ValidateSet('Credentials', 'CredentialsWithApplicationId', 'CredentialsWithTenantId', 'ServicePrincipalWithSecret', 'ServicePrincipalWithThumbprint', 'ServicePrincipalWithPath', 'Interactive', 'Identity', 'AccessToken')]
    $AuthenticationType

    [boolean]
    $Connected = $false

    [string]
    $ConnectedDateTime

    [PSCredential]
    $Credentials

    [string]
    [ValidateSet('AzureCloud', 'AzureChinaCloud', 'AzureGermanyCloud', 'AzureUSGovernment', 'AzureDOD')]
    $EnvironmentName

    [boolean]
    $MultiFactorAuthentication

    [string]
    $ApplicationId

    [string]
    $ApplicationSecret

    [string]
    $TenantId

    [string]
    $TenantGUID

    [securestring]
    $CertificatePassword

    [string]
    $CertificatePath

    [string]
    $CertificateThumbprint

    [securestring[]]
    $AccessTokens

    [switch]
    $Identity

    Setup()
    {
        # Determine the environment name based on email
        if ($null -eq $this.EnvironmentName -and -not $Global:MSCloudLoginTriedGetEnvironment)
        {
            $Global:MSCloudLoginTriedGetEnvironment = $true
            if ($null -ne $this.Credentials)
            {
                $Global:CloudEnvironmentInfo = Get-CloudEnvironmentInfo -Credentials $this.Credentials
            }
            elseif ($this.ApplicationID -and $this.CertificateThumbprint)
            {
                $Global:CloudEnvironmentInfo = Get-CloudEnvironmentInfo -ApplicationId $this.ApplicationId -TenantId $this.TenantId -CertificateThumbprint $this.CertificateThumbprint
            }
            elseif ($this.ApplicationID -and $this.ApplicationSecret)
            {
                $Global:CloudEnvironmentInfo = Get-CloudEnvironmentInfo -ApplicationId $this.ApplicationId -TenantId $this.TenantId -ApplicationSecret $this.ApplicationSecret
            }
            elseif ($this.Identity.IsPresent)
            {
                $Global:CloudEnvironmentInfo = Get-CloudEnvironmentInfo -Identity -TenantId $this.TenantId
            }
            elseif ($this.AccessToken)
            {
                $Global:CloudEnvironmentInfo = Get-CloudEnvironmentInfo -TenantId $this.TenantId
            }

            Write-Verbose "Set environment to {$($Global:CloudEnvironmentInfo.tenant_region_sub_scope)}"
        }
        switch ($Global:CloudEnvironmentInfo.tenant_region_sub_scope)
        {
            'AzureGermanyCloud'
            {
                $this.EnvironmentName = 'O365GermanyCloud'
            }
            'DOD'
            {
                $this.EnvironmentName = 'AzureDOD'
            }
            'DODCON'
            {
                $this.EnvironmentName = 'AzureUSGovernment'
            }
            'USGov'
            {
                $this.EnvironmentName = 'AzureUSGovernment'
            }
            default
            {
                if ($null -ne $Global:CloudEnvironmentInfo -and $Global:CloudEnvironmentInfo.token_endpoint.StartsWith('https://login.partner.microsoftonline.cn'))
                {
                    $this.EnvironmentName = 'AzureChinaCloud'

                    # Converting tenant to GUID. This is a limitation of the PnP module which
                    # can't recognize the tenant when FQDN is provided.
                    $tenantGUIDValue = $Global:CloudEnvironmentInfo.token_endpoint.Split('/')[3]
                    $this.TenantGUID = $tenantGUIDValue
                }
                else
                {
                    $this.EnvironmentName = 'AzureCloud'
                }
            }
        }

        if ([System.String]::IsNullOrEmpty($this.EnvironmentName))
        {
            if ($null -ne $this.TenantId -and $this.TenantId.EndsWith('.cn'))
            {
                $this.EnvironmentName = 'AzureChinaCloud'
            }
            else
            {
                $this.EnvironmentName = 'AzureCloud'
            }
        }

        # Determine the Authentication Type
        if ($this.ApplicationId -and $this.TenantId -and $this.CertificateThumbprint)
        {
            $this.AuthenticationType = 'ServicePrincipalWithThumbprint'
        }
        elseif ($this.ApplicationId -and $this.TenantId -and $this.ApplicationSecret)
        {
            $this.AuthenticationType = 'ServicePrincipalWithSecret'
        }
        elseif ($this.ApplicationId -and $this.TenantId -and $this.CertificatePath -and $this.CertificatePassword)
        {
            $this.AuthenticationType = 'ServicePrincipalWithPath'
        }
        elseif ($this.Credentials -and $this.ApplicationId)
        {
            $this.AuthenticationType = 'CredentialsWithApplicationId'
        }
        elseif ($this.Credentials -and $this.TenantId)
        {
            $this.AuthenticationType = 'CredentialsWithTenantId'
        }
        elseif ($this.Credentials)
        {
            $this.AuthenticationType = 'Credentials'
        }
        elseif ($this.Identity)
        {
            $this.AuthenticationType = 'Identity'
        }
        elseif ($this.AccessTokens -and -not [System.String]::IsNullOrEmpty($this.TenantId))
        {
            $this.AuthenticationType = 'AccessToken'
        }
        else
        {
            $this.AuthenticationType = 'Interactive'
        }
    }
}

class ExchangeOnline:Workload
{
    [string]
    [ValidateSet('O365Default', 'O365GermanyCloud', 'O365China', 'O365USGovGCCHigh', 'O365USGovDod')]
    $ExchangeEnvironmentName = 'O365Default'

    [boolean]
    $SkipModuleReload = $false

    ExchangeOnline()
    {
    }

    [void] Connect()
    {
        ([Workload]$this).Setup()

        switch ($this.EnvironmentName)
        {
            'AzureCloud'
            {
                $this.ExchangeEnvironmentName = 'O365Default'
            }
            'AzureGermanyCloud'
            {
                $this.ExchangeEnvironmentName = 'O365GermanyCloud'
            }
            'AzureDOD'
            {
                $this.ExchangeEnvironmentName = 'O365USGovDoD'
            }
            'AzureUSGovernment'
            {
                $this.ExchangeEnvironmentName = 'O365USGovGCCHigh'
            }
            'AzureChinaCloud'
            {
                $this.ExchangeEnvironmentName = 'O365China'
            }
        }

        Connect-MSCloudLoginExchangeOnline
    }

    [void] Disconnect()
    {
        Write-Verbose -Message 'Disconnecting from Exchange Online Connection'
        Disconnect-ExchangeOnline -Confirm:$false
        $this.Connected = $false
    }
}

class MicrosoftGraph:Workload
{
    [string]
    [ValidateSet('China', 'Global', 'USGov', 'USGovDoD', 'Germany')]
    $GraphEnvironment = 'Global'

    [string]
    [ValidateSet('v1.0', 'beta')]
    $ProfileName = 'v1.0'

    [string]
    $ResourceUrl

    [string]
    $Scope

    [string]
    $TokenUrl

    [string]
    $UserTokenUrl

    MicrosoftGraph()
    {
    }

    [void] Connect()
    {
        ([Workload]$this).Setup()

        if ($null -ne $this.Credentials -and [System.String]::IsNullOrEmpty($this.TenantId))
        {
            $this.TenantId = $this.Credentials.Username.Split('@')[1]
        }
        switch ($this.EnvironmentName)
        {
            'AzureCloud'
            {
                $this.GraphEnvironment = 'Global'
                $this.ResourceUrl = 'https://graph.microsoft.com/'
                $this.Scope = 'https://graph.microsoft.com/.default'
                $this.TokenUrl = "https://login.microsoftonline.com/$($this.TenantId)/oauth2/v2.0/token"
                $this.UserTokenUrl = "https://login.microsoftonline.com/$($this.TenantId)/oauth2/v2.0/authorize"
            }
            'AzureUSGovernment'
            {
                $this.GraphEnvironment = 'USGov'
                $this.ResourceUrl = 'https://graph.microsoft.us/'
                $this.Scope = 'https://graph.microsoft.us/.default'
                $this.TokenUrl = "https://login.microsoftonline.us/$($this.TenantId)/oauth2/v2.0/token"
                $this.UserTokenUrl = "https://login.microsoftonline.us/$($this.TenantId)/oauth2/v2.0/authorize"
            }
            'AzureDOD'
            {
                $this.GraphEnvironment = 'USGovDoD'
                $this.ResourceUrl = 'https://dod-graph.microsoft.us/'
                $this.Scope = 'https://dod-graph.microsoft.us/.default'
                $this.TokenUrl = "https://login.microsoftonline.us/$($this.TenantId)/oauth2/v2.0/token"
                $this.UserTokenUrl = "https://login.microsoftonline.us/$($this.TenantId)/oauth2/v2.0/authorize"
            }
            'AzureChinaCloud'
            {
                $this.GraphEnvironment = 'China'
                $this.ResourceUrl = 'https://microsoftgraph.chinacloudapi.cn/'
                $this.Scope = 'https://microsoftgraph.chinacloudapi.cn/.default'
                $this.TokenUrl = "https://login.chinacloudapi.cn/$($this.TenantId)/oauth2/v2.0/token"
                $this.UserTokenUrl = "https://login.chinacloudapi.cn/$($this.TenantId)/oauth2/v2.0/authorize"
            }
        }
        Connect-MSCloudLoginMicrosoftGraph
    }
}

class PnP:Workload
{
    [string]
    $ConnectionUrl

    [string]
    $ClientId = '9bc3ab49-b65d-410a-85ad-de819febfddc'

    [string]
    $RedirectURI = 'https://oauth.spops.microsoft.com/'

    [string]
    $AdminUrl

    [string]
    [ValidateSet('Production', 'PPE', 'China', 'Germany', 'USGovernment', 'USGovernmentHigh', 'USGovernmentDoD')]
    $PnPAzureEnvironment

    PnP()
    {
        if (-not [String]::IsNullOrEmpty($this.CertificateThumbprint) -and (-not[String]::IsNullOrEmpty($this.CertificatePassword) -or
                -not[String]::IsNullOrEmpty($this.CertificatePath))
        )
        {
            throw 'Cannot specify both a Certificate Thumbprint and Certificate Path and Password'
        }
    }

    [void] Connect([boolean]$ForceRefresh)
    {
        ([Workload]$this).Setup()

        # PnP uses Production instead of AzureCloud to designate the Public Azure Cloud * AzureUSGovernment to USGovernmentHigh
        if ($this.EnvironmentName -eq 'AzureCloud')
        {
            $this.PnPAzureEnvironment = 'Production'
        }
        elseif ($this.EnvironmentName -eq 'AzureUSGovernment')
        {
            $this.PnPAzureEnvironment = 'USGovernmentHigh'
        }
        elseif ($this.EnvironmentName -eq 'AzureDOD')
        {
            $this.PnPAzureEnvironment = 'USGovernmentDoD'
        }
        elseif ($this.EnvironmentName -eq 'AzureGermany')
        {
            $this.PnPAzureEnvironment = 'Germany'
        }
        elseif ($this.EnvironmentName -eq 'AzureChinaCloud')
        {
            $this.PnPAzureEnvironment = 'China'
        }

        Connect-MSCloudLoginPnP -ForceRefreshConnection $ForceRefresh
    }
}

class PowerPlatform:Workload
{
    [string]
    $Endpoint = 'prod'

    PowerPlatform()
    {
    }

    [void] Connect()
    {
        ([Workload]$this).Setup()
        Connect-MSCloudLoginPowerPlatform
    }
}

class SecurityComplianceCenter:Workload
{
    [boolean]
    $SkipModuleReload = $false

    [string]
    $ConnectionUrl

    [string]
    $AuthorizationUrl

    [string]
    $AzureADAuthorizationEndpointUri

    SecurityComplianceCenter()
    {
    }

    [void] Connect()
    {
        ([Workload]$this).Setup()

        switch ($this.EnvironmentName)
        {
            'AzureCloud'
            {
                $this.ConnectionUrl = 'https://ps.compliance.protection.outlook.com/powershell-liveid/'
                $this.AuthorizationUrl = 'https://login.microsoftonline.com/organizations'
            }
            'AzureUSGovernment'
            {
                $this.ConnectionUrl = 'https://ps.compliance.protection.office365.us/powershell-liveid/'
                $this.AuthorizationUrl = 'https://login.microsoftonline.us/organizations'
                $this.AzureADAuthorizationEndpointUri = 'https://login.microsoftonline.us/common'
            }
            'AzureDOD'
            {
                $this.ConnectionUrl = 'https://l5.ps.compliance.protection.office365.us/powershell-liveid/'
                $this.AuthorizationUrl = 'https://login.microsoftonline.us/organizations'
                $this.AzureADAuthorizationEndpointUri = 'https://login.microsoftonline.us/common'
            }
            'AzureGermany'
            {
                $this.ConnectionUrl = 'https://ps.compliance.protection.outlook.de/powershell-liveid/'
                $this.AuthorizationUrl = 'https://login.microsoftonline.de/organizations'
            }
            'AzureChinaCloud'
            {
                $this.ConnectionUrl = 'https://ps.compliance.protection.partner.outlook.cn/powershell-liveid/'
                $this.AuthorizationUrl = 'https://login.chinacloudapi.cn/organizations'
            }
        }
        Connect-MSCloudLoginSecurityCompliance
    }
}

class Tasks:Workload
{
    [string]
    $HostUrl

    [string]
    $AuthorizationUrl

    [string]
    $ResourceUrl

    [string]
    $Scope

    [string]
    $AccessToken

    Tasks()
    {
    }

    [void] Connect()
    {
        ([Workload]$this).Setup()
        switch ($this.EnvironmentName)
        {
            'AzureDOD'
            {
                $this.HostUrl          = "https://tasks.office.us"
                $this.Scope            = "https://tasks.office.us/.default"
                $this.AuthorizationUrl = "https://login.microsoftonline.us"
                $this.ResourceUrl      = "https://tasks.osi.apps.mil"
            }
            'AzureUSGovernment'
            {
                $this.HostUrl          = "https://tasks.office.us"
                $this.Scope            = "https://tasks.office365.us/.default"
                $this.AuthorizationUrl = "https://login.microsoftonline.us"
                $this.ResourceUrl      = "https://tasks.office365.us"
            }
            default
            {
                $this.HostUrl          = "https://tasks.office.com"
                $this.Scope            = "https://tasks.office.com/.default"
                $this.AuthorizationUrl = "https://login.microsoftonline.com"
                $this.ResourceUrl      = "https://tasks.office.com"
            }
        }

        Connect-MSCloudLoginTasks
    }
}

class Teams:Workload
{
    Teams()
    {
    }

    [void] Connect()
    {
        ([Workload]$this).Setup()
        Connect-MSCloudLoginTeams
    }
}
