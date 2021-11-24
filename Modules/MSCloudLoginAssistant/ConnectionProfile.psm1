class MSCloudLoginConnectionProfile
{
    [string]
    $CreatedTime

    [string]
    $OrganizationName

    [Azure]
    $Azure

    [AzureAD]
    $AzureAD

    [ExchangeOnline]
    $ExchangeOnline

    [Intune]
    $Intune

    [MicrosoftGraph]
    $MicrosoftGraph

    [PnP]
    $PnP

    [PowerPlatform]
    $PowerPlatform

    [SecurityComplianceCenter]
    $SecurityComplianceCenter

    [Teams]
    $Teams

    MSCloudLoginConnectionProfile()
    {
        $this.CreatedTime = [System.DateTime]::Now.ToString()

        # Workloads Object Creation
        $this.Azure                    = New-Object Azure
        $this.AzureAD                  = New-Object AzureAD
        $this.ExchangeOnline           = New-Object ExchangeOnline
        $this.Intune                   = New-Object Intune
        $this.MicrosoftGraph           = New-Object MicrosoftGraph
        $this.PnP                      = New-Object PnP
        $this.PowerPlatform            = New-Object PowerPlatform
        $this.SecurityComplianceCenter = New-Object SecurityComplianceCenter
        $this.Teams                    = New-Object Teams
    }
}

class Workload
{
    [string]
    [ValidateSet('Credentials', 'CredentialsWithApplicationId', 'ServicePrincipalWithSecret', 'ServicePrincipalWithThumbprint', 'ServicePrincipalWithPath', 'Interactive')]
    $AuthenticationType

    [boolean]
    $Connected = $false

    [string]
    $ConnectedDateTime

    [PSCredential]
    $Credentials

    [string]
    [ValidateSet('AzureCloud', 'AzureChinaCloud', 'AzureGermanyCloud', 'AzureUSGovernment')]
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
    $CertificatePassword

    [string]
    $CertificatePath

    [string]
    $CertificateThumbprint

    Setup()
    {
        # Determine the environment name based on email
        if ($null -eq $this.EnvironmentName)
        {
            $domain = $null
            if ($null -ne $this.Credentials)
            {
                $domain = $this.Credentials.UserName.Split('@')[1]
            }
            elseif ($this.ApplicationID)
            {
                if ($null -eq $Global:AttemptedToGetOrganizationName)
                {
                    $Global:AttemptedToGetOrganizationName = $true

                    if ([System.String]::IsNullOrEmpty($this.CertificateThumbprint))
                    {
                        $domain = $this.TenantId
                    }
                    else
                    {
                        $domain = Get-MSCloudLoginOrganizationName `
                                -ApplicationId $this.ApplicationId `
                                -TenantId $this.TenantId `
                                -CertificateThumbprint $this.CertificateThumbprint
                    }
                }
            }

            if ($domain -like '*.de')
            {
                $this.EnvironmentName = 'AzureGermanyCloud'
            }
            elseif ($domain -like '*.us')
            {
                $this.EnvironmentName = 'AzureUSGovernment'
            }
            else
            {
                $this.EnvironmentName = 'AzureCloud'
            }
        }

        # Determine the Authentication Type
        if ($this.ApplicationId -and $this.TenantId -and $this.CertificateThumbprint)
        {
            $this.AuthenticationType = "ServicePrincipalWithThumbprint"
        }
        elseif ($this.ApplicationId -and $this.TenantId -and $this.ApplicationSecret)
        {
            $this.AuthenticationType = "ServicePrincipalWithSecret"
        }
        elseif ($this.ApplicationId -and $this.TenantId -and $this.CertificatePath -and $this.CertificatePassword)
        {
            $this.AuthenticationType = "ServicePrincipalWithPAth"
        }
        elseif ($this.Credentials -and $this.ApplicationId)
        {
            $this.AuthenticationType = 'CredentialsWithApplicationId'
        }
        elseif ($this.Credentials)
        {
            $this.AuthenticationType = 'Credentials'
        }
        else
        {
            $this.AuthenticationType = 'Interactive'
        }
    }
}

class Azure:Workload
{
    [string]
    $ClientID = "1950a258-227b-4e31-a9cf-717495945fc2"

    [string]
    $ResourceURI = "https://management.core.windows.net"

    [string]
    $RedirectURI = "urn:ietf:wg:oauth:2.0:oob";

    [switch]
    $UseModernAuthentication

    Azure()
    {}

    [void] Connect() {
        ([Workload]$this).Setup()
        Connect-MSCloudLoginAzure
    }
}

class AzureAD:Workload
{
    AzureAD()
    {}

    [void] Connect() {
        ([Workload]$this).Setup()
        Connect-MSCloudLoginAzureAD
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
    {}

    [void] Connect() {
        ([Workload]$this).Setup()

        switch ($this.EnvironmentName)
        {
            "AzureCloud" {
                $this.ExchangeEnvironmentName    = 'O365Default'
            }
            "AzureGermanyCloud" {
                $this.ExchangeEnvironmentName    = 'O365GermanyCloud'
            }
            "AzureUSGovernment" {
                $this.ExchangeEnvironmentName    = 'O365USGovGCCHigh'
            }
        }

        Connect-MSCloudLoginExchangeOnline
    }
}

class Intune:Workload
{
    [string]
    $AuthorizationUrl

    [string]
    $GraphResourceId

    [string]
    $GraphBaseUrl

    Intune()
    {}

    [void] Connect() {
        ([Workload]$this).Setup()

        $tenantId = ''
        if ($null -ne $this.Credentials)
        {
            $tenantId = $this.Credentials.Username.Split('@')[1]
        }
        switch ($this.EnvironmentName)
        {
            "AzureCloud" {
                $this.AuthorizationUrl = "https://login.microsoftonline.com/oauth/v2.0/token/$($this.TenantId)"
                $this.GraphResourceId  = 'https://graph.microsoft.com/'
                $this.GraphBaseUrl     = 'https://graph.microsoft.com'
            }
            "AzureUSGovernment" {
                $this.AuthorizationUrl = "https://login.microsoftonline.us/oauth/v2.0/token/$($this.TenantId)"
                $this.GraphResourceId  = 'https://graph.microsoft.us/'
                $this.GraphBaseUrl     = 'https://graph.microsoft.us'
            }
        }
        Connect-MSCloudLoginIntune
    }
}

class MicrosoftGraph:Workload
{
    [string]
    $AccessToken

    [string]
    [ValidateSet("China", "Global", "USGov", "USGovDoD", "Germany")]
    $GraphEnvironment = "Global"

    [string]
    [ValidateSet("v1.0", "beta")]
    $ProfileName = "v1.0"

    [string]
    $ResourceUrl

    [string]
    $Scope

    [string]
    $TokenUrl

    [string]
    $UserTokenUrl

    MicrosoftGraph()
    {}

    [void] Connect() {
        ([Workload]$this).Setup()

        if ($null -ne $this.Credentials -and [System.String]::IsNullOrEmpty($this.TenantId))
        {
            $this.TenantId = $this.Credentials.Username.Split('@')[1]
        }
        switch ($this.EnvironmentName)
        {
            "AzureCloud" {
                $this.GraphEnvironment = 'Global'
                $this.ResourceUrl      = 'https://graph.microsoft.com/'
                $this.Scope            = 'https://graph.microsoft.com/.default'
                $this.TokenUrl         = "https://login.microsoftonline.com/$($this.TenantId)/oauth2/v2.0/token"
                $this.UserTokenUrl     = "https://login.microsoftonline.com/$($this.TenantId)/oauth2/v2.0/authorize"
            }
            "AzureUSGovernment" {
                $this.GraphEnvironment = 'USGov'
                $this.ResourceUrl      = 'https://graph.microsoft.us/'
                $this.Scope            = 'https://graph.microsoft.us/.default'
                $this.TokenUrl         = "https://login.microsoftonline.us/$($this.TenantId)/oauth2/v2.0/token"
                $this.UserTokenUrl     = "https://login.microsoftonline.us/$($this.TenantId)/oauth2/v2.0/authorize"
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
    $RedirectURI = "https://oauth.spops.microsoft.com/"

    [string]
    $AdminUrl

    [string]
    $AccessToken

    [string]
    [ValidateSet('Production', 'PPE', 'China', 'Germany', 'USGovernment', 'USGovernmentHigh', 'USGovernmentDoD')]
    $PnPAzureEnvironment

    PnP()
    {
        if (-not [String]::IsNullOrEmpty($this.CertificateThumbprint) -and (-not[String]::IsNullOrEmpty($this.CertificatePassword) -or
            -not[String]::IsNullOrEmpty($this.CertificatePath))
        )
        {
            throw "Cannot specific both a Certificate Thumbprint and Certificate Path and Password"
        }
    }

    [void] Connect([boolean]$ForceRefresh) {
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
        elseif ($this.EnvironmentName -eq 'AzureGermany')
        {
            $this.PnPAzureEnvironment = 'Germany'
        }

        Connect-MSCloudLoginPnP -ForceRefreshConnection $ForceRefresh
    }
}

class PowerPlatform:Workload
{
    [string]
    $Endpoint = 'prod'

    PowerPlatform()
    {}

    [void] Connect() {
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

    SecurityComplianceCenter()
    {}

    [void] Connect() {
        ([Workload]$this).Setup()

        switch ($this.EnvironmentName)
        {
            "AzureCloud"
            {
                $this.ConnectionUrl = 'https://ps.compliance.protection.outlook.com/powershell-liveid/'
                $this.AuthorizationUrl = 'https://login.microsoftonline.com/organizations'
            }
            "AzureUSGovernment"
            {
                $this.ConnectionUrl = 'https://ps.compliance.protection.office365.us/powershell-liveid/'
                $this.AuthorizationUrl = 'https://login.microsoftonline.us/organizations'
            }
            "AzureGermany"
            {
                $this.ConnectionUrl = 'https://ps.compliance.protection.outlook.de/powershell-liveid/'
                $this.AuthorizationUrl = 'https://login.microsoftonline.de/organizations'
            }
        }
        Connect-MSCloudLoginSecurityCompliance
    }
}

class Teams:Workload
{
    Teams()
    {}

    [void] Connect() {
        ([Workload]$this).Setup()
        Connect-MSCloudLoginTeams
    }
}
