function Connect-MSCloudLoginPowerPlatform
{
    [CmdletBinding()]
    param()

    try
    {
        $moduleName = "Microsoft.PowerApps.Administration.PowerShell"
        $WarningPreference = 'SilentlyContinue'
        Import-Module -Name $moduleName -Global -ErrorAction SilentlyContinue -Force | Out-Null
        $WarningPreference = 'Continue'
        if ($null -eq $Global:currentSession -or $global:currentSession.loggedIn -eq $false -or `
            $global:currentSession.expiresOn -lt (Get-Date))
        {
            $tenantName = $Global:o365Credential.UserName.Split('@')[1]
            $tenantInfo = Get-TenantLoginEndPoint -TenantName $tenantName
            $tenantId = $tenantInfo.issuer.Replace("https://", "").Split('/')[1]
            $Endpoint = 'prod'

            if ($tenantInfo.tenant_region_sub_scope -eq 'GCC')
            {
                $Endpoint = 'usgov'
            }
            $ManagementAudience = "https://management.azure.com/"
            $TokenInfoManagement = Get-PowerPlatformTokenInfo -Audience $ManagementAudience -Credentials $Global:o365Credential
            $Global:currentSession = @{
                loggedIn = $true;
                idToken = $TokenInfoManagement.JwtToken;
                upn = $TokenInfoManagement.Claims.upn;
                tenantId = $tenantId;
                userId = $TokenInfoManagement.Claims.oid;
                refreshToken = $TokenInfoManagement.RefreshToken;
                expiresOn = (Get-Date).AddHours(8);
                resourceTokens = @{
                    $ManagementAudience = @{
                        accessToken = $TokenInfoManagement.AccessToken;
                        expiresOn = $TokenInfoManagement.ExpiresOn.DateTime;
                    }
                };
                selectedEnvironment = "~default";
                flowEndpoint =
                    switch ($Endpoint)
                    {
                        "prod"      { "api.flow.microsoft.com" }
                        "usgov"     { "gov.api.flow.microsoft.us" }
                        "usgovhigh" { "high.api.flow.microsoft.us" }
                        "preview"   { "preview.api.flow.microsoft.com" }
                        "tip1"      { "tip1.api.flow.microsoft.com"}
                        "tip2"      { "tip2.api.flow.microsoft.com" }
                        default     { throw "Unsupported endpoint '$Endpoint'"}
                    };
                powerAppsEndpoint =
                    switch ($Endpoint)
                    {
                        "prod"      { "api.powerapps.com" }
                        "usgov"     { "gov.api.powerapps.us" }
                        "usgovhigh" { "high.api.powerapps.us" }
                        "preview"   { "preview.api.powerapps.com" }
                        "tip1"      { "tip1.api.powerapps.com"}
                        "tip2"      { "tip2.api.powerapps.com" }
                        default     { throw "Unsupported endpoint '$Endpoint'"}
                    };
                bapEndpoint =
                    switch ($Endpoint)
                    {
                        "prod"      { "api.bap.microsoft.com" }
                        "usgov"     { "gov.api.bap.microsoft.us" }
                        "usgovhigh" { "high.api.bap.microsoft.us" }
                        "preview"   { "preview.api.bap.microsoft.com" }
                        "tip1"      { "tip1.api.bap.microsoft.com"}
                        "tip2"      { "tip2.api.bap.microsoft.com" }
                        default     { throw "Unsupported endpoint '$Endpoint'"}
                    };
                graphEndpoint =
                    switch ($Endpoint)
                    {
                        "prod"      { "graph.windows.net" }
                        "usgov"     { "graph.windows.net" }
                        "usgovhigh" { "graph.windows.net" }
                        "preview"   { "graph.windows.net" }
                        "tip1"      { "graph.windows.net"}
                        "tip2"      { "graph.windows.net" }
                        default     { throw "Unsupported endpoint '$Endpoint'"}
                    };
                cdsOneEndpoint =
                    switch ($Endpoint)
                    {
                        "prod"      { "api.cds.microsoft.com" }
                        "usgov"     { "gov.api.cds.microsoft.us" }
                        "usgovhigh" { "high.api.cds.microsoft.us" }
                        "preview"   { "preview.api.cds.microsoft.com" }
                        "tip1"      { "tip1.api.cds.microsoft.com"}
                        "tip2"      { "tip2.api.cds.microsoft.com" }
                        default     { throw "Unsupported endpoint '$Endpoint'"}
                    };
            };

            $Route = "https://{bapEndpoint}/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments/~default?`$expand=permissions&api-version={apiVersion}" `

            $uri = $Route `
                | ReplaceMacro -Macro "{apiVersion}"  -Value $ApiVersion `
                | ReplaceMacro -Macro "{flowEndpoint}" -Value $global:currentSession.flowEndpoint `
                | ReplaceMacro -Macro "{powerAppsEndpoint}" -Value $global:currentSession.powerAppsEndpoint `
                | ReplaceMacro -Macro "{bapEndpoint}" -Value $global:currentSession.bapEndpoint `
                | ReplaceMacro -Macro "{graphEndpoint}" -Value $global:currentSession.graphEndpoint `
                | ReplaceMacro -Macro "{cdsOneEndpoint}" -Value $global:currentSession.cdsOneEndpoint;

            $hostMapping = @{
                "management.azure.com"        = "https://management.azure.com/";
                "api.powerapps.com"           = "https://service.powerapps.com/";
                "tip1.api.powerapps.com"      = "https://service.powerapps.com/";
                "tip2.api.powerapps.com"      = "https://service.powerapps.com/";
                "graph.windows.net"           = "https://graph.windows.net/";
                "api.bap.microsoft.com"       = "https://service.powerapps.com/";
                "tip1.api.bap.microsoft.com"  = "https://service.powerapps.com/";
                "tip2.api.bap.microsoft.com"  = "https://service.powerapps.com/";
                "api.flow.microsoft.com"      = "https://service.flow.microsoft.com/";
                "tip1.api.flow.microsoft.com" = "https://service.flow.microsoft.com/";
                "tip2.api.flow.microsoft.com" = "https://service.flow.microsoft.com/";
                "gov.api.bap.microsoft.us"    = "https://gov.service.powerapps.us/";
                "high.api.bap.microsoft.us"   = "https://high.service.powerapps.us/";
                "gov.api.powerapps.us"        = "https://gov.service.powerapps.us/";
                "high.api.powerapps.us"       = "https://high.service.powerapps.us/";
                "gov.api.flow.microsoft.us"   = "https://gov.service.flow.microsoft.us/";
                "high.api.flow.microsoft.us"  = "https://high.service.flow.microsoft.us/";
            }

            $uriObject = New-Object System.Uri($Uri)
            $uriObjectHost = $uriObject.Host
            $ServiceAudience = $hostMapping[$uriObjectHost]
            $TokenInfoService = Get-PowerPlatformTokenInfo -Audience $ServiceAudience -Credentials $Global:o365Credential
            $ServiceResourceToken = @{
                accessToken = $TokenInfoService.AccessToken;
                expiresOn = $TokenInfoService.ExpiresOn.DateTime;
            }
            $Global:currentSession.resourceTokens.Add($ServiceAudience, $ServiceResourceToken)
        }
        return
    }
    catch
    {
        throw $_
    }
}