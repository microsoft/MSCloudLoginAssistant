
function Get-AzureADDLL
{
    [CmdletBinding()]
    [OutputType([System.String])]
    param(
    )
    if($Global:MSCloudLoginAzureAdDll)
    {
        return $Global:MSCloudLoginAzureAdDll
    }    
    [array]$AzureADModules = Get-Module -ListAvailable | Where-Object {$_.name -eq "AzureAD"}
    if ($AzureADModules.count -eq 0)
    {
        Throw "Can't find Azure AD DLL. Install the module manually 'Install-Module AzureAD'"
    }
    else
    {
        $Global:MSCloudLoginAzureAdDll = Join-Path (($AzureADModules | Sort-Object version -Descending | Select-Object -first 1).Path | split-Path) Microsoft.IdentityModel.Clients.ActiveDirectory.dll
        return $Global:MSCloudLoginAzureAdDll
    }
}

# very ugly, but all my attempts to set the afteraccess and beforeaccess handlers have failed in powershell
# either it hangs the session, or throws that there is no runspace available(since the auth is happening on a different thread), or it simply ignored my attemtps
# since this is pure C# it should work
# an alternate version would be to load a precompiled dll, but chose to go with this current option because of simplicity of the class
$charpCode="
using System;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System.IO;
using System.Security.Cryptography;

namespace ADAL
{
    public class FilePersistedTokenCache : TokenCache
    {
        public string CacheFilePath { get; private set; }
        private static readonly object FileLock = new object();
        private readonly byte[] _additionalEntropy;
        private DataProtectionScope _dataProtectionScope;

        public FilePersistedTokenCache(string filePath, bool isPerUser, byte[] additionalEntropy)
        {
            _additionalEntropy = additionalEntropy;
            _dataProtectionScope = isPerUser ? DataProtectionScope.CurrentUser : DataProtectionScope.LocalMachine;
            CacheFilePath = filePath;
            this.AfterAccess = AfterAccessNotification;
            this.BeforeAccess = BeforeAccessNotification;
            lock (FileLock)
            {
                readFromFile();
            }
        }
        
        public override void Clear()
        {
            base.Clear();
            File.Delete(CacheFilePath);
        }
        
        void BeforeAccessNotification(TokenCacheNotificationArgs args)
        {
            lock (FileLock)
            {
                readFromFile();
            }
        }
        
        void AfterAccessNotification(TokenCacheNotificationArgs args)
        {
            // if the access operation resulted in a cache update
            if (this.HasStateChanged)
            {
                lock (FileLock)
                {
                    // reflect changes in the persistent store
                    writeToFile();
                    // once the write operation took place, restore the HasStateChanged bit to false
                    this.HasStateChanged = false;
                }
            }
        }

        private void readFromFile()
        {
            try
            {
                byte[] protectedBytes = (!string.IsNullOrEmpty(CacheFilePath) && File.Exists(CacheFilePath))
                    ? File.ReadAllBytes(CacheFilePath)
                    : null;
                byte[] unprotectedBytes = (protectedBytes != null)
                    ? ProtectedData.Unprotect(protectedBytes, _additionalEntropy, _dataProtectionScope)
                    : null;
                this.Deserialize(unprotectedBytes);
            }
            catch (Exception ex)
            {
                // no logging unfortunately
            }
        }

        private void writeToFile()
        {
            try
            {
                var blob = this.Serialize();
                if (blob != null)
                {
                    byte[] protectedBytes = ProtectedData.Protect(blob, _additionalEntropy, _dataProtectionScope);
                    File.WriteAllBytes(CacheFilePath, protectedBytes);
                }
                else
                {
                    File.Delete(CacheFilePath);
                }
            }
            catch (Exception ex)
            {
                // no logging unfortunately             
            }
        }
    }
}"


function Get-PersistedTokenCacheInstance
{
    Param(
        [Parameter(Mandatory = $True)]        
        $FilePath,

        [Parameter(Mandatory = $false)]
        [System.Byte[]]
        $TokenCacheEntropy,

        [Parameter()]
        [ValidateSet("CurrentUser", "LocalMachine")]
        [System.String]
        $TokenCacheDataProtectionScope
    )

    if (!([System.Management.Automation.PSTypeName]'ADAL.FilePersistedTokenCache').Type)   
    {     
        try
        {
            # there are some very nasty problems with the fact that there are multiple versions of ADAL dll being used            
            # across all of the platforms
            # if we just pass the adaldlllocation then  ie. when calling acquireToken it would say that it cannot find the method out of the blue after a couple of calls            
            # for the compilation step and the load type step we simply forward the currently loaded assembly 
            try
            {
                Enable-AppDomainLoadAnyVersionResolution

                   # $location = [PsObject].Assembly.Location
                $adalDLLLocation = Get-AzureADDLL
                $compileParams = New-Object System.CodeDom.Compiler.CompilerParameters
                $assemblyRange = @("System.dll", "System.Security.dll", "System.Core.dll", "System.Threading.dll", $adalDLLLocation, $location)
                $compileParams.ReferencedAssemblies.AddRange($assemblyRange)
                $compileParams.GenerateInMemory = $True    

                try
                {
                    Add-Type -TypeDefinition $charpCode -CompilerParameters $compileParams -passthru  | Out-Null 
                }
                catch
                {

                }


                # if we wanted to use a precompiled dll
                # chose to just compile the code dynamically because it seems easier to mantain for such a simple class
                #Add-Type -Path "$PSScriptRoot\ADAL.FilePersistedTokenCache.dll"
            }            
            finally
            {
                Disable-AppDomainLoadAnyVersionResolution
            }
        }
        catch
        {
            Write-Error $_   
        }        
    }
         
    $isPerUserDataProtection = $TokenCacheDataProtectionScope -ne "LocalMachine"
    return New-Object "ADAL.FilePersistedTokenCache" -ArgumentList $FilePath, $isPerUserDataProtection, $TokenCacheEntropy
}