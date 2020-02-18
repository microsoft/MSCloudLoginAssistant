
function Get-AzureADDLL
{
    [CmdletBinding()]
    [OutputType([System.String])]
    param(
    )
    [array]$AzureADModules = Get-Module -ListAvailable | Where-Object {$_.name -eq "AzureAD"}
    if ($AzureADModules.count -eq 0)
    {
        Throw "Can't find Azure AD DLL. Install the module manually 'Install-Module AzureAD'"
    }
    else
    {
        $AzureDLL = Join-Path (($AzureADModules | Sort-Object version -Descending | Select-Object -first 1).Path | split-Path) Microsoft.IdentityModel.Clients.ActiveDirectory.dll
        return $AzureDLL
    }
}

# very ugly, but all my attempts to set the afteraccess and beforeaccess handlers have failed in powershell
# either it hangs the session, or throws that there is no runspace available(since the auth is happening on a different thread), or it simply ignored my attemtps
# since this is pure C# it should work
# an alternate version would be to load a precompiled dll, but chose to go with this current option because of simplicity of the class
$charpCode="
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System.IO;
using System.Security.Cryptography;

namespace ADAL
{
    public class FilePersistedTokenCache : TokenCache
    {
        public string CacheFilePath { get; private set; }
        private static readonly object FileLock = new object();
        
        public FilePersistedTokenCache(string filePath)
        {
            CacheFilePath = filePath;
            this.AfterAccess = AfterAccessNotification;
            this.BeforeAccess = BeforeAccessNotification;
            lock (FileLock)
            {
                this.Deserialize(ReadFromFileIfExists(CacheFilePath));
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
                this.Deserialize(ReadFromFileIfExists(CacheFilePath));
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
                    WriteToFileIfNotNull(CacheFilePath, this.Serialize());
                    // once the write operation took place, restore the HasStateChanged bit to false
                    this.HasStateChanged = false;
                }
            }
        }

        private byte[] ReadFromFileIfExists(string path)
        {
            byte[] protectedBytes = (!string.IsNullOrEmpty(path) && File.Exists(path)) 
                ? File.ReadAllBytes(path) : null;
            byte[] unprotectedBytes = (protectedBytes != null) 
                ? ProtectedData.Unprotect(protectedBytes, null, DataProtectionScope.CurrentUser) : null;
            return unprotectedBytes;
        }

        private static void WriteToFileIfNotNull(string path, byte[] blob)
        {
            if (blob != null)
            {
                byte[] protectedBytes = ProtectedData.Protect(blob, null, DataProtectionScope.CurrentUser);
                File.WriteAllBytes(path, protectedBytes);
            }
            else
            {
                File.Delete(path);
            }
        }
    }
}"


function Get-PersistedTokenCacheInstance
{
    Param(
        [Parameter(Mandatory = $True)]        
        $FilePath
    )

    if (!([System.Management.Automation.PSTypeName]'ADAL.FilePersistedTokenCache').Type)   
    {
     
        try
        {
            # there are some very nasty problems with the fact that there are multiple versions of ADAL dll being used            
            # across all of the platforms
            # if we just pass the adaldlllocation then  ie. when calling acquireToken it would say that it cannot find the method out of the blue after a couple of calls            
            # for the compilation step and the load type step we simply forward the currently loaded assembly
            $onAssemblyResolveEventHandler = [ResolveEventHandler]{
                param($sender, $e)
            
                Write-Verbose "ResolveEventHandler: Attempting FullName resolution of $($e.Name)" 
                foreach($assembly in [System.AppDomain]::CurrentDomain.GetAssemblies()) {
                    if ($assembly.FullName -eq $e.Name) {
                        Write-Host "Successful FullName resolution of $($e.Name)" 
                        return $assembly
                    }
                }
            
                Write-Verbose "ResolveEventHandler: Attempting name-only resolution of $($e.Name)" 
                foreach($assembly in [System.AppDomain]::CurrentDomain.GetAssemblies()) {
                    # Get just the name from the FullName (no version)
                    $assemblyName = $assembly.FullName.Substring(0, $assembly.FullName.IndexOf(", "))
            
                    if ($e.Name.StartsWith($($assemblyName + ","))) {
            
                        Write-Verbose "Successful name-only (no version) resolution of $assemblyName" 
                        return $assembly
                    }
                }
                            
                return $null
            }
            
            try
            {
                [System.AppDomain]::CurrentDomain.add_AssemblyResolve($onAssemblyResolveEventHandler)

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
                [System.AppDomain]::CurrentDomain.remove_AssemblyResolve($onAssemblyResolveEventHandler)
            }
        }
        catch
        {
            Write-Error $_   
        }        
    }
         
    return New-Object "ADAL.FilePersistedTokenCache" -ArgumentList $FilePath 
}