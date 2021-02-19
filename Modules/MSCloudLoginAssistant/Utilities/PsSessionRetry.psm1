function Ensure-RemotePsSession
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        $RemoteSessionName,

        [Parameter(Mandatory = $true)]
        $TestModuleLoadedCommand,

        [Parameter(Mandatory = $true)]
        $MaxConnectionsMessageSearchString,

        [Parameter(Mandatory = $true)]
        [ScriptBlock]
        $CreateSessionScriptBlock,

        [Parameter(Mandatory = $true)]
        [ScriptBlock]
        $ExistingSessionPredicate,

        [Parameter()]
        [int]
        $MaxAttempts = 12
    )
    $existingSessions = Get-PSSession | Where-Object -FilterScript $ExistingSessionPredicate
    [array]$activeSessions = $existingSessions | Where-Object -FilterScript { $_.State -eq 'Opened' }
    [array] $sessionsToClose = $existingSessions | Where-Object -FilterScript { $_.State -ne 'Opened' }
    for ($i = 0; $i -lt $sessionsToClose.Length; $i++)
    {
        $sessionName = $sessionsToClose[$i].Name
        Write-Verbose "Closing remote powershell session $sessionName"
        Remove-Session $sessionsToClose[$i]
    }
    if ($activeSessions.Length -ge 1)
    {
        $command = Get-Command $TestModuleLoadedCommand -ErrorAction 'SilentlyContinue'
        if ($null -ne $command)
        {
            return
        }
        $module = Import-PSSession $activeSessions[0] -DisableNameChecking -AllowClobber
        Import-Module $module -Global | Out-Null
        return
    }


    $connectionTriesCounter = 0
    $createdSession = $false
    do
    {
        $CurrentVerbosePreference = $VerbosePreference
        $CurrentInformationPreference = $InformationPreference
        $CurrentWarningPreference = $WarningPreference
        $VerbosePreference = "SilentlyContinue"
        $InformationPreference = "SilentlyContinue"
        $WarningPreference = "SilentlyContinue"

        $connectionTriesCounter++

        try
        {
            Write-Verbose -Message "Attempting to create a remote session for $RemoteSessionName"
            Invoke-Command $CreateSessionScriptBlock
            $createdSession = $true
            Write-Verbose -Message "Successfully connected to $RemoteSessionName"
        }
        catch
        {
            # unfortunatelly there is nothing except the error message that could uniquely identify this case, hello potential localization issues
            $isMaxAllowedConnectionsError = $null -ne $_.Exception -and $_.Exception.Message.Contains($MaxConnectionsMessageSearchString)
            if (!$isMaxAllowedConnectionsError)
            {
                throw
            }
        }
        finally
        {
            $VerbosePreference = $CurrentVerbosePreference
            $InformationPreference = $CurrentInformationPreference
            $WarningPreference = $CurrentWarningPreference
        }

        $shouldRetryConnection = !$createdSession -and $connectionTriesCounter -le $MaxAttempts
        if ($shouldRetryConnection)
        {
            Write-Information "[$connectionTriesCounter/$MaxAttempts] Too many existing workspaces. Waiting an additional 70 seconds for sessions to free up."
            Start-Sleep -Seconds 70
        }
    } while ($shouldRetryConnection)

    if (!$createdSession)
    {
        throw "The maximum retry attempt to create a $RemoteSessionName connection has been exceeded."
    }
}