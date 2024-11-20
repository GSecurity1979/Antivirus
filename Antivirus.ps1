# Set your VirusTotal public API key here
$VirusTotalApiKey = "28d53b2690cc5d8afc29c7e5104902742af02f14c80368ef4bbd2d01e57e1b77"

# Set the polling interval (in seconds) for the monitoring loop
$PollingInterval = 300  # Adjusted to reduce CPU usage

# Dictionary to cache scanned file hashes (with clean results)
$scannedFiles = @{}

# Function to log actions and events
function Write-Log {
    param (
        [string]$Message
    )
    $logFile = "$env:USERPROFILE\Documents\SimpleAntivirus.log"
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp - $Message"
    Add-Content -Path $logFile -Value $logEntry
}

# Function to ensure the script is running with elevated privileges (as Administrator)
function Ensure-Elevation {
    if (-not ([Security.Principal.WindowsPrincipal]([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        Write-Log "Restarting script as Administrator."
        $newProcess = New-Object System.Diagnostics.ProcessStartInfo "powershell"
        $newProcess.Arguments = "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" 
        $newProcess.Verb = "runas"
        $newProcess.WindowStyle = "Hidden"
        [System.Diagnostics.Process]::Start($newProcess)
        exit
    }
}

# Function to ensure WMI (Winmgmt) service is running and set to Automatic
function Ensure-WMIService {
    $wmiService = Get-Service -Name "winmgmt"
    if ($wmiService.Status -ne 'Running') {
        Write-Log "Starting WMI (winmgmt) service..."
        Set-Service -Name "winmgmt" -StartupType Automatic
        Start-Service -Name "winmgmt"
        Write-Log "WMI (winmgmt) service started."
    }
}

# Function to monitor all fixed and removable drives
function Monitor-AllDrives {
    $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.DriveType -eq 'Fixed' -or $_.DriveType -eq 'Removable' }
    foreach ($drive in $drives) {
        Monitor-Path -Path $drive.Root
    }
}

# Function to monitor mapped network shares
function Monitor-NetworkShares {
    $networkDrives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.DriveType -eq 'Network' }
    foreach ($drive in $networkDrives) {
        Monitor-Path -Path $drive.Root
    }
}

# Function to monitor file changes
function Monitor-Path {
    param ([string]$Path)

    $fileWatcher = New-Object System.IO.FileSystemWatcher
    $fileWatcher.Path = $Path
    $fileWatcher.IncludeSubdirectories = $true
    $fileWatcher.EnableRaisingEvents = $true

    Register-ObjectEvent $fileWatcher "Created" -Action {
        $filePath = $Event.SourceEventArgs.FullPath
        Write-Log "New file created: $filePath"
        if (-not (Check-FileCertificate -FilePath $filePath)) {
            Block-Execution -FilePath $filePath -Reason "Untrusted certificate"
        } else {
            $scanResults = Get-VirusTotalScan -FilePath $filePath
            if ($scanResults -and $scanResults.data.attributes.last_analysis_stats.malicious -gt 0) {
                Block-Execution -FilePath $filePath -Reason "File detected as malware on VirusTotal"
            }
        }
    } | Out-Null

    Register-ObjectEvent $fileWatcher "Changed" -Action {
        $filePath = $Event.SourceEventArgs.FullPath
        Write-Log "File modified: $filePath"
    } | Out-Null
}

# Function to check if the file has already been scanned and is clean
function Check-FileInVirusTotalCache {
    param (
        [string]$fileHash
    )

    if ($scannedFiles.ContainsKey($fileHash)) {
        Write-Log "File hash $fileHash found in cache (clean)."
        return $true
    } else {
        return $false
    }
}

# Function to send the file to VirusTotal if it's not in cache and check scan results
function Get-VirusTotalScan {
    param (
        [string]$FilePath
    )

    # Calculate the file hash
    $fileHash = Get-FileHash -Algorithm SHA256 -Path $FilePath

    if (Check-FileInVirusTotalCache -fileHash $fileHash.Hash) {
        return $null
    }

    # Query VirusTotal to see if the file was already uploaded and analyzed
    $url = "https://www.virustotal.com/api/v3/files/$($fileHash.Hash)"
    $headers = @{"x-apikey" = $VirusTotalApiKey}

    $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -ErrorAction SilentlyContinue

    if ($response -and $response.data.attributes.last_analysis_stats.malicious -eq 0) {
        Write-Log "File $FilePath is clean, already scanned."
        $scannedFiles[$fileHash.Hash] = $true
        return $response
    } elseif ($response) {
        return $response
    } else {
        Write-Log "VirusTotal did not return any results for $FilePath. It may not have been uploaded yet."
        return $null
    }
}

# Whitelist of critical processes (system-related)
$whitelistedProcesses = @(
    "explorer",    # File Explorer and Desktop
    "winlogon",    # Windows Logon Process
    "taskhostw",   # Task Host Window
    "csrss",       # Client/Server Runtime
    "services",    # Windows Services
    "lsass",       # Local Security Authority
    "dwm",         # Desktop Window Manager
    "svchost",     # Generic Host Process for Services
    "smss",        # Session Manager Subsystem
    "wininit",     # Windows Initialization Process
    "System",      # System Process
    "conhost",     # Console Window Host
    "cmd",         # Command Prompt
    "powershell"   # PowerShell itself
)

# Function to block execution of a file
function Block-Execution {
    param (
        [string]$FilePath,
        [string]$Reason
    )

    # Remove all permissions from the file
    $acl = Get-Acl -Path $FilePath
    $acl.SetAccessRuleProtection($true, $false) # Protect the ACL
    $acl.Access | ForEach-Object {
        $acl.RemoveAccessRule($_)
    }
    Set-Acl -Path $FilePath -AclObject $acl
    Write-Log "Blocked file ${FilePath}: ${Reason}"
}

# Function to check the file certificate
function Check-FileCertificate {
    param (
        [string]$FilePath
    )

    try {
        $signature = Get-AuthenticodeSignature -FilePath $FilePath
        switch ($signature.Status) {
            'Valid' {
                return $true
            }
            'NotSigned' {
                Write-Log "File $FilePath is not digitally signed."
                Block-Execution -FilePath $FilePath -Reason "Not signed"
                return $false
            }
            'UnknownError' {
                Write-Log "Unknown error while verifying signature of $FilePath."
                return $false
            }
            default {
                Write-Log "File $FilePath has an invalid or untrusted signature: $($signature.Status)"
                Block-Execution -FilePath $FilePath -Reason "Invalid signature"
                return $false
            }
        }
    } catch {
        Write-Log "Error checking certificate for ${FilePath}: $($_.Exception.Message)"
        return $false
    }
}

# Advanced keylogger detection: look for suspicious processes but skip whitelisted ones
function Monitor-Keyloggers {
    $suspiciousProcesses = Get-Process | Where-Object {
        ($_.ProcessName -match 'hook|log|key|capture|sniff') -or
        ($_.Description -like "*keyboard*") -and
        (-not $whitelistedProcesses -contains $_.ProcessName)
    }

    foreach ($process in $suspiciousProcesses) {
        Write-Log "Potential keylogger detected: $($process.ProcessName)"
        try {
            Stop-Process -Id $process.Id -Force
            Write-Log "Keylogger process terminated: $($process.ProcessName)"
        } catch {
            Write-Log "Failed to terminate process: $($process.ProcessName)"
        }
    }
}

# Function to monitor for suspicious screen overlays
function Monitor-Overlays {
    $windows = Get-Process | Where-Object {
        $_.MainWindowTitle -ne "" -and
        (-not $whitelistedProcesses -contains $_.ProcessName)
    }

    foreach ($window in $windows) {
        Write-Log "Potential screen overlay or UI hijacker detected: $($window.ProcessName)"
        try {
            Stop-Process -Id $window.Id -Force
            Write-Log "Overlay process terminated: $($window.ProcessName)"
        } catch {
            Write-Log "Failed to terminate process: $($window.ProcessName)"
        }
    }
}

# Main monitoring loop
function Start-AdvancedMonitoring {
    while ($true) {
        # Ensure WMI service is running
        Ensure-WMIService

        # Monitor all fixed, removable, and network drives
        Monitor-AllDrives
        Monitor-NetworkShares

        # Overlay detection
        Monitor-Overlays

        # Keylogger detection
        Monitor-Keyloggers

        Start-Sleep -Seconds $PollingInterval
    }
}

# Ensure elevation
Ensure-Elevation

Start-Job -ScriptBlock {
    Start-AdvancedMonitoring
}
