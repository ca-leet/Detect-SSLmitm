# SSL MITM Detection Script
# Requires PowerShell 5.1 or higher
# Run with administrator privileges for complete system access

# Import required modules
using namespace System.Security.Cryptography.X509Certificates
using namespace System.Net.Security

# Configuration
$script:LogPath = "$env:USERPROFILE\Documents\SSLMonitoring"
$script:LogFile = "SSL-MITM-Detection.log"
$script:ScriptPath = $MyInvocation.MyCommand.Path

# Create log directory if it doesn't exist
if (-not (Test-Path -Path $script:LogPath)) {
    New-Item -ItemType Directory -Path $script:LogPath | Out-Null
}

function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [ValidateSet('Info', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Add-Content -Path "$script:LogPath\$script:LogFile" -Value $logMessage
    
    switch ($Level) {
        'Info'    { Write-Host $logMessage -ForegroundColor White }
        'Warning' { Write-Host $logMessage -ForegroundColor Yellow }
        'Error'   { Write-Host $logMessage -ForegroundColor Red }
    }
}

# Known good certificate hashes - will be automatically updated
$script:GoldenHashes = @{
    "www.google.com"      = ""
    "mail.google.com"     = ""
    "www.whitehouse.gov"  = ""
    "www.costco.com"      = ""
    "www.facebook.com"    = ""
    "www.usbank.com"      = ""
    "www.twitter.com"     = ""
    "www.linkedin.com"    = ""
}

function Get-CertificateChain {
    param (
        [Parameter(Mandatory=$true)]
        [Uri]$Uri,
        [int]$TimeoutSeconds = 30
    )
    
    try {
        if (-not ($Uri.Scheme -eq "https")) {
            throw "Only HTTPS URLs are supported"
        }

        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        $request = [System.Net.HttpWebRequest]::Create($Uri)
        $request.Timeout = $TimeoutSeconds * 1000
        $request.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials

        try {
            $response = $request.GetResponse()
            $response.Dispose()
        }
        catch [System.Net.WebException] {
            if ($_.Exception.Status -ne [System.Net.WebExceptionStatus]::TrustFailure) {
                throw
            }
        }

        $servicePoint = $request.ServicePoint
        $chain = New-Object X509Chain
        
        $chain.ChainPolicy.RevocationFlag = [X509RevocationFlag]::EntireChain
        $chain.ChainPolicy.RevocationMode = [X509RevocationMode]::Online
        $chain.ChainPolicy.UrlRetrievalTimeout = New-TimeSpan -Seconds $TimeoutSeconds
        
        $success = $chain.Build($servicePoint.Certificate)
        
        if (-not $success) {
            $errors = $chain.ChainStatus | ForEach-Object { $_.StatusInformation }
            throw "Certificate chain building failed: $($errors -join ', ')"
        }

        return @{
            LeafCert = $chain.ChainElements[0].Certificate
            IntermediateCert = $chain.ChainElements[1].Certificate
            Chain = $chain
        }
    }
    catch {
        Write-Log -Message "Error getting certificate chain for $Uri : $_" -Level Error
        throw
    }
}

function Get-CertHash {
    param (
        [Parameter(Mandatory=$true)]
        [Uri]$Uri
    )
    
    try {
        $certInfo = Get-CertificateChain -Uri $Uri
        return $certInfo.IntermediateCert.GetCertHashString()
    }
    catch {
        Write-Log -Message "Failed to get certificate hash for $Uri : $_" -Level Error
        return $null
    }
}

function Update-ScriptContent {
    param (
        [string]$ScriptPath,
        [hashtable]$NewHashes
    )
    
    try {
        # Read the current script content
        $scriptContent = Get-Content -Path $ScriptPath -Raw
        
        # Create the new hashtable content
        $hashTableContent = @"
`$script:GoldenHashes = @{
$(($NewHashes.GetEnumerator() | ForEach-Object { "    `"$($_.Key)`"      = `"$($_.Value)`"" }) -join "`n")
}
"@
        
        # Replace the existing hashtable with the new one
        $pattern = '(?ms)\$script:GoldenHashes\s*=\s*@\{.*?\}'
        $newContent = $scriptContent -replace $pattern, $hashTableContent
        
        # Create a backup of the original script
        $backupPath = "$ScriptPath.backup"
        Copy-Item -Path $ScriptPath -Destination $backupPath -Force
        Write-Log -Message "Created script backup at $backupPath" -Level Info
        
        # Write the updated content back to the script
        $newContent | Set-Content -Path $ScriptPath -Force
        Write-Log -Message "Successfully updated script with new hashes" -Level Info
        
        return $true
    }
    catch {
        Write-Log -Message "Failed to update script content: $_" -Level Error
        return $false
    }
}

function Update-GoldenHashes {
    param (
        [string[]]$Uris = $script:GoldenHashes.Keys,
        [switch]$UpdateScript
    )
    
    Write-Log -Message "Starting golden hash update process" -Level Info
    $newHashes = @{}
    $successful = $true
    
    foreach ($uri in $Uris) {
        try {
            Write-Log -Message "Getting certificate hash for $uri" -Level Info
            $hash = Get-CertHash -Uri "https://$uri"
            
            if ($hash) {
                $newHashes[$uri] = $hash
                Write-Log -Message "Successfully updated hash for $uri" -Level Info
            }
            else {
                $successful = $false
                Write-Log -Message "Failed to get hash for $uri" -Level Error
            }
        }
        catch {
            $successful = $false
            Write-Log -Message "Failed to update hash for $uri : $_" -Level Error
        }
    }
    
    if ($UpdateScript -and $successful) {
        Write-Log -Message "Attempting to update script with new hashes..." -Level Info
        
        if (-not $script:ScriptPath) {
            Write-Log -Message "Cannot update script: Script path not found" -Level Error
            return $false
        }
        
        if (Update-ScriptContent -ScriptPath $script:ScriptPath -NewHashes $newHashes) {
            Write-Log -Message "Successfully updated script with new golden hashes" -Level Info
            return $true
        }
        else {
            Write-Log -Message "Failed to update script with new hashes" -Level Error
            return $false
        }
    }
    else {
        # Output the new hashes without updating the script
        Write-Log -Message "New golden hashes generated. Please review:" -Level Info
        $newHashes.GetEnumerator() | ForEach-Object {
            Write-Output "`"$($_.Key)`" = `"$($_.Value)`""
        }
        return $successful
    }
}

function Test-SSLMitm {
    param (
        [switch]$ContinuousMonitoring,
        [int]$MonitoringIntervalMinutes = 60,
        [switch]$AutoUpdateHashes
    )
    
    function Test-SingleRun {
        $detections = @()
        
        foreach ($uri in $script:GoldenHashes.Keys) {
            try {
                Write-Log -Message "Checking certificate for $uri" -Level Info
                $currentHash = Get-CertHash -Uri "https://$uri"
                
                if (-not $currentHash) {
                    Write-Log -Message "Unable to get current certificate hash for $uri" -Level Warning
                    continue
                }
                
                if ($currentHash -eq $script:GoldenHashes[$uri]) {
                    Write-Log -Message "Certificate hash match for $uri" -Level Info
                }
                else {
                    # If AutoUpdateHashes is enabled, verify if this is a legitimate update
                    if ($AutoUpdateHashes) {
                        $certInfo = Get-CertificateChain -Uri "https://$uri"
                        $certExpirationDate = $certInfo.IntermediateCert.NotAfter
                        
                        # If the certificate is relatively new (less than 7 days old), consider updating
                        if ((Get-Date) - $certInfo.IntermediateCert.NotBefore -lt (New-TimeSpan -Days 7)) {
                            Write-Log -Message "Detected new certificate for $uri, updating golden hash" -Level Warning
                            Update-GoldenHashes -Uris @($uri) -UpdateScript
                            continue
                        }
                    }
                    
                    $message = "POTENTIAL MITM DETECTED: Certificate hash mismatch for $uri"
                    Write-Log -Message $message -Level Error
                    $detections += @{
                        Uri = $uri
                        ExpectedHash = $script:GoldenHashes[$uri]
                        CurrentHash = $currentHash
                        Timestamp = Get-Date
                    }
                }
            }
            catch {
                Write-Log -Message "Error checking certificate for $uri : $_" -Level Error
            }
        }
        
        return $detections
    }
    
    if ($ContinuousMonitoring) {
        Write-Log -Message "Starting continuous monitoring with $MonitoringIntervalMinutes minute interval" -Level Info
        
        while ($true) {
            $detections = Test-SingleRun
            
            if ($detections.Count -gt 0) {
                Write-Log -Message "Found $($detections.Count) potential MITM situations" -Level Warning
            }
            
            Start-Sleep -Seconds ($MonitoringIntervalMinutes * 60)
        }
    }
    else {
        return Test-SingleRun
    }
}

# Example usage:
# Update golden hashes and modify the script:
# Update-GoldenHashes -UpdateScript

# Run a single MITM detection check with auto-updating of hashes:
# Test-SSLMitm -AutoUpdateHashes

# Start continuous monitoring with auto-updating:
# Test-SSLMitm -ContinuousMonitoring -MonitoringIntervalMinutes 30 -AutoUpdateHashes
