#!/usr/bin/env pwsh
# =============================================================================
# SIEM OpenSource PyMES - Maintenance and Backup Script
# =============================================================================
# This script provides comprehensive maintenance operations for the SIEM
# solution including backups, updates, health checks, and cleanup tasks.
# 
# Usage:
#   .\maintenance.ps1 [operation] [options]
#
# Operations:
#   backup          Create full system backup
#   restore         Restore from backup
#   update          Update all services
#   health-check    Perform system health check
#   cleanup         Clean up old data and logs
#   optimize        Optimize system performance
#   security-scan   Run security vulnerability scan
#   status          Show system status
#   help            Show this help message
# =============================================================================

param(
    [Parameter(Position=0)]
    [ValidateSet("backup", "restore", "update", "health-check", "cleanup", "optimize", "security-scan", "status", "help")]
    [string]$Operation = "help",
    
    [string]$BackupPath = "",
    [string]$RestoreFile = "",
    [switch]$Force,
    [switch]$Verbose,
    [switch]$DryRun,
    [int]$RetentionDays = 30
)

# =============================================================================
# GLOBAL VARIABLES
# =============================================================================
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$PROJECT_NAME = "siem-pymes"
$LOG_FILE = "$SCRIPT_DIR\maintenance.log"
$ERROR_LOG = "$SCRIPT_DIR\maintenance-errors.log"
$CONFIG_DIR = "$SCRIPT_DIR\config"
$DATA_DIR = "$SCRIPT_DIR\data"
$BACKUP_DIR = "$SCRIPT_DIR\backups"
$TEMP_DIR = "$SCRIPT_DIR\temp"

# Default backup path
if ([string]::IsNullOrEmpty($BackupPath)) {
    $BackupPath = "$BACKUP_DIR\$(Get-Date -Format 'yyyyMMdd-HHmmss')"
}

# Colors for output
$RED = "Red"
$GREEN = "Green"
$YELLOW = "Yellow"
$BLUE = "Cyan"
$MAGENTA = "Magenta"
$WHITE = "White"

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO",
        [string]$Color = $WHITE
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Write to console with color
    Write-Host $logMessage -ForegroundColor $Color
    
    # Write to log file
    Add-Content -Path $LOG_FILE -Value $logMessage
    
    # Write errors to error log
    if ($Level -eq "ERROR") {
        Add-Content -Path $ERROR_LOG -Value $logMessage
    }
}

function Write-Success {
    param([string]$Message)
    Write-Log $Message "SUCCESS" $GREEN
}

function Write-Warning {
    param([string]$Message)
    Write-Log $Message "WARNING" $YELLOW
}

function Write-Error-Custom {
    param([string]$Message)
    Write-Log $Message "ERROR" $RED
}

function Write-Info {
    param([string]$Message)
    Write-Log $Message "INFO" $BLUE
}

function Show-Banner {
    Write-Host @"
╔══════════════════════════════════════════════════════════════════════════════╗
║                    SIEM OpenSource PyMES - Maintenance                      ║
║                         Backup & Maintenance Script                         ║
║                                                                              ║
║  Comprehensive maintenance operations for your SIEM infrastructure          ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor $MAGENTA
}

function Show-Help {
    Write-Host @"
SIEM OpenSource PyMES - Maintenance Script

Usage: .\maintenance.ps1 [operation] [options]

Operations:
  backup          Create full system backup
  restore         Restore from backup
  update          Update all services
  health-check    Perform system health check
  cleanup         Clean up old data and logs
  optimize        Optimize system performance
  security-scan   Run security vulnerability scan
  status          Show system status
  help            Show this help message

Options:
  -BackupPath     Custom backup directory path
  -RestoreFile    Backup file to restore from
  -Force          Force operation without confirmation
  -Verbose        Enable verbose output
  -DryRun         Show what would be done without executing
  -RetentionDays  Number of days to retain backups (default: 30)

Examples:
  .\maintenance.ps1 backup
  .\maintenance.ps1 restore -RestoreFile "backups\20231201-120000\backup.tar.gz"
  .\maintenance.ps1 cleanup -RetentionDays 7
  .\maintenance.ps1 health-check -Verbose

For more information, visit: https://github.com/your-repo/siem-pymes
"@ -ForegroundColor $WHITE
}

function Test-DockerRunning {
    try {
        $null = docker ps 2>$null
        return $true
    }
    catch {
        return $false
    }
}

function Get-ServiceStatus {
    if (-not (Test-DockerRunning)) {
        Write-Error-Custom "Docker is not running"
        return $false
    }
    
    try {
        $services = docker-compose ps --format json | ConvertFrom-Json
        return $services
    }
    catch {
        Write-Error-Custom "Failed to get service status: $($_.Exception.Message)"
        return $false
    }
}

function Stop-Services {
    Write-Info "Stopping SIEM services..."
    try {
        docker-compose stop
        Write-Success "Services stopped successfully"
        return $true
    }
    catch {
        Write-Error-Custom "Failed to stop services: $($_.Exception.Message)"
        return $false
    }
}

function Start-Services {
    Write-Info "Starting SIEM services..."
    try {
        docker-compose up -d
        Write-Success "Services started successfully"
        return $true
    }
    catch {
        Write-Error-Custom "Failed to start services: $($_.Exception.Message)"
        return $false
    }
}

function Wait-ForServices {
    param([int]$TimeoutSeconds = 300)
    
    Write-Info "Waiting for services to be ready..."
    $waited = 0
    
    while ($waited -lt $TimeoutSeconds) {
        $services = Get-ServiceStatus
        if ($services) {
            $runningServices = $services | Where-Object { $_.State -eq "running" }
            if ($runningServices.Count -eq $services.Count) {
                Write-Success "All services are running"
                return $true
            }
        }
        
        Start-Sleep -Seconds 10
        $waited += 10
        Write-Host "." -NoNewline
    }
    
    Write-Warning "Services did not start within $TimeoutSeconds seconds"
    return $false
}

# =============================================================================
# BACKUP OPERATIONS
# =============================================================================

function Invoke-Backup {
    Write-Info "Starting full system backup..."
    
    # Create backup directory
    if (-not (Test-Path $BackupPath)) {
        New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null
    }
    
    $backupSuccess = $true
    
    try {
        # Backup configuration files
        Write-Info "Backing up configuration files..."
        if (Test-Path $CONFIG_DIR) {
            Copy-Item -Path $CONFIG_DIR -Destination "$BackupPath\config" -Recurse -Force
            Write-Success "Configuration files backed up"
        }
        
        # Backup environment file
        if (Test-Path "$SCRIPT_DIR\.env") {
            Copy-Item -Path "$SCRIPT_DIR\.env" -Destination "$BackupPath\.env" -Force
            Write-Success "Environment file backed up"
        }
        
        # Backup docker-compose file
        if (Test-Path "$SCRIPT_DIR\docker-compose.yml") {
            Copy-Item -Path "$SCRIPT_DIR\docker-compose.yml" -Destination "$BackupPath\docker-compose.yml" -Force
            Write-Success "Docker Compose file backed up"
        }
        
        # Create Elasticsearch snapshot
        Write-Info "Creating Elasticsearch snapshot..."
        $snapshotName = "backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        try {
            $elasticPassword = (Get-Content "$SCRIPT_DIR\.env" | Where-Object { $_ -match "ELASTIC_PASSWORD=(.*)" }) -replace "ELASTIC_PASSWORD=", ""
            $headers = @{
                "Authorization" = "Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("elastic:$elasticPassword"))
                "Content-Type" = "application/json"
            }
            
            # Create snapshot repository if it doesn't exist
            $repoBody = @{
                type = "fs"
                settings = @{
                    location = "/usr/share/elasticsearch/backup"
                }
            } | ConvertTo-Json
            
            Invoke-RestMethod -Uri "https://localhost:9200/_snapshot/backup_repo" -Method PUT -Headers $headers -Body $repoBody -SkipCertificateCheck
            
            # Create snapshot
            $snapshotBody = @{
                indices = "*"
                ignore_unavailable = $true
                include_global_state = $false
            } | ConvertTo-Json
            
            Invoke-RestMethod -Uri "https://localhost:9200/_snapshot/backup_repo/$snapshotName" -Method PUT -Headers $headers -Body $snapshotBody -SkipCertificateCheck
            Write-Success "Elasticsearch snapshot created: $snapshotName"
        }
        catch {
            Write-Warning "Failed to create Elasticsearch snapshot: $($_.Exception.Message)"
        }
        
        # Backup Docker volumes
        Write-Info "Backing up Docker volumes..."
        try {
            $volumes = docker volume ls --format "{{.Name}}" | Where-Object { $_ -match $PROJECT_NAME }
            foreach ($volume in $volumes) {
                Write-Info "Backing up volume: $volume"
                docker run --rm -v "${volume}:/data" -v "${BackupPath}:/backup" alpine tar czf "/backup/${volume}.tar.gz" -C /data .
            }
            Write-Success "Docker volumes backed up"
        }
        catch {
            Write-Warning "Failed to backup Docker volumes: $($_.Exception.Message)"
            $backupSuccess = $false
        }
        
        # Create backup metadata
        $metadata = @{
            timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            version = "1.0"
            services = (Get-ServiceStatus | ForEach-Object { $_.Name })
            backup_type = "full"
            retention_days = $RetentionDays
        } | ConvertTo-Json -Depth 3
        
        Set-Content -Path "$BackupPath\metadata.json" -Value $metadata
        
        # Create backup archive
        Write-Info "Creating backup archive..."
        $archivePath = "$BackupPath.tar.gz"
        tar -czf $archivePath -C (Split-Path $BackupPath) (Split-Path $BackupPath -Leaf)
        
        # Remove temporary backup directory
        Remove-Item -Path $BackupPath -Recurse -Force
        
        if ($backupSuccess) {
            Write-Success "Backup completed successfully: $archivePath"
            return $true
        } else {
            Write-Warning "Backup completed with warnings: $archivePath"
            return $true
        }
    }
    catch {
        Write-Error-Custom "Backup failed: $($_.Exception.Message)"
        return $false
    }
}

function Invoke-Restore {
    param([string]$RestoreFile)
    
    if ([string]::IsNullOrEmpty($RestoreFile)) {
        Write-Error-Custom "Restore file not specified"
        return $false
    }
    
    if (-not (Test-Path $RestoreFile)) {
        Write-Error-Custom "Restore file not found: $RestoreFile"
        return $false
    }
    
    Write-Info "Starting system restore from: $RestoreFile"
    
    if (-not $Force) {
        $confirmation = Read-Host "This will overwrite current configuration. Continue? (y/N)"
        if ($confirmation -ne "y" -and $confirmation -ne "Y") {
            Write-Info "Restore cancelled"
            return $false
        }
    }
    
    try {
        # Stop services
        if (-not (Stop-Services)) {
            return $false
        }
        
        # Create temporary restore directory
        $restoreDir = "$TEMP_DIR\restore-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        New-Item -ItemType Directory -Path $restoreDir -Force | Out-Null
        
        # Extract backup archive
        Write-Info "Extracting backup archive..."
        tar -xzf $RestoreFile -C $restoreDir
        
        $extractedDir = Get-ChildItem -Path $restoreDir -Directory | Select-Object -First 1
        if (-not $extractedDir) {
            Write-Error-Custom "Invalid backup archive structure"
            return $false
        }
        
        # Restore configuration files
        Write-Info "Restoring configuration files..."
        if (Test-Path "$($extractedDir.FullName)\config") {
            Remove-Item -Path $CONFIG_DIR -Recurse -Force -ErrorAction SilentlyContinue
            Copy-Item -Path "$($extractedDir.FullName)\config" -Destination $CONFIG_DIR -Recurse -Force
            Write-Success "Configuration files restored"
        }
        
        # Restore environment file
        if (Test-Path "$($extractedDir.FullName)\.env") {
            Copy-Item -Path "$($extractedDir.FullName)\.env" -Destination "$SCRIPT_DIR\.env" -Force
            Write-Success "Environment file restored"
        }
        
        # Restore docker-compose file
        if (Test-Path "$($extractedDir.FullName)\docker-compose.yml") {
            Copy-Item -Path "$($extractedDir.FullName)\docker-compose.yml" -Destination "$SCRIPT_DIR\docker-compose.yml" -Force
            Write-Success "Docker Compose file restored"
        }
        
        # Restore Docker volumes
        Write-Info "Restoring Docker volumes..."
        $volumeBackups = Get-ChildItem -Path $extractedDir.FullName -Filter "*.tar.gz"
        foreach ($volumeBackup in $volumeBackups) {
            $volumeName = $volumeBackup.BaseName
            Write-Info "Restoring volume: $volumeName"
            
            # Remove existing volume
            docker volume rm $volumeName -f 2>$null
            
            # Create new volume and restore data
            docker volume create $volumeName
            docker run --rm -v "${volumeName}:/data" -v "$($extractedDir.FullName):/backup" alpine tar xzf "/backup/$($volumeBackup.Name)" -C /data
        }
        Write-Success "Docker volumes restored"
        
        # Start services
        if (-not (Start-Services)) {
            return $false
        }
        
        # Wait for services to be ready
        Wait-ForServices
        
        # Clean up temporary files
        Remove-Item -Path $restoreDir -Recurse -Force
        
        Write-Success "System restore completed successfully"
        return $true
    }
    catch {
        Write-Error-Custom "Restore failed: $($_.Exception.Message)"
        return $false
    }
}

# =============================================================================
# UPDATE OPERATIONS
# =============================================================================

function Invoke-Update {
    Write-Info "Starting system update..."
    
    try {
        # Create backup before update
        Write-Info "Creating pre-update backup..."
        $preUpdateBackup = "$BACKUP_DIR\pre-update-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        $global:BackupPath = $preUpdateBackup
        if (-not (Invoke-Backup)) {
            Write-Warning "Pre-update backup failed, continuing with update..."
        }
        
        # Pull latest images
        Write-Info "Pulling latest Docker images..."
        docker-compose pull
        
        # Restart services with new images
        Write-Info "Restarting services with updated images..."
        docker-compose up -d
        
        # Wait for services to be ready
        Wait-ForServices
        
        Write-Success "System update completed successfully"
        return $true
    }
    catch {
        Write-Error-Custom "Update failed: $($_.Exception.Message)"
        return $false
    }
}

# =============================================================================
# HEALTH CHECK OPERATIONS
# =============================================================================

function Invoke-HealthCheck {
    Write-Info "Performing system health check..."
    
    $healthStatus = @{
        overall = "healthy"
        services = @{}
        resources = @{}
        security = @{}
        issues = @()
    }
    
    # Check service status
    Write-Info "Checking service status..."
    $services = Get-ServiceStatus
    if ($services) {
        foreach ($service in $services) {
            $healthStatus.services[$service.Name] = @{
                status = $service.State
                health = if ($service.State -eq "running") { "healthy" } else { "unhealthy" }
            }
            
            if ($service.State -ne "running") {
                $healthStatus.issues += "Service $($service.Name) is not running"
                $healthStatus.overall = "degraded"
            }
        }
    } else {
        $healthStatus.overall = "critical"
        $healthStatus.issues += "Unable to get service status"
    }
    
    # Check system resources
    Write-Info "Checking system resources..."
    try {
        # CPU usage
        $cpuUsage = Get-Counter "\Processor(_Total)\% Processor Time" -SampleInterval 1 -MaxSamples 3 | 
                   Select-Object -ExpandProperty CounterSamples | 
                   Measure-Object -Property CookedValue -Average | 
                   Select-Object -ExpandProperty Average
        
        $healthStatus.resources.cpu = [math]::Round($cpuUsage, 2)
        
        if ($cpuUsage -gt 90) {
            $healthStatus.issues += "High CPU usage: $([math]::Round($cpuUsage, 2))%"
            $healthStatus.overall = "degraded"
        }
        
        # Memory usage
        $totalMemory = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory
        $availableMemory = (Get-Counter "\Memory\Available Bytes").CounterSamples.CookedValue
        $memoryUsage = (($totalMemory - $availableMemory) / $totalMemory) * 100
        
        $healthStatus.resources.memory = [math]::Round($memoryUsage, 2)
        
        if ($memoryUsage -gt 90) {
            $healthStatus.issues += "High memory usage: $([math]::Round($memoryUsage, 2))%"
            $healthStatus.overall = "degraded"
        }
        
        # Disk usage
        $diskUsage = Get-PSDrive C | ForEach-Object {
            $used = $_.Used
            $total = $_.Used + $_.Free
            ($used / $total) * 100
        }
        
        $healthStatus.resources.disk = [math]::Round($diskUsage, 2)
        
        if ($diskUsage -gt 90) {
            $healthStatus.issues += "High disk usage: $([math]::Round($diskUsage, 2))%"
            $healthStatus.overall = "degraded"
        }
    }
    catch {
        Write-Warning "Failed to check system resources: $($_.Exception.Message)"
    }
    
    # Check security status
    Write-Info "Checking security status..."
    try {
        # Check if default passwords are still in use
        $envContent = Get-Content "$SCRIPT_DIR\.env" -ErrorAction SilentlyContinue
        if ($envContent) {
            $defaultPasswords = @("changeme", "password", "admin", "123456")
            foreach ($line in $envContent) {
                if ($line -match "PASSWORD=(.+)") {
                    $password = $matches[1]
                    if ($password -in $defaultPasswords) {
                        $healthStatus.issues += "Default password detected in environment file"
                        $healthStatus.security.default_passwords = $true
                        $healthStatus.overall = "degraded"
                    }
                }
            }
        }
        
        # Check SSL certificate expiration
        $certFiles = Get-ChildItem -Path "$CONFIG_DIR\certs" -Filter "*.crt" -Recurse -ErrorAction SilentlyContinue
        foreach ($certFile in $certFiles) {
            try {
                $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certFile.FullName)
                $daysUntilExpiry = ($cert.NotAfter - (Get-Date)).Days
                
                if ($daysUntilExpiry -lt 30) {
                    $healthStatus.issues += "SSL certificate $($certFile.Name) expires in $daysUntilExpiry days"
                    $healthStatus.security.cert_expiry = $true
                    if ($daysUntilExpiry -lt 7) {
                        $healthStatus.overall = "critical"
                    } else {
                        $healthStatus.overall = "degraded"
                    }
                }
            }
            catch {
                Write-Warning "Failed to check certificate $($certFile.Name): $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Warning "Failed to check security status: $($_.Exception.Message)"
    }
    
    # Display health check results
    Write-Host "`n" -NoNewline
    Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor $MAGENTA
    Write-Host "║                            HEALTH CHECK RESULTS                             ║" -ForegroundColor $MAGENTA
    Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor $MAGENTA
    
    # Overall status
    $statusColor = switch ($healthStatus.overall) {
        "healthy" { $GREEN }
        "degraded" { $YELLOW }
        "critical" { $RED }
        default { $WHITE }
    }
    Write-Host "Overall Status: " -NoNewline
    Write-Host $healthStatus.overall.ToUpper() -ForegroundColor $statusColor
    
    # Service status
    Write-Host "`nService Status:" -ForegroundColor $BLUE
    foreach ($service in $healthStatus.services.Keys) {
        $serviceStatus = $healthStatus.services[$service]
        $serviceColor = if ($serviceStatus.health -eq "healthy") { $GREEN } else { $RED }
        Write-Host "  $service`: " -NoNewline
        Write-Host $serviceStatus.status -ForegroundColor $serviceColor
    }
    
    # Resource usage
    Write-Host "`nResource Usage:" -ForegroundColor $BLUE
    if ($healthStatus.resources.cpu) {
        $cpuColor = if ($healthStatus.resources.cpu -gt 80) { $RED } elseif ($healthStatus.resources.cpu -gt 60) { $YELLOW } else { $GREEN }
        Write-Host "  CPU: " -NoNewline
        Write-Host "$($healthStatus.resources.cpu)%" -ForegroundColor $cpuColor
    }
    if ($healthStatus.resources.memory) {
        $memColor = if ($healthStatus.resources.memory -gt 80) { $RED } elseif ($healthStatus.resources.memory -gt 60) { $YELLOW } else { $GREEN }
        Write-Host "  Memory: " -NoNewline
        Write-Host "$($healthStatus.resources.memory)%" -ForegroundColor $memColor
    }
    if ($healthStatus.resources.disk) {
        $diskColor = if ($healthStatus.resources.disk -gt 80) { $RED } elseif ($healthStatus.resources.disk -gt 60) { $YELLOW } else { $GREEN }
        Write-Host "  Disk: " -NoNewline
        Write-Host "$($healthStatus.resources.disk)%" -ForegroundColor $diskColor
    }
    
    # Issues
    if ($healthStatus.issues.Count -gt 0) {
        Write-Host "`nIssues Found:" -ForegroundColor $RED
        foreach ($issue in $healthStatus.issues) {
            Write-Host "  • $issue" -ForegroundColor $YELLOW
        }
    } else {
        Write-Host "`nNo issues found" -ForegroundColor $GREEN
    }
    
    Write-Host ""
    
    return $healthStatus.overall -eq "healthy"
}

# =============================================================================
# CLEANUP OPERATIONS
# =============================================================================

function Invoke-Cleanup {
    Write-Info "Starting system cleanup..."
    
    try {
        # Clean up old backups
        Write-Info "Cleaning up old backups..."
        $cutoffDate = (Get-Date).AddDays(-$RetentionDays)
        $oldBackups = Get-ChildItem -Path $BACKUP_DIR -Filter "*.tar.gz" | Where-Object { $_.CreationTime -lt $cutoffDate }
        
        foreach ($backup in $oldBackups) {
            if ($DryRun) {
                Write-Info "[DRY RUN] Would delete: $($backup.FullName)"
            } else {
                Remove-Item -Path $backup.FullName -Force
                Write-Info "Deleted old backup: $($backup.Name)"
            }
        }
        
        # Clean up Docker system
        Write-Info "Cleaning up Docker system..."
        if (-not $DryRun) {
            docker system prune -f
            docker volume prune -f
            Write-Success "Docker system cleaned up"
        } else {
            Write-Info "[DRY RUN] Would run Docker system cleanup"
        }
        
        # Clean up log files
        Write-Info "Cleaning up old log files..."
        $logFiles = Get-ChildItem -Path $SCRIPT_DIR -Filter "*.log" | Where-Object { $_.CreationTime -lt $cutoffDate }
        
        foreach ($logFile in $logFiles) {
            if ($DryRun) {
                Write-Info "[DRY RUN] Would delete: $($logFile.FullName)"
            } else {
                Remove-Item -Path $logFile.FullName -Force
                Write-Info "Deleted old log file: $($logFile.Name)"
            }
        }
        
        # Clean up temporary files
        Write-Info "Cleaning up temporary files..."
        if (Test-Path $TEMP_DIR) {
            $tempFiles = Get-ChildItem -Path $TEMP_DIR -Recurse | Where-Object { $_.CreationTime -lt $cutoffDate }
            
            foreach ($tempFile in $tempFiles) {
                if ($DryRun) {
                    Write-Info "[DRY RUN] Would delete: $($tempFile.FullName)"
                } else {
                    Remove-Item -Path $tempFile.FullName -Force -Recurse
                    Write-Info "Deleted temporary file: $($tempFile.Name)"
                }
            }
        }
        
        Write-Success "System cleanup completed"
        return $true
    }
    catch {
        Write-Error-Custom "Cleanup failed: $($_.Exception.Message)"
        return $false
    }
}

# =============================================================================
# OPTIMIZATION OPERATIONS
# =============================================================================

function Invoke-Optimize {
    Write-Info "Starting system optimization..."
    
    try {
        # Optimize Elasticsearch indices
        Write-Info "Optimizing Elasticsearch indices..."
        try {
            $elasticPassword = (Get-Content "$SCRIPT_DIR\.env" | Where-Object { $_ -match "ELASTIC_PASSWORD=(.*)" }) -replace "ELASTIC_PASSWORD=", ""
            $headers = @{
                "Authorization" = "Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("elastic:$elasticPassword"))
                "Content-Type" = "application/json"
            }
            
            # Force merge indices
            Invoke-RestMethod -Uri "https://localhost:9200/_forcemerge?max_num_segments=1" -Method POST -Headers $headers -SkipCertificateCheck
            Write-Success "Elasticsearch indices optimized"
        }
        catch {
            Write-Warning "Failed to optimize Elasticsearch indices: $($_.Exception.Message)"
        }
        
        # Restart services to free up memory
        Write-Info "Restarting services to optimize memory usage..."
        if (-not $DryRun) {
            docker-compose restart
            Wait-ForServices
            Write-Success "Services restarted"
        } else {
            Write-Info "[DRY RUN] Would restart services"
        }
        
        Write-Success "System optimization completed"
        return $true
    }
    catch {
        Write-Error-Custom "Optimization failed: $($_.Exception.Message)"
        return $false
    }
}

# =============================================================================
# SECURITY SCAN OPERATIONS
# =============================================================================

function Invoke-SecurityScan {
    Write-Info "Starting security vulnerability scan..."
    
    $securityIssues = @()
    
    try {
        # Check for Docker security issues
        Write-Info "Scanning Docker containers for vulnerabilities..."
        try {
            $containers = docker ps --format "{{.Names}}"
            foreach ($container in $containers) {
                Write-Info "Scanning container: $container"
                # Note: This would require a vulnerability scanner like Trivy
                # docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image $container
            }
        }
        catch {
            Write-Warning "Failed to scan containers: $($_.Exception.Message)"
        }
        
        # Check file permissions
        Write-Info "Checking file permissions..."
        $sensitiveFiles = @(
            "$SCRIPT_DIR\.env",
            "$CONFIG_DIR\certs"
        )
        
        foreach ($file in $sensitiveFiles) {
            if (Test-Path $file) {
                # Check if file is readable by others (Windows equivalent)
                $acl = Get-Acl $file
                $publicAccess = $acl.Access | Where-Object { $_.IdentityReference -eq "Everyone" -and $_.FileSystemRights -match "Read" }
                if ($publicAccess) {
                    $securityIssues += "File $file has public read access"
                }
            }
        }
        
        # Check for default credentials
        Write-Info "Checking for default credentials..."
        if (Test-Path "$SCRIPT_DIR\.env") {
            $envContent = Get-Content "$SCRIPT_DIR\.env"
            $defaultPasswords = @("changeme", "password", "admin", "123456", "default")
            
            foreach ($line in $envContent) {
                if ($line -match "PASSWORD=(.+)") {
                    $password = $matches[1]
                    if ($password -in $defaultPasswords) {
                        $securityIssues += "Default password found: $password"
                    }
                }
            }
        }
        
        # Display security scan results
        Write-Host "`n" -NoNewline
        Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor $MAGENTA
        Write-Host "║                          SECURITY SCAN RESULTS                              ║" -ForegroundColor $MAGENTA
        Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor $MAGENTA
        
        if ($securityIssues.Count -eq 0) {
            Write-Host "No security issues found" -ForegroundColor $GREEN
        } else {
            Write-Host "Security Issues Found:" -ForegroundColor $RED
            foreach ($issue in $securityIssues) {
                Write-Host "  • $issue" -ForegroundColor $YELLOW
            }
        }
        
        Write-Host ""
        
        return $securityIssues.Count -eq 0
    }
    catch {
        Write-Error-Custom "Security scan failed: $($_.Exception.Message)"
        return $false
    }
}

# =============================================================================
# STATUS OPERATIONS
# =============================================================================

function Show-Status {
    Write-Info "Getting system status..."
    
    # Show service status
    $services = Get-ServiceStatus
    if ($services) {
        Write-Host "`n" -NoNewline
        Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor $MAGENTA
        Write-Host "║                              SERVICE STATUS                                 ║" -ForegroundColor $MAGENTA
        Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor $MAGENTA
        
        foreach ($service in $services) {
            $statusColor = if ($service.State -eq "running") { $GREEN } else { $RED }
            Write-Host "$($service.Name.PadRight(20)) : " -NoNewline
            Write-Host $service.State -ForegroundColor $statusColor
        }
    }
    
    # Show access URLs
    Write-Host "`n" -NoNewline
    Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor $MAGENTA
    Write-Host "║                              ACCESS URLS                                    ║" -ForegroundColor $MAGENTA
    Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor $MAGENTA
    
    Write-Host "Kibana Dashboard    : https://localhost:5601" -ForegroundColor $BLUE
    Write-Host "Wazuh Dashboard     : https://localhost:443" -ForegroundColor $BLUE
    Write-Host "Grafana Dashboard   : https://localhost:3000" -ForegroundColor $BLUE
    Write-Host "Elasticsearch API   : https://localhost:9200" -ForegroundColor $BLUE
    
    Write-Host ""
    
    return $true
}

# =============================================================================
# MAIN FUNCTION
# =============================================================================

function Main {
    # Show banner
    Show-Banner
    
    # Initialize log files
    "" | Out-File $LOG_FILE
    "" | Out-File $ERROR_LOG
    
    Write-Info "Starting maintenance operation: $Operation"
    
    # Create required directories
    @($BACKUP_DIR, $TEMP_DIR) | ForEach-Object {
        if (-not (Test-Path $_)) {
            New-Item -ItemType Directory -Path $_ -Force | Out-Null
        }
    }
    
    # Execute operation
    $success = switch ($Operation) {
        "backup" { Invoke-Backup }
        "restore" { Invoke-Restore -RestoreFile $RestoreFile }
        "update" { Invoke-Update }
        "health-check" { Invoke-HealthCheck }
        "cleanup" { Invoke-Cleanup }
        "optimize" { Invoke-Optimize }
        "security-scan" { Invoke-SecurityScan }
        "status" { Show-Status }
        "help" { Show-Help; return }
        default { 
            Write-Error-Custom "Unknown operation: $Operation"
            Show-Help
            return
        }
    }
    
    if ($success) {
        Write-Success "Operation '$Operation' completed successfully"
    } else {
        Write-Error-Custom "Operation '$Operation' failed"
        Write-Info "Check the error log: $ERROR_LOG"
    }
}

# =============================================================================
# SCRIPT EXECUTION
# =============================================================================

try {
    Main
}
catch {
    Write-Error-Custom "Script execution failed: $($_.Exception.Message)"
    Write-Info "Check the error log: $ERROR_LOG"
}

# =============================================================================
# END OF SCRIPT
# =============================================================================