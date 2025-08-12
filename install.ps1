#!/usr/bin/env pwsh
# =============================================================================
# SIEM OpenSource PyMES - Installation Script for Windows
# =============================================================================
# This script automates the installation and setup of the SIEM solution
# including all prerequisites, configuration, and initial deployment.
# 
# Usage:
#   .\install.ps1 [options]
#
# Options:
#   -Quick          Quick installation with default settings
#   -Production     Production installation with enhanced security
#   -Development    Development installation with debug features
#   -SkipDocker     Skip Docker installation check
#   -SkipSSL        Skip SSL certificate generation
#   -Help           Show this help message
# =============================================================================

param(
    [switch]$Quick,
    [switch]$Production,
    [switch]$Development,
    [switch]$SkipDocker,
    [switch]$SkipSSL,
    [switch]$Help
)

# =============================================================================
# GLOBAL VARIABLES
# =============================================================================
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$PROJECT_NAME = "siem-pymes"
$LOG_FILE = "$SCRIPT_DIR\install.log"
$ERROR_LOG = "$SCRIPT_DIR\install-errors.log"
$CONFIG_DIR = "$SCRIPT_DIR\config"
$DATA_DIR = "$SCRIPT_DIR\data"
$CERTS_DIR = "$SCRIPT_DIR\config\certs"
$BACKUP_DIR = "$SCRIPT_DIR\backups"

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
║                        SIEM OpenSource PyMES                                ║
║                     Installation Script v1.0                               ║
║                                                                              ║
║  Complete SIEM solution with Wazuh, Elastic Stack, Suricata & Monitoring    ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor $MAGENTA
}

function Show-Help {
    Write-Host @"
SIEM OpenSource PyMES - Installation Script

Usage: .\install.ps1 [options]

Options:
  -Quick          Quick installation with default settings
  -Production     Production installation with enhanced security
  -Development    Development installation with debug features
  -SkipDocker     Skip Docker installation check
  -SkipSSL        Skip SSL certificate generation
  -Help           Show this help message

Examples:
  .\install.ps1 -Quick
  .\install.ps1 -Production
  .\install.ps1 -Development -SkipDocker

For more information, visit: https://github.com/your-repo/siem-pymes
"@ -ForegroundColor $WHITE
}

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-Command {
    param([string]$Command)
    try {
        Get-Command $Command -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

function Install-Chocolatey {
    Write-Info "Installing Chocolatey package manager..."
    try {
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        Write-Success "Chocolatey installed successfully"
        return $true
    }
    catch {
        Write-Error-Custom "Failed to install Chocolatey: $($_.Exception.Message)"
        return $false
    }
}

function Install-Docker {
    Write-Info "Checking Docker installation..."
    
    if (Test-Command "docker") {
        $dockerVersion = docker --version
        Write-Success "Docker is already installed: $dockerVersion"
        return $true
    }
    
    Write-Info "Installing Docker Desktop..."
    try {
        if (-not (Test-Command "choco")) {
            if (-not (Install-Chocolatey)) {
                return $false
            }
        }
        
        choco install docker-desktop -y
        Write-Success "Docker Desktop installed successfully"
        Write-Warning "Please restart your computer and run the script again to continue"
        return $false
    }
    catch {
        Write-Error-Custom "Failed to install Docker: $($_.Exception.Message)"
        return $false
    }
}

function Install-DockerCompose {
    Write-Info "Checking Docker Compose installation..."
    
    if (Test-Command "docker-compose") {
        $composeVersion = docker-compose --version
        Write-Success "Docker Compose is already installed: $composeVersion"
        return $true
    }
    
    Write-Info "Installing Docker Compose..."
    try {
        if (-not (Test-Command "choco")) {
            if (-not (Install-Chocolatey)) {
                return $false
            }
        }
        
        choco install docker-compose -y
        Write-Success "Docker Compose installed successfully"
        return $true
    }
    catch {
        Write-Error-Custom "Failed to install Docker Compose: $($_.Exception.Message)"
        return $false
    }
}

function Install-OpenSSL {
    Write-Info "Checking OpenSSL installation..."
    
    if (Test-Command "openssl") {
        $opensslVersion = openssl version
        Write-Success "OpenSSL is already installed: $opensslVersion"
        return $true
    }
    
    Write-Info "Installing OpenSSL..."
    try {
        if (-not (Test-Command "choco")) {
            if (-not (Install-Chocolatey)) {
                return $false
            }
        }
        
        choco install openssl -y
        Write-Success "OpenSSL installed successfully"
        return $true
    }
    catch {
        Write-Error-Custom "Failed to install OpenSSL: $($_.Exception.Message)"
        return $false
    }
}

function Test-SystemRequirements {
    Write-Info "Checking system requirements..."
    
    # Check RAM
    $totalRAM = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
    Write-Info "Total RAM: $totalRAM GB"
    
    if ($totalRAM -lt 8) {
        Write-Warning "Minimum 8GB RAM recommended. Current: $totalRAM GB"
    } else {
        Write-Success "RAM requirement met: $totalRAM GB"
    }
    
    # Check disk space
    $freeSpace = [math]::Round((Get-PSDrive C).Free / 1GB, 2)
    Write-Info "Free disk space: $freeSpace GB"
    
    if ($freeSpace -lt 50) {
        Write-Warning "Minimum 50GB free space recommended. Current: $freeSpace GB"
    } else {
        Write-Success "Disk space requirement met: $freeSpace GB"
    }
    
    # Check Windows version
    $osVersion = [System.Environment]::OSVersion.Version
    Write-Info "Windows version: $osVersion"
    
    if ($osVersion.Major -lt 10) {
        Write-Warning "Windows 10 or later recommended"
    } else {
        Write-Success "Windows version requirement met"
    }
    
    return $true
}

function Initialize-Directories {
    Write-Info "Initializing directory structure..."
    
    $directories = @(
        $CONFIG_DIR,
        $DATA_DIR,
        $CERTS_DIR,
        $BACKUP_DIR,
        "$DATA_DIR\elasticsearch",
        "$DATA_DIR\kibana",
        "$DATA_DIR\logstash",
        "$DATA_DIR\wazuh",
        "$DATA_DIR\suricata\logs",
        "$DATA_DIR\suricata\lib",
        "$DATA_DIR\grafana",
        "$DATA_DIR\postgresql",
        "$DATA_DIR\redis",
        "$DATA_DIR\nginx\logs",
        "$CONFIG_DIR\elasticsearch",
        "$CONFIG_DIR\kibana",
        "$CONFIG_DIR\logstash\pipeline",
        "$CONFIG_DIR\wazuh-manager",
        "$CONFIG_DIR\wazuh-dashboard",
        "$CONFIG_DIR\wazuh-indexer",
        "$CONFIG_DIR\suricata",
        "$CONFIG_DIR\grafana\provisioning\dashboards",
        "$CONFIG_DIR\grafana\provisioning\datasources",
        "$CONFIG_DIR\postgresql",
        "$CONFIG_DIR\redis",
        "$CONFIG_DIR\nginx\conf.d",
        "$CONFIG_DIR\elastalert\rules",
        "$CONFIG_DIR\filebeat",
        "$CONFIG_DIR\prometheus",
        "$CERTS_DIR\ca",
        "$CERTS_DIR\elasticsearch",
        "$CERTS_DIR\kibana",
        "$CERTS_DIR\logstash",
        "$CERTS_DIR\wazuh",
        "$CERTS_DIR\grafana",
        "$CERTS_DIR\nginx"
    )
    
    foreach ($dir in $directories) {
        if (-not (Test-Path $dir)) {
            try {
                New-Item -ItemType Directory -Path $dir -Force | Out-Null
                Write-Info "Created directory: $dir"
            }
            catch {
                Write-Error-Custom "Failed to create directory $dir: $($_.Exception.Message)"
                return $false
            }
        }
    }
    
    Write-Success "Directory structure initialized successfully"
    return $true
}

function Generate-SSLCertificates {
    Write-Info "Generating SSL certificates..."
    
    if (-not (Test-Command "openssl")) {
        Write-Error-Custom "OpenSSL is required for certificate generation"
        return $false
    }
    
    try {
        # Generate CA private key
        Write-Info "Generating CA private key..."
        & openssl genrsa -out "$CERTS_DIR\ca\ca.key" 4096
        
        # Generate CA certificate
        Write-Info "Generating CA certificate..."
        & openssl req -new -x509 -days 365 -key "$CERTS_DIR\ca\ca.key" -out "$CERTS_DIR\ca\ca.crt" -subj "/C=US/ST=CA/L=San Francisco/O=SIEM PyMES/OU=Security/CN=SIEM-CA"
        
        # Generate service certificates
        $services = @("elasticsearch", "kibana", "logstash", "wazuh", "grafana", "nginx")
        
        foreach ($service in $services) {
            Write-Info "Generating certificate for $service..."
            
            # Generate private key
            & openssl genrsa -out "$CERTS_DIR\$service\$service.key" 2048
            
            # Generate certificate signing request
            & openssl req -new -key "$CERTS_DIR\$service\$service.key" -out "$CERTS_DIR\$service\$service.csr" -subj "/C=US/ST=CA/L=San Francisco/O=SIEM PyMES/OU=Security/CN=$service"
            
            # Generate certificate
            & openssl x509 -req -in "$CERTS_DIR\$service\$service.csr" -CA "$CERTS_DIR\ca\ca.crt" -CAkey "$CERTS_DIR\ca\ca.key" -CAcreateserial -out "$CERTS_DIR\$service\$service.crt" -days 365
            
            # Clean up CSR
            Remove-Item "$CERTS_DIR\$service\$service.csr" -Force
        }
        
        Write-Success "SSL certificates generated successfully"
        return $true
    }
    catch {
        Write-Error-Custom "Failed to generate SSL certificates: $($_.Exception.Message)"
        return $false
    }
}

function Setup-Environment {
    Write-Info "Setting up environment configuration..."
    
    $envFile = "$SCRIPT_DIR\.env"
    $envExampleFile = "$SCRIPT_DIR\.env.example"
    
    if (-not (Test-Path $envExampleFile)) {
        Write-Error-Custom ".env.example file not found"
        return $false
    }
    
    if (-not (Test-Path $envFile)) {
        Write-Info "Creating .env file from .env.example..."
        Copy-Item $envExampleFile $envFile
        
        # Generate random passwords
        $passwords = @{
            "ELASTIC_PASSWORD" = -join ((1..16) | ForEach-Object { [char]((65..90) + (97..122) + (48..57) | Get-Random) })
            "KIBANA_PASSWORD" = -join ((1..16) | ForEach-Object { [char]((65..90) + (97..122) + (48..57) | Get-Random) })
            "WAZUH_API_PASSWORD" = -join ((1..16) | ForEach-Object { [char]((65..90) + (97..122) + (48..57) | Get-Random) })
            "GRAFANA_PASSWORD" = -join ((1..16) | ForEach-Object { [char]((65..90) + (97..122) + (48..57) | Get-Random) })
            "POSTGRES_PASSWORD" = -join ((1..16) | ForEach-Object { [char]((65..90) + (97..122) + (48..57) | Get-Random) })
            "REDIS_PASSWORD" = -join ((1..16) | ForEach-Object { [char]((65..90) + (97..122) + (48..57) | Get-Random) })
        }
        
        # Update passwords in .env file
        $envContent = Get-Content $envFile
        foreach ($key in $passwords.Keys) {
            $envContent = $envContent -replace "$key=.*", "$key=$($passwords[$key])"
        }
        Set-Content $envFile $envContent
        
        Write-Success "Environment file created with random passwords"
    } else {
        Write-Info "Environment file already exists"
    }
    
    return $true
}

function Start-Services {
    Write-Info "Starting SIEM services..."
    
    try {
        # Pull latest images
        Write-Info "Pulling Docker images..."
        & docker-compose pull
        
        # Start services
        Write-Info "Starting services with Docker Compose..."
        & docker-compose up -d
        
        Write-Success "Services started successfully"
        return $true
    }
    catch {
        Write-Error-Custom "Failed to start services: $($_.Exception.Message)"
        return $false
    }
}

function Wait-ForServices {
    Write-Info "Waiting for services to be ready..."
    
    $services = @(
        @{Name="Elasticsearch"; Url="https://localhost:9200"; MaxWait=300},
        @{Name="Kibana"; Url="https://localhost:5601"; MaxWait=300},
        @{Name="Grafana"; Url="https://localhost:3000"; MaxWait=180},
        @{Name="Wazuh Dashboard"; Url="https://localhost:443"; MaxWait=300}
    )
    
    foreach ($service in $services) {
        Write-Info "Waiting for $($service.Name) to be ready..."
        $waited = 0
        $ready = $false
        
        while ($waited -lt $service.MaxWait -and -not $ready) {
            try {
                $response = Invoke-WebRequest -Uri $service.Url -SkipCertificateCheck -TimeoutSec 5 -ErrorAction SilentlyContinue
                if ($response.StatusCode -eq 200 -or $response.StatusCode -eq 302) {
                    $ready = $true
                    Write-Success "$($service.Name) is ready"
                }
            }
            catch {
                Start-Sleep -Seconds 10
                $waited += 10
                Write-Host "." -NoNewline
            }
        }
        
        if (-not $ready) {
            Write-Warning "$($service.Name) is not ready after $($service.MaxWait) seconds"
        }
    }
}

function Show-AccessInformation {
    Write-Host @"

╔══════════════════════════════════════════════════════════════════════════════╗
║                           INSTALLATION COMPLETE                             ║
╚══════════════════════════════════════════════════════════════════════════════╝

Your SIEM solution is now running! Access the following services:

🔍 Kibana (Elasticsearch UI):
   URL: https://localhost:5601
   Username: elastic
   Password: Check .env file for ELASTIC_PASSWORD

🛡️  Wazuh Dashboard:
   URL: https://localhost:443
   Username: admin
   Password: Check .env file for WAZUH_API_PASSWORD

📊 Grafana (Monitoring):
   URL: https://localhost:3000
   Username: admin
   Password: Check .env file for GRAFANA_PASSWORD

🔧 Management Commands:
   Start services:  docker-compose up -d
   Stop services:   docker-compose down
   View logs:       docker-compose logs -f [service_name]
   Status:          docker-compose ps

📁 Important Directories:
   Configuration: $CONFIG_DIR
   Data:          $DATA_DIR
   Certificates:  $CERTS_DIR
   Backups:       $BACKUP_DIR
   Logs:          $LOG_FILE

⚠️  Security Notes:
   - Change default passwords in .env file
   - Configure firewall rules
   - Set up regular backups
   - Monitor system resources

📖 Documentation: README.md
🐛 Issues: Check $ERROR_LOG

"@ -ForegroundColor $GREEN
}

function Main {
    # Show help if requested
    if ($Help) {
        Show-Help
        return
    }
    
    # Show banner
    Show-Banner
    
    # Check if running as administrator
    if (-not (Test-Administrator)) {
        Write-Error-Custom "This script must be run as Administrator"
        Write-Info "Please right-click PowerShell and select 'Run as Administrator'"
        return
    }
    
    # Initialize log files
    "" | Out-File $LOG_FILE
    "" | Out-File $ERROR_LOG
    
    Write-Info "Starting SIEM installation process..."
    Write-Info "Installation mode: $(if ($Production) {'Production'} elseif ($Development) {'Development'} else {'Standard'})"
    
    # Check system requirements
    if (-not (Test-SystemRequirements)) {
        Write-Error-Custom "System requirements check failed"
        return
    }
    
    # Install prerequisites
    if (-not $SkipDocker) {
        if (-not (Install-Docker)) {
            return
        }
        
        if (-not (Install-DockerCompose)) {
            return
        }
    }
    
    if (-not $SkipSSL) {
        if (-not (Install-OpenSSL)) {
            return
        }
    }
    
    # Initialize directories
    if (-not (Initialize-Directories)) {
        return
    }
    
    # Generate SSL certificates
    if (-not $SkipSSL) {
        if (-not (Generate-SSLCertificates)) {
            return
        }
    }
    
    # Setup environment
    if (-not (Setup-Environment)) {
        return
    }
    
    # Start services
    if (-not (Start-Services)) {
        return
    }
    
    # Wait for services to be ready
    if (-not $Quick) {
        Wait-ForServices
    }
    
    # Show access information
    Show-AccessInformation
    
    Write-Success "SIEM installation completed successfully!"
}

# =============================================================================
# SCRIPT EXECUTION
# =============================================================================

try {
    Main
}
catch {
    Write-Error-Custom "Installation failed: $($_.Exception.Message)"
    Write-Info "Check the error log: $ERROR_LOG"
}

# =============================================================================
# END OF SCRIPT
# =============================================================================