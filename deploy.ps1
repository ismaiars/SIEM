# =============================================================================
# SIEM OpenSource PyMES Deployment Script
# =============================================================================
# This PowerShell script automates the deployment of the SIEM solution
# including Docker containers, SSL certificates, and initial configuration
# =============================================================================

param(
    [Parameter(Mandatory=$false)]
    [string]$Environment = "development",
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipSSL,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipInit,
    
    [Parameter(Mandatory=$false)]
    [switch]$Cleanup,
    
    [Parameter(Mandatory=$false)]
    [switch]$UpdateOnly,
    
    [Parameter(Mandatory=$false)]
    [switch]$Verbose
)

# Set error action preference
$ErrorActionPreference = "Stop"

# Enable verbose output if requested
if ($Verbose) {
    $VerbosePreference = "Continue"
}

# Script variables
$ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ProjectRoot = $ScriptPath
$ConfigPath = Join-Path $ProjectRoot "config"
$CertsPath = Join-Path $ConfigPath "ssl"
$LogsPath = Join-Path $ProjectRoot "logs"
$DataPath = Join-Path $ProjectRoot "data"

# Colors for output
$Colors = @{
    'Info' = 'Cyan'
    'Success' = 'Green'
    'Warning' = 'Yellow'
    'Error' = 'Red'
    'Header' = 'Magenta'
}

# Logging function
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Write to console with color
    if ($Colors.ContainsKey($Level)) {
        Write-Host $logMessage -ForegroundColor $Colors[$Level]
    } else {
        Write-Host $logMessage
    }
    
    # Write to log file
    $logFile = Join-Path $LogsPath "deployment.log"
    if (Test-Path $LogsPath) {
        Add-Content -Path $logFile -Value $logMessage
    }
}

# Header function
function Write-Header {
    param([string]$Title)
    
    Write-Host ""
    Write-Host "=" * 80 -ForegroundColor $Colors['Header']
    Write-Host $Title.ToUpper().PadLeft(40 + $Title.Length / 2) -ForegroundColor $Colors['Header']
    Write-Host "=" * 80 -ForegroundColor $Colors['Header']
    Write-Host ""
}

# Check prerequisites
function Test-Prerequisites {
    Write-Header "Checking Prerequisites"
    
    $prerequisites = @(
        @{ Name = "Docker"; Command = "docker --version" },
        @{ Name = "Docker Compose"; Command = "docker-compose --version" },
        @{ Name = "OpenSSL"; Command = "openssl version" }
    )
    
    $allGood = $true
    
    foreach ($prereq in $prerequisites) {
        try {
            $result = Invoke-Expression $prereq.Command 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-Log "✓ $($prereq.Name) is installed: $($result.Split([Environment]::NewLine)[0])" "Success"
            } else {
                Write-Log "✗ $($prereq.Name) is not working properly" "Error"
                $allGood = $false
            }
        } catch {
            Write-Log "✗ $($prereq.Name) is not installed or not in PATH" "Error"
            $allGood = $false
        }
    }
    
    if (-not $allGood) {
        Write-Log "Please install missing prerequisites before continuing" "Error"
        exit 1
    }
    
    # Check available disk space (minimum 10GB)
    $drive = (Get-Location).Drive
    $freeSpace = (Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='$($drive.Name)'").FreeSpace / 1GB
    
    if ($freeSpace -lt 10) {
        Write-Log "Warning: Low disk space ($([math]::Round($freeSpace, 2)) GB available). Minimum 10GB recommended." "Warning"
    } else {
        Write-Log "✓ Sufficient disk space available ($([math]::Round($freeSpace, 2)) GB)" "Success"
    }
}

# Create directory structure
function Initialize-Directories {
    Write-Header "Initializing Directory Structure"
    
    $directories = @(
        $LogsPath,
        $DataPath,
        $CertsPath,
        (Join-Path $DataPath "elasticsearch"),
        (Join-Path $DataPath "wazuh-indexer"),
        (Join-Path $DataPath "wazuh-manager"),
        (Join-Path $DataPath "grafana"),
        (Join-Path $DataPath "postgres"),
        (Join-Path $DataPath "redis"),
        (Join-Path $DataPath "suricata"),
        (Join-Path $LogsPath "nginx"),
        (Join-Path $LogsPath "elasticsearch"),
        (Join-Path $LogsPath "kibana"),
        (Join-Path $LogsPath "logstash"),
        (Join-Path $LogsPath "wazuh"),
        (Join-Path $LogsPath "grafana"),
        (Join-Path $LogsPath "suricata")
    )
    
    foreach ($dir in $directories) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Write-Log "Created directory: $dir" "Info"
        } else {
            Write-Log "Directory already exists: $dir" "Info"
        }
    }
    
    # Set permissions for data directories (Linux-style permissions for Docker)
    if ($Environment -ne "windows") {
        $dataDirectories = @(
            (Join-Path $DataPath "elasticsearch"),
            (Join-Path $DataPath "wazuh-indexer"),
            (Join-Path $DataPath "grafana")
        )
        
        foreach ($dir in $dataDirectories) {
            try {
                # This would work in WSL or Linux environment
                & chmod 777 $dir 2>$null
                Write-Log "Set permissions for: $dir" "Info"
            } catch {
                Write-Log "Could not set permissions for: $dir (this is normal on Windows)" "Warning"
            }
        }
    }
}

# Generate SSL certificates
function New-SSLCertificates {
    Write-Header "Generating SSL Certificates"
    
    if ($SkipSSL) {
        Write-Log "Skipping SSL certificate generation" "Warning"
        return
    }
    
    $services = @("siem", "kibana", "wazuh", "grafana", "elasticsearch", "logstash", "status")
    
    # Generate CA key and certificate
    $caKey = Join-Path $CertsPath "ca.key"
    $caCert = Join-Path $CertsPath "ca.crt"
    
    if (-not (Test-Path $caCert)) {
        Write-Log "Generating CA certificate..." "Info"
        
        # Generate CA private key
        & openssl genrsa -out $caKey 4096
        
        # Generate CA certificate
        & openssl req -new -x509 -days 365 -key $caKey -out $caCert -subj "/C=US/ST=State/L=City/O=SIEM-PyMES/OU=IT/CN=SIEM-CA"
        
        Write-Log "CA certificate generated" "Success"
    } else {
        Write-Log "CA certificate already exists" "Info"
    }
    
    # Generate DH parameters
    $dhParam = Join-Path $CertsPath "dhparam.pem"
    if (-not (Test-Path $dhParam)) {
        Write-Log "Generating DH parameters (this may take a while)..." "Info"
        & openssl dhparam -out $dhParam 2048
        Write-Log "DH parameters generated" "Success"
    }
    
    # Generate certificates for each service
    foreach ($service in $services) {
        $serviceKey = Join-Path $CertsPath "$service.key"
        $serviceCsr = Join-Path $CertsPath "$service.csr"
        $serviceCert = Join-Path $CertsPath "$service.crt"
        
        if (-not (Test-Path $serviceCert)) {
            Write-Log "Generating certificate for $service..." "Info"
            
            # Generate private key
            & openssl genrsa -out $serviceKey 2048
            
            # Generate certificate signing request
            & openssl req -new -key $serviceKey -out $serviceCsr -subj "/C=US/ST=State/L=City/O=SIEM-PyMES/OU=IT/CN=$service.local"
            
            # Generate certificate
            & openssl x509 -req -in $serviceCsr -CA $caCert -CAkey $caKey -CAcreateserial -out $serviceCert -days 365
            
            # Clean up CSR
            Remove-Item $serviceCsr -Force
            
            Write-Log "Certificate generated for $service" "Success"
        } else {
            Write-Log "Certificate already exists for $service" "Info"
        }
    }
}

# Setup environment file
function Initialize-Environment {
    Write-Header "Setting up Environment Configuration"
    
    $envFile = Join-Path $ProjectRoot ".env"
    $envExampleFile = Join-Path $ProjectRoot ".env.example"
    
    if (-not (Test-Path $envFile) -and (Test-Path $envExampleFile)) {
        Copy-Item $envExampleFile $envFile
        Write-Log "Created .env file from .env.example" "Success"
        
        # Generate random passwords
        $passwords = @{
            'ELASTIC_PASSWORD' = -join ((1..16) | ForEach {[char]((65..90) + (97..122) + (48..57) | Get-Random)})
            'KIBANA_PASSWORD' = -join ((1..16) | ForEach {[char]((65..90) + (97..122) + (48..57) | Get-Random)})
            'WAZUH_PASSWORD' = -join ((1..16) | ForEach {[char]((65..90) + (97..122) + (48..57) | Get-Random)})
            'GRAFANA_ADMIN_PASSWORD' = -join ((1..16) | ForEach {[char]((65..90) + (97..122) + (48..57) | Get-Random)})
            'POSTGRES_PASSWORD' = -join ((1..16) | ForEach {[char]((65..90) + (97..122) + (48..57) | Get-Random)})
            'REDIS_PASSWORD' = -join ((1..16) | ForEach {[char]((65..90) + (97..122) + (48..57) | Get-Random)})
        }
        
        # Update .env file with generated passwords
        $envContent = Get-Content $envFile
        foreach ($key in $passwords.Keys) {
            $envContent = $envContent -replace "$key=changeme", "$key=$($passwords[$key])"
        }
        
        # Set environment-specific values
        $envContent = $envContent -replace "ENVIRONMENT=development", "ENVIRONMENT=$Environment"
        
        Set-Content $envFile $envContent
        
        Write-Log "Generated random passwords and updated environment configuration" "Success"
        Write-Log "Please review and customize the .env file as needed" "Warning"
    } else {
        Write-Log ".env file already exists" "Info"
    }
}

# Pull Docker images
function Get-DockerImages {
    Write-Header "Pulling Docker Images"
    
    Write-Log "Pulling required Docker images..." "Info"
    
    try {
        & docker-compose pull
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Successfully pulled all Docker images" "Success"
        } else {
            Write-Log "Some images failed to pull, but continuing..." "Warning"
        }
    } catch {
        Write-Log "Error pulling Docker images: $($_.Exception.Message)" "Error"
        throw
    }
}

# Deploy services
function Start-Services {
    Write-Header "Starting SIEM Services"
    
    Write-Log "Starting Docker Compose services..." "Info"
    
    try {
        if ($UpdateOnly) {
            & docker-compose up -d --force-recreate
        } else {
            & docker-compose up -d
        }
        
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Successfully started all services" "Success"
        } else {
            Write-Log "Some services failed to start" "Error"
            throw "Docker Compose failed"
        }
    } catch {
        Write-Log "Error starting services: $($_.Exception.Message)" "Error"
        throw
    }
}

# Wait for services to be ready
function Wait-ForServices {
    Write-Header "Waiting for Services to be Ready"
    
    $services = @(
        @{ Name = "Elasticsearch"; Url = "http://localhost:9200/_cluster/health"; Timeout = 300 },
        @{ Name = "Kibana"; Url = "http://localhost:5601/api/status"; Timeout = 180 },
        @{ Name = "Wazuh Manager"; Url = "http://localhost:55000"; Timeout = 120 },
        @{ Name = "Grafana"; Url = "http://localhost:3000/api/health"; Timeout = 60 }
    )
    
    foreach ($service in $services) {
        Write-Log "Waiting for $($service.Name) to be ready..." "Info"
        
        $timeout = $service.Timeout
        $elapsed = 0
        $interval = 10
        
        do {
            try {
                $response = Invoke-WebRequest -Uri $service.Url -TimeoutSec 5 -UseBasicParsing 2>$null
                if ($response.StatusCode -eq 200) {
                    Write-Log "✓ $($service.Name) is ready" "Success"
                    break
                }
            } catch {
                # Service not ready yet
            }
            
            Start-Sleep $interval
            $elapsed += $interval
            
            if ($elapsed % 30 -eq 0) {
                Write-Log "Still waiting for $($service.Name)... ($elapsed/$timeout seconds)" "Info"
            }
            
        } while ($elapsed -lt $timeout)
        
        if ($elapsed -ge $timeout) {
            Write-Log "⚠ $($service.Name) did not become ready within $timeout seconds" "Warning"
        }
    }
}

# Initialize SIEM data
function Initialize-SIEMData {
    Write-Header "Initializing SIEM Data"
    
    if ($SkipInit) {
        Write-Log "Skipping SIEM data initialization" "Warning"
        return
    }
    
    Write-Log "Setting up initial SIEM configuration..." "Info"
    
    # Wait a bit more for services to fully initialize
    Start-Sleep 30
    
    # Create Elasticsearch index templates
    try {
        Write-Log "Creating Elasticsearch index templates..." "Info"
        
        $indexTemplates = @(
            "wazuh-alerts",
            "suricata-events",
            "filebeat-logs",
            "logstash-logs"
        )
        
        foreach ($template in $indexTemplates) {
            $templateBody = @{
                "index_patterns" = @("$template-*")
                "settings" = @{
                    "number_of_shards" = 1
                    "number_of_replicas" = 0
                    "index.refresh_interval" = "5s"
                }
                "mappings" = @{
                    "properties" = @{
                        "@timestamp" = @{ "type" = "date" }
                        "message" = @{ "type" = "text" }
                        "level" = @{ "type" = "keyword" }
                    }
                }
            } | ConvertTo-Json -Depth 10
            
            try {
                Invoke-RestMethod -Uri "http://localhost:9200/_index_template/$template" -Method PUT -Body $templateBody -ContentType "application/json" -TimeoutSec 30
                Write-Log "Created index template: $template" "Success"
            } catch {
                Write-Log "Failed to create index template $template : $($_.Exception.Message)" "Warning"
            }
        }
    } catch {
        Write-Log "Error setting up Elasticsearch templates: $($_.Exception.Message)" "Warning"
    }
    
    Write-Log "SIEM initialization completed" "Success"
}

# Cleanup function
function Remove-Deployment {
    Write-Header "Cleaning up SIEM Deployment"
    
    Write-Log "Stopping and removing all containers..." "Info"
    
    try {
        & docker-compose down -v --remove-orphans
        Write-Log "Containers stopped and removed" "Success"
    } catch {
        Write-Log "Error stopping containers: $($_.Exception.Message)" "Warning"
    }
    
    # Optionally remove data directories
    $response = Read-Host "Do you want to remove all data directories? This will delete all SIEM data! (y/N)"
    if ($response -eq 'y' -or $response -eq 'Y') {
        try {
            if (Test-Path $DataPath) {
                Remove-Item $DataPath -Recurse -Force
                Write-Log "Data directories removed" "Success"
            }
            if (Test-Path $LogsPath) {
                Remove-Item $LogsPath -Recurse -Force
                Write-Log "Log directories removed" "Success"
            }
        } catch {
            Write-Log "Error removing directories: $($_.Exception.Message)" "Error"
        }
    }
}

# Show deployment status
function Show-Status {
    Write-Header "SIEM Deployment Status"
    
    Write-Log "Checking service status..." "Info"
    
    try {
        & docker-compose ps
    } catch {
        Write-Log "Error getting service status: $($_.Exception.Message)" "Error"
    }
    
    Write-Host ""
    Write-Log "SIEM Web Interfaces:" "Header"
    Write-Log "• Kibana (SIEM Dashboard): https://localhost:5601" "Info"
    Write-Log "• Wazuh Dashboard: https://wazuh.local:443" "Info"
    Write-Log "• Grafana (Monitoring): https://localhost:3000" "Info"
    Write-Log "• Elasticsearch API: https://localhost:9200" "Info"
    
    Write-Host ""
    Write-Log "Default Credentials:" "Header"
    Write-Log "• Elasticsearch: elastic / (check .env file)" "Info"
    Write-Log "• Kibana: elastic / (same as Elasticsearch)" "Info"
    Write-Log "• Grafana: admin / (check .env file)" "Info"
    Write-Log "• Wazuh: admin / (check .env file)" "Info"
    
    Write-Host ""
    Write-Log "Important Notes:" "Header"
    Write-Log "• Add SSL certificates to your browser's trusted store" "Warning"
    Write-Log "• Update /etc/hosts (or C:\Windows\System32\drivers\etc\hosts) with:" "Warning"
    Write-Log "  127.0.0.1 siem.local kibana.local wazuh.local grafana.local" "Warning"
    Write-Log "• Check logs in ./logs/ directory for troubleshooting" "Info"
    Write-Log "• Configuration files are in ./config/ directory" "Info"
}

# Main execution
function Main {
    try {
        Write-Header "SIEM OpenSource PyMES Deployment Script"
        Write-Log "Starting deployment in $Environment environment" "Info"
        
        # Change to script directory
        Set-Location $ProjectRoot
        
        if ($Cleanup) {
            Remove-Deployment
            return
        }
        
        # Run deployment steps
        Test-Prerequisites
        Initialize-Directories
        
        if (-not $UpdateOnly) {
            New-SSLCertificates
            Initialize-Environment
        }
        
        Get-DockerImages
        Start-Services
        Wait-ForServices
        
        if (-not $UpdateOnly) {
            Initialize-SIEMData
        }
        
        Show-Status
        
        Write-Header "Deployment Completed Successfully"
        Write-Log "SIEM OpenSource PyMES has been deployed successfully!" "Success"
        Write-Log "Please check the status above and access the web interfaces." "Info"
        
    } catch {
        Write-Log "Deployment failed: $($_.Exception.Message)" "Error"
        Write-Log "Check the logs for more details: $LogsPath\deployment.log" "Error"
        exit 1
    }
}

# Help function
function Show-Help {
    Write-Host @"
SIEM OpenSource PyMES Deployment Script

Usage: .\deploy.ps1 [OPTIONS]

Options:
  -Environment <env>    Deployment environment (development, staging, production)
  -SkipSSL             Skip SSL certificate generation
  -SkipInit            Skip SIEM data initialization
  -Cleanup             Remove all containers and optionally data
  -UpdateOnly          Only update existing deployment
  -Verbose             Enable verbose output
  -Help                Show this help message

Examples:
  .\deploy.ps1                                    # Deploy with default settings
  .\deploy.ps1 -Environment production            # Deploy for production
  .\deploy.ps1 -SkipSSL -SkipInit                # Quick deployment without SSL/init
  .\deploy.ps1 -Cleanup                          # Clean up deployment
  .\deploy.ps1 -UpdateOnly                       # Update existing deployment
  .\deploy.ps1 -Verbose                          # Deploy with verbose output

"@
}

# Check for help parameter
if ($args -contains "-Help" -or $args -contains "--help" -or $args -contains "-h") {
    Show-Help
    exit 0
}

# Run main function
Main