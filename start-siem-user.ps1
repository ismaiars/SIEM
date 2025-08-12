# Script de inicio del SIEM (Usuario)
Set-Location "C:\Users\ACER-1\Documents\SIEM"

# FunciÃ³n para escribir logs
function Write-SiemLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Add-Content -Path "C:\Users\ACER-1\Documents\SIEM\logs\auto-start-user.log" -Value $logMessage
    Write-Host $logMessage
}

Write-SiemLog "=== Iniciando SIEM OpenSource PyMES ==="

try {
    # Verificar si ya estÃ¡ ejecutÃ¡ndose
    $existingContainers = docker-compose ps -q 2>$null
    if ($existingContainers -and ($LASTEXITCODE -eq 0)) {
        Write-SiemLog "SIEM ya estÃ¡ ejecutÃ¡ndose"
        Write-SiemLog "Dashboard disponible en: http://localhost"
        exit 0
    }
    
    # Verificar que Docker estÃ© ejecutÃ¡ndose
    Write-SiemLog "Verificando estado de Docker..."
    $dockerInfo = docker info 2>$null
    
    if ($LASTEXITCODE -ne 0) {
        Write-SiemLog "Docker no estÃ¡ ejecutÃ¡ndose. Intentando iniciar Docker Desktop..."
        
        # Buscar Docker Desktop
        $dockerPaths = @(
            "C:\Program Files\Docker\Docker\Docker Desktop.exe",
            "$env:LOCALAPPDATA\Programs\Docker\Docker\Docker Desktop.exe",
            "$env:PROGRAMFILES\Docker\Docker\Docker Desktop.exe"
        )
        
        $dockerFound = $false
        foreach ($path in $dockerPaths) {
            if (Test-Path $path) {
                Write-SiemLog "Iniciando Docker Desktop desde: $path"
                Start-Process "$path" -WindowStyle Hidden
                $dockerFound = $true
                break
            }
        }
        
        if (-not $dockerFound) {
            Write-SiemLog "Docker Desktop no encontrado. Por favor, inicia Docker manualmente." "ERROR"
            exit 1
        }
        
        # Esperar a que Docker se inicie
        Write-SiemLog "Esperando a que Docker se inicie..."
        $maxWait = 120 # 2 minutos
        $waited = 0
        
        do {
            Start-Sleep -Seconds 5
            $waited += 5
            $dockerInfo = docker info 2>$null
            
            if ($LASTEXITCODE -eq 0) {
                Write-SiemLog "Docker estÃ¡ listo"
                break
            }
            
            if ($waited % 15 -eq 0) {
                Write-SiemLog "Esperando Docker... ($waited/$maxWait segundos)"
            }
        } while ($waited -lt $maxWait)
        
        if ($LASTEXITCODE -ne 0) {
            Write-SiemLog "Timeout: Docker no se iniciÃ³ en $maxWait segundos" "ERROR"
            exit 1
        }
    } else {
        Write-SiemLog "Docker estÃ¡ ejecutÃ¡ndose"
    }
    
    # Iniciar el SIEM
    Write-SiemLog "Iniciando servicios del SIEM..."
    $output = docker-compose up -d 2>&1
    
    if ($LASTEXITCODE -eq 0) {
        Write-SiemLog "SIEM iniciado exitosamente"
        Write-SiemLog "Dashboard principal: http://localhost"
        Write-SiemLog "Kibana: http://localhost:5601"
        Write-SiemLog "Grafana: http://localhost:3000"
        
        # Esperar un momento y verificar estado
        Start-Sleep -Seconds 10
        $status = docker-compose ps 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-SiemLog "VerificaciÃ³n de estado completada"
        }
    } else {
        Write-SiemLog "Error al iniciar el SIEM: $output" "ERROR"
        exit 1
    }
    
} catch {
    Write-SiemLog "Error inesperado: $($_.Exception.Message)" "ERROR"
    exit 1
}

Write-SiemLog "=== Inicio del SIEM completado ==="
