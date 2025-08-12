# =============================================================================
# Script de Inicio Automático del SIEM (Nivel Usuario)
# =============================================================================
# Este script configura el SIEM para que se inicie automáticamente al iniciar
# sesión del usuario usando el registro de Windows
# =============================================================================

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("install", "uninstall", "status")]
    [string]$Action = "install"
)

# Configuración
$AppName = "SIEM-AutoStart"
$SiemPath = $PSScriptRoot
$LogPath = Join-Path $SiemPath "logs\auto-start-user.log"
$RegistryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"

# Función para escribir logs
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Write-Host $logMessage
    
    # Crear directorio de logs si no existe
    $logDir = Split-Path $LogPath -Parent
    if (!(Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    
    Add-Content -Path $LogPath -Value $logMessage
}

# Función para instalar el inicio automático
function Install-SiemUserAutoStart {
    Write-Log "Configurando inicio automático del SIEM para el usuario actual..."
    
    # Verificar que Docker esté instalado
    try {
        $dockerVersion = docker --version 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Docker detectado: $dockerVersion"
        } else {
            Write-Log "Advertencia: Docker no está disponible en el PATH" "WARN"
        }
    } catch {
        Write-Log "Advertencia: No se pudo verificar Docker" "WARN"
    }
    
    # Crear script de inicio optimizado
    $startScript = @"
# Script de inicio del SIEM (Usuario)
Set-Location "$SiemPath"

# Función para escribir logs
function Write-SiemLog {
    param([string]`$Message, [string]`$Level = "INFO")
    `$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    `$logMessage = "[`$timestamp] [`$Level] `$Message"
    Add-Content -Path "$LogPath" -Value `$logMessage
    Write-Host `$logMessage
}

Write-SiemLog "=== Iniciando SIEM OpenSource PyMES ==="

try {
    # Verificar si ya está ejecutándose
    `$existingContainers = docker-compose ps -q 2>`$null
    if (`$existingContainers -and (`$LASTEXITCODE -eq 0)) {
        Write-SiemLog "SIEM ya está ejecutándose"
        Write-SiemLog "Dashboard disponible en: http://localhost"
        exit 0
    }
    
    # Verificar que Docker esté ejecutándose
    Write-SiemLog "Verificando estado de Docker..."
    `$dockerInfo = docker info 2>`$null
    
    if (`$LASTEXITCODE -ne 0) {
        Write-SiemLog "Docker no está ejecutándose. Intentando iniciar Docker Desktop..."
        
        # Buscar Docker Desktop
        `$dockerPaths = @(
            "C:\Program Files\Docker\Docker\Docker Desktop.exe",
            "`$env:LOCALAPPDATA\Programs\Docker\Docker\Docker Desktop.exe",
            "`$env:PROGRAMFILES\Docker\Docker\Docker Desktop.exe"
        )
        
        `$dockerFound = `$false
        foreach (`$path in `$dockerPaths) {
            if (Test-Path `$path) {
                Write-SiemLog "Iniciando Docker Desktop desde: `$path"
                Start-Process "`$path" -WindowStyle Hidden
                `$dockerFound = `$true
                break
            }
        }
        
        if (-not `$dockerFound) {
            Write-SiemLog "Docker Desktop no encontrado. Por favor, inicia Docker manualmente." "ERROR"
            exit 1
        }
        
        # Esperar a que Docker se inicie
        Write-SiemLog "Esperando a que Docker se inicie..."
        `$maxWait = 120 # 2 minutos
        `$waited = 0
        
        do {
            Start-Sleep -Seconds 5
            `$waited += 5
            `$dockerInfo = docker info 2>`$null
            
            if (`$LASTEXITCODE -eq 0) {
                Write-SiemLog "Docker está listo"
                break
            }
            
            if (`$waited % 15 -eq 0) {
                Write-SiemLog "Esperando Docker... (`$waited/`$maxWait segundos)"
            }
        } while (`$waited -lt `$maxWait)
        
        if (`$LASTEXITCODE -ne 0) {
            Write-SiemLog "Timeout: Docker no se inició en `$maxWait segundos" "ERROR"
            exit 1
        }
    } else {
        Write-SiemLog "Docker está ejecutándose"
    }
    
    # Iniciar el SIEM
    Write-SiemLog "Iniciando servicios del SIEM..."
    `$output = docker-compose up -d 2>&1
    
    if (`$LASTEXITCODE -eq 0) {
        Write-SiemLog "SIEM iniciado exitosamente"
        Write-SiemLog "Dashboard principal: http://localhost"
        Write-SiemLog "Kibana: http://localhost:5601"
        Write-SiemLog "Grafana: http://localhost:3000"
        
        # Esperar un momento y verificar estado
        Start-Sleep -Seconds 10
        `$status = docker-compose ps 2>`$null
        if (`$LASTEXITCODE -eq 0) {
            Write-SiemLog "Verificación de estado completada"
        }
    } else {
        Write-SiemLog "Error al iniciar el SIEM: `$output" "ERROR"
        exit 1
    }
    
} catch {
    Write-SiemLog "Error inesperado: `$(`$_.Exception.Message)" "ERROR"
    exit 1
}

Write-SiemLog "=== Inicio del SIEM completado ==="
"@
    
    $startScriptPath = Join-Path $SiemPath "start-siem-user.ps1"
    Set-Content -Path $startScriptPath -Value $startScript -Encoding UTF8
    
    # Crear comando para el registro
    $command = "PowerShell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$startScriptPath`""
    
    # Agregar al registro de inicio
    try {
        Set-ItemProperty -Path $RegistryPath -Name $AppName -Value $command -Force
        Write-Log "Entrada de registro creada exitosamente"
        Write-Log "Comando: $command"
        return $true
    } catch {
        Write-Log "Error al crear la entrada de registro: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Función para desinstalar el inicio automático
function Uninstall-SiemUserAutoStart {
    Write-Log "Deshabilitando inicio automático del SIEM..."
    
    try {
        # Eliminar del registro
        $regValue = Get-ItemProperty -Path $RegistryPath -Name $AppName -ErrorAction SilentlyContinue
        if ($regValue) {
            Remove-ItemProperty -Path $RegistryPath -Name $AppName -Force
            Write-Log "Entrada de registro eliminada exitosamente"
        } else {
            Write-Log "La entrada de registro no existe"
        }
        
        # Eliminar script de inicio
        $startScriptPath = Join-Path $SiemPath "start-siem-user.ps1"
        if (Test-Path $startScriptPath) {
            Remove-Item $startScriptPath -Force
            Write-Log "Script de inicio eliminado"
        }
        
        return $true
    } catch {
        Write-Log "Error al eliminar la configuración: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Función para verificar el estado
function Get-SiemUserAutoStartStatus {
    Write-Log "Verificando estado del inicio automático del SIEM..."
    
    # Verificar registro
    $regValue = Get-ItemProperty -Path $RegistryPath -Name $AppName -ErrorAction SilentlyContinue
    if ($regValue) {
        Write-Log "Inicio automático: HABILITADO"
        Write-Log "Comando: $($regValue.$AppName)"
    } else {
        Write-Log "Inicio automático: DESHABILITADO"
    }
    
    # Verificar si el SIEM está ejecutándose
    try {
        $containers = docker-compose ps -q 2>$null
        if ($containers -and ($LASTEXITCODE -eq 0)) {
            Write-Log "Estado del SIEM: EJECUTÁNDOSE"
            Write-Log "Dashboard disponible en: http://localhost"
            
            # Mostrar estado de contenedores
            $containerStatus = docker-compose ps --format "table {{.Name}}\t{{.Status}}" 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-Log "Estado de contenedores:"
                $containerStatus | ForEach-Object { Write-Log "  $_" }
            }
        } else {
            Write-Log "Estado del SIEM: DETENIDO"
        }
    } catch {
        Write-Log "No se pudo verificar el estado del SIEM"
    }
    
    # Verificar Docker
    try {
        $dockerInfo = docker info 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Estado de Docker: EJECUTÁNDOSE"
        } else {
            Write-Log "Estado de Docker: DETENIDO"
        }
    } catch {
        Write-Log "Estado de Docker: NO DISPONIBLE"
    }
}

# Script principal
Write-Log "=== Configurador de Inicio Automático del SIEM (Usuario) ==="
Write-Log "Acción: $Action"
Write-Log "Ruta del SIEM: $SiemPath"
Write-Log "Usuario actual: $env:USERNAME"

# Ejecutar acción solicitada
switch ($Action.ToLower()) {
    "install" {
        if (Install-SiemUserAutoStart) {
            Write-Log "¡Inicio automático del SIEM configurado exitosamente!"
            Write-Log "El SIEM se iniciará automáticamente cuando inicies sesión"
            Write-Log ""
            Write-Log "Para probar ahora, puedes ejecutar:"
            Write-Log "  .\start-siem-user.ps1"
            Write-Log ""
            Write-Log "URLs de acceso:"
            Write-Log "  Dashboard principal: http://localhost"
            Write-Log "  Kibana: http://localhost:5601"
            Write-Log "  Grafana: http://localhost:3000"
        } else {
            Write-Log "Error al configurar el inicio automático" "ERROR"
            exit 1
        }
    }
    
    "uninstall" {
        if (Uninstall-SiemUserAutoStart) {
            Write-Log "Inicio automático del SIEM deshabilitado exitosamente"
        } else {
            Write-Log "Error al deshabilitar el inicio automático" "ERROR"
            exit 1
        }
    }
    
    "status" {
        Get-SiemUserAutoStartStatus
    }
    
    default {
        Write-Log "Acción no válida: $Action" "ERROR"
        Write-Log "Acciones válidas: install, uninstall, status"
        exit 1
    }
}

Write-Log "=== Fin del script ==="