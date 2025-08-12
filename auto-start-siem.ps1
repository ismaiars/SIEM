# =============================================================================
# Script de Inicio Automático del SIEM OpenSource PyMES
# =============================================================================
# Este script configura el SIEM para que se inicie automáticamente al arrancar Windows
# usando el Programador de tareas de Windows
# =============================================================================

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("install", "uninstall", "status")]
    [string]$Action = "install"
)

# Configuración
$TaskName = "SIEM-AutoStart"
$TaskDescription = "Inicia automáticamente el SIEM OpenSource PyMES al arrancar el sistema"
$SiemPath = $PSScriptRoot
$LogPath = Join-Path $SiemPath "logs\auto-start.log"

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

# Función para verificar si se ejecuta como administrador
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Función para instalar la tarea programada
function Install-SiemAutoStart {
    Write-Log "Instalando tarea de inicio automático del SIEM..."
    
    # Verificar que Docker esté instalado
    try {
        $dockerVersion = docker --version
        Write-Log "Docker detectado: $dockerVersion"
    } catch {
        Write-Log "Error: Docker no está instalado o no está en el PATH" "ERROR"
        return $false
    }
    
    # Crear script de inicio
    $startScript = @"
# Script de inicio del SIEM
Set-Location "$SiemPath"

# Función para escribir logs
function Write-SiemLog {
    param([string]`$Message)
    `$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path "$LogPath" -Value "[`$timestamp] [STARTUP] `$Message"
}

Write-SiemLog "Iniciando SIEM OpenSource PyMES..."

try {
    # Verificar que Docker esté ejecutándose
    `$dockerStatus = docker info 2>`$null
    if (`$LASTEXITCODE -ne 0) {
        Write-SiemLog "Esperando a que Docker se inicie..."
        Start-Sleep -Seconds 30
        
        # Intentar iniciar Docker Desktop si está instalado
        `$dockerDesktop = Get-Process "Docker Desktop" -ErrorAction SilentlyContinue
        if (-not `$dockerDesktop) {
            `$dockerDesktopPath = "C:\Program Files\Docker\Docker\Docker Desktop.exe"
            if (Test-Path `$dockerDesktopPath) {
                Write-SiemLog "Iniciando Docker Desktop..."
                Start-Process "`$dockerDesktopPath" -WindowStyle Hidden
                Start-Sleep -Seconds 60
            }
        }
    }
    
    # Esperar hasta que Docker esté listo
    `$maxAttempts = 12
    `$attempt = 0
    do {
        `$attempt++
        Write-SiemLog "Verificando estado de Docker (intento `$attempt/`$maxAttempts)..."
        `$dockerStatus = docker info 2>`$null
        if (`$LASTEXITCODE -eq 0) {
            Write-SiemLog "Docker está listo"
            break
        }
        Start-Sleep -Seconds 10
    } while (`$attempt -lt `$maxAttempts)
    
    if (`$LASTEXITCODE -ne 0) {
        Write-SiemLog "Error: Docker no está disponible después de esperar" "ERROR"
        exit 1
    }
    
    # Iniciar el SIEM
    Write-SiemLog "Ejecutando docker-compose up -d..."
    `$result = docker-compose up -d 2>&1
    
    if (`$LASTEXITCODE -eq 0) {
        Write-SiemLog "SIEM iniciado exitosamente"
        Write-SiemLog "Dashboard disponible en: http://localhost"
    } else {
        Write-SiemLog "Error al iniciar el SIEM: `$result" "ERROR"
    }
    
} catch {
    Write-SiemLog "Error inesperado: `$(`$_.Exception.Message)" "ERROR"
}
"@
    
    $startScriptPath = Join-Path $SiemPath "start-siem.ps1"
    Set-Content -Path $startScriptPath -Value $startScript -Encoding UTF8
    
    # Crear la tarea programada
    $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$startScriptPath`""
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
    
    # Registrar la tarea
    try {
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description $TaskDescription -Force
        Write-Log "Tarea programada '$TaskName' creada exitosamente"
        return $true
    } catch {
        Write-Log "Error al crear la tarea programada: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Función para desinstalar la tarea programada
function Uninstall-SiemAutoStart {
    Write-Log "Desinstalando tarea de inicio automático del SIEM..."
    
    try {
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($task) {
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
            Write-Log "Tarea programada '$TaskName' eliminada exitosamente"
        } else {
            Write-Log "La tarea programada '$TaskName' no existe"
        }
        
        # Eliminar script de inicio
        $startScriptPath = Join-Path $SiemPath "start-siem.ps1"
        if (Test-Path $startScriptPath) {
            Remove-Item $startScriptPath -Force
            Write-Log "Script de inicio eliminado"
        }
        
        return $true
    } catch {
        Write-Log "Error al eliminar la tarea programada: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Función para verificar el estado
function Get-SiemAutoStartStatus {
    Write-Log "Verificando estado del inicio automático del SIEM..."
    
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($task) {
        Write-Log "Estado de la tarea: $($task.State)"
        Write-Log "Última ejecución: $($task.LastRunTime)"
        Write-Log "Próxima ejecución: $($task.NextRunTime)"
        
        # Verificar si el SIEM está ejecutándose
        try {
            $containers = docker-compose ps -q 2>$null
            if ($containers) {
                Write-Log "SIEM está ejecutándose actualmente"
                Write-Log "Dashboard disponible en: http://localhost"
            } else {
                Write-Log "SIEM no está ejecutándose actualmente"
            }
        } catch {
            Write-Log "No se pudo verificar el estado del SIEM"
        }
    } else {
        Write-Log "La tarea de inicio automático no está configurada"
    }
}

# Script principal
Write-Log "=== Script de Inicio Automático del SIEM ==="
Write-Log "Acción: $Action"
Write-Log "Ruta del SIEM: $SiemPath"

# Verificar permisos de administrador
if (-not (Test-Administrator)) {
    Write-Log "Error: Este script requiere permisos de administrador" "ERROR"
    Write-Log "Por favor, ejecuta PowerShell como administrador y vuelve a intentar"
    exit 1
}

# Ejecutar acción solicitada
switch ($Action.ToLower()) {
    "install" {
        if (Install-SiemAutoStart) {
            Write-Log "Inicio automático del SIEM configurado exitosamente"
            Write-Log "El SIEM se iniciará automáticamente en el próximo reinicio"
        } else {
            Write-Log "Error al configurar el inicio automático" "ERROR"
            exit 1
        }
    }
    
    "uninstall" {
        if (Uninstall-SiemAutoStart) {
            Write-Log "Inicio automático del SIEM deshabilitado exitosamente"
        } else {
            Write-Log "Error al deshabilitar el inicio automático" "ERROR"
            exit 1
        }
    }
    
    "status" {
        Get-SiemAutoStartStatus
    }
    
    default {
        Write-Log "Acción no válida: $Action" "ERROR"
        Write-Log "Acciones válidas: install, uninstall, status"
        exit 1
    }
}

Write-Log "=== Fin del script ==="