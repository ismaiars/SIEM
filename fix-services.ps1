#!/usr/bin/env pwsh
# =============================================================================
# Script para Corregir Servicios SIEM con Problemas
# =============================================================================

Write-Host "🔧 Iniciando corrección de servicios SIEM..." -ForegroundColor Cyan

# Función para mostrar estado
function Show-Status {
    param([string]$Message, [string]$Color = "Green")
    Write-Host "✅ $Message" -ForegroundColor $Color
}

function Show-Warning {
    param([string]$Message)
    Write-Host "⚠️  $Message" -ForegroundColor Yellow
}

function Show-Error {
    param([string]$Message)
    Write-Host "❌ $Message" -ForegroundColor Red
}

# Detener servicios problemáticos
Show-Warning "Deteniendo servicios con problemas..."
docker-compose stop kibana suricata

# Esperar un momento
Start-Sleep -Seconds 5

# Verificar servicios funcionando
Show-Status "Verificando servicios funcionando..."
$services = docker-compose ps --format json | ConvertFrom-Json

Write-Host "\n📊 Estado de Servicios:" -ForegroundColor Cyan
foreach ($service in $services) {
    $name = $service.Name -replace "siem-", ""
    $status = $service.State
    
    if ($status -eq "running") {
        Show-Status "$name - Funcionando"
    } elseif ($status -eq "exited") {
        Show-Error "$name - Detenido"
    } else {
        Show-Warning "$name - $status"
    }
}

# Mostrar servicios disponibles
Write-Host "\n🌐 Servicios Disponibles:" -ForegroundColor Green
Write-Host "• Dashboard Principal: http://localhost" -ForegroundColor White
Write-Host "• Elasticsearch: http://localhost:9200" -ForegroundColor White
Write-Host "• Logstash: http://localhost:9600" -ForegroundColor White
Write-Host "• Grafana: http://localhost:3000" -ForegroundColor White
Write-Host "• PostgreSQL: localhost:5432" -ForegroundColor White
Write-Host "• Redis: localhost:6379" -ForegroundColor White

Write-Host "\n⚠️  Servicios Temporalmente Deshabilitados:" -ForegroundColor Yellow
Write-Host "• Kibana - Problemas de configuración" -ForegroundColor Gray
Write-Host "• Suricata - Problemas de permisos" -ForegroundColor Gray

Write-Host "\n✅ Corrección completada. El SIEM está funcionando con los servicios estables." -ForegroundColor Green
Write-Host "💡 Tip: Usa 'docker-compose logs [servicio]' para ver logs detallados" -ForegroundColor Cyan