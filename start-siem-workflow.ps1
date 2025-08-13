# =============================================================================
# SIEM Startup Workflow - Inicio Secuencial de Servicios
# =============================================================================
# Este script inicia los servicios del SIEM en el orden correcto según sus dependencias

Write-Host "🚀 Iniciando SIEM con flujo de trabajo secuencial..." -ForegroundColor Green
Write-Host "" 

# Función para verificar el estado de un servicio
function Wait-ForService {
    param(
        [string]$ServiceName,
        [int]$TimeoutSeconds = 120
    )
    
    Write-Host "⏳ Esperando que $ServiceName esté listo..." -ForegroundColor Yellow
    $elapsed = 0
    
    do {
        $status = docker-compose ps $ServiceName --format "table {{.State}}"
        if ($status -match "healthy|running") {
            Write-Host "✅ $ServiceName está listo" -ForegroundColor Green
            return $true
        }
        Start-Sleep 5
        $elapsed += 5
        Write-Host "   Esperando... ($elapsed/$TimeoutSeconds segundos)" -ForegroundColor Gray
    } while ($elapsed -lt $TimeoutSeconds)
    
    Write-Host "❌ Timeout esperando $ServiceName" -ForegroundColor Red
    return $false
}

# =============================================================================
# FASE 1: SERVICIOS BASE (Sin dependencias)
# =============================================================================
Write-Host "📦 FASE 1: Iniciando servicios base..." -ForegroundColor Cyan
Write-Host "" 

# Redis - Cache y sesiones
Write-Host "🔴 Iniciando Redis..." -ForegroundColor White
docker-compose up -d redis
Wait-ForService "redis" 60

# PostgreSQL - Base de datos
Write-Host "🐘 Iniciando PostgreSQL..." -ForegroundColor White
docker-compose up -d postgresql
Wait-ForService "postgresql" 90

Write-Host "" 
Write-Host "✅ Servicios base iniciados correctamente" -ForegroundColor Green
Write-Host "" 

# =============================================================================
# FASE 2: ELASTICSEARCH STACK
# =============================================================================
Write-Host "📦 FASE 2: Iniciando Elasticsearch Stack..." -ForegroundColor Cyan
Write-Host "" 

# Elasticsearch - Motor de búsqueda (base para todo el stack)
Write-Host "🔍 Iniciando Elasticsearch..." -ForegroundColor White
docker-compose up -d elasticsearch
Wait-ForService "elasticsearch" 180

# Pausa para que Elasticsearch se estabilice completamente
Write-Host "⏸️  Pausa de estabilización (30 segundos)..." -ForegroundColor Yellow
Start-Sleep 30

Write-Host "" 
Write-Host "✅ Elasticsearch iniciado correctamente" -ForegroundColor Green
Write-Host "" 

# =============================================================================
# FASE 3: SERVICIOS DEPENDIENTES DE ELASTICSEARCH
# =============================================================================
Write-Host "📦 FASE 3: Iniciando servicios dependientes..." -ForegroundColor Cyan
Write-Host "" 

# Kibana - Interfaz web para Elasticsearch
Write-Host "📊 Iniciando Kibana..." -ForegroundColor White
docker-compose up -d kibana

# Logstash - Procesamiento de logs
Write-Host "🔄 Iniciando Logstash..." -ForegroundColor White
docker-compose up -d logstash

# Esperar que ambos estén listos
Wait-ForService "kibana" 120
Wait-ForService "logstash" 120

Write-Host "" 
Write-Host "✅ Servicios dependientes iniciados" -ForegroundColor Green
Write-Host "" 

# =============================================================================
# FASE 4: SERVICIOS DE MONITOREO Y ANÁLISIS
# =============================================================================
Write-Host "📦 FASE 4: Iniciando servicios de monitoreo..." -ForegroundColor Cyan
Write-Host "" 

# Grafana - Dashboards y visualización
Write-Host "📈 Iniciando Grafana..." -ForegroundColor White
docker-compose up -d grafana

# ElastAlert - Alertas
Write-Host "🚨 Iniciando ElastAlert..." -ForegroundColor White
docker-compose up -d elastalert

# Esperar que estén listos
Wait-ForService "grafana" 90
Wait-ForService "elastalert" 90

Write-Host "" 
Write-Host "✅ Servicios de monitoreo iniciados" -ForegroundColor Green
Write-Host "" 

# =============================================================================
# FASE 5: SERVICIOS DE SEGURIDAD
# =============================================================================
Write-Host "📦 FASE 5: Iniciando servicios de seguridad..." -ForegroundColor Cyan
Write-Host "" 

# Wazuh Manager - HIDS/SIEM
Write-Host "🛡️  Iniciando Wazuh Manager..." -ForegroundColor White
docker-compose up -d wazuh-manager
Wait-ForService "wazuh-manager" 120

# Suricata - IDS/IPS
Write-Host "🔒 Iniciando Suricata..." -ForegroundColor White
docker-compose up -d suricata
Wait-ForService "suricata" 90

Write-Host "" 
Write-Host "✅ Servicios de seguridad iniciados" -ForegroundColor Green
Write-Host "" 

# =============================================================================
# FASE 6: AGENTES Y RECOLECTORES
# =============================================================================
Write-Host "📦 FASE 6: Iniciando agentes y recolectores..." -ForegroundColor Cyan
Write-Host "" 

# Filebeat - Recolector de logs
Write-Host "📄 Iniciando Filebeat..." -ForegroundColor White
docker-compose up -d filebeat
Wait-ForService "filebeat" 90

Write-Host "" 
Write-Host "✅ Agentes y recolectores iniciados" -ForegroundColor Green
Write-Host "" 

# =============================================================================
# FASE 7: SERVICIOS WEB Y PROXY
# =============================================================================
Write-Host "📦 FASE 7: Iniciando servicios web..." -ForegroundColor Cyan
Write-Host "" 

# Nginx - Proxy reverso y balanceador
Write-Host "🌐 Iniciando Nginx..." -ForegroundColor White
docker-compose up -d nginx
Wait-ForService "nginx" 60

Write-Host "" 
Write-Host "✅ Servicios web iniciados" -ForegroundColor Green
Write-Host "" 

# =============================================================================
# VERIFICACIÓN FINAL
# =============================================================================
Write-Host "📋 VERIFICACIÓN FINAL DEL SISTEMA" -ForegroundColor Magenta
Write-Host "" 

# Mostrar estado de todos los servicios
Write-Host "📊 Estado actual de todos los servicios:" -ForegroundColor White
docker-compose ps

Write-Host "" 

# Verificar conectividad del dashboard principal
Write-Host "🌐 Verificando dashboard principal..." -ForegroundColor White
try {
    $response = Invoke-WebRequest -Uri "http://localhost" -UseBasicParsing -TimeoutSec 10
    if ($response.StatusCode -eq 200) {
        Write-Host "✅ Dashboard principal accesible en http://localhost" -ForegroundColor Green
    }
} catch {
    Write-Host "❌ Dashboard principal no accesible" -ForegroundColor Red
}

Write-Host "" 
Write-Host "🎉 SIEM iniciado completamente!" -ForegroundColor Green
Write-Host "" 
Write-Host "📍 URLs de acceso:" -ForegroundColor Yellow
Write-Host "   • Dashboard Principal: http://localhost" -ForegroundColor White
Write-Host "   • Kibana: http://localhost/kibana" -ForegroundColor White
Write-Host "   • Grafana: http://localhost/grafana" -ForegroundColor White
Write-Host "   • Elasticsearch: http://localhost:9200" -ForegroundColor White
Write-Host "" 
Write-Host "💡 Tip: Usa 'docker-compose logs [servicio]' para ver logs específicos" -ForegroundColor Cyan
Write-Host ""