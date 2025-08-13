# Script de Configuración Automática del SIEM
Write-Host "🚀 Configurando tu Sistema SIEM..." -ForegroundColor Green
Write-Host ""

# PASO 1: Generar logs de ejemplo
Write-Host "📊 PASO 1: Generando logs de ejemplo..." -ForegroundColor Yellow

$logDir = "./logs-ejemplo"
if (!(Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force
    Write-Host "✓ Directorio de logs creado: $logDir" -ForegroundColor Green
}

# Generar logs de seguridad simulados
$securityLogs = @(
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [INFO] Usuario admin inicio sesion desde IP 192.168.1.100",
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [WARNING] Intento de login fallido para usuario guest desde IP 10.0.0.50",
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [INFO] Archivo critico /etc/passwd accedido por usuario root",
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [ERROR] Conexion sospechosa detectada desde IP 203.0.113.45",
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [INFO] Backup completado exitosamente",
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [WARNING] Multiples intentos de acceso a directorio restringido",
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [INFO] Servicio web reiniciado por administrador",
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [CRITICAL] Posible ataque de fuerza bruta detectado"
)

$securityLogs | Out-File -FilePath "$logDir/security.log" -Encoding UTF8
Write-Host "✓ Logs de seguridad generados" -ForegroundColor Green

# Generar logs de aplicación web
$webLogs = @(
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') 192.168.1.10 GET /login 200 1234",
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') 10.0.0.25 POST /api/users 201 567",
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') 203.0.113.45 GET /admin 403 89",
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') 192.168.1.15 GET /dashboard 200 2345",
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') 172.16.0.5 POST /api/login 401 123",
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') 10.0.0.30 GET /reports 200 4567"
)

$webLogs | Out-File -FilePath "$logDir/web-access.log" -Encoding UTF8
Write-Host "✓ Logs de aplicación web generados" -ForegroundColor Green

# PASO 2: Configurar Filebeat
Write-Host ""
Write-Host "⚙️ PASO 2: Configurando Filebeat..." -ForegroundColor Yellow

$windowsConfig = @'
# Configuracion adicional para logs de ejemplo
- type: log
  id: windows-demo-logs
  enabled: true
  paths:
    - ./logs-ejemplo/*.log
  fields:
    logtype: demo
    environment: development
    source: windows-demo
  fields_under_root: true
  scan_frequency: 5s
'@

$windowsConfig | Out-File -FilePath "./config/filebeat/windows-inputs.yml" -Encoding UTF8
Write-Host "✓ Configuración de Filebeat actualizada" -ForegroundColor Green

# PASO 3: Crear reglas de alerta
Write-Host ""
Write-Host "🚨 PASO 3: Configurando alertas..." -ForegroundColor Yellow

if (!(Test-Path "./config/elastalert/rules")) {
    New-Item -ItemType Directory -Path "./config/elastalert/rules" -Force
}

$alertRule = @'
name: "Intentos de Login Fallidos"
type: "frequency"
index: "logstash-*"
num_events: 3
timeframe:
  minutes: 5

filter:
- query:
    query_string:
      query: "WARNING AND (login OR authentication) AND (failed OR fallido)"

alert:
- "debug"

alert_text: |
  Se detectaron multiples intentos de login fallidos:
  - Tiempo: {0}
  - Eventos: {1}
'@

$alertRule | Out-File -FilePath "./config/elastalert/rules/login-failures.yml" -Encoding UTF8
Write-Host "✓ Regla de alertas para login fallidos creada" -ForegroundColor Green

# PASO 4: Reiniciar servicios
Write-Host ""
Write-Host "🔄 PASO 4: Aplicando configuración..." -ForegroundColor Yellow

Write-Host "Reiniciando Filebeat..." -ForegroundColor Cyan
docker-compose restart filebeat

Write-Host "Reiniciando Logstash..." -ForegroundColor Cyan
docker-compose restart logstash

Write-Host "✓ Servicios reiniciados exitosamente" -ForegroundColor Green

# PASO 5: Generar logs adicionales
Write-Host ""
Write-Host "📈 PASO 5: Generando logs adicionales..." -ForegroundColor Yellow

for ($i = 1; $i -le 10; $i++) {
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $randomLogs = @(
        "$timestamp [INFO] Proceso $i completado exitosamente",
        "$timestamp [WARNING] Uso de memoria alto detectado: 85%",
        "$timestamp [ERROR] Conexion a base de datos fallo temporalmente",
        "$timestamp [INFO] Usuario conectado desde nueva ubicacion"
    )
    
    $randomLogs | Add-Content -Path "$logDir/security.log" -Encoding UTF8
    Start-Sleep -Milliseconds 500
}

Write-Host "✓ Logs adicionales generados" -ForegroundColor Green

# FINALIZACIÓN
Write-Host ""
Write-Host "🌐 ACCEDE A TUS SERVICIOS:" -ForegroundColor White
Write-Host "• Kibana: http://localhost:5601" -ForegroundColor Cyan
Write-Host "• Dashboard: http://localhost" -ForegroundColor Cyan
Write-Host "• Elasticsearch: http://localhost:9200" -ForegroundColor Cyan
Write-Host ""
Write-Host "📊 PRÓXIMOS PASOS:" -ForegroundColor White
Write-Host "1. Ve a Kibana y explora la sección 'Discover'" -ForegroundColor Yellow
Write-Host "2. Busca logs con: logtype:demo" -ForegroundColor Yellow
Write-Host "3. Crea tu primer dashboard" -ForegroundColor Yellow
Write-Host "4. Revisa las alertas en los logs" -ForegroundColor Yellow
Write-Host ""
Write-Host "Tu SIEM esta listo para usar!" -ForegroundColor Green