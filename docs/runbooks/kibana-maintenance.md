# Runbook - Mantenimiento de Kibana

## 📋 Información del Runbook

| Campo | Valor |
|-------|-------|
| **ID del Runbook** | RB-003-KIBANA-MAINTENANCE |
| **Versión** | 1.0 |
| **Fecha de Creación** | Diciembre 2024 |
| **Última Actualización** | Diciembre 2024 |
| **Autor** | Equipo de Operaciones |
| **Clasificación** | INTERNO |
| **Frecuencia** | Diaria/Semanal/Mensual |

## 🎯 Objetivo y Alcance

### Objetivo
Proporcionar procedimientos estandarizados para el mantenimiento preventivo y correctivo de Kibana, asegurando la disponibilidad de dashboards, visualizaciones y funcionalidades de análisis de datos del SIEM.

### Alcance
- Kibana Server
- Dashboards y visualizaciones
- Índices y patrones de índices
- Usuarios y roles
- Configuraciones de alertas
- Integraciones con Elasticsearch
- Plugins y extensiones

### Prerrequisitos
- Acceso administrativo a Kibana
- Conocimiento de Elasticsearch y Kibana
- Acceso SSH a servidores
- Herramientas de monitoreo configuradas

## 📅 Tareas de Mantenimiento

### Mantenimiento Diario

#### 1. Verificación del Estado de Kibana
```bash
#!/bin/bash
# Script: daily_kibana_check.sh

DATE=$(date +"%Y-%m-%d %H:%M:%S")
LOG_FILE="/var/log/kibana_maintenance.log"
KIBANA_URL="http://localhost:5601"
KIBANA_CONFIG="/etc/kibana/kibana.yml"
KIBANA_LOG="/var/log/kibana/kibana.log"

echo "[$DATE] Iniciando verificación diaria de Kibana" >> $LOG_FILE

# Verificar estado del servicio
echo "=== ESTADO DEL SERVICIO KIBANA ===" >> $LOG_FILE
systemctl status kibana >> $LOG_FILE 2>&1

# Verificar conectividad HTTP
echo "\n=== VERIFICACIÓN DE CONECTIVIDAD ===" >> $LOG_FILE
response_code=$(curl -s -o /dev/null -w "%{http_code}" $KIBANA_URL)
echo "Código de respuesta HTTP: $response_code" >> $LOG_FILE

if [ "$response_code" != "200" ]; then
  echo "ERROR: Kibana no responde correctamente" >> $LOG_FILE
  echo "ERROR: Kibana no responde (HTTP $response_code)" | mail -s "Kibana Service Alert" admin@company.com
fi

# Verificar conectividad con Elasticsearch
echo "\n=== CONECTIVIDAD CON ELASTICSEARCH ===" >> $LOG_FILE
elasticsearch_status=$(curl -s "$KIBANA_URL/api/status" | jq -r '.status.overall.state' 2>/dev/null)
echo "Estado de Elasticsearch desde Kibana: $elasticsearch_status" >> $LOG_FILE

if [ "$elasticsearch_status" != "green" ]; then
  echo "ADVERTENCIA: Estado de Elasticsearch no es green" >> $LOG_FILE
fi

# Verificar logs de errores recientes
echo "\n=== ERRORES RECIENTES ===" >> $LOG_FILE
if [ -f "$KIBANA_LOG" ]; then
  tail -50 "$KIBANA_LOG" | grep -i "error\|fatal\|exception" >> $LOG_FILE
fi

# Verificar uso de memoria
echo "\n=== USO DE MEMORIA ===" >> $LOG_FILE
kibana_pid=$(pgrep -f kibana)
if [ -n "$kibana_pid" ]; then
  ps -p $kibana_pid -o pid,ppid,cmd,%mem,%cpu >> $LOG_FILE
fi

# Verificar espacio en disco
echo "\n=== ESPACIO EN DISCO ===" >> $LOG_FILE
df -h /var/log/kibana/ >> $LOG_FILE
df -h /usr/share/kibana/ >> $LOG_FILE

echo "[$DATE] Verificación diaria completada" >> $LOG_FILE
```

#### 2. Monitoreo de Dashboards
```bash
#!/bin/bash
# Script: dashboard_monitoring.sh

DATE=$(date +"%Y-%m-%d %H:%M:%S")
LOG_FILE="/var/log/kibana_dashboards.log"
KIBANA_URL="http://localhost:5601"
API_KEY="your-api-key-here"  # Configurar API key

echo "[$DATE] Monitoreando dashboards de Kibana" >> $LOG_FILE

# Verificar dashboards críticos
echo "=== VERIFICACIÓN DE DASHBOARDS CRÍTICOS ===" >> $LOG_FILE

critical_dashboards=(
  "security-overview"
  "threat-detection"
  "network-monitoring"
  "system-performance"
)

for dashboard in "${critical_dashboards[@]}"; do
  echo "Verificando dashboard: $dashboard" >> $LOG_FILE
  
  # Buscar dashboard por título
  dashboard_response=$(curl -s -H "kbn-xsrf: true" -H "Authorization: ApiKey $API_KEY" \
    "$KIBANA_URL/api/saved_objects/_find?type=dashboard&search_fields=title&search=$dashboard")
  
  dashboard_count=$(echo "$dashboard_response" | jq -r '.total' 2>/dev/null)
  
  if [ "$dashboard_count" = "0" ] || [ "$dashboard_count" = "null" ]; then
    echo "ERROR: Dashboard '$dashboard' no encontrado" >> $LOG_FILE
    echo "ERROR: Dashboard crítico '$dashboard' no encontrado" | mail -s "Kibana Dashboard Alert" admin@company.com
  else
    echo "OK: Dashboard '$dashboard' encontrado" >> $LOG_FILE
  fi
done

# Verificar visualizaciones rotas
echo "\n=== VERIFICACIÓN DE VISUALIZACIONES ===" >> $LOG_FILE

# Obtener todas las visualizaciones
vis_response=$(curl -s -H "kbn-xsrf: true" -H "Authorization: ApiKey $API_KEY" \
  "$KIBANA_URL/api/saved_objects/_find?type=visualization&per_page=1000")

vis_count=$(echo "$vis_response" | jq -r '.total' 2>/dev/null)
echo "Total de visualizaciones: $vis_count" >> $LOG_FILE

# Verificar patrones de índices
echo "\n=== VERIFICACIÓN DE PATRONES DE ÍNDICES ===" >> $LOG_FILE

index_patterns_response=$(curl -s -H "kbn-xsrf: true" -H "Authorization: ApiKey $API_KEY" \
  "$KIBANA_URL/api/saved_objects/_find?type=index-pattern")

index_patterns_count=$(echo "$index_patterns_response" | jq -r '.total' 2>/dev/null)
echo "Total de patrones de índices: $index_patterns_count" >> $LOG_FILE

# Verificar patrones críticos
critical_patterns=(
  "wazuh-alerts-*"
  "filebeat-*"
  "suricata-*"
  "system-*"
)

for pattern in "${critical_patterns[@]}"; do
  pattern_exists=$(echo "$index_patterns_response" | jq -r ".saved_objects[] | select(.attributes.title == \"$pattern\") | .id" 2>/dev/null)
  
  if [ -z "$pattern_exists" ]; then
    echo "ERROR: Patrón de índice '$pattern' no encontrado" >> $LOG_FILE
    echo "ERROR: Patrón de índice crítico '$pattern' no encontrado" | mail -s "Kibana Index Pattern Alert" admin@company.com
  else
    echo "OK: Patrón de índice '$pattern' encontrado" >> $LOG_FILE
  fi
done

echo "[$DATE] Monitoreo de dashboards completado" >> $LOG_FILE
```

#### 3. Verificación de Rendimiento
```bash
#!/bin/bash
# Script: kibana_performance_check.sh

DATE=$(date +"%Y-%m-%d %H:%M:%S")
LOG_FILE="/var/log/kibana_performance.log"
KIBANA_URL="http://localhost:5601"
KIBANA_LOG="/var/log/kibana/kibana.log"

echo "[$DATE] Verificando rendimiento de Kibana" >> $LOG_FILE

# Medir tiempo de respuesta
echo "=== TIEMPO DE RESPUESTA ===" >> $LOG_FILE
start_time=$(date +%s.%N)
response=$(curl -s -w "Time: %{time_total}s\nHTTP Code: %{http_code}\n" "$KIBANA_URL/api/status")
end_time=$(date +%s.%N)
response_time=$(echo "$end_time - $start_time" | bc)

echo "Tiempo de respuesta de API: ${response_time}s" >> $LOG_FILE
echo "$response" >> $LOG_FILE

# Verificar si el tiempo de respuesta es aceptable (< 5 segundos)
if (( $(echo "$response_time > 5" | bc -l) )); then
  echo "ADVERTENCIA: Tiempo de respuesta alto: ${response_time}s" >> $LOG_FILE
  echo "ADVERTENCIA: Kibana responde lentamente (${response_time}s)" | mail -s "Kibana Performance Alert" admin@company.com
fi

# Verificar uso de CPU y memoria
echo "\n=== USO DE RECURSOS ===" >> $LOG_FILE
kibana_pid=$(pgrep -f kibana)
if [ -n "$kibana_pid" ]; then
  echo "PID de Kibana: $kibana_pid" >> $LOG_FILE
  
  # CPU y memoria
  ps -p $kibana_pid -o pid,ppid,cmd,%mem,%cpu --no-headers >> $LOG_FILE
  
  # Memoria detallada
  if [ -f "/proc/$kibana_pid/status" ]; then
    echo "\nMemoria detallada:" >> $LOG_FILE
    grep -E "VmSize|VmRSS|VmData" "/proc/$kibana_pid/status" >> $LOG_FILE
  fi
fi

# Verificar logs de rendimiento
echo "\n=== LOGS DE RENDIMIENTO ===" >> $LOG_FILE
if [ -f "$KIBANA_LOG" ]; then
  # Buscar consultas lentas
  tail -1000 "$KIBANA_LOG" | grep -i "slow\|timeout\|took.*ms" | tail -10 >> $LOG_FILE
fi

# Verificar conexiones activas
echo "\n=== CONEXIONES ACTIVAS ===" >> $LOG_FILE
netstat -an | grep :5601 | wc -l >> $LOG_FILE

echo "[$DATE] Verificación de rendimiento completada" >> $LOG_FILE
```

### Mantenimiento Semanal

#### 1. Limpieza de Logs
```bash
#!/bin/bash
# Script: weekly_kibana_cleanup.sh

DATE=$(date +"%Y-%m-%d %H:%M:%S")
LOG_FILE="/var/log/kibana_maintenance.log"
KIBANA_LOG_DIR="/var/log/kibana"
RETENTION_DAYS=14

echo "[$DATE] Iniciando limpieza semanal de Kibana" >> $LOG_FILE

# Verificar espacio antes de la limpieza
echo "=== ESPACIO ANTES DE LIMPIEZA ===" >> $LOG_FILE
du -sh $KIBANA_LOG_DIR >> $LOG_FILE

# Comprimir logs antiguos
echo "\n=== COMPRIMIENDO LOGS ANTIGUOS ===" >> $LOG_FILE
find $KIBANA_LOG_DIR -name "*.log" -mtime +7 -exec gzip {} \; >> $LOG_FILE 2>&1

# Eliminar logs muy antiguos
echo "\n=== ELIMINANDO LOGS ANTIGUOS (>$RETENTION_DAYS días) ===" >> $LOG_FILE
find $KIBANA_LOG_DIR -name "*.gz" -mtime +$RETENTION_DAYS -delete >> $LOG_FILE 2>&1

# Limpiar archivos temporales
echo "\n=== LIMPIANDO ARCHIVOS TEMPORALES ===" >> $LOG_FILE
find /tmp -name "kibana*" -mtime +1 -delete >> $LOG_FILE 2>&1
find /var/tmp -name "kibana*" -mtime +1 -delete >> $LOG_FILE 2>&1

# Limpiar cache de Kibana
echo "\n=== LIMPIANDO CACHE ===" >> $LOG_FILE
if [ -d "/usr/share/kibana/optimize" ]; then
  rm -rf /usr/share/kibana/optimize/.cache/* >> $LOG_FILE 2>&1
fi

# Verificar espacio después de la limpieza
echo "\n=== ESPACIO DESPUÉS DE LIMPIEZA ===" >> $LOG_FILE
du -sh $KIBANA_LOG_DIR >> $LOG_FILE

echo "[$DATE] Limpieza semanal completada" >> $LOG_FILE
```

#### 2. Backup de Configuraciones
```bash
#!/bin/bash
# Script: backup_kibana_config.sh

DATE=$(date +"%Y-%m-%d")
BACKUP_DIR="/backup/kibana/$DATE"
LOG_FILE="/var/log/kibana_backup.log"
KIBANA_URL="http://localhost:5601"
API_KEY="your-api-key-here"

echo "[$(date)] Iniciando backup de configuraciones de Kibana" >> $LOG_FILE

# Crear directorio de backup
mkdir -p "$BACKUP_DIR" >> $LOG_FILE 2>&1

# Backup de configuración principal
echo "=== BACKUP DE CONFIGURACIÓN PRINCIPAL ===" >> $LOG_FILE
cp /etc/kibana/kibana.yml "$BACKUP_DIR/" >> $LOG_FILE 2>&1

# Backup de dashboards
echo "\n=== BACKUP DE DASHBOARDS ===" >> $LOG_FILE
curl -s -H "kbn-xsrf: true" -H "Authorization: ApiKey $API_KEY" \
  "$KIBANA_URL/api/saved_objects/_export" \
  -H "Content-Type: application/json" \
  -d '{"type": "dashboard"}' \
  > "$BACKUP_DIR/dashboards.ndjson" 2>> $LOG_FILE

# Backup de visualizaciones
echo "\n=== BACKUP DE VISUALIZACIONES ===" >> $LOG_FILE
curl -s -H "kbn-xsrf: true" -H "Authorization: ApiKey $API_KEY" \
  "$KIBANA_URL/api/saved_objects/_export" \
  -H "Content-Type: application/json" \
  -d '{"type": "visualization"}' \
  > "$BACKUP_DIR/visualizations.ndjson" 2>> $LOG_FILE

# Backup de patrones de índices
echo "\n=== BACKUP DE PATRONES DE ÍNDICES ===" >> $LOG_FILE
curl -s -H "kbn-xsrf: true" -H "Authorization: ApiKey $API_KEY" \
  "$KIBANA_URL/api/saved_objects/_export" \
  -H "Content-Type: application/json" \
  -d '{"type": "index-pattern"}' \
  > "$BACKUP_DIR/index-patterns.ndjson" 2>> $LOG_FILE

# Backup de búsquedas guardadas
echo "\n=== BACKUP DE BÚSQUEDAS GUARDADAS ===" >> $LOG_FILE
curl -s -H "kbn-xsrf: true" -H "Authorization: ApiKey $API_KEY" \
  "$KIBANA_URL/api/saved_objects/_export" \
  -H "Content-Type: application/json" \
  -d '{"type": "search"}' \
  > "$BACKUP_DIR/searches.ndjson" 2>> $LOG_FILE

# Backup completo de todos los objetos
echo "\n=== BACKUP COMPLETO ===" >> $LOG_FILE
curl -s -H "kbn-xsrf: true" -H "Authorization: ApiKey $API_KEY" \
  "$KIBANA_URL/api/saved_objects/_export" \
  -H "Content-Type: application/json" \
  -d '{"excludeExportDetails": true}' \
  > "$BACKUP_DIR/all-objects.ndjson" 2>> $LOG_FILE

# Comprimir backup
echo "\n=== COMPRIMIENDO BACKUP ===" >> $LOG_FILE
tar -czf "$BACKUP_DIR.tar.gz" -C "$(dirname $BACKUP_DIR)" "$(basename $BACKUP_DIR)" >> $LOG_FILE 2>&1
rm -rf "$BACKUP_DIR" >> $LOG_FILE 2>&1

# Verificar backup
if [ -f "$BACKUP_DIR.tar.gz" ]; then
  backup_size=$(du -h "$BACKUP_DIR.tar.gz" | cut -f1)
  echo "Backup completado: $BACKUP_DIR.tar.gz ($backup_size)" >> $LOG_FILE
else
  echo "ERROR: Backup falló" >> $LOG_FILE
  echo "ERROR: Backup de Kibana falló" | mail -s "Kibana Backup Error" admin@company.com
fi

# Limpiar backups antiguos (mantener últimos 30 días)
find /backup/kibana/ -name "*.tar.gz" -mtime +30 -delete >> $LOG_FILE 2>&1

echo "[$(date)] Backup de configuraciones completado" >> $LOG_FILE
```

#### 3. Optimización de Índices
```bash
#!/bin/bash
# Script: optimize_kibana_indices.sh

DATE=$(date +"%Y-%m-%d %H:%M:%S")
LOG_FILE="/var/log/kibana_optimization.log"
KIBANA_URL="http://localhost:5601"
ELASTICSEARCH_URL="http://localhost:9200"
API_KEY="your-api-key-here"

echo "[$DATE] Iniciando optimización de índices" >> $LOG_FILE

# Verificar patrones de índices sin datos
echo "=== VERIFICANDO PATRONES SIN DATOS ===" >> $LOG_FILE

# Obtener todos los patrones de índices
patterns_response=$(curl -s -H "kbn-xsrf: true" -H "Authorization: ApiKey $API_KEY" \
  "$KIBANA_URL/api/saved_objects/_find?type=index-pattern&per_page=1000")

echo "$patterns_response" | jq -r '.saved_objects[].attributes.title' 2>/dev/null | while read pattern; do
  if [ -n "$pattern" ]; then
    echo "Verificando patrón: $pattern" >> $LOG_FILE
    
    # Verificar si existen índices que coincidan con el patrón
    indices_count=$(curl -s "$ELASTICSEARCH_URL/_cat/indices/$pattern?h=index" | wc -l)
    
    if [ "$indices_count" -eq 0 ]; then
      echo "ADVERTENCIA: Patrón '$pattern' no tiene índices coincidentes" >> $LOG_FILE
    else
      echo "OK: Patrón '$pattern' tiene $indices_count índices" >> $LOG_FILE
    fi
  fi
done

# Verificar campos de patrones de índices
echo "\n=== VERIFICANDO CAMPOS DE PATRONES ===" >> $LOG_FILE

# Refrescar campos de patrones críticos
critical_patterns=(
  "wazuh-alerts-*"
  "filebeat-*"
  "suricata-*"
)

for pattern in "${critical_patterns[@]}"; do
  echo "Refrescando campos para: $pattern" >> $LOG_FILE
  
  # Buscar el ID del patrón
  pattern_id=$(echo "$patterns_response" | jq -r ".saved_objects[] | select(.attributes.title == \"$pattern\") | .id" 2>/dev/null)
  
  if [ -n "$pattern_id" ]; then
    # Refrescar campos
    refresh_response=$(curl -s -X POST -H "kbn-xsrf: true" -H "Authorization: ApiKey $API_KEY" \
      "$KIBANA_URL/api/index_patterns/index_pattern/$pattern_id/refresh_fields")
    
    echo "Campos refrescados para $pattern" >> $LOG_FILE
  else
    echo "ERROR: No se encontró el patrón $pattern" >> $LOG_FILE
  fi
done

echo "[$DATE] Optimización de índices completada" >> $LOG_FILE
```

### Mantenimiento Mensual

#### 1. Análisis de Uso
```bash
#!/bin/bash
# Script: monthly_usage_analysis.sh

DATE=$(date +"%Y-%m-%d")
REPORT_FILE="/var/log/kibana_monthly_report_$(date +%Y%m).log"
KIBANA_URL="http://localhost:5601"
KIBANA_LOG="/var/log/kibana/kibana.log"
API_KEY="your-api-key-here"

echo "[$(date)] Generando reporte mensual de uso de Kibana" >> $REPORT_FILE

# Estadísticas generales
echo "=== ESTADÍSTICAS GENERALES ===" >> $REPORT_FILE
kibana_version=$(curl -s "$KIBANA_URL/api/status" | jq -r '.version.number' 2>/dev/null)
echo "Versión de Kibana: $kibana_version" >> $REPORT_FILE
echo "Fecha del reporte: $DATE" >> $REPORT_FILE

# Contar objetos guardados
echo "\n=== OBJETOS GUARDADOS ===" >> $REPORT_FILE

# Dashboards
dashboards_count=$(curl -s -H "kbn-xsrf: true" -H "Authorization: ApiKey $API_KEY" \
  "$KIBANA_URL/api/saved_objects/_find?type=dashboard&per_page=1" | jq -r '.total' 2>/dev/null)
echo "Total de dashboards: $dashboards_count" >> $REPORT_FILE

# Visualizaciones
visualizations_count=$(curl -s -H "kbn-xsrf: true" -H "Authorization: ApiKey $API_KEY" \
  "$KIBANA_URL/api/saved_objects/_find?type=visualization&per_page=1" | jq -r '.total' 2>/dev/null)
echo "Total de visualizaciones: $visualizations_count" >> $REPORT_FILE

# Búsquedas guardadas
searches_count=$(curl -s -H "kbn-xsrf: true" -H "Authorization: ApiKey $API_KEY" \
  "$KIBANA_URL/api/saved_objects/_find?type=search&per_page=1" | jq -r '.total' 2>/dev/null)
echo "Total de búsquedas guardadas: $searches_count" >> $REPORT_FILE

# Patrones de índices
index_patterns_count=$(curl -s -H "kbn-xsrf: true" -H "Authorization: ApiKey $API_KEY" \
  "$KIBANA_URL/api/saved_objects/_find?type=index-pattern&per_page=1" | jq -r '.total' 2>/dev/null)
echo "Total de patrones de índices: $index_patterns_count" >> $REPORT_FILE

# Análisis de logs del mes
echo "\n=== ANÁLISIS DE LOGS DEL MES ===" >> $REPORT_FILE
if [ -f "$KIBANA_LOG" ]; then
  current_month=$(date +"%Y-%m")
  
  # Errores del mes
  errors_count=$(grep "$current_month" "$KIBANA_LOG" | grep -i "error" | wc -l)
  echo "Errores del mes: $errors_count" >> $REPORT_FILE
  
  # Advertencias del mes
  warnings_count=$(grep "$current_month" "$KIBANA_LOG" | grep -i "warn" | wc -l)
  echo "Advertencias del mes: $warnings_count" >> $REPORT_FILE
  
  # Top errores
  echo "\nTop 5 errores más frecuentes:" >> $REPORT_FILE
  grep "$current_month" "$KIBANA_LOG" | grep -i "error" | \
    sed 's/.*ERROR/ERROR/' | sort | uniq -c | sort -nr | head -5 >> $REPORT_FILE
fi

# Análisis de rendimiento
echo "\n=== ANÁLISIS DE RENDIMIENTO ===" >> $REPORT_FILE

# Tiempo de respuesta promedio
if [ -f "$KIBANA_LOG" ]; then
  avg_response_time=$(grep "$current_month" "$KIBANA_LOG" | \
    grep -o "took [0-9]*ms" | \
    sed 's/took //g' | sed 's/ms//g' | \
    awk '{sum+=$1; count++} END {if(count>0) print sum/count; else print 0}')
  echo "Tiempo de respuesta promedio: ${avg_response_time}ms" >> $REPORT_FILE
fi

# Uso de recursos
echo "\n=== USO DE RECURSOS ===" >> $REPORT_FILE
kibana_pid=$(pgrep -f kibana)
if [ -n "$kibana_pid" ]; then
  echo "PID de Kibana: $kibana_pid" >> $REPORT_FILE
  ps -p $kibana_pid -o pid,ppid,cmd,%mem,%cpu --no-headers >> $REPORT_FILE
fi

# Tamaño de logs
echo "\n=== TAMAÑO DE LOGS ===" >> $REPORT_FILE
echo "Tamaño total de logs: $(du -sh /var/log/kibana/ | cut -f1)" >> $REPORT_FILE

echo "[$(date)] Reporte mensual completado" >> $REPORT_FILE
```

#### 2. Actualización de Dashboards
```bash
#!/bin/bash
# Script: update_dashboards.sh

DATE=$(date +"%Y-%m-%d %H:%M:%S")
LOG_FILE="/var/log/kibana_maintenance.log"
KIBANA_URL="http://localhost:5601"
API_KEY="your-api-key-here"
DASHBOARDS_DIR="/opt/siem/dashboards"

echo "[$DATE] Iniciando actualización de dashboards" >> $LOG_FILE

# Crear backup antes de actualizar
echo "=== CREANDO BACKUP ANTES DE ACTUALIZACIÓN ===" >> $LOG_FILE
backup_dir="/backup/kibana/pre-update-$(date +%Y%m%d)"
mkdir -p "$backup_dir" >> $LOG_FILE 2>&1

# Exportar dashboards actuales
curl -s -H "kbn-xsrf: true" -H "Authorization: ApiKey $API_KEY" \
  "$KIBANA_URL/api/saved_objects/_export" \
  -H "Content-Type: application/json" \
  -d '{"type": "dashboard"}' \
  > "$backup_dir/current-dashboards.ndjson" 2>> $LOG_FILE

# Verificar si hay nuevos dashboards para importar
echo "\n=== VERIFICANDO NUEVOS DASHBOARDS ===" >> $LOG_FILE
if [ -d "$DASHBOARDS_DIR" ]; then
  for dashboard_file in "$DASHBOARDS_DIR"/*.ndjson; do
    if [ -f "$dashboard_file" ]; then
      echo "Importando: $(basename $dashboard_file)" >> $LOG_FILE
      
      # Importar dashboard
      import_response=$(curl -s -X POST -H "kbn-xsrf: true" -H "Authorization: ApiKey $API_KEY" \
        "$KIBANA_URL/api/saved_objects/_import" \
        -H "Content-Type: application/json" \
        --form file=@"$dashboard_file")
      
      # Verificar resultado de importación
      success_count=$(echo "$import_response" | jq -r '.successCount' 2>/dev/null)
      error_count=$(echo "$import_response" | jq -r '.errorCount' 2>/dev/null)
      
      echo "Importación de $(basename $dashboard_file): $success_count éxitos, $error_count errores" >> $LOG_FILE
      
      if [ "$error_count" != "0" ] && [ "$error_count" != "null" ]; then
        echo "Errores en importación:" >> $LOG_FILE
        echo "$import_response" | jq -r '.errors[]' >> $LOG_FILE 2>/dev/null
      fi
    fi
  done
else
  echo "Directorio de dashboards no encontrado: $DASHBOARDS_DIR" >> $LOG_FILE
fi

# Verificar dashboards después de actualización
echo "\n=== VERIFICANDO DASHBOARDS DESPUÉS DE ACTUALIZACIÓN ===" >> $LOG_FILE
dashboards_after=$(curl -s -H "kbn-xsrf: true" -H "Authorization: ApiKey $API_KEY" \
  "$KIBANA_URL/api/saved_objects/_find?type=dashboard&per_page=1" | jq -r '.total' 2>/dev/null)
echo "Total de dashboards después de actualización: $dashboards_after" >> $LOG_FILE

echo "[$DATE] Actualización de dashboards completada" >> $LOG_FILE
```

## 🔧 Procedimientos de Mantenimiento Específicos

### Gestión de Patrones de Índices

#### Crear Patrón de Índice
```bash
#!/bin/bash
# Script: create_index_pattern.sh

PATTERN_NAME="$1"
TIME_FIELD="$2"
KIBANA_URL="http://localhost:5601"
API_KEY="your-api-key-here"

if [ -z "$PATTERN_NAME" ]; then
  echo "Uso: $0 <pattern_name> [time_field]"
  echo "Ejemplo: $0 'new-logs-*' '@timestamp'"
  exit 1
fi

echo "Creando patrón de índice: $PATTERN_NAME"

# Preparar payload
if [ -n "$TIME_FIELD" ]; then
  payload=$(cat <<EOF
{
  "attributes": {
    "title": "$PATTERN_NAME",
    "timeFieldName": "$TIME_FIELD"
  }
}
EOF
)
else
  payload=$(cat <<EOF
{
  "attributes": {
    "title": "$PATTERN_NAME"
  }
}
EOF
)
fi

# Crear patrón de índice
response=$(curl -s -X POST -H "kbn-xsrf: true" -H "Authorization: ApiKey $API_KEY" \
  -H "Content-Type: application/json" \
  "$KIBANA_URL/api/saved_objects/index-pattern" \
  -d "$payload")

# Verificar resultado
pattern_id=$(echo "$response" | jq -r '.id' 2>/dev/null)

if [ "$pattern_id" != "null" ] && [ -n "$pattern_id" ]; then
  echo "Patrón de índice creado exitosamente: $pattern_id"
  
  # Refrescar campos
  echo "Refrescando campos..."
  curl -s -X POST -H "kbn-xsrf: true" -H "Authorization: ApiKey $API_KEY" \
    "$KIBANA_URL/api/index_patterns/index_pattern/$pattern_id/refresh_fields" > /dev/null
  
  echo "Patrón de índice '$PATTERN_NAME' creado y configurado"
else
  echo "ERROR: No se pudo crear el patrón de índice"
  echo "Respuesta: $response"
  exit 1
fi
```

#### Eliminar Patrón de Índice
```bash
#!/bin/bash
# Script: delete_index_pattern.sh

PATTERN_NAME="$1"
KIBANA_URL="http://localhost:5601"
API_KEY="your-api-key-here"

if [ -z "$PATTERN_NAME" ]; then
  echo "Uso: $0 <pattern_name>"
  exit 1
fi

echo "Buscando patrón de índice: $PATTERN_NAME"

# Buscar patrón por nombre
pattern_response=$(curl -s -H "kbn-xsrf: true" -H "Authorization: ApiKey $API_KEY" \
  "$KIBANA_URL/api/saved_objects/_find?type=index-pattern&search_fields=title&search=$PATTERN_NAME")

pattern_id=$(echo "$pattern_response" | jq -r ".saved_objects[] | select(.attributes.title == \"$PATTERN_NAME\") | .id" 2>/dev/null)

if [ -n "$pattern_id" ] && [ "$pattern_id" != "null" ]; then
  echo "Eliminando patrón de índice: $pattern_id"
  
  # Eliminar patrón
  delete_response=$(curl -s -X DELETE -H "kbn-xsrf: true" -H "Authorization: ApiKey $API_KEY" \
    "$KIBANA_URL/api/saved_objects/index-pattern/$pattern_id")
  
  echo "Patrón de índice '$PATTERN_NAME' eliminado"
else
  echo "ERROR: Patrón de índice '$PATTERN_NAME' no encontrado"
  exit 1
fi
```

### Gestión de Usuarios y Roles

#### Crear Usuario
```bash
#!/bin/bash
# Script: create_kibana_user.sh

USERNAME="$1"
PASSWORD="$2"
ROLES="$3"
ELASTICSEARCH_URL="http://localhost:9200"
ELASTIC_USER="elastic"
ELASTIC_PASSWORD="changeme"

if [ -z "$USERNAME" ] || [ -z "$PASSWORD" ] || [ -z "$ROLES" ]; then
  echo "Uso: $0 <username> <password> <roles>"
  echo "Ejemplo: $0 'analyst' 'password123' 'kibana_user,monitoring_user'"
  exit 1
fi

echo "Creando usuario: $USERNAME"

# Crear usuario
user_payload=$(cat <<EOF
{
  "password": "$PASSWORD",
  "roles": [$(echo "$ROLES" | sed 's/,/","/g' | sed 's/^/"/' | sed 's/$/"/')],
  "full_name": "$USERNAME",
  "email": "$USERNAME@company.com"
}
EOF
)

response=$(curl -s -X POST -u "$ELASTIC_USER:$ELASTIC_PASSWORD" \
  -H "Content-Type: application/json" \
  "$ELASTICSEARCH_URL/_security/user/$USERNAME" \
  -d "$user_payload")

if echo "$response" | grep -q '"created":true'; then
  echo "Usuario '$USERNAME' creado exitosamente"
else
  echo "ERROR: No se pudo crear el usuario"
  echo "Respuesta: $response"
  exit 1
fi
```

## 🚨 Procedimientos de Emergencia

### Recuperación de Kibana
```bash
#!/bin/bash
# Script: emergency_kibana_recovery.sh

KIBANA_CONFIG="/etc/kibana/kibana.yml"
KIBANA_LOG="/var/log/kibana/kibana.log"
BACKUP_DIR="/backup/kibana"
LOG_FILE="/var/log/kibana_emergency.log"

echo "[$(date)] Iniciando recuperación de emergencia de Kibana" >> $LOG_FILE

# Verificar estado actual
echo "=== ESTADO ACTUAL ===" >> $LOG_FILE
systemctl status kibana >> $LOG_FILE 2>&1

# Intentar reinicio simple
echo "\n=== INTENTANDO REINICIO ===" >> $LOG_FILE
systemctl restart kibana >> $LOG_FILE 2>&1
sleep 30

# Verificar si Kibana responde
response_code=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:5601")
echo "Código de respuesta después del reinicio: $response_code" >> $LOG_FILE

if [ "$response_code" = "200" ]; then
  echo "ÉXITO: Kibana recuperado con reinicio simple" >> $LOG_FILE
  exit 0
fi

# Si el reinicio falla, verificar configuración
echo "\n=== VERIFICANDO CONFIGURACIÓN ===" >> $LOG_FILE
if [ -f "$KIBANA_CONFIG" ]; then
  echo "Verificando sintaxis de configuración..." >> $LOG_FILE
  
  # Verificar sintaxis YAML básica
  python3 -c "import yaml; yaml.safe_load(open('$KIBANA_CONFIG'))" >> $LOG_FILE 2>&1
  
  if [ $? -ne 0 ]; then
    echo "ERROR: Configuración YAML inválida" >> $LOG_FILE
    
    # Restaurar configuración desde backup
    if [ -f "$BACKUP_DIR/latest/kibana.yml" ]; then
      echo "Restaurando configuración desde backup" >> $LOG_FILE
      cp "$BACKUP_DIR/latest/kibana.yml" "$KIBANA_CONFIG" >> $LOG_FILE 2>&1
    fi
  fi
fi

# Verificar conectividad con Elasticsearch
echo "\n=== VERIFICANDO ELASTICSEARCH ===" >> $LOG_FILE
es_response=$(curl -s "http://localhost:9200/_cluster/health")
echo "Estado de Elasticsearch: $es_response" >> $LOG_FILE

es_status=$(echo "$es_response" | jq -r '.status' 2>/dev/null)
if [ "$es_status" != "green" ] && [ "$es_status" != "yellow" ]; then
  echo "ERROR: Elasticsearch no está disponible" >> $LOG_FILE
  echo "ERROR: Elasticsearch no disponible para Kibana" | mail -s "Kibana Emergency" admin@company.com
fi

# Limpiar cache y archivos temporales
echo "\n=== LIMPIANDO CACHE ===" >> $LOG_FILE
rm -rf /usr/share/kibana/optimize/.cache/* >> $LOG_FILE 2>&1
rm -rf /tmp/kibana* >> $LOG_FILE 2>&1

# Verificar permisos
echo "\n=== VERIFICANDO PERMISOS ===" >> $LOG_FILE
chown -R kibana:kibana /usr/share/kibana >> $LOG_FILE 2>&1
chown -R kibana:kibana /var/log/kibana >> $LOG_FILE 2>&1
chmod 755 /usr/share/kibana >> $LOG_FILE 2>&1

# Intentar reinicio después de limpieza
echo "\n=== REINICIO DESPUÉS DE LIMPIEZA ===" >> $LOG_FILE
systemctl restart kibana >> $LOG_FILE 2>&1
sleep 30

# Verificación final
final_response=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:5601")
echo "Código de respuesta final: $final_response" >> $LOG_FILE

if [ "$final_response" = "200" ]; then
  echo "ÉXITO: Kibana recuperado exitosamente" >> $LOG_FILE
else
  echo "ERROR: No se pudo recuperar Kibana" >> $LOG_FILE
  echo "ERROR: Kibana no se pudo recuperar" | mail -s "Kibana Emergency" admin@company.com
fi

echo "[$(date)] Recuperación de emergencia completada" >> $LOG_FILE
```

### Restauración desde Backup
```bash
#!/bin/bash
# Script: restore_kibana_backup.sh

BACKUP_FILE="$1"
KIBANA_URL="http://localhost:5601"
API_KEY="your-api-key-here"
LOG_FILE="/var/log/kibana_restore.log"

if [ -z "$BACKUP_FILE" ]; then
  echo "Uso: $0 <backup_file.tar.gz>"
  exit 1
fi

if [ ! -f "$BACKUP_FILE" ]; then
  echo "ERROR: Archivo de backup no encontrado: $BACKUP_FILE"
  exit 1
fi

echo "[$(date)] Iniciando restauración desde backup" >> $LOG_FILE
echo "Archivo de backup: $BACKUP_FILE" >> $LOG_FILE

# Extraer backup
echo "=== EXTRAYENDO BACKUP ===" >> $LOG_FILE
temp_dir="/tmp/kibana_restore_$(date +%s)"
mkdir -p "$temp_dir" >> $LOG_FILE 2>&1
tar -xzf "$BACKUP_FILE" -C "$temp_dir" >> $LOG_FILE 2>&1

# Encontrar directorio extraído
backup_dir=$(find "$temp_dir" -type d -name "*kibana*" | head -1)
if [ -z "$backup_dir" ]; then
  backup_dir="$temp_dir"
fi

echo "Directorio de backup: $backup_dir" >> $LOG_FILE

# Restaurar configuración principal
echo "\n=== RESTAURANDO CONFIGURACIÓN ===" >> $LOG_FILE
if [ -f "$backup_dir/kibana.yml" ]; then
  cp "$backup_dir/kibana.yml" "/etc/kibana/kibana.yml" >> $LOG_FILE 2>&1
  echo "Configuración principal restaurada" >> $LOG_FILE
fi

# Restaurar objetos guardados
echo "\n=== RESTAURANDO OBJETOS GUARDADOS ===" >> $LOG_FILE

for object_file in "$backup_dir"/*.ndjson; do
  if [ -f "$object_file" ]; then
    echo "Restaurando: $(basename $object_file)" >> $LOG_FILE
    
    # Importar objetos
    import_response=$(curl -s -X POST -H "kbn-xsrf: true" -H "Authorization: ApiKey $API_KEY" \
      "$KIBANA_URL/api/saved_objects/_import?overwrite=true" \
      -H "Content-Type: application/json" \
      --form file=@"$object_file")
    
    success_count=$(echo "$import_response" | jq -r '.successCount' 2>/dev/null)
    error_count=$(echo "$import_response" | jq -r '.errorCount' 2>/dev/null)
    
    echo "$(basename $object_file): $success_count éxitos, $error_count errores" >> $LOG_FILE
  fi
done

# Reiniciar Kibana
echo "\n=== REINICIANDO KIBANA ===" >> $LOG_FILE
systemctl restart kibana >> $LOG_FILE 2>&1

# Verificar restauración
echo "\n=== VERIFICANDO RESTAURACIÓN ===" >> $LOG_FILE
sleep 30
response_code=$(curl -s -o /dev/null -w "%{http_code}" "$KIBANA_URL")
echo "Código de respuesta: $response_code" >> $LOG_FILE

if [ "$response_code" = "200" ]; then
  echo "ÉXITO: Restauración completada exitosamente" >> $LOG_FILE
else
  echo "ERROR: Problemas después de la restauración" >> $LOG_FILE
fi

# Limpiar archivos temporales
rm -rf "$temp_dir" >> $LOG_FILE 2>&1

echo "[$(date)] Restauración completada" >> $LOG_FILE
```

## 📊 Monitoreo y Alertas

### Script de Monitoreo Continuo
```bash
#!/bin/bash
# Script: continuous_kibana_monitoring.sh

KIBANA_URL="http://localhost:5601"
ALERT_EMAIL="admin@company.com"
CHECK_INTERVAL=300  # 5 minutos
MAX_RESPONSE_TIME=10  # segundos

while true; do
  # Verificar si Kibana está ejecutándose
  if ! systemctl is-active --quiet kibana; then
    echo "ALERTA: Kibana no está ejecutándose" | mail -s "Kibana Service Alert" $ALERT_EMAIL
  fi
  
  # Verificar tiempo de respuesta
  start_time=$(date +%s.%N)
  response_code=$(curl -s -o /dev/null -w "%{http_code}" "$KIBANA_URL")
  end_time=$(date +%s.%N)
  response_time=$(echo "$end_time - $start_time" | bc)
  
  if [ "$response_code" != "200" ]; then
    echo "ALERTA: Kibana no responde (HTTP $response_code)" | mail -s "Kibana Response Alert" $ALERT_EMAIL
  fi
  
  if (( $(echo "$response_time > $MAX_RESPONSE_TIME" | bc -l) )); then
    echo "ALERTA: Kibana responde lentamente (${response_time}s)" | mail -s "Kibana Performance Alert" $ALERT_EMAIL
  fi
  
  # Verificar uso de memoria
  kibana_pid=$(pgrep -f kibana)
  if [ -n "$kibana_pid" ]; then
    memory_usage=$(ps -p $kibana_pid -o %mem --no-headers | tr -d ' ')
    if (( $(echo "$memory_usage > 80" | bc -l) )); then
      echo "ALERTA: Alto uso de memoria en Kibana: ${memory_usage}%" | mail -s "Kibana Memory Alert" $ALERT_EMAIL
    fi
  fi
  
  # Verificar espacio en disco
  disk_usage=$(df /var/log/kibana | tail -1 | awk '{print $5}' | sed 's/%//')
  if [ $disk_usage -gt 85 ]; then
    echo "ALERTA: Poco espacio en disco para logs de Kibana: ${disk_usage}%" | mail -s "Kibana Disk Alert" $ALERT_EMAIL
  fi
  
  sleep $CHECK_INTERVAL
done
```

## 📋 Checklist de Mantenimiento

### Checklist Diario
- [ ] Verificar estado del servicio Kibana
- [ ] Comprobar tiempo de respuesta
- [ ] Verificar conectividad con Elasticsearch
- [ ] Revisar logs de errores
- [ ] Verificar dashboards críticos
- [ ] Comprobar uso de memoria y CPU

### Checklist Semanal
- [ ] Limpiar logs antiguos
- [ ] Crear backup de configuraciones
- [ ] Verificar patrones de índices
- [ ] Optimizar visualizaciones
- [ ] Revisar rendimiento general
- [ ] Actualizar campos de patrones

### Checklist Mensual
- [ ] Generar reporte de uso
- [ ] Actualizar dashboards
- [ ] Revisar usuarios y permisos
- [ ] Optimizar configuración
- [ ] Planificar actualizaciones
- [ ] Documentar cambios

## 📞 Contactos de Soporte

### Equipo Interno
```yaml
Administrador Principal:
  Nombre: [Nombre]
  Teléfono: [Teléfono]
  Email: [Email]

Equipo de Visualización:
  Nombre: [Nombre]
  Teléfono: [Teléfono]
  Email: [Email]
```

### Soporte Externo
```yaml
Elastic Support:
  Portal: https://support.elastic.co
  Documentación: https://www.elastic.co/guide/en/kibana/current/index.html
  Community: https://discuss.elastic.co/c/kibana

Consultor Elastic:
  Nombre: [Nombre]
  Teléfono: [Teléfono]
  Email: [Email]
```

## 📚 Referencias y Documentación

### Documentación Oficial
- [Kibana Guide](https://www.elastic.co/guide/en/kibana/current/index.html)
- [Kibana API](https://www.elastic.co/guide/en/kibana/current/api.html)
- [Elasticsearch Guide](https://www.elastic.co/guide/en/elasticsearch/reference/current/index.html)

### Herramientas Útiles
- [Kibana Dev Tools](https://www.elastic.co/guide/en/kibana/current/console-kibana.html)
- [Index Pattern Management](https://www.elastic.co/guide/en/kibana/current/managing-index-patterns.html)
- [Saved Objects API](https://www.elastic.co/guide/en/kibana/current/saved-objects-api.html)

---

**Documento clasificado como INTERNO**  
**Última actualización**: Diciembre 2024  
**Próxima revisión**: Marzo 2025  
**Aprobado por**: Administrador de Sistemas