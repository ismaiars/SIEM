# Runbook - Mantenimiento de Elasticsearch

## 📋 Información del Runbook

| Campo | Valor |
|-------|-------|
| **ID del Runbook** | RB-001-ES-MAINTENANCE |
| **Versión** | 1.0 |
| **Fecha de Creación** | Diciembre 2024 |
| **Última Actualización** | Diciembre 2024 |
| **Autor** | Equipo de Operaciones |
| **Clasificación** | INTERNO |
| **Frecuencia** | Diaria/Semanal/Mensual |

## 🎯 Objetivo y Alcance

### Objetivo
Proporcionar procedimientos estandarizados para el mantenimiento preventivo y correctivo de Elasticsearch, asegurando el rendimiento óptimo, disponibilidad y integridad de los datos del SIEM.

### Alcance
- Cluster de Elasticsearch (nodos master, data, ingest)
- Índices de logs de seguridad
- Plantillas de índices
- Políticas de lifecycle management (ILM)
- Snapshots y backups
- Monitoreo y alertas

### Prerrequisitos
- Acceso administrativo al cluster de Elasticsearch
- Conocimiento de APIs de Elasticsearch
- Herramientas de monitoreo configuradas
- Acceso a sistemas de backup

## 📅 Tareas de Mantenimiento

### Mantenimiento Diario

#### 1. Verificación del Estado del Cluster
```bash
#!/bin/bash
# Script: daily_cluster_check.sh

ES_HOST="localhost:9200"
DATE=$(date +"%Y-%m-%d %H:%M:%S")
LOG_FILE="/var/log/elasticsearch/maintenance.log"

echo "[$DATE] Iniciando verificación diaria del cluster" >> $LOG_FILE

# Verificar estado del cluster
echo "=== ESTADO DEL CLUSTER ===" >> $LOG_FILE
curl -s "$ES_HOST/_cluster/health?pretty" >> $LOG_FILE

# Verificar nodos
echo "\n=== NODOS ACTIVOS ===" >> $LOG_FILE
curl -s "$ES_HOST/_cat/nodes?v" >> $LOG_FILE

# Verificar índices
echo "\n=== ESTADO DE ÍNDICES ===" >> $LOG_FILE
curl -s "$ES_HOST/_cat/indices?v&s=index" >> $LOG_FILE

# Verificar shards no asignados
echo "\n=== SHARDS NO ASIGNADOS ===" >> $LOG_FILE
curl -s "$ES_HOST/_cat/shards?v" | grep UNASSIGNED >> $LOG_FILE

# Verificar uso de disco
echo "\n=== USO DE DISCO ===" >> $LOG_FILE
curl -s "$ES_HOST/_cat/allocation?v" >> $LOG_FILE

echo "[$DATE] Verificación diaria completada" >> $LOG_FILE
```

#### 2. Monitoreo de Rendimiento
```bash
#!/bin/bash
# Script: performance_check.sh

ES_HOST="localhost:9200"
DATE=$(date +"%Y-%m-%d %H:%M:%S")
LOG_FILE="/var/log/elasticsearch/performance.log"

echo "[$DATE] Iniciando verificación de rendimiento" >> $LOG_FILE

# Estadísticas del cluster
echo "=== ESTADÍSTICAS DEL CLUSTER ===" >> $LOG_FILE
curl -s "$ES_HOST/_cluster/stats?pretty" >> $LOG_FILE

# Estadísticas de nodos
echo "\n=== ESTADÍSTICAS DE NODOS ===" >> $LOG_FILE
curl -s "$ES_HOST/_nodes/stats?pretty" >> $LOG_FILE

# Tareas pendientes
echo "\n=== TAREAS PENDIENTES ===" >> $LOG_FILE
curl -s "$ES_HOST/_cat/pending_tasks?v" >> $LOG_FILE

# Thread pools
echo "\n=== THREAD POOLS ===" >> $LOG_FILE
curl -s "$ES_HOST/_cat/thread_pool?v" >> $LOG_FILE

# Hot threads
echo "\n=== HOT THREADS ===" >> $LOG_FILE
curl -s "$ES_HOST/_nodes/hot_threads" >> $LOG_FILE

echo "[$DATE] Verificación de rendimiento completada" >> $LOG_FILE
```

#### 3. Verificación de Ingestión de Datos
```bash
#!/bin/bash
# Script: ingestion_check.sh

ES_HOST="localhost:9200"
DATE=$(date +"%Y-%m-%d")
YESTERDAY=$(date -d "yesterday" +"%Y-%m-%d")
LOG_FILE="/var/log/elasticsearch/ingestion.log"

echo "[$(date)] Verificando ingestión de datos" >> $LOG_FILE

# Verificar documentos indexados hoy
echo "=== DOCUMENTOS INDEXADOS HOY ===" >> $LOG_FILE
for index in wazuh-alerts logstash suricata; do
  count=$(curl -s "$ES_HOST/${index}-${DATE}/_count" | jq '.count')
  echo "${index}-${DATE}: $count documentos" >> $LOG_FILE
done

# Comparar con ayer
echo "\n=== COMPARACIÓN CON AYER ===" >> $LOG_FILE
for index in wazuh-alerts logstash suricata; do
  today_count=$(curl -s "$ES_HOST/${index}-${DATE}/_count" | jq '.count')
  yesterday_count=$(curl -s "$ES_HOST/${index}-${YESTERDAY}/_count" | jq '.count')
  echo "${index}: Hoy=$today_count, Ayer=$yesterday_count" >> $LOG_FILE
  
  # Alerta si la diferencia es mayor al 50%
  if [ $today_count -lt $((yesterday_count / 2)) ]; then
    echo "ALERTA: Reducción significativa en $index" >> $LOG_FILE
    echo "ALERTA: Reducción significativa en $index" | mail -s "Elasticsearch Alert" admin@company.com
  fi
done

echo "[$(date)] Verificación de ingestión completada" >> $LOG_FILE
```

### Mantenimiento Semanal

#### 1. Optimización de Índices
```bash
#!/bin/bash
# Script: weekly_optimization.sh

ES_HOST="localhost:9200"
DATE=$(date +"%Y-%m-%d %H:%M:%S")
LOG_FILE="/var/log/elasticsearch/weekly_maintenance.log"

echo "[$DATE] Iniciando optimización semanal" >> $LOG_FILE

# Force merge de índices antiguos (más de 7 días)
echo "=== FORCE MERGE DE ÍNDICES ANTIGUOS ===" >> $LOG_FILE
for i in {7..30}; do
  old_date=$(date -d "$i days ago" +"%Y.%m.%d")
  
  # Verificar si el índice existe
  if curl -s "$ES_HOST/_cat/indices" | grep -q "$old_date"; then
    echo "Force merge para índices de $old_date" >> $LOG_FILE
    
    # Force merge con max_num_segments=1 para índices antiguos
    curl -X POST "$ES_HOST/*-$old_date/_forcemerge?max_num_segments=1" >> $LOG_FILE 2>&1
    
    # Hacer índices de solo lectura
    curl -X PUT "$ES_HOST/*-$old_date/_settings" -H 'Content-Type: application/json' -d'{
      "index.blocks.write": true
    }' >> $LOG_FILE 2>&1
  fi
done

# Limpiar cache
echo "\n=== LIMPIEZA DE CACHE ===" >> $LOG_FILE
curl -X POST "$ES_HOST/_cache/clear" >> $LOG_FILE 2>&1

echo "[$DATE] Optimización semanal completada" >> $LOG_FILE
```

#### 2. Verificación de Snapshots
```bash
#!/bin/bash
# Script: snapshot_verification.sh

ES_HOST="localhost:9200"
REPO_NAME="backup_repository"
DATE=$(date +"%Y-%m-%d %H:%M:%S")
LOG_FILE="/var/log/elasticsearch/snapshots.log"

echo "[$DATE] Verificando snapshots" >> $LOG_FILE

# Listar snapshots
echo "=== SNAPSHOTS DISPONIBLES ===" >> $LOG_FILE
curl -s "$ES_HOST/_snapshot/$REPO_NAME/_all?pretty" >> $LOG_FILE

# Verificar snapshot más reciente
echo "\n=== VERIFICACIÓN DEL SNAPSHOT MÁS RECIENTE ===" >> $LOG_FILE
latest_snapshot=$(curl -s "$ES_HOST/_snapshot/$REPO_NAME/_all" | jq -r '.snapshots | sort_by(.start_time) | last | .snapshot')

if [ "$latest_snapshot" != "null" ]; then
  echo "Verificando snapshot: $latest_snapshot" >> $LOG_FILE
  curl -s "$ES_HOST/_snapshot/$REPO_NAME/$latest_snapshot/_status?pretty" >> $LOG_FILE
else
  echo "ERROR: No se encontraron snapshots" >> $LOG_FILE
  echo "ERROR: No se encontraron snapshots" | mail -s "Elasticsearch Snapshot Alert" admin@company.com
fi

# Verificar espacio en repositorio de backup
echo "\n=== ESPACIO EN REPOSITORIO ===" >> $LOG_FILE
df -h /backup/elasticsearch >> $LOG_FILE

echo "[$DATE] Verificación de snapshots completada" >> $LOG_FILE
```

### Mantenimiento Mensual

#### 1. Limpieza de Índices Antiguos
```bash
#!/bin/bash
# Script: monthly_cleanup.sh

ES_HOST="localhost:9200"
RETENTION_DAYS=90
DATE=$(date +"%Y-%m-%d %H:%M:%S")
LOG_FILE="/var/log/elasticsearch/monthly_cleanup.log"

echo "[$DATE] Iniciando limpieza mensual" >> $LOG_FILE

# Eliminar índices más antiguos que RETENTION_DAYS
echo "=== ELIMINANDO ÍNDICES ANTIGUOS (>$RETENTION_DAYS días) ===" >> $LOG_FILE

for i in $(seq $RETENTION_DAYS 365); do
  old_date=$(date -d "$i days ago" +"%Y.%m.%d")
  
  # Buscar índices con esta fecha
  indices=$(curl -s "$ES_HOST/_cat/indices" | grep "$old_date" | awk '{print $3}')
  
  for index in $indices; do
    if [ ! -z "$index" ]; then
      echo "Eliminando índice: $index" >> $LOG_FILE
      curl -X DELETE "$ES_HOST/$index" >> $LOG_FILE 2>&1
    fi
  done
done

# Verificar espacio liberado
echo "\n=== ESPACIO EN DISCO DESPUÉS DE LIMPIEZA ===" >> $LOG_FILE
curl -s "$ES_HOST/_cat/allocation?v" >> $LOG_FILE

echo "[$DATE] Limpieza mensual completada" >> $LOG_FILE
```

#### 2. Análisis de Rendimiento Mensual
```bash
#!/bin/bash
# Script: monthly_performance_analysis.sh

ES_HOST="localhost:9200"
DATE=$(date +"%Y-%m-%d %H:%M:%S")
REPORT_FILE="/var/log/elasticsearch/monthly_report_$(date +%Y%m).log"

echo "[$DATE] Generando reporte mensual de rendimiento" >> $REPORT_FILE

# Estadísticas generales
echo "=== ESTADÍSTICAS GENERALES DEL CLUSTER ===" >> $REPORT_FILE
curl -s "$ES_HOST/_cluster/stats?pretty" >> $REPORT_FILE

# Top índices por tamaño
echo "\n=== TOP 10 ÍNDICES POR TAMAÑO ===" >> $REPORT_FILE
curl -s "$ES_HOST/_cat/indices?v&s=store.size:desc" | head -11 >> $REPORT_FILE

# Análisis de shards
echo "\n=== ANÁLISIS DE SHARDS ===" >> $REPORT_FILE
curl -s "$ES_HOST/_cat/shards?v" | awk '{print $1}' | sort | uniq -c | sort -nr >> $REPORT_FILE

# Estadísticas de búsqueda
echo "\n=== ESTADÍSTICAS DE BÚSQUEDA ===" >> $REPORT_FILE
curl -s "$ES_HOST/_nodes/stats/indices/search?pretty" >> $REPORT_FILE

# Estadísticas de indexación
echo "\n=== ESTADÍSTICAS DE INDEXACIÓN ===" >> $REPORT_FILE
curl -s "$ES_HOST/_nodes/stats/indices/indexing?pretty" >> $REPORT_FILE

echo "[$DATE] Reporte mensual completado" >> $REPORT_FILE
```

## 🔧 Procedimientos de Mantenimiento Específicos

### Gestión de Índices

#### Crear Plantilla de Índice
```bash
#!/bin/bash
# Crear plantilla para logs de seguridad

curl -X PUT "$ES_HOST/_index_template/security_logs" -H 'Content-Type: application/json' -d'{
  "index_patterns": ["security-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 1,
      "index.refresh_interval": "30s",
      "index.codec": "best_compression"
    },
    "mappings": {
      "properties": {
        "@timestamp": {
          "type": "date"
        },
        "source_ip": {
          "type": "ip"
        },
        "destination_ip": {
          "type": "ip"
        },
        "event_type": {
          "type": "keyword"
        },
        "severity": {
          "type": "keyword"
        },
        "message": {
          "type": "text",
          "analyzer": "standard"
        }
      }
    }
  },
  "priority": 100
}'
```

#### Configurar ILM Policy
```bash
#!/bin/bash
# Configurar política de lifecycle management

curl -X PUT "$ES_HOST/_ilm/policy/security_policy" -H 'Content-Type: application/json' -d'{
  "policy": {
    "phases": {
      "hot": {
        "actions": {
          "rollover": {
            "max_size": "10GB",
            "max_age": "1d"
          },
          "set_priority": {
            "priority": 100
          }
        }
      },
      "warm": {
        "min_age": "7d",
        "actions": {
          "set_priority": {
            "priority": 50
          },
          "allocate": {
            "number_of_replicas": 0
          },
          "forcemerge": {
            "max_num_segments": 1
          }
        }
      },
      "cold": {
        "min_age": "30d",
        "actions": {
          "set_priority": {
            "priority": 0
          },
          "allocate": {
            "number_of_replicas": 0
          }
        }
      },
      "delete": {
        "min_age": "90d",
        "actions": {
          "delete": {}
        }
      }
    }
  }
}'
```

### Gestión de Snapshots

#### Crear Snapshot Manual
```bash
#!/bin/bash
# Script: create_snapshot.sh

ES_HOST="localhost:9200"
REPO_NAME="backup_repository"
SNAPSHOT_NAME="manual_snapshot_$(date +%Y%m%d_%H%M%S)"

echo "Creando snapshot: $SNAPSHOT_NAME"

# Crear snapshot
curl -X PUT "$ES_HOST/_snapshot/$REPO_NAME/$SNAPSHOT_NAME?wait_for_completion=true" -H 'Content-Type: application/json' -d'{
  "indices": "*",
  "ignore_unavailable": true,
  "include_global_state": false,
  "metadata": {
    "taken_by": "manual_backup",
    "taken_because": "maintenance_procedure"
  }
}'

echo "\nSnapshot $SNAPSHOT_NAME creado exitosamente"
```

#### Restaurar desde Snapshot
```bash
#!/bin/bash
# Script: restore_snapshot.sh

ES_HOST="localhost:9200"
REPO_NAME="backup_repository"
SNAPSHOT_NAME="$1"

if [ -z "$SNAPSHOT_NAME" ]; then
  echo "Uso: $0 <snapshot_name>"
  exit 1
fi

echo "Restaurando desde snapshot: $SNAPSHOT_NAME"

# Cerrar índices que se van a restaurar
echo "Cerrando índices existentes..."
curl -X POST "$ES_HOST/_all/_close"

# Restaurar snapshot
echo "Iniciando restauración..."
curl -X POST "$ES_HOST/_snapshot/$REPO_NAME/$SNAPSHOT_NAME/_restore?wait_for_completion=true" -H 'Content-Type: application/json' -d'{
  "ignore_unavailable": true,
  "include_global_state": false
}'

echo "\nRestauración completada"
```

### Optimización de Rendimiento

#### Ajustar Configuración de Memoria
```bash
#!/bin/bash
# Script: optimize_memory.sh

ES_HOST="localhost:9200"

echo "Optimizando configuración de memoria"

# Limpiar cache de field data
curl -X POST "$ES_HOST/_cache/clear?fielddata=true"

# Limpiar cache de query
curl -X POST "$ES_HOST/_cache/clear?query=true"

# Limpiar cache de request
curl -X POST "$ES_HOST/_cache/clear?request=true"

# Configurar circuit breaker
curl -X PUT "$ES_HOST/_cluster/settings" -H 'Content-Type: application/json' -d'{
  "persistent": {
    "indices.breaker.fielddata.limit": "40%",
    "indices.breaker.request.limit": "60%",
    "indices.breaker.total.limit": "95%"
  }
}'

echo "Optimización de memoria completada"
```

#### Rebalancear Shards
```bash
#!/bin/bash
# Script: rebalance_shards.sh

ES_HOST="localhost:9200"

echo "Iniciando rebalanceo de shards"

# Habilitar rebalanceo
curl -X PUT "$ES_HOST/_cluster/settings" -H 'Content-Type: application/json' -d'{
  "persistent": {
    "cluster.routing.rebalance.enable": "all",
    "cluster.routing.allocation.allow_rebalance": "always",
    "cluster.routing.allocation.cluster_concurrent_rebalance": 2
  }
}'

# Monitorear progreso
echo "Monitoreando progreso del rebalanceo..."
while true; do
  relocating=$(curl -s "$ES_HOST/_cat/shards" | grep RELOCATING | wc -l)
  if [ $relocating -eq 0 ]; then
    echo "Rebalanceo completado"
    break
  else
    echo "Shards relocalizándose: $relocating"
    sleep 30
  fi
done
```

## 🚨 Procedimientos de Emergencia

### Recuperación de Cluster Rojo
```bash
#!/bin/bash
# Script: recover_red_cluster.sh

ES_HOST="localhost:9200"
LOG_FILE="/var/log/elasticsearch/emergency_recovery.log"

echo "[$(date)] Iniciando recuperación de cluster rojo" >> $LOG_FILE

# Verificar estado actual
echo "=== ESTADO ACTUAL ===" >> $LOG_FILE
curl -s "$ES_HOST/_cluster/health?pretty" >> $LOG_FILE

# Identificar shards problemáticos
echo "\n=== SHARDS PROBLEMÁTICOS ===" >> $LOG_FILE
curl -s "$ES_HOST/_cat/shards?v" | grep -E "(UNASSIGNED|INITIALIZING)" >> $LOG_FILE

# Intentar reasignar shards no asignados
echo "\n=== REASIGNANDO SHARDS ===" >> $LOG_FILE
curl -X POST "$ES_HOST/_cluster/reroute?retry_failed=true" >> $LOG_FILE 2>&1

# Si hay índices corruptos, intentar recuperación
echo "\n=== INTENTANDO RECUPERACIÓN DE ÍNDICES ===" >> $LOG_FILE
for index in $(curl -s "$ES_HOST/_cat/indices" | grep red | awk '{print $3}'); do
  echo "Recuperando índice: $index" >> $LOG_FILE
  curl -X POST "$ES_HOST/$index/_recovery" >> $LOG_FILE 2>&1
done

# Verificar estado después de la recuperación
echo "\n=== ESTADO DESPUÉS DE RECUPERACIÓN ===" >> $LOG_FILE
curl -s "$ES_HOST/_cluster/health?pretty" >> $LOG_FILE

echo "[$(date)] Recuperación completada" >> $LOG_FILE
```

### Liberación de Espacio de Emergencia
```bash
#!/bin/bash
# Script: emergency_space_cleanup.sh

ES_HOST="localhost:9200"
LOG_FILE="/var/log/elasticsearch/emergency_cleanup.log"

echo "[$(date)] Iniciando limpieza de emergencia" >> $LOG_FILE

# Verificar espacio actual
echo "=== ESPACIO ACTUAL ===" >> $LOG_FILE
df -h >> $LOG_FILE
curl -s "$ES_HOST/_cat/allocation?v" >> $LOG_FILE

# Eliminar índices más antiguos hasta liberar espacio
echo "\n=== ELIMINANDO ÍNDICES ANTIGUOS ===" >> $LOG_FILE
for i in $(seq 30 90); do
  old_date=$(date -d "$i days ago" +"%Y.%m.%d")
  indices=$(curl -s "$ES_HOST/_cat/indices" | grep "$old_date" | awk '{print $3}')
  
  for index in $indices; do
    if [ ! -z "$index" ]; then
      echo "Eliminando índice de emergencia: $index" >> $LOG_FILE
      curl -X DELETE "$ES_HOST/$index" >> $LOG_FILE 2>&1
      
      # Verificar si se liberó suficiente espacio
      disk_usage=$(df / | tail -1 | awk '{print $5}' | sed 's/%//')
      if [ $disk_usage -lt 80 ]; then
        echo "Espacio suficiente liberado" >> $LOG_FILE
        break 2
      fi
    fi
  done
done

# Force merge para liberar espacio adicional
echo "\n=== FORCE MERGE PARA LIBERAR ESPACIO ===" >> $LOG_FILE
curl -X POST "$ES_HOST/_forcemerge?only_expunge_deletes=true" >> $LOG_FILE 2>&1

echo "[$(date)] Limpieza de emergencia completada" >> $LOG_FILE
```

## 📊 Monitoreo y Alertas

### Script de Monitoreo Continuo
```bash
#!/bin/bash
# Script: continuous_monitoring.sh

ES_HOST="localhost:9200"
ALERT_EMAIL="admin@company.com"
THRESHOLD_DISK=85
THRESHOLD_MEMORY=90
THRESHOLD_CPU=80

while true; do
  # Verificar estado del cluster
  cluster_status=$(curl -s "$ES_HOST/_cluster/health" | jq -r '.status')
  
  if [ "$cluster_status" != "green" ]; then
    echo "ALERTA: Cluster status is $cluster_status" | mail -s "Elasticsearch Alert" $ALERT_EMAIL
  fi
  
  # Verificar uso de disco
  disk_usage=$(curl -s "$ES_HOST/_nodes/stats" | jq '.nodes[].fs.total.available_in_bytes')
  # Implementar lógica de verificación de disco
  
  # Verificar memoria
  memory_usage=$(curl -s "$ES_HOST/_nodes/stats" | jq '.nodes[].jvm.mem.heap_used_percent')
  # Implementar lógica de verificación de memoria
  
  # Verificar CPU
  cpu_usage=$(curl -s "$ES_HOST/_nodes/stats" | jq '.nodes[].os.cpu.percent')
  # Implementar lógica de verificación de CPU
  
  sleep 300  # Verificar cada 5 minutos
done
```

## 📋 Checklist de Mantenimiento

### Checklist Diario
- [ ] Verificar estado del cluster (verde/amarillo/rojo)
- [ ] Revisar logs de errores
- [ ] Verificar ingestión de datos
- [ ] Comprobar uso de disco
- [ ] Verificar rendimiento de consultas
- [ ] Revisar alertas de monitoreo

### Checklist Semanal
- [ ] Ejecutar force merge en índices antiguos
- [ ] Verificar snapshots
- [ ] Limpiar cache
- [ ] Revisar configuración de ILM
- [ ] Analizar logs de rendimiento
- [ ] Verificar integridad de datos

### Checklist Mensual
- [ ] Eliminar índices antiguos según política de retención
- [ ] Generar reporte de rendimiento
- [ ] Revisar y ajustar configuraciones
- [ ] Planificar actualizaciones
- [ ] Revisar capacidad y escalabilidad
- [ ] Actualizar documentación

## 📞 Contactos de Soporte

### Equipo Interno
```yaml
Administrador Principal:
  Nombre: [Nombre]
  Teléfono: [Teléfono]
  Email: [Email]

Equipo de Operaciones:
  Nombre: [Nombre]
  Teléfono: [Teléfono]
  Email: [Email]
```

### Soporte Externo
```yaml
Elastic Support:
  Portal: https://support.elastic.co
  Teléfono: [Teléfono de soporte]
  Email: [Email de soporte]

Consultor Elasticsearch:
  Nombre: [Nombre]
  Teléfono: [Teléfono]
  Email: [Email]
```

## 📚 Referencias y Documentación

### Documentación Oficial
- [Elasticsearch Reference](https://www.elastic.co/guide/en/elasticsearch/reference/current/index.html)
- [Elasticsearch Operations Guide](https://www.elastic.co/guide/en/elasticsearch/reference/current/operations.html)
- [Index Lifecycle Management](https://www.elastic.co/guide/en/elasticsearch/reference/current/index-lifecycle-management.html)

### Herramientas Útiles
- [Elasticsearch Head](https://github.com/mobz/elasticsearch-head)
- [Cerebro](https://github.com/lmenezes/cerebro)
- [ElasticHQ](https://github.com/ElasticHQ/elasticsearch-HQ)
- [Curator](https://github.com/elastic/curator)

---

**Documento clasificado como INTERNO**  
**Última actualización**: Diciembre 2024  
**Próxima revisión**: Marzo 2025  
**Aprobado por**: Administrador de Sistemas