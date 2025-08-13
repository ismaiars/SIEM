# 🔗 Guía de Conexión de Servicios y Creación de Dashboards

## 📋 Estado Actual de los Servicios

Todos los servicios principales del SIEM están configurados y ejecutándose:

| Servicio | Puerto | Estado | URL de Acceso |
|----------|--------|--------|---------------|
| **Elasticsearch** | 9200 | ✅ Healthy | http://localhost:9200 |
| **Kibana** | 5601 | ✅ Healthy | http://localhost:5601 |
| **Grafana** | 3000 | ✅ Running | http://localhost:3000 |
| **Prometheus** | 9090 | ✅ Healthy | http://localhost:9090 |
| **Node Exporter** | 9100 | ✅ Running | http://localhost:9100 |
| **Logstash** | 5044, 9600 | ✅ Healthy | http://localhost:9600 |
| **PostgreSQL** | 5432 | ✅ Healthy | localhost:5432 |
| **Redis** | 6379 | ✅ Healthy | localhost:6379 |
| **Nginx** | 80, 443 | ✅ Healthy | http://localhost |

## 🔐 Credenciales de Acceso

### Grafana
- **URL**: http://localhost:3000/login
- **Usuario**: `admin`
- **Contraseña**: `SecureGrafanaPass123!`

### Kibana
- **URL**: http://localhost:5601
- **Sin autenticación** (configurado para desarrollo)

### Prometheus
- **URL**: http://localhost:9090
- **Sin autenticación**

## 📊 Datasources Configurados en Grafana

Los siguientes datasources ya están configurados automáticamente:

### 1. Prometheus (Principal)
- **Tipo**: Prometheus
- **URL**: http://prometheus:9090
- **Estado**: ✅ Configurado como datasource por defecto
- **Uso**: Métricas de infraestructura, rendimiento y monitoreo

### 2. Elasticsearch
- **Tipo**: Elasticsearch
- **URL**: http://elasticsearch:9200
- **Base de datos**: `[logstash-]YYYY.MM.DD`
- **Uso**: Logs, eventos de seguridad, análisis de logs

### 3. Loki
- **Tipo**: Loki
- **URL**: http://loki:3100
- **Uso**: Agregación de logs alternativa

### 4. PostgreSQL
- **Tipo**: PostgreSQL
- **URL**: postgresql:5432
- **Base de datos**: `siem`
- **Uso**: Datos estructurados, reportes

### 5. Redis
- **Tipo**: Redis
- **URL**: redis:6379
- **Uso**: Métricas de cache y sesiones

## 🎯 Dashboards Disponibles

### Dashboards Pre-configurados
1. **SIEM Infrastructure Overview** (`siem-overview.json`)
   - Métricas generales de infraestructura
   - Estado de servicios
   - Rendimiento del sistema

2. **SIEM Security Dashboard** (`siem-security.json`)
   - Eventos de seguridad
   - Alertas y amenazas
   - Análisis de logs de seguridad

## 🛠️ Cómo Crear Nuevos Dashboards

### Paso 1: Acceder a Grafana
1. Ve a http://localhost:3000/login
2. Inicia sesión con las credenciales proporcionadas
3. Haz clic en el ícono "+" en el menú lateral
4. Selecciona "Dashboard"

### Paso 2: Agregar Paneles
1. Haz clic en "Add panel"
2. Selecciona el tipo de visualización (Graph, Stat, Table, etc.)
3. Configura el datasource (Prometheus, Elasticsearch, etc.)
4. Escribe tu consulta:

#### Ejemplos de Consultas Prometheus:
```promql
# CPU Usage
100 - (avg(irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)

# Memory Usage
(1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100

# Disk Usage
100 - ((node_filesystem_avail_bytes * 100) / node_filesystem_size_bytes)

# Network Traffic
irate(node_network_receive_bytes_total[5m])
```

#### Ejemplos de Consultas Elasticsearch:
```json
{
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-1h"}}}
      ]
    }
  },
  "aggs": {
    "events_over_time": {
      "date_histogram": {
        "field": "@timestamp",
        "interval": "1m"
      }
    }
  }
}
```

### Paso 3: Configurar Alertas
1. En el panel, ve a la pestaña "Alert"
2. Haz clic en "Create Alert"
3. Define las condiciones de alerta
4. Configura las notificaciones

## 🔄 Verificación de Conexiones

### Verificar Prometheus
```bash
# Verificar que Prometheus esté recolectando métricas
curl http://localhost:9090/api/v1/targets

# Verificar métricas disponibles
curl http://localhost:9090/api/v1/label/__name__/values
```

### Verificar Elasticsearch
```bash
# Estado del cluster
curl http://localhost:9200/_cluster/health?pretty

# Índices disponibles
curl http://localhost:9200/_cat/indices?v
```

### Verificar Grafana Datasources
1. Ve a Configuration > Data Sources en Grafana
2. Verifica que todos los datasources muestren "Working"
3. Haz clic en "Test" para verificar la conectividad

## 📈 Métricas Disponibles

### Métricas de Sistema (Node Exporter)
- CPU, Memoria, Disco, Red
- Procesos del sistema
- Estadísticas de filesystem

### Métricas de Aplicaciones
- Elasticsearch: Rendimiento, índices, queries
- Logstash: Pipeline, eventos procesados
- Grafana: Usuarios, dashboards, alertas

### Logs y Eventos
- Logs de aplicaciones en Elasticsearch
- Eventos de seguridad
- Logs de sistema

## 🚨 Solución de Problemas

### Si un Datasource no Conecta:
1. Verifica que el servicio esté ejecutándose: `docker ps`
2. Revisa los logs: `docker logs [nombre-contenedor]`
3. Verifica la conectividad de red: `docker network inspect siem_siem-network`

### Si no Aparecen Métricas:
1. Verifica que Prometheus esté scrapeando: http://localhost:9090/targets
2. Revisa la configuración en `config/prometheus/prometheus.yml`
3. Reinicia Prometheus: `docker restart siem-prometheus`

### Si Grafana no Carga Dashboards:
1. Verifica los archivos en `config/grafana/provisioning/`
2. Reinicia Grafana: `docker restart siem-grafana`
3. Revisa los logs: `docker logs siem-grafana`

## 📚 Recursos Adicionales

- **Documentación de Prometheus**: https://prometheus.io/docs/
- **Documentación de Grafana**: https://grafana.com/docs/
- **Query Language de Prometheus**: https://prometheus.io/docs/prometheus/latest/querying/
- **Elasticsearch Query DSL**: https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl.html

## 🎉 ¡Todo Listo!

Tu SIEM está completamente configurado con:
- ✅ Todos los servicios conectados
- ✅ Datasources configurados en Grafana
- ✅ Dashboards base disponibles
- ✅ Métricas siendo recolectadas
- ✅ Sistema listo para monitoreo y alertas

**Próximos pasos sugeridos:**
1. Explora los dashboards existentes
2. Crea dashboards personalizados según tus necesidades
3. Configura alertas para eventos críticos
4. Personaliza las métricas según tu entorno

---
**¡Disfruta monitoreando tu infraestructura con tu SIEM completo!** 🚀