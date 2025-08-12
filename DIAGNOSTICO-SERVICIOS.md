# 🔍 Diagnóstico de Servicios SIEM

## 📊 Estado Actual de los Servicios

### ✅ Servicios Funcionando Correctamente
- **Elasticsearch**: ✅ Saludable
- **Nginx**: ✅ Saludable (Proxy inverso funcionando)
- **PostgreSQL**: ✅ Saludable
- **Redis**: ✅ Saludable
- **Logstash**: 🟡 Iniciando (normal, toma tiempo)
- **ElastAlert**: ✅ Funcionando

### ❌ Servicios con Problemas

#### 1. **Suricata IDS** - Estado: Reiniciando
**Problema**: Permisos de escritura en directorios
```
Error: Output directory is not writable: /var/lib
Error: Output directory is not writable: /var/lib/suricata/rules
```
**Causa**: El contenedor no tiene permisos para escribir en los directorios de salida

#### 2. **Wazuh Manager** - Estado: Reiniciando
**Problema**: Certificados SSL faltantes
```
Failed reading certificate file /etc/ssl/filebeat.pem: no pem file
Failed to add CA to the cert pool, CA is not a valid PEM document
```
**Causa**: Los certificados SSL requeridos no están generados o configurados

#### 3. **Filebeat** - Estado: Reiniciando
**Problema**: Configuración de template incompleta
```
Exiting: setup.template.name and setup.template.pattern have to be set if index name is modified
```
**Causa**: Configuración de Elasticsearch template incorrecta

#### 4. **Grafana** - Estado: Reiniciando
**Problema**: No puede conectar a PostgreSQL
```
Error: failed to check table existence: dial tcp: lookup postgres on 127.0.0.11:53: no such host
```
**Causa**: Problema de resolución DNS entre contenedores

#### 5. **Kibana** - Estado: Reiniciando
**Problema**: Esperando conexión con Elasticsearch
**Causa**: Dependencia de Elasticsearch que aún está inicializando

## 🔧 Soluciones Recomendadas

### Solución Inmediata (Temporal)
```powershell
# Reiniciar servicios problemáticos uno por uno
docker-compose restart elasticsearch
docker-compose restart kibana
docker-compose restart grafana
```

### Solución Completa (Recomendada)

#### 1. Generar Certificados SSL
```powershell
# Ejecutar script de generación de certificados
.\scripts\generate-certs.ps1
```

#### 2. Configurar Permisos de Volúmenes
```powershell
# Crear directorios con permisos correctos
mkdir -p data\suricata\logs
mkdir -p data\suricata\rules
```

#### 3. Reiniciar Servicios en Orden
```powershell
# Parar todos los servicios
docker-compose down

# Iniciar servicios base primero
docker-compose up -d elasticsearch postgresql redis

# Esperar 30 segundos
Start-Sleep 30

# Iniciar servicios dependientes
docker-compose up -d kibana grafana logstash

# Esperar 30 segundos más
Start-Sleep 30

# Iniciar servicios de seguridad
docker-compose up -d wazuh-manager suricata filebeat

# Finalmente nginx
docker-compose up -d nginx
```

## ⏱️ Tiempos de Inicio Normales

| Servicio | Tiempo Estimado | Razón |
|----------|----------------|-------|
| Elasticsearch | 30-60 segundos | Inicialización de índices |
| Kibana | 60-120 segundos | Espera Elasticsearch + UI |
| Grafana | 30-60 segundos | Conexión DB + plugins |
| Logstash | 45-90 segundos | Carga de pipelines |
| Wazuh Manager | 60-120 segundos | Inicialización completa |
| Suricata | 30-60 segundos | Carga de reglas |

## 🚨 Indicadores de Problemas

### Señales de Alerta
- Servicios reiniciando constantemente (más de 3 veces)
- Logs con errores de certificados
- Errores de conexión de red entre contenedores
- Problemas de permisos de archivos

### Comandos de Diagnóstico
```powershell
# Ver estado detallado
docker-compose ps -a

# Ver logs de un servicio específico
docker-compose logs --tail=20 [nombre-servicio]

# Ver uso de recursos
docker stats

# Verificar redes
docker network ls
docker network inspect siem_default
```

## 💡 Recomendaciones

### Para Desarrollo
1. **Paciencia**: Los servicios pueden tardar 5-10 minutos en estar completamente operativos
2. **Monitoreo**: Usar `docker-compose logs -f` para seguimiento en tiempo real
3. **Recursos**: Asegurar al menos 8GB RAM disponible

### Para Producción
1. **Certificados**: Generar certificados SSL válidos
2. **Persistencia**: Configurar volúmenes persistentes
3. **Monitoreo**: Implementar healthchecks robustos
4. **Backup**: Configurar respaldos automáticos

## 🔄 Script de Verificación Automática

Puedes usar este comando para verificar el estado cada 30 segundos:
```powershell
while ($true) {
    Clear-Host
    Write-Host "=== Estado SIEM $(Get-Date) ===" -ForegroundColor Cyan
    docker-compose ps
    Start-Sleep 30
}
```

---

**Nota**: Es normal que algunos servicios tarden en inicializar completamente. El dashboard principal en http://localhost seguirá funcionando y mostrará el estado actualizado de cada servicio.