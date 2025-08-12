# Runbook - Mantenimiento de Wazuh

## 📋 Información del Runbook

| Campo | Valor |
|-------|-------|
| **ID del Runbook** | RB-002-WAZUH-MAINTENANCE |
| **Versión** | 1.0 |
| **Fecha de Creación** | Diciembre 2024 |
| **Última Actualización** | Diciembre 2024 |
| **Autor** | Equipo de Operaciones |
| **Clasificación** | INTERNO |
| **Frecuencia** | Diaria/Semanal/Mensual |

## 🎯 Objetivo y Alcance

### Objetivo
Proporcionar procedimientos estandarizados para el mantenimiento preventivo y correctivo de Wazuh Manager, asegurando la detección efectiva de amenazas, el rendimiento óptimo y la integridad de los logs de seguridad.

### Alcance
- Wazuh Manager (servidor principal)
- Wazuh Agents (endpoints)
- Reglas de detección personalizadas
- Decodificadores
- Configuraciones de monitoreo
- Logs y alertas
- Integraciones con SIEM

### Prerrequisitos
- Acceso administrativo al Wazuh Manager
- Conocimiento de configuración de Wazuh
- Acceso SSH a servidores
- Herramientas de monitoreo configuradas

## 📅 Tareas de Mantenimiento

### Mantenimiento Diario

#### 1. Verificación del Estado del Manager
```bash
#!/bin/bash
# Script: daily_wazuh_check.sh

DATE=$(date +"%Y-%m-%d %H:%M:%S")
LOG_FILE="/var/log/wazuh_maintenance.log"
WAZUH_PATH="/var/ossec"

echo "[$DATE] Iniciando verificación diaria de Wazuh" >> $LOG_FILE

# Verificar estado del servicio
echo "=== ESTADO DEL SERVICIO WAZUH ===" >> $LOG_FILE
systemctl status wazuh-manager >> $LOG_FILE 2>&1

# Verificar procesos de Wazuh
echo "\n=== PROCESOS DE WAZUH ===" >> $LOG_FILE
ps aux | grep ossec | grep -v grep >> $LOG_FILE

# Verificar conectividad de agentes
echo "\n=== AGENTES CONECTADOS ===" >> $LOG_FILE
$WAZUH_PATH/bin/agent_control -l >> $LOG_FILE

# Verificar agentes desconectados
echo "\n=== AGENTES DESCONECTADOS ===" >> $LOG_FILE
$WAZUH_PATH/bin/agent_control -l | grep "Never connected\|Disconnected" >> $LOG_FILE

# Verificar logs de errores
echo "\n=== ERRORES RECIENTES ===" >> $LOG_FILE
tail -50 $WAZUH_PATH/logs/ossec.log | grep -i error >> $LOG_FILE

# Verificar uso de disco
echo "\n=== USO DE DISCO ===" >> $LOG_FILE
du -sh $WAZUH_PATH/logs/ >> $LOG_FILE
du -sh $WAZUH_PATH/queue/ >> $LOG_FILE

echo "[$DATE] Verificación diaria completada" >> $LOG_FILE
```

#### 2. Monitoreo de Alertas
```bash
#!/bin/bash
# Script: alert_monitoring.sh

DATE=$(date +"%Y-%m-%d")
YESTERDAY=$(date -d "yesterday" +"%Y-%m-%d")
LOG_FILE="/var/log/wazuh_alerts.log"
WAZUH_PATH="/var/ossec"
ALERT_THRESHOLD=1000

echo "[$(date)] Monitoreando alertas de Wazuh" >> $LOG_FILE

# Contar alertas del día
today_alerts=$(grep "$DATE" $WAZUH_PATH/logs/alerts/alerts.log | wc -l)
yesterday_alerts=$(grep "$YESTERDAY" $WAZUH_PATH/logs/alerts/alerts.log | wc -l)

echo "Alertas hoy: $today_alerts" >> $LOG_FILE
echo "Alertas ayer: $yesterday_alerts" >> $LOG_FILE

# Verificar si hay una reducción significativa
if [ $today_alerts -lt $((yesterday_alerts / 2)) ]; then
  echo "ALERTA: Reducción significativa en alertas" >> $LOG_FILE
  echo "ALERTA: Reducción significativa en alertas de Wazuh" | mail -s "Wazuh Alert" admin@company.com
fi

# Verificar alertas de alta severidad
high_severity=$(grep "$DATE" $WAZUH_PATH/logs/alerts/alerts.log | grep -E "level.*1[0-5]" | wc -l)
echo "Alertas de alta severidad: $high_severity" >> $LOG_FILE

if [ $high_severity -gt 50 ]; then
  echo "ALERTA: Muchas alertas de alta severidad" >> $LOG_FILE
  echo "ALERTA: $high_severity alertas de alta severidad detectadas" | mail -s "Wazuh High Severity Alert" admin@company.com
fi

# Top 10 reglas más activadas
echo "\n=== TOP 10 REGLAS MÁS ACTIVADAS ===" >> $LOG_FILE
grep "$DATE" $WAZUH_PATH/logs/alerts/alerts.log | grep -o "Rule: [0-9]*" | sort | uniq -c | sort -nr | head -10 >> $LOG_FILE

echo "[$(date)] Monitoreo de alertas completado" >> $LOG_FILE
```

#### 3. Verificación de Agentes
```bash
#!/bin/bash
# Script: agent_health_check.sh

DATE=$(date +"%Y-%m-%d %H:%M:%S")
LOG_FILE="/var/log/wazuh_agents.log"
WAZUH_PATH="/var/ossec"

echo "[$DATE] Verificando salud de agentes" >> $LOG_FILE

# Obtener lista de todos los agentes
echo "=== RESUMEN DE AGENTES ===" >> $LOG_FILE
total_agents=$($WAZUH_PATH/bin/agent_control -l | grep -c "ID:")
active_agents=$($WAZUH_PATH/bin/agent_control -l | grep -c "Active")
disconnected_agents=$($WAZUH_PATH/bin/agent_control -l | grep -c "Disconnected")
never_connected=$($WAZUH_PATH/bin/agent_control -l | grep -c "Never connected")

echo "Total de agentes: $total_agents" >> $LOG_FILE
echo "Agentes activos: $active_agents" >> $LOG_FILE
echo "Agentes desconectados: $disconnected_agents" >> $LOG_FILE
echo "Nunca conectados: $never_connected" >> $LOG_FILE

# Verificar agentes críticos desconectados
echo "\n=== AGENTES CRÍTICOS DESCONECTADOS ===" >> $LOG_FILE
for critical_agent in "web-server-01" "db-server-01" "dc-01"; do
  status=$($WAZUH_PATH/bin/agent_control -l | grep "$critical_agent" | awk '{print $2}')
  if [ "$status" != "Active" ]; then
    echo "CRÍTICO: $critical_agent está $status" >> $LOG_FILE
    echo "CRÍTICO: Agente $critical_agent desconectado" | mail -s "Wazuh Critical Agent Alert" admin@company.com
  fi
done

# Verificar agentes con problemas de sincronización
echo "\n=== AGENTES CON PROBLEMAS DE SINCRONIZACIÓN ===" >> $LOG_FILE
$WAZUH_PATH/bin/agent_control -l | grep -E "(out of date|outdated)" >> $LOG_FILE

echo "[$DATE] Verificación de agentes completada" >> $LOG_FILE
```

### Mantenimiento Semanal

#### 1. Limpieza de Logs
```bash
#!/bin/bash
# Script: weekly_log_cleanup.sh

DATE=$(date +"%Y-%m-%d %H:%M:%S")
LOG_FILE="/var/log/wazuh_maintenance.log"
WAZUH_PATH="/var/ossec"
RETENTION_DAYS=30

echo "[$DATE] Iniciando limpieza semanal de logs" >> $LOG_FILE

# Verificar espacio antes de la limpieza
echo "=== ESPACIO ANTES DE LIMPIEZA ===" >> $LOG_FILE
du -sh $WAZUH_PATH/logs/ >> $LOG_FILE

# Comprimir logs antiguos
echo "\n=== COMPRIMIENDO LOGS ANTIGUOS ===" >> $LOG_FILE
find $WAZUH_PATH/logs/alerts/ -name "alerts.log.*" -mtime +7 -exec gzip {} \; >> $LOG_FILE 2>&1
find $WAZUH_PATH/logs/archives/ -name "archives.log.*" -mtime +7 -exec gzip {} \; >> $LOG_FILE 2>&1

# Eliminar logs muy antiguos
echo "\n=== ELIMINANDO LOGS ANTIGUOS (>$RETENTION_DAYS días) ===" >> $LOG_FILE
find $WAZUH_PATH/logs/alerts/ -name "*.gz" -mtime +$RETENTION_DAYS -delete >> $LOG_FILE 2>&1
find $WAZUH_PATH/logs/archives/ -name "*.gz" -mtime +$RETENTION_DAYS -delete >> $LOG_FILE 2>&1
find $WAZUH_PATH/logs/firewall/ -name "*.log" -mtime +$RETENTION_DAYS -delete >> $LOG_FILE 2>&1

# Limpiar queue de agentes desconectados
echo "\n=== LIMPIANDO QUEUE DE AGENTES DESCONECTADOS ===" >> $LOG_FILE
for agent_dir in $WAZUH_PATH/queue/agent-info/*; do
  if [ -d "$agent_dir" ]; then
    agent_id=$(basename "$agent_dir")
    agent_status=$($WAZUH_PATH/bin/agent_control -i $agent_id | grep "Status:" | awk '{print $2}')
    
    if [ "$agent_status" = "Disconnected" ]; then
      last_keep_alive=$($WAZUH_PATH/bin/agent_control -i $agent_id | grep "Last keep alive:" | cut -d':' -f2-)
      # Si no ha enviado keep alive en más de 7 días, limpiar queue
      if [ -n "$last_keep_alive" ]; then
        echo "Limpiando queue para agente desconectado: $agent_id" >> $LOG_FILE
        rm -rf $WAZUH_PATH/queue/agent-info/$agent_id/* >> $LOG_FILE 2>&1
      fi
    fi
  fi
done

# Verificar espacio después de la limpieza
echo "\n=== ESPACIO DESPUÉS DE LIMPIEZA ===" >> $LOG_FILE
du -sh $WAZUH_PATH/logs/ >> $LOG_FILE

echo "[$DATE] Limpieza semanal completada" >> $LOG_FILE
```

#### 2. Actualización de Reglas
```bash
#!/bin/bash
# Script: update_rules.sh

DATE=$(date +"%Y-%m-%d %H:%M:%S")
LOG_FILE="/var/log/wazuh_maintenance.log"
WAZUH_PATH="/var/ossec"
RULES_BACKUP_DIR="/backup/wazuh/rules"

echo "[$DATE] Iniciando actualización de reglas" >> $LOG_FILE

# Crear backup de reglas actuales
echo "=== CREANDO BACKUP DE REGLAS ===" >> $LOG_FILE
mkdir -p $RULES_BACKUP_DIR/$(date +%Y%m%d)
cp -r $WAZUH_PATH/ruleset/ $RULES_BACKUP_DIR/$(date +%Y%m%d)/ >> $LOG_FILE 2>&1
cp -r $WAZUH_PATH/etc/rules/ $RULES_BACKUP_DIR/$(date +%Y%m%d)/ >> $LOG_FILE 2>&1

# Verificar sintaxis de reglas personalizadas
echo "\n=== VERIFICANDO SINTAXIS DE REGLAS ===" >> $LOG_FILE
for rule_file in $WAZUH_PATH/etc/rules/*.xml; do
  if [ -f "$rule_file" ]; then
    echo "Verificando: $(basename $rule_file)" >> $LOG_FILE
    xmllint --noout "$rule_file" >> $LOG_FILE 2>&1
    if [ $? -ne 0 ]; then
      echo "ERROR: Sintaxis incorrecta en $rule_file" >> $LOG_FILE
      echo "ERROR: Sintaxis incorrecta en regla $(basename $rule_file)" | mail -s "Wazuh Rule Syntax Error" admin@company.com
    fi
  fi
done

# Actualizar reglas desde repositorio oficial (si está configurado)
echo "\n=== ACTUALIZANDO REGLAS OFICIALES ===" >> $LOG_FILE
# wget -O /tmp/wazuh-rules.tar.gz https://github.com/wazuh/wazuh-ruleset/archive/master.tar.gz
# tar -xzf /tmp/wazuh-rules.tar.gz -C /tmp/
# cp /tmp/wazuh-ruleset-master/rules/* $WAZUH_PATH/ruleset/rules/

# Verificar configuración después de cambios
echo "\n=== VERIFICANDO CONFIGURACIÓN ===" >> $LOG_FILE
$WAZUH_PATH/bin/ossec-logtest -t >> $LOG_FILE 2>&1

if [ $? -eq 0 ]; then
  echo "Configuración válida, reiniciando Wazuh" >> $LOG_FILE
  systemctl restart wazuh-manager >> $LOG_FILE 2>&1
else
  echo "ERROR: Configuración inválida, restaurando backup" >> $LOG_FILE
  cp -r $RULES_BACKUP_DIR/$(date +%Y%m%d)/rules/* $WAZUH_PATH/etc/rules/ >> $LOG_FILE 2>&1
  echo "ERROR: Configuración de reglas inválida, backup restaurado" | mail -s "Wazuh Configuration Error" admin@company.com
fi

echo "[$DATE] Actualización de reglas completada" >> $LOG_FILE
```

### Mantenimiento Mensual

#### 1. Análisis de Rendimiento
```bash
#!/bin/bash
# Script: monthly_performance_analysis.sh

DATE=$(date +"%Y-%m-%d %H:%M:%S")
REPORT_FILE="/var/log/wazuh_monthly_report_$(date +%Y%m).log"
WAZUH_PATH="/var/ossec"

echo "[$DATE] Generando reporte mensual de rendimiento" >> $REPORT_FILE

# Estadísticas generales
echo "=== ESTADÍSTICAS GENERALES ===" >> $REPORT_FILE
echo "Versión de Wazuh: $($WAZUH_PATH/bin/ossec-control info | grep VERSION)" >> $REPORT_FILE
echo "Tiempo de funcionamiento: $(uptime)" >> $REPORT_FILE
echo "Total de agentes: $($WAZUH_PATH/bin/agent_control -l | grep -c 'ID:')" >> $REPORT_FILE
echo "Agentes activos: $($WAZUH_PATH/bin/agent_control -l | grep -c 'Active')" >> $REPORT_FILE

# Análisis de alertas del mes
echo "\n=== ANÁLISIS DE ALERTAS DEL MES ===" >> $REPORT_FILE
current_month=$(date +"%Y %b")
total_alerts=$(grep "$current_month" $WAZUH_PATH/logs/alerts/alerts.log | wc -l)
echo "Total de alertas del mes: $total_alerts" >> $REPORT_FILE

# Top 10 reglas más activadas
echo "\nTop 10 reglas más activadas:" >> $REPORT_FILE
grep "$current_month" $WAZUH_PATH/logs/alerts/alerts.log | grep -o "Rule: [0-9]*" | sort | uniq -c | sort -nr | head -10 >> $REPORT_FILE

# Top 10 agentes con más alertas
echo "\nTop 10 agentes con más alertas:" >> $REPORT_FILE
grep "$current_month" $WAZUH_PATH/logs/alerts/alerts.log | grep -o "Agent: [^)]*" | sort | uniq -c | sort -nr | head -10 >> $REPORT_FILE

# Análisis de rendimiento del sistema
echo "\n=== RENDIMIENTO DEL SISTEMA ===" >> $REPORT_FILE
echo "Uso de CPU:" >> $REPORT_FILE
top -bn1 | grep "Cpu(s)" >> $REPORT_FILE

echo "\nUso de memoria:" >> $REPORT_FILE
free -h >> $REPORT_FILE

echo "\nUso de disco:" >> $REPORT_FILE
df -h $WAZUH_PATH >> $REPORT_FILE

# Estadísticas de logs
echo "\n=== ESTADÍSTICAS DE LOGS ===" >> $REPORT_FILE
echo "Tamaño total de logs: $(du -sh $WAZUH_PATH/logs/ | cut -f1)" >> $REPORT_FILE
echo "Logs de alertas: $(du -sh $WAZUH_PATH/logs/alerts/ | cut -f1)" >> $REPORT_FILE
echo "Logs de archivos: $(du -sh $WAZUH_PATH/logs/archives/ | cut -f1)" >> $REPORT_FILE

echo "[$DATE] Reporte mensual completado" >> $REPORT_FILE
```

#### 2. Optimización de Configuración
```bash
#!/bin/bash
# Script: monthly_optimization.sh

DATE=$(date +"%Y-%m-%d %H:%M:%S")
LOG_FILE="/var/log/wazuh_maintenance.log"
WAZUH_PATH="/var/ossec"
CONFIG_BACKUP_DIR="/backup/wazuh/config"

echo "[$DATE] Iniciando optimización mensual" >> $LOG_FILE

# Crear backup de configuración
echo "=== CREANDO BACKUP DE CONFIGURACIÓN ===" >> $LOG_FILE
mkdir -p $CONFIG_BACKUP_DIR/$(date +%Y%m%d)
cp $WAZUH_PATH/etc/ossec.conf $CONFIG_BACKUP_DIR/$(date +%Y%m%d)/ >> $LOG_FILE 2>&1

# Analizar y optimizar configuración de logcollector
echo "\n=== OPTIMIZANDO LOGCOLLECTOR ===" >> $LOG_FILE

# Verificar archivos de log que no existen
echo "Verificando archivos de log configurados..." >> $LOG_FILE
grep -A 1 "<location>" $WAZUH_PATH/etc/ossec.conf | grep -v "<location>" | grep -v "--" | while read logfile; do
  clean_path=$(echo $logfile | sed 's/<\/location>//g' | sed 's/^[[:space:]]*//')
  if [ ! -f "$clean_path" ] && [ ! -d "$clean_path" ]; then
    echo "ADVERTENCIA: Archivo de log no encontrado: $clean_path" >> $LOG_FILE
  fi
done

# Optimizar configuración de agentes
echo "\n=== OPTIMIZANDO CONFIGURACIÓN DE AGENTES ===" >> $LOG_FILE

# Verificar agentes inactivos y sugerir eliminación
inactive_agents=$($WAZUH_PATH/bin/agent_control -l | grep "Never connected" | wc -l)
if [ $inactive_agents -gt 0 ]; then
  echo "Se encontraron $inactive_agents agentes que nunca se conectaron" >> $LOG_FILE
  echo "Considerar eliminar agentes inactivos para optimizar rendimiento" >> $LOG_FILE
fi

# Verificar configuración de memoria
echo "\n=== VERIFICANDO CONFIGURACIÓN DE MEMORIA ===" >> $LOG_FILE
current_memory=$(grep -A 1 "<memory_size>" $WAZUH_PATH/etc/ossec.conf | grep -v "<memory_size>" | sed 's/<\/memory_size>//g' | sed 's/^[[:space:]]*//')
echo "Configuración actual de memoria: $current_memory" >> $LOG_FILE

# Sugerir optimizaciones basadas en el número de agentes
total_agents=$($WAZUH_PATH/bin/agent_control -l | grep -c "ID:")
if [ $total_agents -gt 100 ] && [ "$current_memory" -lt 2048 ]; then
  echo "RECOMENDACIÓN: Aumentar memory_size a 4096 para $total_agents agentes" >> $LOG_FILE
fi

echo "[$DATE] Optimización mensual completada" >> $LOG_FILE
```

## 🔧 Procedimientos de Mantenimiento Específicos

### Gestión de Agentes

#### Agregar Nuevo Agente
```bash
#!/bin/bash
# Script: add_agent.sh

AGENT_NAME="$1"
AGENT_IP="$2"
WAZUH_PATH="/var/ossec"

if [ -z "$AGENT_NAME" ] || [ -z "$AGENT_IP" ]; then
  echo "Uso: $0 <agent_name> <agent_ip>"
  exit 1
fi

echo "Agregando agente: $AGENT_NAME ($AGENT_IP)"

# Agregar agente
$WAZUH_PATH/bin/manage_agents -a "$AGENT_NAME" "$AGENT_IP" "001"

# Extraer clave del agente
echo "\nClave del agente:"
$WAZUH_PATH/bin/manage_agents -e "$AGENT_NAME"

echo "\nAgente agregado exitosamente"
echo "Instalar el agente en $AGENT_IP y usar la clave mostrada arriba"
```

#### Eliminar Agente Inactivo
```bash
#!/bin/bash
# Script: remove_inactive_agents.sh

WAZUH_PATH="/var/ossec"
LOG_FILE="/var/log/wazuh_maintenance.log"
DAYS_INACTIVE=30

echo "[$(date)] Eliminando agentes inactivos (>$DAYS_INACTIVE días)" >> $LOG_FILE

# Listar agentes nunca conectados
echo "=== AGENTES NUNCA CONECTADOS ===" >> $LOG_FILE
$WAZUH_PATH/bin/agent_control -l | grep "Never connected" >> $LOG_FILE

# Eliminar agentes nunca conectados (requiere confirmación manual)
echo "\nPara eliminar agentes nunca conectados, ejecutar:" >> $LOG_FILE
$WAZUH_PATH/bin/agent_control -l | grep "Never connected" | while read line; do
  agent_id=$(echo $line | awk '{print $2}' | sed 's/,//')
  agent_name=$(echo $line | awk '{print $3}' | sed 's/,//')
  echo "$WAZUH_PATH/bin/manage_agents -r $agent_id" >> $LOG_FILE
done

echo "[$(date)] Revisión de agentes inactivos completada" >> $LOG_FILE
```

### Gestión de Reglas Personalizadas

#### Crear Regla Personalizada
```bash
#!/bin/bash
# Script: create_custom_rule.sh

RULE_FILE="$1"
RULE_DESCRIPTION="$2"
WAZUH_PATH="/var/ossec"

if [ -z "$RULE_FILE" ]; then
  echo "Uso: $0 <rule_file_name> [description]"
  exit 1
fi

RULE_PATH="$WAZUH_PATH/etc/rules/$RULE_FILE"

echo "Creando archivo de regla: $RULE_PATH"

# Crear estructura básica de regla
cat > "$RULE_PATH" << EOF
<!-- Custom rules for $RULE_DESCRIPTION -->
<!-- Created on $(date) -->

<group name="custom,">
  
  <!-- Example rule -->
  <rule id="100001" level="5">
    <decoded_as>custom-decoder</decoded_as>
    <description>Custom rule example</description>
  </rule>
  
</group>
EOF

echo "Archivo de regla creado: $RULE_PATH"
echo "Editar el archivo y agregar reglas personalizadas"
echo "Después ejecutar: systemctl restart wazuh-manager"
```

#### Validar Reglas
```bash
#!/bin/bash
# Script: validate_rules.sh

WAZUH_PATH="/var/ossec"
LOG_FILE="/var/log/wazuh_rule_validation.log"

echo "[$(date)] Validando reglas de Wazuh" >> $LOG_FILE

# Verificar sintaxis XML de todas las reglas
echo "=== VERIFICACIÓN DE SINTAXIS XML ===" >> $LOG_FILE
for rule_file in $WAZUH_PATH/etc/rules/*.xml $WAZUH_PATH/ruleset/rules/*.xml; do
  if [ -f "$rule_file" ]; then
    echo "Verificando: $(basename $rule_file)" >> $LOG_FILE
    xmllint --noout "$rule_file" >> $LOG_FILE 2>&1
    if [ $? -ne 0 ]; then
      echo "ERROR: Sintaxis XML incorrecta en $rule_file" >> $LOG_FILE
    else
      echo "OK: $(basename $rule_file)" >> $LOG_FILE
    fi
  fi
done

# Verificar IDs de reglas duplicados
echo "\n=== VERIFICACIÓN DE IDs DUPLICADOS ===" >> $LOG_FILE
grep -h 'rule id=' $WAZUH_PATH/etc/rules/*.xml $WAZUH_PATH/ruleset/rules/*.xml | \
  grep -o 'id="[0-9]*"' | sort | uniq -d >> $LOG_FILE

# Probar configuración completa
echo "\n=== PRUEBA DE CONFIGURACIÓN ===" >> $LOG_FILE
$WAZUH_PATH/bin/ossec-logtest -t >> $LOG_FILE 2>&1

if [ $? -eq 0 ]; then
  echo "ÉXITO: Configuración válida" >> $LOG_FILE
else
  echo "ERROR: Configuración inválida" >> $LOG_FILE
  echo "ERROR: Configuración de Wazuh inválida" | mail -s "Wazuh Configuration Error" admin@company.com
fi

echo "[$(date)] Validación de reglas completada" >> $LOG_FILE
```

### Gestión de Decodificadores

#### Crear Decodificador Personalizado
```bash
#!/bin/bash
# Script: create_custom_decoder.sh

DECODER_FILE="$1"
DECODER_DESCRIPTION="$2"
WAZUH_PATH="/var/ossec"

if [ -z "$DECODER_FILE" ]; then
  echo "Uso: $0 <decoder_file_name> [description]"
  exit 1
fi

DECODER_PATH="$WAZUH_PATH/etc/decoders/$DECODER_FILE"

echo "Creando archivo de decodificador: $DECODER_PATH"

# Crear estructura básica de decodificador
cat > "$DECODER_PATH" << EOF
<!-- Custom decoders for $DECODER_DESCRIPTION -->
<!-- Created on $(date) -->

<!-- Example decoder -->
<decoder name="custom-decoder">
  <program_name>custom-app</program_name>
</decoder>

<decoder name="custom-decoder-child">
  <parent>custom-decoder</parent>
  <regex>^(\S+) (\S+): (.+)$</regex>
  <order>timestamp, level, message</order>
</decoder>
EOF

echo "Archivo de decodificador creado: $DECODER_PATH"
echo "Editar el archivo y agregar decodificadores personalizados"
echo "Después ejecutar: systemctl restart wazuh-manager"
```

## 🚨 Procedimientos de Emergencia

### Recuperación de Wazuh Manager
```bash
#!/bin/bash
# Script: emergency_recovery.sh

WAZUH_PATH="/var/ossec"
BACKUP_DIR="/backup/wazuh"
LOG_FILE="/var/log/wazuh_emergency.log"

echo "[$(date)] Iniciando recuperación de emergencia" >> $LOG_FILE

# Verificar estado actual
echo "=== ESTADO ACTUAL ===" >> $LOG_FILE
systemctl status wazuh-manager >> $LOG_FILE 2>&1

# Intentar reinicio simple
echo "\n=== INTENTANDO REINICIO ===" >> $LOG_FILE
systemctl restart wazuh-manager >> $LOG_FILE 2>&1
sleep 10

if systemctl is-active --quiet wazuh-manager; then
  echo "ÉXITO: Wazuh reiniciado correctamente" >> $LOG_FILE
  exit 0
fi

# Si el reinicio falla, verificar configuración
echo "\n=== VERIFICANDO CONFIGURACIÓN ===" >> $LOG_FILE
$WAZUH_PATH/bin/ossec-logtest -t >> $LOG_FILE 2>&1

if [ $? -ne 0 ]; then
  echo "ERROR: Configuración inválida, restaurando backup" >> $LOG_FILE
  
  # Restaurar configuración desde backup
  if [ -f "$BACKUP_DIR/latest/ossec.conf" ]; then
    cp "$BACKUP_DIR/latest/ossec.conf" "$WAZUH_PATH/etc/ossec.conf" >> $LOG_FILE 2>&1
    echo "Configuración restaurada desde backup" >> $LOG_FILE
  fi
  
  # Restaurar reglas desde backup
  if [ -d "$BACKUP_DIR/latest/rules" ]; then
    cp -r "$BACKUP_DIR/latest/rules/*" "$WAZUH_PATH/etc/rules/" >> $LOG_FILE 2>&1
    echo "Reglas restauradas desde backup" >> $LOG_FILE
  fi
fi

# Intentar reinicio después de restaurar
echo "\n=== REINICIO DESPUÉS DE RESTAURACIÓN ===" >> $LOG_FILE
systemctl restart wazuh-manager >> $LOG_FILE 2>&1

if systemctl is-active --quiet wazuh-manager; then
  echo "ÉXITO: Wazuh recuperado exitosamente" >> $LOG_FILE
else
  echo "ERROR: No se pudo recuperar Wazuh" >> $LOG_FILE
  echo "ERROR: Wazuh Manager no se pudo recuperar" | mail -s "Wazuh Emergency" admin@company.com
fi

echo "[$(date)] Recuperación de emergencia completada" >> $LOG_FILE
```

### Limpieza de Emergencia de Espacio
```bash
#!/bin/bash
# Script: emergency_space_cleanup.sh

WAZUH_PATH="/var/ossec"
LOG_FILE="/var/log/wazuh_emergency.log"
MIN_FREE_SPACE_GB=5

echo "[$(date)] Iniciando limpieza de emergencia" >> $LOG_FILE

# Verificar espacio disponible
available_space=$(df $WAZUH_PATH | tail -1 | awk '{print $4}')
available_gb=$((available_space / 1024 / 1024))

echo "Espacio disponible: ${available_gb}GB" >> $LOG_FILE

if [ $available_gb -lt $MIN_FREE_SPACE_GB ]; then
  echo "EMERGENCIA: Poco espacio disponible, iniciando limpieza" >> $LOG_FILE
  
  # Eliminar logs de alertas antiguos
  echo "Eliminando logs de alertas antiguos..." >> $LOG_FILE
  find $WAZUH_PATH/logs/alerts/ -name "alerts.log.*" -mtime +7 -delete >> $LOG_FILE 2>&1
  
  # Eliminar logs de archivos antiguos
  echo "Eliminando logs de archivos antiguos..." >> $LOG_FILE
  find $WAZUH_PATH/logs/archives/ -name "archives.log.*" -mtime +7 -delete >> $LOG_FILE 2>&1
  
  # Limpiar queue de agentes
  echo "Limpiando queue de agentes..." >> $LOG_FILE
  find $WAZUH_PATH/queue/ -name "*" -mtime +3 -delete >> $LOG_FILE 2>&1
  
  # Verificar espacio después de limpieza
  available_space_after=$(df $WAZUH_PATH | tail -1 | awk '{print $4}')
  available_gb_after=$((available_space_after / 1024 / 1024))
  
  echo "Espacio disponible después de limpieza: ${available_gb_after}GB" >> $LOG_FILE
  
  if [ $available_gb_after -gt $MIN_FREE_SPACE_GB ]; then
    echo "ÉXITO: Espacio liberado exitosamente" >> $LOG_FILE
  else
    echo "ERROR: No se pudo liberar suficiente espacio" >> $LOG_FILE
    echo "ERROR: Espacio insuficiente en Wazuh" | mail -s "Wazuh Disk Space Emergency" admin@company.com
  fi
else
  echo "Espacio suficiente disponible" >> $LOG_FILE
fi

echo "[$(date)] Limpieza de emergencia completada" >> $LOG_FILE
```

## 📊 Monitoreo y Alertas

### Script de Monitoreo Continuo
```bash
#!/bin/bash
# Script: continuous_monitoring.sh

WAZUH_PATH="/var/ossec"
ALERT_EMAIL="admin@company.com"
CHECK_INTERVAL=300  # 5 minutos

while true; do
  # Verificar si Wazuh está ejecutándose
  if ! systemctl is-active --quiet wazuh-manager; then
    echo "ALERTA: Wazuh Manager no está ejecutándose" | mail -s "Wazuh Service Alert" $ALERT_EMAIL
  fi
  
  # Verificar agentes críticos
  for critical_agent in "web-server-01" "db-server-01" "dc-01"; do
    status=$($WAZUH_PATH/bin/agent_control -l | grep "$critical_agent" | awk '{print $2}')
    if [ "$status" != "Active" ]; then
      echo "ALERTA: Agente crítico $critical_agent está $status" | mail -s "Wazuh Agent Alert" $ALERT_EMAIL
    fi
  done
  
  # Verificar espacio en disco
  disk_usage=$(df $WAZUH_PATH | tail -1 | awk '{print $5}' | sed 's/%//')
  if [ $disk_usage -gt 85 ]; then
    echo "ALERTA: Uso de disco alto: ${disk_usage}%" | mail -s "Wazuh Disk Usage Alert" $ALERT_EMAIL
  fi
  
  # Verificar errores en logs
  recent_errors=$(tail -100 $WAZUH_PATH/logs/ossec.log | grep -i error | wc -l)
  if [ $recent_errors -gt 10 ]; then
    echo "ALERTA: Muchos errores en logs: $recent_errors" | mail -s "Wazuh Error Alert" $ALERT_EMAIL
  fi
  
  sleep $CHECK_INTERVAL
done
```

## 📋 Checklist de Mantenimiento

### Checklist Diario
- [ ] Verificar estado del servicio Wazuh Manager
- [ ] Revisar agentes conectados/desconectados
- [ ] Verificar logs de errores
- [ ] Comprobar ingestión de alertas
- [ ] Revisar uso de disco
- [ ] Verificar agentes críticos

### Checklist Semanal
- [ ] Limpiar logs antiguos
- [ ] Comprimir archivos de log
- [ ] Verificar sintaxis de reglas
- [ ] Actualizar reglas personalizadas
- [ ] Revisar rendimiento del sistema
- [ ] Verificar backups de configuración

### Checklist Mensual
- [ ] Generar reporte de rendimiento
- [ ] Analizar estadísticas de alertas
- [ ] Optimizar configuración
- [ ] Revisar y eliminar agentes inactivos
- [ ] Actualizar documentación
- [ ] Planificar actualizaciones

## 📞 Contactos de Soporte

### Equipo Interno
```yaml
Administrador Principal:
  Nombre: [Nombre]
  Teléfono: [Teléfono]
  Email: [Email]

Equipo de Seguridad:
  Nombre: [Nombre]
  Teléfono: [Teléfono]
  Email: [Email]
```

### Soporte Externo
```yaml
Wazuh Support:
  Portal: https://wazuh.com/support
  Documentación: https://documentation.wazuh.com
  Community: https://groups.google.com/forum/#!forum/wazuh

Consultor Wazuh:
  Nombre: [Nombre]
  Teléfono: [Teléfono]
  Email: [Email]
```

## 📚 Referencias y Documentación

### Documentación Oficial
- [Wazuh Documentation](https://documentation.wazuh.com/)
- [Wazuh Ruleset](https://github.com/wazuh/wazuh-ruleset)
- [Wazuh API Reference](https://documentation.wazuh.com/current/user-manual/api/reference.html)

### Herramientas Útiles
- [Wazuh Web UI](https://documentation.wazuh.com/current/user-manual/kibana-app/index.html)
- [ossec-logtest](https://documentation.wazuh.com/current/user-manual/reference/tools/ossec-logtest.html)
- [agent_control](https://documentation.wazuh.com/current/user-manual/reference/tools/agent_control.html)

---

**Documento clasificado como INTERNO**  
**Última actualización**: Diciembre 2024  
**Próxima revisión**: Marzo 2025  
**Aprobado por**: Administrador de Seguridad