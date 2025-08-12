# Playbook de Respuesta a Incidentes - Ransomware

## 📋 Información del Playbook

| Campo | Valor |
|-------|-------|
| **ID del Playbook** | PB-001-RANSOMWARE |
| **Versión** | 1.0 |
| **Fecha de Creación** | Diciembre 2024 |
| **Última Actualización** | Diciembre 2024 |
| **Autor** | Equipo de Respuesta a Incidentes |
| **Clasificación** | CONFIDENCIAL |
| **Tiempo Estimado** | 2-8 horas |

## 🎯 Objetivo y Alcance

### Objetivo
Proporcionar una guía paso a paso para la detección, contención, erradicación y recuperación de incidentes de ransomware, minimizando el impacto en las operaciones del negocio y los datos críticos.

### Alcance
- Sistemas Windows y Linux
- Servidores de archivos y bases de datos
- Estaciones de trabajo de usuarios
- Infraestructura de red
- Servicios en la nube

### Fuera del Alcance
- Negociación con atacantes
- Pago de rescates (política de la organización)
- Recuperación de datos sin backups

## 🚨 Clasificación de Severidad

### Crítico (P1)
- Cifrado de sistemas críticos de producción
- Afectación a más del 25% de la infraestructura
- Impacto en servicios de cara al cliente
- Datos críticos comprometidos

### Alto (P2)
- Cifrado de sistemas no críticos
- Afectación del 10-25% de la infraestructura
- Impacto en operaciones internas
- Propagación activa detectada

### Medio (P3)
- Cifrado de estaciones de trabajo aisladas
- Afectación menor al 10% de la infraestructura
- Sin propagación detectada
- Sistemas no críticos afectados

## 🔍 Indicadores de Compromiso (IOCs)

### Indicadores Técnicos
```yaml
Archivos:
  - Extensiones: .encrypted, .locked, .crypto, .crypt, .enc
  - Notas de rescate: README.txt, DECRYPT_INSTRUCTIONS.html
  - Ejecutables sospechosos: *.exe en directorios temporales

Procesos:
  - Cifrado masivo de archivos
  - Eliminación de shadow copies (vssadmin.exe)
  - Modificación de registro de Windows
  - Conexiones a dominios sospechosos

Red:
  - Tráfico hacia dominios .onion
  - Comunicación con IPs de C&C conocidas
  - Transferencia de datos inusual
  - Conexiones SMB laterales

Sistema:
  - Cambios en wallpaper del escritorio
  - Servicios detenidos (backup, antivirus)
  - Logs de eventos eliminados
  - Archivos de sistema modificados
```

### Indicadores de Comportamiento
```yaml
Usuarios:
  - Reportes de archivos inaccesibles
  - Mensajes de rescate en pantalla
  - Rendimiento degradado del sistema
  - Aplicaciones que no inician

Sistemas:
  - Incremento en uso de CPU/Disco
  - Actividad de red inusual
  - Fallos en backups automáticos
  - Alertas de antivirus/EDR
```

## 🚀 Fase 1: Detección y Análisis Inicial

### 1.1 Detección Automática

#### Reglas SIEM Activadas
```yaml
Wazuh Rules:
  - 100002: File integrity monitoring alert
  - 100003: Multiple file modifications
  - 100004: Suspicious process execution
  - 100005: Registry modification

Elastic Rules:
  - ransomware_file_encryption
  - suspicious_vssadmin_usage
  - mass_file_deletion
  - crypto_mining_indicators
```

#### Verificación Manual
```bash
# Verificar alertas en Kibana
# Dashboard: Security > Ransomware Detection

# Buscar archivos cifrados
find /home -name "*.encrypted" -o -name "*.locked" -o -name "README*" 2>/dev/null

# Verificar procesos sospechosos
ps aux | grep -E "(crypt|encrypt|ransom)"

# Revisar conexiones de red
netstat -an | grep -E "(443|80|9050)"
```

### 1.2 Evaluación Inicial

#### Checklist de Evaluación
- [ ] Confirmar presencia de ransomware
- [ ] Identificar variante/familia
- [ ] Determinar alcance inicial
- [ ] Evaluar sistemas críticos
- [ ] Verificar estado de backups
- [ ] Identificar vector de entrada

#### Recolección de Evidencias
```bash
# Crear directorio de evidencias
mkdir -p /tmp/incident-$(date +%Y%m%d-%H%M%S)
cd /tmp/incident-$(date +%Y%m%d-%H%M%S)

# Capturar información del sistema
uname -a > system_info.txt
date > timestamp.txt
ps aux > processes.txt
netstat -an > network_connections.txt

# Capturar logs relevantes
cp /var/log/syslog syslog_backup.log
cp /var/log/auth.log auth_backup.log

# Capturar memoria (si es posible)
# dd if=/dev/mem of=memory_dump.raw bs=1M count=1024

# Documentar archivos afectados
find / -name "*.encrypted" -ls > encrypted_files.txt 2>/dev/null
find / -name "README*" -ls > ransom_notes.txt 2>/dev/null
```

## 🛡️ Fase 2: Contención

### 2.1 Contención Inmediata (0-30 minutos)

#### Aislamiento de Red
```bash
# Desconectar sistema afectado de la red
# Opción 1: Deshabilitar interfaz de red
sudo ip link set eth0 down

# Opción 2: Bloquear tráfico con iptables
sudo iptables -A INPUT -j DROP
sudo iptables -A OUTPUT -j DROP

# Opción 3: Desconectar físicamente el cable de red
```

#### Preservación de Evidencias
```bash
# Crear imagen forense del disco (si es posible)
sudo dd if=/dev/sda of=/external/disk_image.dd bs=4M status=progress

# Calcular hash de la imagen
sha256sum /external/disk_image.dd > disk_image.sha256

# Documentar estado actual
date > containment_timestamp.txt
echo "Sistema aislado de la red" >> containment_log.txt
```

### 2.2 Contención Extendida (30 minutos - 2 horas)

#### Identificación de Sistemas Afectados
```bash
# Escanear red en busca de indicadores
nmap -sS -O 192.168.1.0/24 > network_scan.txt

# Verificar logs de firewall
grep -i "ransom\|crypt\|encrypt" /var/log/firewall.log

# Revisar logs de DNS
grep -E "(\.onion|\.bit|suspicious-domain\.com)" /var/log/dns.log
```

#### Segmentación de Red
```bash
# Configurar ACLs en firewall para aislar segmentos
# Ejemplo para pfSense/OPNsense:
# Block rule: Source: Infected_VLAN, Destination: Any, Action: Block

# Configurar VLAN de cuarentena
# Mover sistemas sospechosos a VLAN aislada
```

#### Protección de Sistemas Críticos
```bash
# Verificar y proteger controladores de dominio
sudo systemctl status samba-ad-dc
sudo systemctl status winbind

# Verificar servidores de backup
sudo systemctl status bacula-dir
sudo systemctl status amanda

# Proteger bases de datos
sudo systemctl status mysql
sudo systemctl status postgresql
```

## 🔬 Fase 3: Investigación y Análisis

### 3.1 Análisis de Malware

#### Identificación de la Variante
```bash
# Buscar muestras del malware
find / -name "*.exe" -newer /tmp/infection_time 2>/dev/null

# Calcular hashes de archivos sospechosos
find /tmp -name "*.exe" -exec sha256sum {} \; > malware_hashes.txt

# Consultar bases de datos de threat intelligence
# VirusTotal, Hybrid Analysis, etc.
```

#### Análisis de Comportamiento
```bash
# Revisar modificaciones recientes
find / -mtime -1 -type f | head -100 > recent_modifications.txt

# Analizar logs de procesos
grep -E "(vssadmin|wbadmin|bcdedit)" /var/log/syslog

# Verificar cambios en registro (Windows)
# reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

### 3.2 Análisis de Vector de Entrada

#### Posibles Vectores
```yaml
Email Phishing:
  - Revisar logs de email gateway
  - Buscar attachments sospechosos
  - Verificar links maliciosos

RDP/SSH Brute Force:
  - Revisar logs de autenticación
  - Verificar intentos fallidos
  - Comprobar accesos exitosos

Vulnerabilidades:
  - Escanear sistemas con Nessus/OpenVAS
  - Verificar parches pendientes
  - Revisar servicios expuestos

Movimiento Lateral:
  - Analizar tráfico SMB
  - Verificar uso de credenciales
  - Revisar logs de Active Directory
```

#### Comandos de Investigación
```bash
# Revisar logs de autenticación
grep -i "failed\|invalid" /var/log/auth.log | tail -100

# Buscar conexiones RDP/SSH
grep -E "(ssh|rdp|3389|22)" /var/log/syslog

# Analizar tráfico de red capturado
tcpdump -r network_capture.pcap -nn | grep -E "(443|80|445)"

# Verificar emails sospechosos
grep -i "encrypt\|urgent\|payment" /var/log/mail.log
```

## 🧹 Fase 4: Erradicación

### 4.1 Eliminación del Malware

#### Identificar y Eliminar Archivos Maliciosos
```bash
# Buscar y eliminar ejecutables maliciosos
find / -name "*.exe" -path "/tmp/*" -delete 2>/dev/null
find / -name "*.bat" -path "/tmp/*" -delete 2>/dev/null

# Eliminar archivos de configuración del malware
rm -f /tmp/.config_*
rm -f /var/tmp/.*

# Limpiar directorios temporales
rm -rf /tmp/*
rm -rf /var/tmp/*
```

#### Eliminar Persistencia
```bash
# Revisar y limpiar crontabs
crontab -l > crontab_backup.txt
crontab -r

# Verificar servicios del sistema
systemctl list-units --type=service --state=running | grep -v "@"

# Revisar archivos de inicio
ls -la /etc/init.d/
ls -la /etc/systemd/system/

# Limpiar registro de Windows (si aplica)
# reg delete HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v MalwareName /f
```

### 4.2 Cierre de Vulnerabilidades

#### Aplicar Parches de Seguridad
```bash
# Actualizar sistema operativo
sudo apt update && sudo apt upgrade -y
# o
sudo yum update -y

# Verificar parches críticos
sudo apt list --upgradable | grep -i security

# Aplicar parches específicos
sudo apt install --only-upgrade package-name
```

#### Configurar Controles de Seguridad
```bash
# Habilitar firewall
sudo ufw enable
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Configurar fail2ban
sudo systemctl enable fail2ban
sudo systemctl start fail2ban

# Actualizar reglas de antivirus
sudo freshclam
sudo systemctl restart clamav-daemon
```

## 🔄 Fase 5: Recuperación

### 5.1 Restauración desde Backups

#### Verificar Integridad de Backups
```bash
# Verificar backups disponibles
ls -la /backup/
ls -la /mnt/backup_server/

# Verificar integridad
sha256sum /backup/latest_backup.tar.gz
compare with /backup/latest_backup.sha256

# Probar restauración en entorno aislado
mkdir /tmp/restore_test
tar -xzf /backup/latest_backup.tar.gz -C /tmp/restore_test
```

#### Proceso de Restauración
```bash
# Restaurar archivos críticos
sudo systemctl stop application_service
cp -r /backup/critical_data/* /opt/application/data/
sudo chown -R app_user:app_group /opt/application/data/
sudo systemctl start application_service

# Restaurar bases de datos
mysql -u root -p database_name < /backup/database_backup.sql

# Verificar integridad post-restauración
sudo -u app_user /opt/application/bin/integrity_check.sh
```

### 5.2 Reconstrucción de Sistemas

#### Reinstalación Limpia (si es necesario)
```bash
# Formatear y reinstalar sistema operativo
# 1. Backup de configuraciones críticas
# 2. Formateo completo del disco
# 3. Instalación limpia del OS
# 4. Restauración de datos desde backup verificado
# 5. Aplicación de hardening
```

#### Configuración de Seguridad Mejorada
```bash
# Implementar Application Whitelisting
sudo apt install fapolicyd
sudo systemctl enable fapolicyd

# Configurar monitoreo de integridad
sudo apt install aide
sudo aideinit
sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Configurar logging avanzado
sudo apt install auditd
sudo systemctl enable auditd
```

## 📊 Fase 6: Lecciones Aprendidas

### 6.1 Análisis Post-Incidente

#### Métricas del Incidente
```yaml
Tiempos de Respuesta:
  - Tiempo de detección: _____ minutos
  - Tiempo de contención: _____ minutos
  - Tiempo de erradicación: _____ horas
  - Tiempo de recuperación: _____ horas
  - Tiempo total: _____ horas

Impacto:
  - Sistemas afectados: _____ 
  - Datos comprometidos: _____ GB
  - Tiempo de inactividad: _____ horas
  - Costo estimado: $ _____

Efectividad:
  - Detección automática: Sí/No
  - Contención exitosa: Sí/No
  - Recuperación completa: Sí/No
  - Pérdida de datos: Sí/No
```

### 6.2 Mejoras Identificadas

#### Controles Técnicos
- [ ] Implementar EDR en todos los endpoints
- [ ] Mejorar segmentación de red
- [ ] Configurar backups inmutables
- [ ] Implementar deception technology
- [ ] Mejorar monitoreo de comportamiento

#### Controles Administrativos
- [ ] Actualizar políticas de backup
- [ ] Mejorar entrenamiento de usuarios
- [ ] Revisar procedimientos de respuesta
- [ ] Actualizar plan de continuidad
- [ ] Mejorar comunicación de crisis

#### Controles Físicos
- [ ] Revisar acceso físico a servidores
- [ ] Mejorar seguridad de estaciones de trabajo
- [ ] Implementar controles de acceso

## 📞 Contactos de Emergencia

### Equipo de Respuesta a Incidentes
```yaml
Incident Commander:
  Nombre: [Nombre]
  Teléfono: [Teléfono]
  Email: [Email]

Lead Técnico:
  Nombre: [Nombre]
  Teléfono: [Teléfono]
  Email: [Email]

Comunicaciones:
  Nombre: [Nombre]
  Teléfono: [Teléfono]
  Email: [Email]
```

### Contactos Externos
```yaml
Fuerzas del Orden:
  - FBI Cyber Division: 1-855-292-3937
  - Policía Cibernética Local: [Teléfono]

Proveedores Críticos:
  - ISP: [Teléfono]
  - Proveedor de Backup: [Teléfono]
  - Consultor de Seguridad: [Teléfono]

Legal:
  - Abogado Corporativo: [Teléfono]
  - Consultor de Privacidad: [Teléfono]
```

## 📋 Checklist de Ejecución

### Detección
- [ ] Alerta recibida y validada
- [ ] Severidad determinada
- [ ] Equipo de respuesta notificado
- [ ] Evidencias iniciales recolectadas

### Contención
- [ ] Sistemas afectados identificados
- [ ] Aislamiento de red implementado
- [ ] Evidencias preservadas
- [ ] Sistemas críticos protegidos

### Investigación
- [ ] Vector de entrada identificado
- [ ] Alcance completo determinado
- [ ] Malware analizado
- [ ] Timeline de eventos creado

### Erradicación
- [ ] Malware eliminado
- [ ] Vulnerabilidades cerradas
- [ ] Sistemas limpiados
- [ ] Controles de seguridad implementados

### Recuperación
- [ ] Backups verificados
- [ ] Sistemas restaurados
- [ ] Servicios validados
- [ ] Monitoreo mejorado implementado

### Post-Incidente
- [ ] Reporte de incidente completado
- [ ] Lecciones aprendidas documentadas
- [ ] Mejoras implementadas
- [ ] Entrenamiento actualizado

## 📚 Referencias y Recursos

### Herramientas Recomendadas
- **Análisis de Malware**: VirusTotal, Hybrid Analysis, Cuckoo Sandbox
- **Forense**: Autopsy, Volatility, YARA
- **Descifrado**: No More Ransom Project, Emsisoft Decryptor
- **Threat Intelligence**: MISP, OpenCTI, ThreatConnect

### Documentación Adicional
- [NIST Incident Response Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [SANS Incident Response Process](https://www.sans.org/white-papers/incident-response-process/)
- [No More Ransom](https://www.nomoreransom.org/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

---

**Documento clasificado como CONFIDENCIAL**  
**Última actualización**: Diciembre 2024  
**Próxima revisión**: Junio 2025  
**Aprobado por**: CISO