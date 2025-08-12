# Playbook de Respuesta a Incidentes - Phishing

## 📋 Información del Playbook

| Campo | Valor |
|-------|-------|
| **ID del Playbook** | PB-002-PHISHING |
| **Versión** | 1.0 |
| **Fecha de Creación** | Diciembre 2024 |
| **Última Actualización** | Diciembre 2024 |
| **Autor** | Equipo de Respuesta a Incidentes |
| **Clasificación** | CONFIDENCIAL |
| **Tiempo Estimado** | 1-4 horas |

## 🎯 Objetivo y Alcance

### Objetivo
Proporcionar una respuesta rápida y efectiva ante incidentes de phishing para minimizar el impacto en la organización, proteger las credenciales de usuarios y prevenir compromisos adicionales.

### Alcance
- Emails de phishing dirigidos a empleados
- Sitios web de phishing que imitan servicios corporativos
- Ataques de spear phishing dirigidos
- Compromiso de credenciales corporativas
- Business Email Compromise (BEC)

### Fuera del Alcance
- Phishing dirigido a clientes externos
- Ataques de vishing (phishing telefónico)
- Smishing (phishing por SMS)

## 🚨 Clasificación de Severidad

### Crítico (P1)
- Compromiso confirmado de credenciales de administrador
- Acceso no autorizado a sistemas críticos
- Transferencia financiera fraudulenta
- Compromiso de datos sensibles/PII
- Múltiples usuarios afectados (>50)

### Alto (P2)
- Compromiso de credenciales de usuario estándar
- Acceso a sistemas no críticos
- Intento de transferencia financiera
- Múltiples reportes de phishing (10-50 usuarios)
- Phishing dirigido a ejecutivos

### Medio (P3)
- Reporte de email sospechoso sin compromiso
- Sitio de phishing identificado
- Pocos usuarios afectados (<10)
- Sin evidencia de compromiso

### Bajo (P4)
- Email de phishing genérico bloqueado
- Usuario reporta sin interactuar
- Phishing dirigido a cuentas no críticas

## 🔍 Indicadores de Compromiso (IOCs)

### Indicadores de Email
```yaml
Remitente:
  - Dominios similares a legítimos (typosquatting)
  - Direcciones de email gratuitas (gmail, yahoo, etc.)
  - Dominios recién registrados
  - Headers SPF/DKIM/DMARC fallidos

Contenido:
  - Urgencia artificial ("actúe ahora")
  - Amenazas ("su cuenta será cerrada")
  - Errores ortográficos y gramaticales
  - Enlaces acortados o sospechosos
  - Archivos adjuntos inesperados

Técnicos:
  - Return-Path diferente al From
  - Múltiples redirects en URLs
  - Uso de servicios de URL shortening
  - Archivos con doble extensión
  - Macros habilitadas en documentos
```

### Indicadores de Sitio Web
```yaml
Dominio:
  - Certificados SSL gratuitos o autofirmados
  - Dominios recién registrados (<30 días)
  - Typosquatting de marcas conocidas
  - Subdominios sospechosos

Contenido:
  - Copia exacta de sitios legítimos
  - Formularios de login falsos
  - Solicitud de información sensible
  - Redirecciones múltiples

Técnicos:
  - Hosting en servicios gratuitos
  - Geolocalización inusual
  - Tecnologías web obsoletas
  - Ausencia de políticas de privacidad
```

## 🚀 Fase 1: Detección y Análisis Inicial

### 1.1 Fuentes de Detección

#### Detección Automática
```yaml
Email Security Gateway:
  - Filtros anti-phishing
  - Análisis de reputación de dominios
  - Detección de enlaces maliciosos
  - Análisis de archivos adjuntos

SIEM Rules:
  - Multiple failed login attempts
  - Login from unusual locations
  - Access to sensitive data post-phishing
  - Suspicious email patterns

User Reports:
  - Botón de reporte de phishing
  - Helpdesk tickets
  - Llamadas telefónicas
  - Reportes de seguridad
```

#### Verificación Manual
```bash
# Analizar headers de email sospechoso
cat suspicious_email.eml | grep -E "(From|Return-Path|Received|X-Originating-IP)"

# Verificar reputación de dominio
whois suspicious-domain.com
nslookup suspicious-domain.com

# Analizar URLs en el email
echo "http://suspicious-link.com" | urlscan.io

# Verificar en threat intelligence
curl -X GET "https://www.virustotal.com/vtapi/v2/url/report" \
  --data-urlencode "apikey=YOUR_API_KEY" \
  --data-urlencode "resource=http://suspicious-link.com"
```

### 1.2 Análisis Inicial del Incidente

#### Recolección de Información
```bash
# Crear directorio de investigación
mkdir -p /tmp/phishing-incident-$(date +%Y%m%d-%H%M%S)
cd /tmp/phishing-incident-$(date +%Y%m%d-%H%M%S)

# Guardar email original
cp /path/to/suspicious_email.eml ./original_email.eml

# Extraer headers
formail -X "" < original_email.eml > email_headers.txt

# Extraer URLs
grep -oE 'https?://[^[:space:]]+' original_email.eml > extracted_urls.txt

# Extraer archivos adjuntos
munpack original_email.eml
```

#### Análisis de URLs
```bash
# Verificar cada URL extraída
while read url; do
  echo "Analyzing: $url"
  curl -I "$url" 2>/dev/null | head -5
  echo "---"
done < extracted_urls.txt

# Verificar redirects
curl -L -v "$suspicious_url" 2>&1 | grep -E "(Location|HTTP)"

# Capturar screenshot del sitio
wkhtmltoimage --width 1024 --height 768 "$suspicious_url" site_screenshot.png
```

## 🛡️ Fase 2: Contención

### 2.1 Contención Inmediata (0-15 minutos)

#### Bloqueo de Email
```bash
# Bloquear dominio remitente en email gateway
# Ejemplo para Postfix
echo "suspicious-domain.com REJECT" >> /etc/postfix/sender_access
postmap /etc/postfix/sender_access
systemctl reload postfix

# Bloquear en Microsoft 365
# New-TenantAllowBlockListItems -ListType Sender -Block -Entries "suspicious-domain.com"

# Eliminar emails de buzones
# Search-Mailbox -Identity "All Users" -SearchQuery "From:suspicious-domain.com" -DeleteContent
```

#### Bloqueo de URLs
```bash
# Bloquear en proxy/firewall
echo "suspicious-domain.com" >> /etc/squid/blocked_domains.txt
squid -k reconfigure

# Bloquear en DNS (Pi-hole/pfBlockerNG)
echo "0.0.0.0 suspicious-domain.com" >> /etc/hosts

# Actualizar threat intelligence feeds
echo "suspicious-domain.com,phishing,$(date)" >> /opt/threat-intel/iocs.csv
```

### 2.2 Identificación de Usuarios Afectados

#### Búsqueda en Logs de Email
```bash
# Buscar usuarios que recibieron el email
grep "suspicious-domain.com" /var/log/mail.log | grep "to=" | cut -d'=' -f3 | sort -u > affected_users.txt

# Verificar interacciones con URLs
grep -E "(suspicious-domain\.com|suspicious-url)" /var/log/proxy.log | cut -d' ' -f3 | sort -u > users_clicked.txt

# Buscar en logs de autenticación
grep -A5 -B5 "suspicious-domain.com" /var/log/auth.log > auth_events.txt
```

#### Verificación de Compromiso
```bash
# Verificar logins sospechosos
for user in $(cat users_clicked.txt); do
  echo "Checking user: $user"
  grep "$user" /var/log/auth.log | tail -10
  echo "---"
done

# Verificar cambios de contraseña recientes
grep "password changed" /var/log/auth.log | grep -f users_clicked.txt

# Verificar accesos desde IPs inusuales
grep -f users_clicked.txt /var/log/auth.log | grep -E "([0-9]{1,3}\.){3}[0-9]{1,3}" | sort -u
```

## 🔬 Fase 3: Investigación Detallada

### 3.1 Análisis Forense del Email

#### Análisis de Headers
```bash
# Analizar ruta del email
grep "Received:" email_headers.txt | nl

# Verificar autenticación
grep -E "(SPF|DKIM|DMARC)" email_headers.txt

# Extraer IP de origen
grep "X-Originating-IP\|Received:" email_headers.txt | head -1

# Verificar Message-ID
grep "Message-ID" email_headers.txt
```

#### Análisis de Archivos Adjuntos
```bash
# Verificar archivos extraídos
ls -la part*

# Calcular hashes
find . -name "part*" -exec sha256sum {} \;

# Analizar con antivirus
clamscan --recursive .

# Verificar en VirusTotal
for file in part*; do
  hash=$(sha256sum "$file" | cut -d' ' -f1)
  echo "File: $file, Hash: $hash"
  # curl -X GET "https://www.virustotal.com/vtapi/v2/file/report" --data "apikey=YOUR_API_KEY&resource=$hash"
done
```

### 3.2 Análisis del Sitio de Phishing

#### Recolección de Información
```bash
# Información WHOIS
whois suspicious-domain.com > whois_info.txt

# Información DNS
nslookup suspicious-domain.com > dns_info.txt
dig suspicious-domain.com ANY >> dns_info.txt

# Verificar certificado SSL
echo | openssl s_client -connect suspicious-domain.com:443 2>/dev/null | openssl x509 -text > ssl_cert.txt

# Análisis de tecnologías web
whatweb suspicious-domain.com > web_tech.txt
```

#### Captura de Evidencias
```bash
# Capturar página completa
wget --mirror --convert-links --adjust-extension --page-requisites --no-parent suspicious-domain.com

# Capturar código fuente
curl -s suspicious-domain.com > source_code.html

# Capturar screenshot
wkhtmltoimage --width 1024 --height 768 suspicious-domain.com full_page.png

# Verificar archivos JavaScript
grep -oE 'src="[^"]*\.js[^"]*"' source_code.html | sed 's/src="//g' | sed 's/"//g' > js_files.txt
```

### 3.3 Análisis de Compromiso

#### Verificación de Credenciales
```bash
# Verificar intentos de login fallidos
grep "authentication failure" /var/log/auth.log | grep -f affected_users.txt

# Verificar logins exitosos desde IPs sospechosas
grep "Accepted" /var/log/auth.log | grep -f affected_users.txt

# Verificar cambios en cuentas de usuario
grep -E "(password|account)" /var/log/auth.log | grep -f affected_users.txt
```

#### Análisis de Actividad Post-Compromiso
```bash
# Verificar acceso a recursos sensibles
grep -f affected_users.txt /var/log/application.log | grep -E "(admin|sensitive|confidential)"

# Verificar transferencias de archivos
grep -f affected_users.txt /var/log/ftp.log
grep -f affected_users.txt /var/log/sftp.log

# Verificar actividad de email
grep -f affected_users.txt /var/log/mail.log | grep "sent"
```

## 🧹 Fase 4: Erradicación

### 4.1 Eliminación de Amenazas

#### Limpieza de Emails
```bash
# Eliminar emails maliciosos de todos los buzones
# Para Exchange/Office 365
# New-ComplianceSearch -Name "PhishingCleanup" -ExchangeLocation All -ContentMatchQuery "From:suspicious-domain.com"
# New-ComplianceSearchAction -SearchName "PhishingCleanup" -Purge -PurgeType SoftDelete

# Para sistemas Linux con Dovecot
for user in $(cat affected_users.txt); do
  find /var/mail/$user -name "*" -exec grep -l "suspicious-domain.com" {} \; | xargs rm -f
done
```

#### Revocación de Credenciales Comprometidas
```bash
# Forzar cambio de contraseña para usuarios afectados
for user in $(cat users_clicked.txt); do
  echo "Forcing password change for: $user"
  passwd -e $user
  # Para Active Directory: Set-ADUser -Identity $user -ChangePasswordAtLogon $true
done

# Revocar sesiones activas
for user in $(cat users_clicked.txt); do
  pkill -u $user
  # Para web applications: invalidate all sessions for user
done
```

### 4.2 Fortalecimiento de Defensas

#### Actualización de Filtros
```bash
# Actualizar reglas de email security
echo "# Phishing incident $(date)" >> /etc/postfix/header_checks
echo "/^From:.*suspicious-domain\.com/ REJECT Phishing attempt" >> /etc/postfix/header_checks
postmap /etc/postfix/header_checks

# Actualizar blacklists de URLs
echo "suspicious-domain.com" >> /etc/squid/blacklist.txt
echo "phishing-site.com" >> /etc/squid/blacklist.txt
squid -k reconfigure
```

#### Configuración de Alertas Mejoradas
```yaml
# Regla SIEM para detectar patrones similares
rule_name: "Phishing Email Detection"
condition: |
  email.sender.domain in suspicious_domains OR
  email.subject contains urgent_keywords OR
  email.links contains shortened_urls
action: "alert"
severity: "high"
```

## 🔄 Fase 5: Recuperación

### 5.1 Restauración de Servicios

#### Verificación de Sistemas
```bash
# Verificar integridad de sistemas críticos
sudo aide --check

# Verificar logs de aplicaciones
tail -100 /var/log/application.log | grep -E "(error|warning|critical)"

# Verificar servicios de red
netstat -tlnp | grep -E "(80|443|25|993|995)"

# Verificar procesos sospechosos
ps aux | grep -E "(suspicious|unknown|temp)"
```

#### Monitoreo Intensivo
```bash
# Configurar monitoreo adicional para usuarios afectados
for user in $(cat affected_users.txt); do
  echo "Monitoring user: $user"
  # Agregar reglas específicas de monitoreo
  echo "user=$user" >> /etc/audit/rules.d/phishing-incident.rules
done

# Reiniciar servicio de auditoría
systemctl restart auditd
```

### 5.2 Validación de Recuperación

#### Tests de Funcionalidad
```bash
# Verificar autenticación de usuarios
for user in $(cat affected_users.txt); do
  echo "Testing auth for: $user"
  # Simular login test
done

# Verificar acceso a aplicaciones
curl -I https://internal-app.company.com/login

# Verificar filtrado de emails
echo "Test email from suspicious-domain.com" | sendmail test@company.com
# Verificar que sea bloqueado
```

## 📊 Fase 6: Comunicación y Reporte

### 6.1 Comunicación Interna

#### Notificación a Stakeholders
```yaml
Comunicación Inmediata (15 min):
  - CISO
  - IT Manager
  - Legal/Compliance
  - Gerencia afectada

Actualización Regular (cada 2 horas):
  - Estado del incidente
  - Acciones tomadas
  - Próximos pasos
  - Tiempo estimado de resolución

Comunicación Final:
  - Resumen del incidente
  - Impacto total
  - Lecciones aprendidas
  - Mejoras implementadas
```

#### Comunicación a Usuarios
```yaml
Email de Alerta:
  Asunto: "[URGENTE] Intento de Phishing Detectado"
  Contenido:
    - Descripción del incidente
    - Acciones que deben tomar
    - Qué NO hacer
    - Contacto para reportes

Seguimiento:
  - Recordatorios de seguridad
  - Entrenamiento adicional
  - Verificación de comprensión
```

### 6.2 Reporte del Incidente

#### Métricas del Incidente
```yaml
Detección:
  - Tiempo de detección: _____ minutos
  - Fuente de detección: _____
  - Número de reportes de usuarios: _____

Alcance:
  - Emails enviados: _____
  - Usuarios que recibieron: _____
  - Usuarios que hicieron clic: _____
  - Credenciales comprometidas: _____

Respuesta:
  - Tiempo de contención: _____ minutos
  - Tiempo de erradicación: _____ horas
  - Tiempo total de resolución: _____ horas

Impacto:
  - Sistemas afectados: _____
  - Datos comprometidos: _____
  - Tiempo de inactividad: _____ horas
  - Costo estimado: $ _____
```

## 🎓 Fase 7: Lecciones Aprendidas

### 7.1 Análisis de Efectividad

#### Controles que Funcionaron
- [ ] Email security gateway detectó el phishing
- [ ] Usuarios reportaron emails sospechosos
- [ ] Filtros de URL bloquearon sitios maliciosos
- [ ] Monitoreo detectó actividad sospechosa
- [ ] Respuesta fue rápida y efectiva

#### Controles que Fallaron
- [ ] Email pasó filtros iniciales
- [ ] Usuarios hicieron clic en enlaces
- [ ] Credenciales fueron comprometidas
- [ ] Detección fue tardía
- [ ] Comunicación fue inadecuada

### 7.2 Mejoras Recomendadas

#### Controles Técnicos
- [ ] Implementar DMARC en modo reject
- [ ] Mejorar filtros de email security
- [ ] Implementar sandboxing de URLs
- [ ] Configurar alertas de threat intelligence
- [ ] Implementar autenticación multifactor

#### Controles Administrativos
- [ ] Mejorar entrenamiento de phishing
- [ ] Actualizar políticas de seguridad
- [ ] Implementar simulacros regulares
- [ ] Mejorar procedimientos de reporte
- [ ] Actualizar plan de respuesta

#### Controles de Proceso
- [ ] Automatizar respuesta inicial
- [ ] Mejorar comunicación de crisis
- [ ] Implementar métricas de efectividad
- [ ] Crear playbooks específicos
- [ ] Mejorar coordinación entre equipos

## 📞 Contactos de Emergencia

### Equipo de Respuesta
```yaml
Incident Commander:
  Nombre: [Nombre]
  Teléfono: [Teléfono]
  Email: [Email]

Analista de Seguridad:
  Nombre: [Nombre]
  Teléfono: [Teléfono]
  Email: [Email]

Administrador de Email:
  Nombre: [Nombre]
  Teléfono: [Teléfono]
  Email: [Email]
```

### Contactos Externos
```yaml
Proveedores:
  - Email Security: [Contacto]
  - Threat Intelligence: [Contacto]
  - ISP: [Contacto]

Autoridades:
  - Policía Cibernética: [Teléfono]
  - CERT Nacional: [Teléfono]

Legal:
  - Abogado Corporativo: [Teléfono]
  - Consultor de Privacidad: [Teléfono]
```

## 📋 Checklist de Ejecución

### Detección y Análisis
- [ ] Incidente reportado y validado
- [ ] Severidad determinada
- [ ] Equipo notificado
- [ ] Evidencias recolectadas
- [ ] URLs y dominios analizados

### Contención
- [ ] Emails maliciosos bloqueados
- [ ] URLs maliciosas bloqueadas
- [ ] Usuarios afectados identificados
- [ ] Credenciales comprometidas identificadas

### Erradicación
- [ ] Emails eliminados de buzones
- [ ] Credenciales comprometidas revocadas
- [ ] Filtros actualizados
- [ ] Defensas fortalecidas

### Recuperación
- [ ] Servicios restaurados
- [ ] Monitoreo intensivo implementado
- [ ] Funcionalidad validada
- [ ] Usuarios notificados

### Post-Incidente
- [ ] Reporte completado
- [ ] Comunicación realizada
- [ ] Lecciones documentadas
- [ ] Mejoras implementadas
- [ ] Entrenamiento actualizado

## 📚 Herramientas y Referencias

### Herramientas de Análisis
- **Email Analysis**: MHA (Message Header Analyzer), Email Header Analyzer
- **URL Analysis**: URLVoid, VirusTotal, Hybrid Analysis
- **Threat Intelligence**: PhishTank, OpenPhish, MISP
- **Forensics**: Volatility, Autopsy, YARA

### Referencias
- [Anti-Phishing Working Group](https://apwg.org/)
- [NIST Phishing Guide](https://csrc.nist.gov/publications/detail/sp/800-83/rev-1/final)
- [SANS Phishing Response](https://www.sans.org/white-papers/phishing-response/)
- [PhishTank Database](https://www.phishtank.com/)

---

**Documento clasificado como CONFIDENCIAL**  
**Última actualización**: Diciembre 2024  
**Próxima revisión**: Junio 2025  
**Aprobado por**: CISO