# Guía de Despliegue - SIEM OpenSource PyMES

## 📋 Tabla de Contenidos

1. [Prerrequisitos](#prerrequisitos)
2. [Despliegue Local (Docker Compose)](#despliegue-local-docker-compose)
3. [Despliegue en Kubernetes](#despliegue-en-kubernetes)
4. [Despliegue en Cloud (AWS/Azure/GCP)](#despliegue-en-cloud)
5. [Configuración Post-Despliegue](#configuración-post-despliegue)
6. [Hardening de Seguridad](#hardening-de-seguridad)
7. [Monitoreo y Mantenimiento](#monitoreo-y-mantenimiento)
8. [Troubleshooting](#troubleshooting)

## 🔧 Prerrequisitos

### Hardware Mínimo

#### Entorno de Desarrollo
```yaml
CPU: 4 vCPU
RAM: 8 GB
Storage: 100 GB SSD
Network: 1 Gbps
```

#### Entorno de Producción (Pequeño)
```yaml
CPU: 16 vCPU
RAM: 32 GB
Storage: 500 GB SSD
Network: 10 Gbps
Nodes: 3 (HA)
```

#### Entorno de Producción (Mediano)
```yaml
CPU: 32 vCPU
RAM: 64 GB
Storage: 2 TB SSD
Network: 10 Gbps
Nodes: 5+ (HA)
```

### Software Requerido

```bash
# Docker y Docker Compose
Docker Engine: 20.10+
Docker Compose: 2.0+

# Kubernetes (para producción)
Kubernetes: 1.25+
Helm: 3.8+
kubectl: 1.25+

# Terraform (para IaC)
Terraform: 1.5+
Terraform Providers:
  - AWS: 5.0+
  - Azure: 3.0+
  - GCP: 4.0+

# Ansible (para configuración)
Ansible: 6.0+
Ansible Collections:
  - community.general
  - ansible.posix
  - kubernetes.core
```

### Puertos de Red

```yaml
Elasticsearch:
  - 9200 (HTTP API)
  - 9300 (Transport)

Kibana:
  - 5601 (Web UI)

Wazuh:
  - 1514 (Agent communication)
  - 1515 (Agent registration)
  - 55000 (API)
  - 443 (Dashboard)

Logstash:
  - 5044 (Beats input)
  - 9600 (Monitoring)

Grafana:
  - 3000 (Web UI)

PostgreSQL:
  - 5432 (Database)

Redis:
  - 6379 (Cache)
```

## 🐳 Despliegue Local (Docker Compose)

### Paso 1: Preparación del Entorno

```bash
# Clonar el repositorio
git clone https://github.com/tu-usuario/siem-opensource-pymes.git
cd siem-opensource-pymes

# Configurar variables de entorno
cp .env.example .env

# Editar .env con tus configuraciones
nano .env
```

### Paso 2: Configuración de Variables Críticas

```bash
# .env - Configuraciones mínimas requeridas
ELASTIC_PASSWORD=TuPasswordSeguro123!
WAZUH_ADMIN_PASSWORD=TuPasswordSeguro123!
KIBANA_ELASTICSEARCH_PASSWORD=TuPasswordSeguro123!

# Configurar timezone
TIMEZONE=America/Mexico_City

# Configurar recursos
ELASTIC_ES_JAVA_OPTS=-Xms4g -Xmx4g
LOGSTASH_LS_JAVA_OPTS=-Xms2g -Xmx2g
```

### Paso 3: Preparar Directorios y Permisos

```bash
# Crear directorios de datos
sudo mkdir -p /opt/siem-data/{elasticsearch,wazuh,kibana,logstash}
sudo chown -R 1000:1000 /opt/siem-data/elasticsearch
sudo chown -R 1000:1000 /opt/siem-data/kibana
sudo chown -R 1000:1000 /opt/siem-data/logstash

# Configurar vm.max_map_count para Elasticsearch
echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

### Paso 4: Despliegue del Stack

```bash
# Verificar configuración
docker-compose config

# Levantar servicios base (Elasticsearch primero)
docker-compose up -d elasticsearch

# Esperar que Elasticsearch esté listo
docker-compose logs -f elasticsearch
# Esperar mensaje: "Cluster health status changed from [RED] to [YELLOW]"

# Levantar el resto de servicios
docker-compose up -d

# Verificar estado de todos los servicios
docker-compose ps
```

### Paso 5: Verificación del Despliegue

```bash
# Verificar salud de Elasticsearch
curl -u elastic:TuPasswordSeguro123! http://localhost:9200/_cluster/health?pretty

# Verificar Kibana
curl http://localhost:5601/api/status

# Verificar Wazuh Manager
docker-compose exec wazuh-manager /var/ossec/bin/wazuh-control status

# Ver logs en tiempo real
docker-compose logs -f
```

## ☸️ Despliegue en Kubernetes

### Paso 1: Preparación del Cluster

```bash
# Verificar cluster
kubectl cluster-info
kubectl get nodes

# Crear namespace
kubectl create namespace siem-pymes

# Configurar contexto
kubectl config set-context --current --namespace=siem-pymes
```

### Paso 2: Configurar Secrets

```bash
# Crear secrets para passwords
kubectl create secret generic elasticsearch-credentials \
  --from-literal=username=elastic \
  --from-literal=password=TuPasswordSeguro123!

kubectl create secret generic wazuh-credentials \
  --from-literal=username=admin \
  --from-literal=password=TuPasswordSeguro123!

# Crear secret para TLS (opcional)
kubectl create secret tls siem-tls \
  --cert=path/to/tls.crt \
  --key=path/to/tls.key
```

### Paso 3: Configurar Storage Classes

```yaml
# storage-class.yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: siem-ssd
provisioner: kubernetes.io/aws-ebs  # o azure-disk, gce-pd
parameters:
  type: gp3
  fsType: ext4
allowVolumeExpansion: true
volumeBindingMode: WaitForFirstConsumer
```

```bash
kubectl apply -f k8s/storage-class.yaml
```

### Paso 4: Desplegar Elasticsearch

```bash
# Aplicar manifests en orden
kubectl apply -f k8s/manifests/elasticsearch/

# Verificar despliegue
kubectl get pods -l app=elasticsearch
kubectl logs -l app=elasticsearch

# Esperar que el cluster esté listo
kubectl wait --for=condition=ready pod -l app=elasticsearch --timeout=300s
```

### Paso 5: Desplegar Servicios Dependientes

```bash
# Kibana
kubectl apply -f k8s/manifests/kibana/

# Wazuh
kubectl apply -f k8s/manifests/wazuh/

# Logstash
kubectl apply -f k8s/manifests/logstash/

# Servicios auxiliares
kubectl apply -f k8s/manifests/redis/
kubectl apply -f k8s/manifests/postgres/
```

### Paso 6: Configurar Ingress

```yaml
# ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: siem-ingress
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  tls:
  - hosts:
    - siem.tudominio.com
    secretName: siem-tls
  rules:
  - host: siem.tudominio.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: kibana
            port:
              number: 5601
      - path: /wazuh
        pathType: Prefix
        backend:
          service:
            name: wazuh-dashboard
            port:
              number: 5601
```

### Paso 7: Usar Helm Charts (Alternativa)

```bash
# Agregar repositorio Helm
helm repo add siem-pymes ./k8s/helm-charts
helm repo update

# Instalar con Helm
helm install siem-pymes siem-pymes/siem-stack \
  --namespace siem-pymes \
  --values k8s/helm-charts/values-production.yaml

# Verificar instalación
helm status siem-pymes
helm get values siem-pymes
```

## ☁️ Despliegue en Cloud

### AWS con Terraform

#### Paso 1: Configurar Terraform

```bash
cd infra/terraform/aws

# Copiar variables de ejemplo
cp variables.tf.example variables.tf

# Configurar variables
vim variables.tf
```

```hcl
# variables.tf
variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

variable "cluster_name" {
  description = "EKS cluster name"
  type        = string
  default     = "siem-pymes"
}

variable "node_instance_type" {
  description = "EC2 instance type for worker nodes"
  type        = string
  default     = "m5.xlarge"
}

variable "node_count" {
  description = "Number of worker nodes"
  type        = number
  default     = 3
}
```

#### Paso 2: Desplegar Infraestructura

```bash
# Inicializar Terraform
terraform init

# Planificar despliegue
terraform plan

# Aplicar configuración
terraform apply

# Obtener kubeconfig
aws eks update-kubeconfig --region us-east-1 --name siem-pymes
```

#### Paso 3: Configurar EKS

```bash
# Instalar AWS Load Balancer Controller
kubectl apply -f https://github.com/kubernetes-sigs/aws-load-balancer-controller/releases/download/v2.4.4/v2_4_4_full.yaml

# Instalar EBS CSI Driver
kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/aws-ebs-csi-driver/master/deploy/kubernetes/overlays/stable/ecr/kustomization.yaml

# Configurar storage class
kubectl apply -f k8s/aws/storage-class-gp3.yaml
```

### Azure con Terraform

```bash
cd infra/terraform/azure

# Configurar variables
cp variables.tf.example variables.tf

# Login a Azure
az login

# Desplegar
terraform init
terraform plan
terraform apply

# Configurar kubectl
az aks get-credentials --resource-group siem-pymes-rg --name siem-pymes-aks
```

### GCP con Terraform

```bash
cd infra/terraform/gcp

# Configurar autenticación
export GOOGLE_APPLICATION_CREDENTIALS="path/to/service-account.json"

# Desplegar
terraform init
terraform plan
terraform apply

# Configurar kubectl
gcloud container clusters get-credentials siem-pymes --zone us-central1-a
```

## ⚙️ Configuración Post-Despliegue

### Paso 1: Configuración Inicial de Elasticsearch

```bash
# Configurar passwords de usuarios
curl -X POST "localhost:9200/_security/user/kibana_system/_password" \
  -H "Content-Type: application/json" \
  -u elastic:TuPasswordSeguro123! \
  -d '{"password": "TuPasswordKibana123!"}'

# Crear roles personalizados
curl -X POST "localhost:9200/_security/role/siem_analyst" \
  -H "Content-Type: application/json" \
  -u elastic:TuPasswordSeguro123! \
  -d @config/elasticsearch/roles/siem_analyst.json

# Configurar index templates
curl -X PUT "localhost:9200/_index_template/siem-logs" \
  -H "Content-Type: application/json" \
  -u elastic:TuPasswordSeguro123! \
  -d @elastic/mappings/siem-logs-template.json
```

### Paso 2: Configuración de Kibana

```bash
# Importar dashboards
for dashboard in elastic/kibana-dashboards/*.json; do
  curl -X POST "localhost:5601/api/saved_objects/_import" \
    -H "Content-Type: application/json" \
    -H "kbn-xsrf: true" \
    -u elastic:TuPasswordSeguro123! \
    --form file=@"$dashboard"
done

# Configurar index patterns
curl -X POST "localhost:5601/api/saved_objects/index-pattern" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -u elastic:TuPasswordSeguro123! \
  -d @config/kibana/index-patterns/wazuh-alerts.json
```

### Paso 3: Configuración de Wazuh

```bash
# Registrar agentes
docker-compose exec wazuh-manager /var/ossec/bin/manage_agents

# O usando API
curl -X POST "localhost:55000/agents" \
  -H "Content-Type: application/json" \
  -u admin:TuPasswordSeguro123! \
  -d '{"name": "web-server-01", "ip": "192.168.1.100"}'

# Configurar reglas personalizadas
docker-compose exec wazuh-manager cp /var/ossec/etc/rules/local_rules.xml /var/ossec/etc/rules/local_rules.xml.bak
docker-compose cp wazuh/rules/custom_rules.xml wazuh-manager:/var/ossec/etc/rules/
docker-compose exec wazuh-manager /var/ossec/bin/wazuh-control restart
```

### Paso 4: Configuración de Alertas

```bash
# Configurar ElastAlert
cp config/elastalert/elastalert.yaml.example config/elastalert/elastalert.yaml

# Configurar reglas de alertas
cp config/elastalert/rules/examples/* config/elastalert/rules/

# Reiniciar ElastAlert
docker-compose restart elastalert
```

## 🔒 Hardening de Seguridad

### Paso 1: Configuración TLS/SSL

```bash
# Generar certificados (para desarrollo)
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout certs/siem.key \
  -out certs/siem.crt \
  -subj "/C=MX/ST=CDMX/L=Mexico/O=SIEM-PyMES/CN=siem.local"

# Para producción, usar Let's Encrypt o certificados corporativos
certbot certonly --standalone -d siem.tudominio.com
```

### Paso 2: Configurar Firewall

```bash
# UFW (Ubuntu)
sudo ufw enable
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Permitir puertos necesarios
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 443/tcp   # HTTPS
sudo ufw allow 5601/tcp  # Kibana (temporal)
sudo ufw allow 9200/tcp  # Elasticsearch (temporal)

# Restringir por IP (recomendado)
sudo ufw allow from 192.168.1.0/24 to any port 5601
sudo ufw allow from 192.168.1.0/24 to any port 9200
```

### Paso 3: Hardening del Sistema Operativo

```bash
# Ejecutar playbook de hardening
ansible-playbook -i inventory/production playbooks/hardening.yml

# O manualmente:
# Deshabilitar servicios innecesarios
sudo systemctl disable cups
sudo systemctl disable avahi-daemon

# Configurar fail2ban
sudo apt install fail2ban
sudo cp config/fail2ban/jail.local /etc/fail2ban/
sudo systemctl enable fail2ban
sudo systemctl start fail2ban

# Configurar auditd
sudo apt install auditd
sudo cp config/auditd/audit.rules /etc/audit/rules.d/
sudo systemctl restart auditd
```

### Paso 4: Configurar Backup Automático

```bash
# Configurar backup de Elasticsearch
curl -X PUT "localhost:9200/_snapshot/s3_repository" \
  -H "Content-Type: application/json" \
  -u elastic:TuPasswordSeguro123! \
  -d '{
    "type": "s3",
    "settings": {
      "bucket": "siem-backups",
      "region": "us-east-1",
      "base_path": "elasticsearch"
    }
  }'

# Configurar política de snapshots
curl -X PUT "localhost:9200/_slm/policy/daily-snapshots" \
  -H "Content-Type: application/json" \
  -u elastic:TuPasswordSeguro123! \
  -d @config/elasticsearch/snapshot-policy.json

# Configurar cron para backups
echo "0 2 * * * /opt/siem/scripts/backup/elasticsearch-backup.sh" | sudo crontab -
```

## 📊 Monitoreo y Mantenimiento

### Configurar Monitoreo

```bash
# Habilitar monitoring en Elasticsearch
curl -X PUT "localhost:9200/_cluster/settings" \
  -H "Content-Type: application/json" \
  -u elastic:TuPasswordSeguro123! \
  -d '{
    "persistent": {
      "xpack.monitoring.collection.enabled": true
    }
  }'

# Configurar alertas de sistema
cp config/elastalert/rules/system-alerts/* config/elastalert/rules/
```

### Tareas de Mantenimiento

```bash
# Script de mantenimiento diario
#!/bin/bash
# scripts/maintenance/daily-maintenance.sh

# Limpiar logs antiguos
find /var/log -name "*.log" -mtime +30 -delete

# Optimizar índices de Elasticsearch
curl -X POST "localhost:9200/_forcemerge?max_num_segments=1" \
  -u elastic:TuPasswordSeguro123!

# Verificar salud del cluster
curl -s "localhost:9200/_cluster/health" | jq '.status'

# Rotar logs de Wazuh
docker-compose exec wazuh-manager /var/ossec/bin/wazuh-logrotate
```

## 🔧 Troubleshooting

### Problemas Comunes

#### Elasticsearch no inicia
```bash
# Verificar vm.max_map_count
sysctl vm.max_map_count
# Debe ser >= 262144

# Verificar permisos
ls -la /opt/siem-data/elasticsearch
# Debe ser propiedad de UID 1000

# Verificar logs
docker-compose logs elasticsearch
```

#### Wazuh Manager no conecta con Elasticsearch
```bash
# Verificar conectividad
docker-compose exec wazuh-manager curl -u elastic:password http://elasticsearch:9200

# Verificar configuración
docker-compose exec wazuh-manager cat /var/ossec/etc/ossec.conf | grep -A 10 "<indexer>"

# Reiniciar servicios
docker-compose restart wazuh-manager
```

#### Kibana muestra errores de conexión
```bash
# Verificar configuración
docker-compose exec kibana cat /usr/share/kibana/config/kibana.yml

# Verificar logs
docker-compose logs kibana

# Limpiar cache
docker-compose exec kibana rm -rf /usr/share/kibana/optimize
docker-compose restart kibana
```

### Comandos de Diagnóstico

```bash
# Estado general del stack
docker-compose ps
docker-compose top

# Uso de recursos
docker stats

# Logs en tiempo real
docker-compose logs -f --tail=100

# Verificar conectividad de red
docker network ls
docker network inspect siem_siem_network

# Verificar volúmenes
docker volume ls
docker volume inspect siem_elasticsearch_data
```

### Scripts de Diagnóstico

```bash
# scripts/diagnostics/health-check.sh
#!/bin/bash

echo "=== SIEM Health Check ==="

# Elasticsearch
echo "Elasticsearch Status:"
curl -s localhost:9200/_cluster/health | jq

# Kibana
echo "Kibana Status:"
curl -s localhost:5601/api/status | jq '.status.overall.state'

# Wazuh
echo "Wazuh Manager Status:"
docker-compose exec wazuh-manager /var/ossec/bin/wazuh-control status

# Disk usage
echo "Disk Usage:"
df -h

# Memory usage
echo "Memory Usage:"
free -h
```

## 📚 Referencias

- [Elasticsearch Documentation](https://www.elastic.co/guide/)
- [Wazuh Documentation](https://documentation.wazuh.com/)
- [Kibana User Guide](https://www.elastic.co/guide/en/kibana/)
- [Docker Compose Reference](https://docs.docker.com/compose/)
- [Kubernetes Documentation](https://kubernetes.io/docs/)
- [Terraform Documentation](https://www.terraform.io/docs/)

---

**Documento mantenido por**: Equipo DevOps SIEM  
**Última actualización**: Diciembre 2024  
**Versión**: 1.0  
**Próxima revisión**: Marzo 2025