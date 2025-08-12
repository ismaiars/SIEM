# SIEM OpenSource PyMES - Deployment Guide

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Quick Start](#quick-start)
4. [Deployment Options](#deployment-options)
5. [Local Deployment](#local-deployment)
6. [Cloud Deployment](#cloud-deployment)
7. [Kubernetes Deployment](#kubernetes-deployment)
8. [Configuration](#configuration)
9. [Post-Deployment](#post-deployment)
10. [Monitoring and Maintenance](#monitoring-and-maintenance)
11. [Troubleshooting](#troubleshooting)
12. [Security Considerations](#security-considerations)
13. [Scaling and Performance](#scaling-and-performance)
14. [Backup and Recovery](#backup-and-recovery)
15. [Compliance](#compliance)

## Overview

This deployment guide provides comprehensive instructions for deploying the SIEM OpenSource PyMES solution across different environments. The solution supports multiple deployment methods:

- **Local Deployment**: Docker Compose on a single machine
- **Cloud Deployment**: AWS, Azure, or GCP using Terraform
- **Kubernetes Deployment**: Container orchestration platform
- **Hybrid Deployment**: Combination of on-premises and cloud

## Prerequisites

### System Requirements

#### Minimum Requirements
- **CPU**: 4 cores
- **RAM**: 8 GB
- **Storage**: 50 GB SSD
- **Network**: 1 Gbps
- **OS**: Ubuntu 20.04+, CentOS 8+, or Windows 10/Server 2019+

#### Recommended Requirements
- **CPU**: 8+ cores
- **RAM**: 16+ GB
- **Storage**: 200+ GB SSD
- **Network**: 10 Gbps
- **OS**: Ubuntu 22.04 LTS

### Software Dependencies

#### For Local Deployment
- Docker 24.0+
- Docker Compose 2.0+
- Git
- OpenSSL
- PowerShell 7+ (Windows) or Bash (Linux/macOS)

#### For Cloud Deployment
- Terraform 1.0+
- Cloud CLI tools (AWS CLI, Azure CLI, or gcloud)
- SSH client
- Git

#### For Kubernetes Deployment
- kubectl
- Helm 3.0+
- Kubernetes cluster 1.25+

### Network Requirements

- Internet access for downloading images and updates
- Open ports for SIEM services (see [Port Configuration](#port-configuration))
- DNS resolution for external threat intelligence feeds
- NTP synchronization for accurate timestamps

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/your-org/siem-pymes.git
cd siem-pymes
```

### 2. Choose Your Deployment Method

#### Option A: Local Deployment (Recommended for Testing)

```powershell
# Windows
.\install.ps1 -Mode quick

# Linux/macOS
./install.sh --mode quick
```

#### Option B: Cloud Deployment

```bash
# Configure Terraform variables
cp terraform/terraform.tfvars.example terraform/terraform.tfvars
# Edit terraform.tfvars with your settings

# Deploy to cloud
cd terraform
terraform init
terraform plan
terraform apply
```

### 3. Access the SIEM

After deployment, access the SIEM components:

- **Kibana**: http://localhost:5601 (local) or https://your-domain:5601 (cloud)
- **Wazuh Dashboard**: http://localhost (local) or https://your-domain (cloud)
- **Grafana**: http://localhost:3000 (local) or https://your-domain:3000 (cloud)

## Deployment Options

### Deployment Matrix

| Feature | Local | Cloud | Kubernetes |
|---------|-------|-------|------------|
| Ease of Setup | ⭐⭐⭐ | ⭐⭐ | ⭐ |
| Scalability | ⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| High Availability | ❌ | ⭐⭐⭐ | ⭐⭐⭐ |
| Cost | Low | Medium-High | Medium |
| Maintenance | Manual | Automated | Automated |
| Security | Basic | Advanced | Advanced |

### Choosing the Right Deployment

- **Local**: Development, testing, small environments (<100 endpoints)
- **Cloud**: Production, medium to large environments (100-10,000 endpoints)
- **Kubernetes**: Enterprise, very large environments (10,000+ endpoints)

## Local Deployment

### Windows Deployment

#### 1. Prerequisites Check

```powershell
# Check PowerShell version
$PSVersionTable.PSVersion

# Check Docker
docker --version
docker-compose --version

# Check available resources
Get-ComputerInfo | Select-Object TotalPhysicalMemory, CsProcessors
```

#### 2. Run Installation Script

```powershell
# Quick installation (recommended for testing)
.\install.ps1 -Mode quick

# Production installation with SSL
.\install.ps1 -Mode production -GenerateSSL

# Development installation
.\install.ps1 -Mode development -SkipDocker
```

#### 3. Installation Options

| Parameter | Description | Default |
|-----------|-------------|----------|
| `-Mode` | Installation mode (quick, production, development) | quick |
| `-GenerateSSL` | Generate SSL certificates | false |
| `-SkipDocker` | Skip Docker installation | false |
| `-ConfigFile` | Custom configuration file | .env.example |
| `-LogLevel` | Logging level (DEBUG, INFO, WARN, ERROR) | INFO |

### Linux/macOS Deployment

#### 1. Prerequisites Installation

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y docker.io docker-compose git openssl curl

# CentOS/RHEL
sudo yum install -y docker docker-compose git openssl curl

# macOS (with Homebrew)
brew install docker docker-compose git openssl
```

#### 2. Run Installation Script

```bash
# Make script executable
chmod +x install.sh

# Quick installation
./install.sh --mode quick

# Production installation
./install.sh --mode production --generate-ssl
```

### Configuration Files

#### Environment Configuration (.env)

The `.env` file contains all configuration parameters:

```bash
# Copy example configuration
cp .env.example .env

# Edit configuration
nano .env  # Linux/macOS
notepad .env  # Windows
```

Key configuration sections:

- **General Settings**: Project name, environment, network configuration
- **Service Versions**: Component versions and update policies
- **Security Settings**: Passwords, SSL certificates, encryption
- **Performance Settings**: Memory limits, CPU allocation
- **Monitoring Settings**: Metrics collection, alerting

#### Docker Compose Configuration

The `docker-compose.yml` file defines the service architecture:

```yaml
# View current configuration
docker-compose config

# Validate configuration
docker-compose config --quiet
```

### Port Configuration

| Service | Port | Protocol | Description |
|---------|------|----------|-------------|
| Kibana | 5601 | HTTP/HTTPS | Web interface |
| Elasticsearch | 9200 | HTTP/HTTPS | API endpoint |
| Wazuh Dashboard | 443 | HTTPS | Web interface |
| Wazuh Manager | 1514 | TCP | Agent communication |
| Logstash | 5044 | TCP | Log ingestion |
| Grafana | 3000 | HTTP/HTTPS | Dashboards |
| Prometheus | 9090 | HTTP | Metrics |
| Alertmanager | 9093 | HTTP | Alert management |
| Syslog | 514 | UDP | Log collection |
| SNMP | 161 | UDP | Network monitoring |

## Cloud Deployment

### AWS Deployment

#### 1. Prerequisites

```bash
# Install AWS CLI
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

# Configure AWS credentials
aws configure

# Install Terraform
wget https://releases.hashicorp.com/terraform/1.6.0/terraform_1.6.0_linux_amd64.zip
unzip terraform_1.6.0_linux_amd64.zip
sudo mv terraform /usr/local/bin/
```

#### 2. Configure Terraform Variables

```bash
# Copy example configuration
cp terraform/terraform.tfvars.example terraform/terraform.tfvars

# Edit configuration for AWS
vim terraform/terraform.tfvars
```

Key AWS-specific settings:

```hcl
# AWS Configuration
cloud_provider = "aws"
aws_region = "us-west-2"
aws_profile = "default"

# Instance configuration
instance_type = {
  aws = "t3.xlarge"
}
node_count = 3
disk_size = 100

# Network configuration
vpc_cidr = "10.0.0.0/16"
allowed_cidr_blocks = ["10.0.0.0/8", "your.public.ip/32"]

# Security configuration
enable_waf = true
enable_ddos_protection = true
ssl_certificate_arn = "arn:aws:acm:us-west-2:123456789012:certificate/..."
```

#### 3. Deploy Infrastructure

```bash
cd terraform

# Initialize Terraform
terraform init

# Plan deployment
terraform plan -out=tfplan

# Apply deployment
terraform apply tfplan

# Get outputs
terraform output
```

#### 4. Post-Deployment Configuration

```bash
# Get load balancer DNS
LB_DNS=$(terraform output -raw load_balancer_dns)

# Wait for services to be ready
echo "Waiting for services to initialize..."
sleep 300

# Test connectivity
curl -k https://$LB_DNS:5601/api/status
```

### Azure Deployment

#### 1. Prerequisites

```bash
# Install Azure CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# Login to Azure
az login

# Set subscription
az account set --subscription "your-subscription-id"
```

#### 2. Configure for Azure

```hcl
# Azure Configuration
cloud_provider = "azure"
azure_location = "West US 2"
azure_subscription_id = "your-subscription-id"

# Instance configuration
instance_type = {
  azure = "Standard_D4s_v3"
}
```

### GCP Deployment

#### 1. Prerequisites

```bash
# Install Google Cloud SDK
curl https://sdk.cloud.google.com | bash
exec -l $SHELL

# Initialize gcloud
gcloud init

# Enable required APIs
gcloud services enable compute.googleapis.com
gcloud services enable container.googleapis.com
```

#### 2. Configure for GCP

```hcl
# GCP Configuration
cloud_provider = "gcp"
gcp_project = "your-project-id"
gcp_region = "us-west1"
gcp_zone = "us-west1-a"

# Instance configuration
instance_type = {
  gcp = "n1-standard-4"
}
```

## Kubernetes Deployment

### Prerequisites

```bash
# Install kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

# Install Helm
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

# Verify cluster access
kubectl cluster-info
```

### Deployment Steps

#### 1. Create Namespace

```bash
kubectl create namespace siem-system
kubectl config set-context --current --namespace=siem-system
```

#### 2. Deploy with Helm

```bash
# Add SIEM Helm repository
helm repo add siem-pymes https://charts.siem-pymes.org
helm repo update

# Install SIEM
helm install siem-pymes siem-pymes/siem-stack \
  --namespace siem-system \
  --values kubernetes/values.yaml

# Check deployment status
kubectl get pods -n siem-system
helm status siem-pymes -n siem-system
```

#### 3. Configure Ingress

```yaml
# kubernetes/ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: siem-ingress
  namespace: siem-system
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls:
  - hosts:
    - siem.yourdomain.com
    secretName: siem-tls
  rules:
  - host: siem.yourdomain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: kibana
            port:
              number: 5601
```

```bash
kubectl apply -f kubernetes/ingress.yaml
```

## Configuration

### Initial Configuration

#### 1. Change Default Passwords

```bash
# Generate secure passwords
./scripts/generate-passwords.sh

# Update .env file with new passwords
# Restart services
docker-compose down
docker-compose up -d
```

#### 2. Configure SSL Certificates

```bash
# Generate self-signed certificates (development)
./scripts/generate-ssl.sh

# Or use Let's Encrypt (production)
certbot certonly --standalone -d your-domain.com
```

#### 3. Configure Log Sources

```bash
# Configure rsyslog to send logs to SIEM
echo "*.* @@your-siem-server:514" >> /etc/rsyslog.conf
systemctl restart rsyslog

# Configure Wazuh agents
/var/ossec/bin/agent-auth -m your-siem-server
/var/ossec/bin/ossec-control start
```

### Advanced Configuration

#### Elasticsearch Configuration

```yaml
# config/elasticsearch/elasticsearch.yml
cluster.name: siem-cluster
node.name: siem-node-1
network.host: 0.0.0.0
http.port: 9200
discovery.type: single-node
xpack.security.enabled: true
xpack.security.transport.ssl.enabled: true
```

#### Logstash Configuration

```ruby
# config/logstash/pipeline/main.conf
input {
  beats {
    port => 5044
  }
  syslog {
    port => 514
  }
}

filter {
  if [fields][log_type] == "syslog" {
    grok {
      match => { "message" => "%{SYSLOGTIMESTAMP:timestamp} %{IPORHOST:host} %{DATA:program}: %{GREEDYDATA:message}" }
    }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "logs-%{+YYYY.MM.dd}"
  }
}
```

#### Wazuh Configuration

```xml
<!-- config/wazuh/ossec.conf -->
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>no</logall_json>
  </global>
  
  <alerts>
    <log_alert_level>3</log_alert_level>
    <email_alert_level>12</email_alert_level>
  </alerts>
  
  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
  </remote>
</ossec_config>
```

## Post-Deployment

### Verification Steps

#### 1. Service Health Check

```bash
# Check all services
docker-compose ps

# Check individual service logs
docker-compose logs elasticsearch
docker-compose logs kibana
docker-compose logs wazuh-manager

# Run health check script
./scripts/health-check.sh
```

#### 2. Connectivity Tests

```bash
# Test Elasticsearch
curl -X GET "localhost:9200/_cluster/health?pretty"

# Test Kibana
curl -X GET "localhost:5601/api/status"

# Test Wazuh
curl -X GET "localhost:55000/" -u wazuh:wazuh

# Test Grafana
curl -X GET "localhost:3000/api/health"
```

#### 3. Data Ingestion Test

```bash
# Send test log to syslog
logger -n localhost -P 514 "Test log message from SIEM deployment"

# Check if log appears in Elasticsearch
curl -X GET "localhost:9200/_search?q=Test+log+message&pretty"
```

### Initial Setup Tasks

#### 1. Kibana Setup

1. Access Kibana at http://localhost:5601
2. Create index patterns:
   - `logs-*` for general logs
   - `wazuh-alerts-*` for security alerts
   - `filebeat-*` for system logs
3. Import dashboards from `config/kibana/dashboards/`
4. Configure data views and visualizations

#### 2. Wazuh Setup

1. Access Wazuh Dashboard at http://localhost
2. Login with default credentials (change immediately)
3. Add agents using the agent enrollment process
4. Configure rules and decoders
5. Set up compliance reporting

#### 3. Grafana Setup

1. Access Grafana at http://localhost:3000
2. Login with admin credentials
3. Add Prometheus as data source
4. Import dashboards from `config/grafana/dashboards/`
5. Configure alert notifications

### Agent Deployment

#### Wazuh Agent Installation

```bash
# Linux
wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.7.0-1_amd64.deb
sudo dpkg -i wazuh-agent_4.7.0-1_amd64.deb

# Configure agent
echo "WAZUH_MANAGER='your-siem-server'" >> /var/ossec/etc/ossec.conf

# Start agent
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

```powershell
# Windows
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.0-1.msi -OutFile wazuh-agent.msi
Start-Process msiexec.exe -ArgumentList '/i wazuh-agent.msi /quiet WAZUH_MANAGER="your-siem-server"' -Wait
Start-Service WazuhSvc
```

#### Filebeat Agent Installation

```bash
# Install Filebeat
wget https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.11.0-amd64.deb
sudo dpkg -i filebeat-8.11.0-amd64.deb

# Configure Filebeat
sudo cp config/filebeat/filebeat.yml /etc/filebeat/
sudo systemctl enable filebeat
sudo systemctl start filebeat
```

## Monitoring and Maintenance

### Automated Monitoring

#### Health Checks

```bash
# Run comprehensive health check
./maintenance.ps1 -Operation HealthCheck

# Check specific service
./maintenance.ps1 -Operation HealthCheck -Service elasticsearch

# Schedule regular health checks
crontab -e
# Add: */5 * * * * /opt/siem/maintenance.ps1 -Operation HealthCheck
```

#### Performance Monitoring

```bash
# Monitor resource usage
./maintenance.ps1 -Operation Status

# Check disk usage
df -h /opt/siem/data/

# Monitor memory usage
free -h

# Check Docker stats
docker stats
```

### Maintenance Tasks

#### Regular Maintenance

```bash
# Update Docker images
./maintenance.ps1 -Operation Update

# Clean up old data
./maintenance.ps1 -Operation Cleanup

# Optimize Elasticsearch indices
./maintenance.ps1 -Operation Optimize

# Backup configuration and data
./maintenance.ps1 -Operation Backup
```

#### Log Rotation

```bash
# Configure logrotate
sudo cp config/logrotate/siem /etc/logrotate.d/

# Test logrotate configuration
sudo logrotate -d /etc/logrotate.d/siem

# Force log rotation
sudo logrotate -f /etc/logrotate.d/siem
```

### Alerting Configuration

#### Prometheus Alerts

```yaml
# config/prometheus/alerts/siem-alerts.yml
groups:
- name: siem.rules
  rules:
  - alert: ElasticsearchDown
    expr: up{job="elasticsearch"} == 0
    for: 5m
    labels:
      severity: critical
    annotations:
      summary: "Elasticsearch is down"
      description: "Elasticsearch has been down for more than 5 minutes"
```

#### ElastAlert Configuration

```yaml
# config/elastalert/rules/security-alerts.yml
name: High Severity Security Alert
type: frequency
index: wazuh-alerts-*
num_events: 1
timeframe:
  minutes: 5

filter:
- terms:
    rule.level: [10, 11, 12, 13, 14, 15]

alert:
- "email"
- "slack"

email:
- "security@company.com"

slack:
slack_webhook_url: "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
```

## Troubleshooting

### Common Issues

#### Services Not Starting

```bash
# Check Docker daemon
sudo systemctl status docker

# Check available resources
df -h
free -h

# Check service logs
docker-compose logs --tail=50 elasticsearch
docker-compose logs --tail=50 kibana

# Restart services
docker-compose restart
```

#### Memory Issues

```bash
# Check memory usage
docker stats --no-stream

# Adjust Elasticsearch heap size
# Edit .env file:
ELASTIC_HEAP_SIZE=1g  # Reduce if needed

# Restart Elasticsearch
docker-compose restart elasticsearch
```

#### Network Connectivity

```bash
# Check port availability
netstat -tlnp | grep :9200
netstat -tlnp | grep :5601

# Test internal connectivity
docker-compose exec kibana curl elasticsearch:9200

# Check firewall rules
sudo ufw status
sudo iptables -L
```

#### Data Not Appearing

```bash
# Check Logstash pipeline
docker-compose logs logstash | grep ERROR

# Test log ingestion
echo "test message" | nc localhost 514

# Check Elasticsearch indices
curl "localhost:9200/_cat/indices?v"

# Check Filebeat status
sudo systemctl status filebeat
sudo journalctl -u filebeat -f
```

### Performance Tuning

#### Elasticsearch Optimization

```bash
# Increase heap size (50% of available RAM, max 32GB)
ELASTIC_HEAP_SIZE=4g

# Optimize for write performance
curl -X PUT "localhost:9200/_cluster/settings" -H 'Content-Type: application/json' -d'
{
  "persistent": {
    "indices.memory.index_buffer_size": "40%",
    "indices.memory.min_index_buffer_size": "96mb"
  }
}'

# Configure index templates
curl -X PUT "localhost:9200/_index_template/logs-template" -H 'Content-Type: application/json' -d'
{
  "index_patterns": ["logs-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0,
      "refresh_interval": "30s"
    }
  }
}'
```

#### Logstash Optimization

```ruby
# config/logstash/logstash.yml
pipeline.workers: 4
pipeline.batch.size: 1000
pipeline.batch.delay: 50
queue.type: persisted
queue.max_bytes: 1gb
```

### Log Analysis

#### Centralized Logging

```bash
# View all service logs
docker-compose logs -f

# View specific service logs
docker-compose logs -f elasticsearch
docker-compose logs -f --tail=100 kibana

# Search logs for errors
docker-compose logs | grep -i error
docker-compose logs | grep -i exception
```

#### System Logs

```bash
# Check system logs
sudo journalctl -u docker -f
sudo journalctl -xe

# Check SIEM-specific logs
tail -f /var/log/siem*.log
tail -f /opt/siem/logs/*/*.log
```

## Security Considerations

### Authentication and Authorization

#### Change Default Passwords

```bash
# Generate secure passwords
openssl rand -base64 32

# Update passwords in .env file
ELASTIC_PASSWORD=your-secure-password
KIBANA_PASSWORD=your-secure-password
WAZUH_API_PASSWORD=your-secure-password
GRAFANA_ADMIN_PASSWORD=your-secure-password
```

#### Enable SSL/TLS

```bash
# Generate SSL certificates
./scripts/generate-ssl.sh

# Configure SSL in .env
SSL_ENABLED=true
SSL_CERT_PATH=/opt/siem/ssl/server-cert.pem
SSL_KEY_PATH=/opt/siem/ssl/server-key.pem
```

#### Configure Firewall

```bash
# Ubuntu/Debian
sudo ufw enable
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 443/tcp   # HTTPS
sudo ufw allow 5601/tcp  # Kibana
sudo ufw allow 514/udp   # Syslog
sudo ufw allow 1514/tcp  # Wazuh agents

# CentOS/RHEL
sudo firewall-cmd --permanent --add-port=443/tcp
sudo firewall-cmd --permanent --add-port=5601/tcp
sudo firewall-cmd --permanent --add-port=514/udp
sudo firewall-cmd --permanent --add-port=1514/tcp
sudo firewall-cmd --reload
```

### Network Security

#### Network Segmentation

```yaml
# docker-compose.yml network configuration
networks:
  siem-frontend:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.1.0/24
  siem-backend:
    driver: bridge
    internal: true
    ipam:
      config:
        - subnet: 172.20.2.0/24
```

#### VPN Access

```bash
# Configure OpenVPN for secure remote access
sudo apt install openvpn easy-rsa

# Generate certificates and keys
./scripts/setup-vpn.sh

# Configure client access
./scripts/create-vpn-client.sh username
```

### Data Protection

#### Encryption at Rest

```bash
# Enable Elasticsearch encryption
echo "xpack.security.encryption_keys.data: $(openssl rand -base64 32)" >> config/elasticsearch/elasticsearch.yml

# Encrypt Docker volumes
sudo cryptsetup luksFormat /dev/sdb
sudo cryptsetup luksOpen /dev/sdb siem-data
sudo mkfs.ext4 /dev/mapper/siem-data
```

#### Backup Encryption

```bash
# Encrypt backups with GPG
gpg --gen-key
./maintenance.ps1 -Operation Backup -Encrypt -GPGKey your-key-id
```

## Scaling and Performance

### Horizontal Scaling

#### Elasticsearch Cluster

```yaml
# docker-compose.scale.yml
version: '3.8'
services:
  elasticsearch-node2:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.11.0
    environment:
      - node.name=es-node2
      - cluster.name=siem-cluster
      - discovery.seed_hosts=elasticsearch
      - cluster.initial_master_nodes=es-node1,es-node2
    volumes:
      - es-data2:/usr/share/elasticsearch/data
    networks:
      - siem-network

volumes:
  es-data2:
```

```bash
# Scale Elasticsearch
docker-compose -f docker-compose.yml -f docker-compose.scale.yml up -d
```

#### Load Balancing

```nginx
# config/nginx/nginx.conf
upstream elasticsearch {
    server elasticsearch:9200;
    server elasticsearch-node2:9200;
}

upstream kibana {
    server kibana:5601;
}

server {
    listen 80;
    location /elasticsearch/ {
        proxy_pass http://elasticsearch/;
    }
    location / {
        proxy_pass http://kibana/;
    }
}
```

### Vertical Scaling

#### Resource Allocation

```yaml
# docker-compose.override.yml
version: '3.8'
services:
  elasticsearch:
    deploy:
      resources:
        limits:
          cpus: '4.0'
          memory: 8G
        reservations:
          cpus: '2.0'
          memory: 4G
  
  logstash:
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 4G
        reservations:
          cpus: '1.0'
          memory: 2G
```

### Performance Monitoring

#### Metrics Collection

```bash
# Enable detailed metrics
echo "xpack.monitoring.collection.enabled: true" >> config/elasticsearch/elasticsearch.yml

# Configure Metricbeat
sudo cp config/metricbeat/metricbeat.yml /etc/metricbeat/
sudo systemctl enable metricbeat
sudo systemctl start metricbeat
```

#### Performance Dashboards

```bash
# Import performance dashboards
curl -X POST "kibana:5601/api/saved_objects/_import" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  --form file=@config/kibana/dashboards/performance-dashboard.ndjson
```

## Backup and Recovery

### Automated Backups

#### Configuration Backup

```bash
# Backup configuration files
./maintenance.ps1 -Operation Backup -Type Config

# Backup includes:
# - .env file
# - docker-compose.yml
# - config/ directory
# - SSL certificates
# - Custom rules and dashboards
```

#### Data Backup

```bash
# Backup Elasticsearch data
./maintenance.ps1 -Operation Backup -Type Data

# Create Elasticsearch snapshot
curl -X PUT "localhost:9200/_snapshot/backup_repository" -H 'Content-Type: application/json' -d'
{
  "type": "fs",
  "settings": {
    "location": "/opt/siem/backups/elasticsearch"
  }
}'

curl -X PUT "localhost:9200/_snapshot/backup_repository/snapshot_$(date +%Y%m%d_%H%M%S)" -H 'Content-Type: application/json' -d'
{
  "indices": "*",
  "ignore_unavailable": true,
  "include_global_state": false
}'
```

### Disaster Recovery

#### Recovery Procedures

```bash
# Full system recovery
./maintenance.ps1 -Operation Restore -BackupFile /path/to/backup.tar.gz

# Restore specific components
./maintenance.ps1 -Operation Restore -Type Config -BackupFile config-backup.tar.gz
./maintenance.ps1 -Operation Restore -Type Data -BackupFile data-backup.tar.gz

# Restore Elasticsearch snapshot
curl -X POST "localhost:9200/_snapshot/backup_repository/snapshot_20231201_120000/_restore" -H 'Content-Type: application/json' -d'
{
  "indices": "*",
  "ignore_unavailable": true,
  "include_global_state": false
}'
```

#### Testing Recovery

```bash
# Test backup integrity
./maintenance.ps1 -Operation TestBackup -BackupFile /path/to/backup.tar.gz

# Perform recovery test in isolated environment
docker-compose -f docker-compose.test.yml up -d
./maintenance.ps1 -Operation Restore -Environment test
```

### Backup Scheduling

```bash
# Schedule daily backups
crontab -e
# Add: 0 2 * * * /opt/siem/maintenance.ps1 -Operation Backup -Type Full

# Schedule weekly configuration backups
# Add: 0 3 * * 0 /opt/siem/maintenance.ps1 -Operation Backup -Type Config

# Schedule monthly data archival
# Add: 0 4 1 * * /opt/siem/maintenance.ps1 -Operation Archive -Age 90days
```

## Compliance

### Compliance Frameworks

#### GDPR Compliance

```bash
# Enable GDPR features
echo "COMPLIANCE_GDPR=true" >> .env
echo "DATA_RETENTION_DAYS=2555" >> .env  # 7 years
echo "ENABLE_DATA_ANONYMIZATION=true" >> .env

# Configure data retention policies
curl -X PUT "localhost:9200/_ilm/policy/gdpr-policy" -H 'Content-Type: application/json' -d'
{
  "policy": {
    "phases": {
      "hot": {
        "actions": {
          "rollover": {
            "max_size": "50GB",
            "max_age": "30d"
          }
        }
      },
      "delete": {
        "min_age": "2555d"
      }
    }
  }
}'
```

#### HIPAA Compliance

```bash
# Enable HIPAA features
echo "COMPLIANCE_HIPAA=true" >> .env
echo "ENABLE_AUDIT_LOGGING=true" >> .env
echo "ENABLE_ENCRYPTION=true" >> .env
echo "ACCESS_LOG_RETENTION=2555" >> .env  # 7 years

# Configure access controls
./scripts/setup-hipaa-compliance.sh
```

#### PCI DSS Compliance

```bash
# Enable PCI DSS features
echo "COMPLIANCE_PCI_DSS=true" >> .env
echo "ENABLE_NETWORK_SEGMENTATION=true" >> .env
echo "ENABLE_FILE_INTEGRITY_MONITORING=true" >> .env
echo "LOG_RETENTION_DAYS=365" >> .env  # 1 year minimum

# Configure PCI DSS monitoring
./scripts/setup-pci-compliance.sh
```

### Audit and Reporting

#### Compliance Reporting

```bash
# Generate compliance reports
./scripts/generate-compliance-report.sh --framework GDPR --period monthly
./scripts/generate-compliance-report.sh --framework HIPAA --period quarterly
./scripts/generate-compliance-report.sh --framework PCI-DSS --period annual

# Schedule automated reporting
crontab -e
# Add: 0 9 1 * * /opt/siem/scripts/generate-compliance-report.sh --framework ALL --period monthly
```

#### Audit Trail

```bash
# Enable comprehensive audit logging
echo "ENABLE_AUDIT_TRAIL=true" >> .env
echo "AUDIT_LOG_LEVEL=DEBUG" >> .env

# Configure audit log retention
echo "AUDIT_LOG_RETENTION_DAYS=2555" >> .env  # 7 years

# Monitor audit logs
tail -f /opt/siem/logs/audit/audit.log
```

---

## Support and Resources

### Documentation

- [User Manual](USER_MANUAL.md)
- [API Documentation](API.md)
- [Troubleshooting Guide](TROUBLESHOOTING.md)
- [Security Guide](SECURITY.md)

### Community

- GitHub Issues: https://github.com/your-org/siem-pymes/issues
- Discord Server: https://discord.gg/siem-pymes
- Documentation Wiki: https://wiki.siem-pymes.org

### Professional Support

- Email: support@siem-pymes.org
- Commercial Support: https://siem-pymes.org/support
- Training: https://siem-pymes.org/training

---

**Note**: This deployment guide is comprehensive but may need customization based on your specific environment and requirements. Always test deployments in a non-production environment first.

**Security Warning**: Change all default passwords and configure proper access controls before deploying in production environments.

**Performance Note**: Monitor resource usage and adjust configurations based on your log volume and performance requirements.

For the latest updates and additional resources, visit: https://github.com/your-org/siem-pymes