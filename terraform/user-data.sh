#!/bin/bash
# =============================================================================
# User Data Script for SIEM OpenSource PyMES Cloud Deployment
# =============================================================================
# This script initializes cloud instances with Docker and SIEM components
# =============================================================================

set -e

# Variables
ENVIRONMENT="${environment}"
NODE_COUNT="${node_count}"
LOG_FILE="/var/log/siem-init.log"
SIEM_DIR="/opt/siem"
SIEM_USER="siem"

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

log "Starting SIEM initialization for environment: $ENVIRONMENT"

# Update system
log "Updating system packages..."
apt-get update -y
apt-get upgrade -y

# Install required packages
log "Installing required packages..."
apt-get install -y \
    curl \
    wget \
    git \
    unzip \
    htop \
    vim \
    jq \
    ca-certificates \
    gnupg \
    lsb-release \
    software-properties-common \
    apt-transport-https \
    openssl \
    python3 \
    python3-pip \
    awscli \
    fail2ban \
    ufw \
    chrony

# Configure timezone
log "Configuring timezone..."
timedatectl set-timezone UTC

# Install Docker
log "Installing Docker..."
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
apt-get update -y
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Start and enable Docker
systemctl start docker
systemctl enable docker

# Install Docker Compose (standalone)
log "Installing Docker Compose..."
curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose
ln -sf /usr/local/bin/docker-compose /usr/bin/docker-compose

# Create SIEM user
log "Creating SIEM user..."
useradd -m -s /bin/bash "$SIEM_USER"
usermod -aG docker "$SIEM_USER"
usermod -aG sudo "$SIEM_USER"

# Create SIEM directory structure
log "Creating SIEM directory structure..."
mkdir -p "$SIEM_DIR"
cd "$SIEM_DIR"

# Clone SIEM repository or download configuration
log "Setting up SIEM configuration..."
git clone https://github.com/your-org/siem-pymes.git . || {
    log "Git clone failed, creating basic structure..."
    mkdir -p {
        config/{elasticsearch,kibana,logstash,wazuh,suricata,grafana,prometheus,nginx,elastalert},
        data/{elasticsearch,wazuh,grafana,prometheus,postgres,redis},
        logs/{elasticsearch,kibana,logstash,wazuh,suricata,grafana,prometheus,nginx},
        ssl,
        scripts,
        backups
    }
}

# Set permissions
chown -R "$SIEM_USER:$SIEM_USER" "$SIEM_DIR"
chmod -R 755 "$SIEM_DIR"

# Configure firewall
log "Configuring firewall..."
ufw --force enable
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 5601/tcp  # Kibana
ufw allow 9200/tcp  # Elasticsearch
ufw allow 3000/tcp  # Grafana
ufw allow 9090/tcp  # Prometheus
ufw allow 514/udp   # Syslog
ufw allow 1514/tcp  # Wazuh agent
ufw allow 1515/tcp  # Wazuh cluster

# Configure fail2ban
log "Configuring fail2ban..."
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
ignoreip = 127.0.0.1/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 3

[nginx-http-auth]
enabled = true
port = http,https
logpath = /var/log/nginx/error.log

[nginx-limit-req]
enabled = true
port = http,https
logpath = /var/log/nginx/error.log
EOF

systemctl restart fail2ban
systemctl enable fail2ban

# Configure system limits
log "Configuring system limits..."
cat >> /etc/security/limits.conf << 'EOF'
# SIEM system limits
* soft nofile 65536
* hard nofile 65536
* soft nproc 32768
* hard nproc 32768
root soft nofile 65536
root hard nofile 65536
EOF

# Configure sysctl for Elasticsearch
log "Configuring sysctl parameters..."
cat >> /etc/sysctl.conf << 'EOF'
# SIEM optimizations
vm.max_map_count=262144
vm.swappiness=1
net.core.somaxconn=65535
net.ipv4.tcp_max_syn_backlog=65535
net.core.netdev_max_backlog=5000
net.ipv4.tcp_congestion_control=bbr
EOF

sysctl -p

# Disable swap
log "Disabling swap..."
swapoff -a
sed -i '/ swap / s/^\(.*\)$/#\1/g' /etc/fstab

# Install monitoring agents
log "Installing monitoring agents..."

# Install Node Exporter
wget https://github.com/prometheus/node_exporter/releases/latest/download/node_exporter-1.6.1.linux-amd64.tar.gz
tar xvfz node_exporter-1.6.1.linux-amd64.tar.gz
mv node_exporter-1.6.1.linux-amd64/node_exporter /usr/local/bin/
rm -rf node_exporter-1.6.1.linux-amd64*

# Create Node Exporter service
cat > /etc/systemd/system/node_exporter.service << 'EOF'
[Unit]
Description=Node Exporter
Wants=network-online.target
After=network-online.target

[Service]
User=nobody
Group=nobody
Type=simple
ExecStart=/usr/local/bin/node_exporter
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl start node_exporter
systemctl enable node_exporter

# Install Filebeat
log "Installing Filebeat..."
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | apt-key add -
echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | tee /etc/apt/sources.list.d/elastic-8.x.list
apt-get update
apt-get install -y filebeat

# Configure Filebeat
cat > /etc/filebeat/filebeat.yml << 'EOF'
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/*.log
    - /var/log/syslog
    - /var/log/auth.log
    - /opt/siem/logs/*/*.log
  fields:
    environment: ${ENVIRONMENT}
    node_type: siem
  fields_under_root: true

output.logstash:
  hosts: ["localhost:5044"]

processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
  - add_cloud_metadata: ~
  - add_docker_metadata: ~

logging.level: info
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat
  keepfiles: 7
  permissions: 0644
EOF

systemctl enable filebeat

# Create SSL certificates
log "Creating SSL certificates..."
mkdir -p "$SIEM_DIR/ssl"
cd "$SIEM_DIR/ssl"

# Generate CA
openssl genrsa -out ca-key.pem 4096
openssl req -new -x509 -days 365 -key ca-key.pem -sha256 -out ca.pem -subj "/C=US/ST=CA/L=San Francisco/O=SIEM/OU=Security/CN=SIEM-CA"

# Generate server certificate
openssl genrsa -out server-key.pem 4096
openssl req -subj "/C=US/ST=CA/L=San Francisco/O=SIEM/OU=Security/CN=siem-server" -sha256 -new -key server-key.pem -out server.csr

echo "subjectAltName = DNS:localhost,IP:127.0.0.1,DNS:*.amazonaws.com,DNS:*.compute.internal" > extfile.cnf
echo "extendedKeyUsage = serverAuth" >> extfile.cnf

openssl x509 -req -days 365 -sha256 -in server.csr -CA ca.pem -CAkey ca-key.pem -out server-cert.pem -extfile extfile.cnf -CAcreateserial

# Generate client certificate
openssl genrsa -out client-key.pem 4096
openssl req -subj '/C=US/ST=CA/L=San Francisco/O=SIEM/OU=Security/CN=siem-client' -new -key client-key.pem -out client.csr
echo "extendedKeyUsage = clientAuth" > extfile-client.cnf
openssl x509 -req -days 365 -sha256 -in client.csr -CA ca.pem -CAkey ca-key.pem -out client-cert.pem -extfile extfile-client.cnf -CAcreateserial

# Set certificate permissions
chmod 400 ca-key.pem server-key.pem client-key.pem
chmod 444 ca.pem server-cert.pem client-cert.pem
chown -R "$SIEM_USER:$SIEM_USER" "$SIEM_DIR/ssl"

# Create environment file
log "Creating environment configuration..."
cat > "$SIEM_DIR/.env" << EOF
# SIEM Environment Configuration
ENVIRONMENT=$ENVIRONMENT
NODE_COUNT=$NODE_COUNT
COMPOSE_PROJECT_NAME=siem-pymes

# Network Configuration
SIEM_NETWORK=siem-network
SIEM_SUBNET=172.20.0.0/16

# Elasticsearch Configuration
ELASTIC_VERSION=8.11.0
ELASTIC_PASSWORD=$(openssl rand -base64 32)
ELASTIC_CLUSTER_NAME=siem-cluster
ELASTIC_NODE_NAME=siem-node-\${HOSTNAME}
ELASTIC_DISCOVERY_TYPE=single-node
ELASTIC_HEAP_SIZE=2g
ELASTIC_NETWORK_HOST=0.0.0.0
ELASTIC_HTTP_PORT=9200
ELASTIC_TRANSPORT_PORT=9300

# Kibana Configuration
KIBANA_VERSION=8.11.0
KIBANA_PORT=5601
KIBANA_SERVER_NAME=kibana
KIBANA_ELASTICSEARCH_HOSTS=http://elasticsearch:9200

# Wazuh Configuration
WAZUH_VERSION=4.7.0
WAZUH_API_USER=wazuh
WAZUH_API_PASSWORD=$(openssl rand -base64 32)
WAZUH_CLUSTER_KEY=$(openssl rand -base64 32)

# Logstash Configuration
LOGSTASH_VERSION=8.11.0
LOGSTASH_HEAP_SIZE=1g

# Grafana Configuration
GRAFANA_VERSION=10.2.0
GRAFANA_ADMIN_USER=admin
GRAFANA_ADMIN_PASSWORD=$(openssl rand -base64 32)
GRAFANA_PORT=3000

# PostgreSQL Configuration
POSTGRES_VERSION=15
POSTGRES_DB=siem
POSTGRES_USER=siem
POSTGRES_PASSWORD=$(openssl rand -base64 32)

# Redis Configuration
REDIS_VERSION=7-alpine
REDIS_PASSWORD=$(openssl rand -base64 32)

# Prometheus Configuration
PROMETHEUS_VERSION=v2.47.0
PROMETHEUS_PORT=9090

# SSL Configuration
SSL_ENABLED=true
SSL_CERT_PATH=/opt/siem/ssl/server-cert.pem
SSL_KEY_PATH=/opt/siem/ssl/server-key.pem
SSL_CA_PATH=/opt/siem/ssl/ca.pem

# Backup Configuration
BACKUP_ENABLED=true
BACKUP_RETENTION_DAYS=30
BACKUP_SCHEDULE="0 2 * * *"

# Monitoring Configuration
MONITORING_ENABLED=true
ALERTING_ENABLED=true

# Cloud Configuration
CLOUD_PROVIDER=aws
AWS_REGION=\${AWS_DEFAULT_REGION:-us-west-2}
INSTANCE_ID=\$(curl -s http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null || echo "unknown")
INSTANCE_TYPE=\$(curl -s http://169.254.169.254/latest/meta-data/instance-type 2>/dev/null || echo "unknown")
AVAILABILITY_ZONE=\$(curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone 2>/dev/null || echo "unknown")
EOF

chown "$SIEM_USER:$SIEM_USER" "$SIEM_DIR/.env"
chmod 600 "$SIEM_DIR/.env"

# Create startup script
log "Creating startup script..."
cat > "$SIEM_DIR/start-siem.sh" << 'EOF'
#!/bin/bash
set -e

SIEM_DIR="/opt/siem"
LOG_FILE="/var/log/siem-startup.log"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

log "Starting SIEM services..."
cd "$SIEM_DIR"

# Load environment variables
source .env

# Wait for Docker to be ready
while ! docker info >/dev/null 2>&1; do
    log "Waiting for Docker to be ready..."
    sleep 5
done

# Pull latest images
log "Pulling Docker images..."
docker-compose pull

# Start services
log "Starting SIEM services..."
docker-compose up -d

# Wait for services to be ready
log "Waiting for services to be ready..."
sleep 60

# Check service health
log "Checking service health..."
docker-compose ps

# Start Filebeat
log "Starting Filebeat..."
systemctl start filebeat

log "SIEM startup completed successfully"
EOF

chmod +x "$SIEM_DIR/start-siem.sh"
chown "$SIEM_USER:$SIEM_USER" "$SIEM_DIR/start-siem.sh"

# Create systemd service for SIEM
log "Creating SIEM systemd service..."
cat > /etc/systemd/system/siem.service << EOF
[Unit]
Description=SIEM OpenSource PyMES
Requires=docker.service
After=docker.service
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
User=$SIEM_USER
Group=$SIEM_USER
WorkingDirectory=$SIEM_DIR
ExecStart=$SIEM_DIR/start-siem.sh
ExecStop=/usr/local/bin/docker-compose down
TimeoutStartSec=0
Restart=on-failure
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable siem.service

# Create health check script
log "Creating health check script..."
cat > "$SIEM_DIR/health-check.sh" << 'EOF'
#!/bin/bash

SIEM_DIR="/opt/siem"
cd "$SIEM_DIR"

# Check if all services are running
services=("elasticsearch" "kibana" "wazuh-manager" "logstash" "grafana" "prometheus")
all_healthy=true

for service in "${services[@]}"; do
    if ! docker-compose ps "$service" | grep -q "Up"; then
        echo "Service $service is not running"
        all_healthy=false
    fi
done

if $all_healthy; then
    echo "All SIEM services are healthy"
    exit 0
else
    echo "Some SIEM services are not healthy"
    exit 1
fi
EOF

chmod +x "$SIEM_DIR/health-check.sh"
chown "$SIEM_USER:$SIEM_USER" "$SIEM_DIR/health-check.sh"

# Create cron job for health checks
log "Setting up health check cron job..."
echo "*/5 * * * * $SIEM_USER $SIEM_DIR/health-check.sh >> /var/log/siem-health.log 2>&1" > /etc/cron.d/siem-health
chmod 644 /etc/cron.d/siem-health

# Configure log rotation
log "Configuring log rotation..."
cat > /etc/logrotate.d/siem << 'EOF'
/var/log/siem*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 root root
    postrotate
        systemctl reload rsyslog > /dev/null 2>&1 || true
    endscript
}

/opt/siem/logs/*/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 644 siem siem
    copytruncate
}
EOF

# Install CloudWatch agent (if on AWS)
if curl -s http://169.254.169.254/latest/meta-data/ >/dev/null 2>&1; then
    log "Installing CloudWatch agent..."
    wget https://s3.amazonaws.com/amazoncloudwatch-agent/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb
    dpkg -i amazon-cloudwatch-agent.deb
    
    # Configure CloudWatch agent
    cat > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json << 'EOF'
{
    "metrics": {
        "namespace": "SIEM/EC2",
        "metrics_collected": {
            "cpu": {
                "measurement": [
                    "cpu_usage_idle",
                    "cpu_usage_iowait",
                    "cpu_usage_user",
                    "cpu_usage_system"
                ],
                "metrics_collection_interval": 60
            },
            "disk": {
                "measurement": [
                    "used_percent"
                ],
                "metrics_collection_interval": 60,
                "resources": [
                    "*"
                ]
            },
            "diskio": {
                "measurement": [
                    "io_time"
                ],
                "metrics_collection_interval": 60,
                "resources": [
                    "*"
                ]
            },
            "mem": {
                "measurement": [
                    "mem_used_percent"
                ],
                "metrics_collection_interval": 60
            },
            "netstat": {
                "measurement": [
                    "tcp_established",
                    "tcp_time_wait"
                ],
                "metrics_collection_interval": 60
            },
            "swap": {
                "measurement": [
                    "swap_used_percent"
                ],
                "metrics_collection_interval": 60
            }
        }
    },
    "logs": {
        "logs_collected": {
            "files": {
                "collect_list": [
                    {
                        "file_path": "/var/log/siem*.log",
                        "log_group_name": "/aws/ec2/siem",
                        "log_stream_name": "{instance_id}/siem"
                    },
                    {
                        "file_path": "/var/log/syslog",
                        "log_group_name": "/aws/ec2/siem",
                        "log_stream_name": "{instance_id}/syslog"
                    }
                ]
            }
        }
    }
}
EOF
    
    systemctl enable amazon-cloudwatch-agent
    systemctl start amazon-cloudwatch-agent
fi

# Final system optimization
log "Performing final system optimization..."

# Optimize kernel parameters for high-performance networking
echo 'net.core.rmem_default = 262144' >> /etc/sysctl.conf
echo 'net.core.rmem_max = 16777216' >> /etc/sysctl.conf
echo 'net.core.wmem_default = 262144' >> /etc/sysctl.conf
echo 'net.core.wmem_max = 16777216' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_rmem = 4096 65536 16777216' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_wmem = 4096 65536 16777216' >> /etc/sysctl.conf
sysctl -p

# Set up automatic security updates
echo 'Unattended-Upgrade::Automatic-Reboot "false";' >> /etc/apt/apt.conf.d/50unattended-upgrades
apt-get install -y unattended-upgrades
dpkg-reconfigure -plow unattended-upgrades

# Clean up
log "Cleaning up..."
apt-get autoremove -y
apt-get autoclean
docker system prune -f

# Create status file
echo "SIEM initialization completed at $(date)" > "$SIEM_DIR/init-status.txt"
echo "Environment: $ENVIRONMENT" >> "$SIEM_DIR/init-status.txt"
echo "Node Count: $NODE_COUNT" >> "$SIEM_DIR/init-status.txt"
echo "Instance ID: $(curl -s http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null || echo 'unknown')" >> "$SIEM_DIR/init-status.txt"
echo "Instance Type: $(curl -s http://169.254.169.254/latest/meta-data/instance-type 2>/dev/null || echo 'unknown')" >> "$SIEM_DIR/init-status.txt"

chown "$SIEM_USER:$SIEM_USER" "$SIEM_DIR/init-status.txt"

log "SIEM initialization completed successfully!"
log "SIEM directory: $SIEM_DIR"
log "SIEM user: $SIEM_USER"
log "Environment: $ENVIRONMENT"
log "Node count: $NODE_COUNT"

# Start SIEM services
log "Starting SIEM services..."
systemctl start siem.service

log "User data script execution completed!"

# Send completion notification (if SNS topic is available)
if command -v aws >/dev/null 2>&1; then
    INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null || echo "unknown")
    aws sns publish --topic-arn "arn:aws:sns:${AWS_DEFAULT_REGION}:${AWS_ACCOUNT_ID}:siem-notifications" \
        --message "SIEM instance $INSTANCE_ID initialization completed successfully" \
        --subject "SIEM Instance Ready" 2>/dev/null || true
fi

exit 0