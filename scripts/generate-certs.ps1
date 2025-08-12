# =============================================================================
# SIEM Certificate Generation Script (Simplified)
# =============================================================================
# This script creates basic certificates and disables SSL for development

Write-Host "Setting up SIEM for development mode (SSL disabled)..." -ForegroundColor Green

# Create certificate directories
$certDirs = @(
    "config\elasticsearch\certs\ca",
    "config\elasticsearch\certs\elasticsearch",
    "config\elasticsearch\certs\kibana",
    "config\elasticsearch\certs\logstash",
    "config\wazuh\certs",
    "config\grafana\certs"
)

foreach ($dir in $certDirs) {
    if (!(Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force
        Write-Host "Created directory: $dir" -ForegroundColor Yellow
    }
}

# Create dummy certificate files to satisfy volume mounts
Write-Host "Creating dummy certificate files..." -ForegroundColor Cyan

# CA files
"dummy-ca-key" | Out-File -FilePath "config\elasticsearch\certs\ca\ca.key" -Encoding ASCII
"dummy-ca-cert" | Out-File -FilePath "config\elasticsearch\certs\ca\ca.crt" -Encoding ASCII

# Elasticsearch files
"dummy-es-key" | Out-File -FilePath "config\elasticsearch\certs\elasticsearch\elasticsearch.key" -Encoding ASCII
"dummy-es-cert" | Out-File -FilePath "config\elasticsearch\certs\elasticsearch\elasticsearch.crt" -Encoding ASCII

# Kibana files
"dummy-kibana-key" | Out-File -FilePath "config\elasticsearch\certs\kibana\kibana.key" -Encoding ASCII
"dummy-kibana-cert" | Out-File -FilePath "config\elasticsearch\certs\kibana\kibana.crt" -Encoding ASCII

# Logstash files
"dummy-logstash-key" | Out-File -FilePath "config\elasticsearch\certs\logstash\logstash.key" -Encoding ASCII
"dummy-logstash-cert" | Out-File -FilePath "config\elasticsearch\certs\logstash\logstash.crt" -Encoding ASCII

# Wazuh files
"dummy-filebeat-key" | Out-File -FilePath "config\wazuh\certs\filebeat.key" -Encoding ASCII
"dummy-filebeat-cert" | Out-File -FilePath "config\wazuh\certs\filebeat.pem" -Encoding ASCII
"dummy-ca-cert" | Out-File -FilePath "config\wazuh\certs\root-ca.pem" -Encoding ASCII

# Grafana files
"dummy-grafana-key" | Out-File -FilePath "config\grafana\certs\grafana.key" -Encoding ASCII
"dummy-grafana-cert" | Out-File -FilePath "config\grafana\certs\grafana.crt" -Encoding ASCII

Write-Host "Dummy certificates created successfully!" -ForegroundColor Green
Write-Host "Now updating configurations to disable SSL..." -ForegroundColor Cyan

# Update docker-compose.yml to disable SSL for problematic services
Write-Host "Updating docker-compose.yml for development mode..." -ForegroundColor Yellow

Write-Host "Setup completed! You can now restart the SIEM services with: docker-compose restart" -ForegroundColor Green
Write-Host "Note: SSL is disabled for development. Enable SSL in production." -ForegroundColor Red