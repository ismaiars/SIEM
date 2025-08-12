# =============================================================================
# Terraform Variables for SIEM OpenSource PyMES
# =============================================================================
# This file defines all configurable variables for the SIEM deployment
# =============================================================================

# =============================================================================
# GENERAL CONFIGURATION
# =============================================================================

variable "cloud_provider" {
  description = "Cloud provider to deploy to (aws, azure, gcp, kubernetes)"
  type        = string
  default     = "aws"
  validation {
    condition     = contains(["aws", "azure", "gcp", "kubernetes"], var.cloud_provider)
    error_message = "Cloud provider must be one of: aws, azure, gcp, kubernetes."
  }
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "prod"
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "siem-pymes"
  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.project_name))
    error_message = "Project name must contain only lowercase letters, numbers, and hyphens."
  }
}

variable "organization" {
  description = "Organization name"
  type        = string
  default     = "MyOrganization"
}

variable "owner" {
  description = "Owner of the SIEM deployment"
  type        = string
  default     = "security-team"
}

variable "contact_email" {
  description = "Contact email for the SIEM deployment"
  type        = string
  default     = "security@example.com"
  validation {
    condition     = can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", var.contact_email))
    error_message = "Contact email must be a valid email address."
  }
}

# =============================================================================
# CLOUD PROVIDER SPECIFIC CONFIGURATION
# =============================================================================

# AWS Configuration
variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-west-2"
}

variable "aws_profile" {
  description = "AWS profile to use for deployment"
  type        = string
  default     = "default"
}

variable "aws_account_id" {
  description = "AWS account ID"
  type        = string
  default     = ""
}

# Azure Configuration
variable "azure_location" {
  description = "Azure location for deployment"
  type        = string
  default     = "West US 2"
}

variable "azure_subscription_id" {
  description = "Azure subscription ID"
  type        = string
  default     = ""
}

variable "azure_tenant_id" {
  description = "Azure tenant ID"
  type        = string
  default     = ""
}

# GCP Configuration
variable "gcp_project" {
  description = "GCP project ID"
  type        = string
  default     = ""
}

variable "gcp_region" {
  description = "GCP region for deployment"
  type        = string
  default     = "us-west1"
}

variable "gcp_zone" {
  description = "GCP zone for deployment"
  type        = string
  default     = "us-west1-a"
}

# Kubernetes Configuration
variable "kubernetes_namespace" {
  description = "Kubernetes namespace for SIEM deployment"
  type        = string
  default     = "siem-system"
}

variable "kubernetes_config_path" {
  description = "Path to Kubernetes config file"
  type        = string
  default     = "~/.kube/config"
}

variable "kubernetes_context" {
  description = "Kubernetes context to use"
  type        = string
  default     = ""
}

# =============================================================================
# INFRASTRUCTURE CONFIGURATION
# =============================================================================

variable "instance_type" {
  description = "Instance type for SIEM nodes"
  type = object({
    aws   = string
    azure = string
    gcp   = string
  })
  default = {
    aws   = "t3.xlarge"      # 4 vCPU, 16 GB RAM
    azure = "Standard_D4s_v3" # 4 vCPU, 16 GB RAM
    gcp   = "n1-standard-4"   # 4 vCPU, 15 GB RAM
  }
}

variable "node_count" {
  description = "Number of SIEM nodes"
  type        = number
  default     = 3
  validation {
    condition     = var.node_count >= 1 && var.node_count <= 10
    error_message = "Node count must be between 1 and 10."
  }
}

variable "disk_size" {
  description = "Disk size in GB for each node"
  type        = number
  default     = 100
  validation {
    condition     = var.disk_size >= 50 && var.disk_size <= 1000
    error_message = "Disk size must be between 50 and 1000 GB."
  }
}

variable "disk_type" {
  description = "Disk type for storage"
  type = object({
    aws   = string
    azure = string
    gcp   = string
  })
  default = {
    aws   = "gp3"
    azure = "Premium_LRS"
    gcp   = "pd-ssd"
  }
}

variable "enable_auto_scaling" {
  description = "Enable auto scaling for SIEM nodes"
  type        = bool
  default     = true
}

variable "min_nodes" {
  description = "Minimum number of nodes for auto scaling"
  type        = number
  default     = 1
}

variable "max_nodes" {
  description = "Maximum number of nodes for auto scaling"
  type        = number
  default     = 10
}

# =============================================================================
# NETWORK CONFIGURATION
# =============================================================================

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "VPC CIDR must be a valid CIDR block."
  }
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets"
  type        = list(string)
  default     = ["10.0.11.0/24", "10.0.12.0/24", "10.0.13.0/24"]
}

variable "allowed_cidr_blocks" {
  description = "CIDR blocks allowed to access SIEM"
  type        = list(string)
  default     = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
}

variable "enable_nat_gateway" {
  description = "Enable NAT Gateway for private subnets"
  type        = bool
  default     = true
}

variable "enable_vpn_gateway" {
  description = "Enable VPN Gateway"
  type        = bool
  default     = false
}

variable "enable_flow_logs" {
  description = "Enable VPC Flow Logs"
  type        = bool
  default     = true
}

# =============================================================================
# SECURITY CONFIGURATION
# =============================================================================

variable "ssl_certificate_arn" {
  description = "SSL certificate ARN for load balancer"
  type        = string
  default     = ""
}

variable "domain_name" {
  description = "Domain name for SIEM access"
  type        = string
  default     = ""
}

variable "enable_waf" {
  description = "Enable Web Application Firewall"
  type        = bool
  default     = true
}

variable "enable_ddos_protection" {
  description = "Enable DDoS protection"
  type        = bool
  default     = true
}

variable "enable_encryption_at_rest" {
  description = "Enable encryption at rest for storage"
  type        = bool
  default     = true
}

variable "enable_encryption_in_transit" {
  description = "Enable encryption in transit"
  type        = bool
  default     = true
}

variable "kms_key_id" {
  description = "KMS key ID for encryption"
  type        = string
  default     = ""
}

variable "enable_secrets_manager" {
  description = "Enable secrets manager for sensitive data"
  type        = bool
  default     = true
}

# =============================================================================
# SIEM COMPONENT CONFIGURATION
# =============================================================================

variable "elasticsearch_version" {
  description = "Elasticsearch version"
  type        = string
  default     = "8.11.0"
}

variable "elasticsearch_heap_size" {
  description = "Elasticsearch heap size"
  type        = string
  default     = "2g"
}

variable "elasticsearch_cluster_name" {
  description = "Elasticsearch cluster name"
  type        = string
  default     = "siem-cluster"
}

variable "kibana_version" {
  description = "Kibana version"
  type        = string
  default     = "8.11.0"
}

variable "wazuh_version" {
  description = "Wazuh version"
  type        = string
  default     = "4.7.0"
}

variable "logstash_version" {
  description = "Logstash version"
  type        = string
  default     = "8.11.0"
}

variable "logstash_heap_size" {
  description = "Logstash heap size"
  type        = string
  default     = "1g"
}

variable "suricata_version" {
  description = "Suricata version"
  type        = string
  default     = "7.0.2"
}

variable "grafana_version" {
  description = "Grafana version"
  type        = string
  default     = "10.2.0"
}

variable "prometheus_version" {
  description = "Prometheus version"
  type        = string
  default     = "v2.47.0"
}

variable "postgres_version" {
  description = "PostgreSQL version"
  type        = string
  default     = "15"
}

variable "redis_version" {
  description = "Redis version"
  type        = string
  default     = "7-alpine"
}

# =============================================================================
# MONITORING AND ALERTING
# =============================================================================

variable "enable_monitoring" {
  description = "Enable monitoring and alerting"
  type        = bool
  default     = true
}

variable "enable_prometheus" {
  description = "Enable Prometheus monitoring"
  type        = bool
  default     = true
}

variable "enable_grafana" {
  description = "Enable Grafana dashboards"
  type        = bool
  default     = true
}

variable "enable_alertmanager" {
  description = "Enable Alertmanager"
  type        = bool
  default     = true
}

variable "enable_elastalert" {
  description = "Enable ElastAlert"
  type        = bool
  default     = true
}

variable "monitoring_retention_days" {
  description = "Number of days to retain monitoring data"
  type        = number
  default     = 30
}

variable "alert_email" {
  description = "Email address for alerts"
  type        = string
  default     = ""
}

variable "slack_webhook_url" {
  description = "Slack webhook URL for alerts"
  type        = string
  default     = ""
  sensitive   = true
}

variable "pagerduty_integration_key" {
  description = "PagerDuty integration key"
  type        = string
  default     = ""
  sensitive   = true
}

# =============================================================================
# BACKUP AND DISASTER RECOVERY
# =============================================================================

variable "enable_backup" {
  description = "Enable automated backups"
  type        = bool
  default     = true
}

variable "backup_retention_days" {
  description = "Number of days to retain backups"
  type        = number
  default     = 30
  validation {
    condition     = var.backup_retention_days >= 1 && var.backup_retention_days <= 365
    error_message = "Backup retention days must be between 1 and 365."
  }
}

variable "backup_schedule" {
  description = "Backup schedule in cron format"
  type        = string
  default     = "0 2 * * *" # Daily at 2 AM
}

variable "enable_cross_region_backup" {
  description = "Enable cross-region backup replication"
  type        = bool
  default     = false
}

variable "backup_region" {
  description = "Region for backup replication"
  type        = string
  default     = ""
}

variable "enable_point_in_time_recovery" {
  description = "Enable point-in-time recovery"
  type        = bool
  default     = true
}

# =============================================================================
# DATA RETENTION AND COMPLIANCE
# =============================================================================

variable "log_retention_days" {
  description = "Number of days to retain logs"
  type        = number
  default     = 90
}

variable "audit_log_retention_days" {
  description = "Number of days to retain audit logs"
  type        = number
  default     = 365
}

variable "enable_compliance_mode" {
  description = "Enable compliance mode (GDPR, HIPAA, etc.)"
  type        = bool
  default     = false
}

variable "compliance_frameworks" {
  description = "List of compliance frameworks to adhere to"
  type        = list(string)
  default     = []
  validation {
    condition = alltrue([
      for framework in var.compliance_frameworks :
      contains(["GDPR", "HIPAA", "PCI-DSS", "SOX", "ISO27001", "NIST"], framework)
    ])
    error_message = "Compliance frameworks must be one of: GDPR, HIPAA, PCI-DSS, SOX, ISO27001, NIST."
  }
}

variable "enable_data_encryption" {
  description = "Enable data encryption for compliance"
  type        = bool
  default     = true
}

variable "enable_audit_logging" {
  description = "Enable comprehensive audit logging"
  type        = bool
  default     = true
}

# =============================================================================
# PERFORMANCE AND SCALING
# =============================================================================

variable "enable_performance_monitoring" {
  description = "Enable performance monitoring"
  type        = bool
  default     = true
}

variable "cpu_threshold" {
  description = "CPU threshold for scaling alerts"
  type        = number
  default     = 80
}

variable "memory_threshold" {
  description = "Memory threshold for scaling alerts"
  type        = number
  default     = 80
}

variable "disk_threshold" {
  description = "Disk usage threshold for alerts"
  type        = number
  default     = 85
}

variable "network_threshold" {
  description = "Network usage threshold for alerts"
  type        = number
  default     = 80
}

variable "enable_auto_remediation" {
  description = "Enable automatic remediation for common issues"
  type        = bool
  default     = false
}

# =============================================================================
# TERRAFORM STATE MANAGEMENT
# =============================================================================

variable "terraform_state_bucket" {
  description = "S3 bucket for Terraform state"
  type        = string
  default     = ""
}

variable "terraform_lock_table" {
  description = "DynamoDB table for Terraform state locking"
  type        = string
  default     = ""
}

variable "terraform_state_key" {
  description = "Key for Terraform state file"
  type        = string
  default     = "siem/terraform.tfstate"
}

variable "enable_state_encryption" {
  description = "Enable encryption for Terraform state"
  type        = bool
  default     = true
}

# =============================================================================
# DEVELOPMENT AND TESTING
# =============================================================================

variable "enable_debug_mode" {
  description = "Enable debug mode for troubleshooting"
  type        = bool
  default     = false
}

variable "enable_test_data" {
  description = "Enable test data generation"
  type        = bool
  default     = false
}

variable "test_data_volume" {
  description = "Volume of test data to generate (low, medium, high)"
  type        = string
  default     = "low"
  validation {
    condition     = contains(["low", "medium", "high"], var.test_data_volume)
    error_message = "Test data volume must be one of: low, medium, high."
  }
}

variable "enable_development_tools" {
  description = "Enable development tools and utilities"
  type        = bool
  default     = false
}

# =============================================================================
# COST OPTIMIZATION
# =============================================================================

variable "enable_cost_optimization" {
  description = "Enable cost optimization features"
  type        = bool
  default     = true
}

variable "enable_spot_instances" {
  description = "Enable spot instances for cost savings"
  type        = bool
  default     = false
}

variable "spot_instance_percentage" {
  description = "Percentage of spot instances to use"
  type        = number
  default     = 50
  validation {
    condition     = var.spot_instance_percentage >= 0 && var.spot_instance_percentage <= 100
    error_message = "Spot instance percentage must be between 0 and 100."
  }
}

variable "enable_scheduled_scaling" {
  description = "Enable scheduled scaling for cost optimization"
  type        = bool
  default     = false
}

variable "business_hours_start" {
  description = "Business hours start time (24-hour format)"
  type        = string
  default     = "08:00"
}

variable "business_hours_end" {
  description = "Business hours end time (24-hour format)"
  type        = string
  default     = "18:00"
}

# =============================================================================
# RESOURCE TAGGING
# =============================================================================

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default = {
    Project     = "SIEM-PyMES"
    Environment = "production"
    Owner       = "security-team"
    Purpose     = "security-monitoring"
    CostCenter  = "security"
    Compliance  = "required"
  }
}

variable "additional_tags" {
  description = "Additional tags to apply to resources"
  type        = map(string)
  default     = {}
}

# =============================================================================
# FEATURE FLAGS
# =============================================================================

variable "feature_flags" {
  description = "Feature flags for experimental or optional features"
  type = object({
    enable_machine_learning     = bool
    enable_threat_intelligence  = bool
    enable_user_behavior_analytics = bool
    enable_network_segmentation = bool
    enable_zero_trust          = bool
    enable_cloud_security      = bool
    enable_container_security  = bool
    enable_api_security        = bool
  })
  default = {
    enable_machine_learning     = false
    enable_threat_intelligence  = true
    enable_user_behavior_analytics = false
    enable_network_segmentation = true
    enable_zero_trust          = false
    enable_cloud_security      = true
    enable_container_security  = true
    enable_api_security        = true
  }
}

# =============================================================================
# INTEGRATION CONFIGURATION
# =============================================================================

variable "external_integrations" {
  description = "Configuration for external integrations"
  type = object({
    enable_splunk_integration    = bool
    enable_qradar_integration   = bool
    enable_sentinel_integration = bool
    enable_crowdstrike_integration = bool
    enable_carbon_black_integration = bool
    enable_okta_integration     = bool
    enable_ad_integration       = bool
  })
  default = {
    enable_splunk_integration    = false
    enable_qradar_integration   = false
    enable_sentinel_integration = false
    enable_crowdstrike_integration = false
    enable_carbon_black_integration = false
    enable_okta_integration     = false
    enable_ad_integration       = false
  }
}

variable "api_keys" {
  description = "API keys for external services"
  type = object({
    virustotal_api_key = string
    shodan_api_key     = string
    misp_api_key       = string
    otx_api_key        = string
  })
  default = {
    virustotal_api_key = ""
    shodan_api_key     = ""
    misp_api_key       = ""
    otx_api_key        = ""
  }
  sensitive = true
}

# =============================================================================
# CUSTOM CONFIGURATION
# =============================================================================

variable "custom_config" {
  description = "Custom configuration parameters"
  type        = map(any)
  default     = {}
}

variable "custom_scripts" {
  description = "Custom scripts to run during deployment"
  type        = list(string)
  default     = []
}

variable "custom_rules" {
  description = "Custom security rules and policies"
  type        = map(string)
  default     = {}
}

variable "custom_dashboards" {
  description = "Custom dashboard configurations"
  type        = list(string)
  default     = []
}

# =============================================================================
# END OF VARIABLES
# =============================================================================