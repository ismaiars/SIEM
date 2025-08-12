# SIEM OpenSource PyMES - Variables de Terraform
# Variables configuration for SIEM infrastructure

# General Configuration
variable "project_name" {
  description = "Name of the SIEM project"
  type        = string
  default     = "siem-opensrc-pymes"
}

variable "environment" {
  description = "Environment name (dev, staging, production)"
  type        = string
  default     = "production"
  
  validation {
    condition     = contains(["dev", "staging", "production"], var.environment)
    error_message = "Environment must be one of: dev, staging, production."
  }
}

variable "owner" {
  description = "Owner of the infrastructure"
  type        = string
  default     = "SIEM-Team"
}

variable "cost_center" {
  description = "Cost center for billing"
  type        = string
  default     = "IT-Security"
}

# AWS Configuration
variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "aws_profile" {
  description = "AWS profile to use"
  type        = string
  default     = "default"
}

# Network Configuration
variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
  
  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "VPC CIDR must be a valid IPv4 CIDR block."
  }
}

variable "allowed_cidr_blocks" {
  description = "List of CIDR blocks allowed to access the SIEM"
  type        = list(string)
  default     = ["0.0.0.0/0"]  # Change this in production!
}

variable "domain_name" {
  description = "Domain name for the SIEM services"
  type        = string
  default     = "siem.company.com"
}

variable "create_route53_zone" {
  description = "Whether to create Route53 hosted zone"
  type        = bool
  default     = true
}

# EKS Configuration
variable "kubernetes_version" {
  description = "Kubernetes version for EKS cluster"
  type        = string
  default     = "1.28"
}

variable "eks_node_instance_types" {
  description = "Instance types for EKS worker nodes"
  type        = list(string)
  default     = ["t3.large", "t3.xlarge"]
}

variable "eks_desired_capacity" {
  description = "Desired number of EKS worker nodes"
  type        = number
  default     = 3
}

variable "eks_min_capacity" {
  description = "Minimum number of EKS worker nodes"
  type        = number
  default     = 2
}

variable "eks_max_capacity" {
  description = "Maximum number of EKS worker nodes"
  type        = number
  default     = 10
}

variable "elasticsearch_instance_types" {
  description = "Instance types for Elasticsearch nodes"
  type        = list(string)
  default     = ["r5.large", "r5.xlarge"]
}

# RDS Configuration
variable "rds_instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.t3.medium"
}

variable "rds_allocated_storage" {
  description = "Initial allocated storage for RDS (GB)"
  type        = number
  default     = 100
}

variable "rds_max_allocated_storage" {
  description = "Maximum allocated storage for RDS (GB)"
  type        = number
  default     = 1000
}

variable "db_name" {
  description = "Name of the PostgreSQL database"
  type        = string
  default     = "siem_db"
}

variable "db_username" {
  description = "Username for the PostgreSQL database"
  type        = string
  default     = "siem_admin"
}

# Redis Configuration
variable "redis_node_type" {
  description = "ElastiCache Redis node type"
  type        = string
  default     = "cache.t3.medium"
}

variable "redis_num_nodes" {
  description = "Number of Redis cache nodes"
  type        = number
  default     = 1
}

# Monitoring and Logging
variable "log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 30
}

variable "alert_email" {
  description = "Email address for alerts"
  type        = string
  default     = ""
}

variable "enable_detailed_monitoring" {
  description = "Enable detailed monitoring for resources"
  type        = bool
  default     = true
}

# Security Configuration
variable "enable_encryption" {
  description = "Enable encryption for all supported resources"
  type        = bool
  default     = true
}

variable "enable_backup" {
  description = "Enable automated backups"
  type        = bool
  default     = true
}

variable "backup_retention_days" {
  description = "Number of days to retain backups"
  type        = number
  default     = 30
}

# SIEM Specific Configuration
variable "elasticsearch_version" {
  description = "Elasticsearch version"
  type        = string
  default     = "8.11.0"
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

variable "filebeat_version" {
  description = "Filebeat version"
  type        = string
  default     = "8.11.0"
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

# Storage Configuration
variable "elasticsearch_storage_size" {
  description = "Storage size for Elasticsearch nodes (GB)"
  type        = number
  default     = 500
}

variable "elasticsearch_storage_type" {
  description = "Storage type for Elasticsearch"
  type        = string
  default     = "gp3"
  
  validation {
    condition     = contains(["gp2", "gp3", "io1", "io2"], var.elasticsearch_storage_type)
    error_message = "Storage type must be one of: gp2, gp3, io1, io2."
  }
}

variable "log_storage_size" {
  description = "Storage size for log retention (GB)"
  type        = number
  default     = 1000
}

# Performance Configuration
variable "elasticsearch_heap_size" {
  description = "Elasticsearch heap size (e.g., 2g, 4g)"
  type        = string
  default     = "2g"
}

variable "logstash_heap_size" {
  description = "Logstash heap size (e.g., 1g, 2g)"
  type        = string
  default     = "1g"
}

variable "elasticsearch_replicas" {
  description = "Number of Elasticsearch replicas"
  type        = number
  default     = 1
}

variable "elasticsearch_shards" {
  description = "Number of Elasticsearch primary shards"
  type        = number
  default     = 3
}

# High Availability Configuration
variable "enable_multi_az" {
  description = "Enable multi-AZ deployment"
  type        = bool
  default     = true
}

variable "enable_auto_scaling" {
  description = "Enable auto scaling for EKS nodes"
  type        = bool
  default     = true
}

variable "enable_cluster_autoscaler" {
  description = "Enable cluster autoscaler"
  type        = bool
  default     = true
}

# Compliance and Governance
variable "enable_compliance_logging" {
  description = "Enable compliance logging"
  type        = bool
  default     = true
}

variable "enable_audit_logging" {
  description = "Enable audit logging"
  type        = bool
  default     = true
}

variable "compliance_standards" {
  description = "List of compliance standards to adhere to"
  type        = list(string)
  default     = ["SOC2", "ISO27001", "GDPR"]
}

# Development and Testing
variable "enable_dev_tools" {
  description = "Enable development and debugging tools"
  type        = bool
  default     = false
}

variable "enable_test_data" {
  description = "Enable test data generation"
  type        = bool
  default     = false
}

# Cost Optimization
variable "enable_spot_instances" {
  description = "Enable spot instances for cost optimization"
  type        = bool
  default     = false
}

variable "spot_instance_percentage" {
  description = "Percentage of spot instances in node groups"
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

# Integration Configuration
variable "slack_webhook_url" {
  description = "Slack webhook URL for notifications"
  type        = string
  default     = ""
  sensitive   = true
}

variable "teams_webhook_url" {
  description = "Microsoft Teams webhook URL for notifications"
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

variable "jira_url" {
  description = "JIRA URL for ticket integration"
  type        = string
  default     = ""
}

variable "jira_username" {
  description = "JIRA username"
  type        = string
  default     = ""
}

variable "jira_api_token" {
  description = "JIRA API token"
  type        = string
  default     = ""
  sensitive   = true
}

# Threat Intelligence Configuration
variable "enable_threat_intel" {
  description = "Enable threat intelligence feeds"
  type        = bool
  default     = true
}

variable "threat_intel_feeds" {
  description = "List of threat intelligence feeds"
  type        = list(string)
  default     = [
    "alienvault",
    "emergingthreats",
    "malwaredomainlist",
    "spamhaus"
  ]
}

variable "virustotal_api_key" {
  description = "VirusTotal API key"
  type        = string
  default     = ""
  sensitive   = true
}

variable "shodan_api_key" {
  description = "Shodan API key"
  type        = string
  default     = ""
  sensitive   = true
}

# Machine Learning Configuration
variable "enable_ml_features" {
  description = "Enable machine learning features"
  type        = bool
  default     = true
}

variable "ml_node_instance_type" {
  description = "Instance type for ML nodes"
  type        = string
  default     = "m5.large"
}

variable "enable_anomaly_detection" {
  description = "Enable anomaly detection"
  type        = bool
  default     = true
}

variable "enable_behavioral_analytics" {
  description = "Enable user behavioral analytics"
  type        = bool
  default     = true
}

# Data Retention Configuration
variable "hot_data_retention_days" {
  description = "Days to keep data in hot storage"
  type        = number
  default     = 7
}

variable "warm_data_retention_days" {
  description = "Days to keep data in warm storage"
  type        = number
  default     = 30
}

variable "cold_data_retention_days" {
  description = "Days to keep data in cold storage"
  type        = number
  default     = 365
}

variable "archive_data_retention_days" {
  description = "Days to keep data in archive storage"
  type        = number
  default     = 2555  # 7 years
}

# Network Security Configuration
variable "enable_waf" {
  description = "Enable AWS WAF"
  type        = bool
  default     = true
}

variable "enable_ddos_protection" {
  description = "Enable DDoS protection"
  type        = bool
  default     = true
}

variable "enable_vpc_flow_logs" {
  description = "Enable VPC flow logs"
  type        = bool
  default     = true
}

variable "enable_guardduty" {
  description = "Enable AWS GuardDuty"
  type        = bool
  default     = true
}

variable "enable_security_hub" {
  description = "Enable AWS Security Hub"
  type        = bool
  default     = true
}

# Disaster Recovery Configuration
variable "enable_cross_region_backup" {
  description = "Enable cross-region backup"
  type        = bool
  default     = true
}

variable "backup_region" {
  description = "AWS region for backups"
  type        = string
  default     = "us-west-2"
}

variable "rpo_hours" {
  description = "Recovery Point Objective in hours"
  type        = number
  default     = 4
}

variable "rto_hours" {
  description = "Recovery Time Objective in hours"
  type        = number
  default     = 8
}

# Custom Configuration
variable "custom_tags" {
  description = "Custom tags to apply to all resources"
  type        = map(string)
  default     = {}
}

variable "custom_security_groups" {
  description = "Custom security group rules"
  type = list(object({
    from_port   = number
    to_port     = number
    protocol    = string
    cidr_blocks = list(string)
    description = string
  }))
  default = []
}

variable "custom_elasticsearch_config" {
  description = "Custom Elasticsearch configuration"
  type        = map(any)
  default     = {}
}

variable "custom_kibana_config" {
  description = "Custom Kibana configuration"
  type        = map(any)
  default     = {}
}

variable "custom_wazuh_config" {
  description = "Custom Wazuh configuration"
  type        = map(any)
  default     = {}
}