# =============================================================================
# Terraform Outputs for SIEM OpenSource PyMES
# =============================================================================
# This file defines outputs that will be displayed after deployment
# =============================================================================

# =============================================================================
# GENERAL DEPLOYMENT INFORMATION
# =============================================================================

output "deployment_info" {
  description = "General deployment information"
  value = {
    project_name     = var.project_name
    environment      = var.environment
    cloud_provider   = var.cloud_provider
    deployment_time  = timestamp()
    terraform_version = ">=1.0"
  }
}

output "deployment_region" {
  description = "Deployment region information"
  value = {
    aws_region   = var.cloud_provider == "aws" ? var.aws_region : null
    azure_location = var.cloud_provider == "azure" ? var.azure_location : null
    gcp_region   = var.cloud_provider == "gcp" ? var.gcp_region : null
    gcp_zone     = var.cloud_provider == "gcp" ? var.gcp_zone : null
  }
}

# =============================================================================
# NETWORK INFRASTRUCTURE OUTPUTS
# =============================================================================

output "network_info" {
  description = "Network infrastructure information"
  value = var.cloud_provider == "aws" ? {
    vpc_id               = try(aws_vpc.main[0].id, null)
    vpc_cidr             = try(aws_vpc.main[0].cidr_block, null)
    internet_gateway_id  = try(aws_internet_gateway.main[0].id, null)
    public_subnet_ids    = try(aws_subnet.public[*].id, [])
    private_subnet_ids   = try(aws_subnet.private[*].id, [])
    public_subnet_cidrs  = try(aws_subnet.public[*].cidr_block, [])
    private_subnet_cidrs = try(aws_subnet.private[*].cidr_block, [])
    nat_gateway_ids      = try(aws_nat_gateway.main[*].id, [])
    route_table_ids = {
      public  = try(aws_route_table.public[0].id, null)
      private = try(aws_route_table.private[*].id, [])
    }
  } : null
}

output "security_groups" {
  description = "Security group information"
  value = var.cloud_provider == "aws" ? {
    load_balancer_sg_id = try(aws_security_group.siem_lb[0].id, null)
    nodes_sg_id         = try(aws_security_group.siem_nodes[0].id, null)
    load_balancer_sg_arn = try(aws_security_group.siem_lb[0].arn, null)
    nodes_sg_arn        = try(aws_security_group.siem_nodes[0].arn, null)
  } : null
}

# =============================================================================
# COMPUTE INFRASTRUCTURE OUTPUTS
# =============================================================================

output "compute_info" {
  description = "Compute infrastructure information"
  value = var.cloud_provider == "aws" ? {
    launch_template_id      = try(aws_launch_template.siem[0].id, null)
    launch_template_version = try(aws_launch_template.siem[0].latest_version, null)
    auto_scaling_group_name = try(aws_autoscaling_group.siem[0].name, null)
    auto_scaling_group_arn  = try(aws_autoscaling_group.siem[0].arn, null)
    key_pair_name          = try(aws_key_pair.siem[0].key_name, null)
    instance_type          = var.instance_type.aws
    node_count             = var.node_count
    disk_size              = var.disk_size
  } : null
}

# =============================================================================
# LOAD BALANCER OUTPUTS
# =============================================================================

output "load_balancer_info" {
  description = "Load balancer information"
  value = var.cloud_provider == "aws" ? {
    load_balancer_arn      = try(aws_lb.siem[0].arn, null)
    load_balancer_dns_name = try(aws_lb.siem[0].dns_name, null)
    load_balancer_zone_id  = try(aws_lb.siem[0].zone_id, null)
    target_group_arns      = try(aws_lb_target_group.siem[*].arn, [])
    listener_arns = {
      http  = try(aws_lb_listener.siem_http[0].arn, null)
      https = try(aws_lb_listener.siem_https[0].arn, null)
    }
  } : null
}

output "load_balancer_dns" {
  description = "DNS name of the load balancer"
  value       = var.cloud_provider == "aws" ? try(aws_lb.siem[0].dns_name, null) : null
}

# =============================================================================
# SIEM ACCESS URLS
# =============================================================================

output "siem_access_urls" {
  description = "URLs to access SIEM components"
  value = var.cloud_provider == "aws" && length(aws_lb.siem) > 0 ? {
    kibana = {
      url         = "https://${aws_lb.siem[0].dns_name}:5601"
      description = "Kibana Dashboard - Log Analysis and Visualization"
    }
    wazuh = {
      url         = "https://${aws_lb.siem[0].dns_name}"
      description = "Wazuh Dashboard - Security Monitoring and Compliance"
    }
    grafana = {
      url         = "https://${aws_lb.siem[0].dns_name}:3000"
      description = "Grafana - Metrics and Performance Monitoring"
    }
    prometheus = {
      url         = "https://${aws_lb.siem[0].dns_name}:9090"
      description = "Prometheus - Metrics Collection and Alerting"
    }
    elasticsearch = {
      url         = "https://${aws_lb.siem[0].dns_name}:9200"
      description = "Elasticsearch API - Direct Database Access"
    }
    alertmanager = {
      url         = "https://${aws_lb.siem[0].dns_name}:9093"
      description = "Alertmanager - Alert Management and Routing"
    }
  } : null
}

output "siem_endpoints" {
  description = "SIEM service endpoints"
  value = var.cloud_provider == "aws" && length(aws_lb.siem) > 0 ? {
    base_url = "https://${aws_lb.siem[0].dns_name}"
    ports = {
      kibana        = 5601
      elasticsearch = 9200
      wazuh         = 443
      grafana       = 3000
      prometheus    = 9090
      alertmanager  = 9093
      logstash      = 5044
      syslog        = 514
      wazuh_agent   = 1514
    }
  } : null
}

# =============================================================================
# STORAGE OUTPUTS
# =============================================================================

output "storage_info" {
  description = "Storage infrastructure information"
  value = var.cloud_provider == "aws" ? {
    s3_bucket_name        = try(aws_s3_bucket.logs[0].bucket, null)
    s3_bucket_arn         = try(aws_s3_bucket.logs[0].arn, null)
    s3_bucket_domain_name = try(aws_s3_bucket.logs[0].bucket_domain_name, null)
    backup_vault_name     = var.enable_backup ? try(aws_backup_vault.siem[0].name, null) : null
    backup_vault_arn      = var.enable_backup ? try(aws_backup_vault.siem[0].arn, null) : null
    kms_key_id           = var.enable_backup ? try(aws_kms_key.backup[0].key_id, null) : null
    kms_key_arn          = var.enable_backup ? try(aws_kms_key.backup[0].arn, null) : null
  } : null
}

# =============================================================================
# MONITORING OUTPUTS
# =============================================================================

output "monitoring_info" {
  description = "Monitoring and alerting information"
  value = var.enable_monitoring ? {
    cloudwatch_log_group = var.cloud_provider == "aws" ? try(aws_cloudwatch_log_group.siem[0].name, null) : null
    sns_topic_arn       = var.cloud_provider == "aws" ? try(aws_sns_topic.alerts[0].arn, null) : null
    alarm_names         = var.cloud_provider == "aws" ? try([aws_cloudwatch_metric_alarm.high_cpu[0].alarm_name], []) : []
    monitoring_enabled  = var.enable_monitoring
    prometheus_enabled  = var.enable_prometheus
    grafana_enabled     = var.enable_grafana
    alertmanager_enabled = var.enable_alertmanager
  } : null
}

# =============================================================================
# SECURITY OUTPUTS
# =============================================================================

output "security_info" {
  description = "Security configuration information"
  value = {
    ssl_enabled                = var.ssl_certificate_arn != ""
    waf_enabled               = var.enable_waf
    ddos_protection_enabled   = var.enable_ddos_protection
    encryption_at_rest        = var.enable_encryption_at_rest
    encryption_in_transit     = var.enable_encryption_in_transit
    secrets_manager_enabled   = var.enable_secrets_manager
    compliance_mode_enabled   = var.enable_compliance_mode
    compliance_frameworks     = var.compliance_frameworks
    audit_logging_enabled     = var.enable_audit_logging
  }
}

# =============================================================================
# BACKUP AND RECOVERY OUTPUTS
# =============================================================================

output "backup_info" {
  description = "Backup and disaster recovery information"
  value = var.enable_backup ? {
    backup_enabled            = var.enable_backup
    backup_retention_days     = var.backup_retention_days
    backup_schedule          = var.backup_schedule
    cross_region_backup      = var.enable_cross_region_backup
    backup_region           = var.backup_region
    point_in_time_recovery  = var.enable_point_in_time_recovery
    backup_vault_name       = var.cloud_provider == "aws" ? try(aws_backup_vault.siem[0].name, null) : null
  } : null
}

# =============================================================================
# CONFIGURATION OUTPUTS
# =============================================================================

output "siem_configuration" {
  description = "SIEM component configuration"
  value = {
    elasticsearch = {
      version      = var.elasticsearch_version
      heap_size    = var.elasticsearch_heap_size
      cluster_name = var.elasticsearch_cluster_name
    }
    kibana = {
      version = var.kibana_version
    }
    wazuh = {
      version = var.wazuh_version
    }
    logstash = {
      version   = var.logstash_version
      heap_size = var.logstash_heap_size
    }
    suricata = {
      version = var.suricata_version
    }
    grafana = {
      version = var.grafana_version
    }
    prometheus = {
      version = var.prometheus_version
    }
    postgres = {
      version = var.postgres_version
    }
    redis = {
      version = var.redis_version
    }
  }
}

# =============================================================================
# COST INFORMATION
# =============================================================================

output "cost_optimization" {
  description = "Cost optimization configuration"
  value = {
    cost_optimization_enabled = var.enable_cost_optimization
    spot_instances_enabled   = var.enable_spot_instances
    spot_instance_percentage = var.spot_instance_percentage
    scheduled_scaling_enabled = var.enable_scheduled_scaling
    business_hours = {
      start = var.business_hours_start
      end   = var.business_hours_end
    }
  }
}

# =============================================================================
# FEATURE FLAGS
# =============================================================================

output "enabled_features" {
  description = "Enabled features and capabilities"
  value = {
    feature_flags = var.feature_flags
    integrations  = var.external_integrations
    monitoring = {
      prometheus_enabled       = var.enable_prometheus
      grafana_enabled         = var.enable_grafana
      alertmanager_enabled    = var.enable_alertmanager
      elastalert_enabled      = var.enable_elastalert
      performance_monitoring  = var.enable_performance_monitoring
    }
    security = {
      waf_enabled             = var.enable_waf
      ddos_protection        = var.enable_ddos_protection
      encryption_at_rest     = var.enable_encryption_at_rest
      encryption_in_transit  = var.enable_encryption_in_transit
      compliance_mode        = var.enable_compliance_mode
    }
  }
}

# =============================================================================
# CONNECTION INFORMATION
# =============================================================================

output "connection_info" {
  description = "Connection information for SIEM components"
  value = var.cloud_provider == "aws" && length(aws_lb.siem) > 0 ? {
    ssh_command = "ssh -i ~/.ssh/id_rsa ubuntu@<instance-ip>"
    load_balancer_dns = aws_lb.siem[0].dns_name
    vpc_id = try(aws_vpc.main[0].id, null)
    security_groups = {
      load_balancer = try(aws_security_group.siem_lb[0].id, null)
      nodes         = try(aws_security_group.siem_nodes[0].id, null)
    }
    allowed_cidr_blocks = var.allowed_cidr_blocks
  } : null
}

# =============================================================================
# MAINTENANCE INFORMATION
# =============================================================================

output "maintenance_info" {
  description = "Maintenance and operational information"
  value = {
    log_retention_days       = var.log_retention_days
    audit_log_retention_days = var.audit_log_retention_days
    monitoring_retention_days = var.monitoring_retention_days
    auto_scaling_enabled     = var.enable_auto_scaling
    min_nodes               = var.min_nodes
    max_nodes               = var.max_nodes
    auto_remediation_enabled = var.enable_auto_remediation
    debug_mode_enabled      = var.enable_debug_mode
  }
}

# =============================================================================
# ALERT THRESHOLDS
# =============================================================================

output "alert_thresholds" {
  description = "Configured alert thresholds"
  value = {
    cpu_threshold     = var.cpu_threshold
    memory_threshold  = var.memory_threshold
    disk_threshold    = var.disk_threshold
    network_threshold = var.network_threshold
    alert_email      = var.alert_email != "" ? "configured" : "not configured"
    slack_webhook    = var.slack_webhook_url != "" ? "configured" : "not configured"
    pagerduty_key    = var.pagerduty_integration_key != "" ? "configured" : "not configured"
  }
}

# =============================================================================
# DEPLOYMENT SUMMARY
# =============================================================================

output "deployment_summary" {
  description = "Complete deployment summary"
  value = {
    status = "deployed"
    components = {
      elasticsearch = "deployed"
      kibana       = "deployed"
      wazuh        = "deployed"
      logstash     = "deployed"
      suricata     = "deployed"
      grafana      = var.enable_grafana ? "deployed" : "disabled"
      prometheus   = var.enable_prometheus ? "deployed" : "disabled"
      alertmanager = var.enable_alertmanager ? "deployed" : "disabled"
      elastalert   = var.enable_elastalert ? "deployed" : "disabled"
    }
    infrastructure = {
      cloud_provider = var.cloud_provider
      region        = var.cloud_provider == "aws" ? var.aws_region : (var.cloud_provider == "azure" ? var.azure_location : var.gcp_region)
      node_count    = var.node_count
      instance_type = var.cloud_provider == "aws" ? var.instance_type.aws : (var.cloud_provider == "azure" ? var.instance_type.azure : var.instance_type.gcp)
      disk_size     = var.disk_size
    }
    access = var.cloud_provider == "aws" && length(aws_lb.siem) > 0 ? {
      primary_url = "https://${aws_lb.siem[0].dns_name}"
      kibana_url  = "https://${aws_lb.siem[0].dns_name}:5601"
      grafana_url = "https://${aws_lb.siem[0].dns_name}:3000"
    } : null
  }
}

# =============================================================================
# NEXT STEPS
# =============================================================================

output "next_steps" {
  description = "Recommended next steps after deployment"
  value = {
    immediate = [
      "Wait 5-10 minutes for all services to fully initialize",
      "Access Kibana dashboard to verify Elasticsearch connectivity",
      "Check Wazuh dashboard for agent connectivity",
      "Review Grafana dashboards for system metrics",
      "Verify Prometheus is collecting metrics from all targets"
    ]
    configuration = [
      "Configure log sources to send data to Logstash",
      "Deploy Wazuh agents to monitored systems",
      "Configure Suricata rules for network monitoring",
      "Set up ElastAlert rules for security alerting",
      "Configure notification channels (email, Slack, PagerDuty)"
    ]
    security = [
      "Change default passwords for all services",
      "Configure SSL certificates for production use",
      "Review and adjust security group rules",
      "Enable additional compliance features if required",
      "Set up backup and disaster recovery procedures"
    ]
    monitoring = [
      "Configure custom dashboards in Grafana",
      "Set up additional Prometheus exporters",
      "Configure log retention policies",
      "Set up automated health checks",
      "Configure performance monitoring alerts"
    ]
  }
}

# =============================================================================
# TROUBLESHOOTING
# =============================================================================

output "troubleshooting" {
  description = "Troubleshooting information and common issues"
  value = {
    common_issues = {
      "Services not starting" = "Check Docker logs: docker-compose logs <service-name>"
      "Cannot access dashboards" = "Verify security group rules and load balancer health"
      "High memory usage" = "Adjust Elasticsearch and Logstash heap sizes"
      "Disk space issues" = "Configure log rotation and cleanup policies"
    }
    log_locations = {
      system_logs    = "/var/log/siem*.log"
      docker_logs    = "docker-compose logs"
      service_logs   = "/opt/siem/logs/"
      cloudwatch     = var.cloud_provider == "aws" ? "/aws/ec2/siem" : null
    }
    health_checks = {
      elasticsearch = "curl -X GET 'localhost:9200/_cluster/health'"
      kibana       = "curl -X GET 'localhost:5601/api/status'"
      wazuh        = "curl -X GET 'localhost:55000/'"
      grafana      = "curl -X GET 'localhost:3000/api/health'"
    }
  }
}

# =============================================================================
# RESOURCE TAGS
# =============================================================================

output "resource_tags" {
  description = "Tags applied to all resources"
  value = merge(var.tags, var.additional_tags, {
    Environment     = var.environment
    Project         = var.project_name
    ManagedBy      = "terraform"
    DeploymentDate = timestamp()
    CloudProvider  = var.cloud_provider
  })
}

# =============================================================================
# END OF OUTPUTS
# =============================================================================