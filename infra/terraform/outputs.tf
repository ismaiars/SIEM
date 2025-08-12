# SIEM OpenSource PyMES - Outputs de Terraform
# Output values for SIEM infrastructure

# VPC Outputs
output "vpc_id" {
  description = "ID of the VPC"
  value       = module.vpc.vpc_id
}

output "vpc_cidr_block" {
  description = "CIDR block of the VPC"
  value       = module.vpc.vpc_cidr_block
}

output "private_subnet_ids" {
  description = "IDs of the private subnets"
  value       = module.vpc.private_subnet_ids
}

output "public_subnet_ids" {
  description = "IDs of the public subnets"
  value       = module.vpc.public_subnet_ids
}

output "database_subnet_ids" {
  description = "IDs of the database subnets"
  value       = module.vpc.database_subnet_ids
}

# EKS Outputs
output "eks_cluster_id" {
  description = "EKS cluster ID"
  value       = module.eks.cluster_id
}

output "eks_cluster_arn" {
  description = "EKS cluster ARN"
  value       = module.eks.cluster_arn
}

output "eks_cluster_name" {
  description = "EKS cluster name"
  value       = module.eks.cluster_name
}

output "eks_cluster_endpoint" {
  description = "EKS cluster endpoint"
  value       = module.eks.cluster_endpoint
}

output "eks_cluster_version" {
  description = "EKS cluster Kubernetes version"
  value       = module.eks.cluster_version
}

output "eks_cluster_security_group_id" {
  description = "Security group ID attached to the EKS cluster"
  value       = module.eks.cluster_security_group_id
}

output "eks_node_groups" {
  description = "EKS node groups"
  value       = module.eks.node_groups
  sensitive   = true
}

output "eks_oidc_issuer_url" {
  description = "The URL on the EKS cluster OIDC Issuer"
  value       = module.eks.cluster_oidc_issuer_url
}

output "eks_cluster_certificate_authority_data" {
  description = "Base64 encoded certificate data required to communicate with the cluster"
  value       = module.eks.cluster_certificate_authority_data
  sensitive   = true
}

# RDS Outputs
output "rds_instance_id" {
  description = "RDS instance ID"
  value       = module.rds.db_instance_id
}

output "rds_instance_arn" {
  description = "RDS instance ARN"
  value       = module.rds.db_instance_arn
}

output "rds_endpoint" {
  description = "RDS instance endpoint"
  value       = module.rds.db_instance_endpoint
  sensitive   = true
}

output "rds_port" {
  description = "RDS instance port"
  value       = module.rds.db_instance_port
}

output "rds_database_name" {
  description = "RDS database name"
  value       = module.rds.db_instance_name
}

output "rds_username" {
  description = "RDS instance root username"
  value       = module.rds.db_instance_username
  sensitive   = true
}

# Redis Outputs
output "redis_cluster_id" {
  description = "ElastiCache Redis cluster ID"
  value       = module.redis.cluster_id
}

output "redis_endpoint" {
  description = "ElastiCache Redis endpoint"
  value       = module.redis.cache_nodes[0].address
  sensitive   = true
}

output "redis_port" {
  description = "ElastiCache Redis port"
  value       = module.redis.cache_nodes[0].port
}

# S3 Outputs
output "s3_bucket_names" {
  description = "Names of the S3 buckets"
  value       = module.s3.bucket_names
}

output "s3_bucket_arns" {
  description = "ARNs of the S3 buckets"
  value       = module.s3.bucket_arns
}

output "s3_bucket_domains" {
  description = "Domain names of the S3 buckets"
  value       = module.s3.bucket_domain_names
}

# Load Balancer Outputs
output "alb_arn" {
  description = "ARN of the Application Load Balancer"
  value       = aws_lb.siem_alb.arn
}

output "alb_dns_name" {
  description = "DNS name of the Application Load Balancer"
  value       = aws_lb.siem_alb.dns_name
}

output "alb_zone_id" {
  description = "Zone ID of the Application Load Balancer"
  value       = aws_lb.siem_alb.zone_id
}

output "alb_target_group_arns" {
  description = "ARNs of the target groups"
  value = {
    kibana         = aws_lb_target_group.kibana.arn
    wazuh_dashboard = aws_lb_target_group.wazuh_dashboard.arn
    grafana        = aws_lb_target_group.grafana.arn
  }
}

# Security Groups Outputs
output "security_group_ids" {
  description = "IDs of the security groups"
  value = {
    alb           = module.security_groups.alb_security_group_id
    eks_cluster   = module.security_groups.eks_cluster_security_group_id
    eks_nodes     = module.security_groups.eks_nodes_security_group_id
    rds           = module.security_groups.rds_security_group_id
    redis         = module.security_groups.redis_security_group_id
    elasticsearch = module.security_groups.elasticsearch_security_group_id
  }
}

# IAM Outputs
output "iam_role_arns" {
  description = "ARNs of the IAM roles"
  value = {
    eks_cluster_role     = module.iam.eks_cluster_role_arn
    eks_node_group_role  = module.iam.eks_node_group_role_arn
    elasticsearch_role   = module.iam.elasticsearch_role_arn
    kibana_role         = module.iam.kibana_role_arn
    wazuh_role          = module.iam.wazuh_role_arn
    logstash_role       = module.iam.logstash_role_arn
    filebeat_role       = module.iam.filebeat_role_arn
  }
}

# Route53 Outputs
output "route53_zone_id" {
  description = "Route53 hosted zone ID"
  value       = var.create_route53_zone ? aws_route53_zone.siem_zone[0].zone_id : null
}

output "route53_name_servers" {
  description = "Route53 name servers"
  value       = var.create_route53_zone ? aws_route53_zone.siem_zone[0].name_servers : null
}

# DNS Outputs
output "siem_urls" {
  description = "URLs for SIEM services"
  value = {
    kibana         = "https://kibana.${var.domain_name}"
    wazuh_dashboard = "https://wazuh.${var.domain_name}"
    grafana        = "https://grafana.${var.domain_name}"
    elasticsearch  = "https://elasticsearch.${var.domain_name}"
  }
}

# Certificate Outputs
output "acm_certificate_arn" {
  description = "ARN of the ACM certificate"
  value       = aws_acm_certificate.siem_cert.arn
}

output "acm_certificate_domain_validation_options" {
  description = "Domain validation options for the certificate"
  value       = aws_acm_certificate.siem_cert.domain_validation_options
  sensitive   = true
}

# KMS Outputs
output "kms_key_id" {
  description = "KMS key ID"
  value       = aws_kms_key.siem_key.key_id
}

output "kms_key_arn" {
  description = "KMS key ARN"
  value       = aws_kms_key.siem_key.arn
}

output "kms_key_alias" {
  description = "KMS key alias"
  value       = aws_kms_alias.siem_key_alias.name
}

# CloudWatch Outputs
output "cloudwatch_log_groups" {
  description = "CloudWatch log group names"
  value = {
    for k, v in aws_cloudwatch_log_group.siem_logs : k => v.name
  }
}

# SNS Outputs
output "sns_topic_arn" {
  description = "SNS topic ARN for alerts"
  value       = aws_sns_topic.alerts.arn
}

# Backup Outputs
output "backup_vault_arn" {
  description = "AWS Backup vault ARN"
  value       = aws_backup_vault.siem_backup.arn
}

output "backup_plan_arn" {
  description = "AWS Backup plan ARN"
  value       = aws_backup_plan.siem_backup_plan.arn
}

# Systems Manager Parameter Store Outputs
output "ssm_parameter_names" {
  description = "Names of SSM parameters"
  value = {
    db_password           = aws_ssm_parameter.db_password.name
    elasticsearch_password = aws_ssm_parameter.elasticsearch_password.name
  }
  sensitive = true
}

# Connection Information
output "connection_info" {
  description = "Connection information for SIEM components"
  value = {
    kubernetes = {
      cluster_name = module.eks.cluster_name
      endpoint     = module.eks.cluster_endpoint
      region       = var.aws_region
    }
    
    database = {
      host     = module.rds.db_instance_endpoint
      port     = module.rds.db_instance_port
      database = module.rds.db_instance_name
      username = module.rds.db_instance_username
    }
    
    redis = {
      host = module.redis.cache_nodes[0].address
      port = module.redis.cache_nodes[0].port
    }
    
    storage = {
      logs_bucket     = module.s3.bucket_names["logs"]
      backups_bucket  = module.s3.bucket_names["backups"]
      artifacts_bucket = module.s3.bucket_names["artifacts"]
    }
  }
  sensitive = true
}

# Kubectl Configuration
output "kubectl_config" {
  description = "kubectl configuration command"
  value       = "aws eks update-kubeconfig --region ${var.aws_region} --name ${module.eks.cluster_name}"
}

# Monitoring Endpoints
output "monitoring_endpoints" {
  description = "Monitoring and observability endpoints"
  value = {
    cloudwatch_dashboard = "https://${var.aws_region}.console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#dashboards:"
    eks_console         = "https://${var.aws_region}.console.aws.amazon.com/eks/home?region=${var.aws_region}#/clusters/${module.eks.cluster_name}"
    rds_console         = "https://${var.aws_region}.console.aws.amazon.com/rds/home?region=${var.aws_region}#database:id=${module.rds.db_instance_id}"
    s3_console          = "https://s3.console.aws.amazon.com/s3/buckets/${module.s3.bucket_names["logs"]}?region=${var.aws_region}"
  }
}

# Cost Information
output "cost_tags" {
  description = "Tags for cost tracking"
  value = {
    Project     = var.project_name
    Environment = var.environment
    Owner       = var.owner
    CostCenter  = var.cost_center
  }
}

# Security Information
output "security_info" {
  description = "Security-related information"
  value = {
    vpc_flow_logs_enabled = var.enable_vpc_flow_logs
    encryption_enabled    = var.enable_encryption
    backup_enabled        = var.enable_backup
    multi_az_enabled      = var.enable_multi_az
    
    security_groups = {
      alb_sg           = module.security_groups.alb_security_group_id
      eks_cluster_sg   = module.security_groups.eks_cluster_security_group_id
      eks_nodes_sg     = module.security_groups.eks_nodes_security_group_id
      rds_sg           = module.security_groups.rds_security_group_id
      redis_sg         = module.security_groups.redis_security_group_id
      elasticsearch_sg = module.security_groups.elasticsearch_security_group_id
    }
    
    kms_key_id = aws_kms_key.siem_key.key_id
  }
}

# Deployment Information
output "deployment_info" {
  description = "Information for deployment scripts"
  value = {
    region           = var.aws_region
    cluster_name     = module.eks.cluster_name
    vpc_id           = module.vpc.vpc_id
    private_subnets  = module.vpc.private_subnet_ids
    public_subnets   = module.vpc.public_subnet_ids
    
    target_groups = {
      kibana         = aws_lb_target_group.kibana.arn
      wazuh_dashboard = aws_lb_target_group.wazuh_dashboard.arn
      grafana        = aws_lb_target_group.grafana.arn
    }
    
    load_balancer = {
      arn      = aws_lb.siem_alb.arn
      dns_name = aws_lb.siem_alb.dns_name
      zone_id  = aws_lb.siem_alb.zone_id
    }
  }
}

# Helm Values
output "helm_values" {
  description = "Values for Helm chart deployment"
  value = {
    global = {
      region      = var.aws_region
      environment = var.environment
      domain      = var.domain_name
    }
    
    elasticsearch = {
      version     = var.elasticsearch_version
      storageSize = var.elasticsearch_storage_size
      storageType = var.elasticsearch_storage_type
      heapSize    = var.elasticsearch_heap_size
      replicas    = var.elasticsearch_replicas
      shards      = var.elasticsearch_shards
    }
    
    kibana = {
      version = var.kibana_version
      host    = "kibana.${var.domain_name}"
    }
    
    wazuh = {
      version = var.wazuh_version
      host    = "wazuh.${var.domain_name}"
    }
    
    logstash = {
      version  = var.logstash_version
      heapSize = var.logstash_heap_size
    }
    
    filebeat = {
      version = var.filebeat_version
    }
    
    suricata = {
      version = var.suricata_version
    }
    
    grafana = {
      version = var.grafana_version
      host    = "grafana.${var.domain_name}"
    }
    
    database = {
      host     = module.rds.db_instance_endpoint
      port     = module.rds.db_instance_port
      name     = module.rds.db_instance_name
      username = module.rds.db_instance_username
    }
    
    redis = {
      host = module.redis.cache_nodes[0].address
      port = module.redis.cache_nodes[0].port
    }
    
    storage = {
      logs     = module.s3.bucket_names["logs"]
      backups  = module.s3.bucket_names["backups"]
      artifacts = module.s3.bucket_names["artifacts"]
    }
    
    security = {
      kmsKeyId = aws_kms_key.siem_key.key_id
    }
  }
  sensitive = true
}

# Next Steps
output "next_steps" {
  description = "Next steps for SIEM deployment"
  value = {
    "1_configure_kubectl" = "Run: ${"aws eks update-kubeconfig --region ${var.aws_region} --name ${module.eks.cluster_name}"}"
    "2_verify_cluster"    = "Run: kubectl get nodes"
    "3_deploy_helm_charts" = "Navigate to k8s/helm-charts and run: helm install siem ./siem-stack"
    "4_configure_dns"     = var.create_route53_zone ? "Update your domain registrar to use these name servers: ${join(", ", aws_route53_zone.siem_zone[0].name_servers)}" : "Configure DNS to point to ALB: ${aws_lb.siem_alb.dns_name}"
    "5_access_services"   = "Access services at: ${jsonencode({
      kibana         = "https://kibana.${var.domain_name}"
      wazuh_dashboard = "https://wazuh.${var.domain_name}"
      grafana        = "https://grafana.${var.domain_name}"
    })}"
  }
}