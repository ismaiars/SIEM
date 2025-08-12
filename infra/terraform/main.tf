# SIEM OpenSource PyMES - Infraestructura Principal en AWS
# Terraform configuration for complete SIEM infrastructure

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.1"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }

  backend "s3" {
    bucket         = "siem-terraform-state-bucket"
    key            = "siem/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "siem-terraform-locks"
  }
}

# Provider configuration
provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "SIEM-OpenSource-PyMES"
      Environment = var.environment
      ManagedBy   = "Terraform"
      Owner       = var.owner
      CostCenter  = var.cost_center
    }
  }
}

# Data sources
data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

# Random password for databases
resource "random_password" "db_password" {
  length  = 16
  special = true
}

resource "random_password" "elasticsearch_password" {
  length  = 16
  special = true
}

# Local values
locals {
  name_prefix = "${var.project_name}-${var.environment}"
  
  common_tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "Terraform"
    Owner       = var.owner
    CostCenter  = var.cost_center
  }

  # Subnets configuration
  vpc_cidr = var.vpc_cidr
  azs      = slice(data.aws_availability_zones.available.names, 0, 3)
  
  private_subnets = [
    cidrsubnet(local.vpc_cidr, 8, 1),
    cidrsubnet(local.vpc_cidr, 8, 2),
    cidrsubnet(local.vpc_cidr, 8, 3)
  ]
  
  public_subnets = [
    cidrsubnet(local.vpc_cidr, 8, 101),
    cidrsubnet(local.vpc_cidr, 8, 102),
    cidrsubnet(local.vpc_cidr, 8, 103)
  ]
  
  database_subnets = [
    cidrsubnet(local.vpc_cidr, 8, 201),
    cidrsubnet(local.vpc_cidr, 8, 202),
    cidrsubnet(local.vpc_cidr, 8, 203)
  ]
}

# VPC Module
module "vpc" {
  source = "./modules/vpc"

  name_prefix         = local.name_prefix
  vpc_cidr           = local.vpc_cidr
  availability_zones = local.azs
  private_subnets    = local.private_subnets
  public_subnets     = local.public_subnets
  database_subnets   = local.database_subnets
  
  enable_nat_gateway   = true
  enable_vpn_gateway   = false
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  tags = local.common_tags
}

# Security Groups Module
module "security_groups" {
  source = "./modules/security"

  name_prefix = local.name_prefix
  vpc_id      = module.vpc.vpc_id
  vpc_cidr    = local.vpc_cidr
  
  allowed_cidr_blocks = var.allowed_cidr_blocks
  
  tags = local.common_tags
}

# EKS Cluster Module
module "eks" {
  source = "./modules/eks"

  cluster_name    = "${local.name_prefix}-cluster"
  cluster_version = var.kubernetes_version
  
  vpc_id          = module.vpc.vpc_id
  subnet_ids      = module.vpc.private_subnet_ids
  
  node_groups = {
    siem_nodes = {
      instance_types = var.eks_node_instance_types
      capacity_type  = "ON_DEMAND"
      
      scaling_config = {
        desired_size = var.eks_desired_capacity
        max_size     = var.eks_max_capacity
        min_size     = var.eks_min_capacity
      }
      
      disk_size = 100
      
      labels = {
        role = "siem-worker"
      }
      
      taints = []
    }
    
    elasticsearch_nodes = {
      instance_types = var.elasticsearch_instance_types
      capacity_type  = "ON_DEMAND"
      
      scaling_config = {
        desired_size = 3
        max_size     = 6
        min_size     = 3
      }
      
      disk_size = 200
      
      labels = {
        role = "elasticsearch"
      }
      
      taints = [
        {
          key    = "elasticsearch"
          value  = "true"
          effect = "NO_SCHEDULE"
        }
      ]
    }
  }
  
  tags = local.common_tags
}

# RDS Module for PostgreSQL
module "rds" {
  source = "./modules/rds"

  identifier = "${local.name_prefix}-postgres"
  
  engine         = "postgres"
  engine_version = "15.4"
  instance_class = var.rds_instance_class
  
  allocated_storage     = var.rds_allocated_storage
  max_allocated_storage = var.rds_max_allocated_storage
  storage_encrypted     = true
  
  db_name  = var.db_name
  username = var.db_username
  password = random_password.db_password.result
  
  vpc_security_group_ids = [module.security_groups.rds_security_group_id]
  db_subnet_group_name   = module.vpc.database_subnet_group_name
  
  backup_retention_period = 7
  backup_window          = "03:00-04:00"
  maintenance_window     = "sun:04:00-sun:05:00"
  
  skip_final_snapshot = var.environment != "production"
  deletion_protection = var.environment == "production"
  
  performance_insights_enabled = true
  monitoring_interval         = 60
  
  tags = local.common_tags
}

# ElastiCache Redis Module
module "redis" {
  source = "./modules/redis"

  cluster_id = "${local.name_prefix}-redis"
  
  node_type               = var.redis_node_type
  num_cache_nodes         = var.redis_num_nodes
  parameter_group_name    = "default.redis7"
  port                    = 6379
  
  subnet_group_name      = module.vpc.elasticache_subnet_group_name
  security_group_ids     = [module.security_groups.redis_security_group_id]
  
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  
  tags = local.common_tags
}

# S3 Buckets Module
module "s3" {
  source = "./modules/s3"

  name_prefix = local.name_prefix
  
  buckets = {
    logs = {
      versioning_enabled = true
      lifecycle_rules = [
        {
          id     = "logs_lifecycle"
          status = "Enabled"
          
          transition = [
            {
              days          = 30
              storage_class = "STANDARD_IA"
            },
            {
              days          = 90
              storage_class = "GLACIER"
            },
            {
              days          = 365
              storage_class = "DEEP_ARCHIVE"
            }
          ]
          
          expiration = {
            days = 2555  # 7 years
          }
        }
      ]
    }
    
    backups = {
      versioning_enabled = true
      lifecycle_rules = [
        {
          id     = "backups_lifecycle"
          status = "Enabled"
          
          transition = [
            {
              days          = 7
              storage_class = "STANDARD_IA"
            },
            {
              days          = 30
              storage_class = "GLACIER"
            }
          ]
          
          expiration = {
            days = 365
          }
        }
      ]
    }
    
    artifacts = {
      versioning_enabled = false
      lifecycle_rules = [
        {
          id     = "artifacts_lifecycle"
          status = "Enabled"
          
          expiration = {
            days = 90
          }
        }
      ]
    }
  }
  
  tags = local.common_tags
}

# Application Load Balancer
resource "aws_lb" "siem_alb" {
  name               = "${local.name_prefix}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [module.security_groups.alb_security_group_id]
  subnets           = module.vpc.public_subnet_ids

  enable_deletion_protection = var.environment == "production"

  access_logs {
    bucket  = module.s3.bucket_names["logs"]
    prefix  = "alb-logs"
    enabled = true
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-alb"
  })
}

# Target Groups
resource "aws_lb_target_group" "kibana" {
  name     = "${local.name_prefix}-kibana"
  port     = 5601
  protocol = "HTTP"
  vpc_id   = module.vpc.vpc_id
  
  target_type = "ip"

  health_check {
    enabled             = true
    healthy_threshold   = 2
    interval            = 30
    matcher             = "200"
    path                = "/api/status"
    port                = "traffic-port"
    protocol            = "HTTP"
    timeout             = 5
    unhealthy_threshold = 2
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-kibana-tg"
  })
}

resource "aws_lb_target_group" "wazuh_dashboard" {
  name     = "${local.name_prefix}-wazuh-dash"
  port     = 443
  protocol = "HTTPS"
  vpc_id   = module.vpc.vpc_id
  
  target_type = "ip"

  health_check {
    enabled             = true
    healthy_threshold   = 2
    interval            = 30
    matcher             = "200"
    path                = "/"
    port                = "traffic-port"
    protocol            = "HTTPS"
    timeout             = 5
    unhealthy_threshold = 2
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-wazuh-dashboard-tg"
  })
}

resource "aws_lb_target_group" "grafana" {
  name     = "${local.name_prefix}-grafana"
  port     = 3000
  protocol = "HTTP"
  vpc_id   = module.vpc.vpc_id
  
  target_type = "ip"

  health_check {
    enabled             = true
    healthy_threshold   = 2
    interval            = 30
    matcher             = "200"
    path                = "/api/health"
    port                = "traffic-port"
    protocol            = "HTTP"
    timeout             = 5
    unhealthy_threshold = 2
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-grafana-tg"
  })
}

# ACM Certificate
resource "aws_acm_certificate" "siem_cert" {
  domain_name               = var.domain_name
  subject_alternative_names = ["*.${var.domain_name}"]
  validation_method         = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-certificate"
  })
}

# ALB Listeners
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.siem_alb.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS-1-2-2017-01"
  certificate_arn   = aws_acm_certificate.siem_cert.arn

  default_action {
    type = "fixed-response"

    fixed_response {
      content_type = "text/plain"
      message_body = "SIEM Access Denied"
      status_code  = "403"
    }
  }

  tags = local.common_tags
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.siem_alb.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }

  tags = local.common_tags
}

# ALB Listener Rules
resource "aws_lb_listener_rule" "kibana" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 100

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.kibana.arn
  }

  condition {
    host_header {
      values = ["kibana.${var.domain_name}"]
    }
  }

  tags = local.common_tags
}

resource "aws_lb_listener_rule" "wazuh_dashboard" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 200

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.wazuh_dashboard.arn
  }

  condition {
    host_header {
      values = ["wazuh.${var.domain_name}"]
    }
  }

  tags = local.common_tags
}

resource "aws_lb_listener_rule" "grafana" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 300

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.grafana.arn
  }

  condition {
    host_header {
      values = ["grafana.${var.domain_name}"]
    }
  }

  tags = local.common_tags
}

# Route53 Hosted Zone
resource "aws_route53_zone" "siem_zone" {
  count = var.create_route53_zone ? 1 : 0
  
  name = var.domain_name

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-zone"
  })
}

# Route53 Records
resource "aws_route53_record" "kibana" {
  count = var.create_route53_zone ? 1 : 0
  
  zone_id = aws_route53_zone.siem_zone[0].zone_id
  name    = "kibana.${var.domain_name}"
  type    = "A"

  alias {
    name                   = aws_lb.siem_alb.dns_name
    zone_id                = aws_lb.siem_alb.zone_id
    evaluate_target_health = true
  }
}

resource "aws_route53_record" "wazuh" {
  count = var.create_route53_zone ? 1 : 0
  
  zone_id = aws_route53_zone.siem_zone[0].zone_id
  name    = "wazuh.${var.domain_name}"
  type    = "A"

  alias {
    name                   = aws_lb.siem_alb.dns_name
    zone_id                = aws_lb.siem_alb.zone_id
    evaluate_target_health = true
  }
}

resource "aws_route53_record" "grafana" {
  count = var.create_route53_zone ? 1 : 0
  
  zone_id = aws_route53_zone.siem_zone[0].zone_id
  name    = "grafana.${var.domain_name}"
  type    = "A"

  alias {
    name                   = aws_lb.siem_alb.dns_name
    zone_id                = aws_lb.siem_alb.zone_id
    evaluate_target_health = true
  }
}

# IAM Roles for SIEM Components
module "iam" {
  source = "./modules/iam"

  name_prefix = local.name_prefix
  
  s3_bucket_arns = [
    module.s3.bucket_arns["logs"],
    module.s3.bucket_arns["backups"],
    module.s3.bucket_arns["artifacts"]
  ]
  
  tags = local.common_tags
}

# CloudWatch Log Groups
resource "aws_cloudwatch_log_group" "siem_logs" {
  for_each = toset([
    "elasticsearch",
    "kibana",
    "wazuh",
    "logstash",
    "filebeat",
    "suricata",
    "grafana"
  ])
  
  name              = "/aws/siem/${local.name_prefix}/${each.key}"
  retention_in_days = var.log_retention_days
  
  tags = merge(local.common_tags, {
    Component = each.key
  })
}

# Systems Manager Parameters for sensitive data
resource "aws_ssm_parameter" "db_password" {
  name  = "/${local.name_prefix}/database/password"
  type  = "SecureString"
  value = random_password.db_password.result
  
  tags = local.common_tags
}

resource "aws_ssm_parameter" "elasticsearch_password" {
  name  = "/${local.name_prefix}/elasticsearch/password"
  type  = "SecureString"
  value = random_password.elasticsearch_password.result
  
  tags = local.common_tags
}

# KMS Key for encryption
resource "aws_kms_key" "siem_key" {
  description             = "KMS key for SIEM encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-kms-key"
  })
}

resource "aws_kms_alias" "siem_key_alias" {
  name          = "alias/${local.name_prefix}-key"
  target_key_id = aws_kms_key.siem_key.key_id
}

# CloudWatch Alarms
resource "aws_cloudwatch_metric_alarm" "high_cpu" {
  alarm_name          = "${local.name_prefix}-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EKS"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors EKS cluster CPU utilization"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    ClusterName = module.eks.cluster_name
  }

  tags = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "rds_cpu" {
  alarm_name          = "${local.name_prefix}-rds-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors RDS CPU utilization"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    DBInstanceIdentifier = module.rds.db_instance_id
  }

  tags = local.common_tags
}

# SNS Topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "${local.name_prefix}-alerts"
  
  tags = local.common_tags
}

resource "aws_sns_topic_subscription" "email_alerts" {
  count = var.alert_email != "" ? 1 : 0
  
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Backup configuration
resource "aws_backup_vault" "siem_backup" {
  name        = "${local.name_prefix}-backup-vault"
  kms_key_arn = aws_kms_key.siem_key.arn
  
  tags = local.common_tags
}

resource "aws_backup_plan" "siem_backup_plan" {
  name = "${local.name_prefix}-backup-plan"

  rule {
    rule_name         = "daily_backup"
    target_vault_name = aws_backup_vault.siem_backup.name
    schedule          = "cron(0 5 ? * * *)"
    start_window      = 60
    completion_window = 300

    recovery_point_tags = local.common_tags

    lifecycle {
      cold_storage_after = 30
      delete_after       = 120
    }
  }

  tags = local.common_tags
}

resource "aws_backup_selection" "siem_backup_selection" {
  iam_role_arn = aws_iam_role.backup_role.arn
  name         = "${local.name_prefix}-backup-selection"
  plan_id      = aws_backup_plan.siem_backup_plan.id

  resources = [
    module.rds.db_instance_arn
  ]
}

# IAM role for AWS Backup
resource "aws_iam_role" "backup_role" {
  name = "${local.name_prefix}-backup-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "backup.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "backup_policy" {
  role       = aws_iam_role.backup_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
}

resource "aws_iam_role_policy_attachment" "restore_policy" {
  role       = aws_iam_role.backup_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForRestores"
}