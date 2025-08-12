# =============================================================================
# Terraform Configuration for SIEM OpenSource PyMES
# =============================================================================
# This Terraform configuration deploys the SIEM solution to cloud environments
# with proper security, networking, and monitoring configurations.
# =============================================================================

terraform {
  required_version = ">= 1.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    google = {
      source  = "hashicorp/google"
      version = "~> 4.0"
    }
    docker = {
      source  = "kreuzwerker/docker"
      version = "~> 3.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.0"
    }
  }
  
  # Backend configuration for state management
  backend "s3" {
    bucket         = var.terraform_state_bucket
    key            = "siem/terraform.tfstate"
    region         = var.aws_region
    encrypt        = true
    dynamodb_table = var.terraform_lock_table
  }
}

# =============================================================================
# VARIABLES
# =============================================================================

variable "cloud_provider" {
  description = "Cloud provider to deploy to (aws, azure, gcp)"
  type        = string
  default     = "aws"
  validation {
    condition     = contains(["aws", "azure", "gcp"], var.cloud_provider)
    error_message = "Cloud provider must be one of: aws, azure, gcp."
  }
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "prod"
}

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "siem-pymes"
}

variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-west-2"
}

variable "azure_location" {
  description = "Azure location for deployment"
  type        = string
  default     = "West US 2"
}

variable "gcp_region" {
  description = "GCP region for deployment"
  type        = string
  default     = "us-west1"
}

variable "gcp_project" {
  description = "GCP project ID"
  type        = string
  default     = ""
}

variable "instance_type" {
  description = "Instance type for SIEM nodes"
  type = object({
    aws   = string
    azure = string
    gcp   = string
  })
  default = {
    aws   = "t3.xlarge"
    azure = "Standard_D4s_v3"
    gcp   = "n1-standard-4"
  }
}

variable "node_count" {
  description = "Number of SIEM nodes"
  type        = number
  default     = 3
}

variable "disk_size" {
  description = "Disk size in GB for each node"
  type        = number
  default     = 100
}

variable "enable_monitoring" {
  description = "Enable monitoring and alerting"
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

variable "allowed_cidr_blocks" {
  description = "CIDR blocks allowed to access SIEM"
  type        = list(string)
  default     = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
}

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

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default = {
    Project     = "SIEM-PyMES"
    Environment = "production"
    Owner       = "security-team"
    Purpose     = "security-monitoring"
  }
}

# =============================================================================
# LOCAL VALUES
# =============================================================================

locals {
  name_prefix = "${var.project_name}-${var.environment}"
  
  common_tags = merge(var.tags, {
    Environment   = var.environment
    Project       = var.project_name
    ManagedBy     = "terraform"
    CreatedDate   = timestamp()
  })
  
  # Network configuration
  vpc_cidr = "10.0.0.0/16"
  
  # Subnet configuration
  public_subnets  = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  private_subnets = ["10.0.11.0/24", "10.0.12.0/24", "10.0.13.0/24"]
  
  # Security group ports
  siem_ports = {
    kibana        = 5601
    elasticsearch = 9200
    wazuh         = 443
    grafana       = 3000
    prometheus    = 9090
    alertmanager  = 9093
    logstash      = 5044
    beats         = 5044
    syslog        = 514
    wazuh_agent   = 1514
  }
}

# =============================================================================
# DATA SOURCES
# =============================================================================

# Get availability zones
data "aws_availability_zones" "available" {
  count = var.cloud_provider == "aws" ? 1 : 0
  state = "available"
}

# Get latest Ubuntu AMI
data "aws_ami" "ubuntu" {
  count       = var.cloud_provider == "aws" ? 1 : 0
  most_recent = true
  owners      = ["099720109477"] # Canonical
  
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
  
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# =============================================================================
# AWS RESOURCES
# =============================================================================

# AWS Provider
provider "aws" {
  count  = var.cloud_provider == "aws" ? 1 : 0
  region = var.aws_region
  
  default_tags {
    tags = local.common_tags
  }
}

# VPC
resource "aws_vpc" "main" {
  count                = var.cloud_provider == "aws" ? 1 : 0
  cidr_block           = local.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-vpc"
  })
}

# Internet Gateway
resource "aws_internet_gateway" "main" {
  count  = var.cloud_provider == "aws" ? 1 : 0
  vpc_id = aws_vpc.main[0].id
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-igw"
  })
}

# Public Subnets
resource "aws_subnet" "public" {
  count                   = var.cloud_provider == "aws" ? length(local.public_subnets) : 0
  vpc_id                  = aws_vpc.main[0].id
  cidr_block              = local.public_subnets[count.index]
  availability_zone       = data.aws_availability_zones.available[0].names[count.index]
  map_public_ip_on_launch = true
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-public-subnet-${count.index + 1}"
    Type = "public"
  })
}

# Private Subnets
resource "aws_subnet" "private" {
  count             = var.cloud_provider == "aws" ? length(local.private_subnets) : 0
  vpc_id            = aws_vpc.main[0].id
  cidr_block        = local.private_subnets[count.index]
  availability_zone = data.aws_availability_zones.available[0].names[count.index]
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-private-subnet-${count.index + 1}"
    Type = "private"
  })
}

# NAT Gateway
resource "aws_eip" "nat" {
  count  = var.cloud_provider == "aws" ? length(local.public_subnets) : 0
  domain = "vpc"
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-nat-eip-${count.index + 1}"
  })
  
  depends_on = [aws_internet_gateway.main]
}

resource "aws_nat_gateway" "main" {
  count         = var.cloud_provider == "aws" ? length(local.public_subnets) : 0
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-nat-gateway-${count.index + 1}"
  })
  
  depends_on = [aws_internet_gateway.main]
}

# Route Tables
resource "aws_route_table" "public" {
  count  = var.cloud_provider == "aws" ? 1 : 0
  vpc_id = aws_vpc.main[0].id
  
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main[0].id
  }
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-public-rt"
  })
}

resource "aws_route_table" "private" {
  count  = var.cloud_provider == "aws" ? length(local.private_subnets) : 0
  vpc_id = aws_vpc.main[0].id
  
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main[count.index].id
  }
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-private-rt-${count.index + 1}"
  })
}

# Route Table Associations
resource "aws_route_table_association" "public" {
  count          = var.cloud_provider == "aws" ? length(local.public_subnets) : 0
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public[0].id
}

resource "aws_route_table_association" "private" {
  count          = var.cloud_provider == "aws" ? length(local.private_subnets) : 0
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

# Security Groups
resource "aws_security_group" "siem_lb" {
  count       = var.cloud_provider == "aws" ? 1 : 0
  name        = "${local.name_prefix}-lb-sg"
  description = "Security group for SIEM load balancer"
  vpc_id      = aws_vpc.main[0].id
  
  # HTTPS access
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
  }
  
  # HTTP redirect
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-lb-sg"
  })
}

resource "aws_security_group" "siem_nodes" {
  count       = var.cloud_provider == "aws" ? 1 : 0
  name        = "${local.name_prefix}-nodes-sg"
  description = "Security group for SIEM nodes"
  vpc_id      = aws_vpc.main[0].id
  
  # Allow traffic from load balancer
  dynamic "ingress" {
    for_each = local.siem_ports
    content {
      from_port       = ingress.value
      to_port         = ingress.value
      protocol        = "tcp"
      security_groups = [aws_security_group.siem_lb[0].id]
    }
  }
  
  # SSH access
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
  }
  
  # Inter-node communication
  ingress {
    from_port = 0
    to_port   = 65535
    protocol  = "tcp"
    self      = true
  }
  
  # Syslog UDP
  ingress {
    from_port   = 514
    to_port     = 514
    protocol    = "udp"
    cidr_blocks = var.allowed_cidr_blocks
  }
  
  # Wazuh agent communication
  ingress {
    from_port   = 1514
    to_port     = 1515
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-nodes-sg"
  })
}

# Key Pair
resource "aws_key_pair" "siem" {
  count      = var.cloud_provider == "aws" ? 1 : 0
  key_name   = "${local.name_prefix}-key"
  public_key = file("~/.ssh/id_rsa.pub")
  
  tags = local.common_tags
}

# Launch Template
resource "aws_launch_template" "siem" {
  count         = var.cloud_provider == "aws" ? 1 : 0
  name          = "${local.name_prefix}-template"
  image_id      = data.aws_ami.ubuntu[0].id
  instance_type = var.instance_type.aws
  key_name      = aws_key_pair.siem[0].key_name
  
  vpc_security_group_ids = [aws_security_group.siem_nodes[0].id]
  
  block_device_mappings {
    device_name = "/dev/sda1"
    ebs {
      volume_size           = var.disk_size
      volume_type           = "gp3"
      encrypted             = true
      delete_on_termination = true
    }
  }
  
  user_data = base64encode(templatefile("${path.module}/user-data.sh", {
    environment = var.environment
    node_count  = var.node_count
  }))
  
  tag_specifications {
    resource_type = "instance"
    tags = merge(local.common_tags, {
      Name = "${local.name_prefix}-node"
    })
  }
  
  tags = local.common_tags
}

# Auto Scaling Group
resource "aws_autoscaling_group" "siem" {
  count               = var.cloud_provider == "aws" ? 1 : 0
  name                = "${local.name_prefix}-asg"
  vpc_zone_identifier = aws_subnet.private[*].id
  target_group_arns   = aws_lb_target_group.siem[*].arn
  health_check_type   = "ELB"
  health_check_grace_period = 300
  
  min_size         = var.node_count
  max_size         = var.node_count * 2
  desired_capacity = var.node_count
  
  launch_template {
    id      = aws_launch_template.siem[0].id
    version = "$Latest"
  }
  
  tag {
    key                 = "Name"
    value               = "${local.name_prefix}-asg"
    propagate_at_launch = false
  }
  
  dynamic "tag" {
    for_each = local.common_tags
    content {
      key                 = tag.key
      value               = tag.value
      propagate_at_launch = true
    }
  }
}

# Application Load Balancer
resource "aws_lb" "siem" {
  count              = var.cloud_provider == "aws" ? 1 : 0
  name               = "${local.name_prefix}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.siem_lb[0].id]
  subnets            = aws_subnet.public[*].id
  
  enable_deletion_protection = var.environment == "prod" ? true : false
  
  access_logs {
    bucket  = aws_s3_bucket.logs[0].bucket
    prefix  = "alb-logs"
    enabled = true
  }
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-alb"
  })
}

# Target Groups
resource "aws_lb_target_group" "siem" {
  count    = var.cloud_provider == "aws" ? length(local.siem_ports) : 0
  name     = "${local.name_prefix}-tg-${keys(local.siem_ports)[count.index]}"
  port     = values(local.siem_ports)[count.index]
  protocol = "HTTP"
  vpc_id   = aws_vpc.main[0].id
  
  health_check {
    enabled             = true
    healthy_threshold   = 2
    interval            = 30
    matcher             = "200"
    path                = "/"
    port                = "traffic-port"
    protocol            = "HTTP"
    timeout             = 5
    unhealthy_threshold = 2
  }
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-tg-${keys(local.siem_ports)[count.index]}"
  })
}

# Load Balancer Listeners
resource "aws_lb_listener" "siem_https" {
  count             = var.cloud_provider == "aws" && var.ssl_certificate_arn != "" ? 1 : 0
  load_balancer_arn = aws_lb.siem[0].arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS-1-2-2017-01"
  certificate_arn   = var.ssl_certificate_arn
  
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.siem[0].arn
  }
}

resource "aws_lb_listener" "siem_http" {
  count             = var.cloud_provider == "aws" ? 1 : 0
  load_balancer_arn = aws_lb.siem[0].arn
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
}

# S3 Bucket for logs and backups
resource "aws_s3_bucket" "logs" {
  count  = var.cloud_provider == "aws" ? 1 : 0
  bucket = "${local.name_prefix}-logs-${random_string.bucket_suffix[0].result}"
  
  tags = local.common_tags
}

resource "aws_s3_bucket_versioning" "logs" {
  count  = var.cloud_provider == "aws" ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_encryption" "logs" {
  count  = var.cloud_provider == "aws" ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id
  
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  count  = var.cloud_provider == "aws" ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id
  
  rule {
    id     = "log_retention"
    status = "Enabled"
    
    expiration {
      days = var.backup_retention_days
    }
    
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

# Random string for unique bucket naming
resource "random_string" "bucket_suffix" {
  count   = var.cloud_provider == "aws" ? 1 : 0
  length  = 8
  special = false
  upper   = false
}

# =============================================================================
# MONITORING AND ALERTING
# =============================================================================

# CloudWatch Log Groups
resource "aws_cloudwatch_log_group" "siem" {
  count             = var.cloud_provider == "aws" && var.enable_monitoring ? 1 : 0
  name              = "/aws/ec2/${local.name_prefix}"
  retention_in_days = 30
  
  tags = local.common_tags
}

# CloudWatch Alarms
resource "aws_cloudwatch_metric_alarm" "high_cpu" {
  count               = var.cloud_provider == "aws" && var.enable_monitoring ? 1 : 0
  alarm_name          = "${local.name_prefix}-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "120"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors ec2 cpu utilization"
  alarm_actions       = [aws_sns_topic.alerts[0].arn]
  
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.siem[0].name
  }
  
  tags = local.common_tags
}

# SNS Topic for alerts
resource "aws_sns_topic" "alerts" {
  count = var.cloud_provider == "aws" && var.enable_monitoring ? 1 : 0
  name  = "${local.name_prefix}-alerts"
  
  tags = local.common_tags
}

# =============================================================================
# BACKUP CONFIGURATION
# =============================================================================

# Backup Vault
resource "aws_backup_vault" "siem" {
  count       = var.cloud_provider == "aws" && var.enable_backup ? 1 : 0
  name        = "${local.name_prefix}-backup-vault"
  kms_key_arn = aws_kms_key.backup[0].arn
  
  tags = local.common_tags
}

# KMS Key for backups
resource "aws_kms_key" "backup" {
  count                   = var.cloud_provider == "aws" && var.enable_backup ? 1 : 0
  description             = "KMS key for SIEM backups"
  deletion_window_in_days = 7
  
  tags = local.common_tags
}

resource "aws_kms_alias" "backup" {
  count         = var.cloud_provider == "aws" && var.enable_backup ? 1 : 0
  name          = "alias/${local.name_prefix}-backup"
  target_key_id = aws_kms_key.backup[0].key_id
}

# Backup Plan
resource "aws_backup_plan" "siem" {
  count = var.cloud_provider == "aws" && var.enable_backup ? 1 : 0
  name  = "${local.name_prefix}-backup-plan"
  
  rule {
    rule_name         = "daily_backup"
    target_vault_name = aws_backup_vault.siem[0].name
    schedule          = "cron(0 2 * * ? *)"
    
    lifecycle {
      cold_storage_after = 30
      delete_after       = var.backup_retention_days
    }
    
    recovery_point_tags = local.common_tags
  }
  
  tags = local.common_tags
}

# =============================================================================
# OUTPUTS
# =============================================================================

output "load_balancer_dns" {
  description = "DNS name of the load balancer"
  value       = var.cloud_provider == "aws" ? aws_lb.siem[0].dns_name : null
}

output "vpc_id" {
  description = "ID of the VPC"
  value       = var.cloud_provider == "aws" ? aws_vpc.main[0].id : null
}

output "private_subnet_ids" {
  description = "IDs of the private subnets"
  value       = var.cloud_provider == "aws" ? aws_subnet.private[*].id : null
}

output "public_subnet_ids" {
  description = "IDs of the public subnets"
  value       = var.cloud_provider == "aws" ? aws_subnet.public[*].id : null
}

output "security_group_ids" {
  description = "IDs of the security groups"
  value = var.cloud_provider == "aws" ? {
    load_balancer = aws_security_group.siem_lb[0].id
    nodes         = aws_security_group.siem_nodes[0].id
  } : null
}

output "s3_bucket_name" {
  description = "Name of the S3 bucket for logs"
  value       = var.cloud_provider == "aws" ? aws_s3_bucket.logs[0].bucket : null
}

output "backup_vault_name" {
  description = "Name of the backup vault"
  value       = var.cloud_provider == "aws" && var.enable_backup ? aws_backup_vault.siem[0].name : null
}

output "access_urls" {
  description = "URLs to access SIEM components"
  value = var.cloud_provider == "aws" ? {
    kibana        = "https://${aws_lb.siem[0].dns_name}:5601"
    wazuh         = "https://${aws_lb.siem[0].dns_name}"
    grafana       = "https://${aws_lb.siem[0].dns_name}:3000"
    elasticsearch = "https://${aws_lb.siem[0].dns_name}:9200"
  } : null
}

# =============================================================================
# END OF CONFIGURATION
# =============================================================================