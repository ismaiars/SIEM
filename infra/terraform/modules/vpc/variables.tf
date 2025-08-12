# SIEM OpenSource PyMES - VPC Module Variables

variable "project_name" {
  description = "Name of the project"
  type        = string
  default     = "siem-pymes"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
  
  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "VPC CIDR must be a valid IPv4 CIDR block."
  }
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
  
  validation {
    condition     = length(var.public_subnet_cidrs) >= 2
    error_message = "At least 2 public subnets are required for high availability."
  }
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets"
  type        = list(string)
  default     = ["10.0.10.0/24", "10.0.20.0/24"]
  
  validation {
    condition     = length(var.private_subnet_cidrs) >= 2
    error_message = "At least 2 private subnets are required for high availability."
  }
}

variable "database_subnet_cidrs" {
  description = "CIDR blocks for database subnets"
  type        = list(string)
  default     = ["10.0.100.0/24", "10.0.200.0/24"]
  
  validation {
    condition     = length(var.database_subnet_cidrs) >= 2
    error_message = "At least 2 database subnets are required for RDS multi-AZ."
  }
}

variable "enable_nat_gateway" {
  description = "Enable NAT Gateway for private subnets"
  type        = bool
  default     = true
}

variable "enable_vpc_flow_logs" {
  description = "Enable VPC Flow Logs"
  type        = bool
  default     = true
}

variable "flow_log_retention_days" {
  description = "Retention period for VPC Flow Logs in days"
  type        = number
  default     = 30
  
  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653], var.flow_log_retention_days)
    error_message = "Flow log retention days must be a valid CloudWatch Logs retention period."
  }
}

variable "enable_vpc_endpoints" {
  description = "Enable VPC Endpoints for AWS services"
  type        = bool
  default     = true
}

variable "enable_custom_dhcp" {
  description = "Enable custom DHCP options set"
  type        = bool
  default     = false
}

variable "enable_network_acls" {
  description = "Enable custom Network ACLs for enhanced security"
  type        = bool
  default     = false
}

variable "domain_name" {
  description = "Domain name for DHCP options"
  type        = string
  default     = ""
}

variable "tags" {
  description = "A map of tags to assign to the resources"
  type        = map(string)
  default = {
    Terraform   = "true"
    Project     = "SIEM-PyMES"
    Component   = "VPC"
  }
}

# Advanced networking options
variable "enable_dns_hostnames" {
  description = "Enable DNS hostnames in the VPC"
  type        = bool
  default     = true
}

variable "enable_dns_support" {
  description = "Enable DNS support in the VPC"
  type        = bool
  default     = true
}

variable "enable_classiclink" {
  description = "Enable ClassicLink for the VPC"
  type        = bool
  default     = false
}

variable "enable_classiclink_dns_support" {
  description = "Enable ClassicLink DNS Support for the VPC"
  type        = bool
  default     = false
}

variable "instance_tenancy" {
  description = "A tenancy option for instances launched into the VPC"
  type        = string
  default     = "default"
  
  validation {
    condition     = contains(["default", "dedicated"], var.instance_tenancy)
    error_message = "Instance tenancy must be either 'default' or 'dedicated'."
  }
}

# Security and compliance
variable "enable_flow_log_s3" {
  description = "Enable VPC Flow Logs to S3 instead of CloudWatch"
  type        = bool
  default     = false
}

variable "flow_log_s3_bucket" {
  description = "S3 bucket name for VPC Flow Logs (if enable_flow_log_s3 is true)"
  type        = string
  default     = ""
}

variable "flow_log_format" {
  description = "The format for the flow log"
  type        = string
  default     = "$${version} $${account-id} $${interface-id} $${srcaddr} $${dstaddr} $${srcport} $${dstport} $${protocol} $${packets} $${bytes} $${windowstart} $${windowend} $${action} $${flowlogstatus}"
}

variable "enable_ipv6" {
  description = "Enable IPv6 support"
  type        = bool
  default     = false
}

variable "ipv6_cidr_block" {
  description = "IPv6 CIDR block for the VPC"
  type        = string
  default     = null
}

# Cost optimization
variable "single_nat_gateway" {
  description = "Use a single NAT Gateway for all private subnets (cost optimization)"
  type        = bool
  default     = false
}

variable "one_nat_gateway_per_az" {
  description = "Use one NAT Gateway per availability zone"
  type        = bool
  default     = true
}

# Monitoring and logging
variable "enable_cloudtrail" {
  description = "Enable CloudTrail for VPC API logging"
  type        = bool
  default     = false
}

variable "cloudtrail_s3_bucket" {
  description = "S3 bucket for CloudTrail logs"
  type        = string
  default     = ""
}

# Network security
variable "allowed_cidr_blocks" {
  description = "List of CIDR blocks allowed to access the VPC"
  type        = list(string)
  default     = []
}

variable "enable_network_firewall" {
  description = "Enable AWS Network Firewall"
  type        = bool
  default     = false
}

variable "firewall_policy_arn" {
  description = "ARN of the Network Firewall policy"
  type        = string
  default     = ""
}

# Transit Gateway integration
variable "enable_transit_gateway" {
  description = "Enable Transit Gateway attachment"
  type        = bool
  default     = false
}

variable "transit_gateway_id" {
  description = "Transit Gateway ID for attachment"
  type        = string
  default     = ""
}

variable "transit_gateway_route_table_id" {
  description = "Transit Gateway Route Table ID"
  type        = string
  default     = ""
}

# Peering connections
variable "enable_vpc_peering" {
  description = "Enable VPC peering connections"
  type        = bool
  default     = false
}

variable "peer_vpc_ids" {
  description = "List of VPC IDs to peer with"
  type        = list(string)
  default     = []
}

variable "peer_vpc_cidrs" {
  description = "List of CIDR blocks for peered VPCs"
  type        = list(string)
  default     = []
}

# Subnet-specific configurations
variable "public_subnet_tags" {
  description = "Additional tags for public subnets"
  type        = map(string)
  default     = {}
}

variable "private_subnet_tags" {
  description = "Additional tags for private subnets"
  type        = map(string)
  default     = {}
}

variable "database_subnet_tags" {
  description = "Additional tags for database subnets"
  type        = map(string)
  default     = {}
}

# Route table configurations
variable "public_route_table_tags" {
  description = "Additional tags for public route table"
  type        = map(string)
  default     = {}
}

variable "private_route_table_tags" {
  description = "Additional tags for private route tables"
  type        = map(string)
  default     = {}
}

variable "database_route_table_tags" {
  description = "Additional tags for database route table"
  type        = map(string)
  default     = {}
}

# Gateway configurations
variable "internet_gateway_tags" {
  description = "Additional tags for internet gateway"
  type        = map(string)
  default     = {}
}

variable "nat_gateway_tags" {
  description = "Additional tags for NAT gateways"
  type        = map(string)
  default     = {}
}

variable "nat_eip_tags" {
  description = "Additional tags for NAT gateway Elastic IPs"
  type        = map(string)
  default     = {}
}

# VPC endpoint configurations
variable "vpc_endpoint_policy" {
  description = "Policy document for VPC endpoints"
  type        = string
  default     = null
}

variable "enable_s3_endpoint" {
  description = "Enable S3 VPC endpoint"
  type        = bool
  default     = true
}

variable "enable_dynamodb_endpoint" {
  description = "Enable DynamoDB VPC endpoint"
  type        = bool
  default     = false
}

variable "enable_ec2_endpoint" {
  description = "Enable EC2 VPC endpoint"
  type        = bool
  default     = true
}

variable "enable_ecr_endpoints" {
  description = "Enable ECR VPC endpoints (api and dkr)"
  type        = bool
  default     = true
}

variable "enable_ecs_endpoints" {
  description = "Enable ECS VPC endpoints"
  type        = bool
  default     = false
}

variable "enable_eks_endpoint" {
  description = "Enable EKS VPC endpoint"
  type        = bool
  default     = true
}

variable "enable_ssm_endpoints" {
  description = "Enable SSM VPC endpoints"
  type        = bool
  default     = false
}

variable "enable_logs_endpoint" {
  description = "Enable CloudWatch Logs VPC endpoint"
  type        = bool
  default     = false
}

variable "enable_monitoring_endpoint" {
  description = "Enable CloudWatch Monitoring VPC endpoint"
  type        = bool
  default     = false
}

# Security group for VPC endpoints
variable "vpc_endpoint_security_group_ids" {
  description = "Security group IDs for VPC endpoints"
  type        = list(string)
  default     = []
}

variable "vpc_endpoint_subnet_ids" {
  description = "Subnet IDs for interface VPC endpoints"
  type        = list(string)
  default     = []
}

variable "vpc_endpoint_private_dns_enabled" {
  description = "Enable private DNS for VPC endpoints"
  type        = bool
  default     = true
}

# DHCP options
variable "dhcp_options_domain_name" {
  description = "Domain name for DHCP options"
  type        = string
  default     = ""
}

variable "dhcp_options_domain_name_servers" {
  description = "List of domain name servers for DHCP options"
  type        = list(string)
  default     = ["AmazonProvidedDNS"]
}

variable "dhcp_options_ntp_servers" {
  description = "List of NTP servers for DHCP options"
  type        = list(string)
  default     = []
}

variable "dhcp_options_netbios_name_servers" {
  description = "List of NetBIOS name servers for DHCP options"
  type        = list(string)
  default     = []
}

variable "dhcp_options_netbios_node_type" {
  description = "NetBIOS node type for DHCP options"
  type        = number
  default     = 2
}

variable "dhcp_options_tags" {
  description = "Additional tags for DHCP options"
  type        = map(string)
  default     = {}
}