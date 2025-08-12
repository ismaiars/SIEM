# SIEM OpenSource PyMES - VPC Module Outputs

# VPC
output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.siem_vpc.id
}

output "vpc_arn" {
  description = "ARN of the VPC"
  value       = aws_vpc.siem_vpc.arn
}

output "vpc_cidr_block" {
  description = "CIDR block of the VPC"
  value       = aws_vpc.siem_vpc.cidr_block
}

output "vpc_instance_tenancy" {
  description = "Tenancy of instances spin up within VPC"
  value       = aws_vpc.siem_vpc.instance_tenancy
}

output "vpc_enable_dns_support" {
  description = "Whether or not the VPC has DNS support"
  value       = aws_vpc.siem_vpc.enable_dns_support
}

output "vpc_enable_dns_hostnames" {
  description = "Whether or not the VPC has DNS hostname support"
  value       = aws_vpc.siem_vpc.enable_dns_hostnames
}

output "vpc_main_route_table_id" {
  description = "ID of the main route table associated with this VPC"
  value       = aws_vpc.siem_vpc.main_route_table_id
}

output "vpc_default_network_acl_id" {
  description = "ID of the default network ACL"
  value       = aws_vpc.siem_vpc.default_network_acl_id
}

output "vpc_default_security_group_id" {
  description = "ID of the security group created by default on VPC creation"
  value       = aws_vpc.siem_vpc.default_security_group_id
}

output "vpc_default_route_table_id" {
  description = "ID of the default route table"
  value       = aws_vpc.siem_vpc.default_route_table_id
}

output "vpc_ipv6_association_id" {
  description = "The association ID for the IPv6 CIDR block"
  value       = aws_vpc.siem_vpc.ipv6_association_id
}

output "vpc_ipv6_cidr_block" {
  description = "The IPv6 CIDR block"
  value       = aws_vpc.siem_vpc.ipv6_cidr_block
}

output "vpc_owner_id" {
  description = "The ID of the AWS account that owns the VPC"
  value       = aws_vpc.siem_vpc.owner_id
}

# Internet Gateway
output "igw_id" {
  description = "ID of the Internet Gateway"
  value       = aws_internet_gateway.siem_igw.id
}

output "igw_arn" {
  description = "ARN of the Internet Gateway"
  value       = aws_internet_gateway.siem_igw.arn
}

# Subnets
output "public_subnet_ids" {
  description = "List of IDs of public subnets"
  value       = aws_subnet.public[*].id
}

output "public_subnet_arns" {
  description = "List of ARNs of public subnets"
  value       = aws_subnet.public[*].arn
}

output "public_subnet_cidr_blocks" {
  description = "List of CIDR blocks of public subnets"
  value       = aws_subnet.public[*].cidr_block
}

output "public_subnet_availability_zones" {
  description = "List of availability zones of public subnets"
  value       = aws_subnet.public[*].availability_zone
}

output "private_subnet_ids" {
  description = "List of IDs of private subnets"
  value       = aws_subnet.private[*].id
}

output "private_subnet_arns" {
  description = "List of ARNs of private subnets"
  value       = aws_subnet.private[*].arn
}

output "private_subnet_cidr_blocks" {
  description = "List of CIDR blocks of private subnets"
  value       = aws_subnet.private[*].cidr_block
}

output "private_subnet_availability_zones" {
  description = "List of availability zones of private subnets"
  value       = aws_subnet.private[*].availability_zone
}

output "database_subnet_ids" {
  description = "List of IDs of database subnets"
  value       = aws_subnet.database[*].id
}

output "database_subnet_arns" {
  description = "List of ARNs of database subnets"
  value       = aws_subnet.database[*].arn
}

output "database_subnet_cidr_blocks" {
  description = "List of CIDR blocks of database subnets"
  value       = aws_subnet.database[*].cidr_block
}

output "database_subnet_availability_zones" {
  description = "List of availability zones of database subnets"
  value       = aws_subnet.database[*].availability_zone
}

# Database Subnet Group
output "database_subnet_group_id" {
  description = "ID of the database subnet group"
  value       = aws_db_subnet_group.siem_db_subnet_group.id
}

output "database_subnet_group_name" {
  description = "Name of the database subnet group"
  value       = aws_db_subnet_group.siem_db_subnet_group.name
}

output "database_subnet_group_arn" {
  description = "ARN of the database subnet group"
  value       = aws_db_subnet_group.siem_db_subnet_group.arn
}

# ElastiCache Subnet Group
output "elasticache_subnet_group_id" {
  description = "ID of the ElastiCache subnet group"
  value       = aws_elasticache_subnet_group.siem_cache_subnet_group.id
}

output "elasticache_subnet_group_name" {
  description = "Name of the ElastiCache subnet group"
  value       = aws_elasticache_subnet_group.siem_cache_subnet_group.name
}

# NAT Gateways
output "nat_gateway_ids" {
  description = "List of IDs of the NAT Gateways"
  value       = aws_nat_gateway.siem_nat[*].id
}

output "nat_gateway_allocation_ids" {
  description = "List of allocation IDs of Elastic IPs for NAT Gateways"
  value       = aws_nat_gateway.siem_nat[*].allocation_id
}

output "nat_gateway_subnet_ids" {
  description = "List of subnet IDs of NAT Gateways"
  value       = aws_nat_gateway.siem_nat[*].subnet_id
}

output "nat_gateway_network_interface_ids" {
  description = "List of network interface IDs of NAT Gateways"
  value       = aws_nat_gateway.siem_nat[*].network_interface_id
}

output "nat_gateway_private_ips" {
  description = "List of private IP addresses of NAT Gateways"
  value       = aws_nat_gateway.siem_nat[*].private_ip
}

output "nat_gateway_public_ips" {
  description = "List of public IP addresses of NAT Gateways"
  value       = aws_nat_gateway.siem_nat[*].public_ip
}

# Elastic IPs
output "nat_eip_ids" {
  description = "List of IDs of Elastic IPs for NAT Gateways"
  value       = aws_eip.nat[*].id
}

output "nat_eip_public_ips" {
  description = "List of public IP addresses of Elastic IPs for NAT Gateways"
  value       = aws_eip.nat[*].public_ip
}

# Route Tables
output "public_route_table_id" {
  description = "ID of the public route table"
  value       = aws_route_table.public.id
}

output "private_route_table_ids" {
  description = "List of IDs of the private route tables"
  value       = aws_route_table.private[*].id
}

output "database_route_table_id" {
  description = "ID of the database route table"
  value       = aws_route_table.database.id
}

# VPC Flow Logs
output "vpc_flow_log_id" {
  description = "ID of the VPC Flow Log"
  value       = var.enable_vpc_flow_logs ? aws_flow_log.siem_vpc_flow_log[0].id : null
}

output "vpc_flow_log_cloudwatch_log_group_name" {
  description = "Name of the CloudWatch Log Group for VPC Flow Logs"
  value       = var.enable_vpc_flow_logs ? aws_cloudwatch_log_group.vpc_flow_log[0].name : null
}

output "vpc_flow_log_cloudwatch_log_group_arn" {
  description = "ARN of the CloudWatch Log Group for VPC Flow Logs"
  value       = var.enable_vpc_flow_logs ? aws_cloudwatch_log_group.vpc_flow_log[0].arn : null
}

output "vpc_flow_log_iam_role_arn" {
  description = "ARN of the IAM role for VPC Flow Logs"
  value       = var.enable_vpc_flow_logs ? aws_iam_role.flow_log[0].arn : null
}

# VPC Endpoints
output "vpc_endpoint_s3_id" {
  description = "ID of VPC endpoint for S3"
  value       = var.enable_vpc_endpoints ? aws_vpc_endpoint.s3[0].id : null
}

output "vpc_endpoint_ec2_id" {
  description = "ID of VPC endpoint for EC2"
  value       = var.enable_vpc_endpoints ? aws_vpc_endpoint.ec2[0].id : null
}

output "vpc_endpoint_ecr_api_id" {
  description = "ID of VPC endpoint for ECR API"
  value       = var.enable_vpc_endpoints ? aws_vpc_endpoint.ecr_api[0].id : null
}

output "vpc_endpoint_ecr_dkr_id" {
  description = "ID of VPC endpoint for ECR DKR"
  value       = var.enable_vpc_endpoints ? aws_vpc_endpoint.ecr_dkr[0].id : null
}

output "vpc_endpoint_security_group_id" {
  description = "ID of the security group for VPC endpoints"
  value       = var.enable_vpc_endpoints ? aws_security_group.vpc_endpoint[0].id : null
}

# DHCP Options
output "dhcp_options_id" {
  description = "ID of the DHCP options"
  value       = var.enable_custom_dhcp ? aws_vpc_dhcp_options.siem_dhcp_options[0].id : null
}

output "dhcp_options_owner_id" {
  description = "Owner ID of the DHCP options"
  value       = var.enable_custom_dhcp ? aws_vpc_dhcp_options.siem_dhcp_options[0].owner_id : null
}

# Network ACLs
output "private_network_acl_id" {
  description = "ID of the private network ACL"
  value       = var.enable_network_acls ? aws_network_acl.private[0].id : null
}

output "database_network_acl_id" {
  description = "ID of the database network ACL"
  value       = var.enable_network_acls ? aws_network_acl.database[0].id : null
}

# Availability Zones
output "availability_zones" {
  description = "List of availability zones used"
  value       = data.aws_availability_zones.available.names
}

output "availability_zones_count" {
  description = "Number of availability zones used"
  value       = length(data.aws_availability_zones.available.names)
}

# Region
output "aws_region" {
  description = "AWS region"
  value       = data.aws_region.current.name
}

# Subnet mappings for load balancers
output "public_subnet_mapping" {
  description = "Map of public subnet IDs to availability zones"
  value = zipmap(
    aws_subnet.public[*].availability_zone,
    aws_subnet.public[*].id
  )
}

output "private_subnet_mapping" {
  description = "Map of private subnet IDs to availability zones"
  value = zipmap(
    aws_subnet.private[*].availability_zone,
    aws_subnet.private[*].id
  )
}

output "database_subnet_mapping" {
  description = "Map of database subnet IDs to availability zones"
  value = zipmap(
    aws_subnet.database[*].availability_zone,
    aws_subnet.database[*].id
  )
}

# Network information for security groups
output "vpc_cidr_blocks" {
  description = "List of CIDR blocks for the VPC"
  value       = [aws_vpc.siem_vpc.cidr_block]
}

output "public_subnet_cidrs" {
  description = "List of CIDR blocks for public subnets"
  value       = aws_subnet.public[*].cidr_block
}

output "private_subnet_cidrs" {
  description = "List of CIDR blocks for private subnets"
  value       = aws_subnet.private[*].cidr_block
}

output "database_subnet_cidrs" {
  description = "List of CIDR blocks for database subnets"
  value       = aws_subnet.database[*].cidr_block
}

# Summary information
output "vpc_summary" {
  description = "Summary of VPC configuration"
  value = {
    vpc_id                    = aws_vpc.siem_vpc.id
    vpc_cidr                  = aws_vpc.siem_vpc.cidr_block
    public_subnets_count      = length(aws_subnet.public)
    private_subnets_count     = length(aws_subnet.private)
    database_subnets_count    = length(aws_subnet.database)
    nat_gateways_count        = length(aws_nat_gateway.siem_nat)
    availability_zones_count  = length(data.aws_availability_zones.available.names)
    vpc_flow_logs_enabled     = var.enable_vpc_flow_logs
    vpc_endpoints_enabled     = var.enable_vpc_endpoints
    nat_gateway_enabled       = var.enable_nat_gateway
  }
}

# Tags
output "vpc_tags" {
  description = "Tags applied to VPC"
  value       = aws_vpc.siem_vpc.tags
}

output "public_subnet_tags" {
  description = "Tags applied to public subnets"
  value       = aws_subnet.public[*].tags
}

output "private_subnet_tags" {
  description = "Tags applied to private subnets"
  value       = aws_subnet.private[*].tags
}

output "database_subnet_tags" {
  description = "Tags applied to database subnets"
  value       = aws_subnet.database[*].tags
}