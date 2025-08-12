# SIEM OpenSource PyMES - VPC Module
# Creates VPC with public, private and database subnets

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_region" "current" {}

# VPC
resource "aws_vpc" "siem_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-vpc"
    Type = "VPC"
  })
}

# Internet Gateway
resource "aws_internet_gateway" "siem_igw" {
  vpc_id = aws_vpc.siem_vpc.id

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-igw"
    Type = "Internet Gateway"
  })
}

# Public Subnets
resource "aws_subnet" "public" {
  count = length(var.public_subnet_cidrs)

  vpc_id                  = aws_vpc.siem_vpc.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-public-subnet-${count.index + 1}"
    Type = "Public Subnet"
    "kubernetes.io/role/elb" = "1"
  })
}

# Private Subnets
resource "aws_subnet" "private" {
  count = length(var.private_subnet_cidrs)

  vpc_id            = aws_vpc.siem_vpc.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-private-subnet-${count.index + 1}"
    Type = "Private Subnet"
    "kubernetes.io/role/internal-elb" = "1"
  })
}

# Database Subnets
resource "aws_subnet" "database" {
  count = length(var.database_subnet_cidrs)

  vpc_id            = aws_vpc.siem_vpc.id
  cidr_block        = var.database_subnet_cidrs[count.index]
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-database-subnet-${count.index + 1}"
    Type = "Database Subnet"
  })
}

# Elastic IPs for NAT Gateways
resource "aws_eip" "nat" {
  count = var.enable_nat_gateway ? length(var.public_subnet_cidrs) : 0

  domain = "vpc"
  depends_on = [aws_internet_gateway.siem_igw]

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-nat-eip-${count.index + 1}"
    Type = "NAT Gateway EIP"
  })
}

# NAT Gateways
resource "aws_nat_gateway" "siem_nat" {
  count = var.enable_nat_gateway ? length(var.public_subnet_cidrs) : 0

  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id
  depends_on    = [aws_internet_gateway.siem_igw]

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-nat-gateway-${count.index + 1}"
    Type = "NAT Gateway"
  })
}

# Route Table for Public Subnets
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.siem_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.siem_igw.id
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-public-rt"
    Type = "Public Route Table"
  })
}

# Route Tables for Private Subnets
resource "aws_route_table" "private" {
  count = length(var.private_subnet_cidrs)

  vpc_id = aws_vpc.siem_vpc.id

  dynamic "route" {
    for_each = var.enable_nat_gateway ? [1] : []
    content {
      cidr_block     = "0.0.0.0/0"
      nat_gateway_id = aws_nat_gateway.siem_nat[count.index].id
    }
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-private-rt-${count.index + 1}"
    Type = "Private Route Table"
  })
}

# Route Table for Database Subnets
resource "aws_route_table" "database" {
  vpc_id = aws_vpc.siem_vpc.id

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-database-rt"
    Type = "Database Route Table"
  })
}

# Route Table Associations - Public
resource "aws_route_table_association" "public" {
  count = length(var.public_subnet_cidrs)

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# Route Table Associations - Private
resource "aws_route_table_association" "private" {
  count = length(var.private_subnet_cidrs)

  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

# Route Table Associations - Database
resource "aws_route_table_association" "database" {
  count = length(var.database_subnet_cidrs)

  subnet_id      = aws_subnet.database[count.index].id
  route_table_id = aws_route_table.database.id
}

# Database Subnet Group
resource "aws_db_subnet_group" "siem_db_subnet_group" {
  name       = "${var.project_name}-${var.environment}-db-subnet-group"
  subnet_ids = aws_subnet.database[*].id

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-db-subnet-group"
    Type = "Database Subnet Group"
  })
}

# ElastiCache Subnet Group
resource "aws_elasticache_subnet_group" "siem_cache_subnet_group" {
  name       = "${var.project_name}-${var.environment}-cache-subnet-group"
  subnet_ids = aws_subnet.private[*].id

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-cache-subnet-group"
    Type = "Cache Subnet Group"
  })
}

# VPC Flow Logs (optional)
resource "aws_flow_log" "siem_vpc_flow_log" {
  count = var.enable_vpc_flow_logs ? 1 : 0

  iam_role_arn    = aws_iam_role.flow_log[0].arn
  log_destination = aws_cloudwatch_log_group.vpc_flow_log[0].arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.siem_vpc.id

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-vpc-flow-log"
    Type = "VPC Flow Log"
  })
}

# CloudWatch Log Group for VPC Flow Logs
resource "aws_cloudwatch_log_group" "vpc_flow_log" {
  count = var.enable_vpc_flow_logs ? 1 : 0

  name              = "/aws/vpc/flowlogs/${var.project_name}-${var.environment}"
  retention_in_days = var.flow_log_retention_days

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-vpc-flow-log-group"
    Type = "CloudWatch Log Group"
  })
}

# IAM Role for VPC Flow Logs
resource "aws_iam_role" "flow_log" {
  count = var.enable_vpc_flow_logs ? 1 : 0

  name = "${var.project_name}-${var.environment}-vpc-flow-log-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "vpc-flow-logs.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-vpc-flow-log-role"
    Type = "IAM Role"
  })
}

# IAM Policy for VPC Flow Logs
resource "aws_iam_role_policy" "flow_log" {
  count = var.enable_vpc_flow_logs ? 1 : 0

  name = "${var.project_name}-${var.environment}-vpc-flow-log-policy"
  role = aws_iam_role.flow_log[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}

# VPC Endpoints for AWS Services (optional)
resource "aws_vpc_endpoint" "s3" {
  count = var.enable_vpc_endpoints ? 1 : 0

  vpc_id       = aws_vpc.siem_vpc.id
  service_name = "com.amazonaws.${data.aws_region.current.name}.s3"
  
  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-s3-endpoint"
    Type = "VPC Endpoint"
  })
}

resource "aws_vpc_endpoint" "ec2" {
  count = var.enable_vpc_endpoints ? 1 : 0

  vpc_id              = aws_vpc.siem_vpc.id
  service_name        = "com.amazonaws.${data.aws_region.current.name}.ec2"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.vpc_endpoint[0].id]
  
  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-ec2-endpoint"
    Type = "VPC Endpoint"
  })
}

resource "aws_vpc_endpoint" "ecr_api" {
  count = var.enable_vpc_endpoints ? 1 : 0

  vpc_id              = aws_vpc.siem_vpc.id
  service_name        = "com.amazonaws.${data.aws_region.current.name}.ecr.api"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.vpc_endpoint[0].id]
  
  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-ecr-api-endpoint"
    Type = "VPC Endpoint"
  })
}

resource "aws_vpc_endpoint" "ecr_dkr" {
  count = var.enable_vpc_endpoints ? 1 : 0

  vpc_id              = aws_vpc.siem_vpc.id
  service_name        = "com.amazonaws.${data.aws_region.current.name}.ecr.dkr"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.vpc_endpoint[0].id]
  
  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-ecr-dkr-endpoint"
    Type = "VPC Endpoint"
  })
}

# Security Group for VPC Endpoints
resource "aws_security_group" "vpc_endpoint" {
  count = var.enable_vpc_endpoints ? 1 : 0

  name_prefix = "${var.project_name}-${var.environment}-vpc-endpoint-"
  vpc_id      = aws_vpc.siem_vpc.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-vpc-endpoint-sg"
    Type = "Security Group"
  })
}

# DHCP Options Set (optional)
resource "aws_vpc_dhcp_options" "siem_dhcp_options" {
  count = var.enable_custom_dhcp ? 1 : 0

  domain_name         = var.domain_name != "" ? var.domain_name : "${data.aws_region.current.name}.compute.internal"
  domain_name_servers = ["AmazonProvidedDNS"]

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-dhcp-options"
    Type = "DHCP Options"
  })
}

resource "aws_vpc_dhcp_options_association" "siem_dhcp_options_association" {
  count = var.enable_custom_dhcp ? 1 : 0

  vpc_id          = aws_vpc.siem_vpc.id
  dhcp_options_id = aws_vpc_dhcp_options.siem_dhcp_options[0].id
}

# Network ACLs (optional enhanced security)
resource "aws_network_acl" "private" {
  count = var.enable_network_acls ? 1 : 0

  vpc_id     = aws_vpc.siem_vpc.id
  subnet_ids = aws_subnet.private[*].id

  # Allow inbound traffic from VPC
  ingress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = var.vpc_cidr
    from_port  = 0
    to_port    = 0
  }

  # Allow outbound traffic
  egress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-private-nacl"
    Type = "Network ACL"
  })
}

resource "aws_network_acl" "database" {
  count = var.enable_network_acls ? 1 : 0

  vpc_id     = aws_vpc.siem_vpc.id
  subnet_ids = aws_subnet.database[*].id

  # Allow inbound traffic from private subnets only
  dynamic "ingress" {
    for_each = var.private_subnet_cidrs
    content {
      protocol   = "tcp"
      rule_no    = 100 + index(var.private_subnet_cidrs, ingress.value)
      action     = "allow"
      cidr_block = ingress.value
      from_port  = 5432
      to_port    = 5432
    }
  }

  # Allow outbound traffic to private subnets
  dynamic "egress" {
    for_each = var.private_subnet_cidrs
    content {
      protocol   = "tcp"
      rule_no    = 100 + index(var.private_subnet_cidrs, egress.value)
      action     = "allow"
      cidr_block = egress.value
      from_port  = 1024
      to_port    = 65535
    }
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-database-nacl"
    Type = "Network ACL"
  })
}