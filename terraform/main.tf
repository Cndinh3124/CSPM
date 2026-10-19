# SecNet-CSPM AWS lab: VPC, public/private subnets, a small demo EC2, and a private S3 bucket.
# No NAT Gateway is created to avoid its recurring hourly and data-processing costs.

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_ssm_parameter" "amazon_linux_2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

resource "aws_vpc" "cspm" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name        = "${var.project_name}-vpc"
    Project     = var.project_name
    Environment = "lab"
    ManagedBy   = "Terraform"
  }
}

resource "aws_internet_gateway" "cspm" {
  vpc_id = aws_vpc.cspm.id
  tags   = { Name = "${var.project_name}-igw", Project = var.project_name, ManagedBy = "Terraform" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.cspm.id
  cidr_block              = var.public_subnet_cidr
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true
  tags                    = { Name = "${var.project_name}-public-subnet", Tier = "public", Project = var.project_name, ManagedBy = "Terraform" }
}

resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.cspm.id
  cidr_block        = var.private_subnet_cidr
  availability_zone = data.aws_availability_zones.available.names[0]
  tags              = { Name = "${var.project_name}-private-subnet", Tier = "private", Project = var.project_name, ManagedBy = "Terraform" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.cspm.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.cspm.id
  }
  tags = { Name = "${var.project_name}-public-rt", Project = var.project_name, ManagedBy = "Terraform" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.cspm.id
  tags   = { Name = "${var.project_name}-private-rt", Project = var.project_name, ManagedBy = "Terraform" }
}

resource "aws_route_table_association" "private" {
  subnet_id      = aws_subnet.private.id
  route_table_id = aws_route_table.private.id
}

resource "aws_security_group" "web" {
  name        = "${var.project_name}-web-sg"
  description = "HTTP access for CSPM lab; SSH is restricted by default."
  vpc_id      = aws_vpc.cspm.id

  ingress {
    description = "HTTP demo website"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = var.allow_ssh_from_anywhere ? "INTENTIONAL CSPM DEMO: SSH open to the internet" : "SSH restricted to configured CIDR"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.allow_ssh_from_anywhere ? ["0.0.0.0/0"] : [var.ssh_allowed_cidr]
  }

  egress {
    description = "Outbound traffic for OS package installation and updates"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project_name}-web-sg", Project = var.project_name, ManagedBy = "Terraform" }
}

resource "aws_instance" "web" {
  count                       = var.enable_demo_ec2 ? 1 : 0
  ami                         = data.aws_ssm_parameter.amazon_linux_2023.value
  instance_type               = var.ec2_instance_type
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.web.id]
  associate_public_ip_address = true
  user_data                   = <<-EOF
    #!/bin/bash
    dnf install -y nginx
    systemctl enable --now nginx
    cat > /usr/share/nginx/html/index.html <<'HTML'
    <!doctype html>
    <html><head><title>SecNet-CSPM Lab</title></head>
    <body><h1>SecNet-CSPM AWS Lab</h1><p>Managed by Terraform. Scan this account with Prowler.</p></body></html>
    HTML
  EOF

  root_block_device {
    encrypted   = true
    volume_type = "gp3"
    volume_size = 8
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  tags = {
    Name        = "${var.project_name}-web"
    Project     = var.project_name
    Environment = "lab"
    ManagedBy   = "Terraform"
  }
}

resource "aws_s3_bucket" "cspm_demo" {
  bucket = var.bucket_name
  tags   = { Name = "${var.project_name}-findings-demo", Project = var.project_name, Environment = "lab", ManagedBy = "Terraform" }
}

resource "aws_s3_bucket_public_access_block" "cspm_demo" {
  bucket                  = aws_s3_bucket.cspm_demo.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cspm_demo" {
  bucket = aws_s3_bucket.cspm_demo.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

resource "aws_s3_bucket_versioning" "cspm_demo" {
  bucket = aws_s3_bucket.cspm_demo.id
  versioning_configuration { status = var.enable_bucket_versioning ? "Enabled" : "Suspended" }
}
