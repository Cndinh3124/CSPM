variable "aws_region" {
  description = "AWS region for the lab."
  type        = string
  default     = "ap-southeast-1"
}

variable "project_name" {
  description = "Prefix used for resource names and tags."
  type        = string
  default     = "secnet-cspm"
}

variable "bucket_name" {
  description = "Globally unique S3 bucket name."
  type        = string
  validation {
    condition     = length(var.bucket_name) >= 3 && length(var.bucket_name) <= 63
    error_message = "bucket_name must be between 3 and 63 characters."
  }
}

variable "vpc_cidr" {
  description = "CIDR block for the lab VPC."
  type        = string
  default     = "10.20.0.0/16"
}

variable "public_subnet_cidr" {
  description = "Public subnet hosting the optional demo EC2 instance."
  type        = string
  default     = "10.20.1.0/24"
}

variable "private_subnet_cidr" {
  description = "Private subnet reserved for future private workloads; no NAT Gateway is created."
  type        = string
  default     = "10.20.2.0/24"
}

variable "enable_demo_ec2" {
  description = "Create a small public demo web instance. This incurs EC2/public IPv4 charges while running."
  type        = bool
  default     = true
}

variable "ec2_instance_type" {
  description = "Small instance type for the demo; availability and pricing depend on account and region."
  type        = string
  default     = "t3.micro"
}

variable "ssh_allowed_cidr" {
  description = "Your public IP in CIDR notation, e.g. 203.0.113.10/32. Default denies practical SSH access."
  type        = string
  default     = "127.0.0.1/32"
}

variable "allow_ssh_from_anywhere" {
  description = "INSECURE DEMO ONLY: set true temporarily to generate an open-SSH finding, then set false and apply."
  type        = bool
  default     = false
}

variable "enable_cloudtrail" {
  description = "Create a multi-region CloudTrail and private S3 log bucket. May incur charges."
  type        = bool
  default     = false
}

variable "enable_bucket_versioning" {
  description = "Enable S3 versioning for the lab bucket."
  type        = bool
  default     = true
}
