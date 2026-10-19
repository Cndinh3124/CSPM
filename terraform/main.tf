# Private S3 bucket for the CSPM lab.
# The resource is intentionally configured with security best practices enabled.
resource "aws_s3_bucket" "cspm_demo" {
  bucket = var.bucket_name

  tags = {
    Project     = "SecNet-CSPM"
    Environment = "lab"
    ManagedBy   = "Terraform"
  }
}

resource "aws_s3_bucket_public_access_block" "cspm_demo" {
  bucket = aws_s3_bucket.cspm_demo.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cspm_demo" {
  bucket = aws_s3_bucket.cspm_demo.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Keep versioning enabled normally. Disabling it is an optional, low-impact
# demonstration of a weaker bucket setting. Do not store important data in this lab.
resource "aws_s3_bucket_versioning" "cspm_demo" {
  count  = var.enable_bucket_versioning ? 1 : 0
  bucket = aws_s3_bucket.cspm_demo.id

  versioning_configuration {
    status = "Enabled"
  }
}

output "demo_bucket_name" {
  description = "Name of the private CSPM lab bucket."
  value       = aws_s3_bucket.cspm_demo.bucket
}
