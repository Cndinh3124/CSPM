variable "aws_region" {
  description = "AWS region used for this small lab."
  type        = string
  default     = "ap-southeast-1"
}

variable "bucket_name" {
  description = "Globally unique name for the demo S3 bucket."
  type        = string

  validation {
    condition     = length(var.bucket_name) >= 3 && length(var.bucket_name) <= 63
    error_message = "bucket_name must be between 3 and 63 characters."
  }
}

variable "enable_bucket_versioning" {
  description = "Keep true for normal use. Set false only for a controlled CSPM demo."
  type        = bool
  default     = true
}
