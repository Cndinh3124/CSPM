output "vpc_id" {
  description = "VPC created for the CSPM lab."
  value       = aws_vpc.cspm.id
}

output "public_subnet_id" {
  description = "Public subnet ID."
  value       = aws_subnet.public.id
}

output "private_subnet_id" {
  description = "Private subnet ID (no NAT route)."
  value       = aws_subnet.private.id
}

output "web_instance_public_ip" {
  description = "Public IPv4 address of the optional demo web instance."
  value       = try(aws_instance.web[0].public_ip, null)
}

output "web_url" {
  description = "HTTP URL for the demo web page, if the EC2 instance is enabled."
  value       = try("http://${aws_instance.web[0].public_ip}", null)
}

output "demo_bucket_name" {
  description = "Name of the private CSPM lab bucket."
  value       = aws_s3_bucket.cspm_demo.bucket
}

output "cloudtrail_name" {
  description = "CloudTrail trail name when enabled."
  value       = var.enable_cloudtrail ? aws_cloudtrail.cspm[0].name : null
}
