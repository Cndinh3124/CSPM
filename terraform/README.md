# Terraform lab — SecNet-CSPM

This lab creates a VPC with public and private subnets, an Internet Gateway and routes, a small optional Amazon Linux web EC2 instance, and a private encrypted S3 bucket. CloudTrail logging can be enabled with a variable. A NAT Gateway is deliberately omitted to avoid recurring charges.

## Resources

- VPC `10.20.0.0/16`, one public subnet and one private subnet in the first available AZ.
- Internet Gateway and public route; the private subnet has no default internet route and is reserved for later workloads.
- Optional `t3.micro` EC2 running Nginx, encrypted 8 GiB gp3 root volume, IMDSv2 required.
- Security Group allows HTTP/80 from the internet for the demo; SSH/22 is restricted to `ssh_allowed_cidr` by default.
- Private S3 bucket with all public-access blocks, SSE-S3 encryption and versioning.
- Optional multi-region CloudTrail with a separate private, encrypted log bucket.

## Cost and safety

**EC2 and its public IPv4 address can incur charges while provisioned. CloudTrail, S3 storage/requests and data transfer may also incur charges.** Check current AWS pricing and your account's Free Tier before applying. No NAT Gateway or RDS database is created.

Use a sandbox account and review every plan. Never commit credentials, `.env`, `terraform.tfvars`, state files or scan reports containing sensitive information.

## Deploy

From this directory:

```bash
cp terraform.tfvars.example terraform.tfvars
# Edit bucket_name to a globally unique value and set ssh_allowed_cidr to YOUR_PUBLIC_IP/32.
terraform init
terraform fmt -recursive
terraform validate
terraform plan
terraform apply
```

Check that the AWS identity and region are correct before apply:

```bash
aws sts get-caller-identity
aws configure get region
```

The EC2 web page URL is printed as `web_url` after apply. HTTP is intentionally public for the demo; do not put sensitive data on this instance.

## Controlled CSPM finding demonstration

The default SSH rule is restricted. To intentionally demonstrate an exposed SSH port, set this in `terraform.tfvars`:

```hcl
allow_ssh_from_anywhere = true
```

Then run `terraform plan`, inspect the diff, and `terraform apply`. Run Prowler and inspect the FAIL CSV. After the demonstration, set the value back to `false`, run `terraform plan`, apply the fix, and rerun Prowler to verify. Do not leave SSH open to the internet. This toggle is deliberately opt-in.

## Optional CloudTrail

CloudTrail is off by default to control extra resources and log storage. To enable it, add:

```hcl
enable_cloudtrail = true
```

Review the plan and current AWS pricing before applying. CloudTrail logs are retained in a private S3 bucket; lifecycle expiration is not configured, so remove lab resources when finished if logs are no longer needed.

## Run Prowler

From repository root:

```bash
PYTHONPATH=python python -m secnet_cspm.cli scan
```

The project uses Prowler's native checks and then exports FAIL rows to `reports/findings_fail.csv`. The exact checks reported depend on Prowler version, account configuration and IAM permissions.

## Cleanup

From this directory, first verify account/region and inspect what Terraform manages:

```bash
aws sts get-caller-identity
terraform plan -destroy
terraform destroy
```

Review the destroy plan before confirming. Terraform only deletes resources in its current state; it does not clean up unrelated AWS resources.
