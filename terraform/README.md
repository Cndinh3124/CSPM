# Terraform lab

This configuration creates one private S3 bucket, blocks public access, enables
server-side encryption, and enables versioning by default.

```bash
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars. Bucket names must be globally unique.
terraform init
terraform fmt -check
terraform validate
terraform plan
terraform apply
```

Review the plan before applying it. Use a sandbox account when possible.

For a controlled demonstration of a weaker setting, you may set
`enable_bucket_versioning = false` in `terraform.tfvars`. This may produce a
Prowler finding depending on its checks and version; it is not guaranteed to do so.
Do not put important data in the test bucket.

When done, verify the AWS account and Terraform workspace before cleanup:

```bash
terraform plan -destroy
terraform destroy
```

Never commit `terraform.tfvars`, `.terraform/`, or Terraform state files.
