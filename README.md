# SecNet CSPM — Terraform + Prowler + Gemini

Simple, auditable Cloud Security Posture Management workflow for an AWS lab.

## Workflow

1. **Terraform** creates a small, private AWS S3 lab resource.
2. **Prowler** runs its existing AWS security checks. This project does not reimplement Prowler checks.
3. **Python** selects Prowler CSV rows whose status is `FAIL` into `reports/findings_fail.csv`.
4. **Google Gemini** explains findings and suggests remediation; it does not change AWS resources.
5. An operator reviews and applies approved remediation, then reruns Prowler to verify the result.

## Requirements

- Ubuntu Server 22.04/24.04 or another supported Linux environment
- Python 3.10+
- AWS CLI credentials with least-privilege permissions sufficient for the intended Prowler checks
- Prowler CLI
- Terraform 1.5+
- Gemini API key (optional; needed only for AI analysis)

## 1. Set up Python

From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Edit `.env` and set `GEMINI_API_KEY` only if you plan to use Gemini. Never commit `.env` or cloud credentials.

## 2. Install and verify Prowler

Install Prowler following the official instructions: https://docs.prowler.com/

Check:

```bash
prowler --version
aws sts get-caller-identity
```

Confirm the AWS account and role/user are correct before scanning. Use a lab account and least privilege.

## 3. Deploy the Terraform lab

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars and set a globally unique bucket name.
terraform init
terraform fmt -check
terraform validate
terraform plan
terraform apply
cd ..
```

Review the plan carefully before applying. The sample creates a private S3 bucket with public access blocking, encryption and versioning. It is designed as a small, low-footprint lab, not a full production landing zone.

Destroy only the lab resources when finished and after verifying the selected account/workspace:

```bash
cd terraform
terraform destroy
```

## 4. Scan and export FAIL CSV

```bash
PYTHONPATH=python python -m secnet_cspm.cli scan
```

The runner invokes Prowler with its native CSV output. The CSV processor discovers the most recently modified Prowler CSV, identifies the status column, and exports only rows whose status equals `FAIL` (case-insensitive).

Expected file: `reports/findings_fail.csv`.

If Prowler's CSV schema changes in your installed version, the processor fails clearly instead of silently exporting incorrect data. Inspect the detected CSV headers and adjust the supported status-column mapping if needed.

You can also run Prowler directly:

```bash
prowler aws --status FAIL --output-formats csv --output-directory reports/prowler
```

## 5. Analyze with Gemini

```bash
PYTHONPATH=python python -m secnet_cspm.cli analyze
```

Expected report: `reports/gemini_analysis.md`.

The analysis is advisory. Do not send secrets or sensitive customer data to an AI service. Review your organization's data-handling requirements first. The number of findings sent to Gemini is limited by `MAX_FINDINGS_FOR_AI`.

## 6. Full flow

```bash
PYTHONPATH=python python -m secnet_cspm.cli run
```

This scans, writes the FAIL CSV, and attempts Gemini analysis if a key is configured. Without a Gemini key, CSV generation still works and AI analysis is skipped.

## 7. Tests

```bash
PYTHONPATH=python python -m unittest discover -s tests -v
```

CSV filtering tests use local fixture data and do not need AWS credentials or Gemini.

## Project layout

```text
.
├── python/secnet_cspm/
│   ├── cli.py
│   ├── config.py
│   ├── csv_findings.py
│   ├── gemini_analyzer.py
│   └── prowler_runner.py
├── terraform/
├── tests/
├── reports/
├── .env.example
└── requirements.txt
```

## Security notes

- Prowler remains the security assessment engine; no duplicate check engine is implemented here.
- This starter does **not** auto-remediate resources.
- Gemini recommendations must be reviewed by a person and validated with a fresh scan.
- Never commit AWS credentials, Gemini keys, Terraform state, or sensitive scan results.
- A scan with no FAIL rows is not proof that the entire account is secure; inspect scan coverage and errors as well.
