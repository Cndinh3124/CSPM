"""Run Prowler findings and compliance scans."""
import os
import shutil
import subprocess
from datetime import datetime
from pathlib import Path


PROWLER_BIN = "/root/.local/bin/prowler"


def _run(command: list[str], env: dict, label: str) -> None:
    print(f"\n=== {label} ===")
    print("Command:", " ".join(command))

    result = subprocess.run(command, env=env, check=False)

    if result.returncode not in (0, 3):
        raise RuntimeError(
            f"{label} failed with exit code {result.returncode}"
        )

    print(f"{label} completed (exit code {result.returncode}).")


def run_scan(
    output_dir: Path,
    aws_region: str = "ap-southeast-1",
    aws_profile: str = "secnet-cspm",
) -> Path:
    """Run the findings scan and return its CSV file."""
    prowler = shutil.which("prowler") or PROWLER_BIN

    if not Path(prowler).exists():
        raise RuntimeError(f"Prowler executable not found: {prowler}")

    if not aws_profile or not aws_region:
        raise ValueError("AWS profile and region must not be empty.")

    output_dir.mkdir(parents=True, exist_ok=True)
    before = {p.resolve() for p in output_dir.glob("*.csv")}

    env = os.environ.copy()
    env["AWS_PROFILE"] = aws_profile
    env["AWS_DEFAULT_REGION"] = aws_region

    command = [
        prowler, "aws",
        "--profile", aws_profile,
        "--region", aws_region,
        "--status", "FAIL",
        "--output-formats", "csv",
        "--output-directory", str(output_dir),
        "--no-banner",
    ]

    _run(command, env, "AWS findings scan")

    candidates = [
        p for p in output_dir.glob("*.csv")
        if p.resolve() not in before
    ]

    if not candidates:
        raise RuntimeError("Findings scan completed but no new CSV was found.")

    return max(candidates, key=lambda p: p.stat().st_mtime)


def run_compliance_scan(
    output_dir: Path,
    aws_region: str = "ap-southeast-1",
    aws_profile: str = "secnet-cspm",
) -> Path:
    """Run CIS 5.0 AWS assessment and return its compliance CSV."""
    prowler = shutil.which("prowler") or PROWLER_BIN

    if not Path(prowler).exists():
        raise RuntimeError(f"Prowler executable not found: {prowler}")

    if not aws_profile or not aws_region:
        raise ValueError("AWS profile and region must not be empty.")

    run_dir = output_dir / datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    run_dir.mkdir(parents=True, exist_ok=False)

    env = os.environ.copy()
    env["AWS_PROFILE"] = aws_profile
    env["AWS_DEFAULT_REGION"] = aws_region

    command = [
        prowler, "aws",
        "--profile", aws_profile,
        "--region", aws_region,
        "--compliance", "cis_5.0_aws",
        "--output-formats", "csv",
        "--output-directory", str(run_dir),
        "--no-banner",
    ]

    _run(command, env, "CIS 5.0 AWS compliance scan")

    compliance_dir = run_dir / "compliance"
    candidates = list(compliance_dir.glob("*.csv"))

    if not candidates:
        raise RuntimeError(
            f"CIS scan completed but no compliance CSV was found in "
            f"{compliance_dir}"
        )

    return max(candidates, key=lambda p: p.stat().st_mtime)
