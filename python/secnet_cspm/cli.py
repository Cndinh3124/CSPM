"""Command-line entry point for SecNet-CSPM."""
import argparse
import shutil
import subprocess
from pathlib import Path

from .config import project_path, setting
from .csv_findings import export_failures
from .gemini_analyzer import analyze_csv
from .prowler_runner import run_scan, run_compliance_scan


DASHBOARD_OUTPUT = Path("/opt/CSPM/dashboard-latest/output")
DASHBOARD_SERVICE = "prowler-dashboard.service"


def update_dashboard(findings_csv: Path, compliance_csv: Path) -> None:
    """Publish the latest reports and reload the dashboard."""
    findings_dir = DASHBOARD_OUTPUT
    compliance_dir = findings_dir / "compliance"

    findings_dir.mkdir(parents=True, exist_ok=True)
    compliance_dir.mkdir(parents=True, exist_ok=True)

    # Keep the Overview focused on the latest findings scan.
    for old_csv in findings_dir.glob("*.csv"):
        old_csv.unlink()

    # Keep only the latest CIS compliance report in the active dashboard.
    for old_csv in compliance_dir.glob("*.csv"):
        old_csv.unlink()

    shutil.copy2(findings_csv, findings_dir / findings_csv.name)
    shutil.copy2(compliance_csv, compliance_dir / compliance_csv.name)

    print(f"Dashboard findings CSV: {findings_dir / findings_csv.name}")
    print(f"Dashboard compliance CSV: {compliance_dir / compliance_csv.name}")

    result = subprocess.run(
        ["systemctl", "restart", DASHBOARD_SERVICE],
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(
            "Reports were copied, but Dashboard restart failed. "
            "Check: systemctl status prowler-dashboard.service"
        )

    print("Prowler Dashboard restarted successfully.")


def scan() -> None:
    """Run findings and CIS scans, export failures, and update Dashboard."""
    output_dir = project_path(setting("PROWLER_OUTPUT_DIR", "reports/prowler"))
    region = setting("AWS_DEFAULT_REGION", "ap-southeast-1")
    profile = setting("AWS_PROFILE", "secnet-cspm")

    findings_csv = run_scan(output_dir, region, profile)

    export_failures(
        output_dir,
        project_path(setting("FAIL_CSV_PATH", "reports/findings_fail.csv")),
    )

    compliance_csv = run_compliance_scan(
        project_path(setting("COMPLIANCE_OUTPUT_DIR", "reports/compliance")),
        region,
        profile,
    )

    update_dashboard(findings_csv, compliance_csv)


def analyze() -> None:
    """Analyze the existing FAIL CSV with Gemini."""
    analyze_csv(
        project_path(setting("FAIL_CSV_PATH", "reports/findings_fail.csv")),
        project_path(setting("GEMINI_REPORT_PATH", "reports/gemini_analysis.md")),
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SecNet CSPM: Prowler findings, CIS compliance, and Gemini"
    )
    parser.add_argument(
        "action",
        choices=["scan", "analyze", "run"],
        help="'scan' runs both AWS scans; 'analyze' uses Gemini; "
             "'run' runs scans and then Gemini.",
    )
    action = parser.parse_args().action

    if action in ("scan", "run"):
        scan()

    if action in ("analyze", "run"):
        analyze()


if __name__ == "__main__":
    main()
