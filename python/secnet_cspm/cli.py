"""Command-line entry point for the small CSPM workflow."""
import argparse

from .config import project_path, setting
from .csv_findings import export_failures
from .gemini_analyzer import analyze_csv
from .prowler_runner import run_scan


def scan() -> None:
    """Run Prowler and export its FAIL findings to a separate CSV."""
    output_dir = project_path(setting("PROWLER_OUTPUT_DIR", "reports/prowler"))
    run_scan(output_dir, setting("AWS_DEFAULT_REGION"))
    export_failures(
        output_dir,
        project_path(setting("FAIL_CSV_PATH", "reports/findings_fail.csv")),
    )


def analyze() -> None:
    """Analyze the existing FAIL CSV with Gemini, if configured."""
    analyze_csv(
        project_path(setting("FAIL_CSV_PATH", "reports/findings_fail.csv")),
        project_path(setting("GEMINI_REPORT_PATH", "reports/gemini_analysis.md")),
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SecNet CSPM: Terraform + Prowler + CSV FAIL + Gemini"
    )
    parser.add_argument(
        "action",
        choices=["scan", "analyze", "run"],
        help="'scan' runs Prowler, 'analyze' uses Gemini, 'run' runs both.",
    )
    action = parser.parse_args().action

    if action in ("scan", "run"):
        scan()
    if action in ("analyze", "run"):
        analyze()


if __name__ == "__main__":
    main()
