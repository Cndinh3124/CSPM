import csv
import tempfile
import unittest
from pathlib import Path

from secnet_cspm.csv_findings import export_failures, find_status_column


class CsvFindingTests(unittest.TestCase):
    def test_finds_status_case_insensitively(self):
        self.assertEqual(find_status_column(["CHECK_ID", "STATUS"]), "STATUS")
        self.assertEqual(find_status_column(["status", "check_id"]), "status")
        self.assertIsNone(find_status_column(["CHECK_ID", "RESOURCE"]))

    def test_exports_only_fail_rows(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source_dir = root / "prowler"
            source_dir.mkdir()
            source = source_dir / "scan.csv"

            with source.open("w", newline="", encoding="utf-8") as file:
                writer = csv.DictWriter(file, fieldnames=["STATUS", "CHECK_ID"])
                writer.writeheader()
                writer.writerow({"STATUS": "FAIL", "CHECK_ID": "check-1"})
                writer.writerow({"STATUS": "PASS", "CHECK_ID": "check-2"})
                writer.writerow({"STATUS": "fail", "CHECK_ID": "check-3"})
                writer.writerow({"STATUS": "MANUAL", "CHECK_ID": "check-4"})

            output = root / "findings_fail.csv"
            count = export_failures(source_dir, output)
            self.assertEqual(count, 2)

            with output.open("r", newline="", encoding="utf-8-sig") as file:
                rows = list(csv.DictReader(file))
            self.assertEqual(
                [row["CHECK_ID"] for row in rows],
                ["check-1", "check-3"],
            )

    def test_ignores_newer_csv_without_status_column(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source_dir = root / "prowler"
            source_dir.mkdir()
            good = source_dir / "scan.csv"
            bad = source_dir / "compliance.csv"

            good.write_text("STATUS,CHECK_ID\nFAIL,check-1\n", encoding="utf-8")
            bad.write_text("FRAMEWORK,REQUIREMENT\nCIS,1.1\n", encoding="utf-8")

            # Ensure the compliance file is newest; parser should still find the scan CSV.
            import os
            os.utime(good, (100, 100))
            os.utime(bad, (200, 200))

            output = root / "fail.csv"
            self.assertEqual(export_failures(source_dir, output), 1)


if __name__ == "__main__":
    unittest.main()
