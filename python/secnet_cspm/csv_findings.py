"""Filter FAIL rows from the newest Prowler CSV."""
import csv
from pathlib import Path
from typing import Optional

STATUS_COLUMN_NAMES = {
    "status",
    "finding_status",
    "check_status",
}


def detect_dialect(path: Path):
    """Detect common CSV delimiters."""
    with path.open("r", encoding="utf-8-sig", newline="") as file:
        sample = file.read(8192)
    try:
        return csv.Sniffer().sniff(sample, delimiters=",;\t|")
    except csv.Error:
        return csv.excel


def find_status_column(headers: list[str]) -> Optional[str]:
    normalized = {
        header.strip().lower(): header
        for header in headers
        if header
    }
    for candidate in STATUS_COLUMN_NAMES:
        if candidate in normalized:
            return normalized[candidate]
    return None


def read_headers(path: Path) -> list[str]:
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as file:
            dialect = detect_dialect(path)
            return next(csv.reader(file, dialect=dialect), [])
    except (OSError, csv.Error, UnicodeError):
        return []


def export_failures(source_dir: Path, output_csv: Path) -> int:
    """Export FAIL rows from the newest CSV containing a status column."""
    if not source_dir.exists():
        raise FileNotFoundError(
            f"Thư mục kết quả Prowler không tồn tại: {source_dir}"
        )

    output_resolved = output_csv.resolve()
    candidates = sorted(
        (
            path for path in source_dir.rglob("*.csv")
            if path.resolve() != output_resolved
        ),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )

    source = None
    status_column = None
    for candidate in candidates:
        headers = read_headers(candidate)
        status = find_status_column(headers)
        if status:
            source = candidate
            status_column = status
            break

    if source is None or status_column is None:
        raise FileNotFoundError(
            f"Không tìm thấy CSV có cột trạng thái trong {source_dir}. "
            "Hãy kiểm tra đầu ra Prowler."
        )

    dialect = detect_dialect(source)
    with source.open("r", encoding="utf-8-sig", newline="") as input_file:
        reader = csv.DictReader(input_file, dialect=dialect)
        headers = reader.fieldnames or []
        status_column = find_status_column(headers)
        if status_column is None:
            raise ValueError(f"CSV nguồn không có cột STATUS: {source}")

        rows = [
            row for row in reader
            if (row.get(status_column) or "").strip().upper() == "FAIL"
        ]

    output_csv.parent.mkdir(parents=True, exist_ok=True)
    with output_csv.open("w", encoding="utf-8-sig", newline="") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)

    print(f"CSV nguồn: {source}")
    print(f"Đã xuất {len(rows)} finding(s) FAIL: {output_csv}")
    return len(rows)
