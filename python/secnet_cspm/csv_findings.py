"""Filter real Prowler CSV output to rows with status FAIL."""
import csv
from pathlib import Path
from typing import Optional

STATUS_COLUMN_NAMES = {
    "status",
    "finding_status",
    "check_status",
}


def find_status_column(headers: list[str]) -> Optional[str]:
    """Find the status column without assuming its capitalization."""
    normalized = {header.strip().lower(): header for header in headers if header}
    for candidate in STATUS_COLUMN_NAMES:
        if candidate in normalized:
            return normalized[candidate]
    return None


def read_headers(path: Path) -> list[str]:
    """Read the CSV header only, returning an empty list for invalid files."""
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as file:
            return next(csv.reader(file), [])
    except (OSError, csv.Error, UnicodeError):
        return []


def export_failures(source_dir: Path, output_csv: Path) -> int:
    """Export FAIL rows from the newest Prowler CSV with a status column."""
    if not source_dir.exists():
        raise FileNotFoundError(f"Thư mục kết quả Prowler không tồn tại: {source_dir}")

    # Ignore the destination if it happens to be inside the scan output tree.
    candidates = [
        path
        for path in source_dir.rglob("*.csv")
        if path.resolve() != output_csv.resolve()
    ]
    candidates.sort(key=lambda path: path.stat().st_mtime, reverse=True)

    source = None
    status_column = None
    headers = None
    for candidate in candidates:
        candidate_headers = read_headers(candidate)
        candidate_status = find_status_column(candidate_headers)
        if candidate_status:
            source = candidate
            status_column = candidate_status
            headers = candidate_headers
            break

    if source is None or status_column is None or headers is None:
        raise FileNotFoundError(
            f"Không tìm thấy CSV Prowler hợp lệ có cột trạng thái trong {source_dir}. "
            "Kiểm tra log quét và định dạng CSV của phiên bản Prowler đang dùng."
        )

    with source.open("r", encoding="utf-8-sig", newline="") as input_file:
        reader = csv.DictReader(input_file)
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
