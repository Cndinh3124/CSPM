"""Run Prowler CLI. Prowler itself remains responsible for security checks."""
import os
import shutil
import subprocess
from pathlib import Path


def run_scan(output_dir: Path, aws_region: str = "") -> None:
    """Run an AWS scan and ask Prowler to write CSV findings."""
    prowler = shutil.which("prowler")
    if not prowler:
        raise RuntimeError(
            "Không tìm thấy lệnh 'prowler'. Hãy cài Prowler và kiểm tra PATH."
        )

    output_dir.mkdir(parents=True, exist_ok=True)
    command = [
        prowler,
        "aws",
        "--status", "FAIL",
        "--output-formats", "csv",
        "--output-directory", str(output_dir),
    ]

    # Set a default region for SDK calls. Prowler may evaluate checks across
    # multiple regions according to its own configuration and CLI options.
    env = os.environ.copy()
    if aws_region:
        env["AWS_DEFAULT_REGION"] = aws_region

    print("Đang chạy Prowler. Lệnh:", " ".join(command))
    result = subprocess.run(command, env=env, check=False)

    if result.returncode != 0:
        raise RuntimeError(
            f"Prowler kết thúc với mã {result.returncode}. "
            "Hãy đọc log phía trên; không xem lần quét lỗi là kết quả hợp lệ."
        )
