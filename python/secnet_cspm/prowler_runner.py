
"""Run Prowler CLI with an explicit AWS profile and region."""
import os
import shutil
import subprocess
from pathlib import Path


def run_scan(
    output_dir: Path,
    aws_region: str = "ap-southeast-1",
    aws_profile: str = "secnet-cspm",
) -> None:
    """Run a scoped AWS scan and export FAIL findings to CSV."""
    prowler = shutil.which("prowler")
    if not prowler:
        raise RuntimeError(
            "Không tìm thấy lệnh 'prowler'. Hãy kiểm tra môi trường và PATH."
        )

    if not aws_profile:
        raise ValueError("AWS profile không được để trống.")

    if not aws_region:
        raise ValueError("AWS region không được để trống.")

    output_dir.mkdir(parents=True, exist_ok=True)

    command = [
        prowler,
        "aws",
        "--profile", aws_profile,
        "--region", aws_region,
        "--status", "FAIL",
        "--output-formats", "csv",
        "--output-directory", str(output_dir),
        "--no-banner",
    ]

    env = os.environ.copy()
    env["AWS_PROFILE"] = aws_profile
    env["AWS_DEFAULT_REGION"] = aws_region

    print(f"AWS profile: {aws_profile}")
    print(f"AWS region: {aws_region}")
    print("Đang chạy Prowler:", " ".join(command))

    result = subprocess.run(command, env=env, check=False)

    if result.returncode == 0:
        print("Prowler hoàn tất.")
    elif result.returncode == 3:
        print(
            "Prowler hoàn tất và có finding FAIL. "
            "Tiếp tục xử lý báo cáo."
        )
    else:
        raise RuntimeError(
            f"Prowler gặp lỗi thực thi với mã {result.returncode}. "
            "Không tiếp tục pipeline."
        )
