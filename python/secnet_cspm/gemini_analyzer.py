"""Use Gemini to explain Prowler findings; this module never edits AWS."""
import csv
import json
from pathlib import Path

from google import genai

from .config import setting


def analyze_csv(input_csv: Path, output_md: Path) -> None:
    """Analyze the first N FAIL findings and save a Markdown report."""
    api_key = setting("GEMINI_API_KEY")
    if not api_key:
        print("Chưa cấu hình GEMINI_API_KEY; bỏ qua AI. CSV FAIL vẫn được giữ nguyên.")
        return

    if not input_csv.is_file():
        raise FileNotFoundError(
            f"Không tìm thấy {input_csv}. Hãy chạy bước scan trước."
        )

    with input_csv.open("r", encoding="utf-8-sig", newline="") as file:
        findings = list(csv.DictReader(file))

    output_md.parent.mkdir(parents=True, exist_ok=True)
    if not findings:
        output_md.write_text(
            "# Phân tích CSPM bằng Gemini\n\n"
            "CSV đầu vào không có finding FAIL. Điều này không chứng minh "
            "toàn bộ tài khoản AWS an toàn; hãy kiểm tra log và phạm vi quét.\n",
            encoding="utf-8",
        )
        print(f"Không có finding FAIL. Đã ghi báo cáo: {output_md}")
        return

    try:
        limit = max(1, int(setting("MAX_FINDINGS_FOR_AI", "50")))
    except ValueError as exc:
        raise ValueError("MAX_FINDINGS_FOR_AI phải là số nguyên dương.") from exc

    selected_findings = findings[:limit]
    prompt = f"""
Bạn là trợ lý phân tích Cloud Security Posture Management (CSPM).
Dữ liệu dưới đây là các findings có trạng thái FAIL do Prowler xuất ra.
Không tự tuyên bố đã xác minh cấu hình AWS ngoài dữ liệu được cung cấp.
Nếu thiếu ngữ cảnh, hãy ghi rõ giới hạn và tránh suy đoán thành sự thật.

Với từng finding, hãy trình bày:
1. Check ID/tên kiểm tra và tài nguyên liên quan (nếu có trong dữ liệu).
2. Ý nghĩa của phát hiện và tác động có thể xảy ra.
3. Mức độ ưu tiên đề xuất (Critical/High/Medium/Low) cùng lý do.
4. Các bước khắc phục cụ thể, an toàn; ưu tiên hướng dẫn chính thức của AWS/Prowler.
5. Cách xác minh sau khắc phục bằng cách kiểm tra cấu hình và chạy lại Prowler.

Cuối cùng, đưa ra tóm tắt các nhóm rủi ro và giới hạn của phân tích.
Đây chỉ là khuyến nghị; không thực hiện bất kỳ thay đổi tài nguyên nào.
Findings (JSON, tối đa {limit} dòng):
{json.dumps(selected_findings, ensure_ascii=False, indent=2)}
"""

    client = genai.Client(api_key=api_key)
    try:
        response = client.models.generate_content(
            model=setting("GEMINI_MODEL", "gemini-2.5-flash"),
            contents=prompt,
        )
        report_text = response.text or "Gemini không trả về nội dung văn bản."
    finally:
        client.close()

    output_md.write_text(
        "# Phân tích findings CSPM bằng Gemini\n\n"
        "> Báo cáo do AI tạo để hỗ trợ phân tích. Không phải bằng chứng xác nhận "
        "lỗi đã được khắc phục. Hãy kiểm tra remediation gốc của Prowler và "
        "phê duyệt thủ công trước khi thay đổi AWS.\n\n"
        + report_text
        + "\n",
        encoding="utf-8",
    )
    print(f"Đã ghi báo cáo Gemini: {output_md}")
