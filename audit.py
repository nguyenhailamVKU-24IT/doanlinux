"""Create a read-only report from the same collector used by the dashboard."""
import json
from datetime import datetime
from collector import REPORT_DIR, collect_snapshot


def main():
    snapshot = collect_snapshot()
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = REPORT_DIR / f"security_audit_{stamp}.txt"
    # Exclusive creation prevents concurrent requests from replacing evidence.
    try:
        with path.open("x", encoding="utf-8") as handle:
            handle.write(json.dumps(snapshot, ensure_ascii=False, indent=2) + "\n")
    except FileExistsError:
        raise SystemExit("Đã có báo cáo trong giây này; hãy thử lại sau.")
    print(f"Đã tạo {path.name}; kết quả bảo mật: {snapshot['overall']}")


if __name__ == "__main__":
    main()
