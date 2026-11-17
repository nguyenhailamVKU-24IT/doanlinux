"""Flask web dashboard for the Ubuntu Security Project."""
from __future__ import annotations

import argparse
import os
from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_file

try:
    from .collector import SafeCommandRunner, collect_snapshot, list_reports, load_test_cases, report_path
except ImportError:  # Support `python -m app` from the launcher script.
    from collector import SafeCommandRunner, collect_snapshot, list_reports, load_test_cases, report_path

BASE_DIR = Path(__file__).resolve().parent
app = Flask(__name__, template_folder=BASE_DIR / "templates", static_folder=BASE_DIR / "static")
app.config["JSON_SORT_KEYS"] = False


def page_context(page: str, title: str) -> dict:
    return {"active_page": page, "page_title": title}


@app.get("/")
def dashboard():
    return render_template("dashboard.html", **page_context("dashboard", "Tổng quan bảo mật"))


@app.get("/ssh")
def ssh_page():
    return render_template("ssh.html", **page_context("ssh", "SSH Monitor"), description="Theo dõi dịch vụ OpenSSH, xác thực bằng key và các giới hạn đăng nhập hiệu lực.", panel_title="Cấu hình OpenSSH hiệu lực", explainer="SSH là lớp quản trị từ xa. Dashboard kiểm tra service, trạng thái enable, sshd -T và sshd -t; không sửa sshd_config.", demo_hint="Em giải thích PermitRootLogin no, PubkeyAuthentication yes và PasswordAuthentication no.")


@app.get("/ufw")
def ufw_page():
    return render_template("ufw.html", **page_context("ufw", "UFW Firewall Monitor"), description="Kiểm tra firewall Ubuntu và các rule đang được áp dụng.", panel_title="Chính sách và rule UFW", explainer="UFW được đọc bằng ufw status verbose. Chính sách inbound deny và outbound allow giúp giảm bề mặt tấn công.", demo_hint="Em chỉ ra default deny incoming và rule SSH port 22; website không tự mở firewall.")


@app.get("/fail2ban")
def fail2ban_page():
    return render_template("fail2ban.html", **page_context("fail2ban", "Fail2ban Monitor"), description="Theo dõi jail SSH, số lần lỗi và IP đang bị ban.", panel_title="Jail SSH của Fail2ban", explainer="Fail2ban bổ trợ cho SSH bằng cách đọc log và ban IP. Trạng thái banned bằng 0 không phải là lỗi; đó là chưa có ban event.", demo_hint="Em phân biệt service active với bằng chứng ban IP: Currently banned = 0 không phải PASS cho TC05.")


@app.get("/permissions")
def permissions_page():
    return render_template("permissions.html", **page_context("permissions", "Linux File Permissions"), description="Xác minh quyền file demo theo nguyên tắc least privilege.", panel_title="Chính sách truy cập secret.txt", explainer="Collector kiểm tra stat, owner có quyền đọc và testuser không có quyền đọc. Nội dung file luôn được bỏ qua.", demo_hint="Em giải thích mode 600: owner đọc/ghi, group và others không có quyền.")


@app.get("/reports")
def reports_page():
    return render_template("reports.html", **page_context("reports", "Security Audit Reports"))


@app.get("/tests")
def tests_page():
    return render_template("tests.html", **page_context("tests", "Test Cases"))


@app.get("/api/health")
def health():
    return jsonify({"status": "PASS", "service": "ubuntu-security-dashboard"})


@app.get("/api/snapshot")
def snapshot():
    return jsonify(collect_snapshot())


@app.get("/api/ssh")
def ssh_api():
    return jsonify(collect_snapshot()["ssh"])


@app.get("/api/ufw")
def ufw_api():
    return jsonify(collect_snapshot()["ufw"])


@app.get("/api/fail2ban")
def fail2ban_api():
    return jsonify(collect_snapshot()["fail2ban"])


@app.get("/api/permissions")
def permissions_api():
    return jsonify(collect_snapshot()["permissions"])


@app.get("/api/tests")
def tests_api():
    return jsonify({"items": load_test_cases()})


@app.get("/api/reports")
def reports_api():
    return jsonify({"items": list_reports()})


@app.post("/api/audit")
def audit_api():
    result = SafeCommandRunner().run_audit()
    if not result.ok:
        return jsonify({"status": "UNKNOWN", "error": result.stderr or "Audit không chạy được.", "output": result.stdout}), 503
    return jsonify({"status": "PASS", "output": result.stdout, "reports": list_reports()})


@app.get("/api/reports/<name>")
def report_download(name: str):
    path = report_path(name)
    if path is None:
        return jsonify({"error": "Báo cáo không tồn tại hoặc tên không hợp lệ."}), 404
    try:
        return send_file(path, as_attachment=True, download_name=path.name, mimetype="text/plain")
    except PermissionError:
        return jsonify({"error": "Không đủ quyền đọc báo cáo.", "status": "UNKNOWN"}), 403


@app.errorhandler(404)
def not_found(error):
    if request.path.startswith("/api/"):
        return jsonify({"error": "API endpoint không tồn tại."}), 404
    return render_template("404.html", **page_context("", "Không tìm thấy trang")), 404


@app.errorhandler(500)
def server_error(error):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Không thể đọc dữ liệu Ubuntu ở thời điểm này.", "status": "UNKNOWN"}), 500
    return render_template("500.html", **page_context("", "Lỗi máy chủ")), 500


def main() -> None:
    if os.geteuid() == 0:
        raise SystemExit("Không chạy dashboard bằng root; hãy dùng tài khoản Ubuntu thông thường.")
    parser = argparse.ArgumentParser(description="Ubuntu Security Dashboard")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--debug", action="store_true", help="Chỉ dùng khi phát triển cục bộ")
    args = parser.parse_args()
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
