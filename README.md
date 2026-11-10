# Ubuntu Security Dashboard

Dashboard web read-only cho đồ án Ubuntu Security Project. Website chạy bằng Flask, đọc trạng thái thật của Ubuntu bằng các lệnh kiểm tra cố định và không thay đổi SSH, UFW, Fail2ban hay tài khoản.

## 1. Cài đặt trên Ubuntu VM

```bash
cd "/home/NguyenHaiLam/Desktop/Đồ Án Linux/Ubuntu_Security_Project"
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
```

Nếu máy chưa có `python3-venv`, cài một lần bằng quyền quản trị:

```bash
sudo apt install python3-venv
```

Không chạy Flask bằng `sudo`. Launcher chỉ yêu cầu xác thực sudo một lần; Flask vẫn chạy bằng tài khoản thường và chỉ dùng `sudo -n` cho các lệnh kiểm tra cố định cần quyền đọc. Nếu xác thực sudo thất bại, giao diện hiển thị `UNKNOWN` thay vì giả tạo kết quả.

## 2. Chạy website

### Nhấn icon trên Desktop Ubuntu

Sau khi cài `.venv` và Flask, chạy một lần, không dùng sudo:

```bash
./web_dashboard/install_desktop_launcher.sh
```

Nhấn chuột phải icon **Ubuntu Security Dashboard** trên Desktop → **Allow Launching / Cho phép khởi chạy**, rồi nhấn đúp icon. Launcher sử dụng `.venv` trong dự án, mở Terminal và yêu cầu trình duyệt mở website. Giữ Terminal mở; `Ctrl+C` để dừng. Nếu browser mở trước khi server sẵn sàng, đợi dòng `Running on` rồi tải lại trang. Nếu port 5000 đang được sử dụng, kiểm tra Terminal đang chạy trước đó; không nhấn mở nhiều lần.

Khi launcher hỏi mật khẩu sudo, nhập một lần để đọc SSH, UFW, Fail2ban và quyền file. Launcher kiểm tra thêm `sudo -n true` trước khi mở website. Website vẫn không chạy bằng root. Nếu quyền sudo chưa sẵn sàng, launcher dừng thay vì mở website với dữ liệu thiếu.

Icon trỏ tới vị trí dự án hiện tại. Nếu di chuyển thư mục dự án, chạy lại script cài icon. Script không cài package, không dùng sudo, không sửa firewall.

Kịch bản trình bày: `docs/13-dashboard-demo.md`.

### Chạy bằng Terminal

```bash
./web_dashboard/run_dashboard.sh
```

Mặc định website chỉ bind vào `127.0.0.1:5000` và tắt debug, phù hợp trình diễn trên chính Ubuntu VM. Truy cập bằng trình duyệt trong Ubuntu:

```text
http://127.0.0.1:5000
```

Để xem từ macOS qua Parallels, chỉ dùng khi đã hiểu rủi ro mạng lab và tự bind vào địa chỉ cần thiết:

```bash
DASHBOARD_HOST=0.0.0.0 DASHBOARD_PORT=5000 ./web_dashboard/run_dashboard.sh
```

Không mở port 5000 trên UFW chỉ để demo nếu không cần. Nếu cần truy cập từ Mac, hãy mở rule tạm thời theo quy trình lab rồi xóa sau khi trình diễn.

## 3. Các trang

- `/`: tổng quan trạng thái SSH, UFW, Fail2ban và permissions.
- `/ssh`: cấu hình hiệu lực OpenSSH và kiểm tra `sshd -t`.
- `/ufw`: chính sách mặc định và rule UFW.
- `/fail2ban`: service, jail, số failed/banned.
- `/permissions`: mode file demo, owner-read và testuser-read.
- `/reports`: lịch sử audit và tải report text.
- `/tests`: 8 testcase đọc từ `tests/test_cases.csv`.

API tương ứng nằm dưới `/api/`. Endpoint `POST /api/audit` chỉ chạy script đã xác định `scripts/security_audit.sh` với thư mục output cố định; không có endpoint nhận shell command.

## 4. Kiểm thử backend

Không cần pytest để chạy bộ test cơ bản:

```bash
python3 -m unittest discover -s tests_web -p 'test_*.py' -v
```

Kiểm tra cú pháp:

```bash
python3 -m py_compile web_dashboard/*.py
bash -n web_dashboard/run_dashboard.sh
```

Nếu đã cài dependency, smoke test Flask:

```bash
python3 -m web_dashboard.app --host 127.0.0.1 --port 5000
curl http://127.0.0.1:5000/api/health
```

## 5. An toàn và giới hạn

- Collector dùng `subprocess.run` với argv list, `shell=False` mặc định và không nhận command từ request.
- Danh sách lệnh được phép nằm trong `SafeCommandRunner.registry`.
- Chỉ audit read-only đã có trong repository được gọi từ giao diện.
- Dashboard không chạy root, không sửa cấu hình, không cài package và không tự động remediation.
- `UNKNOWN` có nghĩa là thiếu quyền, thiếu công cụ hoặc không đọc được dữ liệu; không được diễn giải thành PASS.
- Nội dung `/srv/security-lab/secret.txt` không bao giờ được đọc hoặc gửi ra API.
- Các script terminal gốc trong `scripts/`, `01_scripts/` vẫn chạy độc lập.
