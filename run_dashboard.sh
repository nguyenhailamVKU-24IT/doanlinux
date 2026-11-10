#!/usr/bin/env bash
set -Eeuo pipefail

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_dir"

if [[ "${EUID}" -eq 0 ]]; then
  echo "ERROR: không chạy dashboard bằng root; hãy dùng tài khoản Ubuntu thông thường." >&2
  exit 1
fi

if command -v sudo >/dev/null 2>&1; then
  echo "Xác thực sudo một lần để đọc SSH/UFW/Fail2ban (Flask vẫn chạy user thường)..."
  if ! sudo -v; then
    echo "ERROR: không xác thực được sudo. Hãy chạy lại và nhập đúng mật khẩu Ubuntu." >&2
    exit 1
  fi
  if ! sudo -n true; then
    echo "ERROR: sudo chưa sẵn sàng cho lệnh không tương tác. Hãy nhập đúng mật khẩu và chạy lại." >&2
    exit 1
  fi
fi

python_bin=python3
if [[ -x "$project_dir/.venv/bin/python" ]]; then
  python_bin="$project_dir/.venv/bin/python"
fi

if ! "$python_bin" -c 'import flask' >/dev/null 2>&1; then
  echo "ERROR: Flask chưa được cài. Chạy: python3 -m venv .venv && . .venv/bin/activate && python -m pip install -r requirements.txt" >&2
  exit 1
fi

exec "$python_bin" -m web_dashboard.app --host "${DASHBOARD_HOST:-127.0.0.1}" --port "${DASHBOARD_PORT:-5000}"
