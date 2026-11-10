#!/usr/bin/env bash
set -Eeuo pipefail

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_dir"

fail() {
  printf '\nERROR: %s\n' "$1" >&2
  printf '\nNhan Enter de dong cua so...\n'
  read -r _ || true
  exit 1
}

if [[ "${EUID}" -eq 0 ]]; then
  fail "Khong chay dashboard bang root. Hay dung tai khoan Ubuntu thuong."
fi

if command -v sudo >/dev/null 2>&1; then
  printf 'Xac thuc quyen sudo mot lan de doc SSH/UFW/Fail2ban (Flask van chay user thuong)...\n'
  if ! sudo -v; then
    fail "Khong xac thuc duoc sudo. Hay chay lai launcher va nhap dung mat khau Ubuntu."
  fi
  if ! sudo -n true; then
    fail "Sudo chua san sang cho lenh khong tuong tac. Hay nhap dung mat khau va chay lai launcher."
  fi
fi

if [[ ! -x "$project_dir/.venv/bin/python" ]]; then
  printf 'Chua co moi truong Python. Chay cac lenh sau trong Ubuntu:\n\n'
  printf 'sudo apt install python3.12-venv\n'
  printf 'cd %q\n' "$project_dir"
  printf 'python3 -m venv .venv\n. .venv/bin/activate\npython -m pip install -r requirements.txt\n'
  fail "Thieu .venv/bin/python"
fi

if ! "$project_dir/.venv/bin/python" -c 'import flask' >/dev/null 2>&1; then
  printf 'Chay: %q -m pip install -r %q\n' "$project_dir/.venv/bin/python" "$project_dir/requirements.txt"
  fail "Flask chua duoc cai trong .venv"
fi

host="${DASHBOARD_HOST:-127.0.0.1}"
port="${DASHBOARD_PORT:-5000}"
url="http://127.0.0.1:$port"

printf '\nUbuntu Security Dashboard\n'
printf 'Project: %s\n' "$project_dir"
printf 'Website: %s\n' "$url"
printf 'Giu cua so nay mo khi demo. Nhan Ctrl+C de dung website.\n\n'

(
  sleep 2
  if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$url" >/dev/null 2>&1 || true
  fi
) &

exec "$project_dir/.venv/bin/python" -m web_dashboard.app --host "$host" --port "$port"
