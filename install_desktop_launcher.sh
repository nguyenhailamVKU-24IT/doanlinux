#!/usr/bin/env bash
set -Eeuo pipefail

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
launcher="$project_dir/web_dashboard/launch_dashboard.sh"
icon="$project_dir/web_dashboard/assets/security-dashboard.svg"

if [[ "${EUID}" -eq 0 ]]; then
  echo 'ERROR: Hay chay bang tai khoan Ubuntu thuong, khong dung sudo.' >&2
  exit 1
fi

if command -v xdg-user-dir >/dev/null 2>&1; then
  desktop_dir=$(xdg-user-dir DESKTOP)
else
  desktop_dir="$HOME/Desktop"
fi
mkdir -p "$desktop_dir"
desktop_file="$desktop_dir/Ubuntu-Security-Dashboard.desktop"

cat > "$desktop_file" <<EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Ubuntu Security Dashboard
Comment=Mo dashboard bao mat Ubuntu va trinh duyet
Exec="$launcher"
Path=$project_dir
Icon=$icon
Terminal=true
Categories=System;Security;
StartupNotify=true
EOF

chmod +x "$launcher" "$desktop_file"
if command -v gio >/dev/null 2>&1; then
  gio set "$desktop_file" metadata::trusted true 2>/dev/null || true
fi
printf 'Da tao icon: %s\n' "$desktop_file"
printf 'Neu Ubuntu hoi: nhan chuot phai icon -> Allow Launching / Cho phep khoi chay.\n'
printf 'Sau do nhan dup icon Ubuntu Security Dashboard.\n'
