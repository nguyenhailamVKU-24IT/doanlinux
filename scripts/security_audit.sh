#!/usr/bin/env bash
set -Eeuo pipefail
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_dir"
python_bin="$project_dir/.venv/bin/python"
[[ -x "$python_bin" ]] || python_bin=python3
exec "$python_bin" -m audit
