#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${1:-.}"
python3 "$SCRIPT_DIR/bug_report.py" "$TARGET" --open-report --open-html
