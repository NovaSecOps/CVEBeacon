#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
"$ROOT/.venv/bin/python" -m PyInstaller --noconfirm --clean --onedir --name cvebeacon --paths "$ROOT/src" "$ROOT/scripts/cvebeacon_entry.py"
"$ROOT/dist/cvebeacon/cvebeacon" --help
"$ROOT/.venv/bin/python" -m PyInstaller --noconfirm --clean --onefile --name cvebeacon --paths "$ROOT/src" "$ROOT/scripts/cvebeacon_entry.py"
"$ROOT/dist/cvebeacon" --help
