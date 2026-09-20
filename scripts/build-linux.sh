#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
"$ROOT/.venv/bin/python" -m PyInstaller --noconfirm --clean --onedir --name cvebeacon --distpath "$ROOT/dist/onedir" --workpath "$ROOT/build/onedir" --specpath "$ROOT/build" --paths "$ROOT/src" "$ROOT/scripts/cvebeacon_entry.py"
"$ROOT/dist/onedir/cvebeacon/cvebeacon" --help
"$ROOT/.venv/bin/python" -m PyInstaller --noconfirm --clean --onefile --name cvebeacon --distpath "$ROOT/dist" --workpath "$ROOT/build/onefile" --specpath "$ROOT/build" --paths "$ROOT/src" "$ROOT/scripts/cvebeacon_entry.py"
"$ROOT/dist/cvebeacon" --help
