$ErrorActionPreference = "Stop"
$Python = Join-Path $PSScriptRoot "..\.venv\Scripts\python.exe"
& $Python -m PyInstaller --noconfirm --clean --onedir --name cvebeacon --paths (Join-Path $PSScriptRoot "..\src") (Join-Path $PSScriptRoot "cvebeacon_entry.py")
& (Join-Path $PSScriptRoot "..\dist\cvebeacon\cvebeacon.exe") --help
& $Python -m PyInstaller --noconfirm --clean --onefile --name cvebeacon --paths (Join-Path $PSScriptRoot "..\src") (Join-Path $PSScriptRoot "cvebeacon_entry.py")
& (Join-Path $PSScriptRoot "..\dist\cvebeacon.exe") --help
