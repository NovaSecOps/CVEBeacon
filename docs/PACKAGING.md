# Standalone packaging

Install the development dependencies, then build on the target operating system. PyInstaller is not a cross-compiler.

Windows PowerShell:

```console
python -m venv .venv
.venv\Scripts\python.exe -m pip install --upgrade "pip>=26.2"
.venv\Scripts\python.exe -m pip install -e ".[dev]"
powershell -ExecutionPolicy Bypass -File scripts\build-windows.ps1
```

Linux:

```console
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade 'pip>=26.2'
.venv/bin/python -m pip install -e '.[dev]'
sh scripts/build-linux.sh
```

Each script first builds and smoke-tests an easier-to-diagnose one-folder bundle, then builds and smoke-tests the final one-file executable. Outputs are under `dist/`. Build each platform’s artifact on that platform and test it again on a representative clean target before distribution.

Windows outputs are `dist/cvebeacon/cvebeacon.exe` and `dist/cvebeacon.exe`. Linux uses `dist/onedir/cvebeacon/cvebeacon` and `dist/cvebeacon` to avoid a directory/file name collision. The Windows script accepts `-OutputDirectory` and `-WorkDirectory` for isolated builds and stops on build or smoke-test failure.

Native CI exercises CPython 3.11–3.14 on Windows Server 2025 and Ubuntu 24.04. Both package formats are built with Python 3.12 and smoke-tested outside the checkout on each platform. The one-file executable is the recommended portable format; the one-folder bundle is useful for troubleshooting. Workflow artifacts contain both formats and are retained for 14 days. They are validation builds, not formal releases.

Templates and stylesheets are bundled into the same executable. Start the dashboard with `cvebeacon.exe serve` on Windows or `./cvebeacon serve` on Linux; see [dashboard usage](DASHBOARD.md). The package jobs exercise server startup, static assets, manual queries, reports, and preservation of monitoring state.

Linux packages target x86-64 Ubuntu 24.04 and compatible systems. They are not universal static binaries; libc and system library compatibility must be verified on other distributions. Windows validation covers x86-64 Server 2025 runners. Other OS versions and architectures require deployment testing.
