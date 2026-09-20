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

Python 3.12 has been exercised on Windows. Python 3.11 syntax compatibility has been checked, but native 3.11 execution and native Linux packaging still require validation before those deployment targets are approved.
