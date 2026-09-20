# Standalone packaging

Install the development dependencies, then build on the target operating system. PyInstaller is not a cross-compiler.

Windows PowerShell:

```console
python -m venv .venv
.venv\Scripts\python.exe -m pip install -e ".[dev]"
powershell -ExecutionPolicy Bypass -File scripts\build-windows.ps1
```

Linux:

```console
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
sh scripts/build-linux.sh
```

Each script first builds and smoke-tests an easier-to-diagnose one-folder bundle, then builds and smoke-tests the final one-file executable. Outputs are under `dist/`. Build each platform’s artifact on that platform and test it again on a representative clean target before distribution.
