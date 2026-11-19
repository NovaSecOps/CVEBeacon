"""Download the binary runtime closure for supported native release targets."""
from pathlib import Path
import subprocess
import sys


def build(directory):
    directory = Path(directory)
    packages = sorted(str(p) for p in directory.glob("cvebeacon*.whl"))
    if len(packages) != 3:
        raise SystemExit("build all three distributions before assembling the wheelhouse")
    for python in ("311", "312", "313", "314"):
        for architecture in ("x86_64", "aarch64"):
            platforms = [f"manylinux_2_{minor}_{architecture}" for minor in range(17, 40)]
            platforms.append(f"manylinux2014_{architecture}")
            arguments = [sys.executable, "-m", "pip", "download", "--only-binary=:all:",
                         "--dest", str(directory), "--python-version", python,
                         "--implementation", "cp", "--abi", "cp" + python]
            for target in platforms:
                arguments.extend(["--platform", target])
            subprocess.run([*arguments, *packages], check=True)


if __name__ == "__main__":
    build(sys.argv[1] if len(sys.argv) > 1 else "dist")
