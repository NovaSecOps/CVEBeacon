"""Reject runtime data and local source paths in standalone archives."""

from pathlib import Path
import sys
import types

from PyInstaller.archive.readers import CArchiveReader


def inspect(path: Path) -> None:
    archive = CArchiveReader(str(path))
    count = 0
    for name in archive.toc:
        normalized = name.replace("\\", "/").casefold()
        assert not any(part in normalized.split("/") for part in (".private", ".git", ".venv", "tests")), name
        if normalized != "certifi/cacert.pem":  # Public CA roots required for TLS verification.
            assert not normalized.endswith((".db", ".sqlite", ".toml", ".pem", ".key", ".env")), name
        if archive.toc[name][-1] == "z":
            pyz = archive.open_embedded_archive(name)
            for module in pyz.toc:
                if module.startswith("cvebeacon"):
                    def inspect_code(code):
                        assert not Path(code.co_filename).is_absolute(), code.co_filename
                        assert ".private" not in code.co_filename, code.co_filename
                        for const in code.co_consts:
                            if isinstance(const, types.CodeType):
                                inspect_code(const)
                    inspect_code(pyz.extract(module))
                    count += 1
    assert count >= 10, "application modules missing from package"
    print(f"PASS {path.name}: {count} application modules, no operational data")


if __name__ == "__main__":
    for value in sys.argv[1:]:
        inspect(Path(value))
