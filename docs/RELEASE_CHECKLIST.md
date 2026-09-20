# Release checklist

- Confirm distributions include the Apache-2.0 `LICENSE` and project attribution `NOTICE`.
- Run the deterministic test suite on every supported Python version.
- Build and smoke-test the standalone executable separately on Windows and Linux.
- Review dependency versions and vulnerability advisories.
- Confirm the source and network documentation against current endpoints.
- Scan the public tree for secrets, private inventories, machine-specific paths, and generated state.
