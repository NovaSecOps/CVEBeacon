# CVEBeacon Automation

Optional orchestration, secure snapshot uploads, remote collection, digest-bound
SBOM acquisition, low-trust discovery and additional notification channels.

Install Core, Extensions and this companion from the checkout:

```console
python -m pip install . ./extensions ./automation
cvebeacon-auto --help
```

Core and Extensions remain independent. Automation adds credential-bearing
components only when configured. See [the automation guide](../docs/AUTOMATION.md).
