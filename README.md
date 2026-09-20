# ReleaseGate

ReleaseGate is a GenLayer Intelligent Contract for software release admission. Validators independently fetch release notes, a checksum document, and a security policy, then reach consensus on APPROVED or BLOCKED. The contract stores the decision, reasons, source digests, package, version, owner, and lifecycle status.

## Contract

`contracts/release_gate.py`

## Verification

```text
genvm-lint contracts/release_gate.py
python -m pytest tests -q
```

Deployment: GenLayer Studionet. See `artifacts/deployment.json`.
