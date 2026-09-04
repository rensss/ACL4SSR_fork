# Current State

- Objective: publish Quantumult X remote rules generated from `Clash/own`.
- Source of truth: `Clash/own/**/*.yaml`.
- Generated output: `QuantumultX/own/**/*.list`, `filter_remote.conf`, and `diagnostics.json`.
- Active branch: `master`.
- Status: implementation merged and repository-wide generation verified; remote push is pending.

## Verification Record

```bash
python3 -m unittest discover -s tests -v
python3 scripts/clash_own_to_qx.py
git diff --check
```
