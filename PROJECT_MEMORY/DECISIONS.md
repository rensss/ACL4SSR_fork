# Decisions

## 2026-09-04: Rule Source and Publication

- `Clash/own` remains the sole editable rule source.
- The QX remote URL uses GitHub Raw on the `master` branch.
- Generation runs only after relevant pushes to `master`; no scheduled conversion is configured.
- Every source YAML produces a QX `.list`, even when it has no automatic policy binding.

## 2026-09-04: Rule Semantics

- Pure rule sets use manifest-declared `force-policy` values.
- Existing per-rule Clash actions are retained only when the QX policy name is identical and declared by the manifest.
- `no-resolve` is removed with a warning because it has no QX equivalent.
- Unsupported rule types, including `IP-ASN`, are skipped and written to `diagnostics.json`; conversion continues.
