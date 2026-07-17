# AuditBase benchmark packager

This crate creates deterministic, offline, agent-visible benchmark input
packages from evaluator-approved catalogs. It does not select benchmarks,
download repositories, invoke Git, run source code, compile projects, call a
model, or score findings. Catalogs remain evaluator-only; packages contain only
the allowlisted source bytes and `input-manifest.json`.

The packager fails closed when license or contamination review is incomplete,
when cleared material does not permit redistribution, or when a case has high
contamination risk. Internal-evaluation-only material requires an explicit CLI
flag. It rejects path collisions, traversal, Git metadata, reports and truth
artifacts, answer markers, archives, symlinks, hardlinks, special files, byte or
file-count limit violations, and digest mismatches. Reads are bounded and file
hashing is streamed. No packaged content is executed.

Every agent package is blinded. Catalogs with `identityVisible=true` are
rejected, catalog case/project/source identifiers are forbidden in visible
paths, scope, or source bytes, and the catalog case ID is replaced by an
evaluator-issued `run-` plus 32 lowercase hex characters. The package receipt
includes both the source-tree digest and a canonical `manifestSha256` that
binds the opaque run ID, full file inventory, scope instructions, included
paths, and required network policy.

Safe hardlink and permission handling currently requires Unix. Other platforms
return a clear unsupported-platform error rather than weakening checks.

```text
auditbase-benchmark package \
  --catalog evaluator/catalog.json \
  --source prepared/source-tree \
  --output agent-input/opaque-run-id \
  --opaque-run-case-id run-0123456789abcdef0123456789abcdef

auditbase-benchmark verify \
  --catalog evaluator/catalog.json \
  --package agent-input/opaque-run-id \
  --opaque-run-case-id run-0123456789abcdef0123456789abcdef
```

`input-manifest.json` intentionally excludes repository URLs, license review,
contamination review, report locations, and any expected findings. Scoring is
owned by the separate evaluator.
