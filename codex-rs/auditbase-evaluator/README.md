# AuditBase V3 evaluator

This crate is the trusted, deterministic scoring lane for AuditBase V3. It is
not part of the audit agent and must never be copied into an audit guest.
Benchmark ground truth, reviewer identities, adjudication votes, case names,
and scoring artifacts remain evaluator-only. The agent receives source and
scope, never answers or evaluator metadata.

## Frozen primary metric

The primary universe is independently adjudicated, in-scope Critical, High,
and Medium root causes. Severity weights are fixed at `4`, `3`, and `2`.
Matched and missed findings use ground-truth weight; unmatched predictions use
predicted-severity weight.

For each vulnerable run:

```text
weighted F2 = 5*TPw / (5*TPw + 4*FNw + FPw)
```

Scores are exact reduced rationals. Runs are averaged within each project, then
projects receive equal weight in the project-macro result. Clean controls do
not enter F2; they report pass/fail, false-positive weight, and FP/kSLOC.

Unparseable or contract-invalid output scores zero and remains in the
completion denominator. A semantically valid failed-partial result retains
credit for its adjudicated findings, but it still fails completion and every
unreported truth remains a false negative.

## Adjudication boundary

Automation validates hashes and contracts, proposes no authoritative semantic
judgment, enforces one-to-one constraints, and calculates frozen metrics. Two
blinded human reviewers decide semantic identity, duplicates, actionability,
and verification. A disagreement requires an independent third reviewer;
three different decisions require a recorded panel result. There is no LLM
judge in the trusted scoring path.

Multiple reports of one root cause form one duplicate cluster. The earliest
output is its representative. Truth collisions, a noncanonical representative,
pending novel findings, or an unsplit compound finding block scoring rather
than being resolved algorithmically.

Every reviewer vote and final panel decision is bound to both the exact
canonical result SHA-256 and the exact candidate-content SHA-256. A vote cannot
be replayed against a changed result, reordered candidate, or different run.
`matches` and `novel_confirmed` decisions receive credit only when reviewers
also mark the candidate actionable and verified; otherwise scoring fails
closed.

## Run binding and provenance

An arm manifest records `armConfigSha256`, the digest of the static model and
runtime configuration shared by every scheduled run in that arm. Each ingested
run separately records `runProvenanceSha256`, the unique fingerprint of the
actual case, replicate, request, input, and effective runtime. This prevents a
run-specific fingerprint from being incorrectly compared with one static arm
digest across a multi-case evaluation.

The evaluator treats the observed binding values as trusted orchestrator
inputs. Before calling `ingest_result`, the orchestrator must verify the
runner's provenance envelope and artifact binding, then pass both the verified
static arm configuration digest and the verified per-run provenance
fingerprint. This crate validates their shape and manifest consistency; it does
not authenticate or verify the provenance envelope itself.

## Ingest and retry policy

The evaluation manifest freezes the public-contract limits and the maximum
number of attempts. Raw result bytes are capped before parsing; accepted
results must pass both semantic validation and the frozen nested contract
limits. Every observed artifact, including an over-limit artifact, retains its
SHA-256 digest and byte length for an auditable attempt trace.

`EvaluationRun` is created only by the trusted ingestion functions. Its fields
are read-only outside this crate and it is intentionally not deserializable, so
callers cannot construct a scoreable valid run that bypasses ingestion.

Attempts start at zero and must be contiguous. Only a pre-start void attempt
may be retried, and only while the manifest's retry budget remains. The first
non-void attempt is final. Later attempts are rejected instead of allowing an
operator to cherry-pick the best replicate. The selected attempt trace is
hashed into the run score.

## Verification

From `codex-rs`:

```text
cargo test -p codex-auditbase-evaluator
cargo clippy -p codex-auditbase-evaluator --all-targets --no-deps -- -D warnings
bazel test //codex-rs/auditbase-evaluator:auditbase-evaluator-evaluator-test
```

The committed fixtures are synthetic evaluator tests. They are not real audit
targets or production ground truth.
