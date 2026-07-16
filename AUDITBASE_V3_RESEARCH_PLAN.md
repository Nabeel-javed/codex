# AuditBase V3: Research, Architecture, and Execution Plan

Status: research decision record

Date: 2026-07-16

Product-code changes in this phase: none

This document records the evidence-backed direction for AuditBase V3 before
implementation continues. It is intentionally blunt about what exists, what is
only specified, what must be measured, and what would block a production
release.

## Executive decision

AuditBase V3 will remain a small, maintainable fork of Codex. It will use the
existing AuditBase website as the control plane, but it will not reuse the V2
audit engine or V2 worker logic.

The first production integration surface will be one short-lived
`auditbase-agent` process per audit, using Codex non-interactive execution:

- JSONL events for internal progress and supervision.
- A final JSON Schema response for `AuditResult`.
- Rust semantic validation before any result becomes authoritative.
- A stable AuditBase event adapter between raw Codex events and the website.

App-server, the TypeScript/Python SDKs, and direct `codex-core` embedding are not
the initial integration surface. They add state, coupling, or version skew that
AuditBase does not currently need. This decision can be revisited only if the
product later requires in-flight user steering, durable multi-turn resume,
interactive approvals, or thread branching.

## Honest current state

The V3 foundation is credible, but V3 is not yet a smart-contract auditor.

Confirmed by repository inspection:

- Branch: `auditbase-v3`.
- Inspected product-code HEAD before this documentation commit:
  `b12e2448b053c1325794a52b94eb420f627d70b8`.
- The working tree was clean before this research document was created.
- `auditbase-agent` is a real headless Rust binary that delegates to
  `codex_exec::run_main` and does not directly import the TUI.
- `codex-auditbase-contract` contains the versioned schemas, Rust types,
  examples, exporter, and focused invariant tests.
- The V3 work does not import the AuditBase V2 audit engine.
- Only the official Codex upstream fetch remote is configured. No user-owned
  GitHub push remote is currently configured.
- The latest fetched `upstream/main` on 2026-07-16 is
  `315195492c80fdade38e917c18f9584efd599304`. After this documentation-only
  commit, the AuditBase branch has 11 local commits not in upstream and is 106
  upstream commits behind. Those
  commits were inspected as drift, not merged into the verified branch.

The canonical README also retains the 2026-07-14 synchronization evidence. It
is historical evidence; the separate fresh 2026-07-16 verification is recorded
below.

Not implemented yet:

- Smart-contract-specific audit behavior.
- A quality benchmark or measured accuracy advantage.
- Consumption of `AuditRequest` by `auditbase-agent`.
- Emission of `AuditEvent` and `AuditResult` by the agent.
- Upload staging and preserved-path workspace materialization.
- Compilation/dependency orchestration.
- Finding verification and proof execution.
- The Codex JSONL-to-AuditBase event adapter.
- Disposable isolated production workers.
- A production model gateway and job-scoped credentials.
- Temporal, Redis, PostgreSQL, SSE, and website V3 integration.
- Release images, cancellation recovery, and production deployment.

No accuracy claim is permitted until the benchmark gates in this document pass.

## Fresh foundation verification on 2026-07-16

This research pass performed a new serial verification without changing product
code:

- `cargo build -p codex-auditbase-agent`: passed from a refreshed dependency
  cache in 5m39s.
- `auditbase-agent --version`: `auditbase-agent 0.0.0`.
- `just test -p codex-auditbase-agent`: 1/1 passed.
- `just test -p codex-auditbase-contract`: 8/8 passed.
- `just test -p codex-exec`: 129/129 passed.
- `bazel test
  //codex-rs/auditbase-contract:auditbase-contract-contract_examples-test`:
  passed. An initial command from the wrong Bazel package root failed before the
  correct repository-root target was used; this was an invocation error, not a
  test failure.
- `cargo fmt --all -- --check`: passed. Stable Rust emitted only the existing
  warnings about the nightly-only `imports_granularity` setting.
- The agent's dependency tree contains no `codex-tui` or `ratatui` package.
- Strict Clippy with dependency linting found one upstream warning in
  `core-plugins/src/manifest.rs` (`large_enum_variant`). AuditBase did not modify
  upstream code to hide it. Strict Clippy with `--no-deps` then passed both
  AuditBase crates.
- The debug binary is an arm64 Mach-O with SHA-256
  `9b2ef423acfeb18e1f802b7bcac5a4f64fbe3ddfb18f5db135c2c5b50232d121`.

The live, read-only subscription test used `--ephemeral`,
`--ignore-user-config`, `--ignore-rules`, `--sandbox read-only`, and
`project_doc_max_bytes=0`. An explicit `gpt-5.6` attempt failed closed with HTTP
400 because that API-candidate model is not supported by Codex through the
developer's ChatGPT account. Retrying with Codex's subscription-supported
default succeeded in the final refreshed thread
`019f6ce8-bbfe-7a42-9f7d-329418dbcfdc` and returned:

```text
AUDITBASE_V3_HEALTH_OK head=b12e2448 upstream_verified=b24aa20107 current_upstream=315195492 runtime=codex-exec
```

The successful turn reported 32,321 input tokens, 22,016 cached input tokens,
and 240 output tokens. This proves that the current headless foundation and
repository tools work. It does not prove audit quality or production isolation.
The JSONL stream did not expose the exact effective subscription model. This
passes foundation gate G0A below; benchmark-runner provenance gate G0B remains
open until the V3 runner records the effective model rather than inferring it.

## Target architecture

```text
Browser
  |
  | file(s), preserved relative paths, tier, optional guidance
  v
Existing Next.js control plane
  |-- auth / ownership / billing
  |-- POST /api/v3/audits
  |-- PostgreSQL metadata, durable result, and transactional outbox
  |-- binary-safe object storage for source/artifacts
  |-- authenticated SSE endpoint
  |
  v
Temporal V3 workflow (references only; never large source payloads)
  |
  v
Trusted worker/provisioner
  |-- resolves tier -> backend-only model and reasoning effort
  |-- mints revocable, job-scoped model capability
  |-- creates one disposable sandboxed microVM
  v
Per-audit microVM
  |-- read-only /input
  |-- disposable /workspace
  |-- output-only /out
  |-- fresh immutable CODEX_HOME
  |-- auditbase-agent -> Codex exec
  |      |-- JSONL internal event stream
  |      `-- final AuditResult JSON Schema output
  |-- public internet only through controlled egress
  `-- no platform, database, cloud, GitHub, or OpenAI master secrets
         |
         | job-scoped Responses requests only
         v
Trusted AuditBase Model Gateway ----> OpenAI API

JSONL -> V3 adapter -> bounded normalized events -> Redis Stream -> SSE -> Browser
Final output -> Rust validation -> DB result/state/outbox transaction
Outbox publisher -> Redis terminal event -> authenticated SSE -> Browser
```

The terminal order and recovery behavior are mandatory:

```text
validate final or partial AuditResult
-> atomically persist result, terminal state, and an outbox row in PostgreSQL
-> idempotently publish the outbox event to Redis
-> mark the outbox row delivered; reconcile until delivery is confirmed
-> allow the browser to fetch resultUrl
```

PostgreSQL is authoritative. Redis delivery is at least once, so event IDs and
browser reducers must be idempotent. A crash between the database commit and
Redis append cannot erase the terminal notification.

The browser must never see raw Codex events, raw reasoning, model identifiers,
reasoning effort, provider credentials, or unbounded command output.

## Architecture decision record

### ADR-001: Keep the website control plane; replace the execution plane

Keep:

- Next.js website and API framework.
- Authentication, ownership checks, and billing primitives.
- PostgreSQL/Prisma infrastructure.
- Temporal cluster/client/task-queue infrastructure.
- Redis deployment and SSE transport.
- Report-page presentation and export styling.

Replace or substantially adapt:

- Upload protocol and binary staging.
- V3 persistence adapter and state machine.
- Temporal workflow and activities.
- Worker execution environment.
- Redis event envelopes and sequence handling.
- SSE reducer and replay behavior.
- Result/report data mapping.
- Every V2 audit prompt, parser, and audit-engine component.

V3 is a parallel lane beside V2 until shadow and release gates pass. V2 remains
rollback-only and is not a source of V3 auditing logic.

### ADR-002: Use `/api/v3/audits`

The current website already owns an incompatible `/api/v1/audits` route. The V3
product endpoint will therefore be `/api/v3/audits`. Wire-schema identifiers may
still be `auditbase.*.v1`; API generation and schema generation are independent.
This avoids an unsafe atomic cutover and preserves rollback.

### ADR-003: Use one `codex exec`-style process per audit

The process boundary is the lowest-coupling surface that satisfies current
requirements: one job, one initial guidance payload, streaming progress,
cancellation, and one final result. Startup overhead is negligible compared with
multi-minute model work.

Use JSONL and final output schema together. JSONL is operational telemetry, not a
completed report. A job is complete only after a final response deserializes and
passes V3 semantic validation.

### ADR-004: Raw Codex protocol is private upstream input

Raw JSONL is never a public AuditBase API. A versioned adapter translates it into
stable AuditBase events. After every upstream merge, replay fixtures must cover
success, failure, timeout, cancellation, malformed output, unknown event types,
and partial-result recovery.

### ADR-005: Use one fresh microVM per hostile audit job

Production audits run in a Firecracker/Kata-class VM boundary or an equivalent
sandboxed-container runtime with a separate guest kernel. Ordinary Docker
containers are acceptable only for local development. No writable layer,
workspace, cache, `CODEX_HOME`, model session, or guest is reused across jobs.

Codex's own sandbox remains enabled as defense in depth. It is not the only
tenant boundary.

### ADR-006: Keep durable secrets outside the guest

The OpenAI key exists only in a trusted host-side Model Gateway. Prefer no bearer
credential in the guest at all: the provisioner binds the microVM's attested job
identity to one model, one reasoning effort, the Responses endpoint, and explicit
request/token/spend ceilings. Cancellation removes that mapping immediately.

Inside the guest, the trusted launcher/agent control process and repository
commands are separate security principals. Commands run under a separate UID and
network namespace, with a scrubbed environment, hidden `/proc`, no inherited
file descriptors, and no route to the host-side vsock or model channel. The
agent's model transport is non-exportable and marked close-on-exec. Public
command egress follows ADR-007 and cannot address the Model Gateway.

These controls are an intended design, not a proven property of the current
binary. Until adversarial tests show that child processes, debuggers, `/proc`,
sockets, inherited descriptors, and prompt-driven tool calls cannot use the
model channel, the capability boundary remains an open feasibility risk. Even
after that proof, assume a job-scoped capability could be stolen: scope, TTL,
budget, audit logging, and immediate revocation remain mandatory backstops.

### ADR-007: Internet access is public-only and controlled

The approved initial production behavior permits public internet access, but all
traffic passes through a lower-layer egress gateway. Always block loopback,
link-local, private/VPC/cluster ranges, cloud metadata, other workers, control
plane services, Unix sockets, raw sockets, inbound listeners, DNS rebinding, and
redirects to non-public addresses. Codex's network proxy is a second layer, not
the primary boundary.

This decision has an unavoidable consequence: broad public internet
cannot guarantee uploaded-source confidentiality. Malicious code can transmit
the current audit's own source to a public endpoint. AuditBase can protect its
platform and other tenants, but it cannot make that source-exfiltration promise
in public-internet mode.

A future `restricted` mode should use dependency/research allowlists or cached
search for customers who require strong private-code confidentiality. Benchmark
jobs use a stricter policy: no public web access, only the model transport. That
is a benchmark-only anti-leakage exception, not a production-policy change;
production-mode shadow and security tests must exercise the controlled public
egress described above.

### ADR-008: Uploaded repository configuration is data, never authority

Every uploaded file remains visible at its preserved path, but uploaded
`AGENTS.md`, `.codex` configuration, rules, hooks, skills, plugins, MCP setup,
README instructions, code comments, and fetched pages cannot alter trusted
runtime configuration or gain tools.

Runs use a fresh AuditBase-owned `CODEX_HOME`, explicit untrusted project status,
`project_doc_max_bytes=0`, ignored user/project execution rules, no login shells
or profiles, only reviewed AuditBase skills, and no inherited environment except
an explicit allowlist.

Current source inspection established two useful upstream controls:

- `codex-rs/core/src/agents_md.rs` returns before automatic project-instruction
  discovery when `project_doc_max_bytes` is zero.
- `codex-rs/config/src/loader/mod.rs` disables project `.codex` config, hooks,
  and execution-policy layers for untrusted or unknown projects.

That narrows the likely fork patch, but does not close the risk. README files,
comments, build output, fetched pages, and manually read `AGENTS.md` remain
prompt-injection inputs, and upstream base instructions may invite manual nested
instruction discovery. Adversarial tests must cover those paths. If a gap
remains, one narrow, documented, well-tested fork patch is justified.

### ADR-009: Stage bytes outside Temporal history

Uploads are hashed and stored byte-for-byte in binary-safe object storage.
Temporal receives only the audit ID, contract/schema version, opaque workspace
reference, and non-secret tier ID. The worker materializes a case-sensitive Linux
workspace, validates hashes and sizes, and rejects traversal, duplicate,
case-folding-collision, symlink, hardlink, device, FIFO, and archive-bomb tricks.

"File upload only" describes the initial ingestion channel, not an extension
allowlist. Accept every bounded regular file and preserve its bytes and relative
path; do not restrict uploads to `.sol` or text. Binary or unsupported files may
be recorded as unreviewed with an explicit limitation. Special files are not
regular uploads, and archives are not auto-expanded until archive ingestion has
a separately approved contract.

Until browser folder selection is approved, the website's interim capability is
individual or multiple root-level files. The V3 manifest remains nested-path
capable and must preserve any normalized relative path supplied by a future
folder-aware client; it must never invent or flatten a provided path.

### ADR-010: One private backend configuration source

The browser sends a product tier, not a model. The canonical initial file is
`config/auditbase-v3.toml`, validated against a versioned schema. It contains:

- Tier-to-model mapping.
- Reasoning effort.
- Audit/runtime budgets and deadlines.
- Compilation and dependency limits.
- Egress mode and network settings.
- Event/artifact retention.
- Model-gateway quotas.
- Resource ceilings.

Model names and reasoning effort must not appear in browser bundles, public APIs,
SSE, or public reports. Public tier labels/pricing may come from a sanitized
endpoint that contains no execution details.

The backend validates the entire file and every enabled tier at process startup,
including provider/model availability, supported reasoning effort, positive
budgets, and cross-field limits. Any invalid enabled tier fails startup; job
creation for a missing or disabled tier fails clearly and never falls back.
Secrets are references to a secret manager or injected gateway identity, never
values in this file. Initial V3 does not hot-reload configuration: a reviewed
file change receives a content hash/version and rolls out through a restart. The
resolved config version, model snapshot, and reasoning effort are stored in the
private audit record for reproducibility.

For the first production-API quality baseline, test the current flagship OpenAI
API model with the maximum reasoning level it actually supports, pinned by exact
model snapshot when possible. As of this research, OpenAI documents GPT-5.6 as
the current flagship family, but the live test proved that `gpt-5.6` is not
available through the developer's ChatGPT Codex subscription. Local testing may
therefore use Codex's subscription-supported default; production API tiers must
be separately capability-checked and selected by AuditBase's benchmark, not by
marketing names or assumed subscription parity.

### ADR-011: Compilation is useful but nonfatal

Compilers, tests, package lifecycle hooks, `build.rs`, `postinstall`, scripts,
and dependency installers are arbitrary code and run only in the disposable
guest. Failure or missing dependencies produces diagnostics and a limitation;
Codex continues the source audit.

### ADR-012: Crashes preserve evidence but fail the audit

Timeout, cancellation, agent crash, invalid final output, or infrastructure
failure preserves valid findings, usage, coverage, limitations, and bounded
transcripts gathered so far. The overall job becomes `failed`, never silently
`completed`. The UI displays a persistent partial-result warning.

### ADR-013: Upstream compatibility is a release requirement

Keep AuditBase code at boundaries, avoid direct `codex-core` changes, pin Codex
and worker-image commits, and merge upstream in small batches. Every upstream
merge must pass:

- Headless build and unit tests.
- Contract and schema drift tests.
- TUI-dependency boundary check.
- JSONL compatibility fixtures.
- Authenticated smoke test.
- Security/isolation canaries.
- Selected benchmark regression cases.

If the latest upstream fails, production remains on the last verified pinned
release while the merge is repaired. "Latest" is an input to validation, not a
reason to deploy untested code.

### ADR-014: Terminal events use a transactional outbox

The result, terminal audit state, and terminal-event outbox row are committed in
one PostgreSQL transaction. A separate publisher appends a versioned event with
a stable event ID to Redis, then marks the row delivered. It retries safely and
periodically reconciles undelivered rows. SSE consumers deduplicate by event ID
and sequence. Redis is a delivery/cache layer; PostgreSQL remains the terminal
source of truth and the browser can recover status by ordinary authenticated
HTTP even during Redis disruption.

### ADR-015: Language-agnostic architecture, language-gated quality claims

Ingestion, path preservation, Codex execution, findings schemas, events, and
reports remain language-agnostic. AuditBase may accept any bounded regular file.
That does not justify claiming equivalent audit quality for every ecosystem.
Each marketed language/ecosystem must have its own private holdout, toolchain
image, threat-model coverage, and G3/G5 release result. EVM is the first
measurement lane; Move, Solana/Rust, Cairo, and others remain architecturally
supported but quality-unverified until their gates pass.

## Website compatibility findings

The current website has several material V3 gaps:

- Upload UI restricts files to `.sol` and the API flattens paths to basenames.
- Files are converted to text rather than staged as exact bytes.
- The legacy route body and response conflict with the V3 contract.
- Frontend-accessible constants contain model aliases.
- Tier configuration is duplicated across backend/DB and frontend sources.
- Existing statuses, event names, and cancellation semantics differ from V3.
- Current Temporal inputs can carry file content; V3 must use references.
- Current Redis/SSE records do not implement the V3 envelope and sequence rules.
- Current browser progress can be estimated rather than measured.
- Current reports are oriented around confirmed legacy findings and do not fully
  represent suspected findings, multiple locations, limitations, coverage, or
  failed partial results.

The V3 migration must generate TypeScript types and validators from the canonical
schemas. Do not hand-maintain a second browser contract.

## Contract hardening required before website integration

The current contract is strong enough to guide research but needs decisions and
tests for these cross-object invariants:

- A failed/partial compile must require a corresponding limitation.
- Timestamps must be RFC 3339 and chronologically valid.
- Finding and coverage paths must map to the submitted manifest.
- Guidance, diagnostics, snippets, logs, evidence, and total result sizes need
  configurable bounds.
- Failed snapshots must agree with `partialResultsAvailable`, `resultAvailable`,
  and the eventual partial result.
- Path uniqueness must reject case-folding collisions.
- Informational review status and severity combinations need explicit rules.
- Full streams must enforce legal lifecycle transitions, monotonic unique
  sequence numbers, stable finding IDs, idempotent updates, and exactly one
  terminal state.

## Benchmark strategy

No public corpus can prove that AuditBase is best in market. Public source and
reports may be training data, and an internet-enabled agent can retrieve answers.
Use three separated layers:

1. Public reproducibility and external comparison.
2. Recent temporal generalization.
3. A private rotating holdout for product and market claims.

EVMbench is an external baseline, not the sole or primary product benchmark.
Its detect mode is valuable and standardized, but public contamination and
ground-truth incompleteness prevent it from measuring honest precision by itself.

### Safety prerequisite S0: no hostile benchmark execution on the developer host

Offline evaluator fixtures may be built first, but no agent may inspect or run a
real benchmark repository until a minimum disposable benchmark lane exists. It
must use a fresh separate-kernel guest, no host or durable credentials, the
job-scoped model transport from ADR-006, no public web, bounded CPU/memory/disk/
processes/output/time, and guaranteed teardown. Repository commands, compilers,
and package scripts run only there. A prompt saying "do not execute code" or a
read-only host sandbox is not an isolation boundary.

### Phase B0: Harness validation

- Kelp DAO rsETH, pinned at
  `f751d7594051c0766c7ecd1e68daeb0661e43ee3`.
- Five unique judged High/Medium issues provide a small smoke target.
- Remove report-like files, bot output, known issues, chat exports, Git history,
  remotes, and benchmark names from the agent package.
- Use only to validate packaging, paths, invocation, events, final parsing, and
  scoring. Do not publish it as an accuracy claim.
- Kelp's pinned Code4rena repository has no top-level license file, although
  inspected Solidity files carry GPL-3.0-or-later SPDX identifiers. Legal/license
  clearance and required notices are mandatory before copying it into the
  harness.

### Phase B1: Raw Codex parity

Run three paired arms from the same pinned Codex source, worker image, model
snapshot, reasoning effort, tool versions, network, time, and token budgets:

1. Raw `codex exec` behavior built from that pinned source and image.
2. `auditbase-agent` with no audit skill.
3. `auditbase-agent` with the candidate audit workflow/skill.

For arms 1 and 2, prompt and skills are identical; the wrapper is the only
treatment. They should be statistically equivalent. Any material difference
indicates wrapper/configuration drift. Arm 3 differs only by the single declared
candidate workflow/skill treatment, including any prompt it deliberately adds.
It must earn that change through measured quality.

### Phase B2: Public comparable baseline

- Five to ten stratified EVMbench Detect projects first.
- Full Detect suite only after the harness is stable.
- Report the exact pinned task count because published revisions use different
  counts.
- Use EVMbench Patch/Exploit later to validate evidence and proof ability, not as
  the only discovery metric.

### Phase B3: Precision-aware real projects

- Use ScaBench's one-to-one matching approach on five stratified projects, but
  human-review every unmatched AuditBase finding before assigning false-positive
  status.
- Add fixed/patched variants and independently reviewed clean controls.
- Never assume "not in the historical report" means false.

### Phase B4: Coverage stress

- Blackhole pinned at
  `92fff849d3b266e609e6d63478c4164d9f608e91`.
- Approximately 116 contracts, 10,108 in-scope SLOC, and 24 unique judged
  High/Medium issues.
- Honor contest scope, known issues, and the sponsor's delta; whole-repository
  recall without these exclusions is misleading.

### Phase B5: Temporal generalization

- Use ReEVMBench incidents only when an incident truly postdates the exact model
  snapshot's relevant cutoff/release.
- Continuously add newly closed contests and incidents.
- Treat the claimed contamination status as model-specific, never permanent.

### Phase B6: Private rotating holdout

- Use private historical audits, newly commissioned vulnerable/fixed pairs, and
  internally discovered misses.
- Keep source identifiers opaque and ground truth outside the agent environment.
- Rotate cases after any tuning exposure.
- Establish Solidity/EVM first, then independent Move, Solana/Rust, Cairo, and
  other language/ecosystem lanes. Public EVM-only scores cannot validate a
  cross-language quality claim, and no language is marketed as quality-verified
  until its own blinded gate passes.

### Benchmark controls

- The agent receives source and explicit scope only.
- Ground truth is in an evaluator-only environment.
- No Git metadata, reports, remediation diffs, audit names, category labels, or
  answer-bearing comments.
- Opaque case IDs and paths.
- Benchmark jobs cannot access the public web; only model transport is allowed.
  This is an anti-contamination exception. Separate production-mode shadow tests
  exercise controlled public egress.
- Pin and hash source, Codex commit, model snapshot, prompt, skill bundle,
  reasoning effort, toolchain, image, time budget, and network policy.
- Minimum three independent runs per candidate configuration; use more runs for
  final release decisions.
- Match by vulnerability identity: root cause, affected behavior/path, and
  impact. Wording or exact line equality is insufficient.
- Deduplicate multiple reports of the same root cause before scoring.
- Two human reviewers independently adjudicate all unmatched and disputed
  findings; a third reviewer resolves disagreement.
- Report every case, seed/run, failure, and excluded item. Never silently drop
  timeouts or invalid outputs.

### Scoring specification v0

Freeze this specification, case inventory, and thresholds before looking at a
candidate workflow's holdout result:

- The primary universe is independently adjudicated Critical/High/Medium root
  causes in scope. Low and informational results are reported separately.
- Matching is one to one. A match requires the same root cause, affected
  behavior/control-flow path, and material impact. A location within the same
  affected function or directly coupled state transition is acceptable; merely
  sharing a vulnerability label is not.
- A true positive is one eligible AuditBase finding matched to one truth item. A
  false negative is an unmatched truth item. A false positive is an unmatched,
  non-duplicate predicted Medium-or-higher finding after human adjudication.
  Newly discovered real bugs are added to corrected ground truth, not punished
  as false positives.
- Primary severity weights are Critical=4, High=3, Medium=2. Matched and missed
  items use ground-truth weight; unmatched predictions use predicted-severity
  weight. Under-classified Low findings do not receive primary true-positive
  credit. Exact and within-one-band severity accuracy are separate metrics.
- The pre-registered primary metric is the project-macro average of
  severity-weighted F2, which favors recall while retaining a precision penalty.
  Weighted precision/recall/F1, micro aggregates, and per-severity recall remain
  mandatory secondary results. Macro averaging prevents one large repository
  from dominating the release decision.
- `actionable` means two reviewers agree that the finding gives a specific
  affected location/path, root cause, impact path, and usable remediation or
  verification direction. `verified` additionally requires reproducible dynamic
  evidence or a deterministic source/state proof appropriate to the bug.
- An unparseable or schema-invalid run receives zero for the primary project
  score and remains in the completion-rate denominator. A timeout/crash with a
  semantically valid declared partial result may have those partial findings
  scored, but still fails the completion guard and all unreported truths remain
  false negatives. No run is silently retried away.
- Confidence calibration uses adjudicated predictions grouped by declared
  high/medium/low confidence; monotonic precision and calibration error are
  reported. Confidence does not change TP/FP identity.
- Two reviewers label independently, blinded to arm, and a third breaks ties.
  Store match decisions and rationales as versioned evaluation artifacts.

### Metrics

Primary quality metrics:

- Finding-level precision, recall, and F1.
- High/Critical recall and High/Medium recall.
- Severity-weighted recall and precision.
- Verified-finding precision.
- False positives per kSLOC.
- Exact-severity and within-one-band severity accuracy.
- Evidence validity and reproducible-proof rate.
- Root-cause and source-location correctness.

Operational guardrails:

- Valid completion rate and infrastructure-failure rate.
- Coverage of submitted files and security-relevant entry points.
- Wall time, model tokens, API cost, and cost per true positive.
- JSONL/schema/contract error rates.
- Cancellation latency and partial-result preservation.

Confidence is calibrated separately. High-confidence findings must have higher
empirical precision than medium, and medium higher than low. Coverage and volume
are diagnostics; neither substitutes for finding quality.

## Acceptance gates

These numeric thresholds are provisional research decisions, not claims about
current performance. They must be frozen before the first blinded run, then may
be raised from baseline evidence. They must never be changed retroactively to
turn a revealed failure into a pass.

### Gate G0A: Fresh foundation health

- Clean expected branch and pinned upstream ancestry.
- Headless agent builds and reports its version.
- Agent, `codex-exec`, and contract tests pass serially.
- Contract Bazel target and formatting pass.
- Agent dependency graph contains no TUI/`ratatui` dependency.
- Authenticated read-only smoke test succeeds with recorded requested model or
  default-selection mode, auth mode, config overrides, thread ID, Codex SHA,
  binary checksum, and timestamp.
- No unexpected user config, project rules, hooks, or skills load.

Failure blocks all benchmark conclusions.

The 2026-07-16 evidence passes G0A for the current pinned foundation.

### Gate G0B: Benchmark-runner provenance

Before a real benchmark repository is executed, the minimal V3 runner must:

- Record the effective provider, exact model/snapshot, reasoning effort, auth
  class, Codex SHA, binary checksum, worker-image digest, configuration hash,
  prompt/skill hashes, toolchain versions, budgets, and network policy.
- Fail the job if the requested and effective model/configuration differ or if
  any required provenance field is unavailable.
- Translate pinned raw JSONL fixtures through the versioned adapter, reject
  malformed or unknown terminal behavior, and validate the final V3 schema plus
  semantic invariants.
- Bind provenance to the immutable result and evaluation artifact so paired arms
  cannot silently run different configurations.

G0B is not implemented and is release-blocking for B0/B1.

### Gate G1: Contract and runner correctness

- 100% of harness jobs produce a legal terminal state.
- 100% of completed jobs produce schema-valid and semantically valid results.
- Crash, timeout, and cancellation fixtures preserve valid partial artifacts and
  finish as `failed`.
- Event sequences are monotonic, replay-safe, idempotent, and terminal-result
  ordering is correct.
- Compilation-failure fixtures continue the source audit and record limitations.

### Gate G2: Wrapper parity

- Raw Codex and skill-free `auditbase-agent` use exactly the same effective
  model/configuration and task environment.
- Across paired repeated runs, the wrapper has no material quality regression;
  use paired bootstrap confidence intervals and investigate any absolute
  recall/precision difference above two percentage points.
- Completion, token, and tool behavior differences are explained, not averaged
  away.

### Gate G3: Audit workflow value

On the development and temporal sets, the candidate workflow/skill must:

- Improve severity-weighted recall over raw Codex by at least five absolute
  percentage points, with the paired 95% confidence interval excluding zero.
- Lose no more than two absolute precision points.
- Reduce or preserve false positives per kSLOC.
- Preserve valid-completion rate.
- Demonstrate the improvement on more than one project and more than one bug
  family; one memorized benchmark win is insufficient.

The pre-registered primary test is the paired change in project-macro,
severity-weighted F2. The recall and precision deltas above are simultaneous
guardrails, not substitutes for the primary result.

If no candidate passes, keep raw Codex and redesign the workflow. Complexity is
not accepted without measured value.

### Gate G4: Production security

- No durable platform/OpenAI/cloud secret is present in the guest.
- The trusted agent control process is isolated from repository-command UIDs,
  environments, process inspection, inherited descriptors, and network paths.
- A stolen job capability cannot change model, call other APIs, exceed budget or
  TTL, access another job, or work after cancellation.
- Job A cannot read Job B source, artifacts, logs, caches, or sessions.
- Public HTTPS works while localhost, metadata, private/VPC/cluster ranges,
  Unix sockets, redirects, CNAMEs, DNS rebinding, and control-plane services are
  blocked below the Codex layer.
- Malicious `.codex`, hooks, `AGENTS.md`, skills, plugins, MCP setup, README, and
  dependency scripts cannot change trusted configuration or persist.
- Fork bombs, memory/disk/inode/open-file floods, infinite loops, and log floods
  terminate within configured limits without affecting neighboring jobs.
- Cancellation revokes model access, kills descendants, preserves partial
  results, and destroys the guest.
- Traversal, symlink/hardlink, special-file, archive-bomb, Markdown/XSS, and
  terminal-control payloads are rejected or sanitized.
- Teardown leaves no reusable source, writable cache, session, or credential.

Any failure is release-blocking.

### Gate G5: Shadow reliability and quality

- At least 100 internal/shadow audits with at least 98% valid completion.
- Zero cross-tenant, authorization, platform-credential, model-capability,
  internal-data, or terminal-order violations. This does not claim current-source
  confidentiality while broad public egress is enabled; ADR-007 states that
  residual risk explicitly.
- High-confidence/verified findings achieve at least 90% adjudicated precision.
- Private-holdout High/Critical recall target is at least 70%; High/Medium recall
  target is at least 55%; actionable precision target is at least 75%.
- Results include uncertainty intervals and do not hide invalid runs.
- Every user-visible High/Medium has a valid location, root-cause explanation,
  impact path, and evidence; "verified" requires reproducible evidence where
applicable.
- Each marketed language/ecosystem separately passes its blinded private-holdout
  quality and toolchain gates; an EVM result cannot release another ecosystem.

The absolute quality targets are starting release bars and will be recalibrated
upward after the first blinded baseline. They are not current results.

### Gate G6: "Best in market" claim

AuditBase may make this claim only after a blind, same-model-or-disclosed-model,
same-budget, same-corpus comparison against named alternatives on a private
rotating holdout. AuditBase must be statistically highest on the declared
project-macro severity-weighted F2 metric, win by at least five absolute points,
satisfy all precision and security guardrails, and publish enough methodology
for independent review. The five-point margin is provisional until it is frozen
before the first blinded market comparison.

A public EVMbench score, a cherry-picked project, or one successful audit is not
sufficient.

## Consecutive execution roadmap

No product coding was authorized in this research phase. Once implementation
starts, work should proceed in this order:

1. Reconfirm G0A at the pinned head and retain the 2026-07-16 evidence.
2. Freeze the scoring specification; resolve contract-hardening items and
   regenerate schemas.
3. Build the offline evaluator/fixtures and sanitized package builder, plus the
   minimal V3 runner provenance record, JSONL adapter, bounded accumulator, and
   final schema/semantic validator. Do not execute a benchmark repository yet.
4. Pass G0B and G1 fault/contract fixtures without hostile source execution.
5. Implement the minimum separate-kernel benchmark runner, model gateway,
   untrusted-repository controls, and S0 adversarial safety checks.
6. Package and run B0/B1, then establish wrapper parity.
7. Establish the private rotating holdout and blinded adjudication process before
   tuning the audit workflow.
8. Expand binary staging and the benchmark supervisor into the production
   isolated job supervisor.
9. Implement the transactional outbox, then add the separate `/api/v3/audits`
   persistence and Temporal lane.
10. Upgrade Redis/SSE replay and the V3 report adapter.
11. Run benchmark iteration; keep only changes that pass G3.
12. Add and gate non-EVM language/toolchain lanes individually.
13. Run production isolation tests and production-egress shadow audits, then
    pass G4/G5.
14. Feature-flag V3 for internal users, then a small customer cohort.
15. Cut over only after gates pass; retain a pinned rollback until stability is
    proven.

## Risks that remain explicitly open

1. Public-internet mode can leak the current uploaded source to a public host.
2. The private holdout corpus does not yet exist.
3. V3 quality has not been measured.
4. The current agent and V3 contract are not yet connected.
5. Upstream disables automatic `AGENTS.md` discovery at zero project-doc bytes
   and disables untrusted project config layers, but prompt injection through
   ordinary readable content and manual instruction discovery still need
   adversarial proof.
6. Public benchmark and underlying project licenses require per-case review.
7. A user-owned GitHub push remote for the V3 fork is not configured.
8. `upstream/main` is currently 106 commits ahead; no 2026-07-16 upstream update
   has passed the AuditBase promotion gates.
9. The separate model-channel/command-runner trust boundary in ADR-006 is not yet
   implemented or adversarially proven.
10. Effective model provenance is not emitted by the current JSONL smoke path.
11. The canonical backend config, outbox, and per-language gates are decisions,
    not implementations.

## Definition of the next successful milestone

The next milestone is not "the backend is integrated." It is:

> A freshly verified, pinned headless Codex foundation completes the sanitized
> Kelp harness inside the S0 disposable lane through the V3 result contract; raw
> Codex and skill-free
> `auditbase-agent` are demonstrably equivalent; all artifacts and metrics are
> reproducible; and no report or ground truth is packaged with or tool/network-
> accessible to the agent.

Kelp can still exist in model-training data, so it remains a harness smoke case,
not contamination-free accuracy evidence. Only after that result exists should
smart-contract workflow changes be judged.

## Evidence and source appendix

Accessed 2026-07-16 unless otherwise stated.

### Official Codex and OpenAI sources

- [Codex non-interactive mode](https://learn.chatgpt.com/docs/non-interactive-mode)
  documents JSONL, final-output schemas, API-key authentication, and headless
  execution.
- [Codex app server](https://learn.chatgpt.com/docs/app-server) and
  [Codex SDK](https://learn.chatgpt.com/docs/codex-sdk) were reviewed as future
  alternatives; neither is the initial V3 boundary.
- [Codex approvals and security](https://learn.chatgpt.com/docs/agent-approvals-security)
  documents sandbox/network controls and their intended defense-in-depth role.
- [Latest model guide](https://developers.openai.com/api/docs/guides/latest-model.md)
  identifies GPT-5.6 as the current flagship API family. The local ChatGPT
  subscription failure is separately recorded because API and subscription
  entitlements differ.

### Benchmark sources and licensing status

- [EVMbench paper](https://arxiv.org/abs/2603.04915) and
  [repository](https://github.com/paradigmxyz/evmbench): 117 curated
  vulnerabilities across 40 repositories; harness repository Apache-2.0.
- [ReEVMBench paper](https://arxiv.org/abs/2603.10795) and
  [repository](https://github.com/blocksecteam/ReEVMBench): temporal diagnostic;
  repository Apache-2.0.
- [ScaBench repository](https://github.com/scabench-org/scabench): 31 projects,
  555 findings, 114 High/Critical in its cited dataset; MIT. Underlying contest
  source and report rights still require case-by-case review.
- [Kelp Code4rena repository](https://github.com/code-423n4/2023-11-kelp),
  pinned `f751d7594051c0766c7ecd1e68daeb0661e43ee3`, and
  [final report](https://code4rena.com/reports/2023-11-kelp): no top-level
  license file at the pinned tree; inspected Solidity files use
  GPL-3.0-or-later SPDX identifiers. Obtain legal clearance and preserve all
  applicable notices before packaging.
- [Blackhole contest repository](https://github.com/code-423n4/2025-05-blackhole),
  pinned `92fff849d3b266e609e6d63478c4164d9f608e91`, and
  [final report](https://code4rena.com/reports/2025-05-blackhole): the pinned
  contest repository has no top-level license file. Treat reuse/redistribution
  as uncleared until the sponsor and Code4rena terms are reviewed.

### Isolation and application-security sources

- [Firecracker design](https://github.com/firecracker-microvm/firecracker/blob/main/docs/design.md)
  for the microVM boundary and jailer model.
- [Kubernetes multi-tenancy](https://kubernetes.io/docs/concepts/security/multi-tenancy/)
  for separate-kernel sandboxing guidance in hostile multi-tenant workloads.
- [OWASP SSRF prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
  for blocking internal/metadata destinations, redirects, and DNS-based bypasses.
- [OWASP prompt-injection prevention](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html)
  for treating uploaded instructions and tool output as adversarial data and for
  testing indirect-prompt-injection paths.

### Local source evidence

- V3 HEAD `b12e2448b053c1325794a52b94eb420f627d70b8`:
  `codex-rs/auditbase-agent/Cargo.toml`,
  `codex-rs/auditbase-agent/src/main.rs`,
  `codex-rs/core/src/agents_md.rs`, and
  `codex-rs/config/src/loader/mod.rs`.
- Website inspection HEAD `4833beb81dae51cc46dcd6289a22c4b05f394d55`:
  `src/app/app/new/page.tsx`, `src/app/api/v1/audits/route.ts`,
  `src/lib/services/audit-orchestrator.ts`, `src/lib/config/scan-tiers.ts`,
  `src/app/api/v1/audits/[id]/stream/route.ts`,
  `src/hooks/use-audit-sse.ts`, and `src/app/app/scans/[id]/page.tsx`.
