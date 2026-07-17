# AuditBase V3

AuditBase V3 is a backend-only, headless audit engine built as a maintainable
fork of OpenAI Codex. The fork supplies Codex's repository navigation, tool
execution, model loop, and non-interactive runtime; AuditBase supplies the
versioned audit contract, orchestration boundary, result validation, isolation
policy, and deterministic evaluation tooling.

V3 is a clean implementation. It does not import the AuditBase V2/Hound audit
engine, prompts, scanners, schemas, persistence, or orchestration.

> **Current safety boundary:** the implemented end-to-end execution lane is for
> explicitly authored, trusted local fixtures only. Production execution of
> untrusted customer uploads is intentionally fail closed until the production
> gates in this document are implemented and independently attested.

The original research record and decision rationale remain in
[AUDITBASE_V3_RESEARCH_PLAN.md](AUDITBASE_V3_RESEARCH_PLAN.md). This README is
the operational source of truth for the implementation.

## What exists

| Component | Location | Responsibility |
| --- | --- | --- |
| Headless agent | `codex-rs/auditbase-agent` | Thin product binary over upstream `codex-exec`; no TUI dependency in the product graph. |
| Public contract | `codex-rs/auditbase-contract` | Strict Rust types, semantic validators, stream/result consistency checks, generated JSON Schemas, and examples. |
| Runner boundary | `codex-rs/auditbase-runner` | Reference-only child protocol, bounded JSONL, workspace verification, Codex launch, result validation, artifact publication, and private provenance. |
| Evaluator | `codex-rs/auditbase-evaluator` | Deterministic, human-adjudicated matching and exact-rational scoring outside the agent trust boundary. |
| Benchmark packager | `codex-rs/auditbase-benchmark` | Offline, blinded, license/contamination-gated source packaging; never runs source or exposes truth to the agent. |
| Website/control plane | Separate `auditbase-github` repository | Auth, upload, private config, PostgreSQL state, Temporal dispatch, outbox, Redis/SSE, and terminal persistence. |
| Temporal worker | `auditbase-github/workers/src/v3` | Reference-only workflow, authenticated control-plane bridge, runner supervision, cancellation, cleanup, and recovery. |

The upstream Codex TUI and other surfaces remain in the fork so upstream merges
stay reviewable. AuditBase does not ship the TUI as its V3 backend. Removing
unrelated upstream source would increase merge risk without improving the
product boundary.

## Architecture

```text
authenticated browser
        |
        | multipart source upload + public V1 contract
        v
Next.js V3 API / control plane
        |-- exact config digest + private tier resolution
        |-- PostgreSQL V3 tables + transactional outbox
        |-- local artifact/workspace storage (trusted-local only)
        |
        +--> outbox publisher --> Redis Stream --> authenticated SSE
        |
        +--> Temporal: AuditV3Workflow (references only)
                    |
                    v
              Python V3 worker host
                    |  auditbase.runner.v1 over bounded JSONL
                    v
              auditbase-v3-runner
                    |-- verifies config, request, workspace and file digests
                    |-- creates disposable private runtime paths
                    |-- launches and reaps the complete Codex process group
                    v
              auditbase-agent / codex-exec
                    |
                    v
              OpenAI model service

trusted scoring lane (never visible to agent):
benchmark packager --> blinded source package --> run --> human adjudication
                                                       --> deterministic evaluator
```

The browser never receives a model identifier or model credential and never
calls Codex or OpenAI directly. Temporal history contains references and small
control metadata, not uploaded source, prompts, findings, model configuration,
credentials, or raw agent output.

## Product scope and contract

The current wire contract uses `auditbase.*.v1` schema identifiers. It accepts
one or many regular source files, including zero-byte files, and preserves their
validated relative paths. File extensions and implementation languages are not
allowlisted. Source-level review continues when a project cannot compile, with
the compilation state and limitations represented explicitly.

The initial scope is intentionally narrow:

- Source-file uploads only; no paste, GitHub, explorer, ZIP, or archive input.
- Backend-owned OpenAI model and reasoning-effort selection by tier.
- Optional user guidance, treated as untrusted data rather than instructions
  that can override the audit policy.
- Canonical states: `queued`, `preparing`, `auditing`, `finalizing`,
  `completed`, and `failed`.
- Structured findings, coverage, compilation evidence, limitations, usage, and
  typed failure details.
- Failed partial results only when a bounded, contract-valid result was actually
  retained. A failure with no valid result does not invent one.

Public objects reject unknown fields. Paths reject absolute paths, traversal,
backslashes, empty components, collisions after normalization, and other
ambiguous forms. File count, upload bytes, request bytes, guidance, events,
logs, diagnostics, evidence, snippets, and results are bounded by the reviewed
backend configuration and semantic validators.

Rust is the canonical public-contract source. Committed schemas live in
`codex-rs/auditbase-contract/schema`, and executable examples live in
`codex-rs/auditbase-contract/examples`. The website consumes a commit- and
hash-locked copy; generated website files are never edited by hand.

## Backend configuration

The single TOML file has this shape:

```toml
schema_version = "auditbase.audit-config.v1"

[tiers.<public-tier-id>]
enabled = true
model = "<reviewed OpenAI model identifier>"
reasoning_effort = "high" # low, medium, or high
audit_timeout_minutes = 480

[runtime]
# concurrency, upload, worker resource, retention, and network limits

[runtime.contract_limits]
# request, guidance, event, result, diagnostic, snippet, and evidence limits
```

Use `codex-rs/auditbase-contract/examples/audit-config.v1.toml` as the
canonical structural example. A deployable copy must live outside browser
bundles and must contain no secret. Every website, outbox, and worker process
loads the same absolute bytes and is configured with their exact lowercase
SHA-256 digest. A missing, disabled, or unknown tier fails clearly; there is no
model fallback.

The tier name is public. The model, reasoning effort, provider details, service
tier, config content, and credentials are private operator data. `thread.started`
proves what Codex was configured to request; it does **not** prove the model
that a remote service actually served. Only a trusted gateway attestation can
establish server-effective provenance.

## Runner and agent behavior

`auditbase-v3-runner` is a zero-argument production boundary. It reads one
bounded `auditbase.runner.v1` request from standard input and writes bounded
normalized JSONL to standard output. Raw prompts, tool calls, command output,
reasoning, and raw Codex JSONL stay private.

Before accepting a result, the trusted-local implementation verifies the
reviewed config digest, request and workspace descriptors, every uploaded file
digest, selected tier, configured Codex runtime, output schema, result
semantics, request/result coverage, and artifact digests. It writes artifacts
atomically into private paths. Successful replay is accepted only after the
cached inputs and provenance bindings are revalidated.

The Codex child is launched with explicit model and reasoning settings,
ephemeral state, strict config, no user config, no project instructions, no
skills, no MCP servers, approval disabled, a controlled workspace, a scrubbed
environment, and an explicit network policy. This narrows prompt-injection and
ambient-configuration risk; it is not a substitute for a separate-kernel
production sandbox.

Timeout, cancellation, pipe failure, and normal completion all trigger process
group cleanup. The Python supervisor and Rust runner exchange a private agent
process-group handoff so the supervisor can reap both layers. Do not weaken or
remove this protocol when changing process launch code.

Trusted-local completion writes
`control/local-run-provenance.v1.json`. It binds the requested and
Codex-configured runtime plus agent, config, request, prompt, output-schema, and
result digests. It is explicitly marked
`trusted_local_only_not_benchmark_or_production` with gateway attestation
`unavailable`; it must remain private and must never be represented as
server-effective provenance.

## Trusted-local test lane

The real local lane exists to exercise the complete Codex path with an authored
synthetic fixture and local subscription authentication. It is not authorized
for customer source, third-party repositories, bounty targets, or any other
untrusted input. Same-user processes and host-readable credentials are outside
its isolation guarantees.

Build the product binaries:

```bash
cd /absolute/path/to/auditbase-v3/codex-rs
cargo build -p codex-auditbase-agent -p codex-auditbase-runner
```

The website repository owns the smoke harness. From that repository:

```bash
AUDITBASE_V3_RUNNER=/absolute/path/to/auditbase-v3/codex-rs/target/debug/auditbase-v3-runner \
AUDITBASE_V3_AGENT_PATH=/absolute/path/to/auditbase-v3/codex-rs/target/debug/auditbase-agent \
AUDITBASE_V3_SMOKE_MODEL=<explicit-supported-openai-model> \
npm run smoke:v3-local
```

`AUDITBASE_V3_SMOKE_AUTH_FILE` may point to a mode-`0600` subscription auth JSON
file; otherwise the harness uses `~/.codex/auth.json`. An optional absolute
`AUDITBASE_V3_SMOKE_ROOT` retains the run under a chosen private directory. The
harness copies auth into a fresh `CODEX_HOME`, audits only the committed
synthetic fixture, validates the result and digest, removes the copied auth and
runtime home, requires at least one material finding in that intentionally
vulnerable fixture, and reports the retained private storage path. This is a
functional sanity check, not an accuracy or recall benchmark.

The standalone runner deliberately returns
`isolation_and_gateway_attestation_required` outside its exact trusted-local
mode. Do not bypass that failure for deployment.

## Build and verification

Run formatting, unit/integration tests, and strict AuditBase-owned lint from
`codex-rs`:

```bash
cargo fmt --all -- --check
cargo test -p codex-auditbase-contract
cargo test -p codex-auditbase-runner --all-features
cargo test -p codex-auditbase-evaluator
cargo test -p codex-auditbase-benchmark
cargo test -p codex-auditbase-agent
cargo test -p codex-core-skills

cargo clippy -p codex-auditbase-contract --all-targets --no-deps -- -D warnings
cargo clippy -p codex-auditbase-runner --all-targets --all-features --no-deps -- -D warnings
cargo clippy -p codex-auditbase-evaluator --all-targets --no-deps -- -D warnings
cargo clippy -p codex-auditbase-benchmark --all-targets --no-deps -- -D warnings
cargo clippy -p codex-auditbase-agent --all-targets --no-deps -- -D warnings

cargo test -p codex-exec --test event_processor_with_json_output
cargo test -p codex-config

cargo tree -p codex-auditbase-agent --edges normal | rg 'codex-tui|ratatui'
```

The final command must produce no matches. Also run the focused upstream
`codex-exec` JSONL tests because the AuditBase adapter depends on that boundary.
When using Bazel on macOS, raise the file-descriptor limit before testing the
AuditBase targets:

```bash
ulimit -n 4096
bazel test --jobs=2 \
  //codex-rs/auditbase-contract/... \
  //codex-rs/auditbase-runner/... \
  //codex-rs/auditbase-evaluator/... \
  //codex-rs/auditbase-benchmark/... \
  //codex-rs/auditbase-agent/...
```

Unit tests and a successful synthetic smoke establish implementation behavior,
not production security or audit accuracy.

## Quality measurement boundary

The audit agent, benchmark source packager, and evaluator are separate trust
domains. `auditbase-benchmark` packages only reviewer-cleared, allowlisted
source into a blinded opaque run directory. It rejects incomplete license or
contamination review, visible case identity, reports/truth artifacts, Git
metadata, archives, traversal, symlinks, hardlinks, special files, answer
markers, unexpected files, and digest/limit mismatches. It never downloads,
compiles, executes, calls a model, or scores the source.

```bash
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

The trusted evaluator uses two blinded human reviewers for semantic matches; a
disagreement requires a third reviewer and unresolved three-way disagreement
requires a recorded panel decision. There is no LLM judge. Critical, High, and
Medium truth items have weights 4, 3, and 2, and the frozen vulnerable-run
metric is exact-rational weighted F2:

```text
5 * TP_weight / (5 * TP_weight + 4 * FN_weight + FP_weight)
```

Runs are averaged within each project, then projects receive equal macro
weight. Clean controls report false-positive behavior separately. Invalid
output scores zero and remains in the completion denominator. This machinery
defines how future evidence is measured; synthetic evaluator fixtures are not
evidence that V3 is accurate.

## Contract export and website synchronization

Regenerate schemas in place and review the diff before committing contract
artifacts:

```bash
cd /absolute/path/to/auditbase-v3/codex-rs
cargo run -p codex-auditbase-contract --bin auditbase-export-schemas -- \
  auditbase-contract/schema
cargo test -p codex-auditbase-contract
```

After the canonical Rust repository is clean and committed, synchronize the
website atomically:

```bash
cd /absolute/path/to/auditbase-github
AUDITBASE_V3_EXPECTED_COMMIT=$(git -C /absolute/path/to/auditbase-v3 rev-parse HEAD) \
  npm run contract:v3:sync -- /absolute/path/to/auditbase-v3
```

The sync script refuses a dirty source repository, copies only the public
schemas and examples, generates TypeScript, rejects private model/config fields,
and writes `src/contracts/auditbase-v3/contract-lock.json` with the exact source
commit and file hashes. Commit the Rust contract first and the website lock
second. Never hand-edit generated schemas or TypeScript.

## Upstream Codex update policy

AuditBase tracks the latest **verified** Codex commit, not an automatically
moving `main` branch.

1. Keep `upstream` fetch-only and fetch it before major work and releases.
2. Start `sync/codex-YYYYMMDD-<short-sha>` from the verified AuditBase branch.
3. Merge the fetched upstream commit on that temporary branch.
4. Review conflicts and the execution boundary: CLI flags, JSONL events,
   configuration loading, model provenance, skills/project instructions, tool
   sandboxing, environment inheritance, and child-process lifecycle.
5. Run the Rust, Bazel, website contract/conformance, worker, and synthetic
   trusted-local gates. Replay malformed, timeout, cancellation, retry, and
   partial-result fixtures.
6. Run the frozen benchmark/evaluator gate when a licensed private corpus is
   available. Do not substitute a public, contamination-prone smoke fixture.
7. Fast-forward the verified AuditBase branch only after every required gate
   passes. Record the upstream SHA, AuditBase SHA, config/arm digest, runtime
   image, and results.

A large upstream change is a reason for deeper review, not a reason to pin V3
forever or to merge without verification. AuditBase-owned changes should remain
at narrow boundaries so future merges stay tractable.

## Production fail-closed gates

Opening V3 to hostile customer uploads requires all of the following; labels or
environment acknowledgements alone do not satisfy them:

- One disposable, separate-kernel microVM per audit and verified teardown.
- Host-enforced public-only egress, including internal/metadata blocking,
  redirect and DNS-rebinding defenses, and no cross-audit network path.
- A keyless, job-scoped OpenAI gateway with quota enforcement and signed
  server-effective model/runtime attestation. Model credentials must never enter
  the guest.
- Object-store workspace and artifact transport with streaming size limits,
  immutable references, digest verification, and guest/host manifest agreement.
- No database, Redis, Temporal, website worker token, cloud, or other customer
  credential in the audit guest.
- Deployed PostgreSQL terminal/outbox atomicity, idempotent Redis publication,
  cancellation reconciliation, retention workers, backup/restore, and operator
  alerts verified under failure injection.
- A deliberate billing/credit policy integrated atomically with audit creation
  and terminal handling. The trusted-local lane currently performs no charge.
- Load, abuse, dependency, secret-leak, prompt-injection, and isolation testing,
  followed by a limited shadow/canary rollout with rollback.
- A licensed, private, blinded and rotating holdout corpus with human
  adjudication before making any quality claim.

Until these gates pass, the website public routes and worker remain restricted
to explicit loopback synthetic testing and the runner remains fail closed for
production mode.

## Honest non-claims

- V3 is not production ready for untrusted uploads.
- The trusted-local lane is not a sandbox for hostile code.
- V3 has not been shown to be the best auditor in the market, or to exceed any
  competitor's precision, recall, severity accuracy, or weighted F2.
- Public/synthetic fixtures test plumbing and can be present in model training
  data; they are not independent accuracy evidence.
- Language-agnostic ingestion means the agent can inspect arbitrary source
  text. It does not promise that every compiler, build system, or chain-specific
  verifier is installed.
- Configured model provenance is not server-effective provenance.
- The current product scope is OpenAI only; Anthropic support is not part of
  this implementation.
- Lifecycle/progress can be delivered in real time, but the current real runner
  does not publish findings incrementally while the model is still auditing.

These boundaries are deliberate. They let the team finish and verify one
coherent foundation without representing unfinished infrastructure or
unmeasured audit quality as complete.
