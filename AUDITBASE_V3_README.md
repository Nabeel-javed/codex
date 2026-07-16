# AuditBase V3

Canonical status, decisions, and step-by-step delivery plan for the clean-room AuditBase V3 agent.

Last verified: 2026-07-16

Detailed evidence, ADRs, benchmark design, security boundaries, and acceptance
gates: [AuditBase V3 research plan](AUDITBASE_V3_RESEARCH_PLAN.md).

## Mission

Build a backend-only smart-contract auditing product on the open-source Codex runtime. The existing website will eventually submit uploaded source code to this new backend, which will run an isolated audit and return structured findings and a report.

AuditBase V3 will not reuse the AuditBase V2 agent implementation.

## Non-negotiable decisions

- Import no AuditBase V2 agent code, prompts, schemas, scanners, orchestration, persistence, or finalization logic.
- Use the open-source Codex runtime as the agent foundation.
- Ship a headless backend agent. The Codex terminal UI is not part of the product.
- Use OpenAI models only for the initial V3; do not build a multi-provider abstraction yet.
- Use the developer's existing ChatGPT subscription authentication only for local development and testing.
- Use OpenAI API authentication for production website audits.
- Keep production OpenAI API credentials server-side; never expose them to the browser or uploaded-code worker.
- Defer Anthropic and other model providers for at least the next few months.
- Require an explicit backend tier configuration for each audit job. The browser sends only the tier identifier; it never sends or receives the underlying OpenAI model name.
- Treat uploaded repositories as untrusted and execute each audit in an isolated, disposable worker.
- Optimize for audit quality and correctness, not for minimum cost, disk usage, token usage, or development speed.
- Add skills, multi-agent lanes, and verification only after measured evidence shows that they improve the raw Codex baseline.
- Continuously track official Codex updates, but deploy only an explicitly tested and pinned upstream commit.
- Never merge or deploy `upstream/main` directly into production without compatibility gates and a rollback artifact.

## Authentication policy

### Local development and testing

Use the developer's existing ChatGPT subscription authentication. This is the path already proven by the headless smoke test. Do not add API-key configuration merely for local testing.

### Production website

Use OpenAI API authentication owned by the backend. The browser submits only an approved audit tier; the backend-only configuration maps that tier to its OpenAI model and reasoning effort. Only the trusted backend model gateway supplies the API credential. Do not use a developer ChatGPT subscription for production jobs or expose model identifiers to the browser.

No production API key has been configured yet. That work belongs to the future control-plane and model-gateway step.

## Approved V3 product contract decisions

These decisions were confirmed after a read-only inspection of the existing website, API, database, Temporal workflow, Redis event stream, worker lifecycle, and report UI in `/Users/Nabeel/Desktop/auditbase/company/auditbase-github`.

### Existing platform integration

- Keep the existing website authentication, PostgreSQL persistence, credits, Temporal orchestration, Redis Streams, and report UI where they remain suitable.
- Replace the existing audit engine with the V3 `auditbase-agent`; do not copy the V2 audit engine into V3.
- Use authenticated Server-Sent Events (SSE) for one-way real-time audit progress, logs, findings, and completion updates.
- Use ordinary authenticated HTTP endpoints for job creation and future control actions such as cancellation or additional guidance.

### Upload and source policy

- Support file upload as the only initial ingestion channel. Paste, explorer, and GitHub ingestion are deferred.
- Support individual and multiple file uploads.
- Preserve each file's normalized relative path; never flatten an upload to its basename.
- Apply no extension allowlist: accept every bounded regular file byte-for-byte, including binary or unfamiliar formats. Unsupported/unreviewed files must produce an explicit limitation.
- Keep ingestion, execution, schemas, and reporting language-agnostic. Market audit quality for a language/ecosystem only after its own blinded benchmark gate passes; EVM is the first measurement lane.
- Treat uploaded files, filenames, repository instructions, build scripts, and commands as untrusted input.
- The upload contract must carry normalized relative paths. Special files are rejected. Browser folder selection and ZIP/archive expansion remain undecided and must not be implemented without approval.
- Until folder selection is approved, the website supports individual or multiple root-level files. The manifest remains nested-path capable and must preserve any relative path supplied by a future folder-aware client.

### Tier and model policy

- Keep product audit tiers.
- The frontend sends only the selected tier identifier and must contain no real model identifiers or model aliases that disclose the underlying model.
- Each tier has a separate backend-only model and reasoning-effort configuration.
- Use the versioned `config/auditbase-v3.toml` backend configuration with logically separate `tiers` and `runtime` sections. Validate all enabled tiers at startup and fail closed; store the private config hash and effective model provenance per job. Secrets stay outside the file. Initial changes roll out through reviewed restarts, not hot reload.
- A missing, disabled, or invalid tier/model configuration fails job creation with a clear error; the backend must not silently select another model.
- Local ChatGPT subscription testing and production OpenAI API model availability are separate capabilities. The 2026-07-16 test confirmed that an API-candidate model may be unavailable through ChatGPT authentication.

### Execution and failure policy

- The trusted agent and commands executed in the isolated uploaded-code environment may access broad public internet only through controlled egress that blocks internal, metadata, loopback, private, and control-plane destinations.
- Internet access does not grant uploaded code access to the OpenAI API key, database credentials, Redis credentials, cloud credentials, other audits, or host files.
- Broad public egress cannot guarantee confidentiality of the current audit's own source; offer a future restricted-egress mode for that requirement.
- A compilation or dependency-resolution failure is nonfatal when Codex can continue a source-level audit. Record the failure as an explicit limitation and continue.
- If the agent crashes, is cancelled by infrastructure, or exceeds its audit time limit, preserve any findings and events already produced, mark them as partial and incomplete, and mark the overall audit as `failed`.
- A failed audit with partial results must never be presented as a completed audit.

### Findings and reports

- Store a versioned structured JSON result as the system of record.
- Retain findings with explicit review statuses instead of discarding everything except confirmed findings.
- Retain normalized, versioned, bounded AuditBase events, coverage, reviewed files/functions, limitations, compilation status, and incomplete work. Raw Codex JSONL/reasoning remains private and bounded.
- Continue supporting frontend-derived PDF, JSON, Markdown, and HTML report exports.

## Upstream Codex update policy

OpenAI Codex is an actively changing dependency. AuditBase must distinguish between the latest available Codex commit and the latest AuditBase-verified Codex commit.

```text
upstream/main (latest available)
        |
        v
isolated sync branch
        |
        v
compatibility and quality gates
        |
        v
auditbase-v3 (latest verified)
        |
        v
pinned immutable production build
```

Rules:

1. Keep `upstream` fetch-only and never push to the official OpenAI repository.
2. Fetch upstream changes regularly and before every major AuditBase development step or release.
3. Create a temporary branch named `sync/codex-<date>-<short-sha>` from the current verified AuditBase branch.
4. Merge `upstream/main` into the temporary branch. Do not update the verified branch or production directly.
5. Require the following gates before promotion:
   - `auditbase-agent` Cargo build.
   - Relevant package and Codex executor tests.
   - TUI-free product dependency check.
   - Local subscription-authenticated repository-tool smoke test.
   - Audit job schema and website compatibility tests once those interfaces exist.
   - Held-out smart-contract audit benchmark once the safe benchmark lane and private holdout exist.
6. Record the upstream commit, AuditBase commit, model, configuration, worker image, test results, and benchmark results for every promoted version.
7. Promote the sync branch through a reviewed merge only when all available gates pass.
8. Keep the previous immutable production artifact available for immediate rollback.
9. If an upstream change compiles but reduces audit precision, recall, reliability, isolation, or schema compatibility, keep the current verified version and investigate the update separately.

Automation should eventually check `upstream/main` daily and open an update pull request, but it must never deploy an upstream change automatically.

Current upstream comparison, verified on 2026-07-14:

```text
Initial Codex baseline:            c39520f3d1522f2587694b52eba7d3eb39460137
Verified upstream Codex commit:    b24aa20107f365a1d0f06de9e0b28df5c516c7dd
AuditBase synchronization commit:  75b0e690fd562c0d2d5d6407132aa45518185d69
Difference at synchronization:     0 upstream commits
```

AuditBase contains the latest upstream commit available at the time of this synchronization. Future upstream commits must pass the same promotion process.

Current fetched comparison, verified on 2026-07-16:

```text
Verified product-code ancestor:     b12e2448b053c1325794a52b94eb420f627d70b8
Latest fetched upstream/main:       315195492c80fdade38e917c18f9584efd599304
AuditBase-only commits incl. docs:  11
Upstream commits not yet promoted:  106
```

No 2026-07-16 upstream commit was merged. Production and development remain on
the verified AuditBase head until a temporary sync branch passes the full gate
set. The only configured remote is the official fetch-only upstream; its push
URL is disabled and no user-owned GitHub remote exists yet.

## Current status

### Completed: research and architecture decision record

Status: COMPLETE (documentation and verification only; no product code)

The 2026-07-16 research pass inspected the V3 fork and website, refreshed
official Codex/OpenAI guidance, designed the isolation boundary and versioned
backend configuration, selected the `codex exec` JSONL plus final-schema process
boundary, defined a contamination-aware benchmark/scoring protocol, added
transactional-outbox delivery, and reordered the roadmap so hostile benchmark
repositories never execute on the developer host. The full record is in
`AUDITBASE_V3_RESEARCH_PLAN.md`.

### Completed: clean Codex baseline

1. Created a completely separate repository at:

   ```text
   /Users/Nabeel/Desktop/auditbase-v3
   ```

2. Cloned the complete history of the official OpenAI Codex repository.

3. Configured the OpenAI repository as a fetch-only upstream:

   ```text
   upstream fetch: https://github.com/openai/codex.git
   upstream push:  DISABLED
   ```

4. Created the local development branch:

   ```text
   auditbase-v3
   ```

5. Pinned the initial baseline:

   ```text
   commit: c39520f3d1522f2587694b52eba7d3eb39460137
   date:   2026-07-14
   title:  Timestamp app-server notifications at emission (#32905)
   ```

6. Built only the standalone headless executor:

   ```text
   /Users/Nabeel/Desktop/auditbase-v3/codex-rs/target/debug/codex-exec
   ```

   Verified properties:

   - Native Apple Silicon Mach-O executable.
   - Debug smoke-test build.
   - No TUI executable was produced.
   - Git remained clean after the build.

7. Ran a real authenticated, read-only agent smoke test using the compiled fork.

   The agent used repository tools to inspect `codex-rs/exec/Cargo.toml`, found the package and binary declarations, and returned:

   ```text
   AUDITBASE_V3_CODEX_OK package=codex-exec binary=codex-exec
   ```

   Smoke-test thread:

   ```text
   019f5e1e-eb94-7842-a0cf-4d8060c42038
   ```

8. Verified the compiled binary checksum:

   ```text
   SHA-256: e8292eaf73496ed732b404c9c2c5a3115e10875eab07f0c481bd488a38abb1f4
   ```

9. Confirmed that both AuditBase V2 repositories remained untouched.

### Completed: AuditBase headless product binary

Implementation commit:

```text
0c4f0443e6fac12817ffccf6b92a27b4daf91915
```

1. Added a dedicated Rust package and binary:

   ```text
   package: codex-auditbase-agent
   binary:  auditbase-agent
   path:    /Users/Nabeel/Desktop/auditbase-v3/codex-rs/target/debug/auditbase-agent
   ```

2. Kept the new binary as a thin headless product boundary over the upstream `codex-exec` library. The Codex agent loop, repository tools, sandbox, sessions, OpenAI model support, and structured-output behavior remain in the maintained upstream runtime instead of being copied.

3. Verified the product identity:

   ```text
   auditbase-agent 0.0.0
   ```

4. Inspected the complete normal Cargo dependency graph and confirmed that neither `codex-tui` nor `ratatui` is present.

5. Added and ran a focused regression test for forwarding prompts and root configuration overrides into `codex-exec`:

   ```text
   just test -p codex-auditbase-agent
   1 test run: 1 passed, 0 skipped
   ```

6. Ran the required scoped Clippy fix pass and repository formatter successfully:

   ```text
   just fix -p codex-auditbase-agent
   just fmt
   ```

7. Ran a real authenticated, read-only smoke test through `auditbase-agent`. The agent used repository tools to inspect its own package and entry point, then returned exactly:

   ```text
   AUDITBASE_V3_AGENT_OK package=codex-auditbase-agent binary=auditbase-agent runtime=codex-exec
   ```

   Smoke-test thread:

   ```text
   019f5e8c-76bb-71d3-8d40-f1465621a054
   ```

8. Verified the compiled debug binary checksum:

   ```text
   SHA-256: 5f25f26a7db84b9c1fe3b8a5eb25d3ab2910648a3ce1b48cfe8f4fcc524eb98e
   ```

9. Imported no AuditBase V2 code, prompts, schemas, or orchestration.

### Completed: first upstream synchronization rehearsal

Synchronization commit:

```text
75b0e690fd562c0d2d5d6407132aa45518185d69
```

1. Tagged the previous verified AuditBase state for rollback:

   ```text
   tag:    auditbase-v3-step1-verified
   commit: c303fd0b876740d41489a2863690282733cc6db9
   ```

2. Created `sync/codex-20260714-b24aa20107` from the verified AuditBase branch and merged four upstream commits without conflicts.

3. Reviewed the upstream delta: 41 files changed, primarily covering injectable model managers, app-server environment status, and SQLite thread-history projection. No file in `codex-rs/auditbase-agent` changed.

4. Built the synchronized product successfully:

   ```text
   cargo build -p codex-auditbase-agent
   ```

5. Ran the available focused and executor compatibility tests:

   ```text
   just test -p codex-auditbase-agent
   1 test run: 1 passed, 0 skipped

   just test -p codex-exec
   129 tests run: 129 passed, 0 skipped
   ```

6. Verified the product identity and dependency boundary:

   ```text
   auditbase-agent 0.0.0
   TUI_DEPENDENCY_ABSENT
   ```

7. Ran a real subscription-authenticated, read-only repository-tool smoke test. The running agent verified its own package, runtime delegation, and synchronized upstream ancestry, then returned exactly:

   ```text
   AUDITBASE_V3_SYNC_OK upstream=b24aa20107 binary=auditbase-agent runtime=codex-exec
   ```

   Smoke-test thread:

   ```text
   019f5ea5-467f-7cd0-bf09-0dbd68c95852
   ```

8. Ran `just fmt` successfully with no resulting source changes.

9. Promoted the exact tested synchronization commit to `auditbase-v3` with a fast-forward, preserving the tested commit identity.

10. Verified the synchronized debug binary checksum:

    ```text
    SHA-256: 5be46494448c0c6517b780606f0d5a958f6ba216ce00ef62dc804b386524b0cd
    ```

### Completed: versioned V3 audit contract

Implementation commit:

```text
b78549197f0cba8d512ff91da55150146484cfe3
```

1. Added an independent Rust contract package:

   ```text
   package: codex-auditbase-contract
   path:    /Users/Nabeel/Desktop/auditbase-v3/codex-rs/auditbase-contract
   ```

2. Defined seven versioned schemas generated from Rust types:

   - Audit creation request.
   - Accepted-job response.
   - Audit snapshot.
   - API error.
   - SSE audit event.
   - Terminal audit result.
   - Backend-only audit configuration.

3. Defined multipart upload correlation through stable file IDs and normalized relative paths. The contract never relies on multipart ordering or sanitized browser filenames.

4. Defined the canonical lifecycle:

   ```text
   queued -> preparing -> auditing -> finalizing -> completed
      |          |           |            |
      +----------+-----------+------------+-> failed
   ```

5. Defined compilation failure as a recorded limitation that does not stop source-level analysis, and defined agent crash, cancellation, infrastructure failure, invalid output, model unavailability, and audit timeout as terminal failures.

6. Defined partial-result preservation: a failed audit retains available findings, coverage, events, diagnostics, and usage while remaining visibly failed and incomplete.

7. Defined authenticated SSE event envelopes, replay sequence behavior, terminal events, and result retrieval without exposing internal Codex JSONL or backend model identifiers to the browser.

8. Added representative request, response, configuration, event, completed-result, and failed-partial-result examples plus a complete existing-website compatibility map.

9. Added semantic validation for path traversal, duplicate paths and IDs, checksums, lifecycle transitions, finding evidence, coverage counts, severity counts, result/failure invariants, configuration, and public model secrecy.

10. Generated and committed all JSON Schema fixtures, then verified they exactly match the Rust source of truth.

11. Ran the focused Cargo contract suite successfully:

    ```text
    just test -p codex-auditbase-contract
    8 tests run: 8 passed, 0 skipped
    ```

12. Ran the Bazel integration target successfully after declaring the examples and schemas as compile-time test data:

    ```text
    bazel test //codex-rs/auditbase-contract:auditbase-contract-contract_examples-test
    1 test target: passed
    ```

13. Ran the required scoped Clippy fix, repository formatter, Bazel lock update, and Bazel lock verification successfully.

14. Added no smart-contract audit prompt, skill, V2 code, website mutation, worker execution logic, or production credential.

### Important current limitations

- The upstream `codex-exec` runtime implementation remains unmodified; V3 currently adds the isolated `codex-auditbase-agent` wrapper and independent `codex-auditbase-contract` package.
- The upstream TUI source still exists in the fork for mergeability, but the `auditbase-agent` dependency graph does not include it.
- The current `auditbase-agent` binary is a debug build, not a production release build.
- There is no smart-contract-specific audit mode yet.
- The V3 contract and findings/result schemas exist, but the existing website API, Temporal workflow, Redis stream adapter, report page, and `auditbase-agent` do not implement them yet.
- There is no isolated worker image, production model gateway, or website integration yet.
- Production OpenAI API authentication is not configured yet; the current smoke test uses subscription authentication as intended for development and testing.
- No multi-provider abstraction is planned for the initial V3.
- No skills or V2 components have been added.
- The latest fetched Codex upstream is 106 commits ahead. It is deliberately not merged because it has not passed the AuditBase sync and benchmark gates.
- The current fork still has no user-owned GitHub push remote, so commits remain local until that remote is configured intentionally.
- The V3 contract passes both Cargo and Bazel tests. The separate `auditbase-agent` Bazel path still reaches a pre-existing pinned-upstream mismatch: `exec-server/BUILD.bazel` passes `unit_test_args` to a `codex_rust_crate` macro that does not accept it. Cargo remains the verified product-agent build path until that unrelated upstream baseline issue is resolved.
- Audit-quality regression testing is not yet available because the safe benchmark lane and private holdout do not exist. Future upstream promotions must add that gate once they exist.
- Exact effective model identity is not emitted in the current JSONL smoke stream. Production provenance recording remains a release-gate requirement.
- Strict Clippy across all transitive dependencies currently stops on an upstream `large_enum_variant` warning in `core-plugins/src/manifest.rs`; strict `--no-deps` Clippy passes both AuditBase crates.

## Current smoke test

Run from Terminal:

```bash
cd /Users/Nabeel/Desktop/auditbase-v3

./codex-rs/target/debug/auditbase-agent \
  --ephemeral \
  --ignore-user-config \
  --ignore-rules \
  --json \
  --sandbox read-only \
  -c project_doc_max_bytes=0 \
  --cd "$PWD" \
  "Inspect the AuditBase agent package, entry point, current Git HEAD, verified upstream ancestry, and current upstream/main using read-only tools. If they match the recorded values, reply exactly: AUDITBASE_V3_HEALTH_OK head=b12e2448 upstream_verified=b24aa20107 current_upstream=315195492 runtime=codex-exec"
```

The 2026-07-16 run succeeded as thread
`019f6ce8-bbfe-7a42-9f7d-329418dbcfdc` with the exact health result above. It
used Codex's ChatGPT-subscription-supported default model. A preceding explicit
`gpt-5.6` attempt failed clearly because that model was not supported through
ChatGPT authentication; production API models must be validated separately.

This is a headless process. It accepts a task, performs the work, prints JSONL
events and the result, and exits. It does not open a terminal UI.

## Target system

```text
Existing website frontend
        |
        v
Existing authenticated Next.js API
        |-- PostgreSQL audit state, result, and transactional outbox
        |       `-- idempotent publisher --> Redis Streams --> SSE --> website
        |
        `-- Temporal V3 workflow --> trusted provisioner
                                      |
                                      v
                            Fresh separate-kernel microVM
                                      |
                                      v
                       auditbase-agent (headless Codex fork)
                                      |
                                      v
                         Trusted OpenAI API gateway
                                      |
                                      v
                            OpenAI API (production)
                                      |
                                      v
                    Validated findings, events, and report
```

The website control plane must never execute uploaded code. Audit workers must never receive permanent infrastructure credentials or the production OpenAI API key. Local development may use the developer's existing subscription authentication; production must use the backend-owned OpenAI API path shown above. Existing website infrastructure is retained only where it satisfies the V3 contract and isolation requirements.

## Step-by-step roadmap

Only one step should be active at a time. A step is complete only when its acceptance checks pass and the evidence is recorded in this document.

### Step 0: Establish a working Codex baseline

Status: COMPLETE

Evidence: source clone, pinned commit, clean branch, successful headless build, real model connection, repository tool execution, and exact smoke-test result recorded above.

### Step 1: Create the AuditBase headless product binary

Status: COMPLETE

Evidence: implementation commit `0c4f0443e6fac12817ffccf6b92a27b4daf91915`, successful Cargo build, successful version command, TUI-free dependency graph, passing focused package test, successful lint and format passes, and exact real-model smoke-test output recorded above.

Work:

- Create an `auditbase-agent` binary based on the working headless executor.
- Keep the Codex agent loop, repository navigation, tools, sandbox, sessions, OpenAI model support, and structured-output support.
- Remove the TUI and interactive Codex surfaces from the AuditBase product build.
- Keep the untouched upstream history and fetch remote so future Codex changes remain mergeable.
- Preserve the raw Codex behavior before introducing smart-contract instructions.
- Preserve the existing subscription-authentication path for local development and testing.

Acceptance checks:

- `auditbase-agent --version` runs successfully.
- The product dependency graph does not include `codex-tui`.
- The original headless smoke test passes through `auditbase-agent`.
- No AuditBase V2 code is present.
- Relevant tests pass and the Git diff is reviewed before committing.

### Step 1.5: Establish and rehearse upstream synchronization

Status: COMPLETE

Evidence: rollback tag `auditbase-v3-step1-verified`, verified upstream commit `b24aa20107f365a1d0f06de9e0b28df5c516c7dd`, synchronization commit `75b0e690fd562c0d2d5d6407132aa45518185d69`, conflict-free merge, successful Cargo build, 1 passing AuditBase package test, 129 passing `codex-exec` tests, TUI-free dependency graph, exact real-model smoke output, and clean formatting result recorded above.

Work:

- Create an isolated sync branch from the verified AuditBase V3 branch.
- Merge the current four upstream Codex commits into that branch.
- Review upstream changes and conflicts before modifying AuditBase-owned code.
- Build and test `auditbase-agent` through the available compatibility gates.
- Run the real subscription-authenticated repository-tool smoke test.
- Confirm that the TUI remains absent from the product dependency graph.
- Merge the verified sync result into `auditbase-v3` and record both commit identities.
- Define the repeatable commands that future automation will execute.

Acceptance checks:

- The verified AuditBase branch contains the reviewed current upstream commit.
- `auditbase-agent` builds and its focused tests pass.
- The real-model smoke test passes with repository tool execution.
- No AuditBase V2 code is introduced.
- The product dependency graph remains TUI-free.
- The previous verified commit remains available as a rollback point.
- The canonical README records the upstream SHA, resulting AuditBase SHA, commands, tests, and limitations.

### Step 2: Define the first smart-contract audit contract

Status: COMPLETE

Evidence: implementation commit `b78549197f0cba8d512ff91da55150146484cfe3`, seven generated schemas, eight validated examples/event sequences, 8 passing Cargo tests, one passing Bazel integration target, clean scoped Clippy, clean formatting, and successful Bazel lock verification recorded above.

Define new V3 inputs and outputs without copying V2 schemas.

Initial input:

- Versioned audit request.
- Selected tier identifier; no browser-supplied model.
- One or more uploaded regular files with normalized, preserved relative paths and byte hashes.
- Optional user focus/guidance treated as untrusted audit context.
- Backend-resolved tier, model, reasoning effort, and runtime configuration.

Initial output:

- Versioned structured findings JSON as the system of record.
- Human-readable report.
- Files and functions reviewed.
- Finding review status and evidence.
- Compilation/dependency status, limitations, partial-result status, and unfinished coverage.
- Normalized, versioned, bounded AuditBase execution events and usage. Raw Codex JSONL and reasoning remain private.

Contract behavior:

- Compilation or dependency failure does not stop source-level analysis when Codex can continue.
- Agent crash or time-limit failure preserves partial artifacts but leaves the overall audit failed.
- The API and SSE event schema must use one canonical lifecycle vocabulary; website adapters must not invent competing statuses.
- Uploaded files preserve relative paths. Browser folder selection and archive/ZIP support remain explicitly undecided.

### Step 3: Create the safe benchmark lane and evaluator

Status: NEXT -- NOT STARTED

- Freeze the scoring specification and build offline evaluator fixtures first.
- Build sanitized, hashed benchmark packages without exposing ground truth to the agent.
- Implement immutable effective-model/config provenance, the JSONL-to-V3 adapter, bounded result accumulator, and final schema/semantic validator; pass their failure fixtures before a real repository runs.
- Before any real benchmark source reaches the agent, provide one fresh separate-kernel guest per run, no host or permanent credentials, job-scoped model transport, no public web, bounded resources/output/time, and guaranteed teardown.
- Prove that repository commands cannot access the model channel, host, other jobs, internal networks, or ground truth.
- Do not execute hostile benchmark repositories on the developer host.

### Step 4: Run the raw Codex EVM baseline

Status: PENDING

- Run sanitized Kelp only as a harness smoke case, then paired raw `codex exec` and skill-free `auditbase-agent` arms from the same pinned source/image.
- Use identical model, reasoning, prompt, tools, scope, network, token, and time settings; the wrapper is the only parity treatment.
- Expand into stratified EVMbench, precision-aware ScaBench cases, Blackhole coverage stress, temporal cases, and finally the private rotating holdout.
- Record every run, invalid result, match decision, finding, miss, false positive, cost, and uncertainty interval.
- Keep public web disabled only for anti-contamination benchmark runs; separately test the production controlled-public-egress mode during shadow/security qualification.
- Do not add an audit skill until wrapper parity and the raw baseline are understood.

### Step 5: Create the production isolated audit worker

Status: PENDING

- One fresh Firecracker/Kata-class microVM or equivalent separate-kernel guest per audit. Ordinary containers are local-development only.
- Read-only immutable input plus a disposable writable build workspace.
- No permanent secrets in the worker.
- Broad public outbound access only through controlled egress that blocks loopback, metadata, private/VPC/cluster networks, redirects/rebinding, platform services, host files, and other audits.
- Separate the trusted agent/model channel from repository-command UID, process, descriptor, environment, and network access.
- CPU, memory, disk, and runtime limits.
- Safe file-path validation, workspace materialization, and repository-instruction quarantine.

### Step 6: Create the V3 control plane

Status: PENDING

- Add the separate authenticated `/api/v3/audits` lane for the versioned V3 contract.
- Upload ingestion with preserved relative paths.
- Reuse the existing database, Temporal workflow, and Redis Streams where compatibility and isolation checks pass.
- Canonical status, cancellation, bounded SSE events, transactional outbox/reconciliation, and report retrieval.
- Encrypted source and artifact storage where required by the production deployment.
- Backend-only per-tier OpenAI model and reasoning-effort configuration.
- Server-side OpenAI API credentials and short-lived worker authorization.

### Step 7: Integrate the existing website

Status: PENDING

- Keep the website as the customer interface.
- Replace the old audit-engine execution step with `auditbase-agent` through the new V3 API and worker contract.
- Show upload validation, queued/running/completed/failed states, and the final report.
- Preserve normalized relative file paths and remove the current `.sol`-only restriction.
- Remove real model identifiers and model aliases from frontend code and responses.
- Retain the existing authenticated SSE path after normalizing its event and status schemas.
- Do not expose internal Codex protocols or provider secrets to the browser.

### Step 8: Improve audit quality through measured additions

Status: PENDING

Possible additions, each evaluated independently:

- Smart-contract audit skills.
- Protocol threat modelling.
- Coverage enforcement.
- Independent candidate verification.
- Reproducible PoCs and negative controls.
- Parallel audit lanes.

An addition remains only if it improves the held-out benchmark without unacceptable precision or reliability regressions.

Add Move, Solana/Rust, Cairo, and other ecosystem lanes only with their own
toolchain image, private cases, and release gates.

### Step 9: Production hardening and release

Status: PENDING

- Optimized release build.
- Complete relevant test suites.
- Multi-tenant security review.
- Load, cancellation, recovery, and failure testing.
- Upstream update procedure.
- Apache-2.0 license and modification notices.
- Selected-customer rollout with monitoring.

## Stop point

Product implementation is currently stopped after Step 2. The research and
architecture record is complete, but Step 3 coding must not begin until the user
explicitly authorizes coding.

When a step is completed, update this document with:

- The exact commit.
- Commands executed.
- Tests and observed results.
- Known limitations.
- The newly approved next step.
