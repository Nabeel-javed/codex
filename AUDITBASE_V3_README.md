# AuditBase V3

Canonical status, decisions, and step-by-step delivery plan for the clean-room AuditBase V3 agent.

Last verified: 2026-07-14

## Mission

Build a backend-only smart-contract auditing product on the open-source Codex runtime. The existing website will eventually submit uploaded source code to this new backend, which will run an isolated audit and return structured findings and a report.

AuditBase V3 will not reuse the AuditBase V2 agent implementation.

## Non-negotiable decisions

- Import no AuditBase V2 agent code, prompts, schemas, scanners, orchestration, persistence, or finalization logic.
- Use the open-source Codex runtime as the agent foundation.
- Ship a headless backend agent. The Codex terminal UI is not part of the product.
- Support OpenAI Responses-compatible model providers for the next few months.
- Defer native Anthropic support.
- Require an explicit provider and model for each future audit job; do not silently change models.
- Treat uploaded repositories as untrusted and execute each audit in an isolated, disposable worker.
- Optimize for audit quality and correctness, not for minimum cost, disk usage, token usage, or development speed.
- Add skills, multi-agent lanes, and verification only after measured evidence shows that they improve the raw Codex baseline.

## Current status

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

### Important current limitations

- The Codex source is still unmodified.
- The upstream TUI source still exists in the fork, although it was not built and is not needed by `codex-exec`.
- The binary is still named `codex-exec`, not `auditbase-agent`.
- The current binary is a debug build, not a production release build.
- There is no smart-contract-specific audit mode yet.
- There is no V3 findings schema, report format, HTTP API, queue, isolated worker image, model gateway, or website integration yet.
- No skills or V2 components have been added.

## Current smoke test

Run from Terminal:

```bash
cd /Users/Nabeel/Desktop/auditbase-v3

./codex-rs/target/debug/codex-exec \
  --ephemeral \
  --sandbox read-only \
  --cd "$PWD" \
  "Inspect this repository and briefly explain what codex-rs/exec does."
```

This is a headless process. It accepts a task, performs the work, prints the result, and exits. It does not open a terminal UI.

## Target system

```text
Existing website frontend
        |
        v
New AuditBase V3 HTTP API
        |
        v
Audit job queue and encrypted source storage
        |
        v
Disposable isolated worker
        |
        v
auditbase-agent (headless Codex fork)
        |
        v
Internal model gateway
        |
        v
Approved OpenAI Responses-compatible provider
        |
        v
New findings, execution trace, and report
```

The control plane must never execute uploaded code. Audit workers must never receive permanent infrastructure or provider credentials.

## Step-by-step roadmap

Only one step should be active at a time. A step is complete only when its acceptance checks pass and the evidence is recorded in this document.

### Step 0: Establish a working Codex baseline

Status: COMPLETE

Evidence: source clone, pinned commit, clean branch, successful headless build, real model connection, repository tool execution, and exact smoke-test result recorded above.

### Step 1: Create the AuditBase headless product binary

Status: NEXT -- NOT STARTED

Work:

- Create an `auditbase-agent` binary based on the working headless executor.
- Keep the Codex agent loop, repository navigation, tools, sandbox, sessions, model-provider support, and structured-output support.
- Remove the TUI and interactive Codex surfaces from the AuditBase product build.
- Keep the untouched upstream history and fetch remote so future Codex changes remain mergeable.
- Preserve the raw Codex behavior before introducing smart-contract instructions.

Acceptance checks:

- `auditbase-agent --version` runs successfully.
- The product dependency graph does not include `codex-tui`.
- The original headless smoke test passes through `auditbase-agent`.
- No AuditBase V2 code is present.
- Relevant tests pass and the Git diff is reviewed before committing.

### Step 2: Define the first smart-contract audit contract

Status: PENDING

Define new V3 inputs and outputs without copying V2 schemas.

Initial input:

- Repository/workspace path.
- Explicit scope.
- Explicit provider profile.
- Explicit model.
- Time and resource limits.

Initial output:

- Structured findings JSON.
- Human-readable report.
- Files and functions reviewed.
- Limitations and unfinished coverage.
- Complete execution events and usage.

### Step 3: Run the raw Codex Solidity baseline

Status: PENDING

- Select one representative Solidity repository with known, independently verified ground truth.
- Run manual Codex and `auditbase-agent` with the same model and scope.
- Confirm that backend automation preserves the manual Codex behavior.
- Record verified findings, misses, false positives, runtime, and execution traces.
- Do not add skills until this baseline is understood.

### Step 4: Create the isolated audit worker

Status: PENDING

- One disposable container or virtualized sandbox per audit.
- Read-only immutable input plus a disposable writable build workspace.
- No permanent secrets in the worker.
- Network denied by default except for the internal model gateway and explicitly approved dependencies.
- CPU, memory, disk, and runtime limits.
- Safe archive extraction and repository-instruction quarantine.

### Step 5: Create the V3 control plane

Status: PENDING

- New HTTP API.
- Upload ingestion.
- Job database and queue.
- Status, cancellation, events, and report retrieval.
- Encrypted source and artifact storage.
- Approved provider/model registry.
- Short-lived model-gateway credentials.

### Step 6: Integrate the existing website

Status: PENDING

- Keep the website as the customer interface.
- Replace the old audit-engine call with the new V3 API contract.
- Show upload validation, queued/running/completed/failed states, and the final report.
- Do not expose internal Codex protocols or provider secrets to the browser.

### Step 7: Improve audit quality through measured additions

Status: PENDING

Possible additions, each evaluated independently:

- Smart-contract audit skills.
- Protocol threat modelling.
- Coverage enforcement.
- Independent candidate verification.
- Reproducible PoCs and negative controls.
- Parallel audit lanes.

An addition remains only if it improves the held-out benchmark without unacceptable precision or reliability regressions.

### Step 8: Production hardening and release

Status: PENDING

- Optimized release build.
- Complete relevant test suites.
- Multi-tenant security review.
- Load, cancellation, recovery, and failure testing.
- Upstream update procedure.
- Apache-2.0 license and modification notices.
- Selected-customer rollout with monitoring.

## Stop point

The project is currently stopped after Step 0. Step 1 must not begin until it is explicitly approved.

When a step is completed, update this document with:

- The exact commit.
- Commands executed.
- Tests and observed results.
- Known limitations.
- The newly approved next step.
