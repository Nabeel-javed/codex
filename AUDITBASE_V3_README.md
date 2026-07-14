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
- Use OpenAI models only for the initial V3; do not build a multi-provider abstraction yet.
- Use the developer's existing ChatGPT subscription authentication only for local development and testing.
- Use OpenAI API authentication for production website audits.
- Keep production OpenAI API credentials server-side; never expose them to the browser or uploaded-code worker.
- Defer Anthropic and other model providers for at least the next few months.
- Require an explicit OpenAI model for each future audit job; do not silently change models.
- Treat uploaded repositories as untrusted and execute each audit in an isolated, disposable worker.
- Optimize for audit quality and correctness, not for minimum cost, disk usage, token usage, or development speed.
- Add skills, multi-agent lanes, and verification only after measured evidence shows that they improve the raw Codex baseline.
- Continuously track official Codex updates, but deploy only an explicitly tested and pinned upstream commit.
- Never merge or deploy `upstream/main` directly into production without compatibility gates and a rollback artifact.

## Authentication policy

### Local development and testing

Use the developer's existing ChatGPT subscription authentication. This is the path already proven by the headless smoke test. Do not add API-key configuration merely for local testing.

### Production website

Use OpenAI API authentication owned by the backend. The browser may submit an approved OpenAI model selection, but only the backend model gateway supplies the API credential. Do not use a developer ChatGPT subscription for production jobs.

No production API key has been configured yet. That work belongs to the future control-plane and model-gateway step.

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
   - Held-out smart-contract audit benchmark once the Step 3 benchmark exists.
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

### Important current limitations

- The upstream `codex-exec` runtime implementation remains unmodified; V3 currently adds only the isolated `codex-auditbase-agent` wrapper package and workspace registration.
- The upstream TUI source still exists in the fork for mergeability, but the `auditbase-agent` dependency graph does not include it.
- The current `auditbase-agent` binary is a debug build, not a production release build.
- There is no smart-contract-specific audit mode yet.
- There is no V3 findings schema, report format, HTTP API, queue, isolated worker image, model gateway, or website integration yet.
- Production OpenAI API authentication is not configured yet; the current smoke test uses subscription authentication as intended for development and testing.
- No multi-provider abstraction is planned for the initial V3.
- No skills or V2 components have been added.
- Bazel lock synchronization succeeds, but building the new Bazel target currently reaches and then fails on a pre-existing pinned-upstream mismatch: `exec-server/BUILD.bazel` passes `unit_test_args` to a `codex_rust_crate` macro that does not accept it. Cargo is the verified Step 1 build path; this unrelated Bazel baseline issue remains recorded for later resolution.
- Audit-quality regression testing is not yet available because the held-out Solidity benchmark is created in Step 3. Future upstream promotions must add that gate once the benchmark exists.

## Current smoke test

Run from Terminal:

```bash
cd /Users/Nabeel/Desktop/auditbase-v3

./codex-rs/target/debug/auditbase-agent \
  --ephemeral \
  --sandbox read-only \
  --cd "$PWD" \
  "Use repository inspection tools to read codex-rs/auditbase-agent/Cargo.toml, codex-rs/auditbase-agent/src/main.rs, and the current Git commit. Verify the package name, binary name, delegation to codex_exec::run_main, and that commit b24aa20107f365a1d0f06de9e0b28df5c516c7dd is an ancestor of HEAD. Then reply with exactly this single line and nothing else: AUDITBASE_V3_SYNC_OK upstream=b24aa20107 binary=auditbase-agent runtime=codex-exec"
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
Internal OpenAI API gateway
        |
        v
OpenAI API (production)
        |
        v
New findings, execution trace, and report
```

The control plane must never execute uploaded code. Audit workers must never receive permanent infrastructure credentials or the production OpenAI API key. Local development may use the developer's existing subscription authentication; production must use the backend-owned OpenAI API path shown above.

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

Status: NEXT -- NOT STARTED

Define new V3 inputs and outputs without copying V2 schemas.

Initial input:

- Repository/workspace path.
- Explicit scope.
- Explicit OpenAI model.
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
- Approved OpenAI model registry.
- Server-side OpenAI API credentials and short-lived worker authorization.

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

The project is currently stopped after Step 1.5. Step 2 must not begin until it is explicitly approved.

When a step is completed, update this document with:

- The exact commit.
- Commands executed.
- Tests and observed results.
- Known limitations.
- The newly approved next step.
