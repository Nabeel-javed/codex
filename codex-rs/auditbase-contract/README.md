# AuditBase V3 Contract

This crate is the versioned boundary between the existing AuditBase website and the new headless `auditbase-agent`. Rust types are the source of truth; committed JSON Schemas and examples are generated or validated from those types.

This contract contains no V2 audit logic, smart-contract prompt, persistence implementation, queue implementation, or OpenAI credential.

## V1 scope

V1 remains a pre-release contract until the hardening and cross-language
conformance gates pass. Tightening its semantics before website integration does
not imply that a deployed V1 may later be reinterpreted.

- File uploads only.
- Individual or multiple regular files, including zero-byte files.
- Extension- and language-agnostic file content.
- Preserved normalized relative paths.
- Backend-only tier-to-model configuration.
- Authenticated HTTP job operations.
- Authenticated SSE event delivery backed by the existing Redis Stream.
- Structured findings and final results.
- Partial artifact preservation when an audit fails.

Paste, explorer, GitHub, ZIP, and archive ingestion are not part of V1.

## HTTP surface

The existing website API owns authentication, authorization, credits, persistence, queue submission, and audit ownership checks.

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/v3/audits` | Validate an upload and enqueue an audit. |
| `GET` | `/api/v3/audits/{auditId}` | Return `AuditSnapshot`. |
| `GET` | `/api/v3/audits/{auditId}/stream` | Stream `AuditEvent` records over SSE. |
| `GET` | `/api/v3/audits/{auditId}/result` | Return `AuditResult` after completion or a failed partial run. |

The browser never calls Codex or OpenAI directly.

### Create request

`POST /api/v3/audits` uses `multipart/form-data`:

1. A required `request` part with media type `application/json` containing `AuditRequest`.
2. One binary part per manifest entry, named `file.<fileId>`.
3. The server matches parts by `fileId`, never by multipart order or client-supplied filename.
4. The server verifies the byte length and SHA-256 digest before storing or enqueueing the audit.

Example manifest entry:

```json
{
  "fileId": "source-001",
  "path": "contracts/token/Token.sol",
  "sizeBytes": 2048,
  "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "mediaType": "text/plain"
}
```

The corresponding multipart field name is `file.source-001`. `path` is the authoritative workspace path. A multipart parser may sanitize filenames, so multipart filenames must not be used as repository paths.

On success, the API returns `202 Accepted` with `AuditAccepted`. Validation and configuration failures use `ApiErrorResponse`; a missing, disabled, or unavailable tier must fail clearly without a fallback model.

## Relative path rules

Every uploaded path must:

- Be non-empty and relative.
- Use `/` separators on every operating system.
- Contain no empty, `.` or `..` components.
- Contain no backslash, NUL, drive-letter separator, or absolute prefix.
- Be unique within the audit after normalization and Unicode lowercasing.

The worker materializes files beneath a new disposable workspace and performs a containment check before every write. It never flattens paths to basenames.

## Backend configuration

There is one backend-only TOML configuration file with two sections. Its exact
bytes are SHA-256 pinned per audit, so every control-plane and runner process
must load the same absolute file rather than reserialize it:

- `tiers`: public tier identifiers mapped to private model, reasoning effort, enabled state, and audit timeout. The initial timeout maximum is 1,680 minutes (28 hours), leaving cleanup and finalization reserve inside the worker's 30-hour hard process boundary.
- `runtime`: concurrency, upload, worker resource, retention, network, and
  contract-size settings.

The frontend sends only a tier identifier. Model identifiers and reasoning effort must not appear in browser bundles, public API responses, SSE events, audit results, or report exports.
The closed reasoning-effort set is `low`, `medium`, `high`, `xhigh`, and `max`;
unknown values fail contract deserialization rather than falling back.

Production uses `controlled_public`; benchmark jobs use `benchmark_model_only`.
Isolation remains mandatory: uploaded code receives no OpenAI, database, Redis,
cloud, or cross-audit credentials.

Contract limits cap the serialized request, event, and result plus guidance,
logs, snippets, per-item and aggregate diagnostics, and per-item and per-finding
evidence. The trusted runner enforces raw byte limits before deserialization and
then calls the semantic limit validators. `max_result_bytes` cannot exceed the
runner's canonical 256 MiB hard model-output boundary.

Every public `u64` is limited to JavaScript's maximum safe integer
(`9007199254740991`) in both semantic validation and the committed schemas.
Optional guidance must be non-empty when present; omit it when no guidance was
provided. The JSON Schema rejects zero-length strings with `minLength: 1`, and
Rust semantic validation remains authoritative for rejecting whitespace-only
guidance.

## Canonical lifecycle

```text
queued
  -> preparing
       -> auditing
            -> finalizing
                 -> completed

Any non-terminal state -> failed
```

The only public statuses are:

- `queued`
- `preparing`
- `auditing`
- `finalizing`
- `completed`
- `failed`

`completed` and `failed` are terminal. Cancellation, infrastructure loss, model failure, invalid final output, agent crash, and audit timeout are represented by `status: failed` plus a typed failure code.

The API, database adapter, Temporal workflow, Redis events, and website must use this vocabulary. Legacy `pending`, `processing`, and `stopped` values are adapter inputs only and must not escape through the V1 API.

## Compilation and dependency behavior

Compilation is evidence, not a prerequisite for source review.

- `compilation.status: succeeded` means the uploaded workspace compiled.
- `failed` means compilation was attempted but failed.
- `partial` means only part of a multi-language or multi-package workspace compiled.
- `not_attempted` means no applicable compiler was run.

A failed or partial compilation does not fail the audit when Codex can continue
source-level review. A failed compilation requires limitation code
`compilation_failed`; a partial compilation requires `compilation_partial`.

## Failure and partial-result behavior

When the agent crashes, is cancelled, times out, or loses required infrastructure:

1. Stop further audit work.
2. Preserve events, findings, coverage, compilation diagnostics, and usage already emitted.
3. Write an `AuditResult` with `status: failed` and required `failure` details.
4. Set `partial: true` when the retained result does not represent finished coverage.
5. Emit a terminal `failed` event.
6. Never display the result as a completed audit.

A completed result must have `partial: false` and no failure object.
A failed result must have `partial: true`; a failure before any retainable result
instead exposes no result.

## SSE protocol

Each Redis Stream record maps to one `AuditEvent`. The SSE response uses:

```text
id: <sequence>
event: <payload type>
data: <serialized AuditEvent JSON>
```

Event payload types are:

- `status`
- `progress`
- `log`
- `finding`
- `limitation`
- `usage`
- `completed`
- `failed`

Requirements:

- `sequence` starts at 1 and is contiguous within an audit; gaps and duplicates
  are invalid.
- Every timestamp uses exactly uppercase UTC with millisecond precision:
  `YYYY-MM-DDTHH:MM:SS.sssZ`. Offsets, lowercase suffixes, missing or extra
  fractional digits, and leap-second spellings are rejected.
- `eventId` is stable and unique within an audit.
- Events are append-only and replayable during the configured retention period.
- The endpoint accepts the standard `Last-Event-ID` header and resumes after that sequence.
- Replayed events preserve their original IDs, sequence numbers, timestamps, and data.
- Heartbeats may be SSE comments and are not persisted contract events.
- `completed` and `failed` close the stream after delivery.
- The completion event does not embed the full report; the browser fetches `resultUrl`.

Codex JSONL events are internal worker input. The worker adapter translates them into this stable product event contract so upstream Codex event changes do not become browser breaking changes.

The full-stream validator treats `AuditAccepted` as establishing `queued`. Status
events must then form one contiguous lifecycle, finding updates must follow a
discovery with the same stable ID, timestamps cannot move backwards, and the
final status/payload/snapshot/result must agree.

For a retained result, the event stream must reproduce findings in discovery
order with their latest state, limitations in exact result order, and total
usage as the checked sum of usage deltas. Missing or mismatched result state is
invalid. Finding or limitation events are invalid when no result is retained;
usage may still be preserved for a failure without a partial result.

Termination is deliberately represented by two consecutive records: first the
final `status` transition (`finalizing -> completed` or any non-terminal state
`-> failed`), then exactly one matching `completed` or `failed` payload as the
last record. The status transition updates lifecycle state; the terminal payload
announces durable result availability and closes SSE after delivery.

## Finding contract

Every retained finding has:

- Stable ID.
- Title, severity, review status, and confidence.
- Category, description, impact, and remediation.
- Zero or more precise source locations.
- Evidence collected from source, commands, tests, artifacts, or analysis.
- Explicit proof status and any proof commands/artifacts.

Finding review statuses:

- `verified`: supported by retained evidence; validation rejects a verified finding with no evidence.
- `suspected`: plausible but not fully verified.
- `informational`: retained contextual or hardening observation.

Confidence uses `high`, `medium`, or `low`. Severity uses `critical`, `high`, `medium`, `low`, or `informational` so the existing report UI can preserve all current severity lanes.
Informational review status is valid if and only if severity is informational.

Rejected candidates are not silently converted into findings. The future audit execution trace may retain candidate investigation history separately; the V1 report contains only retained findings with the statuses above.

## Result contract

`AuditResult` is the system of record for website rendering and PDF, JSON, Markdown, and HTML exports. It includes:

- Terminal status and partial flag.
- Timing and executive summary.
- Findings and exact severity counts.
- Per-file review coverage and reviewed functions.
- Compilation commands, status, and diagnostics.
- Explicit limitations.
- Token, request, and duration usage.
- Typed failure details for failed audits.

The result intentionally excludes the model identifier. Reproducibility metadata that contains private deployment details belongs in an internal operator record, not the public result.

## Existing website compatibility

| Existing component | V1 behavior |
| --- | --- |
| Next.js upload page | Remove `.sol` restriction; create a manifest with stable file IDs and preserved relative paths. |
| `POST /api/v3/audits` | Parse multipart request, validate contract, resolve tier server-side, persist files, and start Temporal. |
| Prisma `AuditFile.filePath` | Store validated manifest `path`; never assign `File.name` as the authoritative path. |
| Prisma `Audit.status` | Store canonical status values only for V1 jobs. |
| Prisma `Audit.results` | Store serialized `AuditResult`. |
| Prisma `Audit.hypotheses` | Legacy field; V1 findings come from `AuditResult.findings`. |
| Temporal workflow | Orchestrate the disposable worker and persist canonical status transitions. |
| Redis Stream | Persist serialized `AuditEvent` records and sequence. |
| Existing SSE route | Preserve authentication/reconnect behavior; emit V1 event names and envelopes. |
| Scan page | Render canonical statuses and fetch the result after a terminal event. |
| Existing report exports | Derive all exports from the stored V1 result. |
| Frontend tier constants | Keep presentation metadata only; remove real model names and aliases. |

## Versioning rules

- `schemaVersion` is required in every top-level public object.
- V1 rejects unknown fields to expose accidental contract drift.
- Additive or breaking wire changes require a new schema version when old consumers cannot safely ignore them.
- The backend may support multiple versions during a migration, but it must never reinterpret an existing version.
- The website and worker must pin the same schema fixture set in compatibility tests.

## Generated artifacts

Rust types live under `src/`. Committed schemas live under `schema/`, and validated payloads live under `examples/`.

Regenerate schemas from `codex-rs/`:

```bash
cargo run -p codex-auditbase-contract --bin auditbase-export-schemas -- \
  auditbase-contract/schema
```

Verify the crate:

```bash
just test -p codex-auditbase-contract
```

Schema fixture tests fail when committed JSON Schemas differ from the Rust source of truth. Example tests deserialize and semantically validate every committed example.
