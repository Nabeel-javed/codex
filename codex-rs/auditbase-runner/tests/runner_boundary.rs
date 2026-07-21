use std::collections::BTreeMap;
use std::io::Write;
use std::process::Command;
use std::process::Stdio;

use codex_auditbase_contract::AuditEventPayload;
use codex_auditbase_contract::AuditStatus;
use codex_auditbase_contract::AuditUsage;
use codex_auditbase_contract::ContractLimits;
use codex_auditbase_contract::Failure;
use codex_auditbase_contract::FailureCode;
use codex_auditbase_contract::Limitation;
use codex_auditbase_contract::TerminalAuditStatus;
use codex_auditbase_contract::validate_event_stream;
use codex_auditbase_runner::RunnerError;
use codex_auditbase_runner::accumulator::AuditAccumulator;
use codex_auditbase_runner::accumulator::IngestResult;
use codex_auditbase_runner::adapter::AdapterContext;
use codex_auditbase_runner::adapter::AuditEventAdapter;
use codex_auditbase_runner::checkpoint::PrivatePartialAuditState;
use codex_auditbase_runner::child_protocol::RunnerOutput;
use codex_auditbase_runner::child_protocol::RunnerTerminalStatus;
use codex_auditbase_runner::child_protocol::TrustedFixtureScenario;
use codex_auditbase_runner::child_protocol::parse_runner_request;
use codex_auditbase_runner::child_protocol::production_rejection;
use codex_auditbase_runner::child_protocol::trusted_fixture_outputs;
use codex_auditbase_runner::child_protocol::validate_trusted_fixture_artifact;
use codex_auditbase_runner::final_output::ModelOutputContext;
use codex_auditbase_runner::final_output::TrustedCompletedResultContext;
use codex_auditbase_runner::final_output::build_completed_result;
use codex_auditbase_runner::final_output::parse_model_audit_output;
use codex_auditbase_runner::provenance::AuthClass;
use codex_auditbase_runner::provenance::CodexConfiguredRuntime;
use codex_auditbase_runner::provenance::EffectiveRuntime;
use codex_auditbase_runner::provenance::NetworkPolicy;
use codex_auditbase_runner::provenance::PrivateRunProvenance;
use codex_auditbase_runner::provenance::ProvenanceSchemaVersion;
use codex_auditbase_runner::provenance::RequestedRuntime;
use codex_auditbase_runner::provenance::RunBudget;
use codex_auditbase_runner::provenance::canonical_sha256;
use codex_auditbase_runner::provenance::configured_runtime_from_thread_started;
use codex_auditbase_runner::provenance::parse_provenance_envelope;
use codex_auditbase_runner::raw_jsonl::JsonlLimits;
use codex_auditbase_runner::raw_jsonl::parse_thread_events;
use codex_auditbase_runner::supervisor::FinalOutputState;
use codex_auditbase_runner::supervisor::ProcessDisposition;
use codex_auditbase_runner::supervisor::RunResolution;
use codex_auditbase_runner::supervisor::classify_scripted_run;
use codex_exec::ThreadEvent;
use pretty_assertions::assert_eq;
use serde_json::json;

const SUCCESS_JSONL: &[u8] = include_bytes!("../fixtures/jsonl/success.jsonl");
const MALFORMED_JSONL: &[u8] = include_bytes!("../fixtures/jsonl/malformed.jsonl");
const UNKNOWN_JSONL: &[u8] = include_bytes!("../fixtures/jsonl/unknown.jsonl");
const TURN_FAILED_JSONL: &[u8] = include_bytes!("../fixtures/jsonl/turn-failed.jsonl");
const ERROR_JSONL: &[u8] = include_bytes!("../fixtures/jsonl/error.jsonl");
const MISSING_TERMINAL_JSONL: &[u8] = include_bytes!("../fixtures/jsonl/missing-terminal.jsonl");
const COMPLETED_OUTPUT: &[u8] = include_bytes!("../fixtures/final/completed.json");
const PARTIAL_OUTPUT: &[u8] = include_bytes!("../fixtures/final/partial.json");
const COMPLETED_RESULT_ARTIFACT: &[u8] =
    include_bytes!("../fixtures/artifacts/completed-result.json");
const FAILED_RESULT_ARTIFACT: &[u8] =
    include_bytes!("../fixtures/artifacts/failed-partial-result.json");

#[test]
fn raw_jsonl_is_strict_and_bounded() {
    let parsed = parse_thread_events(SUCCESS_JSONL, limits()).expect("fixture should parse");
    assert_eq!(parsed.events.len(), 6);

    assert!(matches!(
        parse_thread_events(MALFORMED_JSONL, limits()),
        Err(RunnerError::MalformedJsonl { .. })
    ));
    assert!(matches!(
        parse_thread_events(UNKNOWN_JSONL, limits()),
        Err(RunnerError::UnknownThreadEvent { .. })
    ));
    let unknown_nested_usage = br#"{"type":"turn.completed","usage":{"input_tokens":1,"cached_input_tokens":0,"cache_write_input_tokens":0,"output_tokens":1,"reasoning_output_tokens":0,"future_token_class":1}}"#;
    assert!(matches!(
        parse_thread_events(unknown_nested_usage, limits()),
        Err(RunnerError::UnknownThreadEventField { field, .. })
            if field == "usage.future_token_class"
    ));
    let best_effort_item_drift = br#"{"type":"thread.started","thread_id":"thread-item-drift","model":"gpt-5","model_provider_id":"openai","reasoning_effort":"high"}
{"type":"turn.started"}
{"type":"item.completed","item":{"type":"error","message":"private warning without an item id"}}
{"type":"item.completed","item":{"id":"command-1","type":"command_execution","command":"true","aggregated_output":"","exit_code":0,"status":"completed","future_command_state":true}}
{"type":"item.updated","item":{"id":null,"type":"reasoning"}}
{"type":"turn.completed","usage":{"input_tokens":1,"cached_input_tokens":0,"cache_write_input_tokens":0,"output_tokens":1,"reasoning_output_tokens":0}}
"#;
    let parsed_item_drift = parse_thread_events(best_effort_item_drift, limits())
        .expect("item progress is best-effort");
    assert_eq!(parsed_item_drift.events.len(), 3);
    assert!(matches!(
        parse_thread_events(br#"{"type":"turn.completed"}"#, limits()),
        Err(RunnerError::MalformedJsonl { .. })
    ));
    assert!(matches!(
        parse_thread_events(
            SUCCESS_JSONL,
            JsonlLimits {
                max_total_bytes: SUCCESS_JSONL.len() - 1,
                ..limits()
            }
        ),
        Err(RunnerError::ByteLimit { .. })
    ));
    assert!(matches!(
        parse_thread_events(
            SUCCESS_JSONL,
            JsonlLimits {
                max_line_bytes: 10,
                ..limits()
            }
        ),
        Err(RunnerError::ByteLimit { .. })
    ));
    assert!(matches!(
        parse_thread_events(
            SUCCESS_JSONL,
            JsonlLimits {
                max_events: 1,
                ..limits()
            }
        ),
        Err(RunnerError::EventLimit { .. })
    ));
}

#[test]
fn provenance_requires_all_three_runtime_layers_and_binds_artifacts() {
    let parsed = parse_thread_events(SUCCESS_JSONL, limits()).expect("fixture should parse");
    let ThreadEvent::ThreadStarted(started) = &parsed.events[0] else {
        panic!("first event should start the thread");
    };
    let configured =
        configured_runtime_from_thread_started(started).expect("configured fields should exist");
    assert_eq!(configured.service_tier, None);

    let provenance = provenance(configured)
        .expect("provenance fixture should build")
        .into_envelope()
        .expect("valid provenance");
    provenance.validate().expect("envelope should validate");
    assert_eq!(provenance.fingerprint_sha256.len(), 64);

    let result = json!({"auditId":"audit-fixture","retained":true});
    let binding = codex_auditbase_runner::provenance::PrivateRunArtifactBinding::from_result(
        &provenance,
        &result,
        Some("9".repeat(64)),
    )
    .expect("binding should build");
    binding
        .validate_against(&provenance, &result, Some(&"9".repeat(64)))
        .expect("binding should match exact artifacts");
    assert!(
        binding
            .validate_against(
                &provenance,
                &json!({"different":true}),
                Some(&"9".repeat(64))
            )
            .is_err()
    );
    assert!(
        binding
            .validate_against(&provenance, &result, Some(&"8".repeat(64)))
            .is_err()
    );

    let mut swapped_record = provenance.record.clone();
    swapped_record.input_manifest_sha256 = "7".repeat(64);
    let swapped = swapped_record
        .into_envelope()
        .expect("swapped record is shaped");
    assert!(
        binding
            .validate_against(&swapped, &result, Some(&"9".repeat(64)))
            .is_err()
    );

    let mut mismatch = provenance.record.clone();
    mismatch.effective.model = "different-model".to_owned();
    assert!(matches!(
        mismatch.validate(),
        Err(RunnerError::RuntimeMismatch { .. })
    ));

    let mut missing = serde_json::to_value(&provenance).expect("serialize envelope");
    missing["record"]["effective"]
        .as_object_mut()
        .expect("effective object")
        .remove("modelSnapshot");
    assert!(
        parse_provenance_envelope(
            &serde_json::to_vec(&missing).expect("serialize changed envelope")
        )
        .is_err()
    );

    let legacy = parse_thread_events(
        br#"{"type":"thread.started","thread_id":"legacy"}"#,
        limits(),
    )
    .expect("legacy event remains parseable");
    let ThreadEvent::ThreadStarted(legacy) = &legacy.events[0] else {
        panic!("legacy thread event expected");
    };
    assert!(configured_runtime_from_thread_started(legacy).is_err());
}

#[test]
fn provenance_accepts_exact_xhigh_and_rejects_reasoning_effort_drift() {
    let configured = CodexConfiguredRuntime {
        provider_id: "openai".to_owned(),
        model: "gpt-test".to_owned(),
        reasoning_effort: "xhigh".to_owned(),
        service_tier: None,
    };
    let provenance = provenance(configured).expect("xhigh provenance fixture should build");
    provenance
        .validate()
        .expect("all three exact xhigh runtime layers should validate");

    let mut drifted = provenance;
    drifted.effective.reasoning_effort = "high".to_owned();
    assert!(matches!(
        drifted.validate(),
        Err(RunnerError::RuntimeMismatch { .. })
    ));
}

#[test]
fn private_model_output_cannot_author_trusted_lifecycle_fields() {
    let context = model_context();
    let output = parse_model_audit_output(COMPLETED_OUTPUT, 1024 * 1024, &context)
        .expect("fixture should parse");
    let result = build_completed_result(
        output,
        TrustedCompletedResultContext {
            audit_id: "audit-fixture".to_owned(),
            submitted_paths: context.submitted_paths.clone(),
            started_at: "2026-07-17T10:00:00.000Z".to_owned(),
            finished_at: "2026-07-17T10:01:00.000Z".to_owned(),
            usage: trusted_usage(),
        },
    )
    .expect("trusted runner should construct result");
    assert_eq!(result.audit_id, "audit-fixture");
    assert_eq!(result.status, TerminalAuditStatus::Completed);

    for forbidden in [
        ("auditId", json!("model-controlled")),
        ("status", json!("failed")),
        ("provenance", json!({"forged":true})),
        ("usage", json!({"inputTokens":999999})),
    ] {
        let mut value: serde_json::Value =
            serde_json::from_slice(COMPLETED_OUTPUT).expect("fixture JSON");
        value
            .as_object_mut()
            .expect("output object")
            .insert(forbidden.0.to_owned(), forbidden.1);
        assert!(matches!(
            parse_model_audit_output(
                &serde_json::to_vec(&value).expect("serialize forged output"),
                1024 * 1024,
                &context
            ),
            Err(RunnerError::MalformedModelOutput { .. })
        ));
    }
    assert!(matches!(
        parse_model_audit_output(COMPLETED_OUTPUT, 10, &context),
        Err(RunnerError::ByteLimit { .. })
    ));
}

#[test]
fn supervisor_classifies_every_terminal_and_fault_path() {
    let success = events(SUCCESS_JSONL).expect("success fixture should parse");
    assert_eq!(
        classify_scripted_run(
            &success,
            ProcessDisposition::Exited { code: 0 },
            FinalOutputState::Valid
        ),
        RunResolution::Completed
    );
    assert_failure(
        &events(TURN_FAILED_JSONL).expect("turn failure fixture should parse"),
        ProcessDisposition::Exited { code: 0 },
        FinalOutputState::Missing,
        FailureCode::ModelUnavailable,
    );
    assert_failure(
        &events(ERROR_JSONL).expect("error fixture should parse"),
        ProcessDisposition::Exited { code: 0 },
        FinalOutputState::Missing,
        FailureCode::Infrastructure,
    );
    assert_failure(
        &events(MISSING_TERMINAL_JSONL).expect("missing terminal fixture should parse"),
        ProcessDisposition::Exited { code: 0 },
        FinalOutputState::Missing,
        FailureCode::InvalidOutput,
    );
    assert_failure(
        &success,
        ProcessDisposition::Exited { code: 0 },
        FinalOutputState::Invalid,
        FailureCode::InvalidOutput,
    );
    assert_failure(
        &success,
        ProcessDisposition::Crashed,
        FinalOutputState::Valid,
        FailureCode::AgentCrash,
    );
    assert_failure(
        &success,
        ProcessDisposition::TimedOut,
        FinalOutputState::Valid,
        FailureCode::AuditTimeout,
    );
    assert_failure(
        &success,
        ProcessDisposition::Cancelled,
        FinalOutputState::Valid,
        FailureCode::Cancelled,
    );
}

#[test]
fn retryable_stream_error_is_nonterminal_and_can_complete() {
    let retry_then_success = br#"{"type":"thread.started","thread_id":"thread-retry","model":"gpt-5","model_provider_id":"openai","reasoning_effort":"high"}
{"type":"turn.started"}
{"type":"error","message":"PRIVATE_TRANSIENT_ERROR","will_retry":true}
{"type":"turn.completed","usage":{"input_tokens":100,"cached_input_tokens":20,"cache_write_input_tokens":5,"output_tokens":30,"reasoning_output_tokens":10}}
"#;
    let parsed = events(retry_then_success).expect("retry stream should parse");
    assert!(matches!(
        &parsed[2],
        ThreadEvent::Error(error) if error.will_retry
    ));
    assert_eq!(
        classify_scripted_run(
            &parsed,
            ProcessDisposition::Exited { code: 0 },
            FinalOutputState::Valid,
        ),
        RunResolution::Completed
    );

    let mut adapter = AuditEventAdapter::new(adapter_context()).expect("adapter context");
    adapter
        .adapt_all(&parsed)
        .expect("retryable error must not terminate adaptation");
    let model_output = parse_model_audit_output(COMPLETED_OUTPUT, 1024 * 1024, &model_context())
        .expect("model fixture should parse");
    let result = build_completed_result(
        model_output,
        TrustedCompletedResultContext {
            audit_id: "audit-fixture".to_owned(),
            submitted_paths: vec!["src/example.sol".to_owned()],
            started_at: "2026-07-17T10:00:00.000Z".to_owned(),
            finished_at: "2026-07-17T10:01:00.000Z".to_owned(),
            usage: trusted_usage(),
        },
    )
    .expect("result should build");
    adapter
        .finish(&RunResolution::Completed, Some(&result))
        .expect("successful retry stream should finalize");
}

#[test]
fn fatal_stream_error_can_be_followed_by_canonical_turn_failed() {
    let fatal_then_failed = br#"{"type":"thread.started","thread_id":"thread-fatal","model":"gpt-5","model_provider_id":"openai","reasoning_effort":"high"}
{"type":"turn.started"}
{"type":"error","message":"PRIVATE_FATAL_ERROR","will_retry":false}
{"type":"turn.failed","error":{"message":"PRIVATE_FATAL_ERROR","will_retry":false}}
"#;
    let parsed = events(fatal_then_failed).expect("fatal stream should parse");
    let resolution = classify_scripted_run(
        &parsed,
        ProcessDisposition::Exited { code: 0 },
        FinalOutputState::Missing,
    );
    let RunResolution::Failed(failure) = &resolution else {
        panic!("fatal turn must fail");
    };
    assert_eq!(failure.code, FailureCode::ModelUnavailable);

    let mut adapter = AuditEventAdapter::new(adapter_context()).expect("adapter context");
    adapter
        .adapt_all(&parsed)
        .expect("causal error before turn.failed must be accepted");
    adapter
        .finish(&resolution, None)
        .expect("failed stream should finalize exactly once");
    let public = adapter.into_events();
    assert!(matches!(
        public.last().expect("terminal").payload,
        AuditEventPayload::Failed(_)
    ));
    let serialized = serde_json::to_string(&public).expect("public events serialize");
    assert!(!serialized.contains("PRIVATE_FATAL_ERROR"));
}

#[test]
fn adapter_redacts_raw_data_and_emits_one_valid_terminal_path() {
    let raw = events(SUCCESS_JSONL).expect("success fixture should parse");
    let mut model_output = parse_model_audit_output(PARTIAL_OUTPUT, 1024 * 1024, &model_context())
        .expect("model fixture should parse");
    model_output.limitations.push(Limitation {
        code: "fixture_constraint".to_owned(),
        message: "A deterministic fixture limitation.".to_owned(),
        affected_paths: vec!["src/example.sol".to_owned()],
    });
    let result = build_completed_result(
        model_output,
        TrustedCompletedResultContext {
            audit_id: "audit-fixture".to_owned(),
            submitted_paths: vec!["src/example.sol".to_owned()],
            started_at: "2026-07-17T10:00:00.000Z".to_owned(),
            finished_at: "2026-07-17T10:01:00.000Z".to_owned(),
            usage: trusted_usage(),
        },
    )
    .expect("result should build");
    let mut adapter = AuditEventAdapter::new(adapter_context()).expect("adapter context");
    adapter.adapt_all(&raw).expect("raw stream should adapt");
    adapter
        .finish(&RunResolution::Completed, Some(&result))
        .expect("completion should adapt");
    let public = adapter.into_events();

    let serialized = serde_json::to_string(&public).expect("serialize public events");
    for secret in [
        "SECRET_RAW_REASONING_MUST_NOT_LEAK",
        "SECRET_COMMAND_OUTPUT_MUST_NOT_LEAK",
        "SECRET_MODEL_OUTPUT_MUST_NOT_LEAK",
    ] {
        assert!(!serialized.contains(secret));
    }
    let canonical_tail = &public[public.len() - 5..];
    assert!(matches!(
        canonical_tail[0].payload,
        AuditEventPayload::Finding(_)
    ));
    assert!(matches!(
        canonical_tail[1].payload,
        AuditEventPayload::Limitation(_)
    ));
    assert!(matches!(
        canonical_tail[2].payload,
        AuditEventPayload::Usage(ref usage) if usage == &result.usage
    ));
    assert!(matches!(
        canonical_tail[3].payload,
        AuditEventPayload::Status(ref status) if status.status == AuditStatus::Completed
    ));
    assert!(matches!(
        canonical_tail[4].payload,
        AuditEventPayload::Completed(_)
    ));
    assert!(public.iter().any(|event| matches!(
        &event.payload,
        AuditEventPayload::Finding(finding)
            if finding.finding.id == "finding-accounting-1"
    )));
    assert!(public.iter().any(|event| matches!(
        &event.payload,
        AuditEventPayload::Limitation(limitation)
            if limitation.code == "fixture_constraint"
    )));
    assert!(public.iter().any(|event| matches!(
        &event.payload,
        AuditEventPayload::Usage(usage) if usage == &result.usage
    )));
    validate_event_stream(&public, Some(&result), None, &contract_limits())
        .expect("full public stream should validate");

    let mut accumulator = AuditAccumulator::new("audit-fixture");
    for event in public.clone() {
        assert_eq!(
            accumulator.ingest(event).expect("initial ingest"),
            IngestResult::Added
        );
    }
    for event in public.clone() {
        assert_eq!(
            accumulator.ingest(event).expect("identical replay"),
            IngestResult::Duplicate
        );
    }
    let mut conflict = public[0].clone();
    conflict.occurred_at = "2026-07-17T10:00:01.000Z".to_owned();
    assert!(matches!(
        accumulator.ingest(conflict),
        Err(RunnerError::ReplayConflict { .. })
    ));

    let missing = events(MISSING_TERMINAL_JSONL).expect("missing terminal fixture should parse");
    let failed_resolution = classify_scripted_run(
        &missing,
        ProcessDisposition::Exited { code: 0 },
        FinalOutputState::Missing,
    );
    let mut failed_adapter = AuditEventAdapter::new(adapter_context()).expect("adapter context");
    failed_adapter
        .adapt_all(&missing)
        .expect("nonterminal raw stream should adapt");
    failed_adapter
        .finish(&failed_resolution, None)
        .expect("failed resolution should adapt");
    let failed_public = failed_adapter.into_events();
    assert!(matches!(
        failed_public[failed_public.len() - 2].payload,
        AuditEventPayload::Status(ref status) if status.status == AuditStatus::Failed
    ));
    assert!(matches!(
        failed_public.last().expect("terminal").payload,
        AuditEventPayload::Failed(_)
    ));
    validate_event_stream(&failed_public, None, None, &contract_limits())
        .expect("failed public stream should validate");

    let mut constrained_context = adapter_context();
    constrained_context.max_events = 6;
    let mut constrained =
        AuditEventAdapter::new(constrained_context).expect("constrained adapter context");
    constrained
        .adapt_all(&raw)
        .expect("raw stream should fit before canonical final state");
    let before_finish = constrained.events().to_vec();
    assert!(matches!(
        constrained.finish(&RunResolution::Completed, Some(&result)),
        Err(RunnerError::Adapter { .. })
    ));
    assert_eq!(constrained.events(), before_finish);
}

#[test]
fn adapter_rejects_result_token_usage_that_disagrees_with_codex_terminal() {
    let raw = events(SUCCESS_JSONL).expect("success fixture should parse");
    let model_output = parse_model_audit_output(COMPLETED_OUTPUT, 1024 * 1024, &model_context())
        .expect("model fixture should parse");
    let mut result = build_completed_result(
        model_output,
        TrustedCompletedResultContext {
            audit_id: "audit-fixture".to_owned(),
            submitted_paths: vec!["src/example.sol".to_owned()],
            started_at: "2026-07-17T10:00:00.000Z".to_owned(),
            finished_at: "2026-07-17T10:01:00.000Z".to_owned(),
            usage: trusted_usage(),
        },
    )
    .expect("result should build");
    result.usage.input_tokens += 1;

    let mut adapter = AuditEventAdapter::new(adapter_context()).expect("adapter context");
    adapter.adapt_all(&raw).expect("raw stream should adapt");
    let before_finish = adapter.events().to_vec();
    assert!(matches!(
        adapter.finish(&RunResolution::Completed, Some(&result)),
        Err(RunnerError::Adapter { message })
            if message.contains("token usage differs")
    ));
    assert_eq!(adapter.events(), before_finish);
}

#[test]
fn partial_checkpoint_survives_timeout_and_synthesizes_failed_result() {
    let output = parse_model_audit_output(PARTIAL_OUTPUT, 1024 * 1024, &model_context())
        .expect("partial fixture should validate");
    let mut checkpoint = PrivatePartialAuditState::new(
        "audit-fixture",
        "a".repeat(64),
        "2026-07-17T10:00:00.000Z",
        vec!["src/example.sol".to_owned()],
    )
    .expect("checkpoint should initialize");
    checkpoint
        .checkpoint_validated_model_output(&output, "2026-07-17T10:00:30.000Z")
        .expect("validated content should checkpoint");
    assert!(checkpoint.has_partial_results());

    let failure = Failure {
        code: FailureCode::AuditTimeout,
        message: "The audit exceeded its configured time limit.".to_owned(),
        retryable: true,
    };
    let result = checkpoint
        .synthesize_failed_result(failure.clone(), "2026-07-17T10:01:00.000Z")
        .expect("failed result should synthesize");
    assert_eq!(result.status, TerminalAuditStatus::Failed);
    assert!(result.partial);
    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.failure, Some(failure));
}

#[test]
fn child_protocol_is_strict_fixture_only_and_production_fails_closed() {
    let request_bytes = runner_request().expect("request fixture should serialize");
    let request = parse_runner_request(&request_bytes).expect("request should parse");
    let completed_sha = validate_trusted_fixture_artifact(
        COMPLETED_RESULT_ARTIFACT,
        1024 * 1024,
        &request,
        TrustedFixtureScenario::Completed,
    )
    .expect("completed artifact should validate");
    let completed =
        trusted_fixture_outputs(&request, TrustedFixtureScenario::Completed, &completed_sha);
    for (index, output) in completed.iter().enumerate() {
        let sequence = match output {
            RunnerOutput::AuditEvent { sequence, .. } | RunnerOutput::Terminal { sequence, .. } => {
                *sequence
            }
        };
        assert_eq!(sequence, index as u64 + 1);
    }
    assert!(matches!(
        completed.last().expect("terminal"),
        RunnerOutput::Terminal {
            status: RunnerTerminalStatus::Completed,
            result_ref: Some(result_ref),
            result_sha256: Some(result_sha256),
            ..
        } if result_ref == "artifact:result" && result_sha256 == &completed_sha
    ));
    let failed_sha = validate_trusted_fixture_artifact(
        FAILED_RESULT_ARTIFACT,
        1024 * 1024,
        &request,
        TrustedFixtureScenario::Failed,
    )
    .expect("failed partial artifact should validate");
    assert_eq!(failed_sha.len(), 64);
    assert!(
        validate_trusted_fixture_artifact(
            COMPLETED_RESULT_ARTIFACT,
            1024 * 1024,
            &request,
            TrustedFixtureScenario::Failed,
        )
        .is_err()
    );
    assert!(matches!(
        production_rejection(&request),
        RunnerOutput::Terminal {
            status: RunnerTerminalStatus::Failed,
            result_ref: None,
            partial_result_ref: None,
            ..
        }
    ));

    let mut unknown: serde_json::Value =
        serde_json::from_slice(&request_bytes).expect("request JSON");
    unknown
        .as_object_mut()
        .expect("object")
        .insert("unexpected".to_owned(), json!(true));
    assert!(parse_runner_request(&serde_json::to_vec(&unknown).expect("serialize")).is_err());
}

#[test]
fn production_binary_preserves_specific_rejection_terminal() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_auditbase-v3-runner"))
        .env_remove("AUDITBASE_V3_EXECUTION_MODE")
        .env_remove("AUDITBASE_V3_LOCAL_TRUST_ACK")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("runner binary should start");
    child
        .stdin
        .take()
        .expect("stdin should be piped")
        .write_all(&runner_request().expect("request fixture should serialize"))
        .expect("request should be written");
    let output = child.wait_with_output().expect("runner should terminate");

    assert!(
        output.status.success(),
        "a flushed protocol rejection must not be replaced by a nonzero child exit: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("protocol should be UTF-8");
    let lines: Vec<_> = stdout.lines().collect();
    assert_eq!(lines.len(), 1, "production rejection must be one terminal");
    let terminal: serde_json::Value =
        serde_json::from_str(lines[0]).expect("terminal should be JSON");
    assert_eq!(terminal["kind"], "terminal");
    assert_eq!(terminal["status"], "failed");
    assert_eq!(
        terminal["failure_code"],
        "isolation_and_gateway_attestation_required"
    );
}

fn limits() -> JsonlLimits {
    JsonlLimits {
        max_total_bytes: 1024 * 1024,
        max_line_bytes: 64 * 1024,
        max_events: 100,
    }
}

fn events(fixture: &[u8]) -> Result<Vec<ThreadEvent>, RunnerError> {
    Ok(parse_thread_events(fixture, limits())?.events)
}

fn model_context() -> ModelOutputContext {
    ModelOutputContext {
        submitted_paths: vec!["src/example.sol".to_owned()],
    }
}

fn adapter_context() -> AdapterContext {
    AdapterContext {
        audit_id: "audit-fixture".to_owned(),
        occurred_at: "2026-07-17T10:00:30.000Z".to_owned(),
        max_events: 32,
        max_message_bytes: 256,
    }
}

fn trusted_usage() -> AuditUsage {
    AuditUsage {
        input_tokens: 100,
        cached_input_tokens: 20,
        cache_write_input_tokens: 5,
        output_tokens: 30,
        reasoning_output_tokens: 10,
        model_requests: 1,
        duration_ms: 60_000,
    }
}

fn provenance(configured: CodexConfiguredRuntime) -> Result<PrivateRunProvenance, RunnerError> {
    let reasoning_effort = configured.reasoning_effort.clone();
    let mut toolchain = BTreeMap::new();
    toolchain.insert("forge".to_owned(), "1.2.3".to_owned());
    let toolchain_sha256 = canonical_sha256(&toolchain)?;
    Ok(PrivateRunProvenance {
        schema_version: ProvenanceSchemaVersion::V1,
        audit_id: "audit-fixture".to_owned(),
        requested: RequestedRuntime {
            provider_id: "openai".to_owned(),
            model: "gpt-test".to_owned(),
            reasoning_effort: reasoning_effort.clone(),
            service_tier: None,
            auth_class: AuthClass::ApiKey,
        },
        codex_configured: configured,
        effective: EffectiveRuntime {
            provider_id: "openai".to_owned(),
            model: "gpt-test".to_owned(),
            model_snapshot: "gpt-test-2026-07-17".to_owned(),
            reasoning_effort,
            service_tier: None,
            auth_class: AuthClass::ApiKey,
        },
        codex_git_sha: "a".repeat(40),
        codex_binary_sha256: "b".repeat(64),
        runtime_image_digest: format!("sha256:{}", "c".repeat(64)),
        input_manifest_sha256: "d".repeat(64),
        config_sha256: "e".repeat(64),
        prompt_sha256: "f".repeat(64),
        skill_bundle_sha256: "1".repeat(64),
        output_schema_sha256: "2".repeat(64),
        toolchain,
        toolchain_sha256,
        budget: RunBudget {
            wall_clock_ms: 60_000,
            max_jsonl_bytes: 1024 * 1024,
            max_jsonl_line_bytes: 64 * 1024,
            max_jsonl_events: 100,
            max_final_output_bytes: 1024 * 1024,
        },
        network_policy: NetworkPolicy::ControlledPublic,
    })
}

fn assert_failure(
    events: &[ThreadEvent],
    process: ProcessDisposition,
    final_output: FinalOutputState,
    code: FailureCode,
) {
    let RunResolution::Failed(failure) = classify_scripted_run(events, process, final_output)
    else {
        panic!("expected failed resolution");
    };
    assert_eq!(failure.code, code);
}

fn contract_limits() -> ContractLimits {
    ContractLimits {
        max_request_bytes: 4 * 1024 * 1024,
        max_guidance_bytes: 64 * 1024,
        max_event_bytes: 1024 * 1024,
        max_log_message_bytes: 64 * 1024,
        max_result_bytes: 4 * 1024 * 1024,
        max_diagnostic_item_bytes: 64 * 1024,
        max_diagnostics_bytes: 1024 * 1024,
        max_snippet_bytes: 64 * 1024,
        max_evidence_item_bytes: 1024 * 1024,
        max_finding_evidence_bytes: 2 * 1024 * 1024,
    }
}

fn runner_request() -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&json!({
        "protocol": "auditbase.runner.v1",
        "kind": "run",
        "request": {
            "audit_id": "audit-fixture",
            "job_ref": "job:fixture",
            "workspace_ref": "workspace:fixture",
            "tier_id": "deep",
            "config_sha256": "a".repeat(64),
            "contract_version": "auditbase.audit-workflow.v1",
            "guidance_ref": null,
            "result_ref": "artifact:result",
            "partial_result_ref": "artifact:partial",
            "diagnostics_ref": "artifact:diagnostics",
            "event_sink_ref": "event:sink",
            "idempotency_key": "fixture-key"
        }
    }))
}
