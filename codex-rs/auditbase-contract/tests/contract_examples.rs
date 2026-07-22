#![allow(clippy::expect_used)]

use std::collections::HashMap;
use std::collections::HashSet;

use codex_auditbase_contract::ApiErrorResponse;
use codex_auditbase_contract::AuditAccepted;
use codex_auditbase_contract::AuditConfig;
use codex_auditbase_contract::AuditEvent;
use codex_auditbase_contract::AuditRequest;
use codex_auditbase_contract::AuditResult;
use codex_auditbase_contract::AuditSnapshot;
use codex_auditbase_contract::AuditStatus;
use codex_auditbase_contract::MAX_RESULT_BYTES;
use codex_auditbase_contract::TerminalAuditStatus;
use codex_auditbase_contract::Validate;
use codex_auditbase_contract::generated_schemas;
use pretty_assertions::assert_eq;

const REQUEST: &str = include_str!("../examples/audit-request.v1.json");
const ACCEPTED: &str = include_str!("../examples/audit-accepted.v1.json");
const SNAPSHOT: &str = include_str!("../examples/audit-snapshot.v1.json");
const COMPLETED_SNAPSHOT: &str = include_str!("../examples/audit-snapshot.completed.v1.json");
const FAILED_SNAPSHOT: &str = include_str!("../examples/audit-snapshot.failed-partial.v1.json");
const API_ERROR: &str = include_str!("../examples/api-error.v1.json");
const CONFIG: &str = include_str!("../examples/audit-config.v1.toml");
const COMPLETED_RESULT: &str = include_str!("../examples/audit-result.completed.v1.json");
const FAILED_RESULT: &str = include_str!("../examples/audit-result.failed-partial.v1.json");
const EVENTS: &str = include_str!("../examples/audit-events.v1.jsonl");

#[test]
fn committed_examples_deserialize_and_validate() {
    validate_json::<AuditRequest>(REQUEST);
    validate_json::<AuditAccepted>(ACCEPTED);
    validate_json::<AuditSnapshot>(SNAPSHOT);
    validate_json::<AuditSnapshot>(COMPLETED_SNAPSHOT);
    validate_json::<AuditSnapshot>(FAILED_SNAPSHOT);
    validate_json::<ApiErrorResponse>(API_ERROR);
    validate_json::<AuditResult>(COMPLETED_RESULT);
    validate_json::<AuditResult>(FAILED_RESULT);

    let config: AuditConfig = toml::from_str(CONFIG).expect("config example should parse");
    config.validate().expect("config example should validate");
}

#[test]
fn event_examples_validate_and_are_ordered_per_audit() {
    let mut last_sequence = HashMap::<String, u64>::new();
    let mut event_ids = HashSet::new();

    for (line_index, line) in EVENTS.lines().enumerate() {
        let event: AuditEvent = serde_json::from_str(line)
            .unwrap_or_else(|error| panic!("event line {} should parse: {error}", line_index + 1));
        event.validate().unwrap_or_else(|error| {
            panic!("event line {} should validate: {error}", line_index + 1)
        });
        assert!(event_ids.insert((event.audit_id.clone(), event.event_id.clone())));
        if let Some(previous) = last_sequence.insert(event.audit_id.clone(), event.sequence) {
            assert!(event.sequence > previous);
        }
    }
}

#[test]
fn completed_audit_may_report_compilation_failure() {
    let result: AuditResult = serde_json::from_str(COMPLETED_RESULT).expect("result should parse");
    assert_eq!(result.status, TerminalAuditStatus::Completed);
    result
        .validate()
        .expect("compilation failure must not force audit failure");
}

#[test]
fn terminal_result_invariants_reject_misleading_states() {
    let mut completed: AuditResult =
        serde_json::from_str(COMPLETED_RESULT).expect("result should parse");
    completed.partial = true;
    assert_eq!(
        completed
            .validate()
            .expect_err("partial completion must fail")
            .field,
        "status"
    );

    let mut failed: AuditResult = serde_json::from_str(FAILED_RESULT).expect("result should parse");
    failed.failure = None;
    assert_eq!(
        failed
            .validate()
            .expect_err("failure details are required")
            .field,
        "failure"
    );
}

#[test]
fn upload_manifest_rejects_traversal_and_duplicate_paths() {
    let mut request: AuditRequest = serde_json::from_str(REQUEST).expect("request should parse");
    request.files[0].path = "../secrets.env".to_string();
    assert_eq!(
        request.validate().expect_err("traversal must fail").field,
        "files[0].path"
    );

    let mut request: AuditRequest = serde_json::from_str(REQUEST).expect("request should parse");
    request.files[1].path = request.files[0].path.clone();
    assert_eq!(
        request
            .validate()
            .expect_err("duplicate paths must fail")
            .field,
        "files.path"
    );
}

#[test]
fn canonical_status_transitions_are_explicit() {
    assert!(AuditStatus::Queued.can_transition_to(AuditStatus::Preparing));
    assert!(AuditStatus::Auditing.can_transition_to(AuditStatus::Failed));
    assert!(AuditStatus::Finalizing.can_transition_to(AuditStatus::Completed));
    assert!(!AuditStatus::Queued.can_transition_to(AuditStatus::Completed));
    assert!(!AuditStatus::Completed.can_transition_to(AuditStatus::Failed));
}

#[test]
fn public_examples_do_not_disclose_backend_model_configuration() {
    for public_payload in [
        REQUEST,
        ACCEPTED,
        SNAPSHOT,
        API_ERROR,
        COMPLETED_RESULT,
        FAILED_RESULT,
        EVENTS,
    ] {
        assert!(!public_payload.contains("\"model\""));
        assert!(!public_payload.contains("reasoningEffort"));
        assert!(!public_payload.contains("reasoning_effort"));
    }
}

#[test]
fn committed_schemas_match_rust_types() {
    for (filename, generated) in generated_schemas() {
        let generated =
            serde_json::to_string_pretty(&generated).expect("generated schema should serialize");
        // Compare the exporter's canonical text. Parsing the largest safe JS
        // integer through serde_json's default floating-point number mode can
        // round `9007199254740991.0` down by one and create false schema drift.
        assert_eq!(
            committed_schema(filename).trim_end(),
            generated,
            "schema drift in {filename}"
        );
    }
}

#[test]
fn audit_event_schema_declares_flattened_type_and_data_properties() {
    let (_, schema) = generated_schemas()
        .into_iter()
        .find(|(filename, _)| *filename == "audit-event.v1.schema.json")
        .expect("audit event schema should be generated");
    let schema = serde_json::to_value(schema).expect("schema should serialize");

    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(schema["properties"]["type"], true);
    assert_eq!(schema["properties"]["data"], true);
    let required = schema["required"]
        .as_array()
        .expect("required should be an array");
    assert!(required.iter().any(|value| value == "type"));
    assert!(required.iter().any(|value| value == "data"));
    assert!(
        schema["oneOf"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
    );
}

#[test]
fn audit_request_schema_rejects_zero_length_guidance() {
    let (_, schema) = generated_schemas()
        .into_iter()
        .find(|(filename, _)| *filename == "audit-request.v1.schema.json")
        .expect("audit request schema should be generated");
    let schema = serde_json::to_value(schema).expect("schema should serialize");

    assert_eq!(schema["properties"]["guidance"]["minLength"], 1);
}

#[test]
fn audit_config_schema_caps_results_at_the_runner_boundary() {
    let (_, schema) = generated_schemas()
        .into_iter()
        .find(|(filename, _)| *filename == "audit-config.v1.schema.json")
        .expect("audit config schema should be generated");
    let schema = serde_json::to_value(schema).expect("schema should serialize");

    assert_eq!(
        schema["definitions"]["ContractLimits"]["properties"]["max_result_bytes"]["maximum"]
            .as_f64(),
        Some(MAX_RESULT_BYTES as f64)
    );
}

#[test]
fn audit_config_schema_exposes_only_the_approved_reasoning_efforts() {
    let (_, schema) = generated_schemas()
        .into_iter()
        .find(|(filename, _)| *filename == "audit-config.v1.schema.json")
        .expect("audit config schema should be generated");
    let schema = serde_json::to_value(schema).expect("schema should serialize");
    let efforts = schema["definitions"]["ReasoningEffort"]["enum"]
        .as_array()
        .expect("reasoning effort enum should be an array")
        .iter()
        .map(|value| value.as_str().expect("reasoning effort should be a string"))
        .collect::<Vec<_>>();

    assert_eq!(efforts, vec!["low", "medium", "high", "xhigh", "max"]);
}

fn validate_json<T>(payload: &str)
where
    T: serde::de::DeserializeOwned + Validate,
{
    let value: T = serde_json::from_str(payload)
        .unwrap_or_else(|error| panic!("example should parse: {error}"));
    value
        .validate()
        .unwrap_or_else(|error| panic!("example should validate: {error}"));
}

fn committed_schema(filename: &str) -> &'static str {
    // Keep committed schemas embedded so drift is detected without filesystem
    // discovery or working-directory assumptions.
    match filename {
        "audit-request.v1.schema.json" => include_str!("../schema/audit-request.v1.schema.json"),
        "audit-accepted.v1.schema.json" => {
            include_str!("../schema/audit-accepted.v1.schema.json")
        }
        "audit-snapshot.v1.schema.json" => {
            include_str!("../schema/audit-snapshot.v1.schema.json")
        }
        "api-error.v1.schema.json" => include_str!("../schema/api-error.v1.schema.json"),
        "audit-event.v1.schema.json" => include_str!("../schema/audit-event.v1.schema.json"),
        "audit-result.v1.schema.json" => include_str!("../schema/audit-result.v1.schema.json"),
        "audit-config.v1.schema.json" => include_str!("../schema/audit-config.v1.schema.json"),
        _ => panic!("unexpected schema fixture: {filename}"),
    }
}
