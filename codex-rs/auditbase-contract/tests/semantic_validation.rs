#![allow(clippy::expect_used)]

use codex_auditbase_contract::AuditConfig;
use codex_auditbase_contract::AuditEvent;
use codex_auditbase_contract::AuditEventPayload;
use codex_auditbase_contract::AuditRequest;
use codex_auditbase_contract::AuditResult;
use codex_auditbase_contract::CompilationStatus;
use codex_auditbase_contract::FindingStatus;
use codex_auditbase_contract::JS_MAX_SAFE_INTEGER;
use codex_auditbase_contract::LogEvent;
use codex_auditbase_contract::LogLevel;
use codex_auditbase_contract::LogSource;
use codex_auditbase_contract::MAX_AUDIT_TIMEOUT_MINUTES;
use codex_auditbase_contract::MAX_GUIDANCE_BYTES;
use codex_auditbase_contract::MAX_REQUEST_BYTES;
use codex_auditbase_contract::MAX_RESULT_BYTES;
use codex_auditbase_contract::ReasoningEffort;
use codex_auditbase_contract::Severity;
use codex_auditbase_contract::Validate;
use codex_auditbase_contract::ValidateWithLimits;
use pretty_assertions::assert_eq;

const REQUEST: &str = include_str!("../examples/audit-request.v1.json");
const CONFIG: &str = include_str!("../examples/audit-config.v1.toml");
const COMPLETED_RESULT: &str = include_str!("../examples/audit-result.completed.v1.json");
const FAILED_RESULT: &str = include_str!("../examples/audit-result.failed-partial.v1.json");
const EVENTS: &str = include_str!("../examples/audit-events.v1.jsonl");

#[test]
fn timestamps_are_canonical_utc_milliseconds_and_chronological() {
    for invalid in [
        "2026-07-14 10:00:00.000Z",
        "2026-07-14T10:00:00Z",
        "2026-07-14T10:00:00.00Z",
        "2026-07-14T10:00:00.000z",
        "2026-07-14T12:00:00.000+02:00",
        "2026-07-14T10:00:60.000Z",
    ] {
        let mut result = completed_result();
        result.started_at = invalid.to_string();
        assert_eq!(
            result
                .validate()
                .expect_err("noncanonical timestamp must fail")
                .field,
            "startedAt"
        );
    }

    let mut result = completed_result();
    result.finished_at = "2026-07-14T09:59:59.999Z".to_string();
    assert_eq!(
        result
            .validate()
            .expect_err("time reversal must fail")
            .field,
        "finishedAt"
    );

    let mut result = completed_result();
    result.started_at = "2026-07-14T10:00:00.001Z".to_string();
    result.finished_at = "2026-07-14T10:00:00.002Z".to_string();
    result
        .validate()
        .expect("millisecond ordering should validate");
}

#[test]
fn optional_guidance_is_nonempty_when_present() {
    for invalid in ["", "  \n\t"] {
        let mut request = request_fixture();
        request.guidance = Some(invalid.to_string());
        assert_eq!(
            request
                .validate()
                .expect_err("present guidance must contain non-whitespace text")
                .field,
            "guidance"
        );
    }
}

#[test]
fn every_public_u64_is_bounded_to_json_safe_integer_range() {
    let mut request = request_fixture();
    request.files[0].size_bytes = JS_MAX_SAFE_INTEGER + 1;
    assert_eq!(
        request
            .validate()
            .expect_err("unsafe file size must fail")
            .field,
        "files[0].sizeBytes"
    );

    let mut result = completed_result();
    result.usage.input_tokens = JS_MAX_SAFE_INTEGER + 1;
    assert_eq!(
        result.validate().expect_err("unsafe usage must fail").field,
        "usage.inputTokens"
    );

    let mut event = first_event();
    event.sequence = JS_MAX_SAFE_INTEGER + 1;
    assert_eq!(
        event
            .validate()
            .expect_err("unsafe event sequence must fail")
            .field,
        "sequence"
    );

    let mut config: AuditConfig = toml::from_str(CONFIG).expect("config should parse");
    config.runtime.worker_memory_mib = JS_MAX_SAFE_INTEGER + 1;
    assert_eq!(
        config
            .validate()
            .expect_err("unsafe config integer must fail")
            .field,
        "runtime.worker_memory_mib"
    );
}

#[test]
fn failed_results_are_always_partial() {
    let mut result = failed_result();
    result.partial = false;
    assert_eq!(
        result
            .validate()
            .expect_err("failed nonpartial result must fail")
            .field,
        "partial"
    );
}

#[test]
fn failed_and_partial_compilation_require_typed_limitations() {
    let mut result = completed_result();
    result.limitations.clear();
    assert_eq!(
        result
            .validate()
            .expect_err("failed compilation needs limitation")
            .field,
        "limitations"
    );

    let mut result = completed_result();
    result.compilation.status = CompilationStatus::Partial;
    assert_eq!(
        result
            .validate()
            .expect_err("partial compilation needs its own limitation")
            .field,
        "limitations"
    );
    result.limitations[0].code = "compilation_partial".to_string();
    result
        .validate()
        .expect("partial compilation with typed limitation should validate");
}

#[test]
fn paths_reject_unicode_lowercase_collisions_but_allow_any_extension_and_zero_bytes() {
    let mut request = request_fixture();
    request.files[0].path = "contracts/Äudit.move".to_string();
    request.files[1].path = "contracts/äudit.move".to_string();
    assert_eq!(
        request
            .validate()
            .expect_err("case-folding collision must fail")
            .field,
        "files.path"
    );

    let mut request = request_fixture();
    request.files[0].path = "assets/empty.bin".to_string();
    request.files[0].size_bytes = 0;
    request
        .validate()
        .expect("zero-byte regular files and arbitrary extensions remain valid");

    let mut result = completed_result();
    result.coverage.files[1].path = result.coverage.files[0].path.to_uppercase();
    assert_eq!(
        result
            .validate()
            .expect_err("coverage case-folding collision must fail")
            .field,
        "coverage.files.path"
    );
}

#[test]
fn request_digests_are_canonical_lowercase_sha256() {
    let mut request = request_fixture();
    request.files[0].sha256 = request.files[0].sha256.to_uppercase();
    assert_eq!(
        request
            .validate()
            .expect_err("uppercase digests must fail before cross-language staging")
            .field,
        "files[0].sha256"
    );
}

#[test]
fn informational_status_and_severity_are_coupled() {
    let mut result = completed_result();
    result.findings[0].status = FindingStatus::Informational;
    assert_eq!(
        result.validate().expect_err("mismatch must fail").field,
        "finding.status"
    );

    let mut result = completed_result();
    result.findings[0].severity = Severity::Informational;
    result.summary.finding_counts.high = 0;
    result.summary.finding_counts.informational = 1;
    assert_eq!(
        result.validate().expect_err("mismatch must fail").field,
        "finding.status"
    );
}

#[test]
fn configured_request_result_event_and_nested_limits_are_enforced() {
    let limits = limits();

    let mut request_limit = limits.clone();
    request_limit.max_request_bytes = 1;
    assert_eq!(
        request_fixture()
            .validate_with_limits(&request_limit)
            .expect_err("request size must be bounded")
            .field,
        "request"
    );

    let mut guidance_limit = limits.clone();
    guidance_limit.max_guidance_bytes = 1;
    assert_eq!(
        request_fixture()
            .validate_with_limits(&guidance_limit)
            .expect_err("guidance size must be bounded")
            .field,
        "guidance"
    );

    let mut result_limit = limits.clone();
    result_limit.max_result_bytes = 1;
    assert_eq!(
        completed_result()
            .validate_with_limits(&result_limit)
            .expect_err("result size must be bounded")
            .field,
        "result"
    );

    let mut diagnostic_limit = limits.clone();
    diagnostic_limit.max_diagnostic_item_bytes = 1;
    assert_eq!(
        completed_result()
            .validate_with_limits(&diagnostic_limit)
            .expect_err("diagnostic item must be bounded")
            .field,
        "compilation.diagnostics[0]"
    );

    let mut diagnostics_limit = limits.clone();
    diagnostics_limit.max_diagnostics_bytes = 1;
    assert_eq!(
        completed_result()
            .validate_with_limits(&diagnostics_limit)
            .expect_err("combined diagnostics must be bounded")
            .field,
        "compilation.diagnostics"
    );

    let mut evidence_limit = limits.clone();
    evidence_limit.max_evidence_item_bytes = 1;
    assert_eq!(
        completed_result()
            .validate_with_limits(&evidence_limit)
            .expect_err("evidence item must be bounded")
            .field,
        "finding.evidence[0]"
    );

    let mut evidence_total_limit = limits.clone();
    evidence_total_limit.max_finding_evidence_bytes = 1;
    assert_eq!(
        completed_result()
            .validate_with_limits(&evidence_total_limit)
            .expect_err("combined finding evidence must be bounded")
            .field,
        "finding.evidence"
    );

    let mut event_limit = limits.clone();
    event_limit.max_event_bytes = 1;
    assert_eq!(
        first_event()
            .validate_with_limits(&event_limit)
            .expect_err("event size must be bounded")
            .field,
        "event"
    );

    let mut log_event = first_event();
    log_event.payload = AuditEventPayload::Log(LogEvent {
        level: LogLevel::Info,
        source: LogSource::System,
        message: "long log".to_string(),
    });
    let mut log_limit = limits;
    log_limit.max_log_message_bytes = 1;
    assert_eq!(
        log_event
            .validate_with_limits(&log_limit)
            .expect_err("log message must be bounded")
            .field,
        "data.message"
    );
}

#[test]
fn cache_write_usage_defaults_for_older_payloads() {
    let mut value: serde_json::Value =
        serde_json::from_str(COMPLETED_RESULT).expect("result should parse as JSON");
    value["usage"]
        .as_object_mut()
        .expect("usage should be an object")
        .remove("cacheWriteInputTokens");
    let result: AuditResult = serde_json::from_value(value).expect("older result should parse");
    assert_eq!(result.usage.cache_write_input_tokens, 0);
}

#[test]
fn contract_limit_configuration_is_positive_and_hierarchical() {
    let mut config: AuditConfig = toml::from_str(CONFIG).expect("config should parse");
    config.runtime.contract_limits.max_guidance_bytes =
        config.runtime.contract_limits.max_request_bytes + 1;
    assert_eq!(
        config
            .validate()
            .expect_err("child limit larger than parent must fail")
            .field,
        "runtime.contract_limits.max_guidance_bytes"
    );

    let mut config: AuditConfig = toml::from_str(CONFIG).expect("config should parse");
    config.runtime.contract_limits.max_event_bytes = 0;
    assert_eq!(
        config.validate().expect_err("zero limit must fail").field,
        "runtime.contract_limits.max_event_bytes"
    );
}

#[test]
fn request_and_guidance_caps_match_the_initial_cross_language_boundary() {
    let mut config: AuditConfig = toml::from_str(CONFIG).expect("config should parse");
    config.runtime.contract_limits.max_request_bytes = MAX_REQUEST_BYTES + 1;
    assert_eq!(
        config
            .validate()
            .expect_err("oversized request boundary must fail at config validation")
            .field,
        "runtime.contract_limits.max_request_bytes"
    );

    let mut config: AuditConfig = toml::from_str(CONFIG).expect("config should parse");
    config.runtime.contract_limits.max_guidance_bytes = MAX_GUIDANCE_BYTES + 1;
    assert_eq!(
        config
            .validate()
            .expect_err("oversized guidance boundary must fail at config validation")
            .field,
        "runtime.contract_limits.max_guidance_bytes"
    );
}

#[test]
fn result_cap_matches_the_trusted_runner_output_boundary() {
    let mut config: AuditConfig = toml::from_str(CONFIG).expect("config should parse");
    config.runtime.contract_limits.max_result_bytes = MAX_RESULT_BYTES;
    config
        .validate()
        .expect("the trusted runner's hard result boundary should validate");

    config.runtime.contract_limits.max_result_bytes = MAX_RESULT_BYTES + 1;
    assert_eq!(
        config
            .validate()
            .expect_err("result limit above the trusted runner boundary must fail")
            .field,
        "runtime.contract_limits.max_result_bytes"
    );
}

#[test]
fn tier_reasoning_effort_accepts_exact_xhigh_and_max_and_rejects_unapproved_values() {
    let parsed: AuditConfig = toml::from_str(CONFIG).expect("xhigh should parse");
    assert_eq!(
        parsed
            .tiers
            .get("test")
            .expect("test tier")
            .reasoning_effort,
        ReasoningEffort::XHigh
    );
    assert_eq!(
        serde_json::to_string(&ReasoningEffort::XHigh).expect("xhigh should serialize"),
        "\"xhigh\""
    );

    let max_config = CONFIG.replacen(
        "reasoning_effort = \"xhigh\"",
        "reasoning_effort = \"max\"",
        1,
    );
    let parsed: AuditConfig = toml::from_str(&max_config).expect("max should parse");
    assert_eq!(
        parsed
            .tiers
            .get("test")
            .expect("test tier")
            .reasoning_effort,
        ReasoningEffort::Max
    );
    assert_eq!(
        serde_json::to_string(&ReasoningEffort::Max).expect("max should serialize"),
        "\"max\""
    );

    for unapproved in ["ultra", "x_high"] {
        let invalid = CONFIG.replacen(
            "reasoning_effort = \"xhigh\"",
            &format!("reasoning_effort = \"{unapproved}\""),
            1,
        );
        assert!(
            toml::from_str::<AuditConfig>(&invalid).is_err(),
            "{unapproved} must remain outside the AuditBase V3 boundary"
        );
    }
}

#[test]
fn tier_timeout_leaves_room_inside_the_worker_hard_deadline() {
    let mut config: AuditConfig = toml::from_str(CONFIG).expect("config should parse");
    let tier = config.tiers.get_mut("standard").expect("standard tier");
    tier.audit_timeout_minutes = MAX_AUDIT_TIMEOUT_MINUTES;
    config.validate().expect("maximum timeout should validate");

    let tier = config.tiers.get_mut("standard").expect("standard tier");
    tier.audit_timeout_minutes = MAX_AUDIT_TIMEOUT_MINUTES + 1;
    assert_eq!(
        config
            .validate()
            .expect_err("timeout beyond the worker-safe maximum must fail")
            .field,
        "tiers.standard.audit_timeout_minutes"
    );
}

fn request_fixture() -> AuditRequest {
    serde_json::from_str(REQUEST).expect("request should parse")
}

fn completed_result() -> AuditResult {
    serde_json::from_str(COMPLETED_RESULT).expect("completed result should parse")
}

fn failed_result() -> AuditResult {
    serde_json::from_str(FAILED_RESULT).expect("failed result should parse")
}

fn first_event() -> AuditEvent {
    serde_json::from_str(
        EVENTS
            .lines()
            .next()
            .expect("event fixture should not be empty"),
    )
    .expect("event should parse")
}

fn limits() -> codex_auditbase_contract::ContractLimits {
    toml::from_str::<AuditConfig>(CONFIG)
        .expect("config should parse")
        .runtime
        .contract_limits
}
