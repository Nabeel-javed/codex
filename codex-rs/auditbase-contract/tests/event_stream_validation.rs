#![allow(clippy::expect_used)]

use std::collections::BTreeMap;

use codex_auditbase_contract::AuditConfig;
use codex_auditbase_contract::AuditEvent;
use codex_auditbase_contract::AuditEventPayload;
use codex_auditbase_contract::AuditResult;
use codex_auditbase_contract::AuditSnapshot;
use codex_auditbase_contract::FindingEventAction;
use codex_auditbase_contract::validate_event_stream;
use pretty_assertions::assert_eq;

const CONFIG: &str = include_str!("../examples/audit-config.v1.toml");
const EVENTS: &str = include_str!("../examples/audit-events.v1.jsonl");
const COMPLETED_SNAPSHOT: &str = include_str!("../examples/audit-snapshot.completed.v1.json");
const FAILED_SNAPSHOT: &str = include_str!("../examples/audit-snapshot.failed-partial.v1.json");
const COMPLETED_RESULT: &str = include_str!("../examples/audit-result.completed.v1.json");
const FAILED_RESULT: &str = include_str!("../examples/audit-result.failed-partial.v1.json");

#[test]
fn committed_success_and_failure_streams_are_complete() {
    let streams = streams();
    validate_event_stream(
        &streams["audit-01-example"],
        Some(&completed_result()),
        Some(&completed_snapshot()),
        &limits(),
    )
    .expect("success stream should validate");
    validate_event_stream(
        &streams["audit-02-example"],
        Some(&failed_result()),
        Some(&failed_snapshot()),
        &limits(),
    )
    .expect("failed partial stream should validate");
}

#[test]
fn event_ids_sequences_and_timestamps_are_monotonic_and_unique() {
    let original = streams()["audit-01-example"].clone();

    let mut events = original.clone();
    events[1].sequence = events[0].sequence;
    assert_eq!(
        validate_event_stream(&events, Some(&completed_result()), None, &limits())
            .expect_err("duplicate sequence must fail")
            .field,
        "events[1].sequence"
    );

    let mut events = original.clone();
    events[1].sequence = 3;
    assert_eq!(
        validate_event_stream(&events, Some(&completed_result()), None, &limits())
            .expect_err("sequence gap must fail")
            .field,
        "events[1].sequence"
    );

    let mut events = original.clone();
    events[1].event_id = events[0].event_id.clone();
    assert_eq!(
        validate_event_stream(&events, Some(&completed_result()), None, &limits())
            .expect_err("duplicate event ID must fail")
            .field,
        "events[1].eventId"
    );

    let mut events = original;
    events[1].occurred_at = "2026-07-14T09:59:59.000Z".to_string();
    assert_eq!(
        validate_event_stream(&events, Some(&completed_result()), None, &limits())
            .expect_err("timestamp regression must fail")
            .field,
        "events[1].occurredAt"
    );
}

#[test]
fn status_transitions_are_contiguous_and_terminal_once() {
    let original = streams()["audit-01-example"].clone();

    let mut events = original.clone();
    let AuditEventPayload::Status(status) = &mut events[3].payload else {
        panic!("fixture index should be a status event");
    };
    status.previous = Some(codex_auditbase_contract::AuditStatus::Queued);
    status.status = codex_auditbase_contract::AuditStatus::Preparing;
    assert_eq!(
        validate_event_stream(&events, Some(&completed_result()), None, &limits())
            .expect_err("disconnected status transition must fail")
            .field,
        "events[3].data.previous"
    );

    let mut events = original;
    events.pop();
    assert_eq!(
        validate_event_stream(&events, Some(&completed_result()), None, &limits())
            .expect_err("missing terminal payload must fail")
            .field,
        "events"
    );
}

#[test]
fn finding_updates_require_discovery_and_final_state_must_match() {
    let original = streams()["audit-01-example"].clone();

    let mut events = original.clone();
    let AuditEventPayload::Finding(finding) = &mut events[4].payload else {
        panic!("fixture index should be a finding event");
    };
    finding.action = FindingEventAction::Updated;
    assert_eq!(
        validate_event_stream(&events, Some(&completed_result()), None, &limits())
            .expect_err("update before discovery must fail")
            .field,
        "events[4].data.finding.id"
    );

    let mut events = original.clone();
    events[1].payload = events[4].payload.clone();
    assert_eq!(
        validate_event_stream(&events, Some(&completed_result()), None, &limits())
            .expect_err("duplicate discovery must fail")
            .field,
        "events[4].data.finding.id"
    );

    let mut result = completed_result();
    result.findings[0].title = "Different final title".to_string();
    assert_eq!(
        validate_event_stream(&original, Some(&result), None, &limits())
            .expect_err("final finding state mismatch must fail")
            .field,
        "result.findings"
    );
}

#[test]
fn result_finding_order_limitations_and_usage_must_match_the_stream() {
    let original = streams()["audit-01-example"].clone();

    let mut result = completed_result();
    result.limitations[0].message.push_str(" changed");
    assert_eq!(
        validate_event_stream(&original, Some(&result), None, &limits())
            .expect_err("limitation mismatch must fail")
            .field,
        "result.limitations"
    );

    let mut result = completed_result();
    result.usage.input_tokens += 1;
    assert_eq!(
        validate_event_stream(&original, Some(&result), None, &limits())
            .expect_err("usage mismatch must fail")
            .field,
        "result.usage"
    );

    let mut events = original;
    let mut second_event = events[4].clone();
    second_event.event_id = "event-finding-second".to_string();
    let AuditEventPayload::Finding(second_finding) = &mut second_event.payload else {
        panic!("fixture index should be a finding event");
    };
    second_finding.finding.id = "finding-auth-002".to_string();
    events.insert(5, second_event);
    for (index, event) in events.iter_mut().enumerate() {
        event.sequence = index as u64 + 1;
    }

    let mut result = completed_result();
    let mut second_finding = result.findings[0].clone();
    second_finding.id = "finding-auth-002".to_string();
    result.findings.push(second_finding);
    result.summary.finding_counts.high = 2;
    validate_event_stream(&events, Some(&result), None, &limits())
        .expect("matching discovery order should validate");
    result.findings.swap(0, 1);
    assert_eq!(
        validate_event_stream(&events, Some(&result), None, &limits())
            .expect_err("finding order mismatch must fail")
            .field,
        "result.findings"
    );
}

#[test]
fn terminal_payload_snapshot_and_result_must_agree() {
    let events = streams()["audit-02-example"].clone();
    assert_eq!(
        validate_event_stream(&events, None, Some(&failed_snapshot()), &limits())
            .expect_err("partial flag without result must fail")
            .field,
        "events[6].data.partialResultsAvailable"
    );

    let mut snapshot = failed_snapshot();
    snapshot.audit_id = "different-audit".to_string();
    assert_eq!(
        validate_event_stream(&events, Some(&failed_result()), Some(&snapshot), &limits(),)
            .expect_err("snapshot audit ID mismatch must fail")
            .field,
        "snapshot.auditId"
    );
}

fn streams() -> BTreeMap<String, Vec<AuditEvent>> {
    let mut streams = BTreeMap::<String, Vec<AuditEvent>>::new();
    for line in EVENTS.lines() {
        let event: AuditEvent = serde_json::from_str(line).expect("event should parse");
        streams
            .entry(event.audit_id.clone())
            .or_default()
            .push(event);
    }
    streams
}

fn completed_result() -> AuditResult {
    serde_json::from_str(COMPLETED_RESULT).expect("result should parse")
}

fn failed_result() -> AuditResult {
    serde_json::from_str(FAILED_RESULT).expect("result should parse")
}

fn completed_snapshot() -> AuditSnapshot {
    serde_json::from_str(COMPLETED_SNAPSHOT).expect("snapshot should parse")
}

fn failed_snapshot() -> AuditSnapshot {
    serde_json::from_str(FAILED_SNAPSHOT).expect("snapshot should parse")
}

fn limits() -> codex_auditbase_contract::ContractLimits {
    toml::from_str::<AuditConfig>(CONFIG)
        .expect("config should parse")
        .runtime
        .contract_limits
}
