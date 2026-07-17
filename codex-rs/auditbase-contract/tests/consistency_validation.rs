#![allow(clippy::expect_used)]

use codex_auditbase_contract::AuditConfig;
use codex_auditbase_contract::AuditRequest;
use codex_auditbase_contract::AuditResult;
use codex_auditbase_contract::AuditSnapshot;
use codex_auditbase_contract::Validate;
use codex_auditbase_contract::validate_result_for_job;
use codex_auditbase_contract::validate_snapshot_against_result;
use pretty_assertions::assert_eq;

const REQUEST: &str = include_str!("../examples/audit-request.v1.json");
const CONFIG: &str = include_str!("../examples/audit-config.v1.toml");
const RUNNING_SNAPSHOT: &str = include_str!("../examples/audit-snapshot.v1.json");
const COMPLETED_SNAPSHOT: &str = include_str!("../examples/audit-snapshot.completed.v1.json");
const FAILED_SNAPSHOT: &str = include_str!("../examples/audit-snapshot.failed-partial.v1.json");
const COMPLETED_RESULT: &str = include_str!("../examples/audit-result.completed.v1.json");
const FAILED_RESULT: &str = include_str!("../examples/audit-result.failed-partial.v1.json");

#[test]
fn result_paths_must_map_to_the_submitted_manifest() {
    validate_result_for_job(
        "audit-01-example",
        &completed_request(),
        &completed_result(),
        &limits(),
    )
    .expect("matching request/result should validate");

    let mut result = completed_result();
    result.coverage.files[1].path = "contracts/other.sol".to_string();
    assert_eq!(
        validate_result_for_job("audit-01-example", &completed_request(), &result, &limits(),)
            .expect_err("unknown coverage path must fail")
            .field,
        "coverage.files[1].path"
    );

    let mut result = completed_result();
    result.findings[0].locations[0].path = "contracts/other.sol".to_string();
    assert_eq!(
        validate_result_for_job("audit-01-example", &completed_request(), &result, &limits(),)
            .expect_err("unknown finding path must fail")
            .field,
        "findings[0].locations[0].path"
    );

    let mut result = completed_result();
    result.limitations[0].affected_paths[0] = "contracts/other.sol".to_string();
    assert_eq!(
        validate_result_for_job("audit-01-example", &completed_request(), &result, &limits(),)
            .expect_err("unknown limitation path must fail")
            .field,
        "limitations[0].affectedPaths[0]"
    );
}

#[test]
fn expected_audit_id_is_bound_to_the_result() {
    assert_eq!(
        validate_result_for_job(
            "different-audit",
            &completed_request(),
            &completed_result(),
            &limits(),
        )
        .expect_err("audit ID mismatch must fail")
        .field,
        "auditId"
    );
}

#[test]
fn terminal_snapshots_and_results_must_agree() {
    let completed_snapshot: AuditSnapshot =
        serde_json::from_str(COMPLETED_SNAPSHOT).expect("snapshot should parse");
    validate_snapshot_against_result(&completed_snapshot, Some(&completed_result()))
        .expect("completed snapshot/result should agree");

    let failed_snapshot: AuditSnapshot =
        serde_json::from_str(FAILED_SNAPSHOT).expect("snapshot should parse");
    validate_snapshot_against_result(&failed_snapshot, Some(&failed_result()))
        .expect("failed snapshot/result should agree");

    let mut wrong_result = failed_result();
    wrong_result.audit_id = "another-audit".to_string();
    assert_eq!(
        validate_snapshot_against_result(&failed_snapshot, Some(&wrong_result))
            .expect_err("audit ID mismatch must fail")
            .field,
        "auditId"
    );

    let mut wrong_result = failed_result();
    wrong_result
        .failure
        .as_mut()
        .expect("failure should exist")
        .retryable = false;
    assert_eq!(
        validate_snapshot_against_result(&failed_snapshot, Some(&wrong_result))
            .expect_err("failure mismatch must fail")
            .field,
        "failure"
    );
}

#[test]
fn every_snapshot_status_enforces_result_availability_flags() {
    let mut running: AuditSnapshot =
        serde_json::from_str(RUNNING_SNAPSHOT).expect("snapshot should parse");
    running.partial_results_available = true;
    assert_eq!(
        running
            .validate()
            .expect_err("nonterminal partial flag must fail")
            .field,
        "resultAvailable"
    );

    let mut completed: AuditSnapshot =
        serde_json::from_str(COMPLETED_SNAPSHOT).expect("snapshot should parse");
    completed.partial_results_available = true;
    assert_eq!(
        completed
            .validate()
            .expect_err("completed partial flag must fail")
            .field,
        "status"
    );

    let mut failed: AuditSnapshot =
        serde_json::from_str(FAILED_SNAPSHOT).expect("snapshot should parse");
    failed.result_available = false;
    assert_eq!(
        failed
            .validate()
            .expect_err("failed flags must agree")
            .field,
        "resultAvailable"
    );
}

fn completed_request() -> AuditRequest {
    serde_json::from_str(REQUEST).expect("request should parse")
}

fn completed_result() -> AuditResult {
    serde_json::from_str(COMPLETED_RESULT).expect("result should parse")
}

fn failed_result() -> AuditResult {
    serde_json::from_str(FAILED_RESULT).expect("result should parse")
}

fn limits() -> codex_auditbase_contract::ContractLimits {
    toml::from_str::<AuditConfig>(CONFIG)
        .expect("config should parse")
        .runtime
        .contract_limits
}
