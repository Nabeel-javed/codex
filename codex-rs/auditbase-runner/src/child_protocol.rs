use codex_auditbase_contract::AuditResult;
use codex_auditbase_contract::TerminalAuditStatus;
use codex_auditbase_contract::Validate;
use serde::Deserialize;
use serde::Serialize;

use crate::RunnerError;

pub const RUNNER_PROTOCOL_V1: &str = "auditbase.runner.v1";
pub const WORKFLOW_CONTRACT_V1: &str = "auditbase.audit-workflow.v1";
pub const MAX_REQUEST_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerRequestEnvelope {
    pub protocol: String,
    pub kind: RunnerRequestKind,
    pub request: RunnerJobRequest,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunnerRequestKind {
    Run,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerJobRequest {
    pub audit_id: String,
    pub job_ref: String,
    pub workspace_ref: String,
    pub tier_id: String,
    pub config_sha256: String,
    pub contract_version: String,
    pub guidance_ref: Option<String>,
    pub result_ref: String,
    pub partial_result_ref: String,
    pub diagnostics_ref: String,
    pub event_sink_ref: String,
    pub idempotency_key: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustedFixtureScenario {
    Completed,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RunnerOutput {
    AuditEvent {
        protocol: &'static str,
        sequence: u64,
        event: RunnerAuditEvent,
    },
    Terminal {
        protocol: &'static str,
        sequence: u64,
        status: RunnerTerminalStatus,
        #[serde(skip_serializing_if = "Option::is_none")]
        result_ref: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        result_sha256: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        partial_result_ref: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        partial_result_sha256: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        failure_code: Option<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RunnerAuditEvent {
    pub event_id: String,
    pub event_type: RunnerAuditEventType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress_percent: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finding_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limitation_ref: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum RunnerAuditEventType {
    #[serde(rename = "artifact.available")]
    ArtifactAvailable,
    #[serde(rename = "finding.available")]
    FindingAvailable,
    #[serde(rename = "job.started")]
    JobStarted,
    #[serde(rename = "limitation.available")]
    LimitationAvailable,
    #[serde(rename = "phase.completed")]
    PhaseCompleted,
    #[serde(rename = "phase.progress")]
    PhaseProgress,
    #[serde(rename = "phase.started")]
    PhaseStarted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunnerTerminalStatus {
    Completed,
    Failed,
}

pub fn parse_runner_request(bytes: &[u8]) -> Result<RunnerRequestEnvelope, RunnerError> {
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err(RunnerError::ByteLimit {
            kind: "runner child request",
            actual: bytes.len(),
            maximum: MAX_REQUEST_BYTES,
        });
    }
    let text = std::str::from_utf8(bytes).map_err(|error| RunnerError::MalformedModelOutput {
        message: format!("runner request is not UTF-8: {error}"),
    })?;
    let mut nonempty = text.lines().filter(|line| !line.trim().is_empty());
    let line = nonempty
        .next()
        .ok_or_else(|| RunnerError::MalformedModelOutput {
            message: "runner request is empty".to_owned(),
        })?;
    if nonempty.next().is_some() {
        return Err(RunnerError::MalformedModelOutput {
            message: "runner request must contain exactly one JSON line".to_owned(),
        });
    }
    let request: RunnerRequestEnvelope =
        serde_json::from_str(line).map_err(|error| RunnerError::MalformedModelOutput {
            message: format!("invalid runner request: {error}"),
        })?;
    validate_request(&request)?;
    Ok(request)
}

pub fn trusted_fixture_outputs(
    request: &RunnerRequestEnvelope,
    scenario: TrustedFixtureScenario,
    artifact_sha256: &str,
) -> Vec<RunnerOutput> {
    let audit_id = &request.request.audit_id;
    let event_id_prefix = format!("runner-{}", &fixture_digest(audit_id)[..32]);
    let event = |sequence, event_type, phase: Option<&str>| RunnerOutput::AuditEvent {
        protocol: RUNNER_PROTOCOL_V1,
        sequence,
        event: RunnerAuditEvent {
            event_id: format!("{event_id_prefix}-{sequence:020}"),
            event_type,
            phase: phase.map(str::to_owned),
            message: None,
            progress_percent: None,
            artifact_ref: None,
            finding_ref: None,
            limitation_ref: None,
        },
    };
    let mut outputs = vec![
        event(1, RunnerAuditEventType::JobStarted, None),
        event(
            2,
            RunnerAuditEventType::PhaseStarted,
            Some("scripted_fixture"),
        ),
    ];
    match scenario {
        TrustedFixtureScenario::Completed => {
            outputs.push(event(
                3,
                RunnerAuditEventType::PhaseCompleted,
                Some("scripted_fixture"),
            ));
            outputs.push(RunnerOutput::AuditEvent {
                protocol: RUNNER_PROTOCOL_V1,
                sequence: 4,
                event: RunnerAuditEvent {
                    event_id: format!("{event_id_prefix}-{sequence:020}", sequence = 4),
                    event_type: RunnerAuditEventType::ArtifactAvailable,
                    phase: None,
                    message: None,
                    progress_percent: None,
                    artifact_ref: Some(request.request.result_ref.clone()),
                    finding_ref: None,
                    limitation_ref: None,
                },
            });
            outputs.push(RunnerOutput::Terminal {
                protocol: RUNNER_PROTOCOL_V1,
                sequence: 5,
                status: RunnerTerminalStatus::Completed,
                result_ref: Some(request.request.result_ref.clone()),
                result_sha256: Some(artifact_sha256.to_owned()),
                partial_result_ref: None,
                partial_result_sha256: None,
                failure_code: None,
            });
        }
        TrustedFixtureScenario::Failed => {
            outputs.push(RunnerOutput::Terminal {
                protocol: RUNNER_PROTOCOL_V1,
                sequence: 3,
                status: RunnerTerminalStatus::Failed,
                result_ref: None,
                result_sha256: None,
                partial_result_ref: Some(request.request.partial_result_ref.clone()),
                partial_result_sha256: Some(artifact_sha256.to_owned()),
                failure_code: Some("trusted_fixture_failure".to_owned()),
            });
        }
    }
    outputs
}

pub fn production_rejection(_request: &RunnerRequestEnvelope) -> RunnerOutput {
    RunnerOutput::Terminal {
        protocol: RUNNER_PROTOCOL_V1,
        sequence: 1,
        status: RunnerTerminalStatus::Failed,
        result_ref: None,
        result_sha256: None,
        partial_result_ref: None,
        partial_result_sha256: None,
        failure_code: Some("isolation_and_gateway_attestation_required".to_owned()),
    }
}

/// Emits the fixed public prelude for the explicitly enabled trusted-local
/// real runner. Raw prompts, model output, tool arguments and command output
/// are never copied into this protocol.
pub fn trusted_real_start_outputs(request: &RunnerRequestEnvelope) -> [RunnerOutput; 2] {
    [
        trusted_real_event(
            request,
            1,
            RunnerAuditEventType::JobStarted,
            None,
            None,
            None,
        ),
        trusted_real_event(
            request,
            2,
            RunnerAuditEventType::PhaseStarted,
            Some("codex_audit"),
            None,
            None,
        ),
    ]
}

/// Emits the fixed public completion suffix after the exact result bytes have
/// been atomically staged and hashed by the trusted runner.
pub fn trusted_real_completed_outputs(
    request: &RunnerRequestEnvelope,
    artifact_sha256: &str,
    first_sequence: u64,
) -> [RunnerOutput; 3] {
    [
        trusted_real_event(
            request,
            first_sequence,
            RunnerAuditEventType::PhaseCompleted,
            Some("codex_audit"),
            None,
            None,
        ),
        trusted_real_event(
            request,
            first_sequence + 1,
            RunnerAuditEventType::ArtifactAvailable,
            None,
            None,
            Some(request.request.result_ref.clone()),
        ),
        RunnerOutput::Terminal {
            protocol: RUNNER_PROTOCOL_V1,
            sequence: first_sequence + 2,
            status: RunnerTerminalStatus::Completed,
            result_ref: Some(request.request.result_ref.clone()),
            result_sha256: Some(artifact_sha256.to_owned()),
            partial_result_ref: None,
            partial_result_sha256: None,
            failure_code: None,
        },
    ]
}

pub fn trusted_real_progress_output(
    request: &RunnerRequestEnvelope,
    sequence: u64,
) -> RunnerOutput {
    trusted_real_event(
        request,
        sequence,
        RunnerAuditEventType::PhaseProgress,
        Some("codex_audit"),
        Some(0),
        None,
    )
}

pub fn trusted_real_failed_output(failure_code: &str, sequence: u64) -> RunnerOutput {
    RunnerOutput::Terminal {
        protocol: RUNNER_PROTOCOL_V1,
        sequence,
        status: RunnerTerminalStatus::Failed,
        result_ref: None,
        result_sha256: None,
        partial_result_ref: None,
        partial_result_sha256: None,
        failure_code: Some(failure_code.to_owned()),
    }
}

pub fn trusted_real_failed_output_with_partial(
    failure_code: &str,
    sequence: u64,
    partial_result_ref: &str,
    partial_result_sha256: &str,
) -> RunnerOutput {
    RunnerOutput::Terminal {
        protocol: RUNNER_PROTOCOL_V1,
        sequence,
        status: RunnerTerminalStatus::Failed,
        result_ref: None,
        result_sha256: None,
        partial_result_ref: Some(partial_result_ref.to_owned()),
        partial_result_sha256: Some(partial_result_sha256.to_owned()),
        failure_code: Some(failure_code.to_owned()),
    }
}

fn trusted_real_event(
    request: &RunnerRequestEnvelope,
    sequence: u64,
    event_type: RunnerAuditEventType,
    phase: Option<&str>,
    progress_percent: Option<u8>,
    artifact_ref: Option<String>,
) -> RunnerOutput {
    let digest = fixture_digest(&request.request.audit_id);
    RunnerOutput::AuditEvent {
        protocol: RUNNER_PROTOCOL_V1,
        sequence,
        event: RunnerAuditEvent {
            event_id: format!("runner-{}-{sequence:020}", &digest[..32]),
            event_type,
            phase: phase.map(str::to_owned),
            message: None,
            progress_percent,
            artifact_ref,
            finding_ref: None,
            limitation_ref: None,
        },
    }
}

/// Validates and hashes the exact staged public artifact bytes used by the
/// local-only fixture child. A fixture cannot claim completion from a
/// reference or caller-provided digest alone.
pub fn validate_trusted_fixture_artifact(
    bytes: &[u8],
    maximum_bytes: usize,
    request: &RunnerRequestEnvelope,
    scenario: TrustedFixtureScenario,
) -> Result<String, RunnerError> {
    if bytes.len() > maximum_bytes {
        return Err(RunnerError::ByteLimit {
            kind: "trusted fixture AuditResult artifact",
            actual: bytes.len(),
            maximum: maximum_bytes,
        });
    }
    let result: AuditResult =
        serde_json::from_slice(bytes).map_err(|error| RunnerError::MalformedModelOutput {
            message: format!("fixture artifact is not an AuditResult: {error}"),
        })?;
    result
        .validate()
        .map_err(|error| RunnerError::InvalidModelOutput {
            field: error.field,
            message: error.message,
        })?;
    if result.audit_id != request.request.audit_id {
        return invalid_request("fixture artifact audit_id does not match the request".to_owned());
    }
    let expected = match scenario {
        TrustedFixtureScenario::Completed => TerminalAuditStatus::Completed,
        TrustedFixtureScenario::Failed => TerminalAuditStatus::Failed,
    };
    if result.status != expected {
        return invalid_request(
            "fixture artifact terminal status does not match the scenario".to_owned(),
        );
    }
    if scenario == TrustedFixtureScenario::Failed && !result.partial {
        return invalid_request("failed fixture artifact must retain partial state".to_owned());
    }
    Ok(bytes_sha256(bytes))
}

fn fixture_digest(reference: &str) -> String {
    bytes_sha256(reference.as_bytes())
}

fn bytes_sha256(bytes: &[u8]) -> String {
    use sha2::Digest;

    let digest = sha2::Sha256::digest(bytes);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn validate_request(request: &RunnerRequestEnvelope) -> Result<(), RunnerError> {
    if request.protocol != RUNNER_PROTOCOL_V1 {
        return Err(RunnerError::MalformedModelOutput {
            message: "unsupported runner protocol".to_owned(),
        });
    }
    require_identifier(&request.request.audit_id, "audit_id")?;
    require_identifier(&request.request.tier_id, "tier_id")?;
    require_identifier(&request.request.idempotency_key, "idempotency_key")?;
    require_version(&request.request.contract_version, "contract_version")?;
    if request.request.contract_version != WORKFLOW_CONTRACT_V1 {
        return invalid_request("unsupported workflow contract version".to_owned());
    }
    for (field, value) in [
        ("job_ref", request.request.job_ref.as_str()),
        ("workspace_ref", request.request.workspace_ref.as_str()),
        ("result_ref", request.request.result_ref.as_str()),
        (
            "partial_result_ref",
            request.request.partial_result_ref.as_str(),
        ),
        ("diagnostics_ref", request.request.diagnostics_ref.as_str()),
        ("event_sink_ref", request.request.event_sink_ref.as_str()),
    ] {
        require_reference(value, field)?;
    }
    if request.request.config_sha256.len() != 64
        || !request
            .request
            .config_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(RunnerError::MalformedModelOutput {
            message: "config_sha256 must be a lowercase SHA-256 digest".to_owned(),
        });
    }
    if let Some(guidance_ref) = &request.request.guidance_ref {
        require_reference(guidance_ref, "guidance_ref")?;
    }
    Ok(())
}

fn require_identifier(value: &str, field: &str) -> Result<(), RunnerError> {
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
        })
    {
        return invalid_request(format!("{field} must be a bounded identifier"));
    }
    Ok(())
}

fn require_version(value: &str, field: &str) -> Result<(), RunnerError> {
    if value.is_empty()
        || value.len() > 64
        || !value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
        })
    {
        return invalid_request(format!("{field} must be a bounded version"));
    }
    Ok(())
}

fn require_reference(value: &str, field: &str) -> Result<(), RunnerError> {
    if value.len() > 511 {
        return invalid_request(format!("{field} must be an opaque reference"));
    }
    let Some((scheme, suffix)) = value.split_once(':') else {
        return invalid_request(format!("{field} must be an opaque reference"));
    };
    let valid_scheme = (2..=32).contains(&scheme.len())
        && scheme.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase() || (index > 0 && (byte.is_ascii_digit() || byte == b'-'))
        });
    let valid_suffix = !suffix.is_empty()
        && suffix.len() <= 479
        && suffix.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'.' | b'_' | b'/' | b'-'))
        })
        && !suffix.split('/').any(|segment| segment == "..");
    if !valid_scheme || !valid_suffix || value.contains("://") {
        return invalid_request(format!("{field} must be an opaque reference"));
    }
    Ok(())
}

fn invalid_request<T>(message: String) -> Result<T, RunnerError> {
    Err(RunnerError::MalformedModelOutput { message })
}
