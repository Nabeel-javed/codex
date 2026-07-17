use std::collections::BTreeSet;

use codex_auditbase_contract::AuditResult;
use codex_auditbase_contract::TerminalAuditStatus;
use codex_auditbase_contract::Validate;
use codex_auditbase_contract::ValidateWithLimits;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;

use crate::EvaluationManifest;
use crate::ManifestError;
use crate::RunKey;
use crate::canonical_sha256;
use crate::sha256_hex;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunBinding {
    pub expected_audit_id: String,
    pub observed_source_sha256: String,
    pub observed_scoped_paths_sha256: String,
    pub observed_truth_set_sha256: String,
    pub observed_arm_config_sha256: String,
    pub observed_run_provenance_sha256: String,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidRunDisposition {
    Completed,
    FailedPartial,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InvalidStage {
    MissingArtifact,
    JsonSyntax,
    Deserialize,
    ContractSemanticValidation,
    ArtifactLimits,
    BenchmarkProfileValidation,
    ProvenanceMismatch,
    CaseBindingMismatch,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", tag = "kind", deny_unknown_fields)]
pub enum RunOutcome {
    Valid {
        result: Box<AuditResult>,
        disposition: ValidRunDisposition,
    },
    Invalid {
        stage: InvalidStage,
        code: String,
        detail: String,
    },
    VoidBeforeStart {
        infrastructure_reason: String,
    },
}

/// An evaluator run produced by the trusted ingestion boundary.
///
/// The fields are deliberately private and this type is not deserializable:
/// callers cannot manufacture a scoreable run that bypasses [`ingest_result`]
/// and its contract, limit, provenance, and case-binding checks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvaluationRun {
    pub(crate) key: RunKey,
    pub(crate) attempt: u32,
    pub(crate) arm_config_sha256: String,
    pub(crate) run_provenance_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) artifact_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) artifact_bytes: Option<u64>,
    pub(crate) outcome: RunOutcome,
}

impl EvaluationRun {
    pub fn key(&self) -> &RunKey {
        &self.key
    }

    pub fn attempt(&self) -> u32 {
        self.attempt
    }

    pub fn arm_config_sha256(&self) -> &str {
        &self.arm_config_sha256
    }

    pub fn run_provenance_sha256(&self) -> &str {
        &self.run_provenance_sha256
    }

    pub fn artifact_sha256(&self) -> Option<&str> {
        self.artifact_sha256.as_deref()
    }

    pub fn artifact_bytes(&self) -> Option<u64> {
        self.artifact_bytes
    }

    pub fn outcome(&self) -> &RunOutcome {
        &self.outcome
    }
}

/// A run selected from a complete, contiguous attempt trace under the frozen
/// manifest retry policy. Its fields are intentionally private so scoring
/// cannot accept a caller-selected retry directly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptedRun {
    run: EvaluationRun,
    attempt_trace_sha256: String,
}

impl AcceptedRun {
    pub fn run(&self) -> &EvaluationRun {
        &self.run
    }

    pub fn attempt_trace_sha256(&self) -> &str {
        &self.attempt_trace_sha256
    }
}

#[derive(Debug, Error)]
pub enum IngestSetupError {
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    #[error("run is not pre-registered: {0:?}")]
    UnscheduledRun(RunKey),
    #[error("unknown case: {0}")]
    UnknownCase(String),
    #[error("unknown arm: {0}")]
    UnknownArm(String),
    #[error("expected audit ID must not be empty")]
    EmptyAuditId,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RetrySelectionError {
    #[error("evaluator manifest is invalid: {0}")]
    InvalidManifest(String),
    #[error("run is not pre-registered: {0:?}")]
    UnscheduledRun(RunKey),
    #[error("attempt trace is empty for run: {0:?}")]
    EmptyTrace(RunKey),
    #[error("attempt trace contains a different run key")]
    WrongRunKey,
    #[error("attempt {0} appears more than once")]
    DuplicateAttempt(u32),
    #[error("attempt trace must be contiguous; expected {expected}, found {actual}")]
    NonContiguousAttempt { expected: u32, actual: u32 },
    #[error("attempt {attempt} exceeds retryPolicy.maxAttempts={max_attempts}")]
    AttemptLimit { attempt: u32, max_attempts: u32 },
    #[error("attempt trace contains an attempt after the first non-void outcome")]
    AttemptAfterAccepted,
    #[error("void-before-start attempt has invalid arm provenance or an empty reason")]
    InvalidVoidAttempt,
    #[error("retry policy permits another attempt")]
    RetriesRemaining,
    #[error("every permitted attempt was void before start; evaluation cannot be scored")]
    RetriesExhausted,
    #[error("failed to hash the accepted attempt trace: {0}")]
    TraceHash(String),
}

pub fn ingest_result(
    manifest: &EvaluationManifest,
    key: RunKey,
    attempt: u32,
    binding: &RunBinding,
    bytes: Option<&[u8]>,
) -> Result<EvaluationRun, IngestSetupError> {
    manifest.validate()?;
    if !manifest.is_scheduled(&key) {
        return Err(IngestSetupError::UnscheduledRun(key));
    }
    if binding.expected_audit_id.trim().is_empty() {
        return Err(IngestSetupError::EmptyAuditId);
    }
    let case = manifest
        .case(&key.case_id)
        .ok_or_else(|| IngestSetupError::UnknownCase(key.case_id.clone()))?;
    let arm = manifest
        .arm(&key.arm_id)
        .ok_or_else(|| IngestSetupError::UnknownArm(key.arm_id.clone()))?;

    let arm_config_sha256 = binding.observed_arm_config_sha256.clone();
    let run_provenance_sha256 = binding.observed_run_provenance_sha256.clone();
    let artifact_sha256 = bytes.map(sha256_hex);
    let artifact_bytes = bytes.and_then(|bytes| u64::try_from(bytes.len()).ok());
    let base = |outcome| EvaluationRun {
        key: key.clone(),
        attempt,
        arm_config_sha256: arm_config_sha256.clone(),
        run_provenance_sha256: run_provenance_sha256.clone(),
        artifact_sha256: artifact_sha256.clone(),
        artifact_bytes,
        outcome,
    };
    let invalid = |stage, code: &str, detail: String| {
        base(RunOutcome::Invalid {
            stage,
            code: code.to_owned(),
            detail,
        })
    };

    if let Some(bytes) = bytes
        && u64::try_from(bytes.len()).map_or(true, |length| {
            length > manifest.contract_limits.max_result_bytes
        })
    {
        return Ok(invalid(
            InvalidStage::ArtifactLimits,
            "result_byte_limit_exceeded",
            format!(
                "result artifact exceeds the frozen {} byte limit",
                manifest.contract_limits.max_result_bytes
            ),
        ));
    }

    if binding.observed_arm_config_sha256 != arm.arm_config_sha256 {
        return Ok(invalid(
            InvalidStage::ProvenanceMismatch,
            "arm_config_hash_mismatch",
            "observed arm configuration digest differs from the pre-registered arm".to_owned(),
        ));
    }
    if !is_lower_sha256(&binding.observed_run_provenance_sha256) {
        return Ok(invalid(
            InvalidStage::ProvenanceMismatch,
            "invalid_run_provenance_hash",
            "observed run provenance fingerprint is not a lowercase SHA-256 digest".to_owned(),
        ));
    }
    let bindings = [
        (
            "source_sha256",
            &binding.observed_source_sha256,
            &case.source_sha256,
        ),
        (
            "scoped_paths_sha256",
            &binding.observed_scoped_paths_sha256,
            &case.scoped_paths_sha256,
        ),
        (
            "truth_set_sha256",
            &binding.observed_truth_set_sha256,
            &case.truth_set_sha256,
        ),
    ];
    if let Some((name, _, _)) = bindings
        .iter()
        .find(|(_, observed, expected)| observed != expected)
    {
        return Ok(invalid(
            InvalidStage::CaseBindingMismatch,
            "case_hash_mismatch",
            format!("observed {name} differs from the pre-registered case"),
        ));
    }

    let Some(bytes) = bytes else {
        return Ok(invalid(
            InvalidStage::MissingArtifact,
            "missing_result",
            "the run did not produce a final AuditResult artifact".to_owned(),
        ));
    };

    let value: serde_json::Value = match serde_json::from_slice(bytes) {
        Ok(value) => value,
        Err(error) => {
            return Ok(invalid(
                InvalidStage::JsonSyntax,
                "invalid_json",
                error.to_string(),
            ));
        }
    };
    let result: AuditResult = match serde_json::from_value(value) {
        Ok(result) => result,
        Err(error) => {
            return Ok(invalid(
                InvalidStage::Deserialize,
                "contract_deserialize_failed",
                error.to_string(),
            ));
        }
    };
    if let Err(error) = result.validate() {
        return Ok(invalid(
            InvalidStage::ContractSemanticValidation,
            "contract_semantic_validation_failed",
            error.to_string(),
        ));
    }
    if let Err(error) = result.validate_with_limits(&manifest.contract_limits) {
        return Ok(invalid(
            InvalidStage::ArtifactLimits,
            "contract_limits_exceeded",
            error.to_string(),
        ));
    }
    if result.audit_id != binding.expected_audit_id {
        return Ok(invalid(
            InvalidStage::CaseBindingMismatch,
            "audit_id_mismatch",
            "result auditId does not match the scheduled run".to_owned(),
        ));
    }

    let expected_paths: BTreeSet<_> = case.scoped_paths.iter().cloned().collect();
    let actual_paths: BTreeSet<_> = result
        .coverage
        .files
        .iter()
        .map(|file| file.path.clone())
        .collect();
    if actual_paths != expected_paths {
        return Ok(invalid(
            InvalidStage::BenchmarkProfileValidation,
            "coverage_scope_mismatch",
            "result coverage paths do not exactly match the frozen scope".to_owned(),
        ));
    }

    let disposition = match result.status {
        TerminalAuditStatus::Completed => ValidRunDisposition::Completed,
        TerminalAuditStatus::Failed => ValidRunDisposition::FailedPartial,
    };

    Ok(base(RunOutcome::Valid {
        result: Box::new(result),
        disposition,
    }))
}

/// Select the only scoreable attempt for a scheduled run. Attempts must begin
/// at zero and be contiguous. A retry is legal only after a trusted
/// `VoidBeforeStart`; the first non-void outcome is final and later attempts
/// are rejected rather than cherry-picked.
pub fn select_accepted_attempt(
    manifest: &EvaluationManifest,
    key: &RunKey,
    attempts: &[EvaluationRun],
) -> Result<AcceptedRun, RetrySelectionError> {
    manifest
        .validate()
        .map_err(|error| RetrySelectionError::InvalidManifest(error.to_string()))?;
    if !manifest.is_scheduled(key) {
        return Err(RetrySelectionError::UnscheduledRun(key.clone()));
    }
    if attempts.is_empty() {
        return Err(RetrySelectionError::EmptyTrace(key.clone()));
    }

    let arm = manifest
        .arm(&key.arm_id)
        .ok_or_else(|| RetrySelectionError::UnscheduledRun(key.clone()))?;
    let mut ordered: Vec<_> = attempts.iter().collect();
    ordered.sort_by_key(|run| run.attempt);
    for (index, run) in ordered.iter().enumerate() {
        if &run.key != key {
            return Err(RetrySelectionError::WrongRunKey);
        }
        let expected = u32::try_from(index).map_err(|_| RetrySelectionError::AttemptLimit {
            attempt: run.attempt,
            max_attempts: manifest.retry_policy.max_attempts,
        })?;
        if index > 0 && ordered[index - 1].attempt == run.attempt {
            return Err(RetrySelectionError::DuplicateAttempt(run.attempt));
        }
        if run.attempt != expected {
            return Err(RetrySelectionError::NonContiguousAttempt {
                expected,
                actual: run.attempt,
            });
        }
        if run.attempt >= manifest.retry_policy.max_attempts {
            return Err(RetrySelectionError::AttemptLimit {
                attempt: run.attempt,
                max_attempts: manifest.retry_policy.max_attempts,
            });
        }
        if let RunOutcome::VoidBeforeStart {
            infrastructure_reason,
        } = &run.outcome
            && (infrastructure_reason.trim().is_empty()
                || run.arm_config_sha256 != arm.arm_config_sha256
                || !is_lower_sha256(&run.run_provenance_sha256))
        {
            return Err(RetrySelectionError::InvalidVoidAttempt);
        }
    }

    if let Some((accepted_index, _)) = ordered
        .iter()
        .enumerate()
        .find(|(_, run)| !matches!(run.outcome, RunOutcome::VoidBeforeStart { .. }))
    {
        if accepted_index + 1 != ordered.len() {
            return Err(RetrySelectionError::AttemptAfterAccepted);
        }
        let attempt_trace_sha256 = canonical_sha256(&ordered)
            .map_err(|error| RetrySelectionError::TraceHash(error.to_string()))?;
        return Ok(AcceptedRun {
            run: ordered[accepted_index].clone(),
            attempt_trace_sha256,
        });
    }

    if ordered.len() < manifest.retry_policy.max_attempts as usize {
        Err(RetrySelectionError::RetriesRemaining)
    } else {
        Err(RetrySelectionError::RetriesExhausted)
    }
}

/// Records an infrastructure failure that the trusted scheduler observed
/// before the model/agent started. This must not be used to relabel a started
/// or completed attempt as retryable.
pub fn void_before_start(
    key: RunKey,
    attempt: u32,
    arm_config_sha256: String,
    run_provenance_sha256: String,
    reason: impl Into<String>,
) -> EvaluationRun {
    EvaluationRun {
        key,
        attempt,
        arm_config_sha256,
        run_provenance_sha256,
        artifact_sha256: None,
        artifact_bytes: None,
        outcome: RunOutcome::VoidBeforeStart {
            infrastructure_reason: reason.into(),
        },
    }
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
