use std::collections::BTreeSet;

use chrono::DateTime;
use codex_auditbase_contract::AuditCoverage;
use codex_auditbase_contract::AuditResult;
use codex_auditbase_contract::AuditResultSchemaVersion;
use codex_auditbase_contract::AuditSummary;
use codex_auditbase_contract::AuditUsage;
use codex_auditbase_contract::CompilationReport;
use codex_auditbase_contract::Finding;
use codex_auditbase_contract::Limitation;
use codex_auditbase_contract::TerminalAuditStatus;
use codex_auditbase_contract::Validate;
use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;

use crate::RunnerError;

/// The only shape the model may author. Lifecycle, identity, timestamps,
/// usage, failures, provenance, and terminal events are intentionally absent.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModelAuditOutput {
    pub summary: AuditSummary,
    pub findings: Vec<Finding>,
    pub coverage: AuditCoverage,
    pub compilation: CompilationReport,
    #[serde(default)]
    pub limitations: Vec<Limitation>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelOutputContext {
    pub submitted_paths: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedCompletedResultContext {
    pub audit_id: String,
    pub submitted_paths: Vec<String>,
    pub started_at: String,
    pub finished_at: String,
    pub usage: AuditUsage,
}

pub fn parse_model_audit_output(
    bytes: &[u8],
    maximum_bytes: usize,
    context: &ModelOutputContext,
) -> Result<ModelAuditOutput, RunnerError> {
    if bytes.len() > maximum_bytes {
        return Err(RunnerError::ByteLimit {
            kind: "model audit output",
            actual: bytes.len(),
            maximum: maximum_bytes,
        });
    }
    let output: ModelAuditOutput =
        serde_json::from_slice(bytes).map_err(|error| RunnerError::MalformedModelOutput {
            message: error.to_string(),
        })?;
    validate_model_output(&output, context)?;
    Ok(output)
}

pub fn validate_model_output(
    output: &ModelAuditOutput,
    context: &ModelOutputContext,
) -> Result<(), RunnerError> {
    let expected: BTreeSet<&str> = context.submitted_paths.iter().map(String::as_str).collect();
    if expected.len() != context.submitted_paths.len() {
        return Err(RunnerError::model_output(
            "context.submittedPaths",
            "trusted manifest contains duplicate paths",
        ));
    }
    let covered: BTreeSet<&str> = output
        .coverage
        .files
        .iter()
        .map(|file| file.path.as_str())
        .collect();
    if covered != expected {
        return Err(RunnerError::model_output(
            "coverage.files",
            "must exactly cover the trusted submitted path manifest",
        ));
    }

    let temporary = AuditResult {
        schema_version: AuditResultSchemaVersion::V1,
        audit_id: "semantic-validation".to_owned(),
        status: TerminalAuditStatus::Completed,
        partial: false,
        started_at: "1970-01-01T00:00:00.000Z".to_owned(),
        finished_at: "1970-01-01T00:00:00.000Z".to_owned(),
        summary: output.summary.clone(),
        findings: output.findings.clone(),
        coverage: output.coverage.clone(),
        compilation: output.compilation.clone(),
        limitations: output.limitations.clone(),
        usage: AuditUsage::default(),
        failure: None,
    };
    temporary
        .validate()
        .map_err(|error| RunnerError::model_output(error.field, error.message))?;

    for (finding_index, finding) in output.findings.iter().enumerate() {
        for (location_index, location) in finding.locations.iter().enumerate() {
            require_submitted_path(
                &location.path,
                &expected,
                &format!("findings[{finding_index}].locations[{location_index}].path"),
            )?;
        }
        for (evidence_index, evidence) in finding.evidence.iter().enumerate() {
            if let Some(location) = &evidence.location {
                require_submitted_path(
                    &location.path,
                    &expected,
                    &format!("findings[{finding_index}].evidence[{evidence_index}].location.path"),
                )?;
            }
        }
    }
    for (limitation_index, limitation) in output.limitations.iter().enumerate() {
        for (path_index, path) in limitation.affected_paths.iter().enumerate() {
            require_submitted_path(
                path,
                &expected,
                &format!("limitations[{limitation_index}].affectedPaths[{path_index}]"),
            )?;
        }
    }
    Ok(())
}

pub fn build_completed_result(
    output: ModelAuditOutput,
    context: TrustedCompletedResultContext,
) -> Result<AuditResult, RunnerError> {
    validate_model_output(
        &output,
        &ModelOutputContext {
            submitted_paths: context.submitted_paths,
        },
    )?;
    validate_timestamp_order(&context.started_at, &context.finished_at)?;
    if context.audit_id.trim().is_empty() {
        return Err(RunnerError::model_output(
            "trusted.auditId",
            "must not be empty",
        ));
    }

    let result = AuditResult {
        schema_version: AuditResultSchemaVersion::V1,
        audit_id: context.audit_id,
        status: TerminalAuditStatus::Completed,
        partial: false,
        started_at: context.started_at,
        finished_at: context.finished_at,
        summary: output.summary,
        findings: output.findings,
        coverage: output.coverage,
        compilation: output.compilation,
        limitations: output.limitations,
        usage: context.usage,
        failure: None,
    };
    result
        .validate()
        .map_err(|error| RunnerError::model_output(error.field, error.message))?;
    Ok(result)
}

fn require_submitted_path(
    path: &str,
    expected: &BTreeSet<&str>,
    field: &str,
) -> Result<(), RunnerError> {
    if !expected.contains(path) {
        return Err(RunnerError::model_output(
            field,
            "references a path outside the trusted submitted manifest",
        ));
    }
    Ok(())
}

fn validate_timestamp_order(started_at: &str, finished_at: &str) -> Result<(), RunnerError> {
    let started = DateTime::parse_from_rfc3339(started_at).map_err(|error| {
        RunnerError::model_output("trusted.startedAt", format!("invalid RFC 3339: {error}"))
    })?;
    let finished = DateTime::parse_from_rfc3339(finished_at).map_err(|error| {
        RunnerError::model_output("trusted.finishedAt", format!("invalid RFC 3339: {error}"))
    })?;
    if finished < started {
        return Err(RunnerError::model_output(
            "trusted.finishedAt",
            "must not precede startedAt",
        ));
    }
    Ok(())
}
