use std::collections::BTreeMap;

use chrono::DateTime;
use codex_auditbase_contract::AuditCoverage;
use codex_auditbase_contract::AuditEvent;
use codex_auditbase_contract::AuditEventPayload;
use codex_auditbase_contract::AuditResult;
use codex_auditbase_contract::AuditResultSchemaVersion;
use codex_auditbase_contract::AuditSummary;
use codex_auditbase_contract::AuditUsage;
use codex_auditbase_contract::CompilationReport;
use codex_auditbase_contract::CompilationStatus;
use codex_auditbase_contract::Failure;
use codex_auditbase_contract::FailureCode;
use codex_auditbase_contract::FileCoverage;
use codex_auditbase_contract::Finding;
use codex_auditbase_contract::FindingCounts;
use codex_auditbase_contract::FindingEventAction;
use codex_auditbase_contract::Limitation;
use codex_auditbase_contract::Severity;
use codex_auditbase_contract::TerminalAuditStatus;
use codex_auditbase_contract::Validate;
use serde::Deserialize;
use serde::Serialize;

use crate::RunnerError;
use crate::accumulator::IngestResult;
use crate::final_output::ModelAuditOutput;
use crate::final_output::ModelOutputContext;
use crate::final_output::validate_model_output;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub enum PartialAuditStateSchemaVersion {
    #[serde(rename = "auditbase.private-partial-state.v1")]
    V1,
}

/// Private crash-recovery state. It contains only validated model content and
/// trusted runner metadata; raw reasoning and tool output are never stored.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrivatePartialAuditState {
    pub schema_version: PartialAuditStateSchemaVersion,
    pub audit_id: String,
    pub provenance_fingerprint_sha256: String,
    pub started_at: String,
    pub updated_at: String,
    pub candidate_summary: Option<AuditSummary>,
    pub findings: Vec<Finding>,
    pub coverage: AuditCoverage,
    pub compilation: CompilationReport,
    pub limitations: Vec<Limitation>,
    pub usage: AuditUsage,
    pub last_sequence: u64,
    pub applied_events: BTreeMap<u64, AuditEvent>,
    pub terminal_event_seen: bool,
}

impl PrivatePartialAuditState {
    pub fn new(
        audit_id: impl Into<String>,
        provenance_fingerprint_sha256: impl Into<String>,
        started_at: impl Into<String>,
        submitted_paths: Vec<String>,
    ) -> Result<Self, RunnerError> {
        let audit_id = audit_id.into();
        let provenance_fingerprint_sha256 = provenance_fingerprint_sha256.into();
        let started_at = started_at.into();
        if audit_id.trim().is_empty() || started_at.trim().is_empty() {
            return checkpoint_error("audit_id and started_at must not be empty");
        }
        if provenance_fingerprint_sha256.len() != 64
            || !provenance_fingerprint_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return checkpoint_error("provenance fingerprint must be a lowercase SHA-256 digest");
        }
        if submitted_paths.is_empty() {
            return checkpoint_error("submitted path manifest must not be empty");
        }
        let files: Vec<FileCoverage> = submitted_paths
            .into_iter()
            .map(|path| FileCoverage {
                path,
                reviewed: false,
                functions_reviewed: Vec::new(),
                notes: Vec::new(),
            })
            .collect();
        let coverage = AuditCoverage {
            submitted_file_count: files.len() as u32,
            reviewed_file_count: 0,
            files,
        };
        let probe = AuditResult {
            schema_version: AuditResultSchemaVersion::V1,
            audit_id: audit_id.clone(),
            status: TerminalAuditStatus::Failed,
            partial: true,
            started_at: started_at.clone(),
            finished_at: started_at.clone(),
            summary: AuditSummary {
                title: "Partial audit".to_owned(),
                executive_summary: "Partial audit state.".to_owned(),
                finding_counts: FindingCounts::default(),
            },
            findings: Vec::new(),
            coverage: coverage.clone(),
            compilation: CompilationReport {
                status: CompilationStatus::NotAttempted,
                commands: Vec::new(),
                diagnostics: Vec::new(),
            },
            limitations: Vec::new(),
            usage: AuditUsage::default(),
            failure: Some(Failure {
                code: FailureCode::Internal,
                message: "Validation probe.".to_owned(),
                retryable: false,
            }),
        };
        probe.validate().map_err(|error| RunnerError::Checkpoint {
            message: error.to_string(),
        })?;

        Ok(Self {
            schema_version: PartialAuditStateSchemaVersion::V1,
            audit_id,
            provenance_fingerprint_sha256,
            started_at: started_at.clone(),
            updated_at: started_at,
            candidate_summary: None,
            findings: Vec::new(),
            coverage,
            compilation: CompilationReport {
                status: CompilationStatus::NotAttempted,
                commands: Vec::new(),
                diagnostics: Vec::new(),
            },
            limitations: Vec::new(),
            usage: AuditUsage::default(),
            last_sequence: 0,
            applied_events: BTreeMap::new(),
            terminal_event_seen: false,
        })
    }

    pub fn apply_event(&mut self, event: AuditEvent) -> Result<IngestResult, RunnerError> {
        event.validate().map_err(|error| RunnerError::Checkpoint {
            message: format!("invalid event: {error}"),
        })?;
        if event.audit_id != self.audit_id {
            return checkpoint_error("event audit_id does not match checkpoint audit_id");
        }
        if let Some(existing) = self.applied_events.get(&event.sequence) {
            return if existing == &event {
                Ok(IngestResult::Duplicate)
            } else {
                checkpoint_error("sequence was replayed with a conflicting event")
            };
        }
        if self
            .applied_events
            .values()
            .any(|existing| existing.event_id == event.event_id)
        {
            return checkpoint_error("event identity was replayed with a conflicting payload");
        }
        if self.terminal_event_seen {
            return checkpoint_error("new event arrived after checkpoint terminal event");
        }
        if event.sequence != self.last_sequence + 1 {
            return checkpoint_error("checkpoint event sequence is not contiguous");
        }

        match &event.payload {
            AuditEventPayload::Finding(update) => {
                let position = self
                    .findings
                    .iter()
                    .position(|finding| finding.id == update.finding.id);
                match (update.action, position) {
                    (FindingEventAction::Discovered, None) => {
                        self.findings.push(update.finding.clone());
                    }
                    (FindingEventAction::Updated, Some(index)) => {
                        self.findings[index] = update.finding.clone();
                    }
                    (FindingEventAction::Discovered, Some(_)) => {
                        return checkpoint_error("finding was discovered more than once");
                    }
                    (FindingEventAction::Updated, None) => {
                        return checkpoint_error("finding was updated before discovery");
                    }
                }
                self.candidate_summary = None;
            }
            AuditEventPayload::Limitation(limitation) => {
                self.limitations.push(limitation.clone());
            }
            AuditEventPayload::Usage(usage) => add_usage(&mut self.usage, usage)?,
            AuditEventPayload::Completed(_) | AuditEventPayload::Failed(_) => {
                self.terminal_event_seen = true;
            }
            AuditEventPayload::Status(_)
            | AuditEventPayload::Progress(_)
            | AuditEventPayload::Log(_) => {}
        }
        self.updated_at = event.occurred_at.clone();
        self.last_sequence = event.sequence;
        self.applied_events.insert(event.sequence, event);
        Ok(IngestResult::Added)
    }

    /// Checkpoints a fully parsed and context-validated model payload. This is
    /// useful if the worker crashes after validation but before persistence.
    pub fn checkpoint_validated_model_output(
        &mut self,
        output: &ModelAuditOutput,
        updated_at: impl Into<String>,
    ) -> Result<(), RunnerError> {
        let paths = self
            .coverage
            .files
            .iter()
            .map(|file| file.path.clone())
            .collect();
        validate_model_output(
            output,
            &ModelOutputContext {
                submitted_paths: paths,
            },
        )?;
        self.candidate_summary = Some(output.summary.clone());
        self.findings = output.findings.clone();
        self.coverage = output.coverage.clone();
        self.compilation = output.compilation.clone();
        self.limitations = output.limitations.clone();
        self.updated_at = updated_at.into();
        Ok(())
    }

    pub fn has_partial_results(&self) -> bool {
        !self.findings.is_empty()
            || self.coverage.reviewed_file_count > 0
            || self.compilation.status != CompilationStatus::NotAttempted
            || !self.limitations.is_empty()
            || self.usage.model_requests > 0
    }

    pub fn synthesize_failed_result(
        &self,
        failure: Failure,
        finished_at: impl Into<String>,
    ) -> Result<AuditResult, RunnerError> {
        let finished_at = finished_at.into();
        validate_timestamp_order(&self.started_at, &finished_at)?;
        if failure.message.trim().is_empty() {
            return checkpoint_error("failure message must not be empty");
        }

        let finding_counts = counts(&self.findings);
        let title = self
            .candidate_summary
            .as_ref()
            .map(|summary| format!("Incomplete: {}", summary.title))
            .unwrap_or_else(|| "Incomplete security audit".to_owned());
        let mut limitations = self.limitations.clone();
        limitations.push(Limitation {
            code: failure_code_token(failure.code).to_owned(),
            message: failure.message.clone(),
            affected_paths: self
                .coverage
                .files
                .iter()
                .filter(|file| !file.reviewed)
                .map(|file| file.path.clone())
                .collect(),
        });
        let result = AuditResult {
            schema_version: AuditResultSchemaVersion::V1,
            audit_id: self.audit_id.clone(),
            status: TerminalAuditStatus::Failed,
            partial: true,
            started_at: self.started_at.clone(),
            finished_at,
            summary: AuditSummary {
                title,
                executive_summary: format!(
                    "The audit did not complete. Validated partial results were retained. {}",
                    failure.message
                ),
                finding_counts,
            },
            findings: self.findings.clone(),
            coverage: self.coverage.clone(),
            compilation: self.compilation.clone(),
            limitations,
            usage: self.usage.clone(),
            failure: Some(failure),
        };
        result.validate().map_err(|error| RunnerError::Checkpoint {
            message: error.to_string(),
        })?;
        Ok(result)
    }
}

fn add_usage(total: &mut AuditUsage, delta: &AuditUsage) -> Result<(), RunnerError> {
    total.input_tokens = checked_add(total.input_tokens, delta.input_tokens, "input_tokens")?;
    total.cached_input_tokens = checked_add(
        total.cached_input_tokens,
        delta.cached_input_tokens,
        "cached_input_tokens",
    )?;
    total.cache_write_input_tokens = checked_add(
        total.cache_write_input_tokens,
        delta.cache_write_input_tokens,
        "cache_write_input_tokens",
    )?;
    total.output_tokens = checked_add(total.output_tokens, delta.output_tokens, "output_tokens")?;
    total.reasoning_output_tokens = checked_add(
        total.reasoning_output_tokens,
        delta.reasoning_output_tokens,
        "reasoning_output_tokens",
    )?;
    total.model_requests = total
        .model_requests
        .checked_add(delta.model_requests)
        .ok_or_else(|| RunnerError::Checkpoint {
            message: "usage model_requests overflowed".to_owned(),
        })?;
    total.duration_ms = checked_add(total.duration_ms, delta.duration_ms, "duration_ms")?;
    Ok(())
}

fn checked_add(left: u64, right: u64, field: &str) -> Result<u64, RunnerError> {
    left.checked_add(right)
        .ok_or_else(|| RunnerError::Checkpoint {
            message: format!("usage {field} overflowed"),
        })
}

fn counts(findings: &[Finding]) -> FindingCounts {
    let mut counts = FindingCounts::default();
    for finding in findings {
        match finding.severity {
            Severity::Critical => counts.critical += 1,
            Severity::High => counts.high += 1,
            Severity::Medium => counts.medium += 1,
            Severity::Low => counts.low += 1,
            Severity::Informational => counts.informational += 1,
        }
    }
    counts
}

fn failure_code_token(code: FailureCode) -> &'static str {
    match code {
        FailureCode::AgentCrash => "agent_crash",
        FailureCode::AuditTimeout => "audit_timeout",
        FailureCode::Cancelled => "cancelled",
        FailureCode::Infrastructure => "infrastructure",
        FailureCode::ModelUnavailable => "model_unavailable",
        FailureCode::InvalidOutput => "invalid_output",
        FailureCode::Internal => "internal",
    }
}

fn validate_timestamp_order(started_at: &str, finished_at: &str) -> Result<(), RunnerError> {
    let started =
        DateTime::parse_from_rfc3339(started_at).map_err(|error| RunnerError::Checkpoint {
            message: format!("invalid started_at timestamp: {error}"),
        })?;
    let finished =
        DateTime::parse_from_rfc3339(finished_at).map_err(|error| RunnerError::Checkpoint {
            message: format!("invalid finished_at timestamp: {error}"),
        })?;
    if finished < started {
        return checkpoint_error("finished_at must not precede started_at");
    }
    Ok(())
}

fn checkpoint_error<T>(message: impl Into<String>) -> Result<T, RunnerError> {
    Err(RunnerError::Checkpoint {
        message: message.into(),
    })
}
