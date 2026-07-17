use std::cmp::Ordering;

use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;

use crate::ContractLimits;
use crate::Finding;
use crate::Validate;
use crate::ValidateWithLimits;
use crate::ValidationError;
use crate::validation::require_js_safe_u64;
use crate::validation::require_max_bytes;
use crate::validation::require_nonempty;
use crate::validation::require_relative_path;
use crate::validation::require_rfc3339;
use crate::validation::require_serialized_max_bytes;
use crate::validation::require_token;
use crate::validation::require_total_string_bytes;
use crate::validation::require_unique;
use crate::validation::require_unique_unicode_lowercase;

pub const LIMITATION_COMPILATION_FAILED: &str = "compilation_failed";
pub const LIMITATION_COMPILATION_PARTIAL: &str = "compilation_partial";

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
pub enum AuditResultSchemaVersion {
    #[serde(rename = "auditbase.audit-result.v1")]
    V1,
}

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalAuditStatus {
    Completed,
    Failed,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditResult {
    pub schema_version: AuditResultSchemaVersion,
    pub audit_id: String,
    pub status: TerminalAuditStatus,
    pub partial: bool,
    #[schemars(regex(
        pattern = r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$"
    ))]
    pub started_at: String,
    #[schemars(regex(
        pattern = r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$"
    ))]
    pub finished_at: String,
    pub summary: AuditSummary,
    pub findings: Vec<Finding>,
    pub coverage: AuditCoverage,
    pub compilation: CompilationReport,
    #[serde(default)]
    pub limitations: Vec<Limitation>,
    pub usage: AuditUsage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<Failure>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditSummary {
    pub title: String,
    pub executive_summary: String,
    pub finding_counts: FindingCounts,
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingCounts {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub informational: u32,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditCoverage {
    pub submitted_file_count: u32,
    pub reviewed_file_count: u32,
    pub files: Vec<FileCoverage>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileCoverage {
    pub path: String,
    pub reviewed: bool,
    #[serde(default)]
    pub functions_reviewed: Vec<String>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompilationStatus {
    NotAttempted,
    Succeeded,
    Failed,
    Partial,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompilationReport {
    pub status: CompilationStatus,
    #[serde(default)]
    pub commands: Vec<String>,
    #[serde(default)]
    pub diagnostics: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Limitation {
    pub code: String,
    pub message: String,
    #[serde(default)]
    pub affected_paths: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditUsage {
    #[schemars(range(max = 9007199254740991_u64))]
    pub input_tokens: u64,
    #[schemars(range(max = 9007199254740991_u64))]
    pub cached_input_tokens: u64,
    #[serde(default)]
    #[schemars(range(max = 9007199254740991_u64))]
    pub cache_write_input_tokens: u64,
    #[schemars(range(max = 9007199254740991_u64))]
    pub output_tokens: u64,
    #[schemars(range(max = 9007199254740991_u64))]
    pub reasoning_output_tokens: u64,
    /// Number of underlying model API calls. Zero means unavailable when the
    /// execution surface does not attest this count (for example, a trusted
    /// local subscription-backed Codex run).
    pub model_requests: u32,
    #[schemars(range(max = 9007199254740991_u64))]
    pub duration_ms: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureCode {
    AgentCrash,
    AuditTimeout,
    Cancelled,
    Infrastructure,
    ModelUnavailable,
    InvalidOutput,
    Internal,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Failure {
    pub code: FailureCode,
    pub message: String,
    pub retryable: bool,
}

impl Validate for AuditResult {
    fn validate(&self) -> Result<(), ValidationError> {
        require_token(&self.audit_id, "auditId")?;
        let started_at = require_rfc3339(&self.started_at, "startedAt")?;
        let finished_at = require_rfc3339(&self.finished_at, "finishedAt")?;
        if finished_at.compare(&started_at) == Ordering::Less {
            return Err(ValidationError::new(
                "finishedAt",
                "must not precede startedAt",
            ));
        }
        require_nonempty(&self.summary.title, "summary.title")?;
        require_nonempty(&self.summary.executive_summary, "summary.executiveSummary")?;

        match self.status {
            TerminalAuditStatus::Completed if self.partial || self.failure.is_some() => {
                return Err(ValidationError::new(
                    "status",
                    "completed audits must be complete and must not contain failure details",
                ));
            }
            TerminalAuditStatus::Failed => {
                if !self.partial {
                    return Err(ValidationError::new(
                        "partial",
                        "failed audit results must be marked partial",
                    ));
                }
                if self.failure.is_none() {
                    return Err(ValidationError::new(
                        "failure",
                        "failed audits require failure details",
                    ));
                }
            }
            TerminalAuditStatus::Completed => {}
        }

        require_unique(
            self.findings.iter().map(|finding| finding.id.as_str()),
            "findings.id",
        )?;
        for finding in &self.findings {
            finding.validate()?;
        }
        self.coverage.validate()?;
        self.compilation.validate()?;
        for (index, limitation) in self.limitations.iter().enumerate() {
            limitation.validate_at(&format!("limitations[{index}]"))?;
        }
        let required_compilation_limitation = match self.compilation.status {
            CompilationStatus::Failed => Some(LIMITATION_COMPILATION_FAILED),
            CompilationStatus::Partial => Some(LIMITATION_COMPILATION_PARTIAL),
            CompilationStatus::NotAttempted | CompilationStatus::Succeeded => None,
        };
        if let Some(required_code) = required_compilation_limitation
            && !self
                .limitations
                .iter()
                .any(|limitation| limitation.code == required_code)
        {
            return Err(ValidationError::new(
                "limitations",
                format!("compilation status requires limitation code '{required_code}'"),
            ));
        }
        if let Some(failure) = &self.failure {
            require_nonempty(&failure.message, "failure.message")?;
        }
        self.usage.validate_at("usage")?;
        self.validate_finding_counts()
    }
}

impl ValidateWithLimits for AuditResult {
    fn validate_with_limits(&self, limits: &ContractLimits) -> Result<(), ValidationError> {
        self.validate()?;
        require_serialized_max_bytes(self, limits.max_result_bytes, "result")?;
        for finding in &self.findings {
            finding.validate_with_limits(limits)?;
        }
        for (index, diagnostic) in self.compilation.diagnostics.iter().enumerate() {
            require_max_bytes(
                diagnostic,
                limits.max_diagnostic_item_bytes,
                &format!("compilation.diagnostics[{index}]"),
            )?;
        }
        require_total_string_bytes(
            self.compilation.diagnostics.iter().map(String::as_str),
            limits.max_diagnostics_bytes,
            "compilation.diagnostics",
        )?;
        Ok(())
    }
}

impl AuditResult {
    fn validate_finding_counts(&self) -> Result<(), ValidationError> {
        use crate::Severity;

        let mut actual = FindingCounts::default();
        for finding in &self.findings {
            match finding.severity {
                Severity::Critical => actual.critical += 1,
                Severity::High => actual.high += 1,
                Severity::Medium => actual.medium += 1,
                Severity::Low => actual.low += 1,
                Severity::Informational => actual.informational += 1,
            }
        }
        if actual != self.summary.finding_counts {
            return Err(ValidationError::new(
                "summary.findingCounts",
                "must exactly match the findings array",
            ));
        }
        Ok(())
    }
}

impl AuditUsage {
    pub(crate) fn validate_at(&self, field: &str) -> Result<(), ValidationError> {
        for (name, value) in [
            ("inputTokens", self.input_tokens),
            ("cachedInputTokens", self.cached_input_tokens),
            ("cacheWriteInputTokens", self.cache_write_input_tokens),
            ("outputTokens", self.output_tokens),
            ("reasoningOutputTokens", self.reasoning_output_tokens),
            ("durationMs", self.duration_ms),
        ] {
            require_js_safe_u64(value, &format!("{field}.{name}"))?;
        }
        Ok(())
    }
}

impl Validate for AuditCoverage {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.submitted_file_count != self.files.len() as u32 {
            return Err(ValidationError::new(
                "coverage.submittedFileCount",
                "must match coverage.files length",
            ));
        }
        let reviewed = self.files.iter().filter(|file| file.reviewed).count() as u32;
        if self.reviewed_file_count != reviewed {
            return Err(ValidationError::new(
                "coverage.reviewedFileCount",
                "must match the number of reviewed files",
            ));
        }
        require_unique(
            self.files.iter().map(|file| file.path.as_str()),
            "coverage.files.path",
        )?;
        require_unique_unicode_lowercase(
            self.files.iter().map(|file| file.path.as_str()),
            "coverage.files.path",
        )?;
        for (index, file) in self.files.iter().enumerate() {
            require_relative_path(&file.path, &format!("coverage.files[{index}].path"))?;
            for (symbol_index, symbol) in file.functions_reviewed.iter().enumerate() {
                require_nonempty(
                    symbol,
                    &format!("coverage.files[{index}].functionsReviewed[{symbol_index}]"),
                )?;
            }
        }
        Ok(())
    }
}

impl Validate for CompilationReport {
    fn validate(&self) -> Result<(), ValidationError> {
        for (index, command) in self.commands.iter().enumerate() {
            require_nonempty(command, &format!("compilation.commands[{index}]"))?;
        }
        Ok(())
    }
}

impl Limitation {
    pub(crate) fn validate_at(&self, field: &str) -> Result<(), ValidationError> {
        require_token(&self.code, &format!("{field}.code"))?;
        require_nonempty(&self.message, &format!("{field}.message"))?;
        for (index, path) in self.affected_paths.iter().enumerate() {
            require_relative_path(path, &format!("{field}.affectedPaths[{index}]"))?;
        }
        Ok(())
    }
}
