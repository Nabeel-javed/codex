use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;

use crate::Validate;
use crate::ValidationError;
use crate::validation::require_js_safe_u64;
use crate::validation::require_nonempty;
use crate::validation::require_token;

/// Initial upper bound for one audit's model execution. The 28-hour cap
/// leaves orchestration cleanup and artifact-finalization time inside the
/// worker's 30-hour hard process boundary.
pub const MAX_AUDIT_TIMEOUT_MINUTES: u32 = 28 * 60;
/// Initial public request-manifest ceiling shared by the website and workers.
pub const MAX_REQUEST_BYTES: u64 = 16 * 1024 * 1024;
/// Guidance is part of the request manifest and has a tighter independent cap.
pub const MAX_GUIDANCE_BYTES: u64 = 1024 * 1024;
/// Maximum serialized result accepted by the trusted runner. This must remain
/// aligned with its 256 MiB hard model-output boundary.
pub const MAX_RESULT_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
pub enum AuditConfigSchemaVersion {
    #[serde(rename = "auditbase.audit-config.v1")]
    V1,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct AuditConfig {
    pub schema_version: AuditConfigSchemaVersion,
    pub tiers: BTreeMap<String, TierConfig>,
    pub runtime: RuntimeConfig,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct TierConfig {
    pub enabled: bool,
    pub model: String,
    /// Passed to Codex as the model reasoning effort without exposing it publicly.
    pub reasoning_effort: ReasoningEffort,
    pub audit_timeout_minutes: u32,
}

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasoningEffort {
    Low,
    Medium,
    High,
    #[serde(rename = "xhigh")]
    XHigh,
}

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkAccess {
    ControlledPublic,
    BenchmarkModelOnly,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RuntimeConfig {
    pub max_concurrent_audits: u32,
    pub max_upload_files: u32,
    #[schemars(range(max = 9007199254740991_u64))]
    pub max_upload_bytes: u64,
    pub worker_cpu_cores: u32,
    #[schemars(range(max = 9007199254740991_u64))]
    pub worker_memory_mib: u64,
    #[schemars(range(max = 9007199254740991_u64))]
    pub worker_disk_mib: u64,
    pub artifact_retention_hours: u32,
    pub event_retention_hours: u32,
    pub network_access: NetworkAccess,
    pub contract_limits: ContractLimits,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ContractLimits {
    #[schemars(range(max = 9007199254740991_u64))]
    pub max_request_bytes: u64,
    #[schemars(range(max = 9007199254740991_u64))]
    pub max_guidance_bytes: u64,
    #[schemars(range(max = 9007199254740991_u64))]
    pub max_event_bytes: u64,
    #[schemars(range(max = 9007199254740991_u64))]
    pub max_log_message_bytes: u64,
    #[schemars(range(max = "MAX_RESULT_BYTES"))]
    pub max_result_bytes: u64,
    #[schemars(range(max = 9007199254740991_u64))]
    pub max_diagnostic_item_bytes: u64,
    #[schemars(range(max = 9007199254740991_u64))]
    pub max_diagnostics_bytes: u64,
    #[schemars(range(max = 9007199254740991_u64))]
    pub max_snippet_bytes: u64,
    #[schemars(range(max = 9007199254740991_u64))]
    pub max_evidence_item_bytes: u64,
    #[schemars(range(max = 9007199254740991_u64))]
    pub max_finding_evidence_bytes: u64,
}

impl Validate for AuditConfig {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.tiers.is_empty() {
            return Err(ValidationError::new(
                "tiers",
                "must contain at least one configured tier",
            ));
        }
        if !self.tiers.values().any(|tier| tier.enabled) {
            return Err(ValidationError::new(
                "tiers",
                "must contain at least one enabled tier",
            ));
        }
        for (name, tier) in &self.tiers {
            require_token(name, &format!("tiers.{name}"))?;
            tier.validate_at(&format!("tiers.{name}"))?;
        }
        self.runtime.validate()
    }
}

impl TierConfig {
    fn validate_at(&self, field: &str) -> Result<(), ValidationError> {
        require_nonempty(&self.model, &format!("{field}.model"))?;
        if self.audit_timeout_minutes == 0 {
            return Err(ValidationError::new(
                format!("{field}.audit_timeout_minutes"),
                "must be greater than zero",
            ));
        }
        if self.audit_timeout_minutes > MAX_AUDIT_TIMEOUT_MINUTES {
            return Err(ValidationError::new(
                format!("{field}.audit_timeout_minutes"),
                format!("must be at most {MAX_AUDIT_TIMEOUT_MINUTES}"),
            ));
        }
        Ok(())
    }
}

impl Validate for ContractLimits {
    fn validate(&self) -> Result<(), ValidationError> {
        let positive_values = [
            ("max_request_bytes", self.max_request_bytes),
            ("max_guidance_bytes", self.max_guidance_bytes),
            ("max_event_bytes", self.max_event_bytes),
            ("max_log_message_bytes", self.max_log_message_bytes),
            ("max_result_bytes", self.max_result_bytes),
            ("max_diagnostic_item_bytes", self.max_diagnostic_item_bytes),
            ("max_diagnostics_bytes", self.max_diagnostics_bytes),
            ("max_snippet_bytes", self.max_snippet_bytes),
            ("max_evidence_item_bytes", self.max_evidence_item_bytes),
            (
                "max_finding_evidence_bytes",
                self.max_finding_evidence_bytes,
            ),
        ];
        for (field, value) in positive_values {
            if value == 0 {
                return Err(ValidationError::new(
                    format!("runtime.contract_limits.{field}"),
                    "must be greater than zero",
                ));
            }
            require_js_safe_u64(value, &format!("runtime.contract_limits.{field}"))?;
        }

        let hard_maxima = [
            (
                "max_request_bytes",
                self.max_request_bytes,
                MAX_REQUEST_BYTES,
            ),
            (
                "max_guidance_bytes",
                self.max_guidance_bytes,
                MAX_GUIDANCE_BYTES,
            ),
            ("max_result_bytes", self.max_result_bytes, MAX_RESULT_BYTES),
        ];
        for (field, value, maximum) in hard_maxima {
            if value > maximum {
                return Err(ValidationError::new(
                    format!("runtime.contract_limits.{field}"),
                    format!("must be at most {maximum}"),
                ));
            }
        }

        let contained_limits = [
            (
                "max_guidance_bytes",
                self.max_guidance_bytes,
                "max_request_bytes",
                self.max_request_bytes,
            ),
            (
                "max_log_message_bytes",
                self.max_log_message_bytes,
                "max_event_bytes",
                self.max_event_bytes,
            ),
            (
                "max_diagnostic_item_bytes",
                self.max_diagnostic_item_bytes,
                "max_diagnostics_bytes",
                self.max_diagnostics_bytes,
            ),
            (
                "max_diagnostics_bytes",
                self.max_diagnostics_bytes,
                "max_result_bytes",
                self.max_result_bytes,
            ),
            (
                "max_snippet_bytes",
                self.max_snippet_bytes,
                "max_result_bytes",
                self.max_result_bytes,
            ),
            (
                "max_evidence_item_bytes",
                self.max_evidence_item_bytes,
                "max_finding_evidence_bytes",
                self.max_finding_evidence_bytes,
            ),
            (
                "max_finding_evidence_bytes",
                self.max_finding_evidence_bytes,
                "max_result_bytes",
                self.max_result_bytes,
            ),
        ];
        for (child_name, child, parent_name, parent) in contained_limits {
            if child > parent {
                return Err(ValidationError::new(
                    format!("runtime.contract_limits.{child_name}"),
                    format!("must not exceed {parent_name}"),
                ));
            }
        }
        Ok(())
    }
}

impl Validate for RuntimeConfig {
    fn validate(&self) -> Result<(), ValidationError> {
        let positive_values = [
            (
                "runtime.max_concurrent_audits",
                self.max_concurrent_audits as u64,
            ),
            ("runtime.max_upload_files", self.max_upload_files as u64),
            ("runtime.max_upload_bytes", self.max_upload_bytes),
            ("runtime.worker_cpu_cores", self.worker_cpu_cores as u64),
            ("runtime.worker_memory_mib", self.worker_memory_mib),
            ("runtime.worker_disk_mib", self.worker_disk_mib),
            (
                "runtime.artifact_retention_hours",
                self.artifact_retention_hours as u64,
            ),
            (
                "runtime.event_retention_hours",
                self.event_retention_hours as u64,
            ),
        ];
        for (field, value) in positive_values {
            if value == 0 {
                return Err(ValidationError::new(field, "must be greater than zero"));
            }
            require_js_safe_u64(value, field)?;
        }
        self.contract_limits.validate()
    }
}
