use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;

use crate::Validate;
use crate::ValidationError;
use crate::validation::require_nonempty;
use crate::validation::require_token;

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
    pub reasoning_effort: String,
    pub audit_timeout_minutes: u32,
}

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkAccess {
    Unrestricted,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RuntimeConfig {
    pub max_concurrent_audits: u32,
    pub max_upload_files: u32,
    pub max_upload_bytes: u64,
    pub worker_cpu_cores: u32,
    pub worker_memory_mib: u64,
    pub worker_disk_mib: u64,
    pub artifact_retention_hours: u32,
    pub event_retention_hours: u32,
    pub network_access: NetworkAccess,
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
        require_nonempty(&self.reasoning_effort, &format!("{field}.reasoning_effort"))?;
        if self.audit_timeout_minutes == 0 {
            return Err(ValidationError::new(
                format!("{field}.audit_timeout_minutes"),
                "must be greater than zero",
            ));
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
        }
        Ok(())
    }
}
