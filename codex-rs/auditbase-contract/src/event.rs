use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;

use crate::AuditResultSchemaVersion;
use crate::AuditUsage;
use crate::ContractLimits;
use crate::Failure;
use crate::Finding;
use crate::Limitation;
use crate::Validate;
use crate::ValidateWithLimits;
use crate::ValidationError;
use crate::validation::require_js_safe_u64;
use crate::validation::require_max_bytes;
use crate::validation::require_nonempty;
use crate::validation::require_rfc3339;
use crate::validation::require_serialized_max_bytes;
use crate::validation::require_token;

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
pub enum AuditEventSchemaVersion {
    #[serde(rename = "auditbase.audit-event.v1")]
    V1,
}

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditStatus {
    Queued,
    Preparing,
    Auditing,
    Finalizing,
    Completed,
    Failed,
}

impl AuditStatus {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed)
    }

    /// Returns whether the canonical lifecycle permits `self -> next`.
    pub fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Queued, Self::Preparing)
                | (Self::Preparing, Self::Auditing)
                | (Self::Auditing, Self::Finalizing)
                | (Self::Finalizing, Self::Completed)
                | (
                    Self::Queued | Self::Preparing | Self::Auditing | Self::Finalizing,
                    Self::Failed
                )
        )
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditEvent {
    pub schema_version: AuditEventSchemaVersion,
    pub event_id: String,
    #[schemars(range(min = 1, max = 9007199254740991_u64))]
    pub sequence: u64,
    pub audit_id: String,
    #[schemars(regex(
        pattern = r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$"
    ))]
    pub occurred_at: String,
    #[serde(flatten)]
    pub payload: AuditEventPayload,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum AuditEventPayload {
    Status(StatusEvent),
    Progress(ProgressEvent),
    Log(LogEvent),
    Finding(Box<FindingEvent>),
    Limitation(Limitation),
    Usage(AuditUsage),
    Completed(CompletedEvent),
    Failed(FailedEvent),
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StatusEvent {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous: Option<AuditStatus>,
    pub status: AuditStatus,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProgressEvent {
    pub phase: String,
    pub percentage: u8,
    pub message: String,
}

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Debug,
    Info,
    Warning,
    Error,
}

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LogSource {
    System,
    Agent,
    Tool,
    Build,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LogEvent {
    pub level: LogLevel,
    pub source: LogSource,
    pub message: String,
}

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingEventAction {
    Discovered,
    Updated,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingEvent {
    pub action: FindingEventAction,
    pub finding: Finding,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompletedEvent {
    pub result_available: bool,
    pub result_schema_version: AuditResultSchemaVersion,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FailedEvent {
    pub partial_results_available: bool,
    pub failure: Failure,
}

impl Validate for AuditEvent {
    fn validate(&self) -> Result<(), ValidationError> {
        require_token(&self.event_id, "eventId")?;
        require_token(&self.audit_id, "auditId")?;
        if self.sequence == 0 {
            return Err(ValidationError::new(
                "sequence",
                "must be greater than zero",
            ));
        }
        require_js_safe_u64(self.sequence, "sequence")?;
        require_rfc3339(&self.occurred_at, "occurredAt")?;
        match &self.payload {
            AuditEventPayload::Status(event) => {
                require_nonempty(&event.message, "data.message")?;
                match event.previous {
                    Some(previous) if !previous.can_transition_to(event.status) => {
                        return Err(ValidationError::new(
                            "data.status",
                            "is not a permitted canonical status transition",
                        ));
                    }
                    None if event.status != AuditStatus::Queued => {
                        return Err(ValidationError::new(
                            "data.previous",
                            "may be absent only for the initial queued status",
                        ));
                    }
                    _ => {}
                }
            }
            AuditEventPayload::Progress(event) => {
                require_token(&event.phase, "data.phase")?;
                if event.percentage > 100 {
                    return Err(ValidationError::new(
                        "data.percentage",
                        "must not exceed 100",
                    ));
                }
                require_nonempty(&event.message, "data.message")?;
            }
            AuditEventPayload::Log(event) => require_nonempty(&event.message, "data.message")?,
            AuditEventPayload::Finding(event) => event.finding.validate()?,
            AuditEventPayload::Limitation(event) => {
                event.validate_at("data")?;
            }
            AuditEventPayload::Usage(event) => event.validate_at("data")?,
            AuditEventPayload::Completed(event) => {
                if !event.result_available {
                    return Err(ValidationError::new(
                        "data.resultAvailable",
                        "must be true for a completion event",
                    ));
                }
            }
            AuditEventPayload::Failed(event) => {
                require_nonempty(&event.failure.message, "data.failure.message")?;
            }
        }
        Ok(())
    }
}

impl ValidateWithLimits for AuditEvent {
    fn validate_with_limits(&self, limits: &ContractLimits) -> Result<(), ValidationError> {
        self.validate()?;
        require_serialized_max_bytes(self, limits.max_event_bytes, "event")?;
        match &self.payload {
            AuditEventPayload::Log(event) => {
                require_max_bytes(&event.message, limits.max_log_message_bytes, "data.message")?;
            }
            AuditEventPayload::Finding(event) => {
                event.finding.validate_with_limits(limits)?;
            }
            AuditEventPayload::Status(_)
            | AuditEventPayload::Progress(_)
            | AuditEventPayload::Limitation(_)
            | AuditEventPayload::Usage(_)
            | AuditEventPayload::Completed(_)
            | AuditEventPayload::Failed(_) => {}
        }
        Ok(())
    }
}
