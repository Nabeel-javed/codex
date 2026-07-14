use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;

use crate::Failure;
use crate::Validate;
use crate::ValidationError;
use crate::event::AuditStatus;
use crate::validation::require_nonempty;
use crate::validation::require_relative_path;
use crate::validation::require_sha256;
use crate::validation::require_token;
use crate::validation::require_unique;

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
pub enum AuditRequestSchemaVersion {
    #[serde(rename = "auditbase.audit-request.v1")]
    V1,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditRequest {
    pub schema_version: AuditRequestSchemaVersion,
    pub name: String,
    pub tier: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guidance: Option<String>,
    pub files: Vec<UploadFile>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UploadFile {
    /// Correlates this manifest entry with multipart field `file.<file_id>`.
    pub file_id: String,
    /// Normalized relative path using `/` separators.
    pub path: String,
    pub size_bytes: u64,
    pub sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
}

impl Validate for AuditRequest {
    fn validate(&self) -> Result<(), ValidationError> {
        require_nonempty(&self.name, "name")?;
        if self.name.chars().count() > 255 {
            return Err(ValidationError::new(
                "name",
                "must be at most 255 characters",
            ));
        }
        require_token(&self.tier, "tier")?;
        if self.files.is_empty() {
            return Err(ValidationError::new(
                "files",
                "must contain at least one file",
            ));
        }
        require_unique(
            self.files.iter().map(|file| file.file_id.as_str()),
            "files.fileId",
        )?;
        require_unique(
            self.files.iter().map(|file| file.path.as_str()),
            "files.path",
        )?;

        for (index, file) in self.files.iter().enumerate() {
            require_token(&file.file_id, &format!("files[{index}].fileId"))?;
            require_relative_path(&file.path, &format!("files[{index}].path"))?;
            require_sha256(&file.sha256, &format!("files[{index}].sha256"))?;
            if let Some(media_type) = &file.media_type {
                require_nonempty(media_type, &format!("files[{index}].mediaType"))?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
pub enum AuditAcceptedSchemaVersion {
    #[serde(rename = "auditbase.audit-accepted.v1")]
    V1,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditAccepted {
    pub schema_version: AuditAcceptedSchemaVersion,
    pub audit_id: String,
    pub status: AuditStatus,
    pub events_url: String,
    pub result_url: String,
}

impl Validate for AuditAccepted {
    fn validate(&self) -> Result<(), ValidationError> {
        require_token(&self.audit_id, "auditId")?;
        if self.status != AuditStatus::Queued {
            return Err(ValidationError::new(
                "status",
                "must be 'queued' when accepted",
            ));
        }
        require_nonempty(&self.events_url, "eventsUrl")?;
        require_nonempty(&self.result_url, "resultUrl")
    }
}

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
pub enum AuditSnapshotSchemaVersion {
    #[serde(rename = "auditbase.audit-snapshot.v1")]
    V1,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditSnapshot {
    pub schema_version: AuditSnapshotSchemaVersion,
    pub audit_id: String,
    pub status: AuditStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    pub partial_results_available: bool,
    pub result_available: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<Failure>,
}

impl Validate for AuditSnapshot {
    fn validate(&self) -> Result<(), ValidationError> {
        require_token(&self.audit_id, "auditId")?;
        if let Some(phase) = &self.phase {
            require_token(phase, "phase")?;
        }
        match self.status {
            AuditStatus::Completed if !self.result_available || self.failure.is_some() => Err(
                ValidationError::new("status", "completed audits require a result and no failure"),
            ),
            AuditStatus::Failed if self.failure.is_none() => Err(ValidationError::new(
                "failure",
                "failed audits require failure details",
            )),
            AuditStatus::Queued
            | AuditStatus::Preparing
            | AuditStatus::Auditing
            | AuditStatus::Finalizing
                if self.failure.is_some() =>
            {
                Err(ValidationError::new(
                    "failure",
                    "non-terminal audits must not contain failure details",
                ))
            }
            _ => Ok(()),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
pub enum ApiErrorSchemaVersion {
    #[serde(rename = "auditbase.api-error.v1")]
    V1,
}

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiErrorCode {
    InvalidRequest,
    InvalidPath,
    InvalidTier,
    TierDisabled,
    ModelUnavailable,
    UploadLimitExceeded,
    Unauthorized,
    NotFound,
    Conflict,
    Internal,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApiErrorResponse {
    pub schema_version: ApiErrorSchemaVersion,
    pub code: ApiErrorCode,
    pub message: String,
    pub retryable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
}

impl Validate for ApiErrorResponse {
    fn validate(&self) -> Result<(), ValidationError> {
        require_nonempty(&self.message, "message")?;
        if let Some(field) = &self.field {
            require_nonempty(field, "field")?;
        }
        Ok(())
    }
}
