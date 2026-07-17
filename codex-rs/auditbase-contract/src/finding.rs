use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;

use crate::ContractLimits;
use crate::Validate;
use crate::ValidateWithLimits;
use crate::ValidationError;
use crate::validation::require_max_bytes;
use crate::validation::require_nonempty;
use crate::validation::require_relative_path;
use crate::validation::require_serialized_items_max_bytes;
use crate::validation::require_serialized_max_bytes;
use crate::validation::require_token;

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    Verified,
    Suspected,
    Informational,
}

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub status: FindingStatus,
    pub confidence: Confidence,
    pub category: String,
    pub description: String,
    pub impact: String,
    pub recommendation: String,
    #[serde(default)]
    pub locations: Vec<SourceLocation>,
    #[serde(default)]
    pub evidence: Vec<Evidence>,
    pub proof: Proof,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceLocation {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_line: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_line: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    Source,
    Command,
    Test,
    Artifact,
    Analysis,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Evidence {
    pub kind: EvidenceKind,
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<SourceLocation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_path: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofStatus {
    Passed,
    Failed,
    NotAttempted,
    NotApplicable,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Proof {
    pub status: ProofStatus,
    pub summary: String,
    #[serde(default)]
    pub commands: Vec<String>,
    #[serde(default)]
    pub artifact_paths: Vec<String>,
}

impl Validate for Finding {
    fn validate(&self) -> Result<(), ValidationError> {
        require_token(&self.id, "finding.id")?;
        require_nonempty(&self.title, "finding.title")?;
        require_nonempty(&self.category, "finding.category")?;
        require_nonempty(&self.description, "finding.description")?;
        require_nonempty(&self.impact, "finding.impact")?;
        require_nonempty(&self.recommendation, "finding.recommendation")?;
        let informational_status = self.status == FindingStatus::Informational;
        let informational_severity = self.severity == Severity::Informational;
        if informational_status != informational_severity {
            return Err(ValidationError::new(
                "finding.status",
                "informational status must be used if and only if severity is informational",
            ));
        }
        if self.status == FindingStatus::Verified && self.evidence.is_empty() {
            return Err(ValidationError::new(
                "finding.evidence",
                "verified findings require at least one evidence item",
            ));
        }

        for (index, location) in self.locations.iter().enumerate() {
            location.validate_at(&format!("finding.locations[{index}]"))?;
        }
        for (index, evidence) in self.evidence.iter().enumerate() {
            evidence.validate_at(&format!("finding.evidence[{index}]"))?;
        }
        self.proof.validate_at("finding.proof")
    }
}

impl ValidateWithLimits for Finding {
    fn validate_with_limits(&self, limits: &ContractLimits) -> Result<(), ValidationError> {
        self.validate()?;
        for (index, location) in self.locations.iter().enumerate() {
            if let Some(snippet) = &location.snippet {
                require_max_bytes(
                    snippet,
                    limits.max_snippet_bytes,
                    &format!("finding.locations[{index}].snippet"),
                )?;
            }
        }
        for (index, evidence) in self.evidence.iter().enumerate() {
            require_serialized_max_bytes(
                evidence,
                limits.max_evidence_item_bytes,
                &format!("finding.evidence[{index}]"),
            )?;
            if let Some(location) = &evidence.location
                && let Some(snippet) = &location.snippet
            {
                require_max_bytes(
                    snippet,
                    limits.max_snippet_bytes,
                    &format!("finding.evidence[{index}].location.snippet"),
                )?;
            }
        }
        require_serialized_items_max_bytes(
            &self.evidence,
            limits.max_finding_evidence_bytes,
            "finding.evidence",
        )?;
        Ok(())
    }
}

impl SourceLocation {
    pub(crate) fn validate_at(&self, field: &str) -> Result<(), ValidationError> {
        require_relative_path(&self.path, &format!("{field}.path"))?;
        if let Some(start_line) = self.start_line
            && start_line == 0
        {
            return Err(ValidationError::new(
                format!("{field}.startLine"),
                "must be greater than zero",
            ));
        }
        if let Some(end_line) = self.end_line {
            if end_line == 0 {
                return Err(ValidationError::new(
                    format!("{field}.endLine"),
                    "must be greater than zero",
                ));
            }
            if let Some(start_line) = self.start_line
                && end_line < start_line
            {
                return Err(ValidationError::new(
                    format!("{field}.endLine"),
                    "must not precede startLine",
                ));
            }
        }
        Ok(())
    }
}

impl Evidence {
    fn validate_at(&self, field: &str) -> Result<(), ValidationError> {
        require_nonempty(&self.summary, &format!("{field}.summary"))?;
        if let Some(location) = &self.location {
            location.validate_at(&format!("{field}.location"))?;
        }
        if let Some(command) = &self.command {
            require_nonempty(command, &format!("{field}.command"))?;
        }
        if let Some(path) = &self.artifact_path {
            require_relative_path(path, &format!("{field}.artifactPath"))?;
        }
        Ok(())
    }
}

impl Proof {
    fn validate_at(&self, field: &str) -> Result<(), ValidationError> {
        require_nonempty(&self.summary, &format!("{field}.summary"))?;
        for (index, command) in self.commands.iter().enumerate() {
            require_nonempty(command, &format!("{field}.commands[{index}]"))?;
        }
        for (index, path) in self.artifact_paths.iter().enumerate() {
            require_relative_path(path, &format!("{field}.artifactPaths[{index}]"))?;
        }
        Ok(())
    }
}
