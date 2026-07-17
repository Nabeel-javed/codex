use serde::Deserialize;
use serde::Serialize;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub enum BenchmarkCatalogSchemaVersion {
    #[serde(rename = "auditbase.benchmark-catalog.v1")]
    V1,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub enum BenchmarkInputSchemaVersion {
    #[serde(rename = "auditbase.benchmark-input.v1")]
    V1,
}

/// Evaluator-only metadata. This object must never be mounted into the agent.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BenchmarkCatalog {
    pub schema_version: BenchmarkCatalogSchemaVersion,
    pub case_id: String,
    pub project_id: String,
    pub source: SourceOrigin,
    pub files: Vec<CatalogFile>,
    pub scope: BenchmarkScope,
    pub license: LicenseReview,
    pub contamination: ContaminationReview,
    pub limits: PackageLimits,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceOrigin {
    pub url: String,
    pub revision: String,
    pub retrieved_at: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CatalogFile {
    pub path: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub executable: bool,
    pub in_scope: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BenchmarkScope {
    pub instructions: String,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LicenseStatus {
    Cleared,
    InternalEvaluationOnly,
    Unknown,
    Blocked,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LicenseReview {
    pub status: LicenseStatus,
    pub redistribution_allowed: bool,
    pub spdx_expressions: Vec<String>,
    pub evidence_paths: Vec<String>,
    pub required_notice_paths: Vec<String>,
    pub reviewed_by: String,
    pub reviewed_at: String,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContaminationRisk {
    Low,
    Medium,
    High,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContaminationReview {
    pub risk: ContaminationRisk,
    pub identity_visible: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answer_published_at: Option<String>,
    #[serde(default)]
    pub report_urls: Vec<String>,
    #[serde(default)]
    pub forbidden_path_globs: Vec<String>,
    #[serde(default)]
    pub forbidden_content_sha256: Vec<String>,
    #[serde(default)]
    pub forbidden_content_patterns: Vec<String>,
    pub sanitization_policy_version: String,
    pub reviewed_by: String,
    pub reviewed_at: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PackageLimits {
    pub max_files: u32,
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
    pub max_path_bytes: u32,
}

/// The only manifest written into an agent-visible benchmark package.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentInputManifest {
    pub schema_version: BenchmarkInputSchemaVersion,
    /// Random evaluator-issued identifier (`run-` plus 128 bits of lowercase
    /// hex). It cannot encode the evaluator catalog's case or project name.
    pub run_case_id: String,
    pub tree_sha256: String,
    pub required_network_policy: BenchmarkNetworkPolicy,
    pub files: Vec<AgentInputFile>,
    pub scope: AgentInputScope,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BenchmarkNetworkPolicy {
    ModelOnly,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentInputFile {
    pub path: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub executable: bool,
    pub in_scope: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentInputScope {
    pub instructions: String,
    pub included_paths: Vec<String>,
}
