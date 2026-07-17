use std::collections::BTreeSet;

use codex_auditbase_contract::ContractLimits;
use codex_auditbase_contract::Severity;
use codex_auditbase_contract::Validate;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;

use crate::CanonicalError;
use crate::canonical_sha256;
use crate::is_sha256;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunKey {
    pub case_id: String,
    pub arm_id: String,
    pub replicate: u32,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseKind {
    Vulnerable,
    CleanControl,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaseManifest {
    pub case_id: String,
    pub project_id: String,
    pub kind: CaseKind,
    pub source_sha256: String,
    pub scoped_paths: Vec<String>,
    pub scoped_paths_sha256: String,
    pub truth_set_sha256: String,
    pub sloc: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArmManifest {
    pub arm_id: String,
    /// Digest of the static arm configuration shared by every scheduled run.
    /// Run-specific provenance fingerprints are recorded separately at ingest.
    pub arm_config_sha256: String,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetryPolicy {
    /// Total attempts including the initial attempt. Only a trusted
    /// `void_before_start` outcome permits the next contiguous attempt.
    pub max_attempts: u32,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvaluationManifest {
    pub spec_version: String,
    pub evaluation_id: String,
    pub cases: Vec<CaseManifest>,
    pub arms: Vec<ArmManifest>,
    pub scheduled_runs: Vec<RunKey>,
    pub retry_policy: RetryPolicy,
    pub contract_limits: ContractLimits,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TruthLocation {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TruthItem {
    pub truth_id: String,
    pub severity: Severity,
    pub root_cause: String,
    pub affected_behavior: String,
    pub material_impact: String,
    #[serde(default)]
    pub acceptable_locations: Vec<TruthLocation>,
    pub in_scope: bool,
    pub bug_family: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TruthSet {
    pub case_id: String,
    pub revision: u32,
    pub truths: Vec<TruthItem>,
}

#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("{field} must not be empty")]
    Empty { field: String },
    #[error("{field} is not a lowercase 64-character SHA-256 digest")]
    InvalidSha256 { field: String },
    #[error("duplicate {field}: {value}")]
    Duplicate { field: String, value: String },
    #[error("unknown {field}: {value}")]
    Unknown { field: String, value: String },
    #[error("run is scheduled more than once: {0:?}")]
    DuplicateRun(RunKey),
    #[error("retryPolicy.maxAttempts must be between 1 and 10")]
    InvalidRetryPolicy,
    #[error("contractLimits are invalid: {0}")]
    InvalidContractLimits(String),
    #[error("case {case_id} scoped path digest does not match its path inventory")]
    ScopedPathsHashMismatch { case_id: String },
    #[error("truth set case {actual} does not match manifest case {expected}")]
    TruthCaseMismatch { expected: String, actual: String },
    #[error("truth set digest does not match case {case_id}")]
    TruthHashMismatch { case_id: String },
    #[error("clean control {case_id} contains an in-scope Critical/High/Medium truth")]
    DirtyCleanControl { case_id: String },
    #[error("vulnerable case {case_id} has no in-scope Critical/High/Medium truth")]
    EmptyPrimaryUniverse { case_id: String },
    #[error(transparent)]
    Canonical(#[from] CanonicalError),
}

impl EvaluationManifest {
    pub fn validate(&self) -> Result<(), ManifestError> {
        require_nonempty(&self.spec_version, "specVersion")?;
        require_nonempty(&self.evaluation_id, "evaluationId")?;
        if !(1..=10).contains(&self.retry_policy.max_attempts) {
            return Err(ManifestError::InvalidRetryPolicy);
        }
        self.contract_limits
            .validate()
            .map_err(|error| ManifestError::InvalidContractLimits(error.to_string()))?;

        let mut case_ids = BTreeSet::new();
        let mut project_ids = BTreeSet::new();
        for case in &self.cases {
            require_nonempty(&case.case_id, "cases.caseId")?;
            require_nonempty(&case.project_id, "cases.projectId")?;
            require_sha256(&case.source_sha256, "cases.sourceSha256")?;
            require_sha256(&case.scoped_paths_sha256, "cases.scopedPathsSha256")?;
            require_sha256(&case.truth_set_sha256, "cases.truthSetSha256")?;
            if !case_ids.insert(case.case_id.clone()) {
                return Err(ManifestError::Duplicate {
                    field: "caseId".to_owned(),
                    value: case.case_id.clone(),
                });
            }
            project_ids.insert(case.project_id.clone());

            let mut paths = case.scoped_paths.clone();
            paths.sort();
            if let Some(duplicate) = paths.windows(2).find(|window| window[0] == window[1]) {
                return Err(ManifestError::Duplicate {
                    field: format!("cases[{}].scopedPaths", case.case_id),
                    value: duplicate[0].clone(),
                });
            }
            let actual = canonical_sha256(&paths)?;
            if actual != case.scoped_paths_sha256 {
                return Err(ManifestError::ScopedPathsHashMismatch {
                    case_id: case.case_id.clone(),
                });
            }
        }

        let mut arm_ids = BTreeSet::new();
        for arm in &self.arms {
            require_nonempty(&arm.arm_id, "arms.armId")?;
            require_sha256(&arm.arm_config_sha256, "arms.armConfigSha256")?;
            if !arm_ids.insert(arm.arm_id.clone()) {
                return Err(ManifestError::Duplicate {
                    field: "armId".to_owned(),
                    value: arm.arm_id.clone(),
                });
            }
        }

        let mut scheduled = BTreeSet::new();
        for run in &self.scheduled_runs {
            if !case_ids.contains(&run.case_id) {
                return Err(ManifestError::Unknown {
                    field: "scheduledRuns.caseId".to_owned(),
                    value: run.case_id.clone(),
                });
            }
            if !arm_ids.contains(&run.arm_id) {
                return Err(ManifestError::Unknown {
                    field: "scheduledRuns.armId".to_owned(),
                    value: run.arm_id.clone(),
                });
            }
            if !scheduled.insert(run.clone()) {
                return Err(ManifestError::DuplicateRun(run.clone()));
            }
        }
        Ok(())
    }

    pub fn case(&self, case_id: &str) -> Option<&CaseManifest> {
        self.cases.iter().find(|case| case.case_id == case_id)
    }

    pub fn arm(&self, arm_id: &str) -> Option<&ArmManifest> {
        self.arms.iter().find(|arm| arm.arm_id == arm_id)
    }

    pub fn is_scheduled(&self, key: &RunKey) -> bool {
        self.scheduled_runs.iter().any(|scheduled| scheduled == key)
    }

    pub fn validate_truth_set(&self, truth_set: &TruthSet) -> Result<(), ManifestError> {
        let case = self
            .case(&truth_set.case_id)
            .ok_or_else(|| ManifestError::Unknown {
                field: "truthSet.caseId".to_owned(),
                value: truth_set.case_id.clone(),
            })?;
        truth_set.validate_for_case(case)
    }
}

impl TruthSet {
    pub fn validate_for_case(&self, case: &CaseManifest) -> Result<(), ManifestError> {
        if self.case_id != case.case_id {
            return Err(ManifestError::TruthCaseMismatch {
                expected: case.case_id.clone(),
                actual: self.case_id.clone(),
            });
        }

        let mut truth_ids = BTreeSet::new();
        for truth in &self.truths {
            require_nonempty(&truth.truth_id, "truths.truthId")?;
            require_nonempty(&truth.root_cause, "truths.rootCause")?;
            require_nonempty(&truth.affected_behavior, "truths.affectedBehavior")?;
            require_nonempty(&truth.material_impact, "truths.materialImpact")?;
            require_nonempty(&truth.bug_family, "truths.bugFamily")?;
            if !truth_ids.insert(truth.truth_id.clone()) {
                return Err(ManifestError::Duplicate {
                    field: "truthId".to_owned(),
                    value: truth.truth_id.clone(),
                });
            }
        }

        let primary_count = self
            .truths
            .iter()
            .filter(|truth| truth.in_scope && primary_weight(truth.severity).is_some())
            .count();
        match case.kind {
            CaseKind::CleanControl if primary_count != 0 => {
                return Err(ManifestError::DirtyCleanControl {
                    case_id: case.case_id.clone(),
                });
            }
            CaseKind::Vulnerable if primary_count == 0 => {
                return Err(ManifestError::EmptyPrimaryUniverse {
                    case_id: case.case_id.clone(),
                });
            }
            _ => {}
        }

        let actual = canonical_sha256(self)?;
        if actual != case.truth_set_sha256 {
            return Err(ManifestError::TruthHashMismatch {
                case_id: case.case_id.clone(),
            });
        }
        Ok(())
    }
}

pub fn scoped_paths_sha256(paths: &[String]) -> Result<String, CanonicalError> {
    let mut paths = paths.to_vec();
    paths.sort();
    canonical_sha256(&paths)
}

pub(crate) fn primary_weight(severity: Severity) -> Option<u64> {
    match severity {
        Severity::Critical => Some(4),
        Severity::High => Some(3),
        Severity::Medium => Some(2),
        Severity::Low | Severity::Informational => None,
    }
}

fn require_nonempty(value: &str, field: &str) -> Result<(), ManifestError> {
    if value.trim().is_empty() {
        return Err(ManifestError::Empty {
            field: field.to_owned(),
        });
    }
    Ok(())
}

fn require_sha256(value: &str, field: &str) -> Result<(), ManifestError> {
    if !is_sha256(value) || value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(ManifestError::InvalidSha256 {
            field: field.to_owned(),
        });
    }
    Ok(())
}
