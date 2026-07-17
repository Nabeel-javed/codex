use std::collections::BTreeMap;
use std::collections::BTreeSet;

use codex_auditbase_contract::AuditResult;
use codex_auditbase_contract::Confidence;
use codex_auditbase_contract::FindingStatus;
use codex_auditbase_contract::Severity;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;

use crate::CandidateDisposition;
use crate::FinalCandidateDecision;
use crate::TruthSet;
use crate::canonical_sha256;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CandidateFinding {
    pub finding_id: String,
    pub output_index: u32,
    pub predicted_severity: Severity,
    pub predicted_status: FindingStatus,
    pub predicted_confidence: Confidence,
    pub content_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedMatching {
    pub(crate) result_sha256: String,
    pub(crate) candidates: Vec<CandidateFinding>,
    pub(crate) decisions: BTreeMap<String, FinalCandidateDecision>,
    pub(crate) truth_to_candidate: BTreeMap<String, String>,
    pub(crate) duplicate_count: u32,
}

impl ResolvedMatching {
    pub fn result_sha256(&self) -> &str {
        &self.result_sha256
    }

    pub fn candidates(&self) -> &[CandidateFinding] {
        &self.candidates
    }

    pub fn decisions(&self) -> &BTreeMap<String, FinalCandidateDecision> {
        &self.decisions
    }

    pub fn truth_to_candidate(&self) -> &BTreeMap<String, String> {
        &self.truth_to_candidate
    }

    pub fn duplicate_count(&self) -> u32 {
        self.duplicate_count
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MatchingError {
    #[error("decision case {actual} does not match truth-set case {expected}")]
    CaseMismatch { expected: String, actual: String },
    #[error("missing adjudication decision for candidate {0}")]
    MissingDecision(String),
    #[error("decision exists for unknown candidate {0}")]
    UnknownCandidate(String),
    #[error("decision for candidate {0} is bound to a different AuditResult artifact")]
    ResultBindingMismatch(String),
    #[error("decision for candidate {0} is bound to different candidate content")]
    CandidateContentMismatch(String),
    #[error("duplicate decision for candidate {0}")]
    DuplicateDecision(String),
    #[error("candidate {0} has an empty cluster ID")]
    EmptyCluster(String),
    #[error("cluster {0} has more than one representative")]
    MultipleRepresentatives(String),
    #[error("cluster {0} has no representative")]
    MissingRepresentative(String),
    #[error("candidate {candidate} points to invalid duplicate representative {representative}")]
    InvalidDuplicate {
        candidate: String,
        representative: String,
    },
    #[error("duplicate candidate {candidate} precedes representative {representative}")]
    NonCanonicalRepresentative {
        candidate: String,
        representative: String,
    },
    #[error("candidate {0} is marked representative but has DuplicateOf disposition")]
    RepresentativeIsDuplicate(String),
    #[error("candidate {0} is not a representative but lacks DuplicateOf disposition")]
    NonRepresentativeNotDuplicate(String),
    #[error("candidate {candidate} references unknown truth {truth}")]
    UnknownTruth { candidate: String, truth: String },
    #[error("candidate {0} claims a match without satisfying every semantic axis")]
    SemanticMismatch(String),
    #[error("candidate {0} claims a match without being both actionable and verified")]
    UnqualifiedMatch(String),
    #[error("truth {truth} is matched by both {first} and {second}")]
    TruthCollision {
        truth: String,
        first: String,
        second: String,
    },
    #[error("candidate {0} has an unresolved novel finding")]
    NovelPending(String),
    #[error("candidate {0} contains an unresolved compound finding")]
    CompoundUnsplit(String),
    #[error("failed to hash candidate {0}")]
    CandidateHash(String),
}

pub fn resolve_matching(
    truth_set: &TruthSet,
    result: &AuditResult,
    decisions: Vec<FinalCandidateDecision>,
) -> Result<ResolvedMatching, MatchingError> {
    let result_sha256 = canonical_sha256(result)
        .map_err(|_| MatchingError::CandidateHash("<audit-result>".to_owned()))?;
    let mut candidates = Vec::with_capacity(result.findings.len());
    for (index, finding) in result.findings.iter().enumerate() {
        let content_sha256 = canonical_sha256(finding)
            .map_err(|_| MatchingError::CandidateHash(finding.id.clone()))?;
        candidates.push(CandidateFinding {
            finding_id: finding.id.clone(),
            output_index: index as u32,
            predicted_severity: finding.severity,
            predicted_status: finding.status,
            predicted_confidence: finding.confidence,
            content_sha256,
        });
    }
    let candidate_by_id: BTreeMap<_, _> = candidates
        .iter()
        .map(|candidate| (candidate.finding_id.clone(), candidate))
        .collect();
    let truth_ids: BTreeSet<_> = truth_set
        .truths
        .iter()
        .map(|truth| truth.truth_id.as_str())
        .collect();

    let mut decision_by_id = BTreeMap::new();
    for decision in decisions {
        if decision.case_id != truth_set.case_id {
            return Err(MatchingError::CaseMismatch {
                expected: truth_set.case_id.clone(),
                actual: decision.case_id,
            });
        }
        let Some(candidate) = candidate_by_id.get(&decision.candidate_id) else {
            return Err(MatchingError::UnknownCandidate(decision.candidate_id));
        };
        if decision.result_sha256 != result_sha256 {
            return Err(MatchingError::ResultBindingMismatch(decision.candidate_id));
        }
        if decision.candidate_content_sha256 != candidate.content_sha256 {
            return Err(MatchingError::CandidateContentMismatch(
                decision.candidate_id,
            ));
        }
        if decision.cluster_id.trim().is_empty() {
            return Err(MatchingError::EmptyCluster(decision.candidate_id));
        }
        let id = decision.candidate_id.clone();
        if decision_by_id.insert(id.clone(), decision).is_some() {
            return Err(MatchingError::DuplicateDecision(id));
        }
    }
    for candidate in &candidates {
        if !decision_by_id.contains_key(&candidate.finding_id) {
            return Err(MatchingError::MissingDecision(candidate.finding_id.clone()));
        }
    }

    let mut clusters: BTreeMap<String, Vec<&FinalCandidateDecision>> = BTreeMap::new();
    for decision in decision_by_id.values() {
        clusters
            .entry(decision.cluster_id.clone())
            .or_default()
            .push(decision);
    }
    let mut duplicate_count = 0_u32;
    for (cluster_id, members) in &clusters {
        let representatives: Vec<_> = members
            .iter()
            .filter(|decision| decision.representative)
            .collect();
        if representatives.is_empty() {
            return Err(MatchingError::MissingRepresentative(cluster_id.clone()));
        }
        if representatives.len() > 1 {
            return Err(MatchingError::MultipleRepresentatives(cluster_id.clone()));
        }
        let representative = representatives[0];
        if matches!(
            representative.disposition,
            CandidateDisposition::DuplicateOf { .. }
        ) {
            return Err(MatchingError::RepresentativeIsDuplicate(
                representative.candidate_id.clone(),
            ));
        }
        let representative_index = candidate_by_id[&representative.candidate_id].output_index;
        for member in members {
            if member.representative {
                continue;
            }
            duplicate_count += 1;
            let CandidateDisposition::DuplicateOf { representative_id } = &member.disposition
            else {
                return Err(MatchingError::NonRepresentativeNotDuplicate(
                    member.candidate_id.clone(),
                ));
            };
            if representative_id != &representative.candidate_id {
                return Err(MatchingError::InvalidDuplicate {
                    candidate: member.candidate_id.clone(),
                    representative: representative_id.clone(),
                });
            }
            if candidate_by_id[&member.candidate_id].output_index < representative_index {
                return Err(MatchingError::NonCanonicalRepresentative {
                    candidate: member.candidate_id.clone(),
                    representative: representative.candidate_id.clone(),
                });
            }
        }
    }

    let mut truth_to_candidate = BTreeMap::new();
    for decision in decision_by_id
        .values()
        .filter(|decision| decision.representative)
    {
        let truth_id = match &decision.disposition {
            CandidateDisposition::Matches { truth_id }
            | CandidateDisposition::NovelConfirmed { truth_id } => Some(truth_id),
            CandidateDisposition::NovelPending => {
                return Err(MatchingError::NovelPending(decision.candidate_id.clone()));
            }
            CandidateDisposition::CompoundUnsplit => {
                return Err(MatchingError::CompoundUnsplit(
                    decision.candidate_id.clone(),
                ));
            }
            CandidateDisposition::DuplicateOf { representative_id } => {
                return Err(MatchingError::InvalidDuplicate {
                    candidate: decision.candidate_id.clone(),
                    representative: representative_id.clone(),
                });
            }
            CandidateDisposition::Unsupported
            | CandidateDisposition::RealButBelowPrimarySeverity
            | CandidateDisposition::RealButOutOfScope
            | CandidateDisposition::OverclassifiedBelowPrimary => None,
        };
        let Some(truth_id) = truth_id else {
            continue;
        };
        if !truth_ids.contains(truth_id.as_str()) {
            return Err(MatchingError::UnknownTruth {
                candidate: decision.candidate_id.clone(),
                truth: truth_id.clone(),
            });
        }
        if !decision.assessment.is_primary_match() {
            return Err(MatchingError::SemanticMismatch(
                decision.candidate_id.clone(),
            ));
        }
        if !decision.actionable || !decision.verified {
            return Err(MatchingError::UnqualifiedMatch(
                decision.candidate_id.clone(),
            ));
        }
        if let Some(first) =
            truth_to_candidate.insert(truth_id.clone(), decision.candidate_id.clone())
        {
            return Err(MatchingError::TruthCollision {
                truth: truth_id.clone(),
                first,
                second: decision.candidate_id.clone(),
            });
        }
    }

    Ok(ResolvedMatching {
        result_sha256,
        candidates,
        decisions: decision_by_id,
        truth_to_candidate,
        duplicate_count,
    })
}
