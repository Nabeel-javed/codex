use std::collections::BTreeMap;

use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;

use crate::is_sha256;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AxisDecision {
    Same,
    Different,
    Insufficient,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LocationRelation {
    SameFunction,
    DirectlyCoupledTransition,
    Different,
    Missing,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SemanticAssessment {
    pub root_cause: AxisDecision,
    pub affected_behavior: AxisDecision,
    pub material_impact: AxisDecision,
    pub location: LocationRelation,
}

impl SemanticAssessment {
    pub fn is_primary_match(&self) -> bool {
        self.root_cause == AxisDecision::Same
            && self.affected_behavior == AxisDecision::Same
            && self.material_impact == AxisDecision::Same
            && matches!(
                self.location,
                LocationRelation::SameFunction | LocationRelation::DirectlyCoupledTransition
            )
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum CandidateDisposition {
    Matches { truth_id: String },
    DuplicateOf { representative_id: String },
    NovelPending,
    NovelConfirmed { truth_id: String },
    Unsupported,
    RealButBelowPrimarySeverity,
    RealButOutOfScope,
    OverclassifiedBelowPrimary,
    CompoundUnsplit,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewerVote {
    pub rubric_version: String,
    pub blinded_batch_id: String,
    pub reviewer_id: String,
    pub case_id: String,
    pub candidate_id: String,
    pub result_sha256: String,
    pub candidate_content_sha256: String,
    pub cluster_id: String,
    pub representative: bool,
    pub assessment: SemanticAssessment,
    pub disposition: CandidateDisposition,
    pub actionable: bool,
    pub verified: bool,
    pub rationale: String,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionKind {
    Agreement,
    ThirdReviewer,
    Panel,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinalCandidateDecision {
    pub case_id: String,
    pub candidate_id: String,
    pub result_sha256: String,
    pub candidate_content_sha256: String,
    pub cluster_id: String,
    pub representative: bool,
    pub assessment: SemanticAssessment,
    pub disposition: CandidateDisposition,
    pub actionable: bool,
    pub verified: bool,
    pub resolution: ResolutionKind,
    pub rationale: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReviewResolution {
    Resolved(FinalCandidateDecision),
    NeedsThirdReview,
    NeedsPanel,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct DecisionKey {
    case_id: String,
    candidate_id: String,
    result_sha256: String,
    candidate_content_sha256: String,
    cluster_id: String,
    representative: bool,
    assessment: SemanticAssessment,
    disposition: CandidateDisposition,
    actionable: bool,
    verified: bool,
}

#[derive(Debug, Error)]
pub enum AdjudicationError {
    #[error("two or three independent reviewer votes are required")]
    InvalidVoteCount,
    #[error("reviewer IDs must be unique")]
    DuplicateReviewer,
    #[error("all votes must use the same rubric version")]
    RubricMismatch,
    #[error("all votes must come from the same blinded batch")]
    BlindedBatchMismatch,
    #[error("all votes must concern the same case and candidate")]
    CandidateMismatch,
    #[error("review vote contains an invalid lowercase result or candidate SHA-256 digest")]
    InvalidArtifactHash,
    #[error("all votes must bind the same result and candidate content digests")]
    ArtifactBindingMismatch,
    #[error("panel decision must concern the same case and candidate as the votes")]
    PanelMismatch,
    #[error("panel resolution is allowed only after three distinct decisions")]
    PanelNotRequired,
}

pub fn resolve_reviewer_votes(
    votes: &[ReviewerVote],
) -> Result<ReviewResolution, AdjudicationError> {
    if !(votes.len() == 2 || votes.len() == 3) {
        return Err(AdjudicationError::InvalidVoteCount);
    }
    let reviewer_ids: std::collections::BTreeSet<_> =
        votes.iter().map(|vote| vote.reviewer_id.as_str()).collect();
    if reviewer_ids.len() != votes.len() {
        return Err(AdjudicationError::DuplicateReviewer);
    }
    let first = &votes[0];
    if votes.iter().any(|vote| {
        !is_lower_sha256(&vote.result_sha256) || !is_lower_sha256(&vote.candidate_content_sha256)
    }) {
        return Err(AdjudicationError::InvalidArtifactHash);
    }
    if votes
        .iter()
        .any(|vote| vote.rubric_version != first.rubric_version)
    {
        return Err(AdjudicationError::RubricMismatch);
    }
    if votes
        .iter()
        .any(|vote| vote.blinded_batch_id != first.blinded_batch_id)
    {
        return Err(AdjudicationError::BlindedBatchMismatch);
    }
    if votes
        .iter()
        .any(|vote| vote.case_id != first.case_id || vote.candidate_id != first.candidate_id)
    {
        return Err(AdjudicationError::CandidateMismatch);
    }
    if votes.iter().any(|vote| {
        vote.result_sha256 != first.result_sha256
            || vote.candidate_content_sha256 != first.candidate_content_sha256
    }) {
        return Err(AdjudicationError::ArtifactBindingMismatch);
    }

    let mut counts: BTreeMap<DecisionKey, usize> = BTreeMap::new();
    for vote in votes {
        *counts.entry(DecisionKey::from(vote)).or_default() += 1;
    }
    if let Some((key, _)) = counts.iter().find(|(_, count)| **count >= 2) {
        let kind = if votes.len() == 2 {
            ResolutionKind::Agreement
        } else {
            ResolutionKind::ThirdReviewer
        };
        let rationales = votes
            .iter()
            .filter(|vote| DecisionKey::from(*vote) == *key)
            .map(|vote| vote.rationale.trim())
            .filter(|rationale| !rationale.is_empty())
            .collect::<Vec<_>>()
            .join(" | ");
        return Ok(ReviewResolution::Resolved(
            key.clone().into_final(kind, rationales),
        ));
    }
    Ok(if votes.len() == 2 {
        ReviewResolution::NeedsThirdReview
    } else {
        ReviewResolution::NeedsPanel
    })
}

pub fn resolve_by_panel(
    votes: &[ReviewerVote],
    mut panel: FinalCandidateDecision,
) -> Result<ReviewResolution, AdjudicationError> {
    if votes.len() != 3 {
        return Err(AdjudicationError::InvalidVoteCount);
    }
    if resolve_reviewer_votes(votes)? != ReviewResolution::NeedsPanel {
        return Err(AdjudicationError::PanelNotRequired);
    }
    let first = votes.first().ok_or(AdjudicationError::InvalidVoteCount)?;
    if panel.case_id != first.case_id
        || panel.candidate_id != first.candidate_id
        || panel.result_sha256 != first.result_sha256
        || panel.candidate_content_sha256 != first.candidate_content_sha256
    {
        return Err(AdjudicationError::PanelMismatch);
    }
    panel.resolution = ResolutionKind::Panel;
    Ok(ReviewResolution::Resolved(panel))
}

impl From<&ReviewerVote> for DecisionKey {
    fn from(vote: &ReviewerVote) -> Self {
        Self {
            case_id: vote.case_id.clone(),
            candidate_id: vote.candidate_id.clone(),
            result_sha256: vote.result_sha256.clone(),
            candidate_content_sha256: vote.candidate_content_sha256.clone(),
            cluster_id: vote.cluster_id.clone(),
            representative: vote.representative,
            assessment: vote.assessment.clone(),
            disposition: vote.disposition.clone(),
            actionable: vote.actionable,
            verified: vote.verified,
        }
    }
}

impl DecisionKey {
    fn into_final(self, resolution: ResolutionKind, rationale: String) -> FinalCandidateDecision {
        FinalCandidateDecision {
            case_id: self.case_id,
            candidate_id: self.candidate_id,
            result_sha256: self.result_sha256,
            candidate_content_sha256: self.candidate_content_sha256,
            cluster_id: self.cluster_id,
            representative: self.representative,
            assessment: self.assessment,
            disposition: self.disposition,
            actionable: self.actionable,
            verified: self.verified,
            resolution,
            rationale,
        }
    }
}

fn is_lower_sha256(value: &str) -> bool {
    is_sha256(value) && !value.bytes().any(|byte| byte.is_ascii_uppercase())
}
