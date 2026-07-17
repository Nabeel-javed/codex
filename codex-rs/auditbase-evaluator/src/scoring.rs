use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

use codex_auditbase_contract::TerminalAuditStatus;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;

use crate::AcceptedRun;
use crate::CandidateDisposition;
use crate::CaseKind;
use crate::EvaluationManifest;
use crate::ResolvedMatching;
use crate::RunKey;
use crate::RunOutcome;
use crate::TruthSet;
use crate::canonical_sha256;
use crate::primary_weight;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Rational {
    pub numerator: u128,
    pub denominator: u128,
}

impl Rational {
    pub const ZERO: Self = Self {
        numerator: 0,
        denominator: 1,
    };
    pub const ONE: Self = Self {
        numerator: 1,
        denominator: 1,
    };

    pub fn new(numerator: u128, denominator: u128) -> Result<Self, ScoringError> {
        if denominator == 0 {
            return Err(ScoringError::ZeroDenominator);
        }
        if numerator == 0 {
            return Ok(Self::ZERO);
        }
        let divisor = gcd(numerator, denominator);
        Ok(Self {
            numerator: numerator / divisor,
            denominator: denominator / divisor,
        })
    }

    pub fn checked_add(self, other: Self) -> Result<Self, ScoringError> {
        let left = self
            .numerator
            .checked_mul(other.denominator)
            .ok_or(ScoringError::Overflow)?;
        let right = other
            .numerator
            .checked_mul(self.denominator)
            .ok_or(ScoringError::Overflow)?;
        let numerator = left.checked_add(right).ok_or(ScoringError::Overflow)?;
        let denominator = self
            .denominator
            .checked_mul(other.denominator)
            .ok_or(ScoringError::Overflow)?;
        Self::new(numerator, denominator)
    }

    pub fn checked_div_u128(self, divisor: u128) -> Result<Self, ScoringError> {
        if divisor == 0 {
            return Err(ScoringError::ZeroDenominator);
        }
        let denominator = self
            .denominator
            .checked_mul(divisor)
            .ok_or(ScoringError::Overflow)?;
        Self::new(self.numerator, denominator)
    }
}

impl PartialOrd for Rational {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        let left = self.numerator.checked_mul(other.denominator)?;
        let right = other.numerator.checked_mul(self.denominator)?;
        Some(left.cmp(&right))
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WeightedCounts {
    pub true_positive: u64,
    pub false_negative: u64,
    pub false_positive: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VulnerableScore {
    pub counts: WeightedCounts,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub precision: Option<Rational>,
    pub recall: Rational,
    pub f1: Rational,
    pub f2: Rational,
    pub duplicate_count: u32,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CleanControlScore {
    pub passed: bool,
    pub invalid: bool,
    pub false_positive_count: u32,
    pub false_positive_weight: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub false_positives_per_ksloc: Option<Rational>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "score")]
pub enum QualityScore {
    Vulnerable(VulnerableScore),
    CleanControl(CleanControlScore),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunScore {
    key: RunKey,
    attempt: u32,
    attempt_trace_sha256: String,
    valid_artifact: bool,
    valid_completion: bool,
    quality: QualityScore,
}

impl RunScore {
    pub fn key(&self) -> &RunKey {
        &self.key
    }

    pub fn attempt(&self) -> u32 {
        self.attempt
    }

    pub fn attempt_trace_sha256(&self) -> &str {
        &self.attempt_trace_sha256
    }

    pub fn valid_artifact(&self) -> bool {
        self.valid_artifact
    }

    pub fn valid_completion(&self) -> bool {
        self.valid_completion
    }

    pub fn quality(&self) -> &QualityScore {
        &self.quality
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MacroScore {
    pub project_scores: BTreeMap<String, Rational>,
    pub project_macro_weighted_f2: Rational,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ScoringError {
    #[error("division by zero")]
    ZeroDenominator,
    #[error("metric arithmetic overflow")]
    Overflow,
    #[error("unknown case: {0}")]
    UnknownCase(String),
    #[error("evaluator manifest or truth binding is invalid: {0}")]
    InvalidBinding(String),
    #[error("run provenance does not match its pre-registered arm")]
    ProvenanceMismatch,
    #[error("resolved matching belongs to a different AuditResult artifact")]
    MatchingResultMismatch,
    #[error("run case {run_case} and truth-set case {truth_case} differ")]
    TruthCaseMismatch {
        run_case: String,
        truth_case: String,
    },
    #[error("valid run requires resolved matching")]
    MissingMatching,
    #[error("invalid or void run must not provide matching")]
    UnexpectedMatching,
    #[error(
        "void-before-start run has no quality score and must be replaced under the frozen retry policy"
    )]
    VoidRun,
    #[error("case kind and truth universe are inconsistent")]
    InvalidTruthUniverse,
    #[error("run score is not scheduled: {0:?}")]
    UnscheduledScore(RunKey),
    #[error("duplicate official score for run: {0:?}")]
    DuplicateScore(RunKey),
    #[error("missing official score for run: {0:?}")]
    MissingScore(RunKey),
    #[error("macro score received a clean-control score for vulnerable run {0:?}")]
    WrongScoreKind(RunKey),
    #[error("no vulnerable project scores exist")]
    EmptyMacro,
}

pub fn score_run(
    manifest: &EvaluationManifest,
    truth_set: &TruthSet,
    accepted: &AcceptedRun,
    matching: Option<&ResolvedMatching>,
) -> Result<RunScore, ScoringError> {
    let run = accepted.run();
    manifest
        .validate()
        .map_err(|error| ScoringError::InvalidBinding(error.to_string()))?;
    if !manifest.is_scheduled(&run.key) {
        return Err(ScoringError::UnscheduledScore(run.key.clone()));
    }
    let case = manifest
        .case(&run.key.case_id)
        .ok_or_else(|| ScoringError::UnknownCase(run.key.case_id.clone()))?;
    let arm = manifest
        .arm(&run.key.arm_id)
        .ok_or_else(|| ScoringError::InvalidBinding("unknown run arm".to_owned()))?;
    if run.arm_config_sha256 != arm.arm_config_sha256
        || !is_lower_sha256(&run.run_provenance_sha256)
    {
        return Err(ScoringError::ProvenanceMismatch);
    }
    manifest
        .validate_truth_set(truth_set)
        .map_err(|error| ScoringError::InvalidBinding(error.to_string()))?;
    if truth_set.case_id != run.key.case_id {
        return Err(ScoringError::TruthCaseMismatch {
            run_case: run.key.case_id.clone(),
            truth_case: truth_set.case_id.clone(),
        });
    }
    let primary_truth_weight: u64 = truth_set
        .truths
        .iter()
        .filter(|truth| truth.in_scope)
        .filter_map(|truth| primary_weight(truth.severity))
        .sum();
    match case.kind {
        CaseKind::Vulnerable if primary_truth_weight == 0 => {
            return Err(ScoringError::InvalidTruthUniverse);
        }
        CaseKind::CleanControl if primary_truth_weight != 0 => {
            return Err(ScoringError::InvalidTruthUniverse);
        }
        _ => {}
    }

    match &run.outcome {
        RunOutcome::VoidBeforeStart { .. } => Err(ScoringError::VoidRun),
        RunOutcome::Invalid { .. } => {
            if matching.is_some() {
                return Err(ScoringError::UnexpectedMatching);
            }
            let quality = match case.kind {
                CaseKind::Vulnerable => QualityScore::Vulnerable(vulnerable_score(
                    WeightedCounts {
                        true_positive: 0,
                        false_negative: primary_truth_weight,
                        false_positive: 0,
                    },
                    0,
                )?),
                CaseKind::CleanControl => QualityScore::CleanControl(CleanControlScore {
                    passed: false,
                    invalid: true,
                    false_positive_count: 0,
                    false_positive_weight: 0,
                    false_positives_per_ksloc: None,
                }),
            };
            Ok(RunScore {
                key: run.key.clone(),
                attempt: run.attempt,
                attempt_trace_sha256: accepted.attempt_trace_sha256().to_owned(),
                valid_artifact: false,
                valid_completion: false,
                quality,
            })
        }
        RunOutcome::Valid { result, .. } => {
            let matching = matching.ok_or(ScoringError::MissingMatching)?;
            let result_sha256 =
                canonical_sha256(result).map_err(|_| ScoringError::MatchingResultMismatch)?;
            if result_sha256 != matching.result_sha256 {
                return Err(ScoringError::MatchingResultMismatch);
            }
            let quality = match case.kind {
                CaseKind::Vulnerable => {
                    QualityScore::Vulnerable(score_vulnerable(truth_set, matching)?)
                }
                CaseKind::CleanControl => {
                    QualityScore::CleanControl(score_clean(case.sloc, matching)?)
                }
            };
            Ok(RunScore {
                key: run.key.clone(),
                attempt: run.attempt,
                attempt_trace_sha256: accepted.attempt_trace_sha256().to_owned(),
                valid_artifact: true,
                valid_completion: result.status == TerminalAuditStatus::Completed,
                quality,
            })
        }
    }
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

pub fn project_macro_weighted_f2(
    manifest: &EvaluationManifest,
    arm_id: &str,
    scores: &[RunScore],
) -> Result<MacroScore, ScoringError> {
    let expected: Vec<_> = manifest
        .scheduled_runs
        .iter()
        .filter(|key| key.arm_id == arm_id)
        .filter(|key| {
            manifest
                .case(&key.case_id)
                .is_some_and(|case| case.kind == CaseKind::Vulnerable)
        })
        .cloned()
        .collect();
    let expected_set: BTreeSet<_> = expected.iter().cloned().collect();
    let mut by_key = BTreeMap::new();
    for score in scores.iter().filter(|score| score.key.arm_id == arm_id) {
        let Some(case) = manifest.case(&score.key.case_id) else {
            return Err(ScoringError::UnknownCase(score.key.case_id.clone()));
        };
        if case.kind == CaseKind::CleanControl {
            continue;
        }
        if !expected_set.contains(&score.key) {
            return Err(ScoringError::UnscheduledScore(score.key.clone()));
        }
        if by_key.insert(score.key.clone(), score).is_some() {
            return Err(ScoringError::DuplicateScore(score.key.clone()));
        }
    }
    for key in &expected {
        if !by_key.contains_key(key) {
            return Err(ScoringError::MissingScore(key.clone()));
        }
    }

    let mut by_project: BTreeMap<String, Vec<Rational>> = BTreeMap::new();
    for key in expected {
        let case = manifest
            .case(&key.case_id)
            .ok_or_else(|| ScoringError::UnknownCase(key.case_id.clone()))?;
        let score = by_key[&key];
        let QualityScore::Vulnerable(score) = &score.quality else {
            return Err(ScoringError::WrongScoreKind(key));
        };
        by_project
            .entry(case.project_id.clone())
            .or_default()
            .push(score.f2);
    }
    if by_project.is_empty() {
        return Err(ScoringError::EmptyMacro);
    }

    let mut project_scores = BTreeMap::new();
    for (project, values) in by_project {
        project_scores.insert(project, mean(&values)?);
    }
    let macro_score = mean(&project_scores.values().copied().collect::<Vec<_>>())?;
    Ok(MacroScore {
        project_scores,
        project_macro_weighted_f2: macro_score,
    })
}

fn score_vulnerable(
    truth_set: &TruthSet,
    matching: &ResolvedMatching,
) -> Result<VulnerableScore, ScoringError> {
    let candidate_by_id: BTreeMap<_, _> = matching
        .candidates
        .iter()
        .map(|candidate| (candidate.finding_id.as_str(), candidate))
        .collect();
    let truth_by_id: BTreeMap<_, _> = truth_set
        .truths
        .iter()
        .map(|truth| (truth.truth_id.as_str(), truth))
        .collect();
    let mut counts = WeightedCounts::default();

    for truth in truth_set.truths.iter().filter(|truth| truth.in_scope) {
        let Some(weight) = primary_weight(truth.severity) else {
            continue;
        };
        let credited = matching
            .truth_to_candidate
            .get(&truth.truth_id)
            .and_then(|candidate_id| candidate_by_id.get(candidate_id.as_str()))
            .is_some_and(|candidate| primary_weight(candidate.predicted_severity).is_some());
        if credited {
            counts.true_positive += weight;
        } else {
            counts.false_negative += weight;
        }
    }

    for candidate in &matching.candidates {
        let Some(weight) = primary_weight(candidate.predicted_severity) else {
            continue;
        };
        let decision = &matching.decisions[&candidate.finding_id];
        if !decision.representative {
            continue;
        }
        let matched_primary = match &decision.disposition {
            CandidateDisposition::Matches { truth_id }
            | CandidateDisposition::NovelConfirmed { truth_id } => truth_by_id
                .get(truth_id.as_str())
                .is_some_and(|truth| truth.in_scope && primary_weight(truth.severity).is_some()),
            _ => false,
        };
        if !matched_primary {
            counts.false_positive += weight;
        }
    }
    vulnerable_score(counts, matching.duplicate_count)
}

fn score_clean(sloc: u64, matching: &ResolvedMatching) -> Result<CleanControlScore, ScoringError> {
    let mut false_positive_count = 0_u32;
    let mut false_positive_weight = 0_u64;
    for candidate in &matching.candidates {
        let Some(weight) = primary_weight(candidate.predicted_severity) else {
            continue;
        };
        if matching.decisions[&candidate.finding_id].representative {
            false_positive_count += 1;
            false_positive_weight += weight;
        }
    }
    let false_positives_per_ksloc = if sloc == 0 {
        None
    } else {
        Some(Rational::new(
            u128::from(false_positive_count) * 1_000,
            u128::from(sloc),
        )?)
    };
    Ok(CleanControlScore {
        passed: false_positive_count == 0,
        invalid: false,
        false_positive_count,
        false_positive_weight,
        false_positives_per_ksloc,
    })
}

fn vulnerable_score(
    counts: WeightedCounts,
    duplicate_count: u32,
) -> Result<VulnerableScore, ScoringError> {
    let tp = u128::from(counts.true_positive);
    let fp = u128::from(counts.false_positive);
    let fn_ = u128::from(counts.false_negative);
    let precision = if tp + fp == 0 {
        None
    } else {
        Some(Rational::new(tp, tp + fp)?)
    };
    let recall = Rational::new(tp, tp + fn_)?;
    let f1 = Rational::new(2 * tp, 2 * tp + fn_ + fp)?;
    let f2 = Rational::new(5 * tp, 5 * tp + 4 * fn_ + fp)?;
    Ok(VulnerableScore {
        counts,
        precision,
        recall,
        f1,
        f2,
        duplicate_count,
    })
}

fn mean(values: &[Rational]) -> Result<Rational, ScoringError> {
    if values.is_empty() {
        return Err(ScoringError::ZeroDenominator);
    }
    values
        .iter()
        .copied()
        .try_fold(Rational::ZERO, Rational::checked_add)?
        .checked_div_u128(values.len() as u128)
}

const fn gcd(mut left: u128, mut right: u128) -> u128 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}
