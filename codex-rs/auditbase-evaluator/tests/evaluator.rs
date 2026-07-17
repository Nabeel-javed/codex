#![allow(clippy::unwrap_used)]

use std::collections::BTreeSet;

use codex_auditbase_contract::AuditResult;
use codex_auditbase_contract::Severity;
use codex_auditbase_evaluator::*;
use pretty_assertions::assert_eq;
use serde_json::Value;
use serde_json::json;

const SOURCE_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const PROVENANCE_DIGEST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

#[test]
fn canonical_hash_ignores_object_key_order_but_preserves_array_order() {
    let left: Value = serde_json::from_str(r#"{"b":2,"a":[1,2]}"#).unwrap();
    let right: Value = serde_json::from_str(r#"{"a":[1,2],"b":2}"#).unwrap();
    let reversed: Value = serde_json::from_str(r#"{"a":[2,1],"b":2}"#).unwrap();

    assert_eq!(
        canonical_sha256(&left).unwrap(),
        canonical_sha256(&right).unwrap()
    );
    assert_ne!(
        canonical_sha256(&left).unwrap(),
        canonical_sha256(&reversed).unwrap()
    );
}

#[test]
fn manifest_binds_scope_truth_and_provenance_hashes() {
    let truth = vulnerable_truth();
    let manifest = one_case_manifest(&truth, CaseKind::Vulnerable, "project-a", "arm-a", 1);
    manifest.validate().unwrap();
    manifest.validate_truth_set(&truth).unwrap();

    let mut changed_truth = truth;
    changed_truth.truths[0].root_cause.push_str(" changed");
    assert!(matches!(
        manifest.validate_truth_set(&changed_truth),
        Err(ManifestError::TruthHashMismatch { .. })
    ));

    let result = result_json("audit-1", "completed", false, vec![]);
    let mut binding = binding(&manifest, "synthetic-vulnerable", "arm-a", "audit-1");
    binding.observed_arm_config_sha256 = SOURCE_DIGEST.to_owned();
    let run = ingest_result(
        &manifest,
        run_key("synthetic-vulnerable", "arm-a", 0),
        0,
        &binding,
        Some(&result),
    )
    .unwrap();
    assert!(matches!(
        run.outcome(),
        RunOutcome::Invalid {
            stage: InvalidStage::ProvenanceMismatch,
            ..
        }
    ));
}

#[test]
fn static_arm_config_is_shared_while_each_case_replicate_keeps_unique_run_provenance() {
    let truth_a = vulnerable_truth();
    let mut truth_b = vulnerable_truth();
    truth_b.case_id = "synthetic-vulnerable-b".to_owned();
    for truth in &mut truth_b.truths {
        truth.truth_id.push_str("-B");
    }

    let arm_config_sha256 = PROVENANCE_DIGEST.to_owned();
    let scheduled_runs: Vec<_> = [&truth_a.case_id, &truth_b.case_id]
        .into_iter()
        .flat_map(|case_id| (0..2).map(move |replicate| run_key(case_id, "arm-a", replicate)))
        .collect();
    let manifest = EvaluationManifest {
        spec_version: "auditbase.scoring.v0".to_owned(),
        evaluation_id: "eval-provenance".to_owned(),
        cases: vec![
            case_manifest(&truth_a, CaseKind::Vulnerable, "project-a"),
            case_manifest(&truth_b, CaseKind::Vulnerable, "project-b"),
        ],
        arms: vec![ArmManifest {
            arm_id: "arm-a".to_owned(),
            arm_config_sha256: arm_config_sha256.clone(),
        }],
        scheduled_runs,
        retry_policy: retry_policy(),
        contract_limits: evaluator_limits(),
    };
    manifest.validate().unwrap();

    let mut observed_run_provenance = BTreeSet::new();
    for key in &manifest.scheduled_runs {
        let audit_id = format!("audit-{}-{}", key.case_id, key.replicate);
        let result = result_json(&audit_id, "completed", false, vec![]);
        let mut binding = binding(&manifest, &key.case_id, &key.arm_id, &audit_id);
        binding.observed_run_provenance_sha256 =
            sha256_hex(format!("{}:{}", key.case_id, key.replicate).as_bytes());

        let run = ingest_result(&manifest, key.clone(), 0, &binding, Some(&result)).unwrap();
        assert_eq!(run.arm_config_sha256(), arm_config_sha256);
        assert_eq!(
            run.run_provenance_sha256(),
            binding.observed_run_provenance_sha256
        );
        assert!(matches!(run.outcome(), RunOutcome::Valid { .. }));
        assert!(observed_run_provenance.insert(run.run_provenance_sha256().to_owned()));
    }

    assert_eq!(observed_run_provenance.len(), 4);
}

#[test]
fn reviewer_agreement_disagreement_and_panel_paths_are_explicit() {
    let votes: Vec<ReviewerVote> =
        serde_json::from_str(include_str!("fixtures/reviewer-votes.json")).unwrap();
    let ReviewResolution::Resolved(agreed) = resolve_reviewer_votes(&votes).unwrap() else {
        panic!("matching votes must resolve");
    };
    assert_eq!(agreed.resolution, ResolutionKind::Agreement);

    let mut disagreement = votes.clone();
    disagreement[1].disposition = CandidateDisposition::Unsupported;
    assert_eq!(
        resolve_reviewer_votes(&disagreement).unwrap(),
        ReviewResolution::NeedsThirdReview
    );

    let mut third = votes[0].clone();
    third.reviewer_id = "reviewer-c".to_owned();
    let ReviewResolution::Resolved(resolved) =
        resolve_reviewer_votes(&[disagreement[0].clone(), disagreement[1].clone(), third]).unwrap()
    else {
        panic!("the third reviewer must break a two-way disagreement");
    };
    assert_eq!(resolved.resolution, ResolutionKind::ThirdReviewer);

    let mut third_way = votes[0].clone();
    third_way.reviewer_id = "reviewer-c".to_owned();
    third_way.disposition = CandidateDisposition::RealButOutOfScope;
    let three_way = vec![disagreement[0].clone(), disagreement[1].clone(), third_way];
    assert_eq!(
        resolve_reviewer_votes(&three_way).unwrap(),
        ReviewResolution::NeedsPanel
    );
    let panel = decision(
        "synthetic-vulnerable",
        "F-1",
        "cluster-1",
        true,
        CandidateDisposition::Unsupported,
    );
    let ReviewResolution::Resolved(panel) = resolve_by_panel(&three_way, panel).unwrap() else {
        panic!("a recorded panel must resolve a three-way disagreement");
    };
    assert_eq!(panel.resolution, ResolutionKind::Panel);
}

#[test]
fn reviewer_votes_and_matching_are_bound_to_exact_result_and_candidate_bytes() {
    let votes: Vec<ReviewerVote> =
        serde_json::from_str(include_str!("fixtures/reviewer-votes.json")).unwrap();
    let mut replayed_votes = votes;
    replayed_votes[1].candidate_content_sha256 = SOURCE_DIGEST.to_owned();
    assert!(matches!(
        resolve_reviewer_votes(&replayed_votes),
        Err(AdjudicationError::ArtifactBindingMismatch)
    ));

    let truth = vulnerable_truth();
    let result = parse_result(&result_json(
        "audit-bound",
        "completed",
        false,
        vec![finding("F-CRIT", "critical", "verified")],
    ));
    let mut bound = decision(
        "synthetic-vulnerable",
        "F-CRIT",
        "cluster-critical",
        true,
        CandidateDisposition::Matches {
            truth_id: "TRUTH-CRITICAL".to_owned(),
        },
    );
    bound.result_sha256 = canonical_sha256(&result).unwrap();
    bound.candidate_content_sha256 = canonical_sha256(&result.findings[0]).unwrap();

    let mut changed_result = result.clone();
    changed_result.summary.title = "Same candidate ID, different result".to_owned();
    assert_eq!(
        resolve_matching(&truth, &changed_result, vec![bound.clone()]),
        Err(MatchingError::ResultBindingMismatch("F-CRIT".to_owned()))
    );

    bound.result_sha256 = canonical_sha256(&result).unwrap();
    bound.candidate_content_sha256 = SOURCE_DIGEST.to_owned();
    assert_eq!(
        resolve_matching(&truth, &result, vec![bound]),
        Err(MatchingError::CandidateContentMismatch("F-CRIT".to_owned()))
    );
}

#[test]
fn matches_must_be_both_actionable_and_verified_before_receiving_credit() {
    let truth = vulnerable_truth();
    let result = parse_result(&result_json(
        "audit-qualified",
        "completed",
        false,
        vec![finding("F-CRIT", "critical", "verified")],
    ));
    for (actionable, verified) in [(false, true), (true, false), (false, false)] {
        let mut unqualified = decision(
            "synthetic-vulnerable",
            "F-CRIT",
            "cluster-critical",
            true,
            CandidateDisposition::Matches {
                truth_id: "TRUTH-CRITICAL".to_owned(),
            },
        );
        unqualified.actionable = actionable;
        unqualified.verified = verified;
        assert_eq!(
            resolve_bound_matching(&truth, &result, vec![unqualified]),
            Err(MatchingError::UnqualifiedMatch("F-CRIT".to_owned()))
        );
    }
}

#[test]
fn retry_selection_accepts_only_the_first_non_void_contiguous_attempt() {
    let truth = vulnerable_truth();
    let manifest = one_case_manifest(&truth, CaseKind::Vulnerable, "project-a", "arm-a", 1);
    let key = run_key("synthetic-vulnerable", "arm-a", 0);
    let void = void_before_start(
        key.clone(),
        0,
        PROVENANCE_DIGEST.to_owned(),
        SOURCE_DIGEST.to_owned(),
        "worker was not admitted",
    );
    let result = parse_result(&result_json("audit-retry", "completed", false, vec![]));
    let accepted = valid_run(
        &manifest,
        "synthetic-vulnerable",
        "arm-a",
        0,
        1,
        result.clone(),
    );

    let selected = select_accepted_attempt(&manifest, &key, &[accepted.clone(), void.clone()])
        .expect("input ordering must not affect deterministic retry selection");
    assert_eq!(selected.run().attempt(), 1);
    assert_eq!(selected.attempt_trace_sha256().len(), 64);

    assert_eq!(
        select_accepted_attempt(&manifest, &key, std::slice::from_ref(&void)),
        Err(RetrySelectionError::RetriesRemaining)
    );
    let second_void = void_before_start(
        key.clone(),
        1,
        PROVENANCE_DIGEST.to_owned(),
        PROVENANCE_DIGEST.to_owned(),
        "worker was not admitted",
    );
    assert_eq!(
        select_accepted_attempt(&manifest, &key, &[void, second_void]),
        Err(RetrySelectionError::RetriesExhausted)
    );
    assert_eq!(
        select_accepted_attempt(&manifest, &key, std::slice::from_ref(&accepted)),
        Err(RetrySelectionError::NonContiguousAttempt {
            expected: 0,
            actual: 1,
        })
    );

    let first = valid_run(&manifest, "synthetic-vulnerable", "arm-a", 0, 0, result);
    assert_eq!(
        select_accepted_attempt(&manifest, &key, &[first, accepted]),
        Err(RetrySelectionError::AttemptAfterAccepted)
    );
}

#[test]
fn evaluator_rejects_oversized_results_and_configured_nested_limit_violations() {
    let truth = vulnerable_truth();
    let bytes = result_json(
        "audit-limits",
        "completed",
        false,
        vec![finding("F-CRIT", "critical", "verified")],
    );

    let mut byte_limited = one_case_manifest(&truth, CaseKind::Vulnerable, "project-a", "arm-a", 1);
    byte_limited.contract_limits.max_result_bytes = 512;
    byte_limited.contract_limits.max_diagnostics_bytes = 512;
    byte_limited.contract_limits.max_diagnostic_item_bytes = 256;
    byte_limited.contract_limits.max_snippet_bytes = 256;
    byte_limited.contract_limits.max_finding_evidence_bytes = 512;
    byte_limited.contract_limits.max_evidence_item_bytes = 256;
    let byte_binding = binding(
        &byte_limited,
        "synthetic-vulnerable",
        "arm-a",
        "audit-limits",
    );
    let run = ingest_result(
        &byte_limited,
        run_key("synthetic-vulnerable", "arm-a", 0),
        0,
        &byte_binding,
        Some(&bytes),
    )
    .unwrap();
    assert!(matches!(
        run.outcome(),
        RunOutcome::Invalid {
            stage: InvalidStage::ArtifactLimits,
            code,
            ..
        } if code == "result_byte_limit_exceeded"
    ));
    let expected_artifact_sha256 = sha256_hex(&bytes);
    assert_eq!(
        run.artifact_sha256(),
        Some(expected_artifact_sha256.as_str())
    );
    assert_eq!(run.artifact_bytes(), Some(bytes.len() as u64));

    let mut nested_limited =
        one_case_manifest(&truth, CaseKind::Vulnerable, "project-a", "arm-a", 1);
    nested_limited.contract_limits.max_evidence_item_bytes = 32;
    let nested_binding = binding(
        &nested_limited,
        "synthetic-vulnerable",
        "arm-a",
        "audit-limits",
    );
    let run = ingest_result(
        &nested_limited,
        run_key("synthetic-vulnerable", "arm-a", 0),
        0,
        &nested_binding,
        Some(&bytes),
    )
    .unwrap();
    assert!(matches!(
        run.outcome(),
        RunOutcome::Invalid {
            stage: InvalidStage::ArtifactLimits,
            code,
            ..
        } if code == "contract_limits_exceeded"
    ));
}

#[test]
fn weighted_f2_uses_truth_weights_for_matches_and_misses_and_prediction_weights_for_fp() {
    let truth = vulnerable_truth();
    let manifest = one_case_manifest(&truth, CaseKind::Vulnerable, "project-a", "arm-a", 1);
    let findings = vec![
        finding("F-CRIT", "high", "verified"),
        finding("F-FP", "high", "suspected"),
    ];
    let result = parse_result(&result_json("audit-1", "completed", false, findings));
    let decisions = vec![
        decision(
            "synthetic-vulnerable",
            "F-CRIT",
            "cluster-critical",
            true,
            CandidateDisposition::Matches {
                truth_id: "TRUTH-CRITICAL".to_owned(),
            },
        ),
        decision(
            "synthetic-vulnerable",
            "F-FP",
            "cluster-fp",
            true,
            CandidateDisposition::Unsupported,
        ),
    ];
    let matching = resolve_bound_matching(&truth, &result, decisions).unwrap();
    let mut mismatched_result = result.clone();
    mismatched_result.summary.title = "Different result artifact".to_owned();
    let mismatched_run = valid_run(
        &manifest,
        "synthetic-vulnerable",
        "arm-a",
        0,
        0,
        mismatched_result,
    );
    let mismatched_run = accepted_run(&manifest, mismatched_run);
    assert_eq!(
        score_run(&manifest, &truth, &mismatched_run, Some(&matching)),
        Err(ScoringError::MatchingResultMismatch)
    );
    let run = valid_run(&manifest, "synthetic-vulnerable", "arm-a", 0, 0, result);
    let run = accepted_run(&manifest, run);
    let score = score_run(&manifest, &truth, &run, Some(&matching)).unwrap();
    let QualityScore::Vulnerable(score) = score.quality() else {
        panic!("expected vulnerable score");
    };

    // Critical matched = TP 4, Medium missed = FN 2, unmatched High = FP 3.
    assert_eq!(
        score.counts,
        WeightedCounts {
            true_positive: 4,
            false_negative: 2,
            false_positive: 3,
        }
    );
    assert_eq!(score.f2, Rational::new(20, 31).unwrap());
}

#[test]
fn failed_partial_findings_are_scored_but_completion_fails() {
    let truth = vulnerable_truth();
    let manifest = one_case_manifest(&truth, CaseKind::Vulnerable, "project-a", "arm-a", 1);
    let bytes = result_json(
        "audit-1",
        "failed",
        true,
        vec![finding("F-CRIT", "critical", "verified")],
    );
    let binding = binding(&manifest, "synthetic-vulnerable", "arm-a", "audit-1");
    let run = ingest_result(
        &manifest,
        run_key("synthetic-vulnerable", "arm-a", 0),
        0,
        &binding,
        Some(&bytes),
    )
    .unwrap();
    assert!(matches!(
        run.outcome(),
        RunOutcome::Valid {
            disposition: ValidRunDisposition::FailedPartial,
            ..
        }
    ));
    let RunOutcome::Valid { result, .. } = run.outcome() else {
        unreachable!()
    };
    let matching = resolve_bound_matching(
        &truth,
        result,
        vec![decision(
            "synthetic-vulnerable",
            "F-CRIT",
            "cluster-critical",
            true,
            CandidateDisposition::Matches {
                truth_id: "TRUTH-CRITICAL".to_owned(),
            },
        )],
    )
    .unwrap();
    let run = accepted_run(&manifest, run);
    let score = score_run(&manifest, &truth, &run, Some(&matching)).unwrap();
    assert!(score.valid_artifact());
    assert!(!score.valid_completion());
    let QualityScore::Vulnerable(score) = score.quality() else {
        unreachable!()
    };
    assert_eq!(score.counts.true_positive, 4);
    assert_eq!(score.counts.false_negative, 2);
}

#[test]
fn invalid_run_scores_zero_and_remains_in_the_denominator() {
    let truth = vulnerable_truth();
    let manifest = one_case_manifest(&truth, CaseKind::Vulnerable, "project-a", "arm-a", 1);
    let binding = binding(&manifest, "synthetic-vulnerable", "arm-a", "audit-1");
    let run = ingest_result(
        &manifest,
        run_key("synthetic-vulnerable", "arm-a", 0),
        0,
        &binding,
        Some(b"not json"),
    )
    .unwrap();
    let run = accepted_run(&manifest, run);
    let score = score_run(&manifest, &truth, &run, None).unwrap();
    assert!(!score.valid_artifact());
    let QualityScore::Vulnerable(quality) = score.quality() else {
        unreachable!()
    };
    assert_eq!(quality.f2, Rational::ZERO);
    assert_eq!(quality.counts.false_negative, 6);

    let macro_score = project_macro_weighted_f2(&manifest, "arm-a", &[score]).unwrap();
    assert_eq!(macro_score.project_macro_weighted_f2, Rational::ZERO);
}

#[test]
fn duplicate_spam_is_deduplicated_and_noncanonical_representative_is_rejected() {
    let truth = vulnerable_truth();
    let result = parse_result(&result_json(
        "audit-1",
        "completed",
        false,
        vec![
            finding("F-FIRST", "critical", "verified"),
            finding("F-DUP", "critical", "suspected"),
        ],
    ));
    let decisions = vec![
        decision(
            "synthetic-vulnerable",
            "F-FIRST",
            "cluster-critical",
            true,
            CandidateDisposition::Matches {
                truth_id: "TRUTH-CRITICAL".to_owned(),
            },
        ),
        decision(
            "synthetic-vulnerable",
            "F-DUP",
            "cluster-critical",
            false,
            CandidateDisposition::DuplicateOf {
                representative_id: "F-FIRST".to_owned(),
            },
        ),
    ];
    let matching = resolve_bound_matching(&truth, &result, decisions).unwrap();
    assert_eq!(matching.duplicate_count(), 1);
    assert_eq!(matching.truth_to_candidate()["TRUTH-CRITICAL"], "F-FIRST");

    let reversed = vec![
        decision(
            "synthetic-vulnerable",
            "F-FIRST",
            "cluster-critical",
            false,
            CandidateDisposition::DuplicateOf {
                representative_id: "F-DUP".to_owned(),
            },
        ),
        decision(
            "synthetic-vulnerable",
            "F-DUP",
            "cluster-critical",
            true,
            CandidateDisposition::Matches {
                truth_id: "TRUTH-CRITICAL".to_owned(),
            },
        ),
    ];
    assert!(matches!(
        resolve_bound_matching(&truth, &result, reversed),
        Err(MatchingError::NonCanonicalRepresentative { .. })
    ));
}

#[test]
fn truth_collision_and_unresolved_compound_findings_block_scoring() {
    let truth = vulnerable_truth();
    let result = parse_result(&result_json(
        "audit-1",
        "completed",
        false,
        vec![
            finding("F-1", "critical", "verified"),
            finding("F-2", "critical", "verified"),
        ],
    ));
    let collision = vec![
        decision(
            "synthetic-vulnerable",
            "F-1",
            "cluster-1",
            true,
            CandidateDisposition::Matches {
                truth_id: "TRUTH-CRITICAL".to_owned(),
            },
        ),
        decision(
            "synthetic-vulnerable",
            "F-2",
            "cluster-2",
            true,
            CandidateDisposition::Matches {
                truth_id: "TRUTH-CRITICAL".to_owned(),
            },
        ),
    ];
    assert!(matches!(
        resolve_bound_matching(&truth, &result, collision),
        Err(MatchingError::TruthCollision { .. })
    ));

    let compound = vec![
        decision(
            "synthetic-vulnerable",
            "F-1",
            "cluster-1",
            true,
            CandidateDisposition::CompoundUnsplit,
        ),
        decision(
            "synthetic-vulnerable",
            "F-2",
            "cluster-2",
            true,
            CandidateDisposition::Unsupported,
        ),
    ];
    assert_eq!(
        resolve_bound_matching(&truth, &result, compound),
        Err(MatchingError::CompoundUnsplit("F-1".to_owned()))
    );
}

#[test]
fn clean_controls_are_separate_from_primary_f2() {
    let truth = TruthSet {
        case_id: "synthetic-clean".to_owned(),
        revision: 1,
        truths: vec![],
    };
    let manifest = one_case_manifest(&truth, CaseKind::CleanControl, "project-clean", "arm-a", 1);
    let result = parse_result(&result_json(
        "audit-clean",
        "completed",
        false,
        vec![finding("F-FP", "medium", "suspected")],
    ));
    let matching = resolve_bound_matching(
        &truth,
        &result,
        vec![decision(
            "synthetic-clean",
            "F-FP",
            "cluster-fp",
            true,
            CandidateDisposition::Unsupported,
        )],
    )
    .unwrap();
    let run = valid_run(&manifest, "synthetic-clean", "arm-a", 0, 0, result);
    let run = accepted_run(&manifest, run);
    let score = score_run(&manifest, &truth, &run, Some(&matching)).unwrap();
    let QualityScore::CleanControl(clean) = score.quality() else {
        panic!("clean controls must not receive primary F2");
    };
    assert!(!clean.passed);
    assert_eq!(clean.false_positive_count, 1);
    assert_eq!(clean.false_positive_weight, 2);
    assert_eq!(clean.false_positives_per_ksloc, Some(Rational::ONE));
    assert_eq!(
        project_macro_weighted_f2(&manifest, "arm-a", &[score]),
        Err(ScoringError::EmptyMacro)
    );
}

#[test]
fn project_macro_gives_projects_equal_weight() {
    let truth_a = vulnerable_truth();
    let mut truth_b = vulnerable_truth();
    truth_b.case_id = "synthetic-vulnerable-b".to_owned();
    for truth in &mut truth_b.truths {
        truth.truth_id.push_str("-B");
    }
    let mut manifest = EvaluationManifest {
        spec_version: "auditbase.scoring.v0".to_owned(),
        evaluation_id: "eval-macro".to_owned(),
        cases: vec![
            case_manifest(&truth_a, CaseKind::Vulnerable, "project-a"),
            case_manifest(&truth_b, CaseKind::Vulnerable, "project-b"),
        ],
        arms: vec![ArmManifest {
            arm_id: "arm-a".to_owned(),
            arm_config_sha256: PROVENANCE_DIGEST.to_owned(),
        }],
        scheduled_runs: vec![],
        retry_policy: retry_policy(),
        contract_limits: evaluator_limits(),
    };
    manifest.scheduled_runs = vec![
        run_key("synthetic-vulnerable", "arm-a", 0),
        run_key("synthetic-vulnerable-b", "arm-a", 0),
    ];
    manifest.validate().unwrap();

    let perfect_result = parse_result(&result_json(
        "audit-perfect",
        "completed",
        false,
        vec![
            finding("F-CRIT", "critical", "verified"),
            finding("F-MED", "medium", "verified"),
        ],
    ));
    let perfect_matching = resolve_bound_matching(
        &truth_a,
        &perfect_result,
        vec![
            decision(
                "synthetic-vulnerable",
                "F-CRIT",
                "cluster-critical",
                true,
                CandidateDisposition::Matches {
                    truth_id: "TRUTH-CRITICAL".to_owned(),
                },
            ),
            decision(
                "synthetic-vulnerable",
                "F-MED",
                "cluster-medium",
                true,
                CandidateDisposition::Matches {
                    truth_id: "TRUTH-MEDIUM".to_owned(),
                },
            ),
        ],
    )
    .unwrap();
    let perfect = accepted_run(
        &manifest,
        valid_run(
            &manifest,
            "synthetic-vulnerable",
            "arm-a",
            0,
            0,
            perfect_result,
        ),
    );
    let perfect = score_run(&manifest, &truth_a, &perfect, Some(&perfect_matching)).unwrap();

    let zero_binding = binding(&manifest, "synthetic-vulnerable-b", "arm-a", "audit-zero");
    let zero = ingest_result(
        &manifest,
        run_key("synthetic-vulnerable-b", "arm-a", 0),
        0,
        &zero_binding,
        Some(b"not json"),
    )
    .unwrap();
    let zero = accepted_run(&manifest, zero);
    let zero = score_run(&manifest, &truth_b, &zero, None).unwrap();
    let macro_score = project_macro_weighted_f2(&manifest, "arm-a", &[perfect, zero]).unwrap();
    assert_eq!(
        macro_score.project_macro_weighted_f2,
        Rational::new(1, 2).unwrap()
    );
}

fn vulnerable_truth() -> TruthSet {
    serde_json::from_str(include_str!("fixtures/truth-set.json")).unwrap()
}

fn one_case_manifest(
    truth: &TruthSet,
    kind: CaseKind,
    project_id: &str,
    arm_id: &str,
    replicates: u32,
) -> EvaluationManifest {
    let mut manifest = EvaluationManifest {
        spec_version: "auditbase.scoring.v0".to_owned(),
        evaluation_id: "synthetic-evaluation".to_owned(),
        cases: vec![case_manifest(truth, kind, project_id)],
        arms: vec![ArmManifest {
            arm_id: arm_id.to_owned(),
            arm_config_sha256: PROVENANCE_DIGEST.to_owned(),
        }],
        scheduled_runs: vec![],
        retry_policy: retry_policy(),
        contract_limits: evaluator_limits(),
    };
    manifest.scheduled_runs = (0..replicates)
        .map(|replicate| run_key(&truth.case_id, arm_id, replicate))
        .collect();
    manifest
}

fn case_manifest(truth: &TruthSet, kind: CaseKind, project_id: &str) -> CaseManifest {
    let paths = vec!["src/Vault.sol".to_owned()];
    CaseManifest {
        case_id: truth.case_id.clone(),
        project_id: project_id.to_owned(),
        kind,
        source_sha256: SOURCE_DIGEST.to_owned(),
        scoped_paths_sha256: scoped_paths_sha256(&paths).unwrap(),
        scoped_paths: paths,
        truth_set_sha256: canonical_sha256(truth).unwrap(),
        sloc: 1_000,
    }
}

fn retry_policy() -> RetryPolicy {
    RetryPolicy { max_attempts: 2 }
}

fn evaluator_limits() -> codex_auditbase_contract::ContractLimits {
    codex_auditbase_contract::ContractLimits {
        max_request_bytes: 1024 * 1024,
        max_guidance_bytes: 64 * 1024,
        max_event_bytes: 1024 * 1024,
        max_log_message_bytes: 64 * 1024,
        max_result_bytes: 1024 * 1024,
        max_diagnostic_item_bytes: 64 * 1024,
        max_diagnostics_bytes: 256 * 1024,
        max_snippet_bytes: 64 * 1024,
        max_evidence_item_bytes: 128 * 1024,
        max_finding_evidence_bytes: 512 * 1024,
    }
}

fn run_key(case_id: &str, arm_id: &str, replicate: u32) -> RunKey {
    RunKey {
        case_id: case_id.to_owned(),
        arm_id: arm_id.to_owned(),
        replicate,
    }
}

fn binding(
    manifest: &EvaluationManifest,
    case_id: &str,
    arm_id: &str,
    audit_id: &str,
) -> RunBinding {
    let case = manifest.case(case_id).unwrap();
    let arm = manifest.arm(arm_id).unwrap();
    RunBinding {
        expected_audit_id: audit_id.to_owned(),
        observed_source_sha256: case.source_sha256.clone(),
        observed_scoped_paths_sha256: case.scoped_paths_sha256.clone(),
        observed_truth_set_sha256: case.truth_set_sha256.clone(),
        observed_arm_config_sha256: arm.arm_config_sha256.clone(),
        observed_run_provenance_sha256: PROVENANCE_DIGEST.to_owned(),
    }
}

fn valid_run(
    manifest: &EvaluationManifest,
    case_id: &str,
    arm_id: &str,
    replicate: u32,
    attempt: u32,
    result: AuditResult,
) -> EvaluationRun {
    let binding = binding(manifest, case_id, arm_id, &result.audit_id);
    let bytes = serde_json::to_vec(&result).unwrap();
    let run = ingest_result(
        manifest,
        run_key(case_id, arm_id, replicate),
        attempt,
        &binding,
        Some(&bytes),
    )
    .unwrap();
    assert!(matches!(run.outcome(), RunOutcome::Valid { .. }));
    run
}

fn accepted_run(manifest: &EvaluationManifest, run: EvaluationRun) -> AcceptedRun {
    let key = run.key().clone();
    select_accepted_attempt(manifest, &key, &[run]).unwrap()
}

fn assessment() -> SemanticAssessment {
    SemanticAssessment {
        root_cause: AxisDecision::Same,
        affected_behavior: AxisDecision::Same,
        material_impact: AxisDecision::Same,
        location: LocationRelation::SameFunction,
    }
}

fn resolve_bound_matching(
    truth: &TruthSet,
    result: &AuditResult,
    mut decisions: Vec<FinalCandidateDecision>,
) -> Result<ResolvedMatching, MatchingError> {
    let result_sha256 = canonical_sha256(result).unwrap();
    for decision in &mut decisions {
        let finding = result
            .findings
            .iter()
            .find(|finding| finding.id == decision.candidate_id)
            .unwrap();
        decision.result_sha256 = result_sha256.clone();
        decision.candidate_content_sha256 = canonical_sha256(finding).unwrap();
    }
    resolve_matching(truth, result, decisions)
}

fn decision(
    case_id: &str,
    candidate_id: &str,
    cluster_id: &str,
    representative: bool,
    disposition: CandidateDisposition,
) -> FinalCandidateDecision {
    FinalCandidateDecision {
        case_id: case_id.to_owned(),
        candidate_id: candidate_id.to_owned(),
        result_sha256: SOURCE_DIGEST.to_owned(),
        candidate_content_sha256: PROVENANCE_DIGEST.to_owned(),
        cluster_id: cluster_id.to_owned(),
        representative,
        assessment: assessment(),
        disposition,
        actionable: true,
        verified: true,
        resolution: ResolutionKind::Agreement,
        rationale: "synthetic adjudication".to_owned(),
    }
}

fn finding(id: &str, severity: &str, status: &str) -> Value {
    json!({
        "id": id,
        "title": format!("Synthetic finding {id}"),
        "severity": severity,
        "status": status,
        "confidence": "high",
        "category": "synthetic",
        "description": "A precise synthetic root cause.",
        "impact": "A precise synthetic material impact.",
        "recommendation": "Apply the synthetic correction.",
        "locations": [{"path": "src/Vault.sol", "startLine": 10, "symbol": "withdraw"}],
        "evidence": [{
            "kind": "source",
            "summary": "The affected source transition is reachable.",
            "location": {"path": "src/Vault.sol", "startLine": 10, "symbol": "withdraw"}
        }],
        "proof": {
            "status": "passed",
            "summary": "Synthetic deterministic proof passed.",
            "commands": ["forge test --match-test synthetic"],
            "artifactPaths": ["artifacts/proof.txt"]
        }
    })
}

fn result_json(audit_id: &str, status: &str, partial: bool, findings: Vec<Value>) -> Vec<u8> {
    let mut counts = [0_u32; 5];
    for finding in &findings {
        let index = match finding["severity"].as_str().unwrap() {
            "critical" => 0,
            "high" => 1,
            "medium" => 2,
            "low" => 3,
            "informational" => 4,
            other => panic!("unexpected severity {other}"),
        };
        counts[index] += 1;
    }
    let failure = (status == "failed").then(|| {
        json!({
            "code": "audit_timeout",
            "message": "Synthetic timeout after preserving partial evidence.",
            "retryable": true
        })
    });
    serde_json::to_vec(&json!({
        "schemaVersion": "auditbase.audit-result.v1",
        "auditId": audit_id,
        "status": status,
        "partial": partial,
        "startedAt": "2026-07-17T00:00:00.000Z",
        "finishedAt": "2026-07-17T00:01:00.000Z",
        "summary": {
            "title": "Synthetic audit",
            "executiveSummary": "Synthetic evaluator fixture.",
            "findingCounts": {
                "critical": counts[0],
                "high": counts[1],
                "medium": counts[2],
                "low": counts[3],
                "informational": counts[4]
            }
        },
        "findings": findings,
        "coverage": {
            "submittedFileCount": 1,
            "reviewedFileCount": 1,
            "files": [{
                "path": "src/Vault.sol",
                "reviewed": true,
                "functionsReviewed": ["withdraw", "redeem"],
                "notes": []
            }]
        },
        "compilation": {
            "status": "succeeded",
            "commands": ["forge build"],
            "diagnostics": []
        },
        "limitations": [],
        "usage": {
            "inputTokens": 100,
            "cachedInputTokens": 50,
            "outputTokens": 25,
            "reasoningOutputTokens": 10,
            "modelRequests": 1,
            "durationMs": 60_000
        },
        "failure": failure
    }))
    .unwrap()
}

fn parse_result(bytes: &[u8]) -> AuditResult {
    serde_json::from_slice(bytes).unwrap()
}

#[test]
fn severity_weights_are_frozen() {
    let truth = vulnerable_truth();
    assert_eq!(truth.truths[0].severity, Severity::Critical);
    assert_eq!(truth.truths[1].severity, Severity::Medium);
}
