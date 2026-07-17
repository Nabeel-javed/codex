#![allow(clippy::expect_used)]

mod support;

use std::fs;

use codex_auditbase_benchmark::BenchmarkError;
use codex_auditbase_benchmark::CatalogFile;
use codex_auditbase_benchmark::ContaminationRisk;
use codex_auditbase_benchmark::LicenseStatus;
use codex_auditbase_benchmark::PackageOptions;
use codex_auditbase_benchmark::package_case;
use tempfile::TempDir;

fn prepared() -> (TempDir, std::path::PathBuf) {
    let temporary = TempDir::new().expect("create temporary directory");
    let source = temporary.path().join("source");
    fs::create_dir(&source).expect("create source root");
    support::materialize_source(&source);
    (temporary, source)
}

#[test]
fn incomplete_or_unsafe_review_fails_closed() {
    let (temporary, source) = prepared();

    let mut unknown_license = support::catalog();
    unknown_license.license.status = LicenseStatus::Unknown;
    let error = package_case(
        &unknown_license,
        &source,
        temporary.path().join("unknown-license"),
        support::options(),
    )
    .expect_err("unknown license must fail");
    assert!(matches!(error, BenchmarkError::LicensePolicy(_)));

    let mut nonredistributable = support::catalog();
    nonredistributable.license.redistribution_allowed = false;
    let error = package_case(
        &nonredistributable,
        &source,
        temporary.path().join("nonredistributable"),
        support::options(),
    )
    .expect_err("nonredistributable cleared source must fail");
    assert!(matches!(error, BenchmarkError::LicensePolicy(_)));

    let mut high_contamination = support::catalog();
    high_contamination.contamination.risk = ContaminationRisk::High;
    let error = package_case(
        &high_contamination,
        &source,
        temporary.path().join("high-contamination"),
        support::options(),
    )
    .expect_err("high contamination must fail");
    assert!(matches!(error, BenchmarkError::ContaminationPolicy(_)));

    let mut visible_identity = support::catalog();
    visible_identity.contamination.identity_visible = true;
    let error = package_case(
        &visible_identity,
        &source,
        temporary.path().join("visible-identity"),
        support::options(),
    )
    .expect_err("identity-visible material must not enter a blinded package");
    assert!(matches!(error, BenchmarkError::ContaminationPolicy(_)));
}

#[test]
fn opaque_run_ids_and_catalog_identity_leakage_fail_closed() {
    let (temporary, source) = prepared();
    let catalog = support::catalog();
    let error = package_case(
        &catalog,
        &source,
        temporary.path().join("descriptive-id"),
        PackageOptions::blinded("authored-counter-001"),
    )
    .expect_err("descriptive catalog identity must not be accepted as a run ID");
    assert!(matches!(error, BenchmarkError::InvalidOpaqueRunCaseId));

    let mut scope_leak = catalog.clone();
    scope_leak.scope.instructions = format!("Audit case {}", scope_leak.case_id);
    let error = package_case(
        &scope_leak,
        &source,
        temporary.path().join("scope-leak"),
        support::options(),
    )
    .expect_err("catalog identity in scope text must be rejected");
    assert!(matches!(error, BenchmarkError::Leakage { .. }));

    let mut source_leak = catalog;
    support::replace_counter(
        &mut source_leak,
        &source,
        b"contract Counter { string constant identity = 'auditbase-synthetic'; }",
    );
    let error = package_case(
        &source_leak,
        &source,
        temporary.path().join("source-leak"),
        support::options(),
    )
    .expect_err("catalog identity in source bytes must be rejected");
    assert!(matches!(error, BenchmarkError::Leakage { .. }));
}

#[test]
fn catalog_identity_markers_in_agent_visible_paths_fail_closed() {
    let (temporary, source) = prepared();
    let catalog = support::catalog();
    let cases = [
        ("case", catalog.case_id.clone()),
        ("project", catalog.project_id.to_ascii_uppercase()),
        ("source", "upstream.example/private-repository".to_string()),
    ];

    for (label, marker) in cases {
        let mut leaking = catalog.clone();
        if label == "source" {
            leaking.source.url = marker.clone();
        }
        leaking.files[0].path = format!("contracts/{marker}/Counter.sol");

        let error = package_case(
            &leaking,
            &source,
            temporary.path().join(format!("path-{label}-leak")),
            support::options(),
        )
        .expect_err("catalog identity must not be exposed through an agent-visible path");
        assert!(
            matches!(&error, BenchmarkError::Leakage { .. }),
            "{label} path marker produced unexpected error: {error}"
        );
    }
}

#[test]
fn internal_only_requires_explicit_operator_opt_in() {
    let (temporary, source) = prepared();
    let mut catalog = support::catalog();
    catalog.license.status = LicenseStatus::InternalEvaluationOnly;
    catalog.license.redistribution_allowed = false;

    let error = package_case(
        &catalog,
        &source,
        temporary.path().join("denied"),
        support::options(),
    )
    .expect_err("implicit internal-only use must fail");
    assert!(matches!(error, BenchmarkError::LicensePolicy(_)));

    let output = temporary.path().join("allowed");
    package_case(
        &catalog,
        &source,
        &output,
        PackageOptions {
            allow_internal_evaluation_only: true,
            opaque_run_case_id: support::RUN_CASE_ID.to_string(),
        },
    )
    .expect("explicit internal-only use is allowed");
    #[cfg(unix)]
    support::make_writable(&output);
}

#[test]
fn report_paths_casefold_collisions_and_bad_digests_are_rejected() {
    let (temporary, source) = prepared();

    let mut report = support::catalog();
    report.files.push(CatalogFile {
        path: "docs/audit-report.md".to_string(),
        size_bytes: 1,
        sha256: "00".repeat(32),
        executable: false,
        in_scope: false,
    });
    let error = package_case(
        &report,
        &source,
        temporary.path().join("report"),
        support::options(),
    )
    .expect_err("report path must fail before copying");
    assert!(matches!(error, BenchmarkError::Leakage { .. }));

    let mut collision = support::catalog();
    let mut duplicate = collision.files[0].clone();
    duplicate.path = "Contracts/counter.sol".to_string();
    collision.files.push(duplicate);
    let error = package_case(
        &collision,
        &source,
        temporary.path().join("collision"),
        support::options(),
    )
    .expect_err("case-fold collision must fail");
    assert!(error.to_string().contains("case-folding path collision"));

    let mut digest = support::catalog();
    digest.files[0].sha256 = "00".repeat(32);
    let error = package_case(
        &digest,
        &source,
        temporary.path().join("digest"),
        support::options(),
    )
    .expect_err("digest mismatch must fail");
    assert!(matches!(error, BenchmarkError::DigestMismatch { .. }));
}

#[test]
fn traversal_and_existing_output_are_rejected() {
    let (temporary, source) = prepared();
    let mut traversal = support::catalog();
    traversal.files[0].path = "../Counter.sol".to_string();
    let error = package_case(
        &traversal,
        &source,
        temporary.path().join("traversal"),
        support::options(),
    )
    .expect_err("parent traversal must fail");
    assert!(matches!(error, BenchmarkError::InvalidPath { .. }));

    let existing = temporary.path().join("existing");
    fs::create_dir(&existing).expect("create existing output");
    let error = package_case(&support::catalog(), &source, &existing, support::options())
        .expect_err("existing output must not be replaced");
    assert!(matches!(error, BenchmarkError::OutputExists(path) if path == existing));
}

#[test]
fn content_markers_and_archive_magic_are_rejected() {
    let (temporary, source) = prepared();
    let mut marker_catalog = support::catalog();
    let mut marker_bytes = vec![b'a'; 65_530];
    marker_bytes.extend_from_slice(b"SeCrEt AnSwEr MaRkEr");
    support::replace_counter(&mut marker_catalog, &source, &marker_bytes);
    let error = package_case(
        &marker_catalog,
        &source,
        temporary.path().join("marker"),
        support::options(),
    )
    .expect_err("case-insensitive answer marker must fail");
    assert!(matches!(error, BenchmarkError::Leakage { .. }));

    let mut archive_catalog = support::catalog();
    let archive_source = temporary.path().join("archive-source");
    fs::create_dir(&archive_source).expect("create second source root");
    support::materialize_source(&archive_source);
    support::replace_counter(
        &mut archive_catalog,
        &archive_source,
        b"PK\x03\x04synthetic archive bytes",
    );
    let error = package_case(
        &archive_catalog,
        &archive_source,
        temporary.path().join("archive"),
        support::options(),
    )
    .expect_err("archive magic must fail");
    assert!(matches!(error, BenchmarkError::Archive(_)));
}

#[cfg(unix)]
#[test]
fn symlinks_hardlinks_and_special_files_are_rejected() {
    use std::os::unix::fs::symlink;
    use std::os::unix::net::UnixListener;

    let (temporary, source) = prepared();
    let counter = source.join("contracts/Counter.sol");
    fs::remove_file(&counter).expect("remove counter");
    symlink(source.join("LICENSE"), &counter).expect("create symlink");
    let error = package_case(
        &support::catalog(),
        &source,
        temporary.path().join("symlink"),
        support::options(),
    )
    .expect_err("symlink must fail");
    assert!(matches!(error, BenchmarkError::Symlink(_)));

    fs::remove_file(&counter).expect("remove symlink");
    fs::hard_link(source.join("LICENSE"), &counter).expect("create hardlink");
    let error = package_case(
        &support::catalog(),
        &source,
        temporary.path().join("hardlink"),
        support::options(),
    )
    .expect_err("hardlink must fail");
    assert!(matches!(error, BenchmarkError::Hardlink(_)));

    fs::remove_file(&counter).expect("remove hardlink");
    let _socket = UnixListener::bind(&counter).expect("create Unix socket");
    let error = package_case(
        &support::catalog(),
        &source,
        temporary.path().join("special"),
        support::options(),
    )
    .expect_err("special file must fail");
    assert!(matches!(error, BenchmarkError::NonRegularFile(_)));
}
