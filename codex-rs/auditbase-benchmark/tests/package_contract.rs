#![allow(clippy::expect_used)]

mod support;

use std::fs;

use codex_auditbase_benchmark::BenchmarkError;
use codex_auditbase_benchmark::package_case;
use codex_auditbase_benchmark::verify_package;
use pretty_assertions::assert_eq;
use tempfile::TempDir;

#[test]
fn package_is_deterministic_and_hides_evaluator_metadata() {
    let temporary = TempDir::new().expect("create temporary directory");
    let source = temporary.path().join("source");
    fs::create_dir(&source).expect("create source root");
    support::materialize_source(&source);
    let catalog = support::catalog();

    let first = temporary.path().join("first");
    let second = temporary.path().join("second");
    let first_receipt =
        package_case(&catalog, &source, &first, support::options()).expect("package first copy");

    let mut reordered_catalog = catalog.clone();
    reordered_catalog.files.reverse();
    let second_receipt = package_case(&reordered_catalog, &source, &second, support::options())
        .expect("package reordered copy");

    assert_eq!(first_receipt, second_receipt);
    assert_eq!(
        fs::read(first.join("input-manifest.json")).expect("read first manifest"),
        fs::read(second.join("input-manifest.json")).expect("read second manifest")
    );
    let manifest =
        fs::read_to_string(first.join("input-manifest.json")).expect("read agent-visible manifest");
    assert!(!manifest.contains("projectId"));
    assert!(!manifest.contains("authored-counter-001"));
    assert!(!manifest.contains("auditbase-synthetic"));
    assert!(!manifest.contains("\"caseId\""));
    assert!(manifest.contains(support::RUN_CASE_ID));
    assert!(!manifest.contains("example.invalid"));
    assert!(!manifest.contains("license"));
    assert!(!manifest.contains("contamination"));
    assert!(!manifest.contains("reportUrls"));
    assert!(manifest.contains("model_only"));

    let verified =
        verify_package(&catalog, &first, support::options()).expect("verify created package");
    assert_eq!(first_receipt, verified);
    assert_eq!(first_receipt.file_count, 2);
    assert_eq!(first_receipt.total_bytes, 351);
    assert_eq!(first_receipt.manifest_sha256.len(), 64);
    assert_eq!(first_receipt.run_case_id, support::RUN_CASE_ID);

    let mut changed_scope_catalog = catalog;
    changed_scope_catalog
        .scope
        .instructions
        .push_str(" Review arithmetic boundaries too.");
    let changed_scope = temporary.path().join("changed-scope");
    let changed_receipt = package_case(
        &changed_scope_catalog,
        &source,
        &changed_scope,
        support::options(),
    )
    .expect("package changed scope");
    assert_eq!(changed_receipt.tree_sha256, first_receipt.tree_sha256);
    assert_ne!(
        changed_receipt.manifest_sha256,
        first_receipt.manifest_sha256
    );

    #[cfg(unix)]
    {
        support::make_writable(&first);
        support::make_writable(&second);
        support::make_writable(&changed_scope);
    }
}

#[test]
fn verification_rejects_extra_and_tampered_files() {
    let temporary = TempDir::new().expect("create temporary directory");
    let source = temporary.path().join("source");
    fs::create_dir(&source).expect("create source root");
    support::materialize_source(&source);
    let catalog = support::catalog();

    let extra_package = temporary.path().join("extra-package");
    package_case(&catalog, &source, &extra_package, support::options()).expect("package input");
    #[cfg(unix)]
    support::make_writable(&extra_package);
    fs::write(extra_package.join("unexpected.txt"), b"extra").expect("write extra file");
    let error = verify_package(&catalog, &extra_package, support::options())
        .expect_err("extra file must be rejected");
    assert!(error.to_string().contains("package files differ"));

    let tampered_package = temporary.path().join("tampered-package");
    package_case(&catalog, &source, &tampered_package, support::options())
        .expect("package input again");
    #[cfg(unix)]
    support::make_writable(&tampered_package);
    let tampered = String::from_utf8(support::COUNTER.to_vec())
        .expect("fixture is UTF-8")
        .replace("value += 1", "value += 2");
    fs::write(
        tampered_package.join("input/contracts/Counter.sol"),
        tampered,
    )
    .expect("tamper packaged input");
    let error = verify_package(&catalog, &tampered_package, support::options())
        .expect_err("tampered file must be rejected");
    assert!(error.to_string().contains("digest mismatch"));
}

#[test]
fn verification_rejects_a_non_model_only_network_policy() {
    let temporary = TempDir::new().expect("create temporary directory");
    let source = temporary.path().join("source");
    fs::create_dir(&source).expect("create source root");
    support::materialize_source(&source);
    let catalog = support::catalog();
    let package = temporary.path().join("package");
    package_case(&catalog, &source, &package, support::options()).expect("package input");

    #[cfg(unix)]
    support::make_writable(&package);
    let manifest_path = package.join("input-manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("read agent-visible manifest"))
            .expect("parse agent-visible manifest");
    manifest["requiredNetworkPolicy"] = serde_json::Value::String("unrestricted".to_string());
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).expect("serialize tampered manifest"),
    )
    .expect("write tampered manifest");

    let error = verify_package(&catalog, &package, support::options())
        .expect_err("non-model network policy must be rejected");
    assert!(matches!(error, BenchmarkError::Json { .. }));
}
