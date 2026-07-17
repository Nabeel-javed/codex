use std::collections::BTreeSet;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::BufReader;
use std::io::BufWriter;
use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use serde::Serialize;
use serde_json::Map;
use serde_json::Value;
use sha2::Digest;
use sha2::Sha256;
use walkdir::WalkDir;

use crate::AgentInputFile;
use crate::AgentInputManifest;
use crate::AgentInputScope;
use crate::BenchmarkCatalog;
use crate::BenchmarkInputSchemaVersion;
use crate::BenchmarkNetworkPolicy;
use crate::CatalogFile;
use crate::validation::BenchmarkError;
use crate::validation::ContentPolicy;
use crate::validation::MAX_CATALOG_BYTES;
use crate::validation::MAX_MANIFEST_BYTES;
use crate::validation::decode_sha256;
use crate::validation::ensure_no_symlink_components;
use crate::validation::ensure_single_link;
use crate::validation::has_archive_magic;
use crate::validation::validate_catalog;
use crate::validation::validate_sha256;

const MANIFEST_NAME: &str = "input-manifest.json";
const INPUT_DIRECTORY: &str = "input";
const TREE_DOMAIN: &[u8] = b"auditbase.benchmark-tree.v1\0";
const COPY_BUFFER_BYTES: usize = 64 * 1024;
const ARCHIVE_PREFIX_BYTES: usize = 512;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageOptions {
    /// Permit material whose license review limits it to internal evaluation.
    /// This never relaxes contamination, path, digest, or file-type checks.
    pub allow_internal_evaluation_only: bool,
    /// Opaque per-run identifier exposed to the agent instead of catalog
    /// identity. Must be `run-` followed by 32 lowercase hex characters.
    pub opaque_run_case_id: String,
}

impl PackageOptions {
    pub fn blinded(opaque_run_case_id: impl Into<String>) -> Self {
        Self {
            allow_internal_evaluation_only: false,
            opaque_run_case_id: opaque_run_case_id.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageReceipt {
    /// Evaluator-only catalog identity; this receipt is never agent-visible.
    pub case_id: String,
    pub run_case_id: String,
    pub tree_sha256: String,
    /// Canonical digest of the full agent-visible manifest. This binds the
    /// tree, opaque run ID, scope, and network policy as one package identity.
    pub manifest_sha256: String,
    pub file_count: usize,
    pub total_bytes: u64,
}

/// Load evaluator-only catalog metadata from a bounded regular file.
pub fn load_catalog(path: impl AsRef<Path>) -> Result<BenchmarkCatalog, BenchmarkError> {
    let path = path.as_ref();
    let bytes = read_bounded_regular_file(path, MAX_CATALOG_BYTES)?;
    serde_json::from_slice(&bytes).map_err(|error| BenchmarkError::json(path, error))
}

/// Build an agent-visible input package from an exact, evaluator-approved allowlist.
///
/// Source files are read as bytes. This function never invokes Git, compilers,
/// package managers, build scripts, or any executable found in the source tree.
pub fn package_case(
    catalog: &BenchmarkCatalog,
    source_root: impl AsRef<Path>,
    output_directory: impl AsRef<Path>,
    options: PackageOptions,
) -> Result<PackageReceipt, BenchmarkError> {
    validate_opaque_run_case_id(&options.opaque_run_case_id)?;
    let policy = validate_catalog(catalog, options.allow_internal_evaluation_only)?;
    let source_root = validate_directory_root(source_root.as_ref())?;
    let output_directory = output_directory.as_ref();
    ensure_absent(output_directory)?;

    let output_parent = output_directory.parent().ok_or_else(|| {
        BenchmarkError::Verification("output directory must have a parent".to_string())
    })?;
    let output_parent = if output_parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        output_parent
    };
    let output_parent = validate_directory_root(output_parent)?;
    if output_parent.starts_with(&source_root) {
        return Err(BenchmarkError::Verification(
            "output directory must not be inside the source tree".to_string(),
        ));
    }

    let staging_path = create_staging_directory(&output_parent)?;
    let mut staging = StagingDirectory::new(staging_path);
    let input_root = staging.path().join(INPUT_DIRECTORY);
    std::fs::create_dir(&input_root).map_err(|error| BenchmarkError::io(&input_root, error))?;

    let mut catalog_files = catalog.files.iter().collect::<Vec<_>>();
    catalog_files.sort_by(|left, right| left.path.cmp(&right.path));

    let mut manifest_files = Vec::with_capacity(catalog_files.len());
    let mut total_bytes = 0_u64;
    for catalog_file in catalog_files {
        let source = ensure_no_symlink_components(&source_root, &catalog_file.path)?;
        let canonical_source =
            std::fs::canonicalize(&source).map_err(|error| BenchmarkError::io(&source, error))?;
        if !canonical_source.starts_with(&source_root) {
            return Err(BenchmarkError::InvalidPath {
                path: catalog_file.path.clone(),
                reason: "resolved source escapes the source root".to_string(),
            });
        }

        let destination = input_root.join(&catalog_file.path);
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent).map_err(|error| BenchmarkError::io(parent, error))?;
        }
        copy_validated_file(
            catalog_file,
            &canonical_source,
            &destination,
            &policy,
            catalog,
        )?;
        total_bytes = total_bytes
            .checked_add(catalog_file.size_bytes)
            .ok_or_else(|| BenchmarkError::LimitExceeded("package byte total overflowed".into()))?;
        manifest_files.push(agent_file(catalog_file));
    }

    let tree_sha256 = tree_sha256(&manifest_files)?;
    let included_paths = manifest_files
        .iter()
        .filter(|file| file.in_scope)
        .map(|file| file.path.clone())
        .collect();
    let manifest = AgentInputManifest {
        schema_version: BenchmarkInputSchemaVersion::V1,
        run_case_id: options.opaque_run_case_id.clone(),
        tree_sha256: tree_sha256.clone(),
        required_network_policy: BenchmarkNetworkPolicy::ModelOnly,
        files: manifest_files,
        scope: AgentInputScope {
            instructions: catalog.scope.instructions.clone(),
            included_paths,
        },
    };
    let manifest_sha256 = canonical_manifest_sha256(&manifest)?;
    write_manifest(staging.path(), &manifest)?;
    set_directory_readonly_recursive(staging.path())?;

    let receipt = verify_package_at(catalog, staging.path(), options, Some(&source_root))?;
    if receipt.tree_sha256 != tree_sha256
        || receipt.manifest_sha256 != manifest_sha256
        || receipt.total_bytes != total_bytes
    {
        return Err(BenchmarkError::Verification(
            "internal package receipt did not match packaged bytes".to_string(),
        ));
    }

    std::fs::rename(staging.path(), output_directory)
        .map_err(|error| BenchmarkError::io(output_directory, error))?;
    staging.disarm();
    Ok(receipt)
}

/// Re-validate a package without executing any packaged content.
pub fn verify_package(
    catalog: &BenchmarkCatalog,
    package_directory: impl AsRef<Path>,
    options: PackageOptions,
) -> Result<PackageReceipt, BenchmarkError> {
    validate_opaque_run_case_id(&options.opaque_run_case_id)?;
    verify_package_at(catalog, package_directory.as_ref(), options, None)
}

fn verify_package_at(
    catalog: &BenchmarkCatalog,
    package_directory: &Path,
    options: PackageOptions,
    forbidden_source_root: Option<&Path>,
) -> Result<PackageReceipt, BenchmarkError> {
    let policy = validate_catalog(catalog, options.allow_internal_evaluation_only)?;
    let package_directory = validate_directory_root(package_directory)?;
    if forbidden_source_root.is_some_and(|source| package_directory.starts_with(source)) {
        return Err(BenchmarkError::Verification(
            "package directory must not be inside the source tree".to_string(),
        ));
    }

    let manifest_path = package_directory.join(MANIFEST_NAME);
    let manifest_bytes = read_bounded_regular_file(&manifest_path, MAX_MANIFEST_BYTES)?;
    let manifest: AgentInputManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| BenchmarkError::json(&manifest_path, error))?;
    validate_manifest(catalog, &manifest, &options.opaque_run_case_id)?;
    validate_package_tree(&package_directory, &manifest)?;

    let input_root = package_directory.join(INPUT_DIRECTORY);
    let mut total_bytes = 0_u64;
    for (catalog_file, manifest_file) in catalog_sorted(catalog)
        .into_iter()
        .zip(manifest.files.iter())
    {
        let source = ensure_no_symlink_components(&input_root, &manifest_file.path)?;
        validate_file_bytes(catalog_file, &source, &policy, catalog)?;
        total_bytes = total_bytes
            .checked_add(manifest_file.size_bytes)
            .ok_or_else(|| BenchmarkError::LimitExceeded("package byte total overflowed".into()))?;
    }

    let calculated_tree = tree_sha256(&manifest.files)?;
    if calculated_tree != manifest.tree_sha256 {
        return Err(BenchmarkError::Verification(format!(
            "tree digest mismatch: expected {}, found {calculated_tree}",
            manifest.tree_sha256
        )));
    }

    let manifest_sha256 = canonical_manifest_sha256(&manifest)?;
    Ok(PackageReceipt {
        case_id: catalog.case_id.clone(),
        run_case_id: manifest.run_case_id,
        tree_sha256: calculated_tree,
        manifest_sha256,
        file_count: manifest.files.len(),
        total_bytes,
    })
}

fn validate_manifest(
    catalog: &BenchmarkCatalog,
    manifest: &AgentInputManifest,
    opaque_run_case_id: &str,
) -> Result<(), BenchmarkError> {
    if manifest.run_case_id != opaque_run_case_id {
        return Err(BenchmarkError::InvalidManifest(
            "runCaseId does not match the evaluator-issued opaque run ID".to_string(),
        ));
    }
    validate_sha256(&manifest.tree_sha256, "treeSha256")
        .map_err(|error| BenchmarkError::InvalidManifest(error.to_string()))?;
    if manifest.required_network_policy != BenchmarkNetworkPolicy::ModelOnly {
        return Err(BenchmarkError::InvalidManifest(
            "requiredNetworkPolicy must be model_only".to_string(),
        ));
    }
    if manifest.scope.instructions != catalog.scope.instructions {
        return Err(BenchmarkError::InvalidManifest(
            "scope instructions do not match the evaluator catalog".to_string(),
        ));
    }

    let expected_files = catalog_sorted(catalog)
        .into_iter()
        .map(agent_file)
        .collect::<Vec<_>>();
    if manifest.files != expected_files {
        return Err(BenchmarkError::InvalidManifest(
            "file allowlist does not exactly match the evaluator catalog".to_string(),
        ));
    }
    let expected_scope = expected_files
        .iter()
        .filter(|file| file.in_scope)
        .map(|file| file.path.clone())
        .collect::<Vec<_>>();
    if manifest.scope.included_paths != expected_scope {
        return Err(BenchmarkError::InvalidManifest(
            "includedPaths does not exactly match in-scope files".to_string(),
        ));
    }
    Ok(())
}

fn validate_package_tree(
    package_directory: &Path,
    manifest: &AgentInputManifest,
) -> Result<(), BenchmarkError> {
    let mut expected_files = BTreeSet::from([MANIFEST_NAME.to_string()]);
    let mut expected_directories = BTreeSet::from([INPUT_DIRECTORY.to_string()]);
    for file in &manifest.files {
        let package_path = format!("{INPUT_DIRECTORY}/{}", file.path);
        expected_files.insert(package_path.clone());
        let mut parent = Path::new(&package_path).parent();
        while let Some(path) = parent {
            if path.as_os_str().is_empty() {
                break;
            }
            expected_directories.insert(path_to_portable(path)?);
            parent = path.parent();
        }
    }

    let mut actual_files = BTreeSet::new();
    let mut actual_directories = BTreeSet::new();
    for result in WalkDir::new(package_directory).follow_links(false) {
        let entry = result.map_err(|error| {
            let path = error
                .path()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| package_directory.to_path_buf());
            BenchmarkError::Verification(format!("could not walk {}: {error}", path.display()))
        })?;
        if entry.path() == package_directory {
            continue;
        }
        let relative = entry.path().strip_prefix(package_directory).map_err(|_| {
            BenchmarkError::Verification("package entry escaped package root".to_string())
        })?;
        let portable = path_to_portable(relative)?;
        let metadata = std::fs::symlink_metadata(entry.path())
            .map_err(|error| BenchmarkError::io(entry.path(), error))?;
        if metadata.file_type().is_symlink() {
            return Err(BenchmarkError::Symlink(entry.path().to_path_buf()));
        }
        if metadata.file_type().is_file() {
            ensure_single_link(entry.path(), &metadata)?;
            actual_files.insert(portable);
        } else if metadata.file_type().is_dir() {
            actual_directories.insert(portable);
        } else {
            return Err(BenchmarkError::NonRegularFile(entry.path().to_path_buf()));
        }
    }
    if actual_files != expected_files {
        return Err(BenchmarkError::Verification(format!(
            "package files differ from manifest: expected {expected_files:?}, found {actual_files:?}"
        )));
    }
    if actual_directories != expected_directories {
        return Err(BenchmarkError::Verification(format!(
            "package directories differ from manifest: expected {expected_directories:?}, found {actual_directories:?}"
        )));
    }
    Ok(())
}

fn copy_validated_file(
    catalog_file: &CatalogFile,
    source: &Path,
    destination: &Path,
    policy: &ContentPolicy,
    catalog: &BenchmarkCatalog,
) -> Result<(), BenchmarkError> {
    let input = open_validated_source(catalog_file, source)?;
    let output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|error| BenchmarkError::io(destination, error))?;
    let result = stream_and_validate(
        catalog_file,
        input,
        Some(BufWriter::new(output)),
        policy,
        catalog,
    );
    if result.is_err() {
        let _ = std::fs::remove_file(destination);
    }
    result?;
    set_file_mode(destination, catalog_file.executable)
}

fn validate_file_bytes(
    catalog_file: &CatalogFile,
    source: &Path,
    policy: &ContentPolicy,
    catalog: &BenchmarkCatalog,
) -> Result<(), BenchmarkError> {
    let input = open_validated_source(catalog_file, source)?;
    stream_and_validate(catalog_file, input, None, policy, catalog)
}

fn open_validated_source(
    catalog_file: &CatalogFile,
    source: &Path,
) -> Result<BufReader<File>, BenchmarkError> {
    let file = open_read_nofollow(source)?;
    let metadata = file
        .metadata()
        .map_err(|error| BenchmarkError::io(source, error))?;
    if !metadata.file_type().is_file() {
        return Err(BenchmarkError::NonRegularFile(source.to_path_buf()));
    }
    ensure_single_link(source, &metadata)?;
    if metadata.len() != catalog_file.size_bytes {
        return Err(BenchmarkError::SizeMismatch {
            path: catalog_file.path.clone(),
            expected: catalog_file.size_bytes,
            actual: metadata.len(),
        });
    }
    Ok(BufReader::new(file))
}

fn stream_and_validate(
    catalog_file: &CatalogFile,
    mut input: BufReader<File>,
    mut output: Option<BufWriter<File>>,
    policy: &ContentPolicy,
    catalog: &BenchmarkCatalog,
) -> Result<(), BenchmarkError> {
    let mut scanner = policy.scanner();
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    let mut prefix = Vec::with_capacity(ARCHIVE_PREFIX_BYTES);
    let mut byte_count = 0_u64;
    loop {
        let read = input
            .read(&mut buffer)
            .map_err(|error| BenchmarkError::io(&catalog_file.path, error))?;
        if read == 0 {
            break;
        }
        let chunk = &buffer[..read];
        byte_count = byte_count.checked_add(read as u64).ok_or_else(|| {
            BenchmarkError::LimitExceeded("streamed file byte count overflowed".to_string())
        })?;
        if byte_count > catalog_file.size_bytes
            || byte_count > catalog.limits.max_file_bytes
            || byte_count > catalog.limits.max_total_bytes
        {
            return Err(BenchmarkError::LimitExceeded(format!(
                "{} exceeded a configured byte limit while streaming",
                catalog_file.path
            )));
        }
        if prefix.len() < ARCHIVE_PREFIX_BYTES {
            let wanted = (ARCHIVE_PREFIX_BYTES - prefix.len()).min(chunk.len());
            prefix.extend_from_slice(&chunk[..wanted]);
        }
        scanner.scan(&catalog_file.path, chunk)?;
        hasher.update(chunk);
        if let Some(writer) = output.as_mut() {
            writer
                .write_all(chunk)
                .map_err(|error| BenchmarkError::io(&catalog_file.path, error))?;
        }
    }
    if let Some(mut writer) = output {
        writer
            .flush()
            .map_err(|error| BenchmarkError::io(&catalog_file.path, error))?;
    }
    if has_archive_magic(&prefix) {
        return Err(BenchmarkError::Archive(PathBuf::from(&catalog_file.path)));
    }
    if byte_count != catalog_file.size_bytes {
        return Err(BenchmarkError::SizeMismatch {
            path: catalog_file.path.clone(),
            expected: catalog_file.size_bytes,
            actual: byte_count,
        });
    }
    let digest: [u8; 32] = hasher.finalize().into();
    policy.validate_digest(&catalog_file.path, digest)?;
    let actual = encode_hex(&digest);
    if actual != catalog_file.sha256 {
        return Err(BenchmarkError::DigestMismatch {
            path: catalog_file.path.clone(),
            expected: catalog_file.sha256.clone(),
            actual,
        });
    }
    Ok(())
}

fn tree_sha256(files: &[AgentInputFile]) -> Result<String, BenchmarkError> {
    let mut previous: Option<&str> = None;
    let mut hasher = Sha256::new();
    hasher.update(TREE_DOMAIN);
    for file in files {
        if previous.is_some_and(|path| path >= file.path.as_str()) {
            return Err(BenchmarkError::InvalidManifest(
                "files must be strictly sorted by path".to_string(),
            ));
        }
        previous = Some(&file.path);
        let path = file.path.as_bytes();
        hasher.update((path.len() as u64).to_be_bytes());
        hasher.update(path);
        hasher.update(file.size_bytes.to_be_bytes());
        hasher.update([u8::from(file.executable)]);
        hasher.update([u8::from(file.in_scope)]);
        hasher.update(decode_sha256(&file.sha256, "manifest file sha256")?);
    }
    Ok(encode_hex(&hasher.finalize()))
}

fn canonical_manifest_sha256(manifest: &AgentInputManifest) -> Result<String, BenchmarkError> {
    let value = serde_json::to_value(manifest).map_err(|error| {
        BenchmarkError::Verification(format!("could not serialize agent manifest: {error}"))
    })?;
    let bytes = serde_json::to_vec(&sort_json(value)).map_err(|error| {
        BenchmarkError::Verification(format!(
            "could not encode canonical agent manifest: {error}"
        ))
    })?;
    Ok(encode_hex(&Sha256::digest(bytes)))
}

fn sort_json(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(sort_json).collect()),
        Value::Object(values) => {
            let mut entries: Vec<_> = values.into_iter().collect();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            let mut sorted = Map::new();
            for (key, value) in entries {
                sorted.insert(key, sort_json(value));
            }
            Value::Object(sorted)
        }
        scalar => scalar,
    }
}

fn validate_opaque_run_case_id(value: &str) -> Result<(), BenchmarkError> {
    let Some(hex) = value.strip_prefix("run-") else {
        return Err(BenchmarkError::InvalidOpaqueRunCaseId);
    };
    if hex.len() != 32
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(BenchmarkError::InvalidOpaqueRunCaseId);
    }
    Ok(())
}

fn catalog_sorted(catalog: &BenchmarkCatalog) -> Vec<&CatalogFile> {
    let mut files = catalog.files.iter().collect::<Vec<_>>();
    files.sort_by(|left, right| left.path.cmp(&right.path));
    files
}

fn agent_file(file: &CatalogFile) -> AgentInputFile {
    AgentInputFile {
        path: file.path.clone(),
        size_bytes: file.size_bytes,
        sha256: file.sha256.clone(),
        executable: file.executable,
        in_scope: file.in_scope,
    }
}

fn write_manifest(
    package_directory: &Path,
    manifest: &AgentInputManifest,
) -> Result<(), BenchmarkError> {
    let path = package_directory.join(MANIFEST_NAME);
    let mut bytes =
        serde_json::to_vec_pretty(manifest).map_err(|error| BenchmarkError::json(&path, error))?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(BenchmarkError::LimitExceeded(format!(
            "agent manifest exceeds {MAX_MANIFEST_BYTES} bytes"
        )));
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|error| BenchmarkError::io(&path, error))?;
    file.write_all(&bytes)
        .map_err(|error| BenchmarkError::io(&path, error))?;
    file.sync_all()
        .map_err(|error| BenchmarkError::io(&path, error))?;
    set_file_mode(&path, false)
}

fn read_bounded_regular_file(path: &Path, maximum: u64) -> Result<Vec<u8>, BenchmarkError> {
    let link_metadata =
        std::fs::symlink_metadata(path).map_err(|error| BenchmarkError::io(path, error))?;
    if link_metadata.file_type().is_symlink() {
        return Err(BenchmarkError::Symlink(path.to_path_buf()));
    }
    if !link_metadata.file_type().is_file() {
        return Err(BenchmarkError::NonRegularFile(path.to_path_buf()));
    }
    ensure_single_link(path, &link_metadata)?;
    if link_metadata.len() > maximum {
        return Err(BenchmarkError::LimitExceeded(format!(
            "{} exceeds {maximum} bytes",
            path.display()
        )));
    }
    let file = open_read_nofollow(path)?;
    let metadata = file
        .metadata()
        .map_err(|error| BenchmarkError::io(path, error))?;
    ensure_single_link(path, &metadata)?;
    if metadata.len() != link_metadata.len() || metadata.len() > maximum {
        return Err(BenchmarkError::Verification(format!(
            "{} changed while it was being opened",
            path.display()
        )));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| BenchmarkError::io(path, error))?;
    if bytes.len() as u64 > maximum || bytes.len() as u64 != metadata.len() {
        return Err(BenchmarkError::Verification(format!(
            "{} changed while it was being read",
            path.display()
        )));
    }
    Ok(bytes)
}

fn validate_directory_root(path: &Path) -> Result<PathBuf, BenchmarkError> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|error| BenchmarkError::io(path, error))?;
    if metadata.file_type().is_symlink() {
        return Err(BenchmarkError::Symlink(path.to_path_buf()));
    }
    if !metadata.file_type().is_dir() {
        return Err(BenchmarkError::NonRegularFile(path.to_path_buf()));
    }
    std::fs::canonicalize(path).map_err(|error| BenchmarkError::io(path, error))
}

fn ensure_absent(path: &Path) -> Result<(), BenchmarkError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Err(BenchmarkError::OutputExists(path.to_path_buf())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(BenchmarkError::io(path, error)),
    }
}

fn create_staging_directory(parent: &Path) -> Result<PathBuf, BenchmarkError> {
    let epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| BenchmarkError::Verification("system clock predates Unix epoch".into()))?
        .as_nanos();
    for attempt in 0_u32..128 {
        let path = parent.join(format!(
            ".auditbase-package-{}-{epoch}-{attempt}",
            std::process::id()
        ));
        match create_private_directory(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(BenchmarkError::io(&path, error)),
        }
    }
    Err(BenchmarkError::Verification(
        "could not allocate a unique staging directory".to_string(),
    ))
}

#[cfg(unix)]
fn open_read_nofollow(path: &Path) -> Result<File, BenchmarkError> {
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| BenchmarkError::io(path, error))
}

#[cfg(not(unix))]
fn open_read_nofollow(_path: &Path) -> Result<File, BenchmarkError> {
    Err(BenchmarkError::UnsupportedPlatform)
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700).create(path)
}

#[cfg(not(unix))]
fn create_private_directory(_path: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "safe private staging directories require Unix",
    ))
}

fn path_to_portable(path: &Path) -> Result<String, BenchmarkError> {
    let mut output = String::new();
    for component in path.components() {
        let std::path::Component::Normal(component) = component else {
            return Err(BenchmarkError::Verification(format!(
                "package contains a non-normal path: {}",
                path.display()
            )));
        };
        let component = component.to_str().ok_or_else(|| {
            BenchmarkError::Verification(format!(
                "package contains a non-UTF-8 path: {}",
                path.display()
            ))
        })?;
        if !output.is_empty() {
            output.push('/');
        }
        output.push_str(component);
    }
    Ok(output)
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(unix)]
fn set_file_mode(path: &Path, executable: bool) -> Result<(), BenchmarkError> {
    use std::os::unix::fs::PermissionsExt;

    let mode = if executable { 0o555 } else { 0o444 };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|error| BenchmarkError::io(path, error))
}

#[cfg(not(unix))]
fn set_file_mode(_path: &Path, _executable: bool) -> Result<(), BenchmarkError> {
    Err(BenchmarkError::UnsupportedPlatform)
}

#[cfg(unix)]
fn set_directory_readonly_recursive(root: &Path) -> Result<(), BenchmarkError> {
    use std::os::unix::fs::PermissionsExt;

    let mut directories = Vec::new();
    for result in WalkDir::new(root).follow_links(false) {
        let entry = result.map_err(|error| {
            BenchmarkError::Verification(format!("could not protect package permissions: {error}"))
        })?;
        let metadata = std::fs::symlink_metadata(entry.path())
            .map_err(|error| BenchmarkError::io(entry.path(), error))?;
        if metadata.file_type().is_symlink() {
            return Err(BenchmarkError::Symlink(entry.path().to_path_buf()));
        }
        if metadata.file_type().is_dir() {
            directories.push(entry.path().to_path_buf());
        }
    }
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for directory in directories {
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o555))
            .map_err(|error| BenchmarkError::io(&directory, error))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn set_directory_readonly_recursive(_root: &Path) -> Result<(), BenchmarkError> {
    Err(BenchmarkError::UnsupportedPlatform)
}

struct StagingDirectory {
    path: PathBuf,
    armed: bool,
}

impl StagingDirectory {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for StagingDirectory {
    fn drop(&mut self) {
        if self.armed {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;

                for entry in WalkDir::new(&self.path)
                    .contents_first(true)
                    .follow_links(false)
                    .into_iter()
                    .flatten()
                {
                    if entry.file_type().is_dir() {
                        let _ = std::fs::set_permissions(
                            entry.path(),
                            std::fs::Permissions::from_mode(0o700),
                        );
                    } else if entry.file_type().is_file() {
                        let _ = std::fs::set_permissions(
                            entry.path(),
                            std::fs::Permissions::from_mode(0o600),
                        );
                    }
                }
            }
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}
