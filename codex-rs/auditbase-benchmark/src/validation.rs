use std::collections::HashMap;
use std::collections::HashSet;
use std::fs::Metadata;
use std::path::Path;
use std::path::PathBuf;

use globset::GlobBuilder;
use globset::GlobSet;
use globset::GlobSetBuilder;
use thiserror::Error;

use crate::BenchmarkCatalog;
use crate::ContaminationRisk;
use crate::LicenseStatus;

pub(crate) const MAX_CATALOG_BYTES: u64 = 4 * 1024 * 1024;
pub(crate) const MAX_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
const MAX_FILES_HARD: u32 = 100_000;
const MAX_FILE_BYTES_HARD: u64 = 512 * 1024 * 1024;
const MAX_TOTAL_BYTES_HARD: u64 = 8 * 1024 * 1024 * 1024;
const MAX_PATH_BYTES_HARD: u32 = 4096;
const MAX_SCOPE_BYTES: usize = 16 * 1024;
const MAX_POLICY_ITEMS: usize = 1024;
const MAX_POLICY_ITEM_BYTES: usize = 512;

const BUILTIN_FORBIDDEN_PATH_GLOBS: &[&str] = &[
    ".git",
    ".git/**",
    "**/.git",
    "**/.git/**",
    ".gitmodules",
    "**/.gitmodules",
    "report.md",
    "audit.md",
    "**/report.md",
    "**/audit.md",
    "**/truth.json",
    "**/ground-truth.json",
    "**/ground_truth.json",
    "**/adjudication.json",
    "**/findings/**",
    "**/reports/**",
    "**/audit-reports/**",
    "**/audit_reports/**",
    "**/*-findings.*",
    "**/*_findings.*",
    "**/*audit-report*",
    "**/*audit_report*",
    "**/*bot-report*",
    "**/*4naly3er*",
    "**/*discord-export*",
    "**/*known-issues*",
    "**/*known_issues*",
];

const BUILTIN_FORBIDDEN_CONTENT_PATTERNS: &[&str] = &[
    "verified ground truth vulnerabilities",
    "@vulnerable_at_lines",
    "<yes> <report>",
    "code4rena.com/reports/",
    "sherlock.xyz/contests/",
    "-findings/issues/",
];

#[derive(Debug, Error)]
pub enum BenchmarkError {
    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("JSON error at {path}: {source}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("invalid benchmark catalog: {0}")]
    InvalidCatalog(String),
    #[error("invalid agent input manifest: {0}")]
    InvalidManifest(String),
    #[error("invalid opaque run case ID: expected 'run-' followed by 32 lowercase hex characters")]
    InvalidOpaqueRunCaseId,
    #[error("unsafe benchmark path '{path}': {reason}")]
    InvalidPath { path: String, reason: String },
    #[error("license policy rejected the case: {0}")]
    LicensePolicy(String),
    #[error("contamination policy rejected the case: {0}")]
    ContaminationPolicy(String),
    #[error("source entry is not a regular file: {0}")]
    NonRegularFile(PathBuf),
    #[error("symbolic links are forbidden: {0}")]
    Symlink(PathBuf),
    #[error("hard-linked files are forbidden: {0}")]
    Hardlink(PathBuf),
    #[error("archive content is forbidden: {0}")]
    Archive(PathBuf),
    #[error("answer-bearing content is forbidden in '{path}': {reason}")]
    Leakage { path: String, reason: String },
    #[error("package limit exceeded: {0}")]
    LimitExceeded(String),
    #[error("digest mismatch for '{path}': expected {expected}, found {actual}")]
    DigestMismatch {
        path: String,
        expected: String,
        actual: String,
    },
    #[error("size mismatch for '{path}': expected {expected}, found {actual}")]
    SizeMismatch {
        path: String,
        expected: u64,
        actual: u64,
    },
    #[error("output path already exists: {0}")]
    OutputExists(PathBuf),
    #[error("package verification failed: {0}")]
    Verification(String),
    #[error("safe hard-link verification is not implemented on this platform")]
    UnsupportedPlatform,
}

impl BenchmarkError {
    pub(crate) fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }

    pub(crate) fn json(path: impl Into<PathBuf>, source: serde_json::Error) -> Self {
        Self::Json {
            path: path.into(),
            source,
        }
    }
}

pub(crate) struct ContentPolicy {
    path_globs: GlobSet,
    identity_markers: Vec<(String, Vec<u8>)>,
    patterns: Vec<(String, Vec<u8>)>,
    forbidden_digests: HashSet<[u8; 32]>,
    max_pattern_len: usize,
}

impl ContentPolicy {
    pub(crate) fn from_catalog(catalog: &BenchmarkCatalog) -> Result<Self, BenchmarkError> {
        let mut glob_builder = GlobSetBuilder::new();
        for pattern in BUILTIN_FORBIDDEN_PATH_GLOBS.iter().copied().chain(
            catalog
                .contamination
                .forbidden_path_globs
                .iter()
                .map(String::as_str),
        ) {
            let glob = GlobBuilder::new(pattern)
                .case_insensitive(true)
                .literal_separator(true)
                .build()
                .map_err(|error| {
                    BenchmarkError::InvalidCatalog(format!(
                        "invalid forbidden path glob '{pattern}': {error}"
                    ))
                })?;
            glob_builder.add(glob);
        }
        let path_globs = glob_builder.build().map_err(|error| {
            BenchmarkError::InvalidCatalog(format!("could not build path policy: {error}"))
        })?;

        let identity_markers = [
            ("catalog case identity", catalog.case_id.as_str()),
            ("catalog project identity", catalog.project_id.as_str()),
            ("catalog source URL", catalog.source.url.as_str()),
        ]
        .into_iter()
        .map(|(label, marker)| (label.to_string(), marker.to_ascii_lowercase().into_bytes()))
        .collect::<Vec<_>>();

        let mut patterns = Vec::new();
        for pattern in BUILTIN_FORBIDDEN_CONTENT_PATTERNS {
            patterns.push(((*pattern).to_string(), pattern.as_bytes().to_vec()));
        }
        patterns.extend(identity_markers.iter().cloned());
        for (index, pattern) in catalog
            .contamination
            .forbidden_content_patterns
            .iter()
            .enumerate()
        {
            patterns.push((
                format!("catalog pattern {index}"),
                pattern.to_ascii_lowercase().into_bytes(),
            ));
        }
        let max_pattern_len = patterns
            .iter()
            .map(|(_, pattern)| pattern.len())
            .max()
            .unwrap_or(1);

        let forbidden_digests = catalog
            .contamination
            .forbidden_content_sha256
            .iter()
            .map(|digest| decode_sha256(digest, "forbiddenContentSha256"))
            .collect::<Result<_, _>>()?;

        Ok(Self {
            path_globs,
            identity_markers,
            patterns,
            forbidden_digests,
            max_pattern_len,
        })
    }

    pub(crate) fn validate_path(&self, path: &str) -> Result<(), BenchmarkError> {
        if self.path_globs.is_match(path) {
            return Err(BenchmarkError::Leakage {
                path: path.to_string(),
                reason: "path matches a forbidden report, truth, finding, or Git pattern"
                    .to_string(),
            });
        }
        let folded_path = path.to_ascii_lowercase();
        for (label, marker) in &self.identity_markers {
            if contains_slice(folded_path.as_bytes(), marker) {
                return Err(BenchmarkError::Leakage {
                    path: path.to_string(),
                    reason: format!("matched forbidden agent-visible identity marker '{label}'"),
                });
            }
        }
        if has_archive_extension(path) {
            return Err(BenchmarkError::Archive(PathBuf::from(path)));
        }
        Ok(())
    }

    pub(crate) fn validate_digest(
        &self,
        path: &str,
        digest: [u8; 32],
    ) -> Result<(), BenchmarkError> {
        if self.forbidden_digests.contains(&digest) {
            return Err(BenchmarkError::Leakage {
                path: path.to_string(),
                reason: "content digest matches evaluator-only material".to_string(),
            });
        }
        Ok(())
    }

    pub(crate) fn scanner(&self) -> ContentScanner<'_> {
        ContentScanner {
            policy: self,
            tail: Vec::new(),
        }
    }

    pub(crate) fn validate_small_text(
        &self,
        field: &str,
        value: &str,
    ) -> Result<(), BenchmarkError> {
        let mut scanner = self.scanner();
        scanner.scan(field, value.as_bytes())
    }
}

pub(crate) struct ContentScanner<'a> {
    policy: &'a ContentPolicy,
    tail: Vec<u8>,
}

impl ContentScanner<'_> {
    pub(crate) fn scan(&mut self, path: &str, chunk: &[u8]) -> Result<(), BenchmarkError> {
        let mut searchable = Vec::with_capacity(self.tail.len() + chunk.len());
        searchable.extend_from_slice(&self.tail);
        searchable.extend(chunk.iter().map(u8::to_ascii_lowercase));

        for (label, pattern) in &self.policy.patterns {
            if contains_slice(&searchable, pattern) {
                return Err(BenchmarkError::Leakage {
                    path: path.to_string(),
                    reason: format!("matched forbidden content marker '{label}'"),
                });
            }
        }

        let keep = self.policy.max_pattern_len.saturating_sub(1);
        self.tail.clear();
        if keep > 0 {
            let start = searchable.len().saturating_sub(keep);
            self.tail.extend_from_slice(&searchable[start..]);
        }
        Ok(())
    }
}

pub(crate) fn validate_catalog(
    catalog: &BenchmarkCatalog,
    allow_internal_evaluation_only: bool,
) -> Result<ContentPolicy, BenchmarkError> {
    require_token(&catalog.case_id, "caseId")?;
    require_token(&catalog.project_id, "projectId")?;
    require_nonempty(&catalog.source.url, "source.url")?;
    require_nonempty(&catalog.source.revision, "source.revision")?;
    require_nonempty(&catalog.source.retrieved_at, "source.retrievedAt")?;
    validate_limits(catalog)?;
    validate_license(catalog, allow_internal_evaluation_only)?;
    validate_contamination(catalog)?;

    if catalog.files.is_empty() {
        return Err(BenchmarkError::InvalidCatalog(
            "files must contain at least one entry".to_string(),
        ));
    }
    if catalog.files.len() > catalog.limits.max_files as usize {
        return Err(BenchmarkError::LimitExceeded(format!(
            "{} files exceeds maxFiles {}",
            catalog.files.len(),
            catalog.limits.max_files
        )));
    }
    if !catalog.files.iter().any(|file| file.in_scope) {
        return Err(BenchmarkError::InvalidCatalog(
            "at least one file must be in scope".to_string(),
        ));
    }

    let policy = ContentPolicy::from_catalog(catalog)?;
    policy.validate_small_text("scope.instructions", &catalog.scope.instructions)?;
    if catalog.scope.instructions.len() > MAX_SCOPE_BYTES {
        return Err(BenchmarkError::LimitExceeded(format!(
            "scope instructions exceed {MAX_SCOPE_BYTES} bytes"
        )));
    }

    let mut exact_paths = HashSet::new();
    let mut folded_paths = HashMap::<String, String>::new();
    let mut total_bytes = 0_u64;
    for file in &catalog.files {
        validate_relative_path(&file.path, catalog.limits.max_path_bytes)?;
        policy.validate_path(&file.path)?;
        validate_sha256(&file.sha256, &format!("files[{}].sha256", file.path))?;
        if file.size_bytes > catalog.limits.max_file_bytes {
            return Err(BenchmarkError::LimitExceeded(format!(
                "{} exceeds maxFileBytes {}",
                file.path, catalog.limits.max_file_bytes
            )));
        }
        total_bytes = total_bytes.checked_add(file.size_bytes).ok_or_else(|| {
            BenchmarkError::LimitExceeded("catalog byte total overflowed".to_string())
        })?;
        if !exact_paths.insert(file.path.as_str()) {
            return Err(BenchmarkError::InvalidCatalog(format!(
                "duplicate file path: {}",
                file.path
            )));
        }
        let folded = file.path.to_ascii_lowercase();
        if let Some(previous) = folded_paths.insert(folded, file.path.clone()) {
            return Err(BenchmarkError::InvalidCatalog(format!(
                "case-folding path collision: {previous} and {}",
                file.path
            )));
        }
    }
    if total_bytes > catalog.limits.max_total_bytes {
        return Err(BenchmarkError::LimitExceeded(format!(
            "catalog total {total_bytes} exceeds maxTotalBytes {}",
            catalog.limits.max_total_bytes
        )));
    }

    let catalog_paths = catalog
        .files
        .iter()
        .map(|file| file.path.as_str())
        .collect::<HashSet<_>>();
    for path in catalog
        .license
        .evidence_paths
        .iter()
        .chain(&catalog.license.required_notice_paths)
    {
        validate_relative_path(path, catalog.limits.max_path_bytes)?;
        if !catalog_paths.contains(path.as_str()) {
            return Err(BenchmarkError::LicensePolicy(format!(
                "required license evidence or notice is not packaged: {path}"
            )));
        }
    }

    Ok(policy)
}

fn validate_limits(catalog: &BenchmarkCatalog) -> Result<(), BenchmarkError> {
    let limits = &catalog.limits;
    let positive = [
        ("maxFiles", limits.max_files as u64),
        ("maxFileBytes", limits.max_file_bytes),
        ("maxTotalBytes", limits.max_total_bytes),
        ("maxPathBytes", limits.max_path_bytes as u64),
    ];
    for (field, value) in positive {
        if value == 0 {
            return Err(BenchmarkError::InvalidCatalog(format!(
                "limits.{field} must be greater than zero"
            )));
        }
    }
    if limits.max_files > MAX_FILES_HARD
        || limits.max_file_bytes > MAX_FILE_BYTES_HARD
        || limits.max_total_bytes > MAX_TOTAL_BYTES_HARD
        || limits.max_path_bytes > MAX_PATH_BYTES_HARD
    {
        return Err(BenchmarkError::InvalidCatalog(
            "package limits exceed the packager's hard ceilings".to_string(),
        ));
    }
    Ok(())
}

fn validate_license(
    catalog: &BenchmarkCatalog,
    allow_internal_evaluation_only: bool,
) -> Result<(), BenchmarkError> {
    match catalog.license.status {
        LicenseStatus::Cleared if catalog.license.redistribution_allowed => {}
        LicenseStatus::Cleared => {
            return Err(BenchmarkError::LicensePolicy(
                "cleared material must explicitly allow redistribution".to_string(),
            ));
        }
        LicenseStatus::InternalEvaluationOnly if allow_internal_evaluation_only => {}
        LicenseStatus::InternalEvaluationOnly => {
            return Err(BenchmarkError::LicensePolicy(
                "internal-only material requires explicit operator opt-in".to_string(),
            ));
        }
        LicenseStatus::Unknown => {
            return Err(BenchmarkError::LicensePolicy(
                "license status is unknown".to_string(),
            ));
        }
        LicenseStatus::Blocked => {
            return Err(BenchmarkError::LicensePolicy(
                "license review blocked use".to_string(),
            ));
        }
    }
    if catalog.license.spdx_expressions.is_empty() || catalog.license.evidence_paths.is_empty() {
        return Err(BenchmarkError::LicensePolicy(
            "SPDX expressions and evidence paths are required".to_string(),
        ));
    }
    require_nonempty_license(&catalog.license.reviewed_by, "reviewedBy")?;
    require_nonempty_license(&catalog.license.reviewed_at, "reviewedAt")?;
    for expression in &catalog.license.spdx_expressions {
        require_nonempty_license(expression, "spdxExpressions")?;
    }
    Ok(())
}

fn validate_contamination(catalog: &BenchmarkCatalog) -> Result<(), BenchmarkError> {
    if catalog.contamination.identity_visible {
        return Err(BenchmarkError::ContaminationPolicy(
            "identityVisible must be false for a blinded agent package".to_string(),
        ));
    }
    match catalog.contamination.risk {
        ContaminationRisk::Low | ContaminationRisk::Medium => {}
        ContaminationRisk::High => {
            return Err(BenchmarkError::ContaminationPolicy(
                "high-contamination material is not eligible for packaging".to_string(),
            ));
        }
        ContaminationRisk::Unknown => {
            return Err(BenchmarkError::ContaminationPolicy(
                "contamination risk has not been reviewed".to_string(),
            ));
        }
    }
    require_nonempty_contamination(&catalog.contamination.reviewed_by, "reviewedBy")?;
    require_nonempty_contamination(&catalog.contamination.reviewed_at, "reviewedAt")?;
    require_token(
        &catalog.contamination.sanitization_policy_version,
        "contamination.sanitizationPolicyVersion",
    )?;
    if catalog.contamination.forbidden_path_globs.len() > MAX_POLICY_ITEMS
        || catalog.contamination.forbidden_content_sha256.len() > MAX_POLICY_ITEMS
        || catalog.contamination.forbidden_content_patterns.len() > MAX_POLICY_ITEMS
    {
        return Err(BenchmarkError::ContaminationPolicy(format!(
            "a contamination policy list exceeds {MAX_POLICY_ITEMS} items"
        )));
    }
    for pattern in &catalog.contamination.forbidden_path_globs {
        validate_policy_item(pattern, "forbiddenPathGlobs")?;
    }
    for pattern in &catalog.contamination.forbidden_content_patterns {
        validate_policy_item(pattern, "forbiddenContentPatterns")?;
        if pattern.len() < 8 || !pattern.is_ascii() {
            return Err(BenchmarkError::ContaminationPolicy(
                "forbidden content patterns must be ASCII and at least 8 bytes".to_string(),
            ));
        }
    }
    for digest in &catalog.contamination.forbidden_content_sha256 {
        validate_sha256(digest, "contamination.forbiddenContentSha256")?;
    }
    Ok(())
}

fn validate_policy_item(value: &str, field: &str) -> Result<(), BenchmarkError> {
    if value.trim().is_empty() || value.len() > MAX_POLICY_ITEM_BYTES {
        return Err(BenchmarkError::ContaminationPolicy(format!(
            "{field} entries must be nonempty and at most {MAX_POLICY_ITEM_BYTES} bytes"
        )));
    }
    Ok(())
}

fn require_nonempty(value: &str, field: &str) -> Result<(), BenchmarkError> {
    if value.trim().is_empty() {
        return Err(BenchmarkError::InvalidCatalog(format!(
            "{field} must not be empty"
        )));
    }
    Ok(())
}

fn require_nonempty_license(value: &str, field: &str) -> Result<(), BenchmarkError> {
    if value.trim().is_empty() {
        return Err(BenchmarkError::LicensePolicy(format!(
            "{field} must not be empty"
        )));
    }
    Ok(())
}

fn require_nonempty_contamination(value: &str, field: &str) -> Result<(), BenchmarkError> {
    if value.trim().is_empty() {
        return Err(BenchmarkError::ContaminationPolicy(format!(
            "{field} must not be empty"
        )));
    }
    Ok(())
}

fn require_token(value: &str, field: &str) -> Result<(), BenchmarkError> {
    require_nonempty(value, field)?;
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(BenchmarkError::InvalidCatalog(format!(
            "{field} must be an ASCII token"
        )));
    }
    Ok(())
}

pub(crate) fn validate_relative_path(path: &str, max_bytes: u32) -> Result<(), BenchmarkError> {
    if path.is_empty() {
        return Err(invalid_path(path, "path is empty"));
    }
    if path.len() > max_bytes as usize {
        return Err(invalid_path(path, "path exceeds the configured limit"));
    }
    if !path.is_ascii() || !path.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(invalid_path(
            path,
            "benchmark path policy v1 permits printable ASCII only",
        ));
    }
    if path.starts_with('/') || path.starts_with('\\') || path.contains('\\') || path.contains(':')
    {
        return Err(invalid_path(
            path,
            "path must be portable, relative, and forward-slash delimited",
        ));
    }
    for component in path.split('/') {
        if component.is_empty() || matches!(component, "." | "..") {
            return Err(invalid_path(
                path,
                "path contains an empty, '.' or '..' component",
            ));
        }
        if component.ends_with('.') || component.ends_with(' ') || is_windows_reserved(component) {
            return Err(invalid_path(path, "path contains a non-portable component"));
        }
    }
    Ok(())
}

fn invalid_path(path: &str, reason: &str) -> BenchmarkError {
    BenchmarkError::InvalidPath {
        path: path.to_string(),
        reason: reason.to_string(),
    }
}

fn is_windows_reserved(component: &str) -> bool {
    let stem = component
        .split_once('.')
        .map_or(component, |(stem, _extension)| stem)
        .to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || stem.strip_prefix("COM").is_some_and(|suffix| {
            matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
        })
        || stem.strip_prefix("LPT").is_some_and(|suffix| {
            matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
        })
}

pub(crate) fn validate_sha256(value: &str, field: &str) -> Result<(), BenchmarkError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(BenchmarkError::InvalidCatalog(format!(
            "{field} must be a lowercase SHA-256 digest"
        )));
    }
    Ok(())
}

pub(crate) fn decode_sha256(value: &str, field: &str) -> Result<[u8; 32], BenchmarkError> {
    validate_sha256(value, field)?;
    let mut output = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
    }
    Ok(output)
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => unreachable!("digest is validated before decoding"),
    }
}

pub(crate) fn has_archive_magic(prefix: &[u8]) -> bool {
    prefix.starts_with(b"PK\x03\x04")
        || prefix.starts_with(b"PK\x05\x06")
        || prefix.starts_with(b"PK\x07\x08")
        || prefix.starts_with(b"\x1f\x8b")
        || prefix.starts_with(b"BZh")
        || prefix.starts_with(b"\xfd7zXZ\0")
        || prefix.starts_with(b"7z\xbc\xaf'\x1c")
        || prefix.starts_with(b"Rar!\x1a\x07")
        || prefix.starts_with(b"\x28\xb5\x2f\xfd")
        || prefix.starts_with(b"!<arch>\n")
        || prefix.get(257..262) == Some(b"ustar")
}

fn has_archive_extension(path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    [
        ".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz", ".tbz2", ".tar.xz", ".txz",
        ".tar.zst", ".7z", ".rar", ".gz", ".bz2", ".xz", ".zst", ".jar", ".war", ".ear",
    ]
    .iter()
    .any(|extension| path.ends_with(extension))
}

fn contains_slice(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

pub(crate) fn ensure_single_link(path: &Path, metadata: &Metadata) -> Result<(), BenchmarkError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        if metadata.nlink() != 1 {
            return Err(BenchmarkError::Hardlink(path.to_path_buf()));
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        let _ = metadata;
        Err(BenchmarkError::UnsupportedPlatform)
    }
}

pub(crate) fn ensure_no_symlink_components(
    root: &Path,
    relative: &str,
) -> Result<PathBuf, BenchmarkError> {
    let mut current = root.to_path_buf();
    let component_count = relative.split('/').count();
    for (index, component) in relative.split('/').enumerate() {
        current.push(component);
        let metadata = std::fs::symlink_metadata(&current)
            .map_err(|error| BenchmarkError::io(&current, error))?;
        if metadata.file_type().is_symlink() {
            return Err(BenchmarkError::Symlink(current));
        }
        if index + 1 == component_count {
            if !metadata.file_type().is_file() {
                return Err(BenchmarkError::NonRegularFile(current));
            }
            ensure_single_link(&current, &metadata)?;
        } else if !metadata.file_type().is_dir() {
            return Err(BenchmarkError::NonRegularFile(current));
        }
    }
    Ok(current)
}
