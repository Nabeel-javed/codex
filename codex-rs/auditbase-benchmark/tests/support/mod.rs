use std::fs;
use std::path::Path;

use codex_auditbase_benchmark::BenchmarkCatalog;
use codex_auditbase_benchmark::PackageOptions;
use sha2::Digest;
use sha2::Sha256;

pub const CATALOG: &str = include_str!("../../fixtures/authored/basic/catalog.json");
pub const COUNTER: &[u8] =
    include_bytes!("../../fixtures/authored/basic/source/contracts/Counter.sol");
pub const LICENSE: &[u8] = include_bytes!("../../fixtures/authored/basic/source/LICENSE");
pub const RUN_CASE_ID: &str = "run-0123456789abcdef0123456789abcdef";

pub fn options() -> PackageOptions {
    PackageOptions::blinded(RUN_CASE_ID)
}

pub fn catalog() -> BenchmarkCatalog {
    serde_json::from_str(CATALOG).expect("authored catalog must parse")
}

pub fn materialize_source(root: &Path) {
    fs::create_dir_all(root.join("contracts")).expect("create authored source directory");
    fs::write(root.join("contracts/Counter.sol"), COUNTER).expect("write authored contract");
    fs::write(root.join("LICENSE"), LICENSE).expect("write authored license");
}

#[allow(dead_code)]
pub fn replace_counter(catalog: &mut BenchmarkCatalog, source: &Path, bytes: &[u8]) {
    fs::write(source.join("contracts/Counter.sol"), bytes).expect("replace authored contract");
    let entry = catalog
        .files
        .iter_mut()
        .find(|file| file.path == "contracts/Counter.sol")
        .expect("counter entry exists");
    entry.size_bytes = bytes.len() as u64;
    entry.sha256 = sha256(bytes);
}

#[allow(dead_code)]
pub fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write;

        write!(&mut output, "{byte:02x}").expect("writing to string cannot fail");
    }
    output
}

#[cfg(unix)]
pub fn make_writable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    if !path.exists() {
        return;
    }
    for entry in walkdir::WalkDir::new(path)
        .contents_first(true)
        .into_iter()
        .flatten()
    {
        let mode = if entry.file_type().is_dir() {
            0o700
        } else {
            0o600
        };
        fs::set_permissions(entry.path(), fs::Permissions::from_mode(mode))
            .expect("restore test fixture permissions");
    }
}
