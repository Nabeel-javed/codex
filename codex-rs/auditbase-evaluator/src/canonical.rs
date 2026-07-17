use serde::Serialize;
use serde_json::Map;
use serde_json::Value;
use sha2::Digest;
use sha2::Sha256;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CanonicalError {
    #[error("failed to serialize canonical artifact: {0}")]
    Serialize(#[from] serde_json::Error),
}

/// Serializes an artifact with recursively sorted object keys. Array order is
/// preserved because finding order and reviewer order are meaningful inputs.
pub fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, CanonicalError> {
    let value = serde_json::to_value(value)?;
    serde_json::to_vec(&sort_value(value)).map_err(CanonicalError::from)
}

pub fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, CanonicalError> {
    Ok(sha256_hex(&canonical_json_bytes(value)?))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("{digest:x}")
}

pub fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn sort_value(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(sort_value).collect()),
        Value::Object(values) => {
            let mut entries: Vec<_> = values.into_iter().collect();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            let mut sorted = Map::new();
            for (key, value) in entries {
                sorted.insert(key, sort_value(value));
            }
            Value::Object(sorted)
        }
        scalar => scalar,
    }
}
