use std::collections::HashSet;

use thiserror::Error;

/// A stable, field-addressable contract validation failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("{field}: {message}")]
pub struct ValidationError {
    pub field: String,
    pub message: String,
}

impl ValidationError {
    pub(crate) fn new(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            message: message.into(),
        }
    }
}

/// Performs semantic checks that JSON Schema alone cannot express clearly.
pub trait Validate {
    fn validate(&self) -> Result<(), ValidationError>;
}

pub(crate) fn require_nonempty(value: &str, field: &str) -> Result<(), ValidationError> {
    if value.trim().is_empty() {
        return Err(ValidationError::new(field, "must not be empty"));
    }
    Ok(())
}

pub(crate) fn require_token(value: &str, field: &str) -> Result<(), ValidationError> {
    require_nonempty(value, field)?;
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ValidationError::new(
            field,
            "must contain only ASCII letters, numbers, '.', '-' or '_'",
        ));
    }
    Ok(())
}

pub(crate) fn require_sha256(value: &str, field: &str) -> Result<(), ValidationError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ValidationError::new(
            field,
            "must be a 64-character hexadecimal SHA-256 digest",
        ));
    }
    Ok(())
}

pub(crate) fn require_relative_path(value: &str, field: &str) -> Result<(), ValidationError> {
    require_nonempty(value, field)?;
    if value.starts_with('/')
        || value.starts_with('\\')
        || value.contains('\\')
        || value.contains('\0')
        || value.contains(':')
    {
        return Err(ValidationError::new(
            field,
            "must be a portable, forward-slash-delimited relative path",
        ));
    }

    if value
        .split('/')
        .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(ValidationError::new(
            field,
            "must be normalized and must not contain empty, '.' or '..' components",
        ));
    }
    Ok(())
}

pub(crate) fn require_unique<'a>(
    values: impl IntoIterator<Item = &'a str>,
    field: &str,
) -> Result<(), ValidationError> {
    let mut seen = HashSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(ValidationError::new(
                field,
                format!("duplicate value: {value}"),
            ));
        }
    }
    Ok(())
}
