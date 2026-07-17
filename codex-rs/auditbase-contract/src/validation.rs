use std::cmp::Ordering;
use std::collections::HashMap;
use std::collections::HashSet;

use serde::Serialize;
use thiserror::Error;

use crate::ContractLimits;

/// Largest integer that every supported JSON/JavaScript consumer can
/// represent exactly.
pub const JS_MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

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

/// Applies backend-configured resource limits after structural validation.
pub trait ValidateWithLimits: Validate {
    fn validate_with_limits(&self, limits: &ContractLimits) -> Result<(), ValidationError>;
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
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ValidationError::new(
            field,
            "must be a lowercase 64-character hexadecimal SHA-256 digest",
        ));
    }
    Ok(())
}

pub(crate) fn require_js_safe_u64(value: u64, field: &str) -> Result<(), ValidationError> {
    if value > JS_MAX_SAFE_INTEGER {
        return Err(ValidationError::new(
            field,
            format!("must not exceed the JSON safe integer {JS_MAX_SAFE_INTEGER}"),
        ));
    }
    Ok(())
}

pub(crate) fn require_relative_path(value: &str, field: &str) -> Result<(), ValidationError> {
    require_nonempty(value, field)?;
    if value.chars().count() > 2000 {
        return Err(ValidationError::new(
            field,
            "must be at most 2000 characters",
        ));
    }
    if value.starts_with('/')
        || value.starts_with('\\')
        || value.contains('\\')
        || value.contains(':')
        || value.chars().any(|character| {
            character.is_control() || matches!(character, '<' | '>' | '"' | '|' | '?' | '*')
        })
    {
        return Err(ValidationError::new(
            field,
            "must be a portable, forward-slash-delimited relative path",
        ));
    }

    for component in value.split('/') {
        let base = component.split('.').next().unwrap_or_default();
        let windows_reserved = matches!(
            base.to_ascii_lowercase().as_str(),
            "con"
                | "prn"
                | "aux"
                | "nul"
                | "com1"
                | "com2"
                | "com3"
                | "com4"
                | "com5"
                | "com6"
                | "com7"
                | "com8"
                | "com9"
                | "lpt1"
                | "lpt2"
                | "lpt3"
                | "lpt4"
                | "lpt5"
                | "lpt6"
                | "lpt7"
                | "lpt8"
                | "lpt9"
        );
        if component.is_empty()
            || matches!(component, "." | "..")
            || component.chars().count() > 255
            || component.ends_with('.')
            || component.ends_with(' ')
            || windows_reserved
        {
            return Err(ValidationError::new(
                field,
                "must be normalized and contain only portable path components",
            ));
        }
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

pub(crate) fn require_unique_unicode_lowercase<'a>(
    values: impl IntoIterator<Item = &'a str>,
    field: &str,
) -> Result<(), ValidationError> {
    let mut seen = HashMap::<String, &str>::new();
    for value in values {
        let collision_key = value.to_lowercase();
        if let Some(previous) = seen.insert(collision_key, value) {
            return Err(ValidationError::new(
                field,
                format!("case-folding collision between '{previous}' and '{value}'"),
            ));
        }
    }
    Ok(())
}

pub(crate) fn require_max_bytes(
    value: &str,
    maximum: u64,
    field: &str,
) -> Result<(), ValidationError> {
    if value.len() as u64 > maximum {
        return Err(ValidationError::new(
            field,
            format!("must be at most {maximum} UTF-8 bytes"),
        ));
    }
    Ok(())
}

pub(crate) fn require_serialized_max_bytes<T: Serialize>(
    value: &T,
    maximum: u64,
    field: &str,
) -> Result<(), ValidationError> {
    let encoded = serde_json::to_vec(value).map_err(|error| {
        ValidationError::new(
            field,
            format!("could not be serialized for sizing: {error}"),
        )
    })?;
    if encoded.len() as u64 > maximum {
        return Err(ValidationError::new(
            field,
            format!("serialized value must be at most {maximum} bytes"),
        ));
    }
    Ok(())
}

pub(crate) fn require_total_string_bytes<'a>(
    values: impl IntoIterator<Item = &'a str>,
    maximum: u64,
    field: &str,
) -> Result<(), ValidationError> {
    let mut total = 0_u64;
    for value in values {
        total = total
            .checked_add(value.len() as u64)
            .ok_or_else(|| ValidationError::new(field, "combined UTF-8 byte length overflowed"))?;
    }
    if total > maximum {
        return Err(ValidationError::new(
            field,
            format!("combined values must be at most {maximum} UTF-8 bytes"),
        ));
    }
    Ok(())
}

pub(crate) fn require_serialized_items_max_bytes<'a, T: Serialize + 'a>(
    values: impl IntoIterator<Item = &'a T>,
    maximum: u64,
    field: &str,
) -> Result<(), ValidationError> {
    let mut total = 0_u64;
    for value in values {
        let length = serde_json::to_vec(value)
            .map_err(|error| {
                ValidationError::new(
                    field,
                    format!("could not be serialized for sizing: {error}"),
                )
            })?
            .len() as u64;
        total = total.checked_add(length).ok_or_else(|| {
            ValidationError::new(field, "combined serialized byte length overflowed")
        })?;
    }
    if total > maximum {
        return Err(ValidationError::new(
            field,
            format!("combined serialized values must be at most {maximum} bytes"),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Rfc3339Instant {
    unix_seconds: i64,
    fractional_digits: String,
}

impl Rfc3339Instant {
    pub(crate) fn compare(&self, other: &Self) -> Ordering {
        match self.unix_seconds.cmp(&other.unix_seconds) {
            Ordering::Equal => {
                compare_fractional_digits(&self.fractional_digits, &other.fractional_digits)
            }
            ordering => ordering,
        }
    }
}

pub(crate) fn require_rfc3339(value: &str, field: &str) -> Result<Rfc3339Instant, ValidationError> {
    parse_rfc3339(value).ok_or_else(|| {
        ValidationError::new(
            field,
            "must use canonical UTC millisecond format YYYY-MM-DDTHH:MM:SS.sssZ",
        )
    })
}

fn parse_rfc3339(value: &str) -> Option<Rfc3339Instant> {
    let bytes = value.as_bytes();
    if bytes.len() != 24
        || bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || bytes.get(10) != Some(&b'T')
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
        || bytes.get(19) != Some(&b'.')
        || bytes.get(23) != Some(&b'Z')
    {
        return None;
    }

    let year = parse_ascii_u32(bytes.get(0..4)?)?;
    let month = parse_ascii_u32(bytes.get(5..7)?)?;
    let day = parse_ascii_u32(bytes.get(8..10)?)?;
    let hour = parse_ascii_u32(bytes.get(11..13)?)?;
    let minute = parse_ascii_u32(bytes.get(14..16)?)?;
    let second = parse_ascii_u32(bytes.get(17..19)?)?;

    if year == 0
        || !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let fractional_digits = value.get(20..23)?.to_string();
    parse_ascii_u32(bytes.get(20..23)?)?;
    let local_seconds = days_from_civil(i64::from(year), month, day)
        .checked_mul(86_400)?
        .checked_add(i64::from(hour) * 3_600)?
        .checked_add(i64::from(minute) * 60)?
        .checked_add(i64::from(second))?;

    Some(Rfc3339Instant {
        unix_seconds: local_seconds,
        fractional_digits,
    })
}

fn parse_ascii_u32(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    bytes.iter().try_fold(0_u32, |value, byte| {
        value.checked_mul(10)?.checked_add(u32::from(byte - b'0'))
    })
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year.is_multiple_of(400) || (year.is_multiple_of(4) && !year.is_multiple_of(100)) => {
            29
        }
        2 => 28,
        _ => 0,
    }
}

// Howard Hinnant's civil-date conversion, relative to the Unix epoch.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let adjusted_year = year - i64::from(month <= 2);
    let era = if adjusted_year >= 0 {
        adjusted_year
    } else {
        adjusted_year - 399
    } / 400;
    let year_of_era = adjusted_year - era * 400;
    let adjusted_month = i64::from(month) + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * adjusted_month + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn compare_fractional_digits(left: &str, right: &str) -> Ordering {
    let maximum = left.len().max(right.len());
    let left_bytes = left.as_bytes();
    let right_bytes = right.as_bytes();
    for index in 0..maximum {
        let left_digit = left_bytes.get(index).copied().unwrap_or(b'0');
        let right_digit = right_bytes.get(index).copied().unwrap_or(b'0');
        match left_digit.cmp(&right_digit) {
            Ordering::Equal => {}
            ordering => return ordering,
        }
    }
    Ordering::Equal
}
