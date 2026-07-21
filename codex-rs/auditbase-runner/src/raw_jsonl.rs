use std::collections::BTreeSet;

use codex_exec::ThreadEvent;
use serde_json::Value;

use crate::RunnerError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JsonlLimits {
    pub max_total_bytes: usize,
    pub max_line_bytes: usize,
    pub max_events: usize,
}

impl JsonlLimits {
    pub const fn production_default() -> Self {
        Self {
            max_total_bytes: 32 * 1024 * 1024,
            max_line_bytes: 2 * 1024 * 1024,
            max_events: 100_000,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ParsedJsonl {
    pub events: Vec<ThreadEvent>,
    pub total_bytes: usize,
}

/// Parses the private upstream JSONL wire format with hard byte and event
/// bounds. Unknown top-level event variants and fields fail closed, making
/// upstream drift visible instead of silently changing AuditBase behavior.
pub fn parse_thread_events(bytes: &[u8], limits: JsonlLimits) -> Result<ParsedJsonl, RunnerError> {
    if bytes.len() > limits.max_total_bytes {
        return Err(RunnerError::ByteLimit {
            kind: "Codex JSONL stream",
            actual: bytes.len(),
            maximum: limits.max_total_bytes,
        });
    }

    let mut events = Vec::new();
    let mut lines = bytes.split(|byte| *byte == b'\n').peekable();
    let mut line_number = 0;
    while let Some(mut line) = lines.next() {
        line_number += 1;
        if line.last() == Some(&b'\r') {
            line = &line[..line.len() - 1];
        }
        if line.is_empty() {
            if lines.peek().is_none() {
                continue;
            }
            return Err(RunnerError::EmptyJsonlLine { line: line_number });
        }
        if line.len() > limits.max_line_bytes {
            return Err(RunnerError::ByteLimit {
                kind: "Codex JSONL line",
                actual: line.len(),
                maximum: limits.max_line_bytes,
            });
        }
        if std::str::from_utf8(line).is_err() {
            return Err(RunnerError::InvalidJsonlUtf8 { line: line_number });
        }
        if events.len() == limits.max_events {
            return Err(RunnerError::EventLimit {
                actual: events.len() + 1,
                maximum: limits.max_events,
            });
        }

        let value: Value =
            serde_json::from_slice(line).map_err(|error| RunnerError::MalformedJsonl {
                line: line_number,
                message: error.to_string(),
            })?;
        let is_best_effort_item = is_item_event(&value);
        if let Err(error) = validate_event_envelope(&value, line_number) {
            if is_best_effort_item {
                continue;
            }
            return Err(error);
        }
        let event: ThreadEvent = match serde_json::from_value(value.clone()) {
            Ok(event) => event,
            Err(_) if is_best_effort_item => continue,
            Err(error) => {
                return Err(RunnerError::MalformedJsonl {
                    line: line_number,
                    message: error.to_string(),
                });
            }
        };
        let canonical =
            serde_json::to_value(&event).map_err(|error| RunnerError::MalformedJsonl {
                line: line_number,
                message: format!("could not normalize parsed event: {error}"),
            })?;
        if let Err(error) = reject_ignored_fields(&value, &canonical, line_number, "") {
            if is_best_effort_item {
                continue;
            }
            return Err(error);
        }
        events.push(event);
    }

    Ok(ParsedJsonl {
        events,
        total_bytes: bytes.len(),
    })
}

fn is_item_event(value: &Value) -> bool {
    let Some(event_type) = value.get("type").and_then(Value::as_str) else {
        return false;
    };
    matches!(
        event_type,
        "item.started" | "item.updated" | "item.completed"
    )
}

/// `codex_exec::ThreadEvent` deliberately remains backwards-compatible and
/// therefore does not deny unknown fields on every nested payload. Compare the
/// parsed input with its typed round trip so a field that Serde ignored cannot
/// silently change AuditBase behavior. Canonical fields added by defaults are
/// harmless; only input fields missing from the typed representation fail.
fn reject_ignored_fields(
    input: &Value,
    canonical: &Value,
    line: usize,
    path: &str,
) -> Result<(), RunnerError> {
    match (input, canonical) {
        (Value::Object(input), Value::Object(canonical)) => {
            for (field, value) in input {
                let field_path = if path.is_empty() {
                    field.clone()
                } else {
                    format!("{path}.{field}")
                };
                let Some(canonical_value) = canonical.get(field) else {
                    if known_skipped_null(path, field, value) {
                        continue;
                    }
                    return Err(RunnerError::UnknownThreadEventField {
                        line,
                        field: field_path,
                    });
                };
                reject_ignored_fields(value, canonical_value, line, &field_path)?;
            }
        }
        (Value::Array(input), Value::Array(canonical)) => {
            for (index, (value, canonical_value)) in input.iter().zip(canonical.iter()).enumerate()
            {
                let item_path = format!("{path}[{index}]");
                reject_ignored_fields(value, canonical_value, line, &item_path)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn known_skipped_null(path: &str, field: &str, value: &Value) -> bool {
    if !value.is_null() {
        return false;
    }
    (path.is_empty()
        && matches!(
            field,
            "model" | "model_provider_id" | "reasoning_effort" | "service_tier"
        ))
        || (path == "item.result" && field == "_meta")
}

fn validate_event_envelope(value: &Value, line: usize) -> Result<(), RunnerError> {
    let object = value
        .as_object()
        .ok_or_else(|| RunnerError::MalformedJsonl {
            line,
            message: "top-level JSON value must be an object".to_owned(),
        })?;
    let event_type =
        object
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| RunnerError::MalformedJsonl {
                line,
                message: "top-level `type` must be a string".to_owned(),
            })?;

    let allowed: BTreeSet<&str> = match event_type {
        "thread.started" => [
            "type",
            "thread_id",
            "model",
            "model_provider_id",
            "reasoning_effort",
            "service_tier",
        ]
        .into_iter()
        .collect(),
        "turn.started" => ["type"].into_iter().collect(),
        "turn.completed" => ["type", "usage"].into_iter().collect(),
        "turn.failed" => ["type", "error"].into_iter().collect(),
        "item.started" | "item.updated" | "item.completed" => {
            ["type", "item"].into_iter().collect()
        }
        "error" => ["type", "message", "will_retry"].into_iter().collect(),
        unknown => {
            return Err(RunnerError::UnknownThreadEvent {
                line,
                event_type: unknown.to_owned(),
            });
        }
    };

    if let Some(field) = object
        .keys()
        .find(|field| !allowed.contains(field.as_str()))
    {
        return Err(RunnerError::UnknownThreadEventField {
            line,
            field: field.clone(),
        });
    }
    Ok(())
}
