use thiserror::Error;

/// Stable failures produced at the trusted runner boundary.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum RunnerError {
    #[error("{kind} exceeds its byte limit: {actual} > {maximum}")]
    ByteLimit {
        kind: &'static str,
        actual: usize,
        maximum: usize,
    },
    #[error("JSONL event limit exceeded: {actual} > {maximum}")]
    EventLimit { actual: usize, maximum: usize },
    #[error("JSONL line {line} is empty")]
    EmptyJsonlLine { line: usize },
    #[error("JSONL line {line} is not valid UTF-8")]
    InvalidJsonlUtf8 { line: usize },
    #[error("JSONL line {line} is malformed: {message}")]
    MalformedJsonl { line: usize, message: String },
    #[error("JSONL line {line} has unknown event type `{event_type}`")]
    UnknownThreadEvent { line: usize, event_type: String },
    #[error("JSONL line {line} contains unknown top-level field `{field}`")]
    UnknownThreadEventField { line: usize, field: String },
    #[error("provenance is invalid at `{field}`: {message}")]
    InvalidProvenance { field: String, message: String },
    #[error(
        "requested/effective runtime mismatch at `{field}`: requested `{requested}`, effective `{effective}`"
    )]
    RuntimeMismatch {
        field: String,
        requested: String,
        effective: String,
    },
    #[error("model output is malformed: {message}")]
    MalformedModelOutput { message: String },
    #[error("model output is invalid at `{field}`: {message}")]
    InvalidModelOutput { field: String, message: String },
    #[error("event adaptation failed: {message}")]
    Adapter { message: String },
    #[error("event replay conflict: {message}")]
    ReplayConflict { message: String },
    #[error("checkpoint update failed: {message}")]
    Checkpoint { message: String },
}

impl RunnerError {
    pub(crate) fn provenance(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self::InvalidProvenance {
            field: field.into(),
            message: message.into(),
        }
    }

    pub(crate) fn model_output(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self::InvalidModelOutput {
            field: field.into(),
            message: message.into(),
        }
    }
}
