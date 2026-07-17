//! Versioned product boundary between the AuditBase website and V3 workers.
//!
//! This crate contains transport-neutral data types and validation only. It
//! intentionally contains no audit prompts, orchestration, persistence, or
//! model credentials.

mod config;
mod consistency;
mod event;
mod event_stream;
mod finding;
mod request;
mod result;
mod validation;

pub use config::*;
pub use consistency::*;
pub use event::*;
pub use event_stream::*;
pub use finding::*;
pub use request::*;
pub use result::*;
pub use validation::JS_MAX_SAFE_INTEGER;
pub use validation::Validate;
pub use validation::ValidateWithLimits;
pub use validation::ValidationError;

use schemars::schema::RootSchema;
use schemars::schema::Schema;
use schemars::schema_for;

/// Generates every committed versioned JSON Schema from the Rust source of truth.
pub fn generated_schemas() -> [(&'static str, RootSchema); 7] {
    [
        ("audit-request.v1.schema.json", schema_for!(AuditRequest)),
        ("audit-accepted.v1.schema.json", schema_for!(AuditAccepted)),
        ("audit-snapshot.v1.schema.json", schema_for!(AuditSnapshot)),
        ("api-error.v1.schema.json", schema_for!(ApiErrorResponse)),
        ("audit-event.v1.schema.json", generated_audit_event_schema()),
        ("audit-result.v1.schema.json", schema_for!(AuditResult)),
        ("audit-config.v1.schema.json", schema_for!(AuditConfig)),
    ]
}

fn generated_audit_event_schema() -> RootSchema {
    let mut schema = schema_for!(AuditEvent);
    if let Some(object) = schema.schema.object.as_mut() {
        // `AuditEventPayload` is flattened into the top-level object. Schemars
        // puts `type` and `data` only in `oneOf`; Draft-07 validators then reject
        // them against the parent `additionalProperties: false`. Declaring the
        // two keys at the parent keeps unknown-field rejection while `oneOf`
        // continues to enforce the exact type/data pairing for every variant.
        object
            .properties
            .insert("type".to_string(), Schema::Bool(true));
        object
            .properties
            .insert("data".to_string(), Schema::Bool(true));
        object.required.insert("type".to_string());
        object.required.insert("data".to_string());
    }
    schema
}
