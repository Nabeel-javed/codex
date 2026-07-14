//! Versioned product boundary between the AuditBase website and V3 workers.
//!
//! This crate contains transport-neutral data types and validation only. It
//! intentionally contains no audit prompts, orchestration, persistence, or
//! model credentials.

mod config;
mod event;
mod finding;
mod request;
mod result;
mod validation;

pub use config::*;
pub use event::*;
pub use finding::*;
pub use request::*;
pub use result::*;
pub use validation::Validate;
pub use validation::ValidationError;

use schemars::schema::RootSchema;
use schemars::schema_for;

/// Generates every committed public JSON Schema from the Rust source of truth.
pub fn generated_schemas() -> [(&'static str, RootSchema); 7] {
    [
        ("audit-request.v1.schema.json", schema_for!(AuditRequest)),
        ("audit-accepted.v1.schema.json", schema_for!(AuditAccepted)),
        ("audit-snapshot.v1.schema.json", schema_for!(AuditSnapshot)),
        ("api-error.v1.schema.json", schema_for!(ApiErrorResponse)),
        ("audit-event.v1.schema.json", schema_for!(AuditEvent)),
        ("audit-result.v1.schema.json", schema_for!(AuditResult)),
        ("audit-config.v1.schema.json", schema_for!(AuditConfig)),
    ]
}
