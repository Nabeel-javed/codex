//! Deterministic, evaluator-only scoring for AuditBase V3 benchmarks.
//!
//! Ground truth and adjudication artifacts belong in this crate's trusted
//! evaluator lane. They must never be made available to `auditbase-agent` or
//! copied into an audit guest.

mod adjudication;
mod canonical;
mod ingest;
mod manifest;
mod matching;
mod scoring;

pub use adjudication::*;
pub use canonical::*;
pub use ingest::*;
pub use manifest::*;
pub use matching::*;
pub use scoring::*;
