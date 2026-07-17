//! Deterministic, fail-closed boundary around Codex audit runs.
//!
//! It parses bounded Codex JSONL, normalizes public events, validates
//! model-authored audit content, and constructs public results from trusted
//! runner state. Host execution is available only through the explicit
//! trusted-local developer lane; production remains fail-closed.

pub mod accumulator;
pub mod adapter;
pub mod checkpoint;
pub mod child_protocol;
pub mod final_output;
pub mod provenance;
pub mod raw_jsonl;
pub mod supervisor;
pub mod trusted_local;

mod error;

pub use error::RunnerError;
