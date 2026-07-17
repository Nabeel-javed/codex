//! Deterministic, offline packaging for AuditBase benchmark inputs.
//!
//! This crate deliberately contains no scoring, model calls, agent execution,
//! Git operations, compiler invocation, or third-party benchmark source.

mod model;
mod package;
mod validation;

pub use model::*;
pub use package::PackageOptions;
pub use package::PackageReceipt;
pub use package::load_catalog;
pub use package::package_case;
pub use package::verify_package;
pub use validation::BenchmarkError;
