//! AudiToad's finite baseline scanner.
//!
//! A validated baseline defines the questions and evidence policy. A [`Snapshot`] supplies
//! immutable input; [`scan`] executes the selected profile and returns typed terminal records.
//! Use [`scan_to_file`] when a report and publication receipt are required.
//!
//! ```no_run
//! use auditoad::{ScanRequest, Snapshot, ValidatedBaseline, scan, schema::Limits};
//! use std::path::Path;
//!
//! # fn main() -> Result<(), auditoad::ScanError> {
//! let baseline = ValidatedBaseline::from_file(Path::new("examples/disk-encryption/baseline.json"))?;
//! let limits = Limits::default();
//! let snapshot = Snapshot::inventory(include_bytes!("../examples/disk-encryption/inventory.json"), &limits)?;
//! let result = scan(ScanRequest {
//!     baseline: &baseline,
//!     profile: "inventory",
//!     source_alias: "inventory",
//!     snapshot: &snapshot,
//!     limits,
//!     experimental: false,
//!     mock: None,
//! })?;
//! println!("{:?}", result.report.outcome);
//! # Ok(())
//! # }
//! ```
//!
//! Model questions are answered by the backends an operator configures in an [`Evaluators`]
//! file; live calls require explicit opt-in and an experimental baseline.
//! An experimental observation remains unevaluated even when its suggested decision is clear.
pub mod audit;
mod baseline;
mod bundle;
mod collection;
mod command_line;
mod evaluator;
mod evaluators;
mod json;
mod markdown;
mod replay;
mod scan;
pub mod schema;
mod scoped;
mod score;
mod source;
mod syntax;
mod tlaplus;

pub use baseline::ValidatedBaseline;
pub use evaluator::MockModel;
pub use evaluators::{Backend, Capability, Evaluators};
pub use scan::{
    Preparation, PublishedScan, ScanRequest, ScanResult, scan, scan_to_file,
    scan_to_file_with_evaluators, scan_to_file_with_preparation, scan_to_file_with_progress,
};
pub use score::{compare_scores, score, score_files};
pub use source::{Snapshot, sha256};

/// Invalid inputs (3) and unresolved execution/publication (2) remain distinct.
#[derive(Debug, Clone)]
pub struct ScanError {
    pub exit_code: u8,
    pub message: String,
}

impl ScanError {
    pub(crate) fn invalid(message: impl Into<String>) -> Self {
        Self {
            exit_code: 3,
            message: message.into(),
        }
    }
    /// Construct an unresolved execution or publication error with exit code 2.
    pub fn unresolved(message: impl Into<String>) -> Self {
        Self {
            exit_code: 2,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for ScanError {}

/// Read a local mock script under the same bounded no-link input policy.
pub fn load_mock(path: &std::path::Path) -> Result<MockModel, ScanError> {
    let mut mock = MockModel::from_bytes(
        &source::read_bounded(path, 2 * 1024 * 1024).map_err(ScanError::invalid)?,
    )?;
    mock.input_path = Some(source::unlinked_path(path).map_err(ScanError::invalid)?);
    Ok(mock)
}

#[cfg(test)]
extern crate self as auditoad;
#[cfg(test)]
#[path = "../tests/support/mod.rs"]
mod test_support;
