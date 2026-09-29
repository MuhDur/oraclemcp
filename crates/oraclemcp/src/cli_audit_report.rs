//! `audit report` command-line arguments, isolated from the primary CLI table.

use clap::{Args, ValueEnum};
use std::path::PathBuf;

/// The human-facing serialization selected by `audit report`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum AuditReportFormat {
    Markdown,
    Html,
}

impl AuditReportFormat {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Markdown => "markdown",
            Self::Html => "html",
        }
    }
}

/// Verify an audit chain and export a deterministic redacted session report.
#[derive(Args, Debug)]
pub(crate) struct AuditReportArgs {
    /// Path to the append-only JSONL audit log.
    pub(crate) file: PathBuf,
    /// Human-facing report serialization.
    #[arg(long, value_enum, default_value_t = AuditReportFormat::Markdown)]
    pub(crate) format: AuditReportFormat,
    /// Write the report to this file instead of standard output.
    #[arg(long)]
    pub(crate) out: Option<PathBuf>,
    /// Override the active key id for a legacy env-only key.
    #[arg(long)]
    pub(crate) key_id: Option<String>,
}
