//! Deterministic, export-only rendering of a verified audit session.
//!
//! The command layer deliberately supplies records only after
//! `oraclemcp_audit::verify_reader_with` has accepted them.  This module never
//! opens a ledger or tries to reimplement hash-chain verification: its sole
//! job is to turn that verified projection into a safe human-readable report.

use std::io::BufRead;

use clap::ValueEnum;
use oraclemcp_audit::{
    AuditDecision, AuditFailureCause, AuditOutcome, AuditRecord, JsonlError, REDACTED_SQL_PREVIEW,
    SigningKey, VerifyOutcome, verify_reader_with,
};

/// The human-facing serialization selected by `audit report`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum AuditReportFormat {
    /// CommonMark suitable for an incident or change-review attachment.
    Markdown,
    /// A standalone document with only inline CSS.
    Html,
}

impl AuditReportFormat {
    /// Stable machine-facing name used in the JSON command envelope.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Markdown => "markdown",
            Self::Html => "html",
        }
    }
}

/// Verification information rendered in the header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum AuditReportVerdict {
    /// The complete chain verified with the configured keyring.
    Verified { records: usize },
    /// The first record that failed the shared verifier.
    Broken {
        seq: u64,
        index: usize,
        reason: String,
    },
}

impl AuditReportVerdict {
    /// Stable status name for the command's JSON envelope.
    pub(crate) const fn status(&self) -> &'static str {
        match self {
            Self::Verified { .. } => "verified",
            Self::Broken { .. } => "broken",
        }
    }
}

/// Inputs whose provenance has already been established by the command layer.
pub(crate) struct VerifiedAuditReport<'a> {
    /// Digest of the exact no-follow descriptor that was verified.
    pub(crate) file_digest: &'a str,
    /// Records observed by `verify_reader_with`, in authoritative sequence order.
    pub(crate) records: &'a [AuditRecord],
    /// Complete shared-verifier verdict.
    pub(crate) verdict: AuditReportVerdict,
}

/// A rendered report plus the verifier result that determines the caller's
/// exit code and machine-readable envelope.
pub(crate) struct RenderedAuditReport {
    pub(crate) content: String,
    pub(crate) verdict: AuditReportVerdict,
}

/// Verify and render a ledger through the audit crate's canonical streaming
/// verifier. This is deliberately the only audit-report ingestion path.
///
/// `verify_reader_with` invokes the observer only after an entry passes every
/// chain and MAC check. A later broken record invalidates the session report,
/// so the verified prefix is discarded before rendering the refusal banner.
pub(crate) fn verify_and_render<R: BufRead>(
    reader: R,
    keys: &[SigningKey],
    file_digest: &str,
    format: AuditReportFormat,
) -> Result<RenderedAuditReport, JsonlError> {
    let mut records = Vec::new();
    let verdict = match verify_reader_with(reader, keys, |record| records.push(record.clone()))? {
        VerifyOutcome::Ok { records: count } => AuditReportVerdict::Verified { records: count },
        VerifyOutcome::Broken { seq, index, reason } => {
            records.clear();
            AuditReportVerdict::Broken {
                seq,
                index,
                reason: reason.to_string(),
            }
        }
        _ => {
            records.clear();
            AuditReportVerdict::Broken {
                seq: 0,
                index: 0,
                reason: "unrecognized verification outcome".to_owned(),
            }
        }
    };
    let content = render(
        &VerifiedAuditReport {
            file_digest,
            records: &records,
            verdict: verdict.clone(),
        },
        format,
    );
    Ok(RenderedAuditReport { content, verdict })
}

/// Render a report without consulting the filesystem, clock, or database.
///
/// A broken chain intentionally produces only a refusal banner and safe
/// verification metadata.  In particular, the verified prefix is not emitted:
/// an operator never mistakes a partial chain for a complete session report.
pub(crate) fn render(report: &VerifiedAuditReport<'_>, format: AuditReportFormat) -> String {
    match format {
        AuditReportFormat::Markdown => render_markdown(report),
        AuditReportFormat::Html => render_html(report),
    }
}

fn render_markdown(report: &VerifiedAuditReport<'_>) -> String {
    let mut out = String::from("# Oracle MCP audit session report\n\n");
    match &report.verdict {
        AuditReportVerdict::Verified { records } => {
            out.push_str("**Verification:** VERIFIED\n\n");
            render_markdown_header(&mut out, report.file_digest, report.records, *records);
            render_markdown_timeline(&mut out, report.records);
            render_markdown_sections(&mut out, report.records);
        }
        AuditReportVerdict::Broken { seq, index, reason } => {
            out.push_str(&format!("## CHAIN BROKEN at seq {seq}\n\n"));
            out.push_str("**Verification:** BROKEN — no session timeline was exported.\n\n");
            out.push_str("| Field | Value |\n| --- | --- |\n");
            markdown_row(&mut out, "File digest", report.file_digest);
            markdown_row(&mut out, "Broken record index", &index.to_string());
            markdown_row(&mut out, "Reason", reason);
        }
    }
    out
}

fn render_markdown_header(out: &mut String, digest: &str, records: &[AuditRecord], count: usize) {
    out.push_str("## Verification\n\n| Field | Value |\n| --- | --- |\n");
    markdown_row(out, "File digest", digest);
    markdown_row(out, "Records", &count.to_string());
    markdown_row(out, "Record range", &record_range(records));
    markdown_row(out, "Time range", &time_range(records));
    out.push('\n');
}

fn render_markdown_timeline(out: &mut String, records: &[AuditRecord]) {
    out.push_str("## Timeline\n\n");
    out.push_str(
        "| Seq | Time | Subject | Tool | Level | Decision | Outcome | SQL | Rows | Failure |\n",
    );
    out.push_str("| --- | --- | --- | --- | --- | --- | --- | --- | --- |\n");
    for record in records {
        out.push('|');
        for value in [
            record.seq.to_string(),
            record.timestamp.clone(),
            record.subject.legacy_agent_identity(),
            record.tool.clone(),
            record.danger_level.clone(),
            decision_name(record.decision).to_owned(),
            outcome_name(record.outcome).to_owned(),
            redacted_sql(record),
            record
                .rows_affected
                .map_or_else(|| "-".to_owned(), |rows| rows.to_string()),
            failure_name(record.failure.as_ref()),
        ] {
            out.push(' ');
            out.push_str(&markdown_cell(&value));
            out.push_str(" |");
        }
        out.push('\n');
    }
    out.push('\n');
}

fn render_markdown_sections(out: &mut String, records: &[AuditRecord]) {
    render_markdown_tool_section(
        out,
        "Level changes and elevation windows",
        records,
        |record| matches!(record_kind(record), ReportRecordKind::LevelChange),
    );
    render_markdown_tool_section(out, "Grants and tokens", records, |record| {
        matches!(record_kind(record), ReportRecordKind::GrantOrToken)
    });

    out.push_str("## Refusals\n\n| Class | Count |\n| --- | --- |\n");
    let refusals = refusal_counts(records);
    if refusals.is_empty() {
        out.push_str("| none | 0 |\n");
    } else {
        for (class, count) in refusals {
            markdown_row(out, &class, &count.to_string());
        }
    }
    out.push('\n');
    out.push_str("## Totals\n\n| Metric | Count |\n| --- | --- |\n");
    markdown_row(out, "Records", &records.len().to_string());
    markdown_row(
        out,
        "Refusals",
        &records
            .iter()
            .filter(|record| is_refusal(record.decision))
            .count()
            .to_string(),
    );
    markdown_row(
        out,
        "Failed outcomes",
        &records
            .iter()
            .filter(|record| matches!(record.outcome, AuditOutcome::Failed))
            .count()
            .to_string(),
    );
}

fn render_markdown_tool_section(
    out: &mut String,
    title: &str,
    records: &[AuditRecord],
    predicate: impl Fn(&AuditRecord) -> bool,
) {
    out.push_str("## ");
    out.push_str(title);
    out.push_str("\n\n| Seq | Tool | Decision | Outcome |\n| --- | --- | --- | --- |\n");
    let mut rendered = false;
    for record in records.iter().filter(|record| predicate(record)) {
        rendered = true;
        out.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            record.seq,
            markdown_cell(&record.tool),
            decision_name(record.decision),
            outcome_name(record.outcome),
        ));
    }
    if !rendered {
        out.push_str("| - | none | - | - |\n");
    }
    out.push('\n');
}

fn render_html(report: &VerifiedAuditReport<'_>) -> String {
    let mut out = String::from(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<title>Oracle MCP audit session report</title>\n<style>body{font-family:system-ui,sans-serif;margin:2rem;color:#172033}table{border-collapse:collapse;width:100%;margin:1rem 0}th,td{border:1px solid #bbc3d0;padding:.45rem;text-align:left;vertical-align:top}th{background:#eef2f7}.ok{color:#176b3a;font-weight:700}.broken{color:#a40000;font-weight:700}code{overflow-wrap:anywhere}</style>\n</head>\n<body>\n<h1>Oracle MCP audit session report</h1>\n",
    );
    match &report.verdict {
        AuditReportVerdict::Verified { records } => {
            out.push_str("<p class=\"ok\">Verification: VERIFIED</p>\n");
            html_header(&mut out, report.file_digest, report.records, *records);
            html_timeline(&mut out, report.records);
            html_sections(&mut out, report.records);
        }
        AuditReportVerdict::Broken { seq, index, reason } => {
            out.push_str(&format!(
                "<h2 class=\"broken\">CHAIN BROKEN at seq {seq}</h2>\n"
            ));
            out.push_str("<p class=\"broken\">Verification: BROKEN — no session timeline was exported.</p>\n");
            out.push_str("<table><thead><tr><th>Field</th><th>Value</th></tr></thead><tbody>");
            html_pair(&mut out, "File digest", report.file_digest);
            html_pair(&mut out, "Broken record index", &index.to_string());
            html_pair(&mut out, "Reason", reason);
            out.push_str("</tbody></table>\n");
        }
    }
    out.push_str("</body>\n</html>\n");
    out
}

fn html_header(out: &mut String, digest: &str, records: &[AuditRecord], count: usize) {
    out.push_str(
        "<h2>Verification</h2><table><thead><tr><th>Field</th><th>Value</th></tr></thead><tbody>",
    );
    html_pair(out, "File digest", digest);
    html_pair(out, "Records", &count.to_string());
    html_pair(out, "Record range", &record_range(records));
    html_pair(out, "Time range", &time_range(records));
    out.push_str("</tbody></table>\n");
}

fn html_timeline(out: &mut String, records: &[AuditRecord]) {
    out.push_str("<h2>Timeline</h2><table><thead><tr><th>Seq</th><th>Time</th><th>Subject</th><th>Tool</th><th>Level</th><th>Decision</th><th>Outcome</th><th>SQL</th><th>Rows</th><th>Failure</th></tr></thead><tbody>");
    for record in records {
        out.push_str("<tr>");
        for value in [
            record.seq.to_string(),
            record.timestamp.clone(),
            record.subject.legacy_agent_identity(),
            record.tool.clone(),
            record.danger_level.clone(),
            decision_name(record.decision).to_owned(),
            outcome_name(record.outcome).to_owned(),
            redacted_sql(record),
            record
                .rows_affected
                .map_or_else(|| "-".to_owned(), |rows| rows.to_string()),
            failure_name(record.failure.as_ref()),
        ] {
            out.push_str("<td>");
            out.push_str(&html_escape(&value));
            out.push_str("</td>");
        }
        out.push_str("</tr>");
    }
    out.push_str("</tbody></table>\n");
}

fn html_sections(out: &mut String, records: &[AuditRecord]) {
    html_tool_section(
        out,
        "Level changes and elevation windows",
        records,
        |record| matches!(record_kind(record), ReportRecordKind::LevelChange),
    );
    html_tool_section(out, "Grants and tokens", records, |record| {
        matches!(record_kind(record), ReportRecordKind::GrantOrToken)
    });
    out.push_str(
        "<h2>Refusals</h2><table><thead><tr><th>Class</th><th>Count</th></tr></thead><tbody>",
    );
    let refusals = refusal_counts(records);
    if refusals.is_empty() {
        html_pair(out, "none", "0");
    } else {
        for (class, count) in refusals {
            html_pair(out, &class, &count.to_string());
        }
    }
    out.push_str("</tbody></table>\n<h2>Totals</h2><table><thead><tr><th>Metric</th><th>Count</th></tr></thead><tbody>");
    html_pair(out, "Records", &records.len().to_string());
    html_pair(
        out,
        "Refusals",
        &records
            .iter()
            .filter(|record| is_refusal(record.decision))
            .count()
            .to_string(),
    );
    html_pair(
        out,
        "Failed outcomes",
        &records
            .iter()
            .filter(|record| matches!(record.outcome, AuditOutcome::Failed))
            .count()
            .to_string(),
    );
    out.push_str("</tbody></table>\n");
}

fn html_tool_section(
    out: &mut String,
    title: &str,
    records: &[AuditRecord],
    predicate: impl Fn(&AuditRecord) -> bool,
) {
    out.push_str("<h2>");
    out.push_str(&html_escape(title));
    out.push_str("</h2><table><thead><tr><th>Seq</th><th>Tool</th><th>Decision</th><th>Outcome</th></tr></thead><tbody>");
    let mut rendered = false;
    for record in records.iter().filter(|record| predicate(record)) {
        rendered = true;
        out.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            record.seq,
            html_escape(&record.tool),
            decision_name(record.decision),
            outcome_name(record.outcome)
        ));
    }
    if !rendered {
        out.push_str("<tr><td>-</td><td>none</td><td>-</td><td>-</td></tr>");
    }
    out.push_str("</tbody></table>\n");
}

fn markdown_row(out: &mut String, key: &str, value: &str) {
    out.push_str("| ");
    out.push_str(&markdown_cell(key));
    out.push_str(" | ");
    out.push_str(&markdown_cell(value));
    out.push_str(" |\n");
}

fn html_pair(out: &mut String, key: &str, value: &str) {
    out.push_str("<tr><td>");
    out.push_str(&html_escape(key));
    out.push_str("</td><td>");
    out.push_str(&html_escape(value));
    out.push_str("</td></tr>");
}

fn record_range(records: &[AuditRecord]) -> String {
    match (records.first(), records.last()) {
        (Some(first), Some(last)) => format!("{}..{}", first.seq, last.seq),
        _ => "empty".to_owned(),
    }
}

fn time_range(records: &[AuditRecord]) -> String {
    match (records.first(), records.last()) {
        (Some(first), Some(last)) => format!("{}..{}", first.timestamp, last.timestamp),
        _ => "empty".to_owned(),
    }
}

fn decision_name(decision: AuditDecision) -> &'static str {
    match decision {
        AuditDecision::Allowed => "ALLOWED",
        AuditDecision::StepUpRequired => "STEP_UP_REQUIRED",
        AuditDecision::Blocked => "BLOCKED",
        _ => "UNKNOWN",
    }
}

fn outcome_name(outcome: AuditOutcome) -> &'static str {
    match outcome {
        AuditOutcome::Pending => "PENDING",
        AuditOutcome::Succeeded => "SUCCEEDED",
        AuditOutcome::Failed => "FAILED",
        AuditOutcome::RolledBack => "ROLLED_BACK",
        AuditOutcome::HeldUncommitted => "HELD_UNCOMMITTED",
        AuditOutcome::DiscardedUncommitted => "DISCARDED_UNCOMMITTED",
        AuditOutcome::CommitInDoubt => "COMMIT_IN_DOUBT",
        AuditOutcome::UnknownDiscarded => "UNKNOWN_DISCARDED",
        _ => "UNKNOWN",
    }
}

fn failure_name(failure: Option<&AuditFailureCause>) -> String {
    let Some(failure) = failure else {
        return "-".to_owned();
    };
    let mut text = failure.error_class().to_owned();
    if let Some(reason) = failure.reason_category() {
        text.push(':');
        text.push_str(reason);
    }
    if let Some(code) = failure.ora_code() {
        text.push_str(&format!(":ORA-{code:05}"));
    }
    text
}

/// Current records use a fixed marker, but old signed logs can contain raw SQL.
/// Never reproduce either value: the report has one unconditional marker.
fn redacted_sql(record: &AuditRecord) -> String {
    format!("{}; {REDACTED_SQL_PREVIEW}", record.sql_sha256)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReportRecordKind {
    Timeline,
    LevelChange,
    GrantOrToken,
}

/// One extension seam for later record-specific sections.  Unknown tool names
/// remain visible in the timeline and do not silently disappear.
fn record_kind(record: &AuditRecord) -> ReportRecordKind {
    match record.tool.as_str() {
        "oracle_set_session_level" | "enable_writes" => ReportRecordKind::LevelChange,
        tool if tool.contains("grant") || tool.contains("token") => ReportRecordKind::GrantOrToken,
        _ => ReportRecordKind::Timeline,
    }
}

fn is_refusal(decision: AuditDecision) -> bool {
    matches!(
        decision,
        AuditDecision::Blocked | AuditDecision::StepUpRequired
    )
}

fn refusal_counts(records: &[AuditRecord]) -> Vec<(String, usize)> {
    let mut counts = std::collections::BTreeMap::new();
    for record in records.iter().filter(|record| is_refusal(record.decision)) {
        let class = record.failure.as_ref().map_or_else(
            || decision_name(record.decision).to_owned(),
            |failure| failure_name(Some(failure)),
        );
        *counts.entry(class).or_insert(0) += 1;
    }
    counts.into_iter().collect()
}

fn markdown_cell(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace('\n', "<br>")
        .replace('\r', "")
}

fn html_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '\"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use oraclemcp_audit::{
        AuditEntryDraft, AuditSubject, GENESIS_HASH, SigningKey, sha256_hex, verify_reader_with,
    };

    const TEST_KEY: &str = "audit-report-test-key-material-0123456789";
    const CANARY_SQL: &str = "select audit_report_unredacted_canary from dual";

    fn key() -> SigningKey {
        SigningKey::new("audit-report-fixture", TEST_KEY.as_bytes()).expect("valid fixture key")
    }

    fn records(subject: AuditSubject) -> Vec<AuditRecord> {
        let key = key();
        let drafts = [
            AuditEntryDraft {
                subject: subject.clone(),
                db_evidence: None,
                cancel: None,
                result_masking: None,
                tool: "oracle_query".to_owned(),
                sql: CANARY_SQL.to_owned(),
                danger_level: "READ_ONLY".to_owned(),
                decision: AuditDecision::Allowed,
                rows_affected: Some(1),
                outcome: AuditOutcome::Succeeded,
            },
            AuditEntryDraft {
                subject: subject.clone(),
                db_evidence: None,
                cancel: None,
                result_masking: None,
                tool: "oracle_set_session_level".to_owned(),
                sql: "alter session set current_schema = APP".to_owned(),
                danger_level: "DDL".to_owned(),
                decision: AuditDecision::Allowed,
                rows_affected: None,
                outcome: AuditOutcome::Succeeded,
            },
            AuditEntryDraft {
                subject,
                db_evidence: None,
                cancel: None,
                result_masking: None,
                tool: "oracle_execute".to_owned(),
                sql: "delete from audit_report_canary".to_owned(),
                danger_level: "WRITE".to_owned(),
                decision: AuditDecision::Blocked,
                rows_affected: None,
                outcome: AuditOutcome::Failed,
            },
        ];
        let mut prev = GENESIS_HASH.to_owned();
        drafts
            .iter()
            .enumerate()
            .map(|(index, draft)| {
                let record = AuditRecord::chained_signed(
                    draft,
                    (index + 1) as u64,
                    &prev,
                    format!("2026-09-29T00:00:0{}Z", index + 1),
                    &key,
                );
                prev = record.entry_hash.clone();
                record
            })
            .collect()
    }

    fn jsonl(records: &[AuditRecord]) -> String {
        records
            .iter()
            .map(|record| serde_json::to_string(record).expect("fixture record serializes"))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n"
    }

    fn report_from_records(
        records: &[AuditRecord],
        format: AuditReportFormat,
    ) -> RenderedAuditReport {
        let input = jsonl(records);
        verify_and_render(
            Cursor::new(input.as_bytes()),
            &[key()],
            &sha256_hex(input.as_bytes()),
            format,
        )
        .expect("fixture verifies")
    }

    #[test]
    fn html_escapes_all_values() {
        let report = report_from_records(
            &records(AuditSubject::new("fixture", "<script>alert('x')</script>")),
            AuditReportFormat::Html,
        );
        assert!(
            report
                .content
                .contains("&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;")
        );
        assert!(!report.content.contains("<script>alert('x')</script>"));
    }

    #[test]
    fn report_never_contains_unredacted_sql() {
        let mut legacy_preview_record = records(AuditSubject::new("fixture", "session"))
            .into_iter()
            .next()
            .expect("fixture contains a record");
        // Historical signed schemas allowed a truncated raw preview. Rendering
        // must not rely on that field even when a caller already established
        // the chain's authenticity.
        legacy_preview_record.sql_preview = CANARY_SQL.to_owned();
        for format in [AuditReportFormat::Markdown, AuditReportFormat::Html] {
            let content = render(
                &VerifiedAuditReport {
                    file_digest: "sha256:fixture",
                    records: std::slice::from_ref(&legacy_preview_record),
                    verdict: AuditReportVerdict::Verified { records: 1 },
                },
                format,
            );
            assert!(!content.contains(CANARY_SQL), "{format:?}");
            assert!(content.contains("sql text redacted"), "{format:?}");
        }
    }

    #[test]
    fn report_uses_same_verifier_as_audit_verify() {
        let input = jsonl(&records(AuditSubject::new("fixture", "session")));
        let expected = verify_reader_with(Cursor::new(input.as_bytes()), &[key()], |_| {})
            .expect("shared verifier accepts fixture");
        let report = verify_and_render(
            Cursor::new(input.as_bytes()),
            &[key()],
            &sha256_hex(input.as_bytes()),
            AuditReportFormat::Markdown,
        )
        .expect("report verifier accepts fixture");
        assert_eq!(expected, VerifyOutcome::Ok { records: 3 });
        assert_eq!(report.verdict, AuditReportVerdict::Verified { records: 3 });

        let tampered = input.replacen("oracle_query", "oracle_query_tampered", 1);
        let expected = verify_reader_with(Cursor::new(tampered.as_bytes()), &[key()], |_| {})
            .expect("shared verifier returns broken verdict");
        let report = verify_and_render(
            Cursor::new(tampered.as_bytes()),
            &[key()],
            &sha256_hex(tampered.as_bytes()),
            AuditReportFormat::Markdown,
        )
        .expect("report verifier returns broken verdict");
        assert!(matches!(expected, VerifyOutcome::Broken { seq: 1, .. }));
        assert!(matches!(
            report.verdict,
            AuditReportVerdict::Broken { seq: 1, .. }
        ));
    }

    #[test]
    fn broken_chain_report_banner_and_exit_2() {
        let input = jsonl(&records(AuditSubject::new("fixture", "session")));
        let tampered = input.replacen("oracle_query", "oracle_query_tampered", 1);
        let report = verify_and_render(
            Cursor::new(tampered.as_bytes()),
            &[key()],
            &sha256_hex(tampered.as_bytes()),
            AuditReportFormat::Markdown,
        )
        .expect("tampering is a verifier verdict, not an I/O error");
        assert!(matches!(
            report.verdict,
            AuditReportVerdict::Broken { seq: 1, .. }
        ));
        assert!(report.content.contains("CHAIN BROKEN at seq 1"));
        assert!(!report.content.contains("oracle_execute"));
    }
}
