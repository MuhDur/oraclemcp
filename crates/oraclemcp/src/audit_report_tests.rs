use super::*;

#[test]
fn audit_report_command_parses() {
    let audit = Cli::try_parse_from([
        "oraclemcp",
        "audit",
        "report",
        "audit.jsonl",
        "--format",
        "html",
        "--out",
        "report.html",
    ])
    .expect("parse audit report");
    assert!(matches!(
        audit.command,
        Some(Command::Audit { command: AuditCommand::Report(ref args) })
            if args.file == Path::new("audit.jsonl")
                && args.format == cli_audit_report::AuditReportFormat::Html
                && args.out.as_deref() == Some(Path::new("report.html"))
                && args.key_id.is_none()
    ));
}
