//! The `refusal-corpus export` command must reach the tested, redacting export
//! path without becoming a second way to ship a best-effort or non-redacted
//! dataset, or to clobber the live corpus state. The reproducibility, dedup, and
//! no-secret guarantees are proven in the `refusal_corpus` unit tests; this
//! exercises the CLI wiring and the two refusal boundaries end to end.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn export(corpus: &Path, out: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_oraclemcp"))
        .args([
            "--json",
            "refusal-corpus",
            "export",
            "--corpus",
            corpus.to_str().expect("corpus path is UTF-8"),
            "--out",
            out.to_str().expect("out path is UTF-8"),
        ])
        .output()
        .expect("run refusal-corpus export")
}

#[test]
fn exports_an_empty_corpus_as_zero_records() {
    let temp = tempfile::tempdir().expect("temporary fixture directory");
    // A corpus that has never been written yet exports cleanly as an empty
    // dataset rather than erroring.
    let corpus = temp.path().join("state/refusals.jsonl");
    let out = temp.path().join("export/corpus.jsonl");

    let output = export(&corpus, &out);
    assert!(
        output.status.success(),
        "export failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("export emits JSON");
    assert_eq!(payload["kind"], "oraclemcp_refusal_corpus_export");
    assert_eq!(payload["records"], 0);
    assert!(out.exists(), "export writes the destination file");
    assert!(
        fs::read_to_string(&out).expect("read export").is_empty(),
        "an empty corpus exports an empty dataset"
    );
}

#[test]
fn refuses_to_export_onto_the_source_corpus_path() {
    let temp = tempfile::tempdir().expect("temporary fixture directory");
    let corpus = temp.path().join("refusals.jsonl");

    // --out aliases --corpus: the exporter must refuse rather than risk
    // clobbering the live append-only state with its own output.
    let output = export(&corpus, &corpus);
    assert_eq!(output.status.code(), Some(2));
    let error: serde_json::Value =
        serde_json::from_slice(&output.stderr).expect("refusal is structured JSON");
    assert_eq!(error["code"], "ORACLEMCP_REFUSAL_CORPUS_EXPORT_REFUSED");
}

#[test]
fn refuses_a_tampered_corpus_instead_of_shipping_best_effort() {
    let temp = tempfile::tempdir().expect("temporary fixture directory");
    let corpus = temp.path().join("refusals.jsonl");
    // A record whose "redacted" SQL still carries raw identifiers and a literal
    // must be rejected at the export boundary, not shipped.
    let tampered = r#"{"id":"sha256:tampered","refused_sql_redacted":"SELECT * FROM acme_corp.customers WHERE token = 'hunter2'","refusal_class":"DynamicSql","why":"dynamic SQL"}"#;
    fs::write(&corpus, format!("{tampered}\n")).expect("write synthetic tampered corpus");
    let out = temp.path().join("export.jsonl");

    let output = export(&corpus, &out);
    assert_eq!(output.status.code(), Some(2));
    let error: serde_json::Value =
        serde_json::from_slice(&output.stderr).expect("refusal is structured JSON");
    assert_eq!(error["code"], "ORACLEMCP_REFUSAL_CORPUS_EXPORT_REFUSED");
    assert!(
        !out.exists(),
        "a tampered corpus must not produce any dataset"
    );
}

#[test]
fn refuses_a_differently_spelled_alias_of_the_source() {
    let temp = tempfile::tempdir().expect("temporary fixture directory");
    let dir = temp.path().join("corpus");
    fs::create_dir_all(&dir).expect("create corpus dir");
    let corpus = dir.join("refusals.jsonl");
    fs::write(&corpus, "").expect("seed empty corpus state");
    // `dir/../corpus/refusals.jsonl` names the same file as `corpus` but is not
    // string-equal. A syntactic guard would let this clobber the live state with
    // the public export; the filesystem-identity guard must still refuse it.
    let aliased_out = dir.join("..").join("corpus").join("refusals.jsonl");

    let output = export(&corpus, &aliased_out);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a differently-spelled alias of the source must be refused: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let error: serde_json::Value =
        serde_json::from_slice(&output.stderr).expect("refusal is structured JSON");
    assert_eq!(error["code"], "ORACLEMCP_REFUSAL_CORPUS_EXPORT_REFUSED");
    // The live append-only corpus must be untouched by a refused export.
    assert_eq!(
        fs::read_to_string(&corpus).expect("read corpus"),
        "",
        "a refused export must not overwrite the source corpus"
    );
}
