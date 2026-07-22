//! Every `:n` OCCURRENCE in a positional statement consumes one bind value.
//!
//! The thin driver binds positionally per occurrence, not per distinct
//! placeholder name — its own contract, asserted in `oracledb`'s
//! `declared_bind_count_uses_real_tokenizer_ignoring_literals_and_comments`:
//! `declared_bind_count("insert into t values (:1, :1, :2)")` is **3**, and
//! "execution binds each occurrence its own value".
//!
//! So `WHERE owner = :1 AND (:2 IS NULL OR name = :2)` declares three slots,
//! not two. Reuse a placeholder and the statement silently asks for more values
//! than the call site passes; the mismatch never surfaces locally, because it
//! takes a real database to notice. Oracle answers `ORA-01008: value for bind
//! variable placeholder was not provided`, and the tool returns an error
//! envelope where the caller expected rows.
//!
//! That is not hypothetical: it is what took down the 23ai ladder lane's
//! "created PROCEDURE has no compile errors" assertion, and the same defect was
//! sitting unnoticed in the bounded `get_source` line-range read.
//!
//! This test reads the crate's own sources, so a statement added tomorrow is
//! covered without anyone remembering to list it here.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// A `:n` placeholder and how many times it occurs in one statement.
fn positional_placeholders(text: &str) -> BTreeMap<u32, usize> {
    let bytes = text.as_bytes();
    let mut counts: BTreeMap<u32, usize> = BTreeMap::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b':' {
            index += 1;
            continue;
        }
        // `::` is a Rust path separator, never a bind.
        let mut end = index + 1;
        while end < bytes.len() && bytes[end].is_ascii_digit() {
            end += 1;
        }
        if end > index + 1 {
            let digits = &text[index + 1..end];
            if let Ok(number) = digits.parse::<u32>() {
                *counts.entry(number).or_insert(0) += 1;
            }
        }
        index = end.max(index + 1);
    }
    counts
}

fn rust_sources(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let Ok(entries) = fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}

/// Rust string literals in `source`, with the `\`-newline continuations SQL in
/// this crate is written with folded away. Good enough to find bind
/// placeholders: a false split only ever *reduces* what a literal looks like,
/// and a placeholder cannot straddle the split.
fn string_literals(source: &str) -> Vec<String> {
    let bytes = source.as_bytes();
    let mut literals = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'"' {
            index += 1;
            continue;
        }
        let mut current = String::new();
        let mut cursor = index + 1;
        let mut closed = false;
        while cursor < bytes.len() {
            match bytes[cursor] {
                b'\\' => cursor += 2,
                b'"' => {
                    closed = true;
                    cursor += 1;
                    break;
                }
                byte => {
                    current.push(byte as char);
                    cursor += 1;
                }
            }
        }
        if closed {
            literals.push(current);
        }
        index = cursor.max(index + 1);
    }
    literals
}

#[test]
fn dictionary_sql_never_reuses_a_positional_placeholder() {
    let source_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders = Vec::new();

    for path in rust_sources(&source_root) {
        let source = fs::read_to_string(&path).expect("crate source is readable");
        for literal in string_literals(&source) {
            let counts = positional_placeholders(&literal);
            // Only statements that actually bind positionally are in scope.
            if !counts.contains_key(&1) {
                continue;
            }
            let repeated: Vec<String> = counts
                .iter()
                .filter(|(_, occurrences)| **occurrences > 1)
                .map(|(number, occurrences)| format!(":{number} x{occurrences}"))
                .collect();
            if !repeated.is_empty() {
                let declared: usize = counts.values().sum();
                offenders.push(format!(
                    "{}: reuses {} (statement declares {declared} bind slots)\n    {}",
                    path.display(),
                    repeated.join(", "),
                    literal.split_whitespace().collect::<Vec<_>>().join(" "),
                ));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "a positional placeholder is reused, so these statements declare more bind \
         slots than their call sites supply and Oracle will answer ORA-01008. Give \
         each occurrence its own :n and pass the value again:\n  {}",
        offenders.join("\n  "),
    );
}

#[test]
fn the_scanner_sees_the_defect_it_was_written_for() {
    // The exact shape that broke `compile_errors`: three distinct placeholders,
    // four slots.
    let broken = "WHERE owner = :1 AND (:2 IS NULL OR name = :2) AND ROWNUM <= :3";
    let counts = positional_placeholders(broken);
    assert_eq!(counts.get(&2), Some(&2), "the reuse must be visible");
    assert_eq!(
        counts.values().sum::<usize>(),
        4,
        "four occurrences, four slots"
    );

    // The corrected shape: one occurrence each, four slots, four values.
    let fixed = "WHERE owner = :1 AND (:2 IS NULL OR name = :3) AND ROWNUM <= :4";
    let counts = positional_placeholders(fixed);
    assert!(
        counts.values().all(|occurrences| *occurrences == 1),
        "no placeholder may repeat",
    );
    assert_eq!(counts.values().sum::<usize>(), 4);

    // A Rust path separator is not a bind.
    assert!(positional_placeholders("std::process::exit").is_empty());
}
