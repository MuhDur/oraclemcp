#![allow(dead_code)]

use std::fs;
use std::path::PathBuf;

use serde_json::Value;

pub fn assert_golden(name: &str, actual: &Value) {
    let actual = render(actual);
    let path = golden_path(name);
    if std::env::var_os("UPDATE_GOLDENS").is_some() {
        fs::create_dir_all(path.parent().expect("golden path has parent"))
            .expect("create golden directory");
        fs::write(&path, &actual).expect("write golden file");
        return;
    }

    let expected = fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!(
            "missing golden {}: {err}\nrun with UPDATE_GOLDENS=1 to create it, then review the diff",
            path.display()
        )
    });
    if expected != actual {
        panic!(
            "golden mismatch for {}\n{}\nupdate only after reviewing the protocol change",
            path.display(),
            compact_diff(&expected, &actual)
        );
    }
}

fn render(value: &Value) -> String {
    let scrubbed = scrub_value(value);
    let mut text = serde_json::to_string_pretty(&scrubbed).expect("golden JSON renders");
    text.push('\n');
    text
}

fn golden_path(name: &str) -> PathBuf {
    workspace_root()
        .join("tests")
        .join("golden")
        .join(format!("{name}.json"))
}

fn workspace_root() -> PathBuf {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        if dir.join("Cargo.toml").exists() && dir.join("crates").is_dir() {
            return dir;
        }
        if !dir.pop() {
            panic!("could not find workspace root from CARGO_MANIFEST_DIR");
        }
    }
}

fn scrub_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (key, value) in map {
                if key.eq_ignore_ascii_case("mcp-session-id")
                    || key.eq_ignore_ascii_case("session_id")
                    || key.eq_ignore_ascii_case("session-id")
                {
                    out.insert(key.clone(), Value::String("[SESSION_ID]".to_owned()));
                } else {
                    out.insert(key.clone(), scrub_value(value));
                }
            }
            Value::Object(out)
        }
        Value::Array(values) => Value::Array(values.iter().map(scrub_value).collect()),
        Value::String(text) => Value::String(scrub_text(text)),
        other => other.clone(),
    }
}

fn scrub_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    while index < text.len() {
        if let Some((start, end)) = next_uuid_like(&text[index..]) {
            out.push_str(&text[index..index + start]);
            out.push_str("[SESSION_ID]");
            index += end;
        } else {
            out.push_str(&text[index..]);
            break;
        }
    }
    out
}

fn next_uuid_like(text: &str) -> Option<(usize, usize)> {
    for (start, _) in text.char_indices() {
        let candidate = text.get(start..start + 36)?;
        if is_uuid_like(candidate) {
            return Some((start, start + 36));
        }
    }
    None
}

fn is_uuid_like(text: &str) -> bool {
    if text.len() != 36 {
        return false;
    }
    for (idx, byte) in text.bytes().enumerate() {
        match idx {
            8 | 13 | 18 | 23 => {
                if byte != b'-' {
                    return false;
                }
            }
            _ => {
                if !byte.is_ascii_hexdigit() {
                    return false;
                }
            }
        }
    }
    true
}

fn compact_diff(expected: &str, actual: &str) -> String {
    let expected_lines: Vec<&str> = expected.lines().collect();
    let actual_lines: Vec<&str> = actual.lines().collect();
    let max = expected_lines.len().max(actual_lines.len());
    let first = (0..max).find(|&idx| {
        expected_lines.get(idx).copied().unwrap_or("<missing>")
            != actual_lines.get(idx).copied().unwrap_or("<missing>")
    });
    let Some(first) = first else {
        return "contents differ only by trailing newline state".to_owned();
    };
    let start = first.saturating_sub(6);
    let end = (first + 12).min(max);
    let mut diff = String::from("--- expected\n+++ actual\n");
    for idx in start..end {
        let expected = expected_lines.get(idx).copied();
        let actual = actual_lines.get(idx).copied();
        match (expected, actual) {
            (Some(e), Some(a)) if e == a => {
                diff.push_str("  ");
                diff.push_str(e);
                diff.push('\n');
            }
            (Some(e), Some(a)) => {
                diff.push_str("- ");
                diff.push_str(e);
                diff.push('\n');
                diff.push_str("+ ");
                diff.push_str(a);
                diff.push('\n');
            }
            (Some(e), None) => {
                diff.push_str("- ");
                diff.push_str(e);
                diff.push('\n');
            }
            (None, Some(a)) => {
                diff.push_str("+ ");
                diff.push_str(a);
                diff.push('\n');
            }
            (None, None) => {}
        }
    }
    diff
}

#[allow(dead_code)]
pub fn body_value(content_type: Option<&str>, bytes: &[u8]) -> Value {
    if bytes.is_empty() {
        return Value::String(String::new());
    }
    let text = String::from_utf8_lossy(bytes).to_string();
    if content_type.is_some_and(|ct| ct.contains("application/json")) {
        serde_json::from_slice(bytes).expect("JSON response body parses")
    } else if content_type.is_some_and(|ct| ct.contains("text/event-stream")) {
        sse_body_value(&text)
    } else {
        Value::String(text)
    }
}

#[allow(dead_code)]
fn sse_body_value(text: &str) -> Value {
    let events = text
        .split("\n\n")
        .filter(|event| !event.trim().is_empty())
        .map(|event| {
            let mut out = serde_json::Map::new();
            let mut data_lines = Vec::new();
            for line in event.lines() {
                if let Some(value) = line.strip_prefix("id:") {
                    out.insert("id".to_owned(), Value::String(value.trim().to_owned()));
                } else if let Some(value) = line.strip_prefix("retry:") {
                    let retry = value.trim().parse::<u64>().expect("retry is numeric");
                    out.insert(
                        "retry".to_owned(),
                        Value::Number(serde_json::Number::from(retry)),
                    );
                } else if let Some(value) = line.strip_prefix("data:") {
                    data_lines.push(value.trim_start().to_owned());
                }
            }
            if !data_lines.is_empty() {
                let data = data_lines.join("\n");
                let data = if data.is_empty() {
                    Value::Null
                } else {
                    serde_json::from_str(&data).unwrap_or(Value::String(data))
                };
                out.insert("data".to_owned(), data);
            }
            Value::Object(out)
        })
        .collect();
    Value::Array(events)
}
