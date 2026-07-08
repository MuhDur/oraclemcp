#![allow(dead_code)]

use std::fs;
use std::path::PathBuf;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

/// A reusable canonicalizer that masks non-deterministic or potentially-secret
/// dynamic values in golden output *before* comparison.
///
/// This is the shared golden-artifact discipline every surface adopts: a golden
/// can never itself become a secret leak or a flake, because dynamic values are
/// normalized to stable placeholders (`[TIMESTAMP]`, `[UUID]`, `[ADDR]`,
/// `[PATH]`, `[DURATION]`, `[SCN]`, …). Rules are applied in registration order,
/// each a `(regex, replacement)` pair, so a broad rule never eats a token a more
/// precise rule owns.
pub struct Scrubber {
    rules: Vec<ScrubRule>,
}

struct ScrubRule {
    regex: Regex,
    replacement: String,
}

impl Scrubber {
    /// An empty registry; add rules with [`Scrubber::with_custom`].
    #[must_use]
    pub fn empty() -> Self {
        Scrubber { rules: Vec::new() }
    }

    /// The canonical registry of dynamic-value maskers. Ordered most-specific
    /// first. Intended for *clean* surfaces (e.g. a capabilities/serverInfo
    /// snapshot); the large protocol transcripts deliberately keep their precise
    /// value-aware scrubbing instead (see the module docs on `scrub_value`).
    #[must_use]
    pub fn standard() -> Self {
        Scrubber::empty()
            // RFC3339 / ISO-8601 instants (optional fractional seconds + zone),
            // masked before durations so a trailing `:00` is never mistaken for
            // a bare-second duration.
            .with_custom(
                r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?",
                "[TIMESTAMP]",
            )
            // RFC4122 UUIDs (any version).
            .with_custom(
                r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
                "[UUID]",
            )
            // The redaction subset (paths / host:port / memory addresses).
            .extend_redactions()
            // Durations with an explicit sub-second time unit (never a bare
            // integer, which would collide with counts and JSON schema bounds).
            .with_custom(r"\d+(?:\.\d+)?(?:ns|µs|us|ms)\b", "[DURATION]")
            // Oracle SCN in value position (`"scn": 12345` / `SCN 12345`), never
            // the bare word "scn" in prose.
            .with_custom(r#"("scn"\s*:\s*)\d+"#, "${1}[SCN]")
            .with_custom(r"\bSCN\s+\d+\b", "SCN [SCN]")
    }

    /// The redaction-only subset that can never over-scrub deterministic fixture
    /// data: absolute filesystem paths, host:port pairs, and memory addresses.
    /// Safe to wire into every golden surface — it only masks secret-shaped
    /// leaks, never a semantic constant.
    #[must_use]
    pub fn redactions() -> Self {
        Scrubber::empty().extend_redactions()
    }

    fn extend_redactions(self) -> Self {
        self
            // Memory addresses / opaque hex handles.
            .with_custom(r"\b0x[0-9a-fA-F]{6,}\b", "[ADDR]")
            // host:port (IPv4 and IPv6 loopback). A BARE `:port` is deliberately
            // NOT matched — it would collide with JSON numbers like
            // `"maximum":5000` or `"num_rows":1234`.
            .with_custom(r"\b(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}\b", "[ADDR]")
            .with_custom(r"\[::1\]:\d{1,5}", "[ADDR]")
            // Absolute filesystem paths (real OS roots only, so URL/SQL paths are
            // left intact).
            .with_custom(
                r#"/(?:home|Users|root|tmp|var|opt|private)/[^\s"',;:)\]}\\]*"#,
                "[PATH]",
            )
            .with_custom(r#"[A-Za-z]:\\[^\s"';,]*"#, "[PATH]")
    }

    /// Register an extra rule. Panics if `pattern` is not a valid regex.
    #[must_use]
    pub fn with_custom(mut self, pattern: &str, replacement: &str) -> Self {
        let regex = Regex::new(pattern)
            .unwrap_or_else(|err| panic!("golden scrubber rule /{pattern}/ is not valid: {err}"));
        self.rules.push(ScrubRule {
            regex,
            replacement: replacement.to_owned(),
        });
        self
    }

    /// Apply every rule, in order, to a single string.
    #[must_use]
    pub fn scrub(&self, input: &str) -> String {
        let mut out = input.to_owned();
        for rule in &self.rules {
            out = rule
                .regex
                .replace_all(&out, rule.replacement.as_str())
                .into_owned();
        }
        out
    }

    /// Apply the rules to every string leaf of a JSON value. Keys are structural
    /// and are left untouched.
    #[must_use]
    pub fn scrub_value(&self, value: &Value) -> Value {
        match value {
            Value::String(text) => Value::String(self.scrub(text)),
            Value::Array(items) => {
                Value::Array(items.iter().map(|v| self.scrub_value(v)).collect())
            }
            Value::Object(map) => Value::Object(
                map.iter()
                    .map(|(k, v)| (k.clone(), self.scrub_value(v)))
                    .collect(),
            ),
            other => other.clone(),
        }
    }

    /// The `(pattern, replacement)` pairs — e.g. to wire the same rules into
    /// `insta` as snapshot filters, so an `insta` surface follows the exact same
    /// discipline as the JSON-golden surfaces.
    pub fn rules(&self) -> impl Iterator<Item = (&str, &str)> {
        self.rules
            .iter()
            .map(|r| (r.regex.as_str(), r.replacement.as_str()))
    }
}

/// The shared redaction pass wired into every `assert_golden` surface. Building
/// the regexes is not free, so it is compiled once. Kept to the redaction-only
/// subset so it can never over-scrub the deterministic fixture values (server
/// versions, schema bounds, synthetic timestamps) the transcripts intentionally
/// freeze.
fn redaction_scrubber() -> &'static Scrubber {
    static REDACTION: LazyLock<Scrubber> = LazyLock::new(Scrubber::redactions);
    &REDACTION
}

/// Assert `actual` matches the committed golden `name`, panicking with a unified
/// diff (and a `<name>.actual` sidecar) on mismatch. `UPDATE_GOLDENS=1`
/// regenerates it instead. NEVER set `UPDATE_GOLDENS` in CI.
pub fn assert_golden(name: &str, actual: &Value) {
    if let Err(report) = check_golden(name, actual) {
        panic!("{report}");
    }
}

/// Non-panicking form of [`assert_golden`]: `Ok(())` on a match (or under
/// `UPDATE_GOLDENS`), otherwise `Err` with a unified diff plus the re-approval
/// hint. Lets a test exercise the *failure* path without unwinding.
pub fn check_golden(name: &str, actual: &Value) -> Result<(), String> {
    let actual = render(actual);
    let path = golden_path(name);
    if std::env::var_os("UPDATE_GOLDENS").is_some() {
        fs::create_dir_all(path.parent().expect("golden path has parent"))
            .expect("create golden directory");
        fs::write(&path, &actual).expect("write golden file");
        return Ok(());
    }

    let expected = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(err) => {
            return Err(format!(
                "missing golden {}: {err}\nrun with UPDATE_GOLDENS=1 to create it, then review the diff",
                path.display()
            ));
        }
    };
    if expected == actual {
        return Ok(());
    }

    // Persist the produced output next to the golden for offline diffing. The
    // `.actual` sidecar is gitignored (see .gitignore `*.actual`).
    let actual_path = path.with_extension("actual");
    if let Some(parent) = actual_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    fs::write(&actual_path, &actual).expect("write .actual sidecar");

    Err(format!(
        "golden mismatch for {name}\n{}\nwrote produced output to {}\n\
         review the diff; if the change is intended, re-approve with:\n    \
         UPDATE_GOLDENS=1 cargo test -- {name}\n(never set UPDATE_GOLDENS in CI)",
        compact_diff(&expected, &actual),
        actual_path.display(),
    ))
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
                } else if (key.eq_ignore_ascii_case("next_cursor")
                    || key.eq_ignore_ascii_case("nextCursor"))
                    && value.is_string()
                {
                    // E2: opaque tamper-evident cursors carry a per-process MAC
                    // tag (non-deterministic). Normalize the `.<16-hex>` tag to a
                    // stable token, keeping the opaque body so the golden still
                    // proves a cursor was issued without freezing the secret tag.
                    out.insert(
                        key.clone(),
                        Value::String(scrub_cursor_token(value.as_str().unwrap())),
                    );
                } else {
                    out.insert(key.clone(), scrub_value(value));
                }
            }
            Value::Object(out)
        }
        Value::Array(values) => Value::Array(values.iter().map(scrub_value).collect()),
        Value::String(text) => {
            // Value-aware domain scrubbing first (session ids, cursor/export MAC
            // tags, fence tags, UUID-like tokens), then the shared redaction pass
            // so no absolute path, host:port, or memory address can ever leak
            // into a committed golden.
            let domain = scrub_export_uri(&scrub_text(text));
            Value::String(redaction_scrubber().scrub(&domain))
        }
        other => other.clone(),
    }
}

/// Normalize an opaque `<body>.<16-hex MAC>` cursor token to `<body>.[MAC]` so
/// goldens stay stable across processes while still proving the cursor shape.
fn scrub_cursor_token(token: &str) -> String {
    if let Some((body, tag)) = token.rsplit_once('.')
        && tag.len() == 16
        && tag.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return format!("{body}.[MAC]");
    }
    token.to_owned()
}

/// Within a flat JSON text payload, normalize the MAC tag of any
/// `"next_cursor":"<body>.<16-hex>"` value. Operates on the serialized text
/// channel (the structured channel is scrubbed at the value level).
fn scrub_embedded_cursor_tokens(text: &str) -> String {
    const NEEDLE: &str = "\"next_cursor\":\"";
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(pos) = rest.find(NEEDLE) {
        let value_start = pos + NEEDLE.len();
        out.push_str(&rest[..value_start]);
        let after = &rest[value_start..];
        // The JSON string value ends at the next unescaped quote.
        if let Some(end) = after.find('"') {
            out.push_str(&scrub_cursor_token(&after[..end]));
            rest = &after[end..];
        } else {
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

/// Normalize the per-process MAC tag inside an `oracle-export://exp-N.<16-hex>`
/// URI (or a bare export id) to `oracle-export://exp-N.[MAC]`, keeping the
/// deterministic body so the golden still proves the export shape.
fn scrub_export_uri(value: &str) -> String {
    const SCHEME: &str = "oracle-export://";
    if let Some(id) = value.strip_prefix(SCHEME) {
        return format!("{SCHEME}{}", scrub_cursor_token(id));
    }
    // A bare export id (`exp-N.<16-hex>`).
    if value.starts_with("exp-") {
        return scrub_cursor_token(value);
    }
    value.to_owned()
}

/// Within a flat JSON text payload, normalize the MAC tag of every
/// `oracle-export://exp-N.<16-hex>` URI occurrence.
fn scrub_embedded_export_uris(text: &str) -> String {
    const NEEDLE: &str = "oracle-export://";
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(pos) = rest.find(NEEDLE) {
        out.push_str(&rest[..pos]);
        let after = &rest[pos + NEEDLE.len()..];
        // The id runs until a JSON string boundary (`"`, `\`) or whitespace.
        let end = after
            .find(|c: char| c == '"' || c == '\\' || c.is_whitespace())
            .unwrap_or(after.len());
        out.push_str(NEEDLE);
        out.push_str(&scrub_cursor_token(&after[..end]));
        rest = &after[end..];
    }
    out.push_str(rest);
    out
}

fn scrub_text(text: &str) -> String {
    // A6: the `<untrusted-user-data-<tag>>` fence tag is a per-call content hash
    // (non-deterministic), so normalize it to a stable token before UUID/session
    // scrubbing. This keeps goldens deterministic while still proving the fence
    // (preamble + open/close delimiters) is present in agent-facing text.
    let text = scrub_fence_tags(text);
    // E2: the fenced text channel embeds the structured JSON verbatim, including
    // the opaque `"next_cursor":"<body>.<16-hex MAC>"`. Normalize the MAC tag
    // there too so the golden is stable across processes.
    let text = scrub_embedded_cursor_tokens(&text);
    // E3: likewise normalize the MAC tag inside any embedded
    // `oracle-export://exp-N.<16-hex>` URI in the text channel.
    let text = scrub_embedded_export_uris(&text);
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

/// Replace the 16-hex fence tag in `untrusted-user-data-<tag>` with `[FENCE]`
/// so the golden is stable across runs.
fn scrub_fence_tags(text: &str) -> String {
    const NEEDLE: &str = "untrusted-user-data-";
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(pos) = rest.find(NEEDLE) {
        out.push_str(&rest[..pos]);
        out.push_str(NEEDLE);
        let after = &rest[pos + NEEDLE.len()..];
        let hex_len = after
            .bytes()
            .take_while(u8::is_ascii_hexdigit)
            .count()
            .min(16);
        if hex_len == 16 {
            out.push_str("[FENCE]");
            rest = &after[hex_len..];
        } else {
            // Not a real fence tag (e.g. the neutralized marker); leave it.
            rest = after;
        }
    }
    out.push_str(rest);
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
