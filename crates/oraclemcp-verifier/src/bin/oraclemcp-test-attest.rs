//! Emit a `test-attestation/v1` document for a completed CI lane.
//!
//! Secret material is read only from `ORACLEMCP_TEST_ATTESTATION_KEY`; it is
//! never accepted on argv, written to the output, or rendered in errors.

#![forbid(unsafe_code)]

use oraclemcp_audit::{SigningKey, sha256_hex};
use oraclemcp_verifier::{
    AttestedArtifact, AttestedTest, TestAttestation, TestAttestationDraft, TestOutcome,
    sign_test_attestation,
};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

const KEY_ENV: &str = "ORACLEMCP_TEST_ATTESTATION_KEY";
const KEY_ID_ENV: &str = "ORACLEMCP_TEST_ATTESTATION_KEY_ID";
const MAX_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug)]
struct Arguments {
    artifacts: Vec<String>,
    command: String,
    created_at: String,
    git_sha: String,
    lane: String,
    output: String,
    repo: String,
    tests: Vec<String>,
    toolchain: String,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("test-attest: FAIL: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let arguments = parse_arguments(env::args().skip(1))?;
    let key_id = env::var(KEY_ID_ENV)
        .map_err(|_| format!("required environment variable {KEY_ID_ENV} is not set"))?;
    let secret_hex = env::var(KEY_ENV)
        .map_err(|_| format!("required environment variable {KEY_ENV} is not set"))?;
    let secret = decode_secret(&secret_hex)?;
    let signing_key = SigningKey::new(key_id, secret)
        .map_err(|error| format!("trusted signing key is invalid: {error}"))?;

    let tests = arguments
        .tests
        .iter()
        .map(|spec| parse_test(spec))
        .collect::<Result<Vec<_>, _>>()?;
    let artifacts = arguments
        .artifacts
        .iter()
        .map(|path| hash_artifact(path))
        .collect::<Result<Vec<_>, _>>()?;

    let attestation = TestAttestation::from_draft(TestAttestationDraft {
        lane: arguments.lane,
        repo: arguments.repo,
        git_sha: arguments.git_sha,
        toolchain: arguments.toolchain,
        command: arguments.command,
        created_at: arguments.created_at,
        tests,
        artifacts,
    })
    .map_err(|error| format!("attestation inputs violate test-attestation/v1: {error}"))?;
    let document = sign_test_attestation(&attestation, &signing_key);
    write_new_output(&arguments.output, document.as_bytes())?;
    println!("test-attest: PASS: wrote {}", arguments.output);
    Ok(())
}

fn parse_arguments(arguments: impl Iterator<Item = String>) -> Result<Arguments, String> {
    let mut lane = None;
    let mut repo = None;
    let mut git_sha = None;
    let mut toolchain = None;
    let mut command = None;
    let mut created_at = None;
    let mut output = None;
    let mut tests = Vec::new();
    let mut artifacts = Vec::new();
    let mut arguments = arguments;

    while let Some(flag) = arguments.next() {
        let value = arguments
            .next()
            .ok_or_else(|| format!("{flag} requires one value"))?;
        match flag.as_str() {
            "--lane" => set_once(&mut lane, value, &flag)?,
            "--repo" => set_once(&mut repo, value, &flag)?,
            "--git-sha" => set_once(&mut git_sha, value, &flag)?,
            "--toolchain" => set_once(&mut toolchain, value, &flag)?,
            "--command" => set_once(&mut command, value, &flag)?,
            "--created-at" => set_once(&mut created_at, value, &flag)?,
            "--output" => set_once(&mut output, value, &flag)?,
            "--test" => tests.push(value),
            "--artifact" => artifacts.push(value),
            _ => return Err(format!("unknown argument {flag}")),
        }
    }

    if tests.is_empty() {
        return Err("at least one --test NAME=PASS|SKIP|FAIL is required".to_owned());
    }
    Ok(Arguments {
        artifacts,
        command: require(command, "--command")?,
        created_at: require(created_at, "--created-at")?,
        git_sha: require(git_sha, "--git-sha")?,
        lane: require(lane, "--lane")?,
        output: require(output, "--output")?,
        repo: require(repo, "--repo")?,
        tests,
        toolchain: require(toolchain, "--toolchain")?,
    })
}

fn set_once(slot: &mut Option<String>, value: String, flag: &str) -> Result<(), String> {
    if slot.replace(value).is_some() {
        return Err(format!("{flag} may be supplied only once"));
    }
    Ok(())
}

fn require(value: Option<String>, flag: &str) -> Result<String, String> {
    value.ok_or_else(|| format!("required argument {flag} is missing"))
}

fn parse_test(spec: &str) -> Result<AttestedTest, String> {
    let (name, outcome) = spec
        .rsplit_once('=')
        .ok_or_else(|| "--test must be NAME=PASS|SKIP|FAIL".to_owned())?;
    let outcome = match outcome {
        "PASS" => TestOutcome::Pass,
        "SKIP" => TestOutcome::Skip,
        "FAIL" => TestOutcome::Fail,
        _ => return Err("--test outcome must be exactly PASS, SKIP, or FAIL".to_owned()),
    };
    Ok(AttestedTest {
        detail: None,
        name: name.to_owned(),
        outcome,
    })
}

fn hash_artifact(path: &str) -> Result<AttestedArtifact, String> {
    let path = safe_relative_path(path)?;
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| format!("cannot inspect artifact {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "artifact {} is not a regular non-symlink file",
            path.display()
        ));
    }
    if metadata.len() > MAX_ARTIFACT_BYTES {
        return Err(format!(
            "artifact {} exceeds the {MAX_ARTIFACT_BYTES}-byte verifier limit",
            path.display()
        ));
    }
    let bytes = fs::read(&path)
        .map_err(|error| format!("cannot read artifact {}: {error}", path.display()))?;
    Ok(AttestedArtifact {
        path: path
            .to_str()
            .ok_or_else(|| "artifact path is not UTF-8".to_owned())?
            .to_owned(),
        sha256: sha256_hex(&bytes),
    })
}

fn safe_relative_path(path: &str) -> Result<PathBuf, String> {
    if path.is_empty() || path.contains('\\') {
        return Err("path must be a non-empty portable relative path".to_owned());
    }
    let path = PathBuf::from(path);
    if path
        .components()
        .all(|component| matches!(component, Component::Normal(_)))
    {
        Ok(path)
    } else {
        Err("path must not be absolute or contain dot/prefix components".to_owned())
    }
}

fn write_new_output(path: &str, document: &[u8]) -> Result<(), String> {
    let path = safe_relative_path(path)?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent_metadata = fs::symlink_metadata(parent)
        .map_err(|error| format!("cannot inspect output parent {}: {error}", parent.display()))?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        return Err(format!(
            "output parent {} is not a regular directory",
            parent.display()
        ));
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|error| format!("cannot create new output {}: {error}", path.display()))?;
    output
        .write_all(document)
        .and_then(|()| output.sync_all())
        .map_err(|error| format!("cannot durably write output {}: {error}", path.display()))
}

fn decode_secret(value: &str) -> Result<Vec<u8>, String> {
    if value.len() < 64 || value.len() > 1024 || !value.len().is_multiple_of(2) {
        return Err(format!(
            "{KEY_ENV} must be 64..1024 lowercase hexadecimal characters of even length"
        ));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{KEY_ENV} must be lowercase hexadecimal"));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => unreachable!("alphabet checked above"),
            };
            Ok((digit(pair[0]) << 4) | digit(pair[1]))
        })
        .collect()
}
