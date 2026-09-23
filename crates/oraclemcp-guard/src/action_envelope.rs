//! Canonical, value-redacting binding for previewed actions.

use oraclemcp_audit::hmac_sha256;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::OperatingLevel;

const ENVELOPE_DOMAIN: &[u8] = b"omcp/action-envelope/v1";
const BIND_DOMAIN: &[u8] = b"omcp/bind-hmac/v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OracleBindType {
    Null,
    String,
    I64,
    F64,
    Bool,
    TimestampTz,
}

impl OracleBindType {
    const fn tag(self) -> u8 {
        match self {
            Self::Null => 0,
            Self::String => 1,
            Self::I64 => 2,
            Self::F64 => 3,
            Self::Bool => 4,
            Self::TimestampTz => 5,
        }
    }
}

/// A borrowed view of a backend-independent Oracle bind. Its value is never
/// formatted by `Debug` and never retained by an action envelope.
pub enum CanonicalBind<'a> {
    Null,
    String(&'a str),
    I64(i64),
    F64(f64),
    Bool(bool),
    TimestampTz {
        year: i32,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
        nanosecond: u32,
        offset_minutes: i32,
    },
}

impl CanonicalBind<'_> {
    #[must_use]
    pub const fn bind_type(&self) -> OracleBindType {
        match self {
            Self::Null => OracleBindType::Null,
            Self::String(_) => OracleBindType::String,
            Self::I64(_) => OracleBindType::I64,
            Self::F64(_) => OracleBindType::F64,
            Self::Bool(_) => OracleBindType::Bool,
            Self::TimestampTz { .. } => OracleBindType::TimestampTz,
        }
    }
}

fn bytes(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u64).to_be_bytes());
    out.extend_from_slice(value);
}

fn text(out: &mut Vec<u8>, value: &str) {
    bytes(out, value.as_bytes());
}

/// Canonical encoding of typed bind values. The returned allocation clears
/// itself on drop. Callers should compute a keyed HMAC before dropping it.
#[must_use]
pub fn canonical_binds(binds: &[CanonicalBind<'_>]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::new());
    bytes(&mut out, b"omcp/canonical-binds/v1");
    out.extend_from_slice(&(binds.len() as u64).to_be_bytes());
    for bind in binds {
        out.push(bind.bind_type().tag());
        match bind {
            CanonicalBind::Null => bytes(&mut out, &[]),
            CanonicalBind::String(value) => text(&mut out, value),
            CanonicalBind::I64(value) => {
                let decimal = Zeroizing::new(value.to_string());
                text(&mut out, &decimal);
            }
            CanonicalBind::F64(value) => {
                let decimal = Zeroizing::new(value.to_string());
                text(&mut out, &decimal);
            }
            CanonicalBind::Bool(value) => bytes(&mut out, &[u8::from(*value)]),
            CanonicalBind::TimestampTz {
                year,
                month,
                day,
                hour,
                minute,
                second,
                nanosecond,
                offset_minutes,
            } => {
                let sign = if *offset_minutes < 0 { '-' } else { '+' };
                let offset = offset_minutes.unsigned_abs();
                let iso = Zeroizing::new(format!(
                    "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{nanosecond:09}{sign}{:02}:{:02}",
                    offset / 60,
                    offset % 60,
                ));
                text(&mut out, &iso);
            }
        }
    }
    out
}

#[must_use]
pub fn bind_value_hmac(key: &[u8; 32], canonical: &[u8]) -> [u8; 32] {
    let mut message = Zeroizing::new(Vec::new());
    bytes(&mut message, BIND_DOMAIN);
    bytes(&mut message, canonical);
    hmac_sha256(key, &message)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BindEnvelope {
    pub arity: usize,
    pub types: Vec<OracleBindType>,
    pub value_hmac: [u8; 32],
}

impl BindEnvelope {
    #[must_use]
    pub fn from_binds(key: &[u8; 32], binds: &[CanonicalBind<'_>]) -> Self {
        let canonical = canonical_binds(binds);
        Self {
            arity: binds.len(),
            types: binds.iter().map(CanonicalBind::bind_type).collect(),
            value_hmac: bind_value_hmac(key, &canonical),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActionKind {
    ExecuteDml,
    ExecuteDdlAdmin,
    PreviewDmlSandbox,
    CompileObject,
    CreateOrReplace,
    PatchSource,
    SetSessionLevel { level: OperatingLevel, ttl: u64 },
    CustomToolCall,
    ChangeRequestPromote,
    GrantCreate,
    GrantUse,
}

impl ActionKind {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::ExecuteDml => out.push(1),
            Self::ExecuteDdlAdmin => out.push(2),
            Self::PreviewDmlSandbox => out.push(3),
            Self::CompileObject => out.push(4),
            Self::CreateOrReplace => out.push(5),
            Self::PatchSource => out.push(6),
            Self::SetSessionLevel { level, ttl } => {
                out.push(7);
                text(out, level.as_str());
                out.extend_from_slice(&ttl.to_be_bytes());
            }
            Self::CustomToolCall => out.push(8),
            Self::ChangeRequestPromote => out.push(9),
            Self::GrantCreate => out.push(10),
            Self::GrantUse => out.push(11),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutputCapture {
    pub capture_dbms_output: bool,
    pub max_lines: usize,
    pub max_chars: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecLimits {
    pub timeout_seconds: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionEnvelopeV1 {
    pub version: u8,
    pub action_kind: ActionKind,
    pub statement_digest: [u8; 32],
    pub binds: BindEnvelope,
    pub commit: bool,
    pub hold: bool,
    pub output: OutputCapture,
    pub limits: ExecLimits,
    pub scoped_grant_ref: Option<[u8; 32]>,
}

impl ActionEnvelopeV1 {
    #[must_use]
    pub fn statement_digest(statement: &str) -> [u8; 32] {
        Sha256::digest(statement.as_bytes()).into()
    }

    #[must_use]
    pub fn reference_digest(reference: &str) -> [u8; 32] {
        Sha256::digest(reference.as_bytes()).into()
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        bytes(&mut out, ENVELOPE_DOMAIN);
        out.push(self.version);
        self.action_kind.encode(&mut out);
        bytes(&mut out, &self.statement_digest);
        out.extend_from_slice(&(self.binds.arity as u64).to_be_bytes());
        out.extend_from_slice(&(self.binds.types.len() as u64).to_be_bytes());
        for bind_type in &self.binds.types {
            out.push(bind_type.tag());
        }
        bytes(&mut out, &self.binds.value_hmac);
        out.push(u8::from(self.commit));
        out.push(u8::from(self.hold));
        out.push(u8::from(self.output.capture_dbms_output));
        out.extend_from_slice(&(self.output.max_lines as u64).to_be_bytes());
        out.extend_from_slice(&(self.output.max_chars as u64).to_be_bytes());
        match self.limits.timeout_seconds {
            Some(seconds) => {
                out.push(1);
                out.extend_from_slice(&seconds.to_be_bytes());
            }
            None => out.push(0),
        }
        match self.scoped_grant_ref {
            Some(digest) => {
                out.push(1);
                bytes(&mut out, &digest);
            }
            None => out.push(0),
        }
        out
    }

    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.canonical_bytes()).into()
    }
}
