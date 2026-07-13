//! Result-path masking and deterministic per-profile tokenization.
//!
//! This module is the egress-control seam for `oracle_query`-shaped result
//! payloads. It is deliberately downstream of SQL admission: a masking policy
//! can only remove or transform values that were already produced by a proven
//! read; it never broadens what SQL may run.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::types::OracleCell;

const HMAC_BLOCK_LEN: usize = 64;
const HMAC_OUTPUT_LEN: usize = 32;
const TOKEN_PREFIX: &str = "tok_v1_";

/// Non-null cells masked by `ResultMaskingAction::Mask` are replaced by this
/// fixed marker. The marker intentionally carries no original length signal.
pub const MASKED_RESULT_VALUE: &str = "<masked>";

/// Minimum accepted salt length for deterministic result tokenization.
pub const MIN_PROFILE_MASKING_SALT_BYTES: usize = HMAC_OUTPUT_LEN;

/// Invalid masking-policy or salt material.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum MaskingPolicyError {
    /// A salt identifier was empty.
    #[error("masking salt id must be non-empty")]
    EmptySaltId,
    /// Tokenization salt material was shorter than the HMAC-SHA256 output size.
    #[error("masking salt is too short ({actual} bytes); at least {minimum} bytes are required")]
    SaltTooShort {
        /// Supplied byte length.
        actual: usize,
        /// Required minimum byte length.
        minimum: usize,
    },
}

/// A profile-scoped tokenization salt.
///
/// Debug output redacts the raw bytes. Audit/proof paths should carry only
/// [`Self::salt_id`], never the raw salt material.
#[derive(Clone, PartialEq, Eq)]
pub struct ProfileMaskingSalt {
    salt_id: String,
    bytes: Vec<u8>,
}

impl ProfileMaskingSalt {
    /// Build a salt from state-file material.
    ///
    /// # Errors
    ///
    /// Returns [`MaskingPolicyError`] when `salt_id` is empty or `bytes` has
    /// fewer than [`MIN_PROFILE_MASKING_SALT_BYTES`] bytes.
    pub fn new(
        salt_id: impl Into<String>,
        bytes: impl Into<Vec<u8>>,
    ) -> Result<Self, MaskingPolicyError> {
        let salt_id = salt_id.into();
        if salt_id.trim().is_empty() {
            return Err(MaskingPolicyError::EmptySaltId);
        }
        let bytes = bytes.into();
        if bytes.len() < MIN_PROFILE_MASKING_SALT_BYTES {
            return Err(MaskingPolicyError::SaltTooShort {
                actual: bytes.len(),
                minimum: MIN_PROFILE_MASKING_SALT_BYTES,
            });
        }
        Ok(Self { salt_id, bytes })
    }

    /// Stable non-secret salt identifier carried into audit/proof metadata.
    #[must_use]
    pub fn salt_id(&self) -> &str {
        &self.salt_id
    }

    fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl std::fmt::Debug for ProfileMaskingSalt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProfileMaskingSalt")
            .field("salt_id", &self.salt_id)
            .field("bytes", &"<redacted>")
            .finish()
    }
}

/// Action applied to a matching result column.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResultMaskingAction {
    /// Replace every non-null value with [`MASKED_RESULT_VALUE`].
    Mask,
    /// Replace every non-null value with a deterministic per-profile token.
    Tokenize,
    /// Replace every non-null value with JSON null.
    Null,
}

/// Column selector for one masking rule.
///
/// `column` and `tag` model the ADR's `column|tag` choice. If `schema` or
/// `table` is set, the rule only matches when the caller can provide the same
/// resolved context. The current raw query row path always supplies a result
/// column name and type; future catalog-aware callers can additionally supply
/// owner/table/tag context without changing the policy grammar.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResultColumnMatch {
    /// Optional Oracle owner/schema.
    pub schema: Option<String>,
    /// Optional table/object name.
    pub table: Option<String>,
    /// Optional result or catalog column name. Mutually exclusive with `tag`.
    pub column: Option<String>,
    /// Optional operator-defined sensitivity tag. Mutually exclusive with
    /// `column`.
    pub tag: Option<String>,
}

impl ResultColumnMatch {
    /// Match a concrete column name.
    #[must_use]
    pub fn column(column: impl Into<String>) -> Self {
        Self {
            column: Some(column.into()),
            ..Self::default()
        }
    }

    /// Match a sensitivity tag.
    #[must_use]
    pub fn tag(tag: impl Into<String>) -> Self {
        Self {
            tag: Some(tag.into()),
            ..Self::default()
        }
    }

    /// Add an owner/schema constraint.
    #[must_use]
    pub fn with_schema(mut self, schema: impl Into<String>) -> Self {
        self.schema = Some(schema.into());
        self
    }

    /// Add a table/object constraint.
    #[must_use]
    pub fn with_table(mut self, table: impl Into<String>) -> Self {
        self.table = Some(table.into());
        self
    }

    fn matches(&self, ctx: &ResultColumnContext<'_>) -> bool {
        if let Some(schema) = self.schema.as_deref()
            && !ctx
                .schema
                .is_some_and(|candidate| candidate.eq_ignore_ascii_case(schema))
        {
            return false;
        }
        if let Some(table) = self.table.as_deref()
            && !ctx
                .table
                .is_some_and(|candidate| candidate.eq_ignore_ascii_case(table))
        {
            return false;
        }
        match (self.column.as_deref(), self.tag.as_deref()) {
            (Some(column), None) => ctx.column.eq_ignore_ascii_case(column),
            (None, Some(tag)) => ctx.tag.is_some_and(|candidate| candidate == tag),
            // Empty or ambiguous selectors fail closed by not matching; the
            // policy's mask_unknown_default then decides whether the column is
            // masked as unknown.
            _ => false,
        }
    }
}

/// One result masking rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResultMaskingRule {
    /// Column selector.
    pub column_match: ResultColumnMatch,
    /// Action to apply to a matching non-null cell.
    pub action: ResultMaskingAction,
    /// Optional non-secret policy tag for later audit/proof certificates.
    pub tag: Option<String>,
}

impl ResultMaskingRule {
    /// Build a rule matching a concrete column name.
    #[must_use]
    pub fn column(column: impl Into<String>, action: ResultMaskingAction) -> Self {
        Self {
            column_match: ResultColumnMatch::column(column),
            action,
            tag: None,
        }
    }

    /// Build a rule matching an operator-defined sensitivity tag.
    #[must_use]
    pub fn tagged(tag: impl Into<String>, action: ResultMaskingAction) -> Self {
        Self {
            column_match: ResultColumnMatch::tag(tag),
            action,
            tag: None,
        }
    }

    /// Attach a non-secret policy/audit tag.
    #[must_use]
    pub fn with_policy_tag(mut self, tag: impl Into<String>) -> Self {
        self.tag = Some(tag.into());
        self
    }
}

/// Stable action recorded in a mask-decision certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ResultMaskingDecisionAction {
    /// The column was passed through unchanged.
    Pass,
    /// The column was replaced with [`MASKED_RESULT_VALUE`] for non-null cells.
    Mask,
    /// The column was replaced with a deterministic token for non-null cells.
    Tokenize,
    /// The column was replaced with JSON null for non-null cells.
    Null,
}

impl From<ResultMaskingAction> for ResultMaskingDecisionAction {
    fn from(action: ResultMaskingAction) -> Self {
        match action {
            ResultMaskingAction::Mask => Self::Mask,
            ResultMaskingAction::Tokenize => Self::Tokenize,
            ResultMaskingAction::Null => Self::Null,
        }
    }
}

/// Why a column received the recorded mask-decision action.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ResultMaskingDecisionSource {
    /// A policy rule matched the result column.
    Rule,
    /// No rule matched and `mask_unknown_default=true` masked the column.
    MaskUnknownDefault,
    /// No rule matched and the policy allowed the column through.
    Pass,
}

/// One column-level decision in a result masking certificate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResultMaskingColumnDecision {
    /// Result-set column name.
    pub column: String,
    /// Oracle type name observed for the column.
    pub oracle_type: String,
    /// Action selected for the column.
    pub action: ResultMaskingDecisionAction,
    /// Source of the selected action.
    pub source: ResultMaskingDecisionSource,
    /// Zero-based policy rule index when [`Self::source`] is
    /// [`ResultMaskingDecisionSource::Rule`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_index: Option<usize>,
    /// Optional non-secret tag attached to the matching policy rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_tag: Option<String>,
    /// Non-secret salt id when tokenization was selected with an active salt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub salt_id: Option<String>,
}

impl ResultMaskingColumnDecision {
    fn transforms_value(&self) -> bool {
        self.action != ResultMaskingDecisionAction::Pass
    }
}

/// Per-result proof that records the egress mask decisions used for a query
/// page.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResultMaskingCertificate {
    /// Certificate schema version.
    pub schema_version: u16,
    /// Profile whose masking policy produced the decision, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// Stable hash identity of the masking policy content.
    pub policy_id: String,
    /// Column-level decisions in select-list order.
    pub decisions: Vec<ResultMaskingColumnDecision>,
    /// Audit record entry hash that durably committed this certificate. This is
    /// populated by the dispatcher after the audit append succeeds, never by the
    /// DB serializer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_entry_hash: Option<String>,
}

/// Profile-scoped result masking policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResultMaskingPolicy {
    /// Profile name the policy came from, when known.
    pub profile: Option<String>,
    /// Stable hash identity of the policy content.
    pub policy_id: String,
    /// Rules evaluated in declaration order; first match wins.
    pub rules: Vec<ResultMaskingRule>,
    /// When true, any column not matched by a rule is masked rather than passed
    /// through. This is the fail-closed default for profiles without a complete
    /// catalog-tagging source.
    pub mask_unknown_default: bool,
    /// Active tokenization salt. When absent, `Tokenize` rules degrade to
    /// `Mask` at this transformer seam so plaintext still cannot escape; the
    /// profile loader should reject that configuration before runtime.
    pub token_salt: Option<ProfileMaskingSalt>,
}

impl ResultMaskingPolicy {
    /// Build a policy with no active tokenization salt.
    #[must_use]
    pub fn new(rules: Vec<ResultMaskingRule>, mask_unknown_default: bool) -> Self {
        let policy_id = masking_policy_id(&rules, mask_unknown_default);
        Self {
            profile: None,
            policy_id,
            rules,
            mask_unknown_default,
            token_salt: None,
        }
    }

    /// Attach the non-secret profile name used in proof/audit metadata.
    #[must_use]
    pub fn with_profile(mut self, profile: impl Into<String>) -> Self {
        let profile = profile.into();
        self.profile = (!profile.trim().is_empty()).then_some(profile);
        self
    }

    /// Install the active per-profile tokenization salt.
    #[must_use]
    pub fn with_token_salt(mut self, salt: ProfileMaskingSalt) -> Self {
        self.token_salt = Some(salt);
        self
    }

    fn decision_for(&self, ctx: &ResultColumnContext<'_>) -> ResultMaskingColumnDecision {
        if let Some((rule_index, rule)) = self
            .rules
            .iter()
            .enumerate()
            .find(|(_, rule)| rule.column_match.matches(ctx))
        {
            return ResultMaskingColumnDecision {
                column: ctx.column.to_owned(),
                oracle_type: ctx.oracle_type.to_owned(),
                action: rule.action.into(),
                source: ResultMaskingDecisionSource::Rule,
                rule_index: Some(rule_index),
                rule_tag: rule.tag.clone(),
                salt_id: (rule.action == ResultMaskingAction::Tokenize)
                    .then(|| {
                        self.token_salt
                            .as_ref()
                            .map(|salt| salt.salt_id().to_owned())
                    })
                    .flatten(),
            };
        }
        if self.mask_unknown_default {
            return ResultMaskingColumnDecision {
                column: ctx.column.to_owned(),
                oracle_type: ctx.oracle_type.to_owned(),
                action: ResultMaskingDecisionAction::Mask,
                source: ResultMaskingDecisionSource::MaskUnknownDefault,
                rule_index: None,
                rule_tag: None,
                salt_id: None,
            };
        }
        ResultMaskingColumnDecision {
            column: ctx.column.to_owned(),
            oracle_type: ctx.oracle_type.to_owned(),
            action: ResultMaskingDecisionAction::Pass,
            source: ResultMaskingDecisionSource::Pass,
            rule_index: None,
            rule_tag: None,
            salt_id: None,
        }
    }

    /// Return whether this profile would transform a column when it leaves the
    /// result boundary. A hybrid retrieval must not use such a column as a
    /// predicate: even if its value is masked in `SELECT t.*`, row presence
    /// would otherwise become an egress side channel.
    #[must_use]
    pub fn transforms_filter_column(
        &self,
        schema: Option<&str>,
        table: Option<&str>,
        column: &str,
    ) -> bool {
        self.decision_for(&ResultColumnContext {
            schema,
            table,
            column,
            tag: None,
            oracle_type: "UNKNOWN",
        })
        .transforms_value()
    }

    /// Derive the certificate for a query page from its first row. Oracle result
    /// descriptors are fixed for the page, so the first row supplies the
    /// select-list column names/types. Returns `None` when the policy did not
    /// transform any column.
    #[must_use]
    pub fn certificate_for_row(
        &self,
        row: &crate::types::OracleRow,
    ) -> Option<ResultMaskingCertificate> {
        let decisions = row
            .columns
            .iter()
            .map(|(name, cell)| {
                self.decision_for(&ResultColumnContext::result_column(name, &cell.oracle_type))
            })
            .collect::<Vec<_>>();
        decisions
            .iter()
            .any(ResultMaskingColumnDecision::transforms_value)
            .then(|| ResultMaskingCertificate {
                schema_version: 1,
                profile: self.profile.clone(),
                policy_id: self.policy_id.clone(),
                decisions,
                audit_entry_hash: None,
            })
    }

    pub(crate) fn apply_cell(
        &self,
        ctx: &ResultColumnContext<'_>,
        cell: &OracleCell,
        serialize_original: impl FnOnce() -> Value,
    ) -> Value {
        let action = match self.decision_for(ctx).action {
            ResultMaskingDecisionAction::Pass => {
                return serialize_original();
            }
            ResultMaskingDecisionAction::Mask => ResultMaskingAction::Mask,
            ResultMaskingDecisionAction::Tokenize => ResultMaskingAction::Tokenize,
            ResultMaskingDecisionAction::Null => ResultMaskingAction::Null,
        };
        if cell_is_null(cell) {
            return Value::Null;
        }
        match action {
            ResultMaskingAction::Mask => Value::String(MASKED_RESULT_VALUE.to_owned()),
            ResultMaskingAction::Null => Value::Null,
            ResultMaskingAction::Tokenize => {
                let Some(salt) = self.token_salt.as_ref() else {
                    return Value::String(MASKED_RESULT_VALUE.to_owned());
                };
                let original = serialize_original();
                let plaintext = canonical_plaintext_bytes(&original);
                Value::String(result_masking_token(
                    salt.bytes(),
                    &canonical_type_tag(ctx.oracle_type),
                    &plaintext,
                ))
            }
        }
    }
}

fn masking_policy_id(rules: &[ResultMaskingRule], mask_unknown_default: bool) -> String {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"oraclemcp-result-masking-policy:v1");
    bytes.push(u8::from(mask_unknown_default));
    bytes.extend_from_slice(&(rules.len() as u64).to_be_bytes());
    for rule in rules {
        canonical_push_optional_upper(&mut bytes, rule.column_match.schema.as_deref());
        canonical_push_optional_upper(&mut bytes, rule.column_match.table.as_deref());
        canonical_push_optional_upper(&mut bytes, rule.column_match.column.as_deref());
        canonical_push_optional_exact(&mut bytes, rule.column_match.tag.as_deref());
        bytes.push(match rule.action {
            ResultMaskingAction::Mask => 1,
            ResultMaskingAction::Tokenize => 2,
            ResultMaskingAction::Null => 3,
        });
        canonical_push_optional_exact(&mut bytes, rule.tag.as_deref());
    }
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(7 + digest.len() * 2);
    out.push_str("sha256:");
    for byte in digest {
        push_hex_byte(&mut out, byte);
    }
    out
}

fn push_hex_byte(out: &mut String, byte: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push(HEX[(byte >> 4) as usize] as char);
    out.push(HEX[(byte & 0x0f) as usize] as char);
}

fn canonical_push_optional_upper(out: &mut Vec<u8>, value: Option<&str>) {
    canonical_push_optional_exact(
        out,
        value
            .map(|value| value.trim().to_ascii_uppercase())
            .as_deref(),
    );
}

fn canonical_push_optional_exact(out: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(value) => {
            out.push(1);
            let value = value.trim();
            out.extend_from_slice(&(value.len() as u64).to_be_bytes());
            out.extend_from_slice(value.as_bytes());
        }
        None => out.push(0),
    }
}

/// Column context available while serializing a result row.
pub(crate) struct ResultColumnContext<'a> {
    pub(crate) schema: Option<&'a str>,
    pub(crate) table: Option<&'a str>,
    pub(crate) column: &'a str,
    pub(crate) tag: Option<&'a str>,
    pub(crate) oracle_type: &'a str,
}

impl<'a> ResultColumnContext<'a> {
    pub(crate) fn result_column(column: &'a str, oracle_type: &'a str) -> Self {
        Self {
            schema: None,
            table: None,
            column,
            tag: None,
            oracle_type,
        }
    }
}

fn cell_is_null(cell: &OracleCell) -> bool {
    cell.value.is_none()
        && cell.bytes.is_none()
        && cell.structured.is_none()
        && cell.nested_result.is_none()
}

fn canonical_plaintext_bytes(value: &Value) -> Vec<u8> {
    match value {
        Value::String(text) => text.as_bytes().to_vec(),
        other => serde_json::to_vec(other).unwrap_or_else(|_| b"null".to_vec()),
    }
}

fn canonical_type_tag(oracle_type: &str) -> String {
    let upper = oracle_type.trim().to_ascii_uppercase();
    let family = upper
        .split(['(', ' ', '\t', '\r', '\n'])
        .next()
        .unwrap_or("UNKNOWN");
    if family.is_empty() {
        "UNKNOWN".to_owned()
    } else {
        family.to_owned()
    }
}

fn result_masking_token(salt: &[u8], type_tag: &str, canonical_plaintext_bytes: &[u8]) -> String {
    let mut message = Vec::with_capacity(
        "oraclemcp-mask-token:v1".len() + 2 + type_tag.len() + canonical_plaintext_bytes.len(),
    );
    message.extend_from_slice(b"oraclemcp-mask-token:v1");
    message.push(0);
    message.extend_from_slice(type_tag.as_bytes());
    message.push(0);
    message.extend_from_slice(canonical_plaintext_bytes);

    let mac = hmac_sha256(salt, &message);
    let mut token = String::from(TOKEN_PREFIX);
    token.push_str(&base64url_no_pad(&mac[..16]));
    token
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; HMAC_OUTPUT_LEN] {
    let mut block = [0u8; HMAC_BLOCK_LEN];
    if key.len() > HMAC_BLOCK_LEN {
        let hashed = Sha256::digest(key);
        block[..HMAC_OUTPUT_LEN].copy_from_slice(&hashed);
    } else {
        block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; HMAC_BLOCK_LEN];
    let mut opad = [0x5cu8; HMAC_BLOCK_LEN];
    for i in 0..HMAC_BLOCK_LEN {
        ipad[i] ^= block[i];
        opad[i] ^= block[i];
    }

    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(message);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    let outer_digest = outer.finalize();

    let mut out = [0u8; HMAC_OUTPUT_LEN];
    out.copy_from_slice(&outer_digest);
    out
}

fn base64url_no_pad(bytes: &[u8]) -> String {
    const ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((bytes.len() * 4).div_ceil(3));
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHA[((n >> 18) & 63) as usize] as char);
        out.push(ALPHA[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHA[((n >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHA[(n & 63) as usize] as char);
        }
    }
    out
}

/// Why one column's values cannot be soundly compared across two profiles.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "break")]
#[non_exhaustive]
pub enum MaskComparabilityBreak {
    /// Both profiles destroy the value (`mask` collapses every non-null cell to
    /// the same marker; `null` erases it). Equal outputs no longer imply equal
    /// inputs, so a comparison would silently report "unchanged" for rows that
    /// actually differ.
    ValueDestroyed {
        /// The action both profiles applied.
        action: ResultMaskingDecisionAction,
    },
    /// The two profiles applied different actions to the same column — the
    /// masking policy has drifted between the two databases.
    ActionMismatch {
        /// Action applied by profile A.
        a: ResultMaskingDecisionAction,
        /// Action applied by profile B.
        b: ResultMaskingDecisionAction,
    },
    /// Both profiles tokenized the column, but not under the same salt. Result
    /// tokenization is salted per profile, so equal plaintext yields different
    /// tokens and every row would be reported as changed.
    SaltMismatch {
        /// Non-secret salt id used by profile A, if any.
        a: Option<String>,
        /// Non-secret salt id used by profile B, if any.
        b: Option<String>,
    },
    /// A masking certificate was present but carried no decision for the column.
    /// Treated as incomparable rather than assumed safe.
    DecisionMissing,
}

/// One column that cannot be compared across two profiles, and why.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncomparableMaskedColumn {
    /// Result-set column name.
    pub column: String,
    /// Why the two sides' masked values cannot prove equality or difference.
    pub reason: MaskComparabilityBreak,
}

fn column_decision<'a>(
    certificate: Option<&'a ResultMaskingCertificate>,
    column: &str,
) -> Option<&'a ResultMaskingColumnDecision> {
    certificate?
        .decisions
        .iter()
        .find(|decision| decision.column.eq_ignore_ascii_case(column))
}

/// Columns whose egress-mask decisions make a cross-profile value comparison
/// unsound.
///
/// A cross-database diff compares the **masked** rows: plaintext of a masked
/// column never leaves the server, and never enters the comparison. That is only
/// sound for a column whose masked form still preserves equality:
///
/// * both sides `pass` — the values are plaintext on both sides;
/// * both sides `tokenize` **under the same salt id** — tokenization is a
///   deterministic HMAC, so equal plaintext yields equal tokens.
///
/// Every other combination is reported here, and the caller must refuse.
/// [`ResultMaskingDecisionAction::Mask`] and [`ResultMaskingDecisionAction::Null`]
/// destroy the value, so equal outputs would no longer imply equal inputs —
/// comparing them would report "unchanged" for rows that really differ, the most
/// dangerous possible answer for a prod-vs-staging diff. Differing salts turn
/// identical rows into spurious changes, and a differing action is masking-policy
/// drift between the two databases.
///
/// A `None` certificate means the profile's policy transformed nothing, so every
/// column passed through as plaintext (see [`ResultMaskingPolicy::certificate_for_row`]).
///
/// Callers only need this when values are actually compared, i.e. when both sides
/// returned rows: if one side is empty, every row of the other is a pure
/// add/remove and no equality is ever evaluated.
#[must_use]
pub fn incomparable_masked_columns(
    columns: &[String],
    a: Option<&ResultMaskingCertificate>,
    b: Option<&ResultMaskingCertificate>,
) -> Vec<IncomparableMaskedColumn> {
    let mut incomparable = Vec::new();
    for column in columns {
        let decision_a = column_decision(a, column);
        let decision_b = column_decision(b, column);
        // A profile with no certificate transformed nothing, so every column is
        // plaintext. A profile *with* a certificate but no entry for this column
        // is an inconsistency we refuse to interpret.
        let (Some(action_a), Some(action_b)) = (
            certificate_action(a, decision_a),
            certificate_action(b, decision_b),
        ) else {
            incomparable.push(IncomparableMaskedColumn {
                column: column.clone(),
                reason: MaskComparabilityBreak::DecisionMissing,
            });
            continue;
        };
        if action_a != action_b {
            incomparable.push(IncomparableMaskedColumn {
                column: column.clone(),
                reason: MaskComparabilityBreak::ActionMismatch {
                    a: action_a,
                    b: action_b,
                },
            });
            continue;
        }
        match action_a {
            ResultMaskingDecisionAction::Pass => {}
            ResultMaskingDecisionAction::Tokenize => {
                let salt_a = decision_a.and_then(|decision| decision.salt_id.clone());
                let salt_b = decision_b.and_then(|decision| decision.salt_id.clone());
                if salt_a.is_none() || salt_a != salt_b {
                    incomparable.push(IncomparableMaskedColumn {
                        column: column.clone(),
                        reason: MaskComparabilityBreak::SaltMismatch {
                            a: salt_a,
                            b: salt_b,
                        },
                    });
                }
            }
            action @ (ResultMaskingDecisionAction::Mask | ResultMaskingDecisionAction::Null) => {
                incomparable.push(IncomparableMaskedColumn {
                    column: column.clone(),
                    reason: MaskComparabilityBreak::ValueDestroyed { action },
                });
            }
        }
    }
    incomparable
}

/// The action a profile applied to one column: `Pass` when the profile produced
/// no certificate at all, the recorded action when it did, and `None` when a
/// certificate exists but does not describe the column.
fn certificate_action(
    certificate: Option<&ResultMaskingCertificate>,
    decision: Option<&ResultMaskingColumnDecision>,
) -> Option<ResultMaskingDecisionAction> {
    match (certificate, decision) {
        (None, _) => Some(ResultMaskingDecisionAction::Pass),
        (Some(_), Some(decision)) => Some(decision.action),
        (Some(_), None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serialize::{SerializeOptions, serialize_row};
    use crate::types::OracleRow;
    use serde_json::json;

    fn vector_salt() -> ProfileMaskingSalt {
        ProfileMaskingSalt::new("profile:prod:masking:v1", (0_u8..32).collect::<Vec<_>>())
            .expect("valid vector salt")
    }

    #[test]
    fn token_function_matches_adr_0008_vector() {
        let policy = ResultMaskingPolicy::new(
            vec![ResultMaskingRule::column(
                "EMAIL",
                ResultMaskingAction::Tokenize,
            )],
            false,
        )
        .with_token_salt(vector_salt());
        let opts = SerializeOptions {
            result_masking: Some(policy),
            ..Default::default()
        };
        let row = OracleRow {
            columns: vec![(
                "EMAIL".to_owned(),
                OracleCell::new("VARCHAR2", Some("alice@example.com".to_owned())),
            )],
        };

        assert_eq!(
            serialize_row(&row, &opts),
            json!({ "EMAIL": "tok_v1_c0S0MQpi66BUrAwHZGZXoA" })
        );
    }

    #[test]
    fn mask_unknown_default_masks_unmatched_non_nulls_without_length_signal() {
        let opts = SerializeOptions {
            result_masking: Some(ResultMaskingPolicy::new(Vec::new(), true)),
            ..Default::default()
        };
        let row = OracleRow {
            columns: vec![
                (
                    "ID".to_owned(),
                    OracleCell::new("NUMBER", Some("123456789".to_owned())),
                ),
                (
                    "COMMENT".to_owned(),
                    OracleCell::new("VARCHAR2", Some("sensitive long text".to_owned())),
                ),
                ("NULLABLE".to_owned(), OracleCell::new("VARCHAR2", None)),
            ],
        };

        assert_eq!(
            serialize_row(&row, &opts),
            json!({
                "ID": MASKED_RESULT_VALUE,
                "COMMENT": MASKED_RESULT_VALUE,
                "NULLABLE": null,
            })
        );
    }

    #[test]
    fn transformed_columns_cannot_become_hybrid_filter_oracles() {
        let policy = ResultMaskingPolicy::new(
            vec![ResultMaskingRule::column(
                "SECRET",
                ResultMaskingAction::Mask,
            )],
            false,
        );
        assert!(policy.transforms_filter_column(Some("APP"), Some("DOCS"), "SECRET"));
        assert!(
            !policy.transforms_filter_column(Some("APP"), Some("DOCS"), "LABEL"),
            "a visible column may constrain a hybrid query"
        );
        assert!(
            ResultMaskingPolicy::new(Vec::new(), true).transforms_filter_column(
                Some("APP"),
                Some("DOCS"),
                "LABEL"
            ),
            "mask-unknown profiles fail closed rather than exposing row presence"
        );
    }

    #[test]
    fn tokenization_is_join_consistent_and_default_mask_blocks_side_channel() {
        let policy = ResultMaskingPolicy::new(
            vec![
                ResultMaskingRule::column("EMAIL_A", ResultMaskingAction::Tokenize),
                ResultMaskingRule::column("EMAIL_B", ResultMaskingAction::Tokenize),
            ],
            true,
        )
        .with_token_salt(vector_salt());
        let opts = SerializeOptions {
            result_masking: Some(policy),
            ..Default::default()
        };
        let row = OracleRow {
            columns: vec![
                (
                    "EMAIL_A".to_owned(),
                    OracleCell::new("VARCHAR2", Some("alice@example.com".to_owned())),
                ),
                (
                    "EMAIL_B".to_owned(),
                    OracleCell::new("VARCHAR2", Some("alice@example.com".to_owned())),
                ),
                (
                    "SSN".to_owned(),
                    OracleCell::new("VARCHAR2", Some("123-45-6789".to_owned())),
                ),
            ],
        };

        let rendered = serialize_row(&row, &opts);
        assert_eq!(rendered["EMAIL_A"], rendered["EMAIL_B"]);
        assert_eq!(rendered["SSN"], json!(MASKED_RESULT_VALUE));
        let rendered_text = rendered.to_string();
        assert!(!rendered_text.contains("alice@example.com"));
        assert!(!rendered_text.contains("123-45-6789"));
    }

    #[test]
    fn certificate_records_rederivable_column_decisions() {
        let policy = ResultMaskingPolicy::new(
            vec![
                ResultMaskingRule::column("EMAIL", ResultMaskingAction::Tokenize)
                    .with_policy_tag("pii.email"),
            ],
            true,
        )
        .with_profile("prod")
        .with_token_salt(vector_salt());
        let row = OracleRow {
            columns: vec![
                (
                    "EMAIL".to_owned(),
                    OracleCell::new("VARCHAR2", Some("alice@example.com".to_owned())),
                ),
                (
                    "NOTES".to_owned(),
                    OracleCell::new("CLOB", Some("sensitive notes".to_owned())),
                ),
            ],
        };

        let certificate = policy
            .certificate_for_row(&row)
            .expect("policy transforms at least one column");

        assert_eq!(certificate.schema_version, 1);
        assert_eq!(certificate.profile.as_deref(), Some("prod"));
        assert!(certificate.policy_id.starts_with("sha256:"));
        assert!(certificate.audit_entry_hash.is_none());
        assert_eq!(certificate.decisions.len(), 2);
        assert_eq!(certificate.decisions[0].column, "EMAIL");
        assert_eq!(
            certificate.decisions[0].action,
            ResultMaskingDecisionAction::Tokenize
        );
        assert_eq!(
            certificate.decisions[0].source,
            ResultMaskingDecisionSource::Rule
        );
        assert_eq!(certificate.decisions[0].rule_index, Some(0));
        assert_eq!(
            certificate.decisions[0].rule_tag.as_deref(),
            Some("pii.email")
        );
        assert_eq!(
            certificate.decisions[0].salt_id.as_deref(),
            Some("profile:prod:masking:v1")
        );
        assert_eq!(
            certificate.decisions[1].action,
            ResultMaskingDecisionAction::Mask
        );
        assert_eq!(
            certificate.decisions[1].source,
            ResultMaskingDecisionSource::MaskUnknownDefault
        );

        let rederived = policy
            .certificate_for_row(&row)
            .expect("same row rederives certificate");
        assert_eq!(certificate, rederived);
    }

    #[test]
    fn certificate_absent_when_policy_passes_every_column() {
        let policy = ResultMaskingPolicy::new(Vec::new(), false);
        let row = OracleRow {
            columns: vec![(
                "PUBLIC_ID".to_owned(),
                OracleCell::new("NUMBER", Some("42".to_owned())),
            )],
        };

        assert!(policy.certificate_for_row(&row).is_none());
    }

    #[test]
    fn salt_debug_and_validation_do_not_expose_material() {
        assert_eq!(
            ProfileMaskingSalt::new("", vec![0x11; 32]).unwrap_err(),
            MaskingPolicyError::EmptySaltId
        );
        assert_eq!(
            ProfileMaskingSalt::new("s1", vec![0x11; 31]).unwrap_err(),
            MaskingPolicyError::SaltTooShort {
                actual: 31,
                minimum: 32,
            }
        );
        let salt = ProfileMaskingSalt::new("s1", b"do-not-print-this-mask-salt-1234".to_vec())
            .expect("valid salt");
        let debug = format!("{salt:?}");
        assert!(debug.contains("s1"));
        assert!(!debug.contains("do-not-print"));
        assert!(!debug.contains("1234"));
    }

    fn decision(
        column: &str,
        action: ResultMaskingDecisionAction,
        salt_id: Option<&str>,
    ) -> ResultMaskingColumnDecision {
        ResultMaskingColumnDecision {
            column: column.to_owned(),
            oracle_type: "VARCHAR2".to_owned(),
            action,
            source: ResultMaskingDecisionSource::Rule,
            rule_index: Some(0),
            rule_tag: None,
            salt_id: salt_id.map(str::to_owned),
        }
    }

    fn certificate(decisions: Vec<ResultMaskingColumnDecision>) -> ResultMaskingCertificate {
        ResultMaskingCertificate {
            schema_version: 1,
            profile: Some("prod".to_owned()),
            policy_id: "sha256:test".to_owned(),
            decisions,
            audit_entry_hash: None,
        }
    }

    fn columns(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    #[test]
    fn unmasked_profiles_compare_every_column() {
        assert!(incomparable_masked_columns(&columns(&["ID", "EMAIL"]), None, None).is_empty());
    }

    #[test]
    fn same_salt_tokenization_is_comparable_but_a_different_salt_is_not() {
        let shared = certificate(vec![decision(
            "EMAIL",
            ResultMaskingDecisionAction::Tokenize,
            Some("fleet:v1"),
        )]);
        assert!(
            incomparable_masked_columns(&columns(&["EMAIL"]), Some(&shared), Some(&shared))
                .is_empty(),
            "one deterministic salt on both sides preserves equality"
        );

        let other = certificate(vec![decision(
            "EMAIL",
            ResultMaskingDecisionAction::Tokenize,
            Some("staging:v1"),
        )]);
        assert_eq!(
            incomparable_masked_columns(&columns(&["EMAIL"]), Some(&shared), Some(&other)),
            vec![IncomparableMaskedColumn {
                column: "EMAIL".to_owned(),
                reason: MaskComparabilityBreak::SaltMismatch {
                    a: Some("fleet:v1".to_owned()),
                    b: Some("staging:v1".to_owned()),
                },
            }],
            "per-profile salts make identical plaintext look changed"
        );
    }

    #[test]
    fn tokenization_without_an_active_salt_is_never_comparable() {
        // A tokenize rule with no salt degrades to `<masked>` at the transformer
        // seam, so both sides collapse to the same marker and equality is a lie.
        let unsalted = certificate(vec![decision(
            "EMAIL",
            ResultMaskingDecisionAction::Tokenize,
            None,
        )]);
        assert_eq!(
            incomparable_masked_columns(&columns(&["EMAIL"]), Some(&unsalted), Some(&unsalted)),
            vec![IncomparableMaskedColumn {
                column: "EMAIL".to_owned(),
                reason: MaskComparabilityBreak::SaltMismatch { a: None, b: None },
            }]
        );
    }

    #[test]
    fn value_destroying_actions_are_refused_on_both_sides() {
        for action in [
            ResultMaskingDecisionAction::Mask,
            ResultMaskingDecisionAction::Null,
        ] {
            let cert = certificate(vec![decision("SSN", action, None)]);
            assert_eq!(
                incomparable_masked_columns(&columns(&["SSN"]), Some(&cert), Some(&cert)),
                vec![IncomparableMaskedColumn {
                    column: "SSN".to_owned(),
                    reason: MaskComparabilityBreak::ValueDestroyed { action },
                }],
                "{action:?} collapses distinct values, so `unchanged` would be a false negative"
            );
        }
    }

    #[test]
    fn policy_drift_between_profiles_is_an_action_mismatch() {
        let masked = certificate(vec![decision(
            "SSN",
            ResultMaskingDecisionAction::Mask,
            None,
        )]);
        // The other profile has no policy at all, so its column passes through.
        assert_eq!(
            incomparable_masked_columns(&columns(&["SSN"]), Some(&masked), None),
            vec![IncomparableMaskedColumn {
                column: "SSN".to_owned(),
                reason: MaskComparabilityBreak::ActionMismatch {
                    a: ResultMaskingDecisionAction::Mask,
                    b: ResultMaskingDecisionAction::Pass,
                },
            }]
        );
    }

    #[test]
    fn a_certificate_missing_a_column_fails_closed() {
        let cert = certificate(vec![decision(
            "EMAIL",
            ResultMaskingDecisionAction::Mask,
            None,
        )]);
        assert_eq!(
            incomparable_masked_columns(&columns(&["SSN"]), Some(&cert), Some(&cert)),
            vec![IncomparableMaskedColumn {
                column: "SSN".to_owned(),
                reason: MaskComparabilityBreak::DecisionMissing,
            }],
            "an unexplained column is refused, never assumed to have passed through"
        );
    }

    #[test]
    fn only_the_offending_columns_are_reported() {
        let cert = certificate(vec![
            decision("ID", ResultMaskingDecisionAction::Pass, None),
            decision("EMAIL", ResultMaskingDecisionAction::Mask, None),
        ]);
        let breaks =
            incomparable_masked_columns(&columns(&["ID", "EMAIL"]), Some(&cert), Some(&cert));
        assert_eq!(breaks.len(), 1);
        assert_eq!(breaks[0].column, "EMAIL");
    }

    #[test]
    fn column_lookup_is_case_insensitive() {
        let cert = certificate(vec![decision(
            "email",
            ResultMaskingDecisionAction::Mask,
            None,
        )]);
        assert_eq!(
            incomparable_masked_columns(&columns(&["EMAIL"]), Some(&cert), Some(&cert))
                .first()
                .map(|entry| entry.reason.clone()),
            Some(MaskComparabilityBreak::ValueDestroyed {
                action: ResultMaskingDecisionAction::Mask
            })
        );
    }
}
