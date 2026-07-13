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
}
