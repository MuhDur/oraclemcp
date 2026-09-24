//! Typed AND-only predicates for scoped grants.
//!
//! Requests contain typed scalar values rather than SQL fragments. This
//! module validates them against catalog column metadata, retains values in
//! zeroizing grant values, and renders only server-named bind placeholders.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;

use sqlparser::ast::{BinaryOperator, Expr, Ident, Value};
use sqlparser::dialect::OracleDialect;
use sqlparser::parser::Parser;

use super::{GrantComparison, GrantOp, GrantOperand, GrantPredicateV1, GrantValue, GrantValueKind};

pub const MAX_PREDICATE_IN_VALUES: usize = 1000;
const MAX_NUMBER_PRECISION: u8 = 38;
const MAX_NUMBER_TEXT_BYTES: usize = 256;

/// The exact wire-level operator vocabulary accepted by the request adapter.
/// SQL spellings, case variants, and synonyms are intentionally not accepted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PredicateOperator {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    In,
    Between,
    IsNull,
    IsNotNull,
}

impl PredicateOperator {
    fn parse(token: &str) -> Result<Self, PredicateRefusal> {
        match token {
            "eq" => Ok(Self::Eq),
            "ne" => Ok(Self::Ne),
            "lt" => Ok(Self::Lt),
            "le" => Ok(Self::Le),
            "gt" => Ok(Self::Gt),
            "ge" => Ok(Self::Ge),
            "in" => Ok(Self::In),
            "between" => Ok(Self::Between),
            "is_null" => Ok(Self::IsNull),
            "is_not_null" => Ok(Self::IsNotNull),
            "or" | "not" => Err(PredicateRefusal::OrNotUnsupported),
            _ => Err(PredicateRefusal::InvalidOperator),
        }
    }
}

/// One resolved target-column type supplied by the catalog layer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PredicateColumnType {
    Number {
        precision: Option<u8>,
        scale: Option<i8>,
    },
    Varchar2 {
        max_bytes: u32,
        max_chars: u32,
    },
    Nvarchar2 {
        max_chars: u32,
    },
    Char {
        max_bytes: u32,
        max_chars: u32,
    },
    Date,
    Timestamp {
        fractional_precision: u8,
    },
}

impl PredicateColumnType {
    fn expected(&self) -> &'static str {
        match self {
            Self::Number { .. } => "NUMBER",
            Self::Varchar2 { .. } => "VARCHAR2",
            Self::Nvarchar2 { .. } => "NVARCHAR2",
            Self::Char { .. } => "CHAR",
            Self::Date => "DATE",
            Self::Timestamp { .. } => "TIMESTAMP",
        }
    }

    fn validate_metadata(&self) -> bool {
        match self {
            Self::Number { precision, scale } => {
                precision.is_none_or(|p| (1..=MAX_NUMBER_PRECISION).contains(&p))
                    && scale.is_none_or(|s| (-84..=127).contains(&s))
            }
            Self::Varchar2 {
                max_bytes,
                max_chars,
            }
            | Self::Char {
                max_bytes,
                max_chars,
            } => *max_bytes > 0 && *max_chars > 0,
            Self::Nvarchar2 { max_chars } => *max_chars > 0,
            Self::Timestamp {
                fractional_precision,
            } => *fractional_precision <= 9,
            Self::Date => true,
        }
    }
}

/// Catalog-resolved columns of the one target object. Names are exact catalog
/// names; no SQL spelling is used as a substitute for resolution.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ResolvedColumns(BTreeMap<String, PredicateColumnType>);

impl ResolvedColumns {
    pub fn new(
        columns: impl IntoIterator<Item = (String, PredicateColumnType)>,
    ) -> Result<Self, PredicateRefusal> {
        let mut resolved = BTreeMap::new();
        for (name, column_type) in columns {
            if name.is_empty() || name.len() > 128 || name.contains('\0') {
                return Err(PredicateRefusal::InvalidColumnMetadata);
            }
            if !column_type.validate_metadata() || resolved.insert(name, column_type).is_some() {
                return Err(PredicateRefusal::InvalidColumnMetadata);
            }
        }
        Ok(Self(resolved))
    }

    #[must_use]
    pub fn get(&self, name: &str) -> Option<&PredicateColumnType> {
        self.0.get(name)
    }
}

/// JSON scalar value after strict request decoding. Numeric text is retained
/// exactly so NUMBER precision is never lost through an intermediate float.
#[derive(Clone, Eq, PartialEq)]
pub enum PredicateInputValue {
    Number(String),
    String(String),
    Null,
    Expression(PredicateExpressionRequest),
    Unsupported,
}

impl fmt::Debug for PredicateInputValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Number(_) => "<number>",
            Self::String(_) => "<string>",
            Self::Null => "null",
            Self::Expression(_) => "<expression-refused>",
            Self::Unsupported => "<unsupported-value>",
        })
    }
}

/// Expression-shaped request values are represented only so the builder can
/// return a typed refusal; the JSON adapter must never turn SQL text into one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PredicateExpressionRequest {
    Subquery,
    Function,
    Column(String),
    Bind(String),
    Or,
    Not,
}

/// One JSON request object. Exactly the fields appropriate to `op` may be set.
#[derive(Clone, Eq, PartialEq)]
pub struct PredicateConjunctRequest {
    pub column: String,
    pub op: String,
    pub value: Option<PredicateInputValue>,
    pub values: Option<Vec<PredicateInputValue>>,
    pub low: Option<PredicateInputValue>,
    pub high: Option<PredicateInputValue>,
}

impl fmt::Debug for PredicateConjunctRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PredicateConjunctRequest")
            .field("column", &self.column)
            .field("op", &self.op)
            .field("has_value", &self.value.is_some())
            .field("values_count", &self.values.as_ref().map(Vec::len))
            .field("has_low", &self.low.is_some())
            .field("has_high", &self.high.is_some())
            .finish()
    }
}

impl PredicateConjunctRequest {
    #[must_use]
    pub fn comparison(
        column: impl Into<String>,
        op: impl Into<String>,
        value: PredicateInputValue,
    ) -> Self {
        Self {
            column: column.into(),
            op: op.into(),
            value: Some(value),
            values: None,
            low: None,
            high: None,
        }
    }

    #[must_use]
    pub fn in_list(column: impl Into<String>, values: Vec<PredicateInputValue>) -> Self {
        Self {
            column: column.into(),
            op: "in".into(),
            value: None,
            values: Some(values),
            low: None,
            high: None,
        }
    }

    #[must_use]
    pub fn between(
        column: impl Into<String>,
        low: PredicateInputValue,
        high: PredicateInputValue,
    ) -> Self {
        Self {
            column: column.into(),
            op: "between".into(),
            value: None,
            values: None,
            low: Some(low),
            high: Some(high),
        }
    }

    #[must_use]
    pub fn is_null(column: impl Into<String>, negated: bool) -> Self {
        Self {
            column: column.into(),
            op: if negated { "is_not_null" } else { "is_null" }.into(),
            value: None,
            values: None,
            low: None,
            high: None,
        }
    }
}

/// A typed, value-free refusal from predicate construction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PredicateRefusal {
    OrNotUnsupported,
    SubqueryRefused,
    FunctionRefused,
    ColumnToColumnRefused,
    InListTooLarge {
        len: usize,
    },
    InListEmpty,
    UnknownColumn {
        column: String,
    },
    TypeMismatch {
        column: String,
        expected: &'static str,
    },
    NullComparison,
    ReservedBindName,
    InvalidColumnMetadata,
    InvalidOperator,
    InvalidOperandShape,
    InvalidValue,
    InvertedRange,
    UnsupportedExpression,
}

impl PredicateRefusal {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::OrNotUnsupported => "GRANT_PREDICATE_OR_NOT_UNSUPPORTED",
            Self::SubqueryRefused => "GRANT_PREDICATE_SUBQUERY_REFUSED",
            Self::FunctionRefused => "GRANT_PREDICATE_FUNCTION_REFUSED",
            Self::ColumnToColumnRefused => "GRANT_PREDICATE_COLUMN_COMPARE_REFUSED",
            Self::InListTooLarge { .. } => "GRANT_PREDICATE_IN_LIST_TOO_LARGE",
            Self::InListEmpty => "GRANT_PREDICATE_IN_LIST_EMPTY",
            Self::UnknownColumn { .. } => "GRANT_PREDICATE_COLUMN_UNKNOWN",
            Self::TypeMismatch { .. } => "GRANT_PREDICATE_TYPE_MISMATCH",
            Self::NullComparison => "GRANT_PREDICATE_NULL_COMPARISON",
            Self::ReservedBindName => "GRANT_PREDICATE_RESERVED_BIND",
            Self::InvalidColumnMetadata => "GRANT_PREDICATE_COLUMN_METADATA_INVALID",
            Self::InvalidOperator => "GRANT_PREDICATE_OPERATOR_INVALID",
            Self::InvalidOperandShape => "GRANT_PREDICATE_OPERAND_SHAPE_INVALID",
            Self::InvalidValue => "GRANT_PREDICATE_VALUE_INVALID",
            Self::InvertedRange => "GRANT_PREDICATE_RANGE_INVERTED",
            Self::UnsupportedExpression => "GRANT_PREDICATE_EXPRESSION_UNSUPPORTED",
        }
    }
}

impl fmt::Display for PredicateRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for PredicateRefusal {}

/// Validates structured conjuncts against a resolved target column catalog.
pub struct GrantPredicateBuilder;

impl GrantPredicateBuilder {
    pub fn from_request(
        conjuncts: &[PredicateConjunctRequest],
        columns: &ResolvedColumns,
    ) -> Result<GrantPredicateV1, PredicateRefusal> {
        if conjuncts.is_empty() {
            return Err(PredicateRefusal::InvalidOperandShape);
        }
        let mut built = Vec::with_capacity(conjuncts.len());
        for request in conjuncts {
            built.push(build_comparison(request, columns)?);
        }
        Ok(GrantPredicateV1::new(built))
    }
}

fn build_comparison(
    request: &PredicateConjunctRequest,
    columns: &ResolvedColumns,
) -> Result<GrantComparison, PredicateRefusal> {
    let op = match PredicateOperator::parse(&request.op)? {
        PredicateOperator::Eq => GrantOp::Eq,
        PredicateOperator::Ne => GrantOp::NotEq,
        PredicateOperator::Lt => GrantOp::Lt,
        PredicateOperator::Le => GrantOp::Le,
        PredicateOperator::Gt => GrantOp::Gt,
        PredicateOperator::Ge => GrantOp::Ge,
        PredicateOperator::In => GrantOp::In,
        PredicateOperator::Between => GrantOp::Between,
        PredicateOperator::IsNull => GrantOp::IsNull,
        PredicateOperator::IsNotNull => GrantOp::IsNotNull,
    };
    let column = request.column.clone();
    let column_type = columns
        .get(&column)
        .ok_or_else(|| PredicateRefusal::UnknownColumn {
            column: column.clone(),
        })?;
    let operand = match op {
        GrantOp::IsNull | GrantOp::IsNotNull => {
            ensure_shape(request, false, false, false)?;
            GrantOperand::None
        }
        GrantOp::In => {
            ensure_shape(request, false, true, false)?;
            let values = request
                .values
                .as_ref()
                .ok_or(PredicateRefusal::InListEmpty)?;
            if values.is_empty() {
                return Err(PredicateRefusal::InListEmpty);
            }
            if values.len() > MAX_PREDICATE_IN_VALUES {
                return Err(PredicateRefusal::InListTooLarge { len: values.len() });
            }
            let mut built = values
                .iter()
                .map(|value| build_value(value, &column, column_type))
                .collect::<Result<Vec<_>, _>>()?;
            built.sort_by(|left, right| {
                left.kind()
                    .as_str()
                    .cmp(right.kind().as_str())
                    .then_with(|| left.expose_canonical().cmp(right.expose_canonical()))
            });
            built.dedup();
            GrantOperand::List(built)
        }
        GrantOp::Between => {
            ensure_shape(request, false, false, true)?;
            let low = build_value(
                request
                    .low
                    .as_ref()
                    .ok_or(PredicateRefusal::InvalidOperandShape)?,
                &column,
                column_type,
            )?;
            let high = build_value(
                request
                    .high
                    .as_ref()
                    .ok_or(PredicateRefusal::InvalidOperandShape)?,
                &column,
                column_type,
            )?;
            if compare_values(&low, &high) == Ordering::Greater {
                return Err(PredicateRefusal::InvertedRange);
            }
            GrantOperand::Range(low, high)
        }
        _ => {
            ensure_shape(request, true, false, false)?;
            GrantOperand::Single(build_value(
                request
                    .value
                    .as_ref()
                    .ok_or(PredicateRefusal::InvalidOperandShape)?,
                &column,
                column_type,
            )?)
        }
    };
    let column = super::ColumnIdent::new(column).map_err(|_| PredicateRefusal::InvalidValue)?;
    Ok(GrantComparison {
        column,
        op,
        operand,
    })
}

fn ensure_shape(
    request: &PredicateConjunctRequest,
    value: bool,
    values: bool,
    range: bool,
) -> Result<(), PredicateRefusal> {
    if request.value.is_some() != value
        || request.values.is_some() != values
        || request.low.is_some() != range
        || request.high.is_some() != range
    {
        Err(PredicateRefusal::InvalidOperandShape)
    } else {
        Ok(())
    }
}

fn build_value(
    input: &PredicateInputValue,
    column: &str,
    column_type: &PredicateColumnType,
) -> Result<GrantValue, PredicateRefusal> {
    if matches!(input, PredicateInputValue::Null) {
        return Err(PredicateRefusal::NullComparison);
    }
    if let PredicateInputValue::Expression(expression) = input {
        return Err(match expression {
            PredicateExpressionRequest::Subquery => PredicateRefusal::SubqueryRefused,
            PredicateExpressionRequest::Function => PredicateRefusal::FunctionRefused,
            PredicateExpressionRequest::Column(_) => PredicateRefusal::ColumnToColumnRefused,
            PredicateExpressionRequest::Bind(name)
                if name
                    .strip_prefix(':')
                    .unwrap_or(name)
                    .to_ascii_uppercase()
                    .starts_with("OMCP_G") =>
            {
                PredicateRefusal::ReservedBindName
            }
            PredicateExpressionRequest::Bind(_) => PredicateRefusal::UnsupportedExpression,
            PredicateExpressionRequest::Or | PredicateExpressionRequest::Not => {
                PredicateRefusal::OrNotUnsupported
            }
        });
    }
    let value = match (column_type, input) {
        (PredicateColumnType::Number { precision, scale }, PredicateInputValue::Number(text)) => {
            let value =
                GrantValue::number(text.clone()).map_err(|_| PredicateRefusal::InvalidValue)?;
            if !number_fits(value.expose_canonical(), *precision, *scale) {
                return Err(PredicateRefusal::TypeMismatch {
                    column: column.to_owned(),
                    expected: column_type.expected(),
                });
            }
            value
        }
        (
            PredicateColumnType::Varchar2 {
                max_bytes,
                max_chars,
            }
            | PredicateColumnType::Char {
                max_bytes,
                max_chars,
            },
            PredicateInputValue::String(text),
        ) if text.len() <= *max_bytes as usize && text.chars().count() <= *max_chars as usize => {
            GrantValue::text(text.clone()).map_err(|_| PredicateRefusal::InvalidValue)?
        }
        (PredicateColumnType::Nvarchar2 { max_chars }, PredicateInputValue::String(text))
            if text.chars().count() <= *max_chars as usize =>
        {
            GrantValue::text(text.clone()).map_err(|_| PredicateRefusal::InvalidValue)?
        }
        (PredicateColumnType::Date, PredicateInputValue::String(text)) => {
            if !valid_date(text) {
                return Err(PredicateRefusal::InvalidValue);
            }
            GrantValue::date(text.clone()).map_err(|_| PredicateRefusal::InvalidValue)?
        }
        (
            PredicateColumnType::Timestamp {
                fractional_precision,
            },
            PredicateInputValue::String(text),
        ) => {
            if !valid_timestamp(text, *fractional_precision) {
                return Err(PredicateRefusal::InvalidValue);
            }
            GrantValue::timestamp(text.clone()).map_err(|_| PredicateRefusal::InvalidValue)?
        }
        _ => {
            return Err(PredicateRefusal::TypeMismatch {
                column: column.to_owned(),
                expected: column_type.expected(),
            });
        }
    };
    Ok(value)
}

fn number_fits(text: &str, precision: Option<u8>, scale: Option<i8>) -> bool {
    if text.len() > MAX_NUMBER_TEXT_BYTES {
        return false;
    }
    let unsigned = text.strip_prefix('-').unwrap_or(text);
    let (integer, fraction) = unsigned.split_once('.').unwrap_or((unsigned, ""));
    let integer_digits = integer.trim_start_matches('0').len();
    let fraction_digits = fraction.len();
    let significant_digits = integer_digits + fraction.trim_start_matches('0').len();
    if significant_digits > usize::from(MAX_NUMBER_PRECISION) || integer_digits > 126 {
        return false;
    }
    if precision.is_none() && scale.is_none() {
        return true;
    }
    let scale = scale.unwrap_or(0);
    if scale >= 0 {
        if fraction_digits > scale as usize {
            return false;
        }
        if let Some(precision) = precision {
            integer_digits <= usize::from(precision.saturating_sub(scale as u8))
                && significant_digits <= usize::from(precision)
        } else {
            true
        }
    } else {
        let zeroes = usize::from(scale.unsigned_abs());
        if significant_digits == 0 {
            return true;
        }
        if fraction_digits != 0 || !integer.ends_with(&"0".repeat(zeroes)) {
            return false;
        }
        precision.is_none_or(|p| {
            integer_digits <= usize::from(p) + zeroes
                && integer.trim_end_matches('0').len() <= usize::from(p)
        })
    }
}

fn valid_date(text: &str) -> bool {
    if text.len() != 19 || !super::is_canonical_date(text) {
        return false;
    }
    let bytes = text.as_bytes();
    let year = parse_digits(&bytes[0..4]);
    let month = parse_digits(&bytes[5..7]);
    let day = parse_digits(&bytes[8..10]);
    let hour = parse_digits(&bytes[11..13]);
    let minute = parse_digits(&bytes[14..16]);
    let second = parse_digits(&bytes[17..19]);
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) =
        (year, month, day, hour, minute, second)
    else {
        return false;
    };
    valid_ymd(year, month, day) && hour <= 23 && minute <= 59 && second <= 59
}

fn valid_timestamp(text: &str, precision: u8) -> bool {
    let Some((date, time)) = text.split_once('T') else {
        return false;
    };
    let clock = time.split_once('.').map_or(time, |(clock, _)| clock);
    let date_bytes = date.as_bytes();
    let clock_bytes = clock.as_bytes();
    let Some((year, month, day)) = parse_date(date_bytes) else {
        return false;
    };
    let Some((hour, minute, second)) = parse_clock(clock_bytes) else {
        return false;
    };
    let fraction_ok = match time.split_once('.') {
        None => true,
        Some((_, fraction)) => {
            !fraction.is_empty()
                && fraction.len() <= usize::from(precision)
                && fraction.len() <= 9
                && fraction.bytes().all(|byte| byte.is_ascii_digit())
                && !fraction.ends_with('0')
        }
    };
    valid_ymd(year, month, day) && hour <= 23 && minute <= 59 && second <= 59 && fraction_ok
}

fn valid_ymd(year: u32, month: u32, day: u32) -> bool {
    if !(1..=12).contains(&month) {
        return false;
    }
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    (1..=days).contains(&day)
}

fn parse_digits(bytes: &[u8]) -> Option<u32> {
    bytes.iter().try_fold(0_u32, |number, digit| {
        digit
            .is_ascii_digit()
            .then(|| number * 10 + u32::from(*digit - b'0'))
    })
}

fn parse_date(bytes: &[u8]) -> Option<(u32, u32, u32)> {
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    Some((
        parse_digits(&bytes[..4])?,
        parse_digits(&bytes[5..7])?,
        parse_digits(&bytes[8..10])?,
    ))
}

fn parse_clock(bytes: &[u8]) -> Option<(u32, u32, u32)> {
    if bytes.len() != 8 || bytes[2] != b':' || bytes[5] != b':' {
        return None;
    }
    Some((
        parse_digits(&bytes[..2])?,
        parse_digits(&bytes[3..5])?,
        parse_digits(&bytes[6..8])?,
    ))
}

fn compare_values(left: &GrantValue, right: &GrantValue) -> Ordering {
    match left.kind() {
        GrantValueKind::Number => {
            compare_numbers(left.expose_canonical(), right.expose_canonical())
        }
        GrantValueKind::Text | GrantValueKind::Date | GrantValueKind::Timestamp => {
            left.expose_canonical().cmp(right.expose_canonical())
        }
    }
}

fn compare_numbers(left: &str, right: &str) -> Ordering {
    let (left_negative, left) = (left.starts_with('-'), left.trim_start_matches('-'));
    let (right_negative, right) = (right.starts_with('-'), right.trim_start_matches('-'));
    if left_negative != right_negative {
        return if left_negative {
            Ordering::Less
        } else {
            Ordering::Greater
        };
    }
    let mut result = compare_positive_numbers(left, right);
    if left_negative {
        result = result.reverse();
    }
    result
}

fn compare_positive_numbers(left: &str, right: &str) -> Ordering {
    let (left_int, left_frac) = left.split_once('.').unwrap_or((left, ""));
    let (right_int, right_frac) = right.split_once('.').unwrap_or((right, ""));
    let left_int = left_int.trim_start_matches('0');
    let right_int = right_int.trim_start_matches('0');
    let int_order = left_int.len().cmp(&right_int.len());
    if int_order != Ordering::Equal {
        return int_order;
    }
    let int_order = left_int.cmp(right_int);
    if int_order != Ordering::Equal {
        return int_order;
    }
    let width = left_frac.len().max(right_frac.len());
    left_frac
        .bytes()
        .chain(std::iter::repeat(b'0'))
        .take(width)
        .cmp(
            right_frac
                .bytes()
                .chain(std::iter::repeat(b'0'))
                .take(width),
        )
}

/// A server-generated predicate bind. Its debug representation never reveals
/// the value.
#[derive(Clone)]
pub struct GrantBind {
    name: String,
    value: GrantValue,
}

impl GrantBind {
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn value(&self) -> &GrantValue {
        &self.value
    }
}

impl fmt::Debug for GrantBind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GrantBind")
            .field("name", &self.name)
            .field("value", &self.value)
            .finish()
    }
}

/// Render a validated predicate as AST nodes and positional server-owned bind
/// descriptors. No value text is serialized into the SQL expression.
#[must_use]
pub fn render_ast(predicate: &GrantPredicateV1) -> (Expr, Vec<GrantBind>) {
    let mut binds = Vec::new();
    let mut expression = predicate
        .conjuncts()
        .iter()
        .map(|comparison| render_comparison(comparison, &mut binds));
    let first = expression
        .next()
        .unwrap_or_else(|| Expr::Value(Value::Boolean(false).into()));
    let combined = expression.fold(first, |left, right| Expr::BinaryOp {
        left: Box::new(Expr::Nested(Box::new(left))),
        op: BinaryOperator::And,
        right: Box::new(Expr::Nested(Box::new(right))),
    });
    (combined, binds)
}

fn render_comparison(comparison: &GrantComparison, binds: &mut Vec<GrantBind>) -> Expr {
    let column = Expr::Identifier(Ident::with_quote('"', comparison.column.as_str()));
    let mut bind_expr = |value: &GrantValue| {
        let name = format!("omcp_g{}", binds.len() + 1);
        binds.push(GrantBind {
            name: name.clone(),
            value: value.clone(),
        });
        Expr::Value(Value::Placeholder(format!(":{name}")).into())
    };
    match &comparison.operand {
        GrantOperand::None => match comparison.op {
            GrantOp::IsNull => Expr::IsNull(Box::new(column)),
            GrantOp::IsNotNull => Expr::IsNotNull(Box::new(column)),
            _ => Expr::Value(Value::Boolean(false).into()),
        },
        GrantOperand::Single(value) => Expr::BinaryOp {
            left: Box::new(column),
            op: match comparison.op {
                GrantOp::Eq => BinaryOperator::Eq,
                GrantOp::NotEq => BinaryOperator::NotEq,
                GrantOp::Lt => BinaryOperator::Lt,
                GrantOp::Le => BinaryOperator::LtEq,
                GrantOp::Gt => BinaryOperator::Gt,
                GrantOp::Ge => BinaryOperator::GtEq,
                _ => return Expr::Value(Value::Boolean(false).into()),
            },
            right: Box::new(bind_expr(value)),
        },
        GrantOperand::List(values) => Expr::InList {
            expr: Box::new(column),
            list: values.iter().map(&mut bind_expr).collect(),
            negated: false,
        },
        GrantOperand::Range(low, high) => Expr::Between {
            expr: Box::new(column),
            negated: false,
            low: Box::new(bind_expr(low)),
            high: Box::new(bind_expr(high)),
        },
    }
}

/// Structurally conjoin the caller filter, policy narrowing and grant filter.
/// Each source expression remains a nested AST child; no SQL text is spliced.
#[must_use]
pub fn compose_where(caller: Option<Expr>, policy_q: Option<Expr>, grant_p: Expr) -> Expr {
    let mut parts = [caller, policy_q, Some(grant_p)].into_iter().flatten();
    let first = parts
        .next()
        .unwrap_or_else(|| Expr::Value(Value::Boolean(false).into()));
    parts.fold(first, |left, right| Expr::BinaryOp {
        left: Box::new(Expr::Nested(Box::new(left))),
        op: BinaryOperator::And,
        right: Box::new(Expr::Nested(Box::new(right))),
    })
}

/// Round-trip one rendered predicate through the Oracle parser and require
/// exact AST equality. Intended for tests and the fuzz structural oracle.
pub fn parse_rendered_ast(expression: &Expr) -> Result<Expr, PredicateRefusal> {
    let sql = expression.to_string();
    let mut parser = Parser::new(&OracleDialect {})
        .try_with_sql(&sql)
        .map_err(|_| PredicateRefusal::InvalidValue)?;
    let parsed = parser
        .parse_expr()
        .map_err(|_| PredicateRefusal::InvalidValue)?;
    parser
        .expect_token(&sqlparser::tokenizer::Token::EOF)
        .map_err(|_| PredicateRefusal::InvalidValue)?;
    Ok(parsed)
}
