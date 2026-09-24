//! JSON request decoding that refuses duplicate object members before a
//! JSON-RPC request can be interpreted by dispatch or an approval surface.

use std::cell::RefCell;

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

#[derive(Debug, thiserror::Error)]
pub enum StrictJsonError {
    #[error("duplicate JSON member at one or more JSON pointers")]
    DuplicateMember { json_pointers: Vec<String> },
    #[error("invalid JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
}

impl StrictJsonError {
    pub fn duplicate_pointer(&self) -> Option<&str> {
        match self {
            Self::DuplicateMember { json_pointers } => json_pointers.first().map(String::as_str),
            Self::InvalidJson(_) => None,
        }
    }

    /// Every duplicated member observed while decoding the complete JSON
    /// value. Keeping the full set lets transports distinguish ambiguous
    /// request-envelope fields from duplicate tool arguments.
    pub fn duplicate_pointers(&self) -> &[String] {
        match self {
            Self::DuplicateMember { json_pointers } => json_pointers,
            Self::InvalidJson(_) => &[],
        }
    }

    pub fn jsonrpc_parse_error_response(&self) -> Value {
        let mut response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": null,
            "error": { "code": -32700, "message": "Parse error" }
        });
        if let Some(json_pointer) = self.duplicate_pointer() {
            response["error"]["data"] = serde_json::json!({"json_pointer": json_pointer});
        }
        response
    }
}

pub fn decode_strict_value(bytes: &[u8]) -> Result<Value, StrictJsonError> {
    let duplicates = RefCell::new(Vec::new());
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let decoded = ValueSeed {
        path: String::new(),
        duplicates: &duplicates,
    }
    .deserialize(&mut decoder)
    .and_then(|value| decoder.end().map(|()| value));
    let duplicate_pointers = duplicates.into_inner();
    match decoded {
        Ok(value) if duplicate_pointers.is_empty() => Ok(value),
        Ok(_) => Err(duplicate_member_error(duplicate_pointers)),
        Err(_error) if !duplicate_pointers.is_empty() => {
            Err(duplicate_member_error(duplicate_pointers))
        }
        Err(error) => Err(StrictJsonError::InvalidJson(error)),
    }
}

fn duplicate_member_error(json_pointers: Vec<String>) -> StrictJsonError {
    for json_pointer in &json_pointers {
        tracing::warn!(class = "duplicate_json_member", %json_pointer, "JSON request refused");
    }
    StrictJsonError::DuplicateMember { json_pointers }
}

struct ValueSeed<'a> {
    path: String,
    duplicates: &'a RefCell<Vec<String>>,
}

impl<'de> DeserializeSeed<'de> for ValueSeed<'_> {
    type Value = Value;

    fn deserialize<D: de::Deserializer<'de>>(self, decoder: D) -> Result<Value, D::Error> {
        decoder.deserialize_any(ValueVisitor(self))
    }
}

struct ValueVisitor<'a>(ValueSeed<'a>);

impl<'de> Visitor<'de> for ValueVisitor<'_> {
    type Value = Value;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Value, E> {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }

    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_none<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = seq.next_element_seed(ValueSeed {
            path: child_pointer(&self.0.path, &values.len().to_string()),
            duplicates: self.0.duplicates,
        })? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            let pointer = child_pointer(&self.0.path, &key);
            let duplicate = values.contains_key(&key);
            if duplicate {
                self.0.duplicates.borrow_mut().push(pointer.clone());
            }
            let value = map.next_value_seed(ValueSeed {
                path: pointer,
                duplicates: self.0.duplicates,
            })?;
            if !duplicate {
                values.insert(key, value);
            }
        }
        Ok(Value::Object(values))
    }
}

fn child_pointer(parent: &str, member: &str) -> String {
    format!("{parent}/{}", member.replace('~', "~0").replace('/', "~1"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;

    fn duplicate_pointer(bytes: &[u8]) -> String {
        decode_strict_value(bytes)
            .expect_err("duplicate must be refused")
            .duplicate_pointer()
            .expect("typed duplicate pointer")
            .to_owned()
    }

    #[test]
    fn rejects_duplicate_top_level_member() {
        assert_eq!(duplicate_pointer(br#"{"sql":"A","sql":"B"}"#), "/sql");
    }

    #[test]
    fn rejects_duplicate_nested_member_in_arguments() {
        assert_eq!(
            duplicate_pointer(br#"{"params":{"arguments":{"sql":"A","sql":"B"}}}"#),
            "/params/arguments/sql"
        );
        assert_eq!(
            duplicate_pointer(br#"{"params":{"arguments":{"options":{"a/b~c":1,"a/b~c":2}}}}"#),
            "/params/arguments/options/a~1b~0c"
        );
        assert_eq!(
            duplicate_pointer(br#"{"items":[{"x":1,"x":2}]}"#),
            "/items/0/x"
        );
    }

    #[test]
    fn rejects_duplicate_id_member() {
        assert_eq!(duplicate_pointer(br#"{"id":1,"id":2}"#), "/id");
    }

    #[test]
    fn accepts_duplicate_free_frames() {
        for bytes in [
            br#"{"id":1,"params":{"arguments":{"sql":"SELECT 1 FROM dual"}}}"#.as_slice(),
            br#"[1,true,null,{"x":[2,3]}]"#.as_slice(),
            br#"{"a":1.25,"b":18446744073709551615}"#.as_slice(),
        ] {
            assert_eq!(
                decode_strict_value(bytes).expect("unique JSON"),
                serde_json::from_slice::<Value>(bytes).expect("reference JSON")
            );
        }
        assert!(matches!(
            decode_strict_value(b"{invalid"),
            Err(StrictJsonError::InvalidJson(_))
        ));
        assert_eq!(decode_strict_value(b"null").expect("null"), json!(null));
    }

    fn json_tree() -> impl Strategy<Value = Value> {
        let leaf = prop_oneof![
            Just(Value::Null),
            any::<bool>().prop_map(Value::Bool),
            any::<i64>().prop_map(|n| json!(n)),
            any::<u64>().prop_map(|n| json!(n)),
            any::<f64>()
                .prop_filter("finite JSON number", |n| n.is_finite())
                .prop_map(|n| json!(n)),
            "[a-zA-Z0-9~/]{0,16}".prop_map(Value::String),
        ];
        leaf.prop_recursive(4, 64, 8, |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 0..8).prop_map(Value::Array),
                prop::collection::btree_map("[a-zA-Z0-9~/]{0,8}", inner, 0..8)
                    .prop_map(|entries| Value::Object(entries.into_iter().collect())),
            ]
        })
    }

    proptest! {
        #[test]
        fn strict_decode_equals_serde_value_on_unique_input(value in json_tree()) {
            let bytes = serde_json::to_vec(&value).expect("generated value serializes");
            let actual = decode_strict_value(&bytes).expect("generated JSON is duplicate-free");
            let reference = serde_json::from_slice::<Value>(&bytes).expect("reference JSON parses");
            prop_assert_eq!(actual, reference);
        }
    }
}
