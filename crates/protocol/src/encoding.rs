//! Strict JSON, RFC 8785 JCS, lowercase hex, and canonical decimal `u64`.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::de::{self, DeserializeOwned, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::ser::{Serialize, Serializer};
use serde::Deserialize;
use serde_json::Value;

use crate::error::{ErrorCode, TvcError};

pub fn encode_lower_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

pub fn decode_lower_hex(input: &str) -> Result<Vec<u8>, TvcError> {
    let decoded = hex::decode(input).map_err(|_| TvcError::new(ErrorCode::InvalidHex))?;
    if hex::encode(&decoded) != input {
        return Err(TvcError::new(ErrorCode::InvalidHex));
    }
    Ok(decoded)
}

pub fn decode_lower_hex_array<const N: usize>(input: &str) -> Result<[u8; N], TvcError> {
    let bytes = decode_lower_hex(input)?;
    bytes
        .try_into()
        .map_err(|_| TvcError::new(ErrorCode::InvalidHex))
}

pub fn encode_decimal_u64(value: u64) -> String {
    value.to_string()
}

pub fn decode_decimal_u64(input: &str) -> Result<u64, TvcError> {
    if input.is_empty() {
        return Err(TvcError::new(ErrorCode::InvalidDecimal));
    }
    if input.as_bytes()[0] == b'+' || input.as_bytes()[0] == b'-' {
        return Err(TvcError::new(ErrorCode::InvalidDecimal));
    }
    if input.len() > 1 && input.as_bytes()[0] == b'0' {
        return Err(TvcError::new(ErrorCode::InvalidDecimal));
    }
    if !input.bytes().all(|b| b.is_ascii_digit()) {
        return Err(TvcError::new(ErrorCode::InvalidDecimal));
    }
    input
        .parse()
        .map_err(|_| TvcError::new(ErrorCode::InvalidDecimal))
}

pub fn hex_bytes_serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&encode_lower_hex(bytes))
}

pub fn hex_bytes_deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<u8>, D::Error> {
    let s = String::deserialize(deserializer)?;
    decode_lower_hex(&s).map_err(de::Error::custom)
}

pub fn hex32_serialize<S: Serializer>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&encode_lower_hex(bytes))
}

pub fn hex32_deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
    let s = String::deserialize(deserializer)?;
    decode_lower_hex_array(&s).map_err(de::Error::custom)
}

pub fn decimal_u64_serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&encode_decimal_u64(*value))
}

pub fn decimal_u64_deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<u64, D::Error> {
    let s = String::deserialize(deserializer)?;
    decode_decimal_u64(&s).map_err(de::Error::custom)
}

pub mod hex_bytes {
    pub use super::{hex_bytes_deserialize as deserialize, hex_bytes_serialize as serialize};
}

pub mod hex32 {
    pub use super::{hex32_deserialize as deserialize, hex32_serialize as serialize};
}

pub mod decimal_u64 {
    pub use super::{decimal_u64_deserialize as deserialize, decimal_u64_serialize as serialize};
}

pub fn hex32_vec_serialize<S: Serializer>(
    values: &[[u8; 32]],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_seq(values.iter().map(|value| encode_lower_hex(value)))
}

pub fn hex32_vec_deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<[u8; 32]>, D::Error> {
    Vec::<String>::deserialize(deserializer)?
        .iter()
        .map(|value| decode_lower_hex_array(value).map_err(de::Error::custom))
        .collect()
}

pub mod hex32_vec {
    pub use super::{hex32_vec_deserialize as deserialize, hex32_vec_serialize as serialize};
}

pub fn option_hex_bytes_serialize<S: Serializer>(
    value: &Option<Vec<u8>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match value {
        Some(bytes) => serializer.serialize_some(&encode_lower_hex(bytes)),
        None => serializer.serialize_none(),
    }
}

pub fn option_hex_bytes_deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<u8>>, D::Error> {
    let value = Option::<String>::deserialize(deserializer)?;
    match value {
        Some(s) => decode_lower_hex(&s).map(Some).map_err(de::Error::custom),
        None => Ok(None),
    }
}

pub mod option_hex_bytes {
    pub use super::{
        option_hex_bytes_deserialize as deserialize, option_hex_bytes_serialize as serialize,
    };
}

#[derive(Clone, Debug)]
enum StrictValue {
    Null,
    Bool(bool),
    Number(serde_json::Number),
    String(String),
    Array(Vec<StrictValue>),
    Object(BTreeMap<String, StrictValue>),
}

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StrictVisitor;

        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictValue;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("JSON value")
            }

            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Self::Value, E> {
                Ok(StrictValue::Bool(v))
            }

            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
                Ok(StrictValue::Number(v.into()))
            }

            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(StrictValue::Number(v.into()))
            }

            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(v)
                    .map(StrictValue::Number)
                    .ok_or_else(|| de::Error::custom("non-finite number"))
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(StrictValue::String(v.to_owned()))
            }

            fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(StrictValue::String(v))
            }

            fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(StrictValue::Null)
            }

            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(StrictValue::Null)
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut out = Vec::new();
                while let Some(value) = seq.next_element()? {
                    out.push(value);
                }
                Ok(StrictValue::Array(out))
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut out = BTreeMap::new();
                while let Some((key, value)) = map.next_entry::<String, StrictValue>()? {
                    if out.contains_key(&key) {
                        return Err(de::Error::custom(ErrorCode::DuplicateJsonField.as_str()));
                    }
                    out.insert(key, value);
                }
                Ok(StrictValue::Object(out))
            }
        }

        deserializer.deserialize_any(StrictVisitor)
    }
}

impl From<StrictValue> for Value {
    fn from(value: StrictValue) -> Self {
        match value {
            StrictValue::Null => Value::Null,
            StrictValue::Bool(v) => Value::Bool(v),
            StrictValue::Number(v) => Value::Number(v),
            StrictValue::String(v) => Value::String(v),
            StrictValue::Array(v) => Value::Array(v.into_iter().map(Value::from).collect()),
            StrictValue::Object(v) => Value::Object(
                v.into_iter()
                    .map(|(k, val)| (k, Value::from(val)))
                    .collect(),
            ),
        }
    }
}

fn classify_json_error(error: &serde_json::Error) -> ErrorCode {
    let message = error.to_string();
    if message.contains(ErrorCode::DuplicateJsonField.as_str()) {
        ErrorCode::DuplicateJsonField
    } else if message.contains("unknown field") {
        ErrorCode::UnknownJsonField
    } else {
        ErrorCode::InvalidCanonicalJson
    }
}

/// Parse JSON, rejecting duplicate keys, unknown fields (via serde), and trailing data.
pub fn parse_strict_json<T: DeserializeOwned>(input: &str) -> Result<T, TvcError> {
    let mut de = serde_json::Deserializer::from_str(input);
    let strict = StrictValue::deserialize(&mut de)
        .map_err(|error| TvcError::new(classify_json_error(&error)))?;
    de.end()
        .map_err(|_| TvcError::new(ErrorCode::InvalidCanonicalJson))?;
    let value = Value::from(strict);
    serde_json::from_value(value).map_err(|error| TvcError::new(classify_json_error(&error)))
}

pub fn to_canonical_value<T: Serialize>(value: &T) -> Result<Value, TvcError> {
    serde_json::to_value(value).map_err(|_| TvcError::new(ErrorCode::InvalidCanonicalJson))
}

fn utf16_units(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

fn cmp_utf16(a: &str, b: &str) -> std::cmp::Ordering {
    utf16_units(a).cmp(&utf16_units(b))
}

fn append_json_string(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn append_jcs(out: &mut String, value: &Value) -> Result<(), TvcError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => {
            if n.is_f64() {
                return Err(TvcError::new(ErrorCode::InvalidCanonicalJson));
            }
            out.push_str(&n.to_string());
        }
        Value::String(s) => append_json_string(out, s),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                append_jcs(out, item)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| cmp_utf16(a, b));
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                append_json_string(out, key);
                out.push(':');
                append_jcs(out, &map[*key])?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// RFC 8785 JSON Canonicalization Scheme over a JSON value.
pub fn canonicalize_json_value(value: &Value) -> Result<String, TvcError> {
    let mut out = String::new();
    append_jcs(&mut out, value)?;
    Ok(out)
}

pub fn canonicalize_json_str(input: &str) -> Result<String, TvcError> {
    let mut de = serde_json::Deserializer::from_str(input);
    let strict = StrictValue::deserialize(&mut de)
        .map_err(|error| TvcError::new(classify_json_error(&error)))?;
    de.end()
        .map_err(|_| TvcError::new(ErrorCode::InvalidCanonicalJson))?;
    canonicalize_json_value(&Value::from(strict))
}

pub fn jcs_serialize<T: Serialize>(value: &T) -> Result<String, TvcError> {
    canonicalize_json_value(&to_canonical_value(value)?)
}

pub fn is_rfc8785(input: &str) -> bool {
    match canonicalize_json_str(input) {
        Ok(canonical) => canonical == input,
        Err(_) => false,
    }
}
