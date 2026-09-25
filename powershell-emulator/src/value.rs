use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Value {
    Null,
    Bool(bool),
    Number(i64),
    Float(f64),
    String(String),
    Bytes(Vec<u8>),
    Array(Vec<Value>),
    Map(BTreeMap<String, Value>),
    Object(String),
}

impl Value {
    #[must_use]
    pub fn as_string(&self) -> String {
        match self {
            Self::Null => String::new(),
            Self::Bool(value) => {
                if *value {
                    "True".into()
                } else {
                    "False".into()
                }
            }
            Self::Number(value) => value.to_string(),
            Self::Float(value) => value.to_string(),
            Self::String(value) | Self::Object(value) => value.clone(),
            Self::Bytes(value) => String::from_utf8_lossy(value).into_owned(),
            Self::Array(values) => values
                .iter()
                .map(Self::as_string)
                .collect::<Vec<_>>()
                .join(" "),
            Self::Map(values) => values
                .iter()
                .map(|(key, value)| format!("{key}={}", value.as_string()))
                .collect::<Vec<_>>()
                .join("; "),
        }
    }

    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn as_bytes(&self) -> Vec<u8> {
        match self {
            Self::Bytes(value) => value.clone(),
            Self::Array(values) => values
                .iter()
                .filter_map(|value| match value {
                    Self::Number(number) => u8::try_from(*number).ok(),
                    Self::Float(number) => {
                        let integer = *number as i64;
                        u8::try_from(integer).ok()
                    }
                    _ => None,
                })
                .collect(),
            _ => self.as_string().into_bytes(),
        }
    }

    #[must_use]
    pub fn truthy(&self) -> bool {
        match self {
            Self::Null => false,
            Self::Bool(value) => *value,
            Self::Number(value) => *value != 0,
            Self::Float(value) => *value != 0.0,
            Self::String(value) | Self::Object(value) => !value.is_empty(),
            Self::Bytes(value) => !value.is_empty(),
            Self::Array(value) => !value.is_empty(),
            Self::Map(value) => !value.is_empty(),
        }
    }

    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Number(value) => Some(*value),
            Self::Float(value) if value.is_finite() => Some(*value as i64),
            Self::Bool(value) => Some(i64::from(*value)),
            Self::String(value) => parse_integer(value),
            _ => None,
        }
    }

    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Number(value) => Some(*value as f64),
            Self::Float(value) => Some(*value),
            Self::Bool(value) => Some(if *value { 1.0 } else { 0.0 }),
            Self::String(value) => value.parse().ok(),
            _ => None,
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Self::Null => 0,
            Self::String(value) | Self::Object(value) => value.chars().count(),
            Self::Bytes(value) => value.len(),
            Self::Array(value) => value.len(),
            Self::Map(value) => value.len(),
            Self::Bool(_) | Self::Number(_) | Self::Float(_) => 1,
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[must_use]
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Bool(_) => "bool",
            Self::Number(_) => "int64",
            Self::Float(_) => "double",
            Self::String(_) => "string",
            Self::Bytes(_) => "byte[]",
            Self::Array(_) => "object[]",
            Self::Map(_) => "hashtable",
            Self::Object(_) => "object",
        }
    }
}

fn parse_integer(value: &str) -> Option<i64> {
    let value = value.trim().replace('_', "");
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        i64::from_str_radix(hex, 16).ok()
    } else if let Some(binary) = value
        .strip_prefix("0b")
        .or_else(|| value.strip_prefix("0B"))
    {
        i64::from_str_radix(binary, 2).ok()
    } else {
        value.parse().ok()
    }
}
