use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, PartialEq)]
pub enum Value {
    #[default]
    Undefined,
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<Value>),
    Object(BTreeMap<String, Value>),
    Com(usize),
}

impl Value {
    #[must_use]
    pub fn truthy(&self) -> bool {
        match self {
            Self::Undefined | Self::Null => false,
            Self::Bool(value) => *value,
            Self::Number(value) => *value != 0.0 && !value.is_nan(),
            Self::String(value) => !value.is_empty(),
            Self::Array(_) | Self::Object(_) | Self::Com(_) => true,
        }
    }

    #[must_use]
    pub fn number(&self) -> f64 {
        match self {
            Self::Undefined => f64::NAN,
            Self::Null => 0.0,
            Self::Bool(value) => f64::from(*value),
            Self::Number(value) => *value,
            Self::String(value) => value.trim().parse().unwrap_or(f64::NAN),
            Self::Array(values) if values.len() == 1 => values[0].number(),
            Self::Array(_) | Self::Object(_) | Self::Com(_) => f64::NAN,
        }
    }

    #[must_use]
    pub fn string(&self) -> String {
        match self {
            Self::Undefined => "undefined".into(),
            Self::Null => "null".into(),
            Self::Bool(value) => value.to_string(),
            Self::Number(value) if value.fract() == 0.0 => format!("{value:.0}"),
            Self::Number(value) => value.to_string(),
            Self::String(value) => value.clone(),
            Self::Array(values) => values
                .iter()
                .map(Self::string)
                .collect::<Vec<_>>()
                .join(","),
            Self::Object(_) => "[object Object]".into(),
            Self::Com(_) => "[object ActiveXObject]".into(),
        }
    }
}
