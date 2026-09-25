use super::{
    bitwise_binary, bitwise_shift, compare_values, numeric_binary, values_equal, wildcard_match,
    Engine, EventKind, Host, PowerShellEmulator, TraceEvent, Value,
};

impl PowerShellEmulator {
    pub(crate) fn apply_unary(operator: &str, value: Value) -> Value {
        match operator.to_ascii_lowercase().as_str() {
            "-not" | "!" => Value::Bool(!value.truthy()),
            "-bnot" => value
                .as_i64()
                .map_or(Value::Null, |value| Value::Number(!value)),
            "-" => match value {
                Value::Number(value) => Value::Number(-value),
                Value::Float(value) => Value::Float(-value),
                other => other
                    .as_f64()
                    .map_or(Value::Null, |value| Value::Float(-value)),
            },
            "+" => value,
            _ => Value::Null,
        }
    }

    pub(crate) fn read_member(receiver: Value, member: &str) -> Value {
        let normalized = member.to_ascii_lowercase();
        if normalized == "result" {
            return receiver;
        }
        match receiver {
            Value::Map(values) => values
                .into_iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(member))
                .map_or(Value::Null, |(_, value)| value),
            Value::String(value) if matches!(normalized.as_str(), "length" | "count") => {
                Value::Number(i64::try_from(value.chars().count()).unwrap_or(i64::MAX))
            }
            Value::String(value) if normalized == "chars" => Value::Array(
                value
                    .chars()
                    .map(|character| Value::String(character.to_string()))
                    .collect(),
            ),
            Value::Bytes(value) if matches!(normalized.as_str(), "length" | "count") => {
                Value::Number(i64::try_from(value.len()).unwrap_or(i64::MAX))
            }
            Value::Array(value) if matches!(normalized.as_str(), "length" | "count") => {
                Value::Number(i64::try_from(value.len()).unwrap_or(i64::MAX))
            }
            Value::Array(values) => Value::Array(
                values
                    .into_iter()
                    .map(|value| Self::read_member(value, member))
                    .filter(|value| !matches!(value, Value::Null))
                    .collect(),
            ),
            Value::Object(value)
                if value.eq_ignore_ascii_case("Type:Ref") && normalized == "assembly" =>
            {
                Value::Object("Assembly:System.Management.Automation".into())
            }
            Value::Object(value)
                if value.to_ascii_lowercase().starts_with("reflectionmember:")
                    && normalized == "methodhandle" =>
            {
                Value::Object("RuntimeMethodHandle".into())
            }
            Value::Object(value) if normalized == "typename" => Value::String(value),
            _ => Value::Null,
        }
    }

    #[allow(clippy::cast_precision_loss, clippy::too_many_lines)]
    pub(crate) fn apply_binary(
        &mut self,
        left: Value,
        operator: &str,
        right: Value,
        host: &mut dyn Host,
        depth: usize,
    ) -> Value {
        let normalized = operator.to_ascii_lowercase();
        match normalized.as_str() {
            "+" => match (left, right) {
                (Value::Number(left), Value::Number(right)) => Value::Number(left + right),
                (Value::Float(left), Value::Float(right)) => Value::Float(left + right),
                (Value::Number(left), Value::Float(right)) => Value::Float(left as f64 + right),
                (Value::Float(left), Value::Number(right)) => Value::Float(left + right as f64),
                (Value::Bytes(mut left), Value::Bytes(right)) => {
                    left.extend(right);
                    Value::Bytes(left)
                }
                (Value::Array(mut left), Value::Array(right)) => {
                    left.extend(right);
                    Value::Array(left)
                }
                (Value::Array(mut left), right) => {
                    left.push(right);
                    Value::Array(left)
                }
                (left, Value::Array(mut right)) => {
                    right.insert(0, left);
                    Value::Array(right)
                }
                (left, right) => {
                    Value::String(format!("{}{}", left.as_string(), right.as_string()))
                }
            },
            "-" => numeric_binary(&left, &right, |left, right| left - right),
            "*" => match (&left, &right) {
                (Value::String(value), Value::Number(count)) if *count >= 0 => {
                    let requested = usize::try_from(*count).unwrap_or(usize::MAX);
                    let by_bytes = if value.is_empty() {
                        host.limits().max_loop_iterations
                    } else {
                        host.limits().max_artifact_bytes / value.len()
                    };
                    let accepted = requested
                        .min(host.limits().max_loop_iterations)
                        .min(by_bytes);
                    if accepted < requested {
                        host.emit(TraceEvent::new(
                            depth,
                            Engine::PowerShell,
                            EventKind::LimitReached,
                            "string repetition was truncated",
                        ));
                    }
                    Value::String(value.repeat(accepted))
                }
                (Value::Array(values), Value::Number(count)) if *count >= 0 => {
                    let requested = usize::try_from(*count).unwrap_or(usize::MAX);
                    let by_items = if values.is_empty() {
                        host.limits().max_loop_iterations
                    } else {
                        host.limits().max_loop_iterations / values.len()
                    };
                    let accepted = requested.min(by_items);
                    if accepted < requested {
                        host.emit(TraceEvent::new(
                            depth,
                            Engine::PowerShell,
                            EventKind::LimitReached,
                            "array repetition was truncated",
                        ));
                    }
                    let mut output = Vec::new();
                    for _ in 0..accepted {
                        output.extend(values.clone());
                    }
                    Value::Array(output)
                }
                _ => numeric_binary(&left, &right, |left, right| left * right),
            },
            "/" => {
                if right.as_f64() == Some(0.0) {
                    host.unsupported(Engine::PowerShell, depth, "division by zero");
                    Value::Null
                } else {
                    numeric_binary(&left, &right, |left, right| left / right)
                }
            }
            "%" => {
                let Some(left) = left.as_i64() else {
                    return Value::Null;
                };
                let Some(right) = right.as_i64() else {
                    return Value::Null;
                };
                if right == 0 {
                    host.unsupported(Engine::PowerShell, depth, "remainder by zero");
                    Value::Null
                } else {
                    Value::Number(left % right)
                }
            }
            "-and" => Value::Bool(left.truthy() && right.truthy()),
            "-or" => Value::Bool(left.truthy() || right.truthy()),
            "-xor" => Value::Bool(left.truthy() ^ right.truthy()),
            "-band" => bitwise_binary(&left, &right, |left, right| left & right),
            "-bor" => bitwise_binary(&left, &right, |left, right| left | right),
            "-bxor" => bitwise_binary(&left, &right, |left, right| left ^ right),
            "-shl" => bitwise_shift(&left, &right, true),
            "-shr" => bitwise_shift(&left, &right, false),
            "-join" => {
                let separator = right.as_string();
                let values = match left {
                    Value::Array(values) => values,
                    other => vec![other],
                };
                Value::String(
                    values
                        .iter()
                        .map(Value::as_string)
                        .collect::<Vec<_>>()
                        .join(&separator),
                )
            }
            "-replace" | "-ireplace" | "-creplace" => {
                let replacement_parts = match right {
                    Value::Array(parts) => parts,
                    other => vec![other],
                };
                let pattern = replacement_parts
                    .first()
                    .map_or_else(String::new, Value::as_string);
                let replacement = replacement_parts
                    .get(1)
                    .map_or_else(String::new, Value::as_string);
                let mut builder = regex::RegexBuilder::new(&pattern);
                builder.case_insensitive(normalized != "-creplace");
                match builder.build() {
                    Ok(regex) => Value::String(
                        regex
                            .replace_all(&left.as_string(), replacement.as_str())
                            .into_owned(),
                    ),
                    Err(_) => Value::String(left.as_string().replace(&pattern, &replacement)),
                }
            }
            "-split" | "-isplit" | "-csplit" => {
                let pattern = right.as_string();
                let mut builder = regex::RegexBuilder::new(&pattern);
                builder.case_insensitive(normalized != "-csplit");
                match builder.build() {
                    Ok(regex) => Value::Array(
                        regex
                            .split(&left.as_string())
                            .map(|part| Value::String(part.into()))
                            .collect(),
                    ),
                    Err(_) => Value::Array(
                        left.as_string()
                            .split(&pattern)
                            .map(|part| Value::String(part.into()))
                            .collect(),
                    ),
                }
            }
            "-f" => {
                let arguments = match right {
                    Value::Array(values) => values,
                    other => vec![other],
                };
                let mut output = left.as_string();
                for (index, value) in arguments.iter().enumerate() {
                    output = output.replace(&format!("{{{index}}}"), &value.as_string());
                }
                Value::String(output)
            }
            ".." => {
                let start = left.as_i64().unwrap_or_default();
                let end = right.as_i64().unwrap_or_default();
                let requested = start.abs_diff(end).saturating_add(1);
                let maximum = host.limits().max_loop_iterations;
                if requested > u64::try_from(maximum).unwrap_or(u64::MAX) {
                    host.emit(TraceEvent::new(
                        depth,
                        Engine::PowerShell,
                        EventKind::LimitReached,
                        "numeric range was truncated",
                    ));
                }
                let values = if start <= end {
                    (start..=end).take(maximum).map(Value::Number).collect()
                } else {
                    (end..=start)
                        .rev()
                        .take(maximum)
                        .map(Value::Number)
                        .collect()
                };
                Value::Array(values)
            }
            "-eq" | "-ieq" => Value::Bool(values_equal(&left, &right, false)),
            "-ceq" => Value::Bool(values_equal(&left, &right, true)),
            "-ne" | "-ine" => Value::Bool(!values_equal(&left, &right, false)),
            "-cne" => Value::Bool(!values_equal(&left, &right, true)),
            "-lt" | "-ilt" | "-clt" => compare_values(&left, &right, std::cmp::Ordering::is_lt),
            "-le" | "-ile" | "-cle" => compare_values(&left, &right, std::cmp::Ordering::is_le),
            "-gt" | "-igt" | "-cgt" => compare_values(&left, &right, std::cmp::Ordering::is_gt),
            "-ge" | "-ige" | "-cge" => compare_values(&left, &right, std::cmp::Ordering::is_ge),
            "-like" | "-ilike" | "-clike" | "-notlike" | "-inotlike" | "-cnotlike" => {
                let case_sensitive = normalized.starts_with("-c");
                let matched = wildcard_match(&left.as_string(), &right.as_string(), case_sensitive);
                Value::Bool(if normalized.contains("not") {
                    !matched
                } else {
                    matched
                })
            }
            "-match" | "-imatch" | "-cmatch" | "-notmatch" | "-inotmatch" | "-cnotmatch" => {
                let mut builder = regex::RegexBuilder::new(&right.as_string());
                builder.case_insensitive(!normalized.starts_with("-c"));
                let matched = builder.build().ok().and_then(|regex| {
                    regex.captures(&left.as_string()).map(|captures| {
                        let values = captures
                            .iter()
                            .enumerate()
                            .filter_map(|(index, capture)| {
                                capture.map(|capture| {
                                    (index.to_string(), Value::String(capture.as_str().into()))
                                })
                            })
                            .collect();
                        self.variables.insert("matches".into(), Value::Map(values));
                    })
                });
                let matched = matched.is_some();
                Value::Bool(if normalized.contains("notmatch") {
                    !matched
                } else {
                    matched
                })
            }
            "-contains" | "-icontains" | "-ccontains" | "-notcontains" | "-inotcontains"
            | "-cnotcontains" => {
                let case_sensitive = normalized.starts_with("-c");
                let values = match left {
                    Value::Array(values) => values,
                    other => vec![other],
                };
                let contains = values
                    .iter()
                    .any(|value| values_equal(value, &right, case_sensitive));
                Value::Bool(if normalized.contains("notcontains") {
                    !contains
                } else {
                    contains
                })
            }
            "-in" | "-notin" => {
                let values = match right {
                    Value::Array(values) => values,
                    other => vec![other],
                };
                let contains = values.iter().any(|value| values_equal(&left, value, false));
                Value::Bool(if normalized == "-notin" {
                    !contains
                } else {
                    contains
                })
            }
            "-is" | "-isnot" => {
                let requested = right
                    .as_string()
                    .trim_matches(['[', ']'])
                    .to_ascii_lowercase();
                let matches = match requested.as_str() {
                    "string" | "system.string" => matches!(left, Value::String(_)),
                    "byte[]" | "system.byte[]" => matches!(left, Value::Bytes(_)),
                    "array" | "object[]" | "system.array" => matches!(left, Value::Array(_)),
                    "int" | "int32" | "int64" | "long" => matches!(left, Value::Number(_)),
                    "double" | "float" | "decimal" => matches!(left, Value::Float(_)),
                    "bool" | "boolean" => matches!(left, Value::Bool(_)),
                    "hashtable" => matches!(left, Value::Map(_)),
                    _ => false,
                };
                Value::Bool(if normalized == "-isnot" {
                    !matches
                } else {
                    matches
                })
            }
            _ => {
                host.unsupported(
                    Engine::PowerShell,
                    depth,
                    &format!("unsupported binary operator {operator}"),
                );
                Value::Null
            }
        }
    }
}
