use crate::parser::ParsedSource;
use crate::syntax::{find_switch, named_or_positional};
use crate::{PowerShellEmulator, PowerShellError, Value};
use emulator_core::{Engine, Host};
use regex::RegexBuilder;
use std::collections::{BTreeMap, BTreeSet};

pub(crate) enum PipelineDispatch {
    NotHandled,
    Handled(Option<Value>),
}

impl PowerShellEmulator {
    #[allow(clippy::too_many_lines)]
    pub(crate) fn execute_pipeline_command(
        &mut self,
        parser: &ParsedSource,
        command: &str,
        arguments: &[String],
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<PipelineDispatch, PowerShellError> {
        let value = match command {
            "where-object" | "?" if !arguments.join(" ").contains('{') => {
                let property = arguments.first().map_or("", String::as_str);
                let operator = arguments.get(1).map_or("-eq", String::as_str);
                let expected_expression = arguments.get(2..).unwrap_or_default().join(" ");
                let expected = self.eval_expression(parser, &expected_expression, host, depth)?;
                Some(Value::Array(
                    pipeline_values(self.variables.get("input").cloned())
                        .into_iter()
                        .filter(|value| {
                            compare_property(
                                &Self::read_member(value.clone(), property),
                                operator,
                                &expected,
                            )
                        })
                        .collect(),
                ))
            }
            "foreach-object" | "%" if has_named_block(arguments) => {
                if let Some(begin) = named_script_block(parser, arguments, "-begin") {
                    self.execute_script(parser, &begin, host, depth + 1)?;
                }
                let process = named_script_block(parser, arguments, "-process").unwrap_or_default();
                let mut output = Vec::new();
                for value in pipeline_values(self.variables.get("input").cloned()) {
                    self.variables.insert("_".into(), value.clone());
                    self.variables.insert("psitem".into(), value);
                    let (_, values) =
                        self.execute_script_collect(parser, &process, host, depth + 1)?;
                    output.extend(values);
                }
                if let Some(end) = named_script_block(parser, arguments, "-end") {
                    let (_, values) = self.execute_script_collect(parser, &end, host, depth + 1)?;
                    output.extend(values);
                }
                Some(Value::Array(output))
            }
            "select-object" if find_switch(arguments, "-property").is_some() => {
                let properties =
                    named_or_positional(arguments, &["-property"], usize::MAX).unwrap_or_default();
                let properties = crate::syntax::split_top_level(parser, &properties, ',')
                    .into_iter()
                    .map(|property| property.trim_matches(['\'', '"']).trim().to_string())
                    .filter(|property| !property.is_empty())
                    .collect::<Vec<_>>();
                Some(Value::Array(
                    pipeline_values(self.variables.get("input").cloned())
                        .into_iter()
                        .map(|value| {
                            Value::Map(
                                properties
                                    .iter()
                                    .map(|property| {
                                        (
                                            property.clone(),
                                            Self::read_member(value.clone(), property),
                                        )
                                    })
                                    .collect(),
                            )
                        })
                        .collect(),
                ))
            }
            "select-string" | "sls" => {
                let pattern_expression =
                    named_or_positional(arguments, &["-pattern"], 0).unwrap_or_default();
                let pattern = self
                    .eval_expression(parser, &pattern_expression, host, depth)?
                    .as_string();
                let case_sensitive = find_switch(arguments, "-casesensitive").is_some();
                let simple = find_switch(arguments, "-simplematch").is_some();
                let negate = find_switch(arguments, "-notmatch").is_some();
                let all_matches = find_switch(arguments, "-allmatches").is_some();
                let sources = self.pipeline_text_sources(parser, arguments, host, depth)?;
                let mut results = Vec::new();
                for (path, line_number, line) in sources {
                    let ranges = match_ranges(&line, &pattern, case_sensitive, simple);
                    let matched = !ranges.is_empty();
                    if matched == negate {
                        continue;
                    }
                    let matched_values = if all_matches {
                        ranges
                            .iter()
                            .map(|(start, end)| Value::String(line[*start..*end].into()))
                            .collect()
                    } else {
                        ranges.first().map_or_else(Vec::new, |(start, end)| {
                            vec![Value::String(line[*start..*end].into())]
                        })
                    };
                    results.push(Value::Map(
                        [
                            ("Line".into(), Value::String(line)),
                            (
                                "LineNumber".into(),
                                Value::Number(i64::try_from(line_number).unwrap_or(i64::MAX)),
                            ),
                            ("Path".into(), Value::String(path)),
                            ("Pattern".into(), Value::String(pattern.clone())),
                            ("Matches".into(), Value::Array(matched_values)),
                        ]
                        .into_iter()
                        .collect(),
                    ));
                }
                Some(Value::Array(results))
            }
            "sort-object" | "sort" => {
                let property = named_or_positional(arguments, &["-property"], 0)
                    .filter(|value| !value.starts_with('-'))
                    .map(|value| value.trim_matches(['\'', '"']).to_string());
                let descending = find_switch(arguments, "-descending").is_some();
                let unique = find_switch(arguments, "-unique").is_some();
                let mut values = pipeline_values(self.variables.get("input").cloned());
                values.sort_by(|left, right| {
                    let left = sort_key(left, property.as_deref());
                    let right = sort_key(right, property.as_deref());
                    let ordering = left.cmp(&right);
                    if descending {
                        ordering.reverse()
                    } else {
                        ordering
                    }
                });
                if unique {
                    values.dedup_by(|left, right| {
                        sort_key(left, property.as_deref()) == sort_key(right, property.as_deref())
                    });
                }
                Some(Value::Array(values))
            }
            "group-object" | "group" => {
                let property = named_or_positional(arguments, &["-property"], 0)
                    .filter(|value| !value.starts_with('-'))
                    .map(|value| value.trim_matches(['\'', '"']).to_string());
                let mut groups = BTreeMap::<String, Vec<Value>>::new();
                for value in pipeline_values(self.variables.get("input").cloned()) {
                    groups
                        .entry(sort_key(&value, property.as_deref()))
                        .or_default()
                        .push(value);
                }
                Some(Value::Array(
                    groups
                        .into_iter()
                        .map(|(name, group)| {
                            Value::Map(
                                [
                                    ("Name".into(), Value::String(name)),
                                    (
                                        "Count".into(),
                                        Value::Number(
                                            i64::try_from(group.len()).unwrap_or(i64::MAX),
                                        ),
                                    ),
                                    ("Group".into(), Value::Array(group)),
                                ]
                                .into_iter()
                                .collect(),
                            )
                        })
                        .collect(),
                ))
            }
            "tee-object" | "tee" => {
                let input = self.variables.get("input").cloned().unwrap_or(Value::Null);
                if let Some(variable) = named_or_positional(arguments, &["-variable"], usize::MAX) {
                    self.variables.insert(
                        variable
                            .trim_matches(['\'', '"'])
                            .trim_start_matches('$')
                            .to_ascii_lowercase(),
                        input.clone(),
                    );
                }
                if let Some(path) = named_or_positional(arguments, &["-filepath"], usize::MAX) {
                    let path = self
                        .eval_expression(parser, &path, host, depth)?
                        .as_string();
                    host.write_file(
                        &path,
                        input.as_string().as_bytes(),
                        find_switch(arguments, "-append").is_some(),
                        Engine::PowerShell,
                        depth,
                    )?;
                }
                Some(input)
            }
            "compare-object" | "compare" | "diff" => {
                let reference = named_or_positional(arguments, &["-referenceobject"], 0)
                    .map(|value| self.eval_expression(parser, &value, host, depth))
                    .transpose()?
                    .unwrap_or(Value::Null);
                let difference = named_or_positional(arguments, &["-differenceobject"], 1)
                    .map(|value| self.eval_expression(parser, &value, host, depth))
                    .transpose()?
                    .or_else(|| self.variables.get("input").cloned())
                    .unwrap_or(Value::Null);
                Some(Value::Array(compare_objects(reference, difference)))
            }
            "get-unique" | "gu" => {
                let mut seen = BTreeSet::new();
                let values = pipeline_values(self.variables.get("input").cloned())
                    .into_iter()
                    .filter(|value| seen.insert(value.as_string().to_ascii_lowercase()))
                    .collect();
                Some(Value::Array(values))
            }
            "convertfrom-stringdata" => {
                let input = command_input(self, parser, arguments, host, depth)?;
                let mut output = BTreeMap::new();
                for line in input.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    if let Some((key, value)) = line.split_once('=') {
                        output.insert(
                            key.trim().into(),
                            Value::String(value.trim().replace("\\n", "\n")),
                        );
                    }
                }
                Some(Value::Map(output))
            }
            "convertfrom-csv" => {
                let input = command_input(self, parser, arguments, host, depth)?;
                Some(Value::Array(parse_csv(&input)))
            }
            "import-csv" => {
                let path = named_or_positional(arguments, &["-path", "-literalpath"], 0)
                    .unwrap_or_default();
                let path = self
                    .eval_expression(parser, &path, host, depth)?
                    .as_string();
                let input = host
                    .read_file(&path, Engine::PowerShell, depth)
                    .map_or_else(String::new, |bytes| {
                        String::from_utf8_lossy(&bytes).into_owned()
                    });
                Some(Value::Array(parse_csv(&input)))
            }
            "convertto-csv" => {
                let values = if arguments.is_empty() {
                    pipeline_values(self.variables.get("input").cloned())
                } else {
                    pipeline_values(Some(
                        self.eval_joined_arguments(parser, arguments, host, depth)?,
                    ))
                };
                Some(Value::Array(
                    serialize_csv(&values)
                        .lines()
                        .map(|line| Value::String(line.into()))
                        .collect(),
                ))
            }
            "export-csv" => {
                let path = named_or_positional(arguments, &["-path", "-literalpath"], 0)
                    .unwrap_or_default();
                let path = self
                    .eval_expression(parser, &path, host, depth)?
                    .as_string();
                let values = pipeline_values(self.variables.get("input").cloned());
                let csv = serialize_csv(&values);
                host.write_file(
                    &path,
                    csv.as_bytes(),
                    find_switch(arguments, "-append").is_some(),
                    Engine::PowerShell,
                    depth,
                )?;
                Some(Value::String(path))
            }
            "format-hex" | "fhx" => {
                let bytes = if let Some(path) =
                    named_or_positional(arguments, &["-path", "-literalpath"], usize::MAX)
                {
                    let path = self
                        .eval_expression(parser, &path, host, depth)?
                        .as_string();
                    host.read_file(&path, Engine::PowerShell, depth)
                        .unwrap_or_default()
                } else if arguments.is_empty() {
                    self.variables
                        .get("input")
                        .map_or_else(Vec::new, Value::as_bytes)
                } else {
                    self.eval_joined_arguments(parser, arguments, host, depth)?
                        .as_bytes()
                };
                Some(Value::Array(
                    bytes
                        .chunks(16)
                        .enumerate()
                        .map(|(offset, chunk)| {
                            Value::Map(
                                [
                                    (
                                        "Offset".into(),
                                        Value::Number(
                                            i64::try_from(offset * 16).unwrap_or(i64::MAX),
                                        ),
                                    ),
                                    (
                                        "Bytes".into(),
                                        Value::Array(
                                            chunk
                                                .iter()
                                                .map(|byte| Value::Number(i64::from(*byte)))
                                                .collect(),
                                        ),
                                    ),
                                    (
                                        "Hex".into(),
                                        Value::String(
                                            chunk
                                                .iter()
                                                .map(|byte| format!("{byte:02X}"))
                                                .collect::<Vec<_>>()
                                                .join(" "),
                                        ),
                                    ),
                                ]
                                .into_iter()
                                .collect(),
                            )
                        })
                        .collect(),
                ))
            }
            _ => return Ok(PipelineDispatch::NotHandled),
        };
        Ok(PipelineDispatch::Handled(value))
    }

    fn pipeline_text_sources(
        &mut self,
        parser: &ParsedSource,
        arguments: &[String],
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Vec<(String, usize, String)>, PowerShellError> {
        if let Some(path) = named_or_positional(arguments, &["-path", "-literalpath"], usize::MAX) {
            let path = self
                .eval_expression(parser, &path, host, depth)?
                .as_string();
            let text = host
                .read_file(&path, Engine::PowerShell, depth)
                .map_or_else(String::new, |bytes| {
                    String::from_utf8_lossy(&bytes).into_owned()
                });
            return Ok(text
                .lines()
                .enumerate()
                .map(|(index, line)| (path.clone(), index + 1, line.into()))
                .collect());
        }

        let values = if self.variables.contains_key("input") {
            pipeline_values(self.variables.get("input").cloned())
        } else {
            let input = named_or_positional(arguments, &["-inputobject"], 1)
                .map(|value| self.eval_expression(parser, &value, host, depth))
                .transpose()?
                .unwrap_or(Value::Null);
            pipeline_values(Some(input))
        };
        Ok(values
            .into_iter()
            .flat_map(|value| {
                value
                    .as_string()
                    .lines()
                    .enumerate()
                    .map(|(index, line)| (String::new(), index + 1, line.into()))
                    .collect::<Vec<_>>()
            })
            .collect())
    }
}

fn compare_property(actual: &Value, operator: &str, expected: &Value) -> bool {
    let actual_string = actual.as_string();
    let expected_string = expected.as_string();
    match operator.to_ascii_lowercase().as_str() {
        "-eq" | "-ieq" => actual_string.eq_ignore_ascii_case(&expected_string),
        "-ne" | "-ine" => !actual_string.eq_ignore_ascii_case(&expected_string),
        "-ceq" => actual_string == expected_string,
        "-cne" => actual_string != expected_string,
        "-like" | "-ilike" => wildcard_match(&actual_string, &expected_string, false),
        "-clike" => wildcard_match(&actual_string, &expected_string, true),
        "-match" | "-imatch" => RegexBuilder::new(&expected_string)
            .case_insensitive(true)
            .build()
            .is_ok_and(|regex| regex.is_match(&actual_string)),
        "-cmatch" => RegexBuilder::new(&expected_string)
            .build()
            .is_ok_and(|regex| regex.is_match(&actual_string)),
        "-gt" | "-ge" | "-lt" | "-le" => {
            let Some(actual) = actual.as_f64() else {
                return false;
            };
            let Some(expected) = expected.as_f64() else {
                return false;
            };
            match operator {
                "-gt" => actual > expected,
                "-ge" => actual >= expected,
                "-lt" => actual < expected,
                "-le" => actual <= expected,
                _ => false,
            }
        }
        _ => actual.truthy(),
    }
}

fn wildcard_match(input: &str, pattern: &str, case_sensitive: bool) -> bool {
    let mut regex = String::from("^");
    for character in pattern.chars() {
        match character {
            '*' => regex.push_str(".*"),
            '?' => regex.push('.'),
            other => regex.push_str(&regex::escape(&other.to_string())),
        }
    }
    regex.push('$');
    RegexBuilder::new(&regex)
        .case_insensitive(!case_sensitive)
        .build()
        .is_ok_and(|regex| regex.is_match(input))
}

fn has_named_block(arguments: &[String]) -> bool {
    ["-begin", "-process", "-end"]
        .iter()
        .any(|name| find_switch(arguments, name).is_some())
}

fn named_script_block(parser: &ParsedSource, arguments: &[String], name: &str) -> Option<String> {
    let index = find_switch(arguments, name)?;
    let expression = arguments.get(index + 1)?;
    crate::syntax::extract_delimited(parser, expression, '{', '}').map(|(body, _)| body.into())
}

fn pipeline_values(value: Option<Value>) -> Vec<Value> {
    match value.unwrap_or(Value::Null) {
        Value::Array(values) => values,
        Value::Null => Vec::new(),
        value => vec![value],
    }
}

fn command_input(
    emulator: &mut PowerShellEmulator,
    parser: &ParsedSource,
    arguments: &[String],
    host: &mut dyn Host,
    depth: usize,
) -> Result<String, PowerShellError> {
    if arguments.is_empty() {
        Ok(emulator
            .variables
            .get("input")
            .map_or_else(String::new, Value::as_string))
    } else {
        Ok(emulator
            .eval_joined_arguments(parser, arguments, host, depth)?
            .as_string())
    }
}

fn match_ranges(
    line: &str,
    pattern: &str,
    case_sensitive: bool,
    simple: bool,
) -> Vec<(usize, usize)> {
    if simple {
        let haystack = if case_sensitive {
            line.into()
        } else {
            line.to_ascii_lowercase()
        };
        let needle = if case_sensitive {
            pattern.into()
        } else {
            pattern.to_ascii_lowercase()
        };
        return haystack
            .match_indices(&needle)
            .map(|(start, value)| (start, start + value.len()))
            .collect();
    }
    let mut builder = RegexBuilder::new(pattern);
    builder.case_insensitive(!case_sensitive);
    builder.build().map_or_else(
        |_| Vec::new(),
        |regex| {
            regex
                .find_iter(line)
                .map(|matched| (matched.start(), matched.end()))
                .collect()
        },
    )
}

fn sort_key(value: &Value, property: Option<&str>) -> String {
    property.map_or_else(
        || value.as_string().to_ascii_lowercase(),
        |property| {
            PowerShellEmulator::read_member(value.clone(), property)
                .as_string()
                .to_ascii_lowercase()
        },
    )
}

fn compare_objects(reference: Value, difference: Value) -> Vec<Value> {
    let reference = pipeline_values(Some(reference));
    let difference = pipeline_values(Some(difference));
    let reference_keys = reference
        .iter()
        .map(|value| value.as_string().to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    let difference_keys = difference
        .iter()
        .map(|value| value.as_string().to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    reference
        .into_iter()
        .filter(|value| !difference_keys.contains(&value.as_string().to_ascii_lowercase()))
        .map(|value| comparison_value(value, "<="))
        .chain(
            difference
                .into_iter()
                .filter(|value| !reference_keys.contains(&value.as_string().to_ascii_lowercase()))
                .map(|value| comparison_value(value, "=>")),
        )
        .collect()
}

fn comparison_value(value: Value, indicator: &str) -> Value {
    Value::Map(
        [
            ("InputObject".into(), value),
            ("SideIndicator".into(), Value::String(indicator.into())),
        ]
        .into_iter()
        .collect(),
    )
}

fn parse_csv(input: &str) -> Vec<Value> {
    let mut lines = input.lines();
    let Some(header) = lines.next() else {
        return Vec::new();
    };
    let headers = parse_csv_line(header);
    lines
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let values = parse_csv_line(line);
            Value::Map(
                headers
                    .iter()
                    .enumerate()
                    .map(|(index, header)| {
                        (
                            header.clone(),
                            Value::String(values.get(index).cloned().unwrap_or_default()),
                        )
                    })
                    .collect(),
            )
        })
        .collect()
}

fn parse_csv_line(line: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut characters = line.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '"' if quoted && characters.peek() == Some(&'"') => {
                current.push('"');
                characters.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => values.push(std::mem::take(&mut current)),
            character => current.push(character),
        }
    }
    values.push(current);
    values
}

fn serialize_csv(values: &[Value]) -> String {
    let keys = values
        .iter()
        .filter_map(|value| match value {
            Value::Map(values) => Some(values.keys().cloned()),
            _ => None,
        })
        .flatten()
        .collect::<BTreeSet<_>>();
    if keys.is_empty() {
        return values
            .iter()
            .map(|value| csv_escape(&value.as_string()))
            .collect::<Vec<_>>()
            .join("\n");
    }
    let keys = keys.into_iter().collect::<Vec<_>>();
    let mut lines = vec![keys
        .iter()
        .map(|key| csv_escape(key))
        .collect::<Vec<_>>()
        .join(",")];
    lines.extend(values.iter().map(|value| {
        keys.iter()
            .map(|key| match value {
                Value::Map(values) => values
                    .get(key)
                    .map_or_else(String::new, |value| csv_escape(&value.as_string())),
                _ => String::new(),
            })
            .collect::<Vec<_>>()
            .join(",")
    }));
    lines.join("\n")
}

fn csv_escape(value: &str) -> String {
    if value.contains([',', '"', '\r', '\n']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_parser_handles_quoted_fields() {
        let values = parse_csv("Name,Value\nsafe,\"one,two\"");
        let Value::Map(row) = &values[0] else {
            panic!("expected map")
        };
        assert_eq!(row["Value"], Value::String("one,two".into()));
    }

    #[test]
    fn compare_objects_marks_each_side() {
        let values = compare_objects(
            Value::Array(vec![Value::Number(1), Value::Number(2)]),
            Value::Array(vec![Value::Number(2), Value::Number(3)]),
        );
        assert_eq!(values.len(), 2);
    }
}
