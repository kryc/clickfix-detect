use crate::archives::{create_zip, extract_zip};
use crate::syntax::{extract_delimited, find_switch, named_or_positional};
use crate::transforms::{hex_encode, md5_hash, sha1_hash, sha256_hash};
use crate::{PowerShellEmulator, PowerShellError, Value};
use emulator_core::{ArtifactKind, Engine, EventKind, Host, TraceEvent};
use std::collections::BTreeMap;

pub(crate) enum BuiltinDispatch {
    NotHandled,
    Handled(Option<Value>),
}

impl PowerShellEmulator {
    #[allow(clippy::too_many_lines)]
    pub(crate) fn execute_extended_command(
        &mut self,
        command: &str,
        arguments: &[String],
        statement: &str,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<BuiltinDispatch, PowerShellError> {
        let value = match command {
            "new-object" => Some(self.eval_new_object(statement, host, depth)?),
            "foreach-object" => {
                let body = script_block(arguments);
                let values = pipeline_values(self.variables.get("input").cloned());
                let mut output = Vec::new();
                for (index, value) in values.into_iter().enumerate() {
                    if index >= host.limits().max_loop_iterations {
                        host.emit(TraceEvent::new(
                            depth,
                            Engine::PowerShell,
                            EventKind::LimitReached,
                            "ForEach-Object iteration limit reached",
                        ));
                        break;
                    }
                    self.variables.insert("_".into(), value.clone());
                    self.variables.insert("psitem".into(), value);
                    let (_, values) = self.execute_script_collect(&body, host, depth + 1)?;
                    output.extend(values);
                }
                Some(Value::Array(output))
            }
            "where-object" => {
                let body = script_block(arguments);
                let values = pipeline_values(self.variables.get("input").cloned());
                let mut output = Vec::new();
                for value in values {
                    self.variables.insert("_".into(), value.clone());
                    self.variables.insert("psitem".into(), value.clone());
                    let (result, _) = self.execute_script_collect(&body, host, depth + 1)?;
                    if result.is_some_and(|result| result.truthy()) {
                        output.push(value);
                    }
                }
                Some(Value::Array(output))
            }
            "select-object" => {
                let values = pipeline_values(self.variables.get("input").cloned());
                if let Some(property) =
                    named_or_positional(arguments, &["-expandproperty"], usize::MAX)
                {
                    let property = property.trim_matches(['\'', '"']);
                    let expanded = values
                        .into_iter()
                        .map(|value| Self::read_member(value, property))
                        .collect::<Vec<_>>();
                    if expanded.len() == 1 {
                        expanded.into_iter().next()
                    } else {
                        Some(Value::Array(expanded))
                    }
                } else {
                    let skip = numeric_argument(arguments, &["-skip"]).unwrap_or_default();
                    let first = numeric_argument(arguments, &["-first"]);
                    let last = numeric_argument(arguments, &["-last"]);
                    let mut selected = values.into_iter().skip(skip).collect::<Vec<_>>();
                    if let Some(first) = first {
                        selected.truncate(first);
                    }
                    if let Some(last) = last {
                        let start = selected.len().saturating_sub(last);
                        selected = selected.split_off(start);
                    }
                    Some(Value::Array(selected))
                }
            }
            "measure-object" => {
                let values = pipeline_values(self.variables.get("input").cloned());
                Some(Value::Map(
                    [(
                        "Count".into(),
                        Value::Number(i64::try_from(values.len()).unwrap_or(i64::MAX)),
                    )]
                    .into_iter()
                    .collect(),
                ))
            }
            "out-string" => Some(Value::String(
                self.variables
                    .get("input")
                    .map_or_else(String::new, Value::as_string),
            )),
            "convertfrom-json" => {
                let input = if arguments.is_empty() {
                    self.variables
                        .get("input")
                        .map_or_else(String::new, Value::as_string)
                } else {
                    self.eval_joined_arguments(arguments, host, depth)?
                        .as_string()
                };
                Some(
                    serde_json::from_str::<serde_json::Value>(&input)
                        .map(json_to_value)
                        .map_err(|error| PowerShellError::Evaluation(error.to_string()))?,
                )
            }
            "convertto-json" => {
                let input = if arguments.is_empty() {
                    self.variables.get("input").cloned().unwrap_or(Value::Null)
                } else {
                    self.eval_joined_arguments(arguments, host, depth)?
                };
                Some(Value::String(
                    serde_json::to_string(&value_to_json(&input))
                        .map_err(|error| PowerShellError::Evaluation(error.to_string()))?,
                ))
            }
            "convertto-securestring" => {
                let value = self
                    .eval_joined_arguments(arguments, host, depth)?
                    .as_string();
                Some(Value::Map(
                    [
                        ("__type".into(), Value::String("SecureString".into())),
                        ("data".into(), Value::String(value)),
                    ]
                    .into_iter()
                    .collect(),
                ))
            }
            "convertfrom-securestring" => {
                let value = self.eval_joined_arguments(arguments, host, depth)?;
                Some(match value {
                    Value::Map(values) => values.get("data").cloned().unwrap_or(Value::Null),
                    value => value,
                })
            }
            "write-error" => {
                let message = self
                    .eval_joined_arguments(arguments, host, depth)?
                    .as_string();
                self.error_output.push(message.clone());
                self.variables
                    .entry("error".into())
                    .or_insert_with(|| Value::Array(Vec::new()));
                if let Some(Value::Array(errors)) = self.variables.get_mut("error") {
                    errors.insert(0, Value::String(message.clone()));
                }
                host.emit(
                    TraceEvent::new(
                        depth,
                        Engine::PowerShell,
                        EventKind::Output,
                        "captured PowerShell error output",
                    )
                    .with_data("value", message),
                );
                Some(Value::Null)
            }
            "write-warning" | "write-verbose" | "write-information" | "write-debug" => {
                let message = self
                    .eval_joined_arguments(arguments, host, depth)?
                    .as_string();
                host.emit(
                    TraceEvent::new(
                        depth,
                        Engine::PowerShell,
                        EventKind::Output,
                        format!("captured {command} output"),
                    )
                    .with_data("value", message.clone()),
                );
                Some(Value::String(message))
            }
            "write-progress" => {
                host.emit(
                    TraceEvent::new(
                        depth,
                        Engine::PowerShell,
                        EventKind::Output,
                        "captured PowerShell progress output",
                    )
                    .with_data("arguments", arguments.join(" ")),
                );
                Some(Value::Null)
            }
            "start-sleep" | "sleep" => {
                let duration = named_or_positional(arguments, &["-seconds", "-milliseconds"], 0)
                    .unwrap_or_default();
                host.emit(
                    TraceEvent::new(
                        depth,
                        Engine::PowerShell,
                        EventKind::Command,
                        "fast-forwarded PowerShell sleep",
                    )
                    .with_data("requested_duration", duration),
                );
                Some(Value::Null)
            }
            "get-random" => {
                let minimum = numeric_argument(arguments, &["-minimum"]).unwrap_or_default();
                let maximum = numeric_argument(arguments, &["-maximum"]).unwrap_or(2_147_483_647);
                let count = numeric_argument(arguments, &["-count"]).unwrap_or(1);
                let values = (0..count)
                    .map(|_| {
                        self.random_state ^= self.random_state << 13;
                        self.random_state ^= self.random_state >> 7;
                        self.random_state ^= self.random_state << 17;
                        let width = maximum.saturating_sub(minimum).max(1);
                        let value = minimum
                            + usize::try_from(self.random_state).unwrap_or_default() % width;
                        Value::Number(i64::try_from(value).unwrap_or(i64::MAX))
                    })
                    .collect::<Vec<_>>();
                if count == 1 {
                    values.into_iter().next()
                } else {
                    Some(Value::Array(values))
                }
            }
            "get-date" => Some(Value::String("2024-01-01T00:00:00Z".into())),
            "get-command" => {
                let requested = arguments
                    .first()
                    .map(|argument| argument.trim_matches(['\'', '"']).to_ascii_lowercase())
                    .unwrap_or_default();
                let resolved = self.aliases.get(&requested).cloned().unwrap_or(requested);
                Some(Value::Object(format!("CommandInfo:{resolved}")))
            }
            "get-alias" => {
                let alias = arguments
                    .first()
                    .map(|argument| argument.trim_matches(['\'', '"']).to_ascii_lowercase())
                    .unwrap_or_default();
                Some(
                    self.aliases
                        .get(&alias)
                        .cloned()
                        .map_or(Value::Null, Value::String),
                )
            }
            "set-alias" | "new-alias" => {
                let alias = named_or_positional(arguments, &["-name"], 0)
                    .unwrap_or_default()
                    .trim_matches(['\'', '"'])
                    .to_ascii_lowercase();
                let target = named_or_positional(arguments, &["-value"], 1)
                    .unwrap_or_default()
                    .trim_matches(['\'', '"'])
                    .to_ascii_lowercase();
                self.aliases.insert(alias, target.clone());
                Some(Value::String(target))
            }
            "get-variable" => {
                let name = named_or_positional(arguments, &["-name"], 0)
                    .unwrap_or_default()
                    .trim_matches(['\'', '"'])
                    .trim_start_matches('$')
                    .to_ascii_lowercase();
                let value = self.variables.get(&name).cloned().unwrap_or(Value::Null);
                if find_switch(arguments, "-valueonly").is_some() {
                    Some(value)
                } else {
                    Some(Value::Map(
                        [
                            ("Name".into(), Value::String(name)),
                            ("Value".into(), value),
                        ]
                        .into_iter()
                        .collect(),
                    ))
                }
            }
            "set-variable" | "new-variable" => {
                let name = named_or_positional(arguments, &["-name"], 0)
                    .unwrap_or_default()
                    .trim_matches(['\'', '"'])
                    .trim_start_matches('$')
                    .to_ascii_lowercase();
                let value_expression =
                    named_or_positional(arguments, &["-value"], 1).unwrap_or_default();
                let value = self.eval_expression(&value_expression, host, depth)?;
                self.variables.insert(name, value.clone());
                Some(value)
            }
            "join-path" => {
                let parent = named_or_positional(arguments, &["-path"], 0).unwrap_or_default();
                let child = named_or_positional(arguments, &["-childpath"], 1).unwrap_or_default();
                let parent = self.eval_expression(&parent, host, depth)?.as_string();
                let child = self.eval_expression(&child, host, depth)?.as_string();
                Some(Value::String(format!(
                    "{}\\{}",
                    parent.trim_end_matches(['\\', '/']),
                    child.trim_start_matches(['\\', '/'])
                )))
            }
            "split-path" => {
                let path = named_or_positional(arguments, &["-path"], 0).unwrap_or_default();
                let path = self.eval_expression(&path, host, depth)?.as_string();
                if find_switch(arguments, "-leaf").is_some() {
                    Some(Value::String(
                        path.rsplit(['\\', '/']).next().unwrap_or_default().into(),
                    ))
                } else {
                    Some(Value::String(
                        path.rsplit_once(['\\', '/'])
                            .map_or_else(String::new, |(parent, _)| parent.into()),
                    ))
                }
            }
            "resolve-path" => {
                let path = named_or_positional(arguments, &["-path", "-literalpath"], 0)
                    .unwrap_or_default();
                let path = self.eval_expression(&path, host, depth)?.as_string();
                Some(Value::Map(
                    [("Path".into(), Value::String(path))].into_iter().collect(),
                ))
            }
            "test-path" => {
                let path = named_or_positional(arguments, &["-path", "-literalpath"], 0)
                    .unwrap_or_default();
                let path = self.eval_expression(&path, host, depth)?.as_string();
                Some(Value::Bool(
                    host.read_file(&path, Engine::PowerShell, depth).is_some(),
                ))
            }
            "copy-item" | "copy" | "cp" | "move-item" | "move" | "mv" => {
                let source = named_or_positional(arguments, &["-path", "-literalpath"], 0)
                    .unwrap_or_default();
                let destination =
                    named_or_positional(arguments, &["-destination"], 1).unwrap_or_default();
                let source = self.eval_expression(&source, host, depth)?.as_string();
                let destination = self.eval_expression(&destination, host, depth)?.as_string();
                let result = self.copy_filesystem_item(
                    &source,
                    &destination,
                    command.starts_with("move") || command == "mv",
                    find_switch(arguments, "-recurse").is_some(),
                    host,
                    depth,
                )?;
                let value = if find_switch(arguments, "-passthru").is_some() {
                    result.unwrap_or(Value::Null)
                } else {
                    Value::Null
                };
                return Ok(BuiltinDispatch::Handled(Some(value)));
            }
            "rename-item" | "ren" => {
                let source = named_or_positional(arguments, &["-path", "-literalpath"], 0)
                    .unwrap_or_default();
                let new_name = named_or_positional(arguments, &["-newname"], 1).unwrap_or_default();
                let source = self.eval_expression(&source, host, depth)?.as_string();
                let new_name = self.eval_expression(&new_name, host, depth)?.as_string();
                let parent = source
                    .rsplit_once(['\\', '/'])
                    .map_or("", |(parent, _)| parent);
                let destination = if parent.is_empty() {
                    new_name
                } else {
                    format!("{parent}\\{new_name}")
                };
                if let Some(bytes) = host.read_file(&source, Engine::PowerShell, depth) {
                    host.write_file(&destination, &bytes, false, Engine::PowerShell, depth)?;
                    host.delete_file(&source, Engine::PowerShell, depth);
                    Some(Value::String(destination))
                } else {
                    Some(Value::Null)
                }
            }
            "expand-archive" => {
                let archive = named_or_positional(arguments, &["-path", "-literalpath"], 0)
                    .unwrap_or_default();
                let destination =
                    named_or_positional(arguments, &["-destinationpath"], 1).unwrap_or_default();
                let archive = self.eval_expression(&archive, host, depth)?.as_string();
                let destination = self.eval_expression(&destination, host, depth)?.as_string();
                let Some(bytes) = host.read_file(&archive, Engine::PowerShell, depth) else {
                    return Ok(BuiltinDispatch::Handled(Some(Value::Null)));
                };
                let files = match extract_zip(&bytes) {
                    Ok(files) => files,
                    Err(error) => {
                        host.unsupported(
                            Engine::PowerShell,
                            depth,
                            &format!("Expand-Archive could not parse {archive}: {error}"),
                        );
                        return Ok(BuiltinDispatch::Handled(Some(Value::Null)));
                    }
                };
                let mut paths = Vec::new();
                for (entry, bytes) in files {
                    let path = format!(
                        "{}\\{}",
                        destination.trim_end_matches(['\\', '/']),
                        entry.trim_start_matches(['\\', '/'])
                    );
                    host.write_file(&path, &bytes, false, Engine::PowerShell, depth)?;
                    paths.push(Value::String(path));
                }
                if find_switch(arguments, "-passthru").is_some() {
                    Some(Value::Array(paths))
                } else {
                    Some(Value::Null)
                }
            }
            "compress-archive" => {
                let source = named_or_positional(arguments, &["-path", "-literalpath"], 0)
                    .unwrap_or_default();
                let destination =
                    named_or_positional(arguments, &["-destinationpath"], 1).unwrap_or_default();
                let source = self.eval_expression(&source, host, depth)?.as_string();
                let destination = self.eval_expression(&destination, host, depth)?.as_string();
                let Some(bytes) = host.read_file(&source, Engine::PowerShell, depth) else {
                    return Ok(BuiltinDispatch::Handled(Some(Value::Null)));
                };
                let name = source.rsplit(['\\', '/']).next().unwrap_or("artifact.bin");
                let archive = create_zip(name, &bytes)
                    .map_err(|error| PowerShellError::Evaluation(error.to_string()))?;
                host.write_file(&destination, &archive, false, Engine::PowerShell, depth)?;
                Some(Value::Null)
            }
            "get-filehash" => {
                let path = named_or_positional(arguments, &["-path", "-literalpath"], 0)
                    .unwrap_or_default();
                let algorithm = named_or_positional(arguments, &["-algorithm"], usize::MAX)
                    .unwrap_or_else(|| "SHA256".into())
                    .trim_matches(['\'', '"'])
                    .to_ascii_uppercase();
                let path = self.eval_expression(&path, host, depth)?.as_string();
                let Some(bytes) = host.read_file(&path, Engine::PowerShell, depth) else {
                    return Ok(BuiltinDispatch::Handled(Some(Value::Null)));
                };
                let hash = match algorithm.as_str() {
                    "MD5" => hex_encode(&md5_hash(&bytes)),
                    "SHA1" => hex_encode(&sha1_hash(&bytes)),
                    _ => hex_encode(&sha256_hash(&bytes)),
                }
                .to_ascii_uppercase();
                Some(Value::Map(
                    [
                        ("Algorithm".into(), Value::String(algorithm)),
                        ("Hash".into(), Value::String(hash)),
                        ("Path".into(), Value::String(path)),
                    ]
                    .into_iter()
                    .collect(),
                ))
            }
            "add-type" => {
                let source = named_or_positional(arguments, &["-typedefinition"], 0)
                    .unwrap_or_else(|| arguments.join(" "));
                let source = self.eval_expression(&source, host, depth)?.as_string();
                host.add_artifact(
                    ArtifactKind::Script,
                    "add-type-source.cs",
                    "text/x-csharp",
                    source.as_bytes(),
                    depth,
                );
                for api in [
                    "VirtualAlloc",
                    "VirtualProtect",
                    "WriteProcessMemory",
                    "CreateRemoteThread",
                    "CreateThread",
                    "NtAllocateVirtualMemory",
                    "DllImport",
                ] {
                    if source
                        .to_ascii_lowercase()
                        .contains(&api.to_ascii_lowercase())
                    {
                        host.unsupported(
                            Engine::PowerShell,
                            depth,
                            &format!("modeled native interop declaration: {api}"),
                        );
                    }
                }
                Some(Value::Object("ModeledAddType".into()))
            }
            "get-ciminstance" | "get-wmiobject" => {
                let class = named_or_positional(arguments, &["-classname", "-class"], 0)
                    .unwrap_or_default();
                Some(Self::cim_class_value(class.trim_matches(['\'', '"'])))
            }
            "get-process" => Some(Value::Array(vec![
                Value::Map(
                    [
                        ("Name".into(), Value::String("powershell".into())),
                        ("Id".into(), Value::Number(4_242)),
                    ]
                    .into_iter()
                    .collect(),
                ),
                Value::Map(
                    [
                        ("Name".into(), Value::String("explorer".into())),
                        ("Id".into(), Value::Number(1_337)),
                    ]
                    .into_iter()
                    .collect(),
                ),
            ])),
            "stop-process" => {
                let process =
                    named_or_positional(arguments, &["-id", "-name"], 0).unwrap_or_default();
                host.unsupported(
                    Engine::PowerShell,
                    depth,
                    &format!("modeled process termination request for {process}"),
                );
                Some(Value::Null)
            }
            "hostname" => {
                self.stdout.push("ANALYSIS-HOST".into());
                Some(Value::String("ANALYSIS-HOST".into()))
            }
            "whoami" => {
                self.stdout.push(r"analysis\user".into());
                Some(Value::String(r"analysis\user".into()))
            }
            "invoke-cimmethod" | "invoke-wmimethod" => {
                let method = named_or_positional(arguments, &["-methodname", "-name"], usize::MAX)
                    .unwrap_or_default();
                if method.eq_ignore_ascii_case("Create") {
                    let command_line =
                        named_or_positional(arguments, &["-arguments"], 0).unwrap_or_default();
                    let words = crate::syntax::split_windows_command_line(&command_line);
                    if let Some(program) = words.first() {
                        Self::spawn(
                            program,
                            words[1..].to_vec(),
                            "PowerShell WMI/CIM process creation",
                            host,
                            depth,
                        )?;
                    }
                }
                Some(Value::Object("ModeledCimMethod".into()))
            }
            "register-scheduledtask"
            | "new-scheduledtaskaction"
            | "schtasks"
            | "new-service"
            | "register-wmievent" => {
                host.write_registry(
                    r"HKCU\Software\EmulatorState\Persistence",
                    statement,
                    Engine::PowerShell,
                    depth,
                );
                Some(Value::Object("ModeledScheduledTask".into()))
            }
            _ => return Ok(BuiltinDispatch::NotHandled),
        };
        Ok(BuiltinDispatch::Handled(value))
    }
}

fn pipeline_values(value: Option<Value>) -> Vec<Value> {
    match value.unwrap_or(Value::Null) {
        Value::Array(values) => values,
        Value::Null => Vec::new(),
        value => vec![value],
    }
}

fn script_block(arguments: &[String]) -> String {
    let expression = arguments.join(" ");
    extract_delimited(expression.trim(), '{', '}')
        .map_or_else(|| expression.clone(), |(body, _)| body.into())
}

fn numeric_argument(arguments: &[String], names: &[&str]) -> Option<usize> {
    named_or_positional(arguments, names, usize::MAX)?
        .trim_matches(['\'', '"'])
        .parse()
        .ok()
}

pub(crate) fn network_response_value(response: emulator_core::NetworkResponse) -> Value {
    let headers = response
        .headers
        .into_iter()
        .map(|(key, value)| (key, Value::String(value)))
        .collect::<BTreeMap<_, _>>();
    let content =
        String::from_utf8(response.body.clone()).map_or(Value::Bytes(response.body), Value::String);
    let text = content.as_string();
    Value::Map(
        [
            (
                "StatusCode".into(),
                Value::Number(i64::from(response.status)),
            ),
            ("Content".into(), content),
            ("RawContent".into(), Value::String(text.clone())),
            ("Headers".into(), Value::Map(headers)),
            (
                "StatusDescription".into(),
                Value::String(if response.status < 400 { "OK" } else { "Error" }.into()),
            ),
            ("Links".into(), html_attributes(&text, "a", "href")),
            ("Images".into(), html_attributes(&text, "img", "src")),
            ("Forms".into(), html_attributes(&text, "form", "action")),
            (
                "ParsedHtml".into(),
                Value::Object("ModeledHtmlDocument".into()),
            ),
        ]
        .into_iter()
        .collect(),
    )
}

fn html_attributes(input: &str, tag: &str, attribute: &str) -> Value {
    let pattern = format!(r#"(?is)<{tag}\b[^>]*\b{attribute}\s*=\s*["']([^"']+)["'][^>]*>"#);
    Value::Array(regex::Regex::new(&pattern).map_or_else(
        |_| Vec::new(),
        |regex| {
            regex
                .captures_iter(input)
                .filter_map(|captures| captures.get(1))
                .map(|value| {
                    Value::Map(
                        [(
                            attribute.to_ascii_uppercase(),
                            Value::String(value.as_str().into()),
                        )]
                        .into_iter()
                        .collect(),
                    )
                })
                .collect()
        },
    ))
}

pub(crate) fn json_to_value(value: serde_json::Value) -> Value {
    match value {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(value) => Value::Bool(value),
        serde_json::Value::Number(value) => value.as_i64().map_or_else(
            || Value::Float(value.as_f64().unwrap_or_default()),
            Value::Number,
        ),
        serde_json::Value::String(value) => Value::String(value),
        serde_json::Value::Array(values) => {
            Value::Array(values.into_iter().map(json_to_value).collect())
        }
        serde_json::Value::Object(values) => Value::Map(
            values
                .into_iter()
                .map(|(key, value)| (key, json_to_value(value)))
                .collect(),
        ),
    }
}

fn value_to_json(value: &Value) -> serde_json::Value {
    match value {
        Value::Null => serde_json::Value::Null,
        Value::Bool(value) => serde_json::Value::Bool(*value),
        Value::Number(value) => (*value).into(),
        Value::Float(value) => serde_json::Number::from_f64(*value)
            .map_or(serde_json::Value::Null, serde_json::Value::Number),
        Value::String(value) | Value::Object(value) => value.clone().into(),
        Value::Bytes(value) => serde_json::Value::Array(
            value
                .iter()
                .map(|byte| serde_json::Value::from(*byte))
                .collect(),
        ),
        Value::Array(values) => {
            serde_json::Value::Array(values.iter().map(value_to_json).collect())
        }
        Value::Map(values) => serde_json::Value::Object(
            values
                .iter()
                .map(|(key, value)| (key.clone(), value_to_json(value)))
                .collect(),
        ),
    }
}
