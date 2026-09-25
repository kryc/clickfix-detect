use crate::archives::extract_zip;
use crate::syntax::normalize_variable;
use crate::{PowerShellEmulator, PowerShellError, Value};
use emulator_core::{windows::classify_com_progid, Engine, Host, NetworkIntent};
use std::collections::BTreeMap;

static NULL_VALUE: Value = Value::Null;

pub(crate) enum ComDispatch {
    NotHandled,
    Handled(Value),
}

impl PowerShellEmulator {
    pub(crate) fn create_com_object(prog_id: &str) -> Value {
        let class = classify_com_progid(prog_id);
        let canonical = class.canonical_progid();
        Value::Map(
            [
                (
                    "__type".into(),
                    Value::String(format!("ComObject:{canonical}")),
                ),
                ("ProgId".into(), Value::String(canonical.into())),
            ]
            .into_iter()
            .collect(),
        )
    }

    #[allow(clippy::too_many_lines)]
    pub(crate) fn eval_com_instance_call(
        &mut self,
        receiver_expression: &str,
        receiver: &Value,
        method: &str,
        args: &[Value],
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<ComDispatch, PowerShellError> {
        let Value::Map(properties) = receiver else {
            return Ok(ComDispatch::NotHandled);
        };
        let Some(com_type) = com_type(properties) else {
            return Ok(ComDispatch::NotHandled);
        };
        let method = method.to_ascii_lowercase();

        let value = match (com_type.to_ascii_lowercase().as_str(), method.as_str()) {
            ("wscript.shell", "run" | "exec") => {
                let command = args.first().map_or_else(String::new, Value::as_string);
                Self::spawn_command_line(&command, "PowerShell WScript.Shell", host, depth)?;
                Value::Map(
                    [
                        ("__type".into(), Value::String("ComResult:Exec".into())),
                        ("ExitCode".into(), Value::Number(0)),
                        ("Status".into(), Value::Number(1)),
                        ("StdOut".into(), Value::String(String::new())),
                        ("StdErr".into(), Value::String(String::new())),
                    ]
                    .into_iter()
                    .collect(),
                )
            }
            ("wscript.shell", "regread") => {
                let path = args.first().map_or_else(String::new, Value::as_string);
                host.read_registry(&path, Engine::PowerShell, depth)
                    .map_or(Value::Null, Value::String)
            }
            ("wscript.shell", "regwrite") => {
                let path = args.first().map_or_else(String::new, Value::as_string);
                let value = args.get(1).map_or_else(String::new, Value::as_string);
                host.write_registry(&path, &value, Engine::PowerShell, depth);
                Value::Null
            }
            ("wscript.shell", "regdelete") => {
                let path = args.first().map_or_else(String::new, Value::as_string);
                host.unsupported(
                    Engine::PowerShell,
                    depth,
                    &format!("virtual registry deletion requested for {path}"),
                );
                Value::Null
            }
            ("wscript.shell", "expandenvironmentstrings") => {
                let input = args.first().map_or_else(String::new, Value::as_string);
                Value::String(expand_environment(&input, host))
            }
            ("wscript.shell", "createshortcut") => Value::Map(
                [
                    (
                        "__type".into(),
                        Value::String("ComObject:WScript.Shortcut".into()),
                    ),
                    ("Path".into(), args.first().cloned().unwrap_or(Value::Null)),
                    ("TargetPath".into(), Value::Null),
                    ("Arguments".into(), Value::Null),
                    ("WorkingDirectory".into(), Value::Null),
                    ("WindowStyle".into(), Value::Number(1)),
                ]
                .into_iter()
                .collect(),
            ),
            ("wscript.shortcut", "save") => {
                let path = properties
                    .get("Path")
                    .map_or_else(String::new, Value::as_string);
                let content = format!(
                    "TargetPath={}\nArguments={}\nWorkingDirectory={}\nWindowStyle={}",
                    property(properties, "TargetPath").as_string(),
                    property(properties, "Arguments").as_string(),
                    property(properties, "WorkingDirectory").as_string(),
                    property(properties, "WindowStyle").as_string(),
                );
                host.write_file(&path, content.as_bytes(), false, Engine::PowerShell, depth)?;
                Value::Null
            }
            ("shell.application", "shellexecute") => {
                let program = args.first().map_or_else(String::new, Value::as_string);
                let command_args = args.get(1).map_or_else(String::new, Value::as_string);
                Self::spawn_command_line(
                    &format!("{program} {command_args}"),
                    "PowerShell Shell.Application",
                    host,
                    depth,
                )?;
                Value::Null
            }
            ("shell.application", "namespace") => Value::Map(
                [
                    (
                        "__type".into(),
                        Value::String("ComObject:Shell.Namespace".into()),
                    ),
                    ("Path".into(), args.first().cloned().unwrap_or(Value::Null)),
                ]
                .into_iter()
                .collect(),
            ),
            ("shell.namespace", "copyhere") => {
                let destination = property(properties, "Path").as_string();
                let source = args.first().map_or_else(String::new, Value::as_string);
                if let Some(bytes) = host.read_file(&source, Engine::PowerShell, depth) {
                    if let Ok(files) = extract_zip(&bytes) {
                        for (entry, bytes) in files {
                            host.write_file(
                                &format!(
                                    "{}\\{}",
                                    destination.trim_end_matches(['\\', '/']),
                                    entry
                                ),
                                &bytes,
                                false,
                                Engine::PowerShell,
                                depth,
                            )?;
                        }
                    } else {
                        let name = source.rsplit(['\\', '/']).next().unwrap_or("artifact.bin");
                        host.write_file(
                            &format!("{}\\{name}", destination.trim_end_matches(['\\', '/'])),
                            &bytes,
                            false,
                            Engine::PowerShell,
                            depth,
                        )?;
                    }
                }
                Value::Null
            }
            ("msxml2.xmlhttp" | "winhttp.winhttprequest.5.1", "open") => {
                let method = args.first().map_or_else(|| "GET".into(), Value::as_string);
                let url = args.get(1).map_or_else(String::new, Value::as_string);
                self.update_com_properties(
                    receiver_expression,
                    [
                        ("Method".into(), Value::String(method)),
                        ("Url".into(), Value::String(url)),
                    ],
                );
                Value::Null
            }
            ("msxml2.xmlhttp" | "winhttp.winhttprequest.5.1", "setrequestheader") => {
                let name = args.first().map_or_else(String::new, Value::as_string);
                let value = args.get(1).map_or_else(String::new, Value::as_string);
                let mut headers = match properties.get("Headers").cloned() {
                    Some(Value::Map(headers)) => headers,
                    _ => BTreeMap::new(),
                };
                headers.insert(name, Value::String(value));
                self.update_com_properties(
                    receiver_expression,
                    [("Headers".into(), Value::Map(headers))],
                );
                Value::Null
            }
            ("msxml2.xmlhttp" | "winhttp.winhttprequest.5.1", "send") => {
                let method = property(properties, "Method").as_string();
                let url = property(properties, "Url").as_string();
                let response = host.network_request(NetworkIntent {
                    method: if method.is_empty() {
                        "GET".into()
                    } else {
                        method
                    },
                    url,
                    origin: format!("PowerShell COM {com_type}.Send"),
                    depth,
                });
                if let Some(response) = response {
                    let text = String::from_utf8_lossy(&response.body).into_owned();
                    self.update_com_properties(
                        receiver_expression,
                        [
                            ("Status".into(), Value::Number(i64::from(response.status))),
                            ("ResponseBody".into(), Value::Bytes(response.body)),
                            ("ResponseText".into(), Value::String(text)),
                        ],
                    );
                }
                Value::Null
            }
            ("adodb.stream", "open" | "close") | ("textstream", "close") => Value::Null,
            ("adodb.stream", "write") => {
                let mut bytes = property(properties, "Data").as_bytes();
                bytes.extend(args.first().map_or_else(Vec::new, Value::as_bytes));
                self.update_com_properties(
                    receiver_expression,
                    [("Data".into(), Value::Bytes(bytes))],
                );
                Value::Null
            }
            ("adodb.stream", "writetext") => {
                let mut text = property(properties, "Data").as_string();
                text.push_str(&args.first().map_or_else(String::new, Value::as_string));
                self.update_com_properties(
                    receiver_expression,
                    [("Data".into(), Value::String(text))],
                );
                Value::Null
            }
            ("adodb.stream", "loadfromfile") => {
                let path = args.first().map_or_else(String::new, Value::as_string);
                let data = host
                    .read_file(&path, Engine::PowerShell, depth)
                    .map_or(Value::Null, Value::Bytes);
                self.update_com_properties(receiver_expression, [("Data".into(), data)]);
                Value::Null
            }
            ("adodb.stream", "savetofile") => {
                let path = args.first().map_or_else(String::new, Value::as_string);
                host.write_file(
                    &path,
                    &property(properties, "Data").as_bytes(),
                    false,
                    Engine::PowerShell,
                    depth,
                )?;
                Value::Null
            }
            ("adodb.stream", "read") => property(properties, "Data").clone(),
            ("adodb.stream", "readtext") => Value::String(property(properties, "Data").as_string()),
            ("scripting.filesystemobject", "createtextfile") => Value::Map(
                [
                    (
                        "__type".into(),
                        Value::String("ComObject:TextStream".into()),
                    ),
                    ("Path".into(), args.first().cloned().unwrap_or(Value::Null)),
                    ("Data".into(), Value::String(String::new())),
                ]
                .into_iter()
                .collect(),
            ),
            ("scripting.filesystemobject", "fileexists") => {
                let path = args.first().map_or_else(String::new, Value::as_string);
                Value::Bool(host.read_file(&path, Engine::PowerShell, depth).is_some())
            }
            ("scripting.filesystemobject", "deletefile") => {
                let path = args.first().map_or_else(String::new, Value::as_string);
                Value::Bool(host.delete_file(&path, Engine::PowerShell, depth))
            }
            ("textstream", "write" | "writeline") => {
                let mut data = property(properties, "Data").as_string();
                data.push_str(&args.first().map_or_else(String::new, Value::as_string));
                if method == "writeline" {
                    data.push_str("\r\n");
                }
                let path = property(properties, "Path").as_string();
                host.write_file(&path, data.as_bytes(), false, Engine::PowerShell, depth)?;
                self.update_com_properties(
                    receiver_expression,
                    [("Data".into(), Value::String(data))],
                );
                Value::Null
            }
            _ => return Ok(ComDispatch::NotHandled),
        };
        Ok(ComDispatch::Handled(value))
    }

    fn update_com_properties(
        &mut self,
        receiver_expression: &str,
        updates: impl IntoIterator<Item = (String, Value)>,
    ) {
        if !receiver_expression.trim_start().starts_with('$') {
            return;
        }
        let name = normalize_variable(receiver_expression);
        let Some(Value::Map(properties)) = self.variables.get_mut(&name) else {
            return;
        };
        properties.extend(updates);
    }
}

fn com_type(properties: &BTreeMap<String, Value>) -> Option<&str> {
    properties.get("__type").and_then(|value| match value {
        Value::String(value) => value.strip_prefix("ComObject:"),
        _ => None,
    })
}

fn property<'a>(properties: &'a BTreeMap<String, Value>, name: &str) -> &'a Value {
    properties
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map_or(&NULL_VALUE, |(_, value)| value)
}

fn expand_environment(input: &str, host: &dyn Host) -> String {
    let mut output = String::new();
    let mut remainder = input;
    while let Some(start) = remainder.find('%') {
        output.push_str(&remainder[..start]);
        let after = &remainder[start + 1..];
        let Some(end) = after.find('%') else {
            output.push_str(&remainder[start..]);
            return output;
        };
        let name = &after[..end];
        output.push_str(host.environment(name).unwrap_or(""));
        remainder = &after[end + 1..];
    }
    output.push_str(remainder);
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use emulator_core::{AnalysisLimits, VirtualHost};

    #[test]
    fn creates_known_com_objects() {
        let Value::Map(values) = PowerShellEmulator::create_com_object("WScript.Shell") else {
            panic!("expected COM object")
        };
        assert_eq!(
            values["__type"],
            Value::String("ComObject:WScript.Shell".into())
        );
    }

    #[test]
    fn com_xmlhttp_uses_blocked_synthetic_response() {
        let mut emulator = PowerShellEmulator::new();
        emulator.variables.insert(
            "http".into(),
            PowerShellEmulator::create_com_object("MSXML2.XMLHTTP"),
        );
        let mut host = VirtualHost::new(AnalysisLimits::default());
        host.set_default_network_response_text("fixture");

        let receiver = emulator.variables["http"].clone();
        emulator
            .eval_com_instance_call(
                "$http",
                &receiver,
                "Open",
                &[
                    Value::String("GET".into()),
                    Value::String("https://example.invalid".into()),
                ],
                &mut host,
                0,
            )
            .unwrap();
        let receiver = emulator.variables["http"].clone();
        emulator
            .eval_com_instance_call("$http", &receiver, "Send", &[], &mut host, 0)
            .unwrap();

        let Value::Map(values) = &emulator.variables["http"] else {
            panic!("expected map")
        };
        assert_eq!(values["ResponseText"], Value::String("fixture".into()));
    }
}
