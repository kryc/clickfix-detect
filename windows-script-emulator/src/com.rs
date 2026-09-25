use crate::runtime::Runtime;
use crate::value::Value;
use crate::ScriptError;
use emulator_core::{
    windows::{classify_com_progid, process_intent_from_command_line, ComClass},
    Host, NetworkRequest, ProcessResult,
};
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub(crate) enum ComObject {
    WScriptShell,
    FileSystemObject,
    TextFile {
        path: String,
        append: bool,
    },
    Http {
        method: String,
        url: String,
        headers: BTreeMap<String, String>,
        status: u16,
        body: Vec<u8>,
    },
    Stream {
        bytes: Vec<u8>,
        text: bool,
    },
    ShellApplication,
    Process {
        status: i32,
        exit_code: i32,
        stdout: usize,
        stderr: usize,
    },
    ProcessStream {
        lines: Vec<String>,
        cursor: usize,
    },
    Shortcut {
        path: String,
        target: String,
        arguments: String,
    },
    Folder {
        path: String,
    },
    Unknown(String),
}

pub(crate) fn create(runtime: &mut Runtime, program_id: &str) -> usize {
    let object = match classify_com_progid(program_id) {
        ComClass::WScriptShell => ComObject::WScriptShell,
        ComClass::FileSystemObject => ComObject::FileSystemObject,
        ComClass::XmlHttp | ComClass::WinHttpRequest => ComObject::Http {
            method: "GET".into(),
            url: String::new(),
            headers: BTreeMap::new(),
            status: 0,
            body: Vec::new(),
        },
        ComClass::AdoDbStream => ComObject::Stream {
            bytes: Vec::new(),
            text: false,
        },
        ComClass::ShellApplication => ComObject::ShellApplication,
        ComClass::Unknown(program_id) => ComObject::Unknown(program_id),
    };
    runtime.com_objects.push(object);
    runtime.com_objects.len() - 1
}

pub(crate) fn get(runtime: &Runtime, id: usize, member: &str) -> Value {
    match runtime.com_objects.get(id) {
        Some(ComObject::Http { status, body, .. }) => match member {
            "status" => Value::Number(f64::from(*status)),
            "responsetext" => Value::String(String::from_utf8_lossy(body).into_owned()),
            "responsebody" => Value::Array(
                body.iter()
                    .map(|byte| Value::Number(f64::from(*byte)))
                    .collect(),
            ),
            _ => Value::Undefined,
        },
        Some(ComObject::Stream { bytes, text }) => match member {
            "size" => Value::Number(bytes.len() as f64),
            "type" => Value::Number(if *text { 2.0 } else { 1.0 }),
            _ => Value::Undefined,
        },
        Some(ComObject::Shortcut {
            target, arguments, ..
        }) => match member {
            "targetpath" => Value::String(target.clone()),
            "arguments" => Value::String(arguments.clone()),
            _ => Value::Undefined,
        },
        Some(ComObject::Process {
            status,
            exit_code,
            stdout,
            stderr,
        }) => match member {
            "status" => Value::Number(f64::from(*status)),
            "exitcode" => Value::Number(f64::from(*exit_code)),
            "stdout" => Value::Com(*stdout),
            "stderr" => Value::Com(*stderr),
            _ => Value::Undefined,
        },
        Some(ComObject::ProcessStream { lines, cursor }) => match member {
            "atendofstream" => Value::Bool(*cursor >= lines.len()),
            _ => Value::Undefined,
        },
        _ => Value::Undefined,
    }
}

pub(crate) fn set(
    runtime: &mut Runtime,
    id: usize,
    member: &str,
    value: Value,
    _host: &mut dyn Host,
    _depth: usize,
) -> Result<(), ScriptError> {
    let Some(object) = runtime.com_objects.get_mut(id) else {
        return Ok(());
    };
    match object {
        ComObject::Stream { text, .. } if member == "type" => *text = value.number() == 2.0,
        ComObject::Shortcut { target, .. } if member == "targetpath" => *target = value.string(),
        ComObject::Shortcut { arguments, .. } if member == "arguments" => {
            *arguments = value.string();
        }
        _ => {}
    }
    Ok(())
}

pub(crate) fn call(
    runtime: &mut Runtime,
    id: usize,
    member: &str,
    arguments: &[Value],
    host: &mut dyn Host,
    depth: usize,
) -> Result<Value, ScriptError> {
    let Some(object) = runtime.com_objects.get(id).cloned() else {
        return Ok(Value::Undefined);
    };
    match object {
        ComObject::WScriptShell => call_shell(runtime, member, arguments, host, depth),
        ComObject::FileSystemObject => call_fso(runtime, member, arguments, host, depth),
        ComObject::TextFile { path, append } => {
            call_text_file(runtime, &path, append, member, arguments, host, depth)
        }
        ComObject::Http {
            method,
            url,
            headers,
            status,
            body,
        } => call_http(
            runtime, id, member, arguments, host, depth, method, url, headers, status, body,
        ),
        ComObject::Stream { bytes, text } => {
            call_stream(runtime, id, member, arguments, host, depth, bytes, text)
        }
        ComObject::ShellApplication => {
            call_shell_application(runtime, member, arguments, host, depth)
        }
        ComObject::Process { .. } => Ok(Value::Undefined),
        ComObject::ProcessStream { lines, cursor } => {
            call_process_stream(runtime, id, member, lines, cursor)
        }
        ComObject::Shortcut {
            path,
            target,
            arguments: shortcut_arguments,
        } => {
            if member == "save" {
                let contents = format!(
                    "[InternetShortcut]\r\nTargetPath={target}\r\nArguments={shortcut_arguments}\r\n"
                );
                host.write_file(&path, contents.as_bytes(), false, runtime.engine(), depth)?;
            }
            Ok(Value::Undefined)
        }
        ComObject::Folder { path } => {
            if member == "copyhere" {
                copy_virtual(
                    host,
                    &argument(arguments, 0).string(),
                    &path,
                    runtime,
                    depth,
                )?;
            }
            Ok(Value::Undefined)
        }
        ComObject::Unknown(program_id) => {
            host.unsupported(
                runtime.engine(),
                depth,
                &format!("unsupported COM object {program_id}.{member}"),
            );
            Ok(Value::Undefined)
        }
    }
}

fn call_shell(
    runtime: &mut Runtime,
    member: &str,
    arguments: &[Value],
    host: &mut dyn Host,
    depth: usize,
) -> Result<Value, ScriptError> {
    match member {
        "run" => {
            let command = argument(arguments, 0).string();
            let intent = process_intent_from_command_line(&command, "WScript.Shell.Run", depth, "");
            let wait = argument(arguments, 2).truthy();
            let exit_code = if wait {
                host.process_request(intent)?
                    .map_or(0, |result| result.exit_code)
            } else {
                host.process_intent(intent)?;
                0
            };
            Ok(Value::Number(f64::from(exit_code)))
        }
        "exec" => {
            let command = argument(arguments, 0).string();
            let intent =
                process_intent_from_command_line(&command, "WScript.Shell.Exec", depth, "");
            let result = host.process_request(intent)?;
            Ok(create_process_object(runtime, result))
        }
        "regread" => Ok(host
            .read_registry(&argument(arguments, 0).string(), runtime.engine(), depth)
            .map_or(Value::Undefined, Value::String)),
        "regwrite" => {
            host.write_registry(
                &argument(arguments, 0).string(),
                &argument(arguments, 1).string(),
                runtime.engine(),
                depth,
            );
            Ok(Value::Undefined)
        }

        "expandenvironmentstrings" => {
            let mut output = argument(arguments, 0).string();
            for (name, value) in host.environment_entries() {
                output = replace_ascii_case_insensitive(&output, &format!("%{name}%"), &value);
            }
            Ok(Value::String(output))
        }
        "createshortcut" => {
            runtime.com_objects.push(ComObject::Shortcut {
                path: argument(arguments, 0).string(),
                target: String::new(),
                arguments: String::new(),
            });
            Ok(Value::Com(runtime.com_objects.len() - 1))
        }
        _ => Ok(Value::Undefined),
    }
}

fn create_process_object(runtime: &mut Runtime, result: Option<ProcessResult>) -> Value {
    let (status, result) =
        result.map_or_else(|| (0, ProcessResult::default()), |result| (1, result));
    runtime.com_objects.push(ComObject::ProcessStream {
        lines: result.stdout,
        cursor: 0,
    });
    let stdout = runtime.com_objects.len() - 1;
    runtime.com_objects.push(ComObject::ProcessStream {
        lines: result.stderr,
        cursor: 0,
    });
    let stderr = runtime.com_objects.len() - 1;
    runtime.com_objects.push(ComObject::Process {
        status,
        exit_code: result.exit_code,
        stdout,
        stderr,
    });
    Value::Com(runtime.com_objects.len() - 1)
}

fn call_process_stream(
    runtime: &mut Runtime,
    id: usize,
    member: &str,
    lines: Vec<String>,
    mut cursor: usize,
) -> Result<Value, ScriptError> {
    let value = match member {
        "readall" => {
            let remaining = lines[cursor.min(lines.len())..].join("\r\n");
            cursor = lines.len();
            Value::String(remaining)
        }
        "readline" => {
            let line = lines.get(cursor).cloned().unwrap_or_default();
            cursor = cursor.saturating_add(1).min(lines.len());
            Value::String(line)
        }
        "skipline" => {
            cursor = cursor.saturating_add(1).min(lines.len());
            Value::Undefined
        }
        _ => Value::Undefined,
    };
    runtime.com_objects[id] = ComObject::ProcessStream { lines, cursor };
    Ok(value)
}

fn call_fso(
    runtime: &mut Runtime,
    member: &str,
    arguments: &[Value],
    host: &mut dyn Host,
    depth: usize,
) -> Result<Value, ScriptError> {
    let path = argument(arguments, 0).string();
    match member {
        "createtextfile" => {
            host.write_file(&path, b"", false, runtime.engine(), depth)?;
            runtime
                .com_objects
                .push(ComObject::TextFile { path, append: true });
            Ok(Value::Com(runtime.com_objects.len() - 1))
        }
        "opentextfile" => {
            let mode = argument(arguments, 1).number() as i32;
            runtime.com_objects.push(ComObject::TextFile {
                path,
                append: mode == 8,
            });
            Ok(Value::Com(runtime.com_objects.len() - 1))
        }
        "fileexists" => Ok(Value::Bool(
            host.read_file(&path, runtime.engine(), depth).is_some(),
        )),
        "deletefile" => Ok(Value::Bool(host.delete_file(
            &path,
            runtime.engine(),
            depth,
        ))),
        "copyfile" => {
            copy_virtual(
                host,
                &path,
                &argument(arguments, 1).string(),
                runtime,
                depth,
            )?;
            Ok(Value::Undefined)
        }
        "movefile" => {
            copy_virtual(
                host,
                &path,
                &argument(arguments, 1).string(),
                runtime,
                depth,
            )?;
            host.delete_file(&path, runtime.engine(), depth);
            Ok(Value::Undefined)
        }
        _ => Ok(Value::Undefined),
    }
}

fn call_text_file(
    runtime: &mut Runtime,
    path: &str,
    append: bool,
    member: &str,
    arguments: &[Value],
    host: &mut dyn Host,
    depth: usize,
) -> Result<Value, ScriptError> {
    match member {
        "write" | "writeline" => {
            let mut text = argument(arguments, 0).string();
            if member == "writeline" {
                text.push_str("\r\n");
            }
            host.write_file(path, text.as_bytes(), append, runtime.engine(), depth)?;
            Ok(Value::Undefined)
        }
        "readall" => Ok(host
            .read_file(path, runtime.engine(), depth)
            .map_or(Value::String(String::new()), |bytes| {
                Value::String(String::from_utf8_lossy(&bytes).into_owned())
            })),
        "close" => Ok(Value::Undefined),
        _ => Ok(Value::Undefined),
    }
}

#[allow(clippy::too_many_arguments)]
fn call_http(
    runtime: &mut Runtime,
    id: usize,
    member: &str,
    arguments: &[Value],
    host: &mut dyn Host,
    depth: usize,
    mut method: String,
    mut url: String,
    mut headers: BTreeMap<String, String>,
    mut status: u16,
    mut body: Vec<u8>,
) -> Result<Value, ScriptError> {
    match member {
        "open" => {
            method = argument(arguments, 0).string();
            url = argument(arguments, 1).string();
        }
        "setrequestheader" => {
            headers.insert(
                argument(arguments, 0).string(),
                argument(arguments, 1).string(),
            );
        }
        "send" => {
            let request_body = match argument(arguments, 0) {
                Value::Array(values) => values.iter().map(|value| value.number() as u8).collect(),
                value => value.string().into_bytes(),
            };
            if let Some(response) = host.network_request_detailed(NetworkRequest {
                method: method.clone(),
                url: url.clone(),
                headers: headers.clone(),
                body: request_body,
                origin: "Windows script HTTP COM".into(),
                depth,
            }) {
                status = response.status;
                body = response.body;
            }
        }
        _ => {}
    }
    runtime.com_objects[id] = ComObject::Http {
        method,
        url,
        headers,
        status,
        body,
    };
    Ok(Value::Undefined)
}

#[allow(clippy::too_many_arguments)]
fn call_stream(
    runtime: &mut Runtime,
    id: usize,
    member: &str,
    arguments: &[Value],
    host: &mut dyn Host,
    depth: usize,
    mut bytes: Vec<u8>,
    text: bool,
) -> Result<Value, ScriptError> {
    let result = match member {
        "open" | "close" => Value::Undefined,
        "write" => {
            match argument(arguments, 0) {
                Value::Array(values) => {
                    bytes.extend(values.iter().map(|value| value.number() as u8));
                }
                value => bytes.extend(value.string().into_bytes()),
            }
            Value::Undefined
        }
        "writetext" => {
            bytes.extend(argument(arguments, 0).string().into_bytes());
            Value::Undefined
        }
        "loadfromfile" => {
            bytes = host
                .read_file(&argument(arguments, 0).string(), runtime.engine(), depth)
                .unwrap_or_default();
            Value::Undefined
        }
        "savetofile" => {
            host.write_file(
                &argument(arguments, 0).string(),
                &bytes,
                false,
                runtime.engine(),
                depth,
            )?;
            Value::Undefined
        }
        "read" => Value::Array(
            bytes
                .iter()
                .map(|byte| Value::Number(f64::from(*byte)))
                .collect(),
        ),
        "readtext" => Value::String(String::from_utf8_lossy(&bytes).into_owned()),
        _ => Value::Undefined,
    };
    runtime.com_objects[id] = ComObject::Stream { bytes, text };
    Ok(result)
}

fn call_shell_application(
    runtime: &mut Runtime,
    member: &str,
    arguments: &[Value],
    host: &mut dyn Host,
    depth: usize,
) -> Result<Value, ScriptError> {
    match member {
        "shellexecute" => {
            let program = argument(arguments, 0).string();
            let raw_arguments = argument(arguments, 1).string();
            let command_line = format!("{program} {raw_arguments}").trim().to_owned();
            host.process_intent(process_intent_from_command_line(
                &command_line,
                "Shell.Application.ShellExecute",
                depth,
                &argument(arguments, 2).string(),
            ))?;
            Ok(Value::Undefined)
        }
        "namespace" => {
            runtime.com_objects.push(ComObject::Folder {
                path: argument(arguments, 0).string(),
            });
            Ok(Value::Com(runtime.com_objects.len() - 1))
        }
        _ => Ok(Value::Undefined),
    }
}

fn copy_virtual(
    host: &mut dyn Host,
    source: &str,
    destination: &str,
    runtime: &Runtime,
    depth: usize,
) -> Result<(), ScriptError> {
    if let Some(bytes) = host.read_file(source, runtime.engine(), depth) {
        host.write_file(destination, &bytes, false, runtime.engine(), depth)?;
    }
    Ok(())
}

fn argument(arguments: &[Value], index: usize) -> Value {
    arguments.get(index).cloned().unwrap_or(Value::Undefined)
}

fn replace_ascii_case_insensitive(source: &str, needle: &str, replacement: &str) -> String {
    let mut output = String::new();
    let mut remaining = source;
    let lower_needle = needle.to_ascii_lowercase();
    while let Some(position) = remaining.to_ascii_lowercase().find(lower_needle.as_str()) {
        output.push_str(&remaining[..position]);
        output.push_str(replacement);
        remaining = &remaining[position + needle.len()..];
    }
    output.push_str(remaining);
    output
}
