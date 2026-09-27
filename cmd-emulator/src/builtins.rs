use crate::batch::BatchAction;
use crate::syntax::split_words;
use crate::{CmdEmulator, CmdError, CommandOutput};
use emulator_core::{Engine, EventKind, Host, ProcessIntent, TraceEvent};

pub(crate) fn execute_parts(
    emulator: &mut CmdEmulator,
    command: &str,
    rest: &str,
    host: &mut dyn Host,
    depth: usize,
) -> Result<CommandOutput, CmdError> {
    let name = command
        .trim_start_matches('@')
        .trim_matches('"')
        .to_ascii_lowercase();
    match name.as_str() {
        "" | "rem" | "::" | "cls" => Ok(success()),
        "echo" => Ok(echo(emulator, rest)),
        "set" => Ok(set(rest, host, depth)),
        "cd" | "chdir" => Ok(cd(emulator, rest, host)),
        "pushd" => Ok(pushd(emulator, rest, host)),
        "popd" => Ok(popd(emulator)),
        "md" | "mkdir" => mkdir(emulator, rest, host, depth),
        "rd" | "rmdir" => Ok(rmdir(emulator, rest, host, depth)),
        "dir" => Ok(dir(emulator, rest, host, depth)),
        "type" => Ok(type_files(emulator, rest, host, depth)),
        "copy" => copy(emulator, rest, host, depth),
        "move" => move_files(emulator, rest, host, depth),
        "del" | "erase" => Ok(delete(emulator, rest, host, depth)),
        "ren" | "rename" => rename(emulator, rest, host, depth),
        "ver" => Ok(output("Microsoft Windows [Version 10.0.22631.0]")),
        "path" => Ok(path(rest, host)),
        "exit" => Ok(exit(emulator, rest)),
        "start" => start(emulator, rest, host, depth),
        "call" => call(emulator, rest, host, depth),
        "goto" => Ok(goto(emulator, rest)),
        "shift" => Ok(shift(emulator)),
        "cmd" | "cmd.exe" => nested_cmd(emulator, rest, host, depth),
        _ => external(emulator, command.trim_start_matches('@'), rest, host, depth),
    }
}

fn success() -> CommandOutput {
    CommandOutput::default()
}

fn output(line: impl Into<String>) -> CommandOutput {
    CommandOutput {
        stdout: vec![line.into()],
        ..CommandOutput::default()
    }
}

fn failure(line: impl Into<String>) -> CommandOutput {
    CommandOutput {
        stderr: vec![line.into()],
        code: 1,
        ..CommandOutput::default()
    }
}

fn echo(emulator: &mut CmdEmulator, rest: &str) -> CommandOutput {
    let trimmed = rest.trim();
    if trimmed.eq_ignore_ascii_case("on") {
        emulator.runtime.echo_enabled = true;
        return success();
    }
    if trimmed.eq_ignore_ascii_case("off") {
        emulator.runtime.echo_enabled = false;
        return success();
    }
    if trimmed.is_empty() {
        return output(format!(
            "ECHO is {}.",
            if emulator.runtime.echo_enabled {
                "on"
            } else {
                "off"
            }
        ));
    }
    if trimmed == "." || trimmed == ":" || trimmed == "/" {
        output("")
    } else {
        let value = rest.trim_start();
        let value = value
            .strip_prefix('"')
            .and_then(|inner| inner.strip_suffix('"'))
            .unwrap_or(value);
        output(unescape_carets(value))
    }
}

fn unescape_carets(value: &str) -> String {
    let mut output = String::new();
    let mut characters = value.chars();
    while let Some(ch) = characters.next() {
        if ch == '^' {
            if let Some(escaped) = characters.next() {
                output.push(escaped);
            }
        } else {
            output.push(ch);
        }
    }
    output
}

fn set(rest: &str, host: &mut dyn Host, depth: usize) -> CommandOutput {
    let trimmed = rest.trim();
    if trimmed.is_empty() {
        let lines = host
            .environment_entries()
            .into_iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect();
        return CommandOutput {
            stdout: lines,
            ..CommandOutput::default()
        };
    }
    if let Some(expression) = strip_switch(trimmed, "/a") {
        return set_arithmetic(expression, host);
    }
    if strip_switch(trimmed, "/p").is_some() {
        host.unsupported(Engine::Cmd, depth, "interactive set /p is not supported");
        return failure("SET /P is not supported by cmd-emulator.");
    }
    let assignment = trimmed
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(trimmed);
    if let Some((name, value)) = assignment.split_once('=') {
        let name = name.trim();
        if name.is_empty() {
            return failure("The syntax of the command is incorrect.");
        }
        if value.is_empty() {
            host.remove_environment(name);
        } else {
            host.set_environment(name, value);
        }
        host.emit(
            TraceEvent::new(
                depth,
                Engine::Cmd,
                EventKind::VariableAssignment,
                format!("set environment variable {name}"),
            )
            .with_data("value", value),
        );
        success()
    } else {
        let prefix = assignment.to_ascii_lowercase();
        let lines = host
            .environment_entries()
            .into_iter()
            .filter(|(name, _)| name.to_ascii_lowercase().starts_with(&prefix))
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>();
        if lines.is_empty() {
            failure(format!("Environment variable {assignment} not defined"))
        } else {
            CommandOutput {
                stdout: lines,
                ..CommandOutput::default()
            }
        }
    }
}

fn set_arithmetic(expression: &str, host: &mut dyn Host) -> CommandOutput {
    let expression = expression
        .trim()
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(expression.trim());
    let (assignment, arithmetic) = expression
        .split_once('=')
        .map_or((None, expression), |(name, value)| {
            (Some(name.trim()), value)
        });
    match ArithmeticParser::new(arithmetic, host).parse() {
        Ok(value) => {
            if let Some(name) = assignment {
                if !name.is_empty() {
                    host.set_environment(name, &value.to_string());
                }
            }
            output(value.to_string())
        }
        Err(message) => failure(message),
    }
}

fn cd(emulator: &mut CmdEmulator, rest: &str, host: &dyn Host) -> CommandOutput {
    let mut value = rest.trim();
    if let Some(after) = strip_switch(value, "/d") {
        value = after;
    }
    if value.is_empty() {
        return output(emulator.runtime.current_directory.clone());
    }
    let value = value.trim_matches('"');
    let path = emulator.runtime.resolve_path(value);
    let normalized = emulator_core::normalize_windows_path(&path);
    if emulator.runtime.directories.contains(&normalized) || host.directory_exists(&path) {
        emulator.runtime.current_directory = path;
        success()
    } else {
        failure("The system cannot find the path specified.")
    }
}

fn pushd(emulator: &mut CmdEmulator, rest: &str, host: &dyn Host) -> CommandOutput {
    let previous = emulator.runtime.current_directory.clone();
    let result = cd(emulator, rest, host);
    if result.code == 0 {
        emulator.runtime.directory_stack.push(previous);
    }
    result
}

fn popd(emulator: &mut CmdEmulator) -> CommandOutput {
    if let Some(path) = emulator.runtime.directory_stack.pop() {
        emulator.runtime.current_directory = path;
        success()
    } else {
        failure("The directory stack is empty.")
    }
}

fn mkdir(
    emulator: &mut CmdEmulator,
    rest: &str,
    host: &mut dyn Host,
    depth: usize,
) -> Result<CommandOutput, CmdError> {
    let words = split_words(rest);
    if words.is_empty() {
        return Ok(failure("The syntax of the command is incorrect."));
    }
    for word in words {
        let path = emulator.runtime.resolve_path(&word);
        let mut current = String::new();
        for (index, part) in path.split('\\').enumerate() {
            if index == 0 {
                current.push_str(part);
                current.push('\\');
            } else if !part.is_empty() {
                if !current.ends_with('\\') {
                    current.push('\\');
                }
                current.push_str(part);
                emulator
                    .runtime
                    .directories
                    .insert(emulator_core::normalize_windows_path(&current));
                host.create_directory(&current, Engine::Cmd, depth)?;
            }
        }
    }
    Ok(success())
}

fn rmdir(
    emulator: &mut CmdEmulator,
    rest: &str,
    host: &mut dyn Host,
    depth: usize,
) -> CommandOutput {
    let words = split_words(rest);
    let recursive = words.iter().any(|word| word.eq_ignore_ascii_case("/s"));
    let paths = words
        .iter()
        .filter(|word| !word.starts_with('/'))
        .collect::<Vec<_>>();
    if paths.is_empty() {
        return failure("The syntax of the command is incorrect.");
    }
    for path in paths {
        let resolved = emulator.runtime.resolve_path(path);
        let normalized = emulator_core::normalize_windows_path(&resolved);
        let files = host.list_files(&resolved, Engine::Cmd, depth);
        let mut children = emulator
            .runtime
            .directories
            .iter()
            .filter(|candidate| candidate.starts_with(&(normalized.clone() + "\\")))
            .cloned()
            .collect::<Vec<_>>();
        children.extend(
            host.list_directories(&resolved, Engine::Cmd, depth)
                .into_iter()
                .filter(|candidate| candidate.starts_with(&(normalized.clone() + "\\"))),
        );
        children.sort();
        children.dedup();
        if (!files.is_empty() || !children.is_empty()) && !recursive {
            return failure("The directory is not empty.");
        }
        let mut removed_host = false;
        if recursive {
            for file in files {
                host.delete_file(&file, Engine::Cmd, depth);
            }
            for child in children {
                emulator.runtime.directories.remove(&child);
            }
            removed_host = host.delete_directory(&resolved, true, Engine::Cmd, depth);
        }
        let removed_runtime = emulator.runtime.directories.remove(&normalized);
        if !recursive {
            removed_host = host.delete_directory(&resolved, false, Engine::Cmd, depth);
        }
        if !removed_runtime && !removed_host {
            return failure("The system cannot find the file specified.");
        }
    }
    success()
}

#[allow(clippy::too_many_lines)]
fn dir(emulator: &CmdEmulator, rest: &str, host: &mut dyn Host, depth: usize) -> CommandOutput {
    let words = split_words(rest);
    let bare = words.iter().any(|word| word.eq_ignore_ascii_case("/b"));
    let recursive = words.iter().any(|word| word.eq_ignore_ascii_case("/s"));
    let directories_only = words.iter().any(|word| word.eq_ignore_ascii_case("/a:d"));
    let files_only = words.iter().any(|word| word.eq_ignore_ascii_case("/a:-d"));
    let requested = words
        .iter()
        .find(|word| !word.starts_with('/'))
        .map_or(".", String::as_str)
        .trim_matches('"');
    let resolved = emulator.runtime.resolve_path(requested);
    let (root, pattern) = split_dir_pattern(&resolved);
    let normalized_root = emulator_core::normalize_windows_path(&root);
    let prefix = format!("{}\\", normalized_root.trim_end_matches('\\'));

    let mut entries = Vec::new();
    if !files_only {
        let mut directories = emulator
            .runtime
            .directories
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        directories.extend(host.list_directories(&root, Engine::Cmd, depth));
        directories.sort();
        directories.dedup();
        entries.extend(
            directories
                .iter()
                .filter(|directory| *directory != &normalized_root)
                .filter_map(|directory| {
                    let remainder = directory.strip_prefix(&prefix)?;
                    if !recursive && remainder.contains('\\') {
                        return None;
                    }
                    let name = if recursive {
                        remainder.to_string()
                    } else {
                        remainder.rsplit('\\').next().unwrap_or(remainder).into()
                    };
                    wildcard_match(&name, &pattern).then(|| DirEntry {
                        name,
                        path: directory.clone(),
                        directory: true,
                        length: 0,
                    })
                }),
        );
    }
    if !directories_only {
        entries.extend(
            host.list_files(&root, Engine::Cmd, depth)
                .into_iter()
                .filter_map(|file| {
                    let normalized = emulator_core::normalize_windows_path(&file);
                    let remainder = normalized.strip_prefix(&prefix)?;
                    if !recursive && remainder.contains('\\') {
                        return None;
                    }
                    let name = if recursive {
                        remainder.to_string()
                    } else {
                        remainder.rsplit('\\').next().unwrap_or(remainder).into()
                    };
                    if !wildcard_match(name.rsplit('\\').next().unwrap_or(&name), &pattern) {
                        return None;
                    }
                    let length = host
                        .read_file(&file, Engine::Cmd, depth)
                        .map_or(0, |bytes| bytes.len());
                    Some(DirEntry {
                        name,
                        path: normalized,
                        directory: false,
                        length,
                    })
                }),
        );
    }
    entries.sort_by(|left, right| {
        left.name
            .to_ascii_lowercase()
            .cmp(&right.name.to_ascii_lowercase())
    });

    if bare {
        return CommandOutput {
            stdout: entries.into_iter().map(|entry| entry.name).collect(),
            code: 0,
            ..CommandOutput::default()
        };
    }

    let file_count = entries.iter().filter(|entry| !entry.directory).count();
    let directory_count = entries.iter().filter(|entry| entry.directory).count();
    let total_bytes = entries
        .iter()
        .filter(|entry| !entry.directory)
        .map(|entry| entry.length)
        .sum::<usize>();
    let mut stdout = vec![
        " Volume in drive C has no label.".into(),
        " Volume Serial Number is 434C-4943".into(),
        String::new(),
        format!(" Directory of {root}"),
        String::new(),
    ];
    stdout.extend(entries.into_iter().map(|entry| {
        let name = if recursive { entry.path } else { entry.name };
        if entry.directory {
            format!("01/01/2024  12:00 AM    <DIR>          {name}")
        } else {
            format!(
                "01/01/2024  12:00 AM {length:>17} {name}",
                length = entry.length
            )
        }
    }));
    stdout.push(format!("{file_count:>16} File(s) {total_bytes:>14} bytes"));
    stdout.push(format!(
        "{directory_count:>16} Dir(s)  34,359,738,368 bytes free"
    ));
    CommandOutput {
        stdout,
        code: 0,
        ..CommandOutput::default()
    }
}

#[derive(Debug)]
struct DirEntry {
    name: String,
    path: String,
    directory: bool,
    length: usize,
}

fn split_dir_pattern(path: &str) -> (String, String) {
    if !path.contains(['*', '?']) {
        return (path.into(), "*".into());
    }
    path.rsplit_once('\\').map_or_else(
        || (r"C:\".into(), path.into()),
        |(root, pattern)| (root.into(), pattern.into()),
    )
}

fn wildcard_match(value: &str, pattern: &str) -> bool {
    wildcard_bytes(
        value.to_ascii_lowercase().as_bytes(),
        pattern.to_ascii_lowercase().as_bytes(),
    )
}

fn wildcard_bytes(value: &[u8], pattern: &[u8]) -> bool {
    match pattern {
        [] => value.is_empty(),
        [b'*', rest @ ..] => {
            wildcard_bytes(value, rest)
                || (!value.is_empty() && wildcard_bytes(&value[1..], pattern))
        }
        [b'?', rest @ ..] => !value.is_empty() && wildcard_bytes(&value[1..], rest),
        [first, rest @ ..] => value.first() == Some(first) && wildcard_bytes(&value[1..], rest),
    }
}

fn type_files(
    emulator: &CmdEmulator,
    rest: &str,
    host: &mut dyn Host,
    depth: usize,
) -> CommandOutput {
    let words = split_words(rest);
    if words.is_empty() {
        return failure("The syntax of the command is incorrect.");
    }
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    for word in words {
        let path = emulator.runtime.resolve_path(&word);
        if let Some(bytes) = host.read_file(&path, Engine::Cmd, depth) {
            let text = String::from_utf8_lossy(&bytes).replace("\r\n", "\n");
            if !text.is_empty() {
                stdout.extend(text.trim_end_matches('\n').split('\n').map(str::to_string));
            }
        } else {
            stderr.push(format!("The system cannot find the file specified: {word}"));
        }
    }
    CommandOutput {
        stdout,
        code: i32::from(!stderr.is_empty()),
        stderr,
        ..CommandOutput::default()
    }
}

fn copy(
    emulator: &CmdEmulator,
    rest: &str,
    host: &mut dyn Host,
    depth: usize,
) -> Result<CommandOutput, CmdError> {
    let words = split_words(rest)
        .into_iter()
        .filter(|word| !word.starts_with('/'))
        .collect::<Vec<_>>();
    if words.len() < 2 {
        return Ok(failure("The syntax of the command is incorrect."));
    }
    let source = emulator.runtime.resolve_path(&words[0]);
    let mut target = emulator.runtime.resolve_path(&words[1]);
    if emulator
        .runtime
        .directories
        .contains(&emulator_core::normalize_windows_path(&target))
    {
        let name = source.rsplit('\\').next().unwrap_or(&source);
        target = format!(r"{}\{name}", target.trim_end_matches('\\'));
    }
    let Some(bytes) = host.read_file(&source, Engine::Cmd, depth) else {
        return Ok(failure("The system cannot find the file specified."));
    };
    host.write_file(&target, &bytes, false, Engine::Cmd, depth)?;
    Ok(output("        1 file(s) copied."))
}

fn move_files(
    emulator: &CmdEmulator,
    rest: &str,
    host: &mut dyn Host,
    depth: usize,
) -> Result<CommandOutput, CmdError> {
    let result = copy(emulator, rest, host, depth)?;
    if result.code == 0 {
        if let Some(source) = split_words(rest)
            .into_iter()
            .find(|word| !word.starts_with('/'))
        {
            host.delete_file(&emulator.runtime.resolve_path(&source), Engine::Cmd, depth);
        }
        Ok(output("        1 file(s) moved."))
    } else {
        Ok(result)
    }
}

fn delete(emulator: &CmdEmulator, rest: &str, host: &mut dyn Host, depth: usize) -> CommandOutput {
    let words = split_words(rest)
        .into_iter()
        .filter(|word| !word.starts_with('/'))
        .collect::<Vec<_>>();
    if words.is_empty() {
        return failure("The syntax of the command is incorrect.");
    }
    let mut missing = false;
    for word in words {
        let path = emulator.runtime.resolve_path(&word);
        if word.contains('*') {
            let prefix = path.split('*').next().unwrap_or_default();
            let files = host.list_files(prefix, Engine::Cmd, depth);
            if files.is_empty() {
                missing = true;
            }
            for file in files {
                host.delete_file(&file, Engine::Cmd, depth);
            }
        } else if !host.delete_file(&path, Engine::Cmd, depth) {
            missing = true;
        }
    }
    if missing {
        failure("Could Not Find the specified file.")
    } else {
        success()
    }
}

fn rename(
    emulator: &CmdEmulator,
    rest: &str,
    host: &mut dyn Host,
    depth: usize,
) -> Result<CommandOutput, CmdError> {
    let words = split_words(rest);
    if words.len() != 2 {
        return Ok(failure("The syntax of the command is incorrect."));
    }
    let source = emulator.runtime.resolve_path(&words[0]);
    let target = if words[1].contains('\\') || words[1].contains(':') {
        emulator.runtime.resolve_path(&words[1])
    } else {
        let parent = source.rsplit_once('\\').map_or("", |(parent, _)| parent);
        format!(r"{parent}\{}", words[1])
    };
    let Some(bytes) = host.read_file(&source, Engine::Cmd, depth) else {
        return Ok(failure("The system cannot find the file specified."));
    };
    host.write_file(&target, &bytes, false, Engine::Cmd, depth)?;
    host.delete_file(&source, Engine::Cmd, depth);
    Ok(success())
}

fn path(rest: &str, host: &mut dyn Host) -> CommandOutput {
    let trimmed = rest.trim();
    if trimmed.is_empty() {
        return output(format!(
            "PATH={}",
            host.environment("PATH").unwrap_or_default()
        ));
    }
    let value = trimmed
        .strip_prefix('=')
        .unwrap_or(trimmed)
        .trim_matches('"');
    host.set_environment("PATH", value);
    success()
}

fn exit(emulator: &mut CmdEmulator, rest: &str) -> CommandOutput {
    let words = split_words(rest);
    let code = words
        .iter()
        .find(|word| !word.eq_ignore_ascii_case("/b"))
        .and_then(|word| word.parse().ok())
        .unwrap_or(0);
    if words.iter().any(|word| word.eq_ignore_ascii_case("/b"))
        && emulator.request_batch_action(BatchAction::Return(code))
    {
        return CommandOutput {
            code,
            ..CommandOutput::default()
        };
    }
    CommandOutput {
        code,
        exited: true,
        ..CommandOutput::default()
    }
}

fn goto(emulator: &mut CmdEmulator, rest: &str) -> CommandOutput {
    let label = rest.trim().trim_start_matches(':');
    if label.is_empty() {
        return failure("The syntax of the command is incorrect.");
    }
    if emulator.request_batch_action(BatchAction::Goto(label.into())) {
        success()
    } else {
        failure("GOTO was unexpected at this time.")
    }
}

fn shift(emulator: &mut CmdEmulator) -> CommandOutput {
    if emulator.shift_batch() {
        success()
    } else {
        failure("SHIFT was unexpected at this time.")
    }
}

fn call(
    emulator: &mut CmdEmulator,
    rest: &str,
    host: &mut dyn Host,
    depth: usize,
) -> Result<CommandOutput, CmdError> {
    let trimmed = rest.trim();
    if let Some(label_call) = trimmed.strip_prefix(':') {
        let words = split_words(label_call);
        let Some(label) = words.first() else {
            return Ok(failure("The syntax of the command is incorrect."));
        };
        if emulator.request_batch_action(BatchAction::Call {
            label: label.clone(),
            args: words[1..].to_vec(),
        }) {
            return Ok(success());
        }
        return Ok(failure("CALL :label was unexpected at this time."));
    }
    emulator.execute_chain(trimmed, host, depth + 1)
}

fn start(
    emulator: &CmdEmulator,
    rest: &str,
    host: &mut dyn Host,
    depth: usize,
) -> Result<CommandOutput, CmdError> {
    let mut command_line = rest.trim();
    while command_line.starts_with('/') {
        command_line = command_line
            .split_once(char::is_whitespace)
            .map_or("", |(_, after)| after.trim_start());
    }
    if let Some((after_quote, end)) = command_line
        .strip_prefix('"')
        .and_then(|value| value.find('"').map(|end| (value, end)))
    {
        command_line = after_quote[end + 1..].trim_start();
    }
    let words = split_words(command_line);
    let Some(program) = words.first().cloned() else {
        return Ok(failure("The system cannot find the file specified."));
    };
    let (program, args) = if is_cmd_internal(&program) {
        let command_line = unescape_carets(command_line);
        ("cmd.exe".into(), vec!["/c".into(), command_line])
    } else {
        (program, words[1..].to_vec())
    };
    host.process_intent(ProcessIntent {
        program: program.clone(),
        args: args.clone(),
        command_line: quote_command(&program, &args),
        origin: format!("cmd start from {}", emulator.runtime.current_directory),
        depth,
        stdin: Vec::new(),
        current_directory: emulator.runtime.current_directory.clone(),
    })?;
    Ok(success())
}

fn is_cmd_internal(command: &str) -> bool {
    [
        "call", "cd", "chdir", "cls", "copy", "del", "dir", "echo", "erase", "exit", "for", "goto",
        "if", "md", "mkdir", "move", "popd", "pushd", "rd", "ren", "rename", "rmdir", "set",
        "shift", "title", "type", "ver",
    ]
    .iter()
    .any(|builtin| command.eq_ignore_ascii_case(builtin))
}

fn nested_cmd(
    emulator: &mut CmdEmulator,
    rest: &str,
    host: &mut dyn Host,
    depth: usize,
) -> Result<CommandOutput, CmdError> {
    let lower = rest.to_ascii_lowercase();
    if lower.contains("/v:on") {
        emulator.runtime.delayed_expansion = true;
    } else if lower.contains("/v:off") {
        emulator.runtime.delayed_expansion = false;
    }
    if let Some(index) = find_cmd_switch(rest, "/c").or_else(|| find_cmd_switch(rest, "/k")) {
        let nested = rest[index + 2..].trim().trim_matches('"');
        emulator.execute_chain(nested, host, depth + 1)
    } else {
        failure("Interactive nested cmd sessions are not supported.").pipe(Ok)
    }
}

fn external(
    emulator: &CmdEmulator,
    command: &str,
    rest: &str,
    host: &mut dyn Host,
    depth: usize,
) -> Result<CommandOutput, CmdError> {
    let args = split_words(rest);
    let result = host.process_request(ProcessIntent {
        program: command.into(),
        args: args.clone(),
        command_line: quote_command(command, &args),
        origin: format!(
            "cmd external command from {}",
            emulator.runtime.current_directory
        ),
        depth,
        stdin: emulator.pipe_input.clone().unwrap_or_default(),
        current_directory: emulator.runtime.current_directory.clone(),
    })?;
    Ok(result.map_or_else(
        || CommandOutput {
            stderr: vec![format!(
                "'{command}' is not recognized as an internal or external command,\noperable program or batch file."
            )],
            code: 9009,
            ..CommandOutput::default()
        },
        |result| CommandOutput {
            stdout: result.stdout,
            stderr: result.stderr,
            code: result.exit_code,
            ..CommandOutput::default()
        },
    ))
}

fn quote_command(program: &str, args: &[String]) -> String {
    std::iter::once(program)
        .chain(args.iter().map(String::as_str))
        .map(|value| {
            if value.contains(char::is_whitespace) {
                format!("\"{}\"", value.replace('"', "\\\""))
            } else {
                value.into()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn strip_switch<'a>(value: &'a str, switch: &str) -> Option<&'a str> {
    value
        .get(..switch.len())
        .filter(|prefix| prefix.eq_ignore_ascii_case(switch))
        .map(|_| value[switch.len()..].trim_start())
}

fn find_cmd_switch(value: &str, switch: &str) -> Option<usize> {
    value
        .to_ascii_lowercase()
        .find(&switch.to_ascii_lowercase())
}

struct ArithmeticParser<'a> {
    source: &'a str,
    offset: usize,
    host: &'a dyn Host,
}

impl<'a> ArithmeticParser<'a> {
    fn new(source: &'a str, host: &'a dyn Host) -> Self {
        Self {
            source,
            offset: 0,
            host,
        }
    }

    fn parse(mut self) -> Result<i64, String> {
        let value = self.additive()?;
        self.whitespace();
        if self.offset == self.source.len() {
            Ok(value)
        } else {
            Err(
                "Invalid number. Numeric constants are either decimal, hexadecimal or octal."
                    .into(),
            )
        }
    }

    fn additive(&mut self) -> Result<i64, String> {
        let mut value = self.multiplicative()?;
        loop {
            self.whitespace();
            if self.consume('+') {
                value = value.wrapping_add(self.multiplicative()?);
            } else if self.consume('-') {
                value = value.wrapping_sub(self.multiplicative()?);
            } else {
                return Ok(value);
            }
        }
    }

    fn multiplicative(&mut self) -> Result<i64, String> {
        let mut value = self.unary()?;
        loop {
            self.whitespace();
            if self.consume('*') {
                value = value.wrapping_mul(self.unary()?);
            } else if self.consume('/') {
                let divisor = self.unary()?;
                if divisor == 0 {
                    return Err("Divide by zero error.".into());
                }
                value /= divisor;
            } else if self.consume('%') {
                let divisor = self.unary()?;
                if divisor == 0 {
                    return Err("Divide by zero error.".into());
                }
                value %= divisor;
            } else {
                return Ok(value);
            }
        }
    }

    fn unary(&mut self) -> Result<i64, String> {
        self.whitespace();
        if self.consume('+') {
            self.unary()
        } else if self.consume('-') {
            Ok(-self.unary()?)
        } else if self.consume('(') {
            let value = self.additive()?;
            self.whitespace();
            if self.consume(')') {
                Ok(value)
            } else {
                Err("Missing operator.".into())
            }
        } else {
            self.atom()
        }
    }

    fn atom(&mut self) -> Result<i64, String> {
        self.whitespace();
        let start = self.offset;
        while self.offset < self.source.len() {
            let ch = self.source[self.offset..]
                .chars()
                .next()
                .expect("valid offset");
            if ch.is_ascii_alphanumeric() || ch == '_' {
                self.offset += ch.len_utf8();
            } else {
                break;
            }
        }
        if start == self.offset {
            return Err("Missing operand.".into());
        }
        let atom = &self.source[start..self.offset];
        if let Some(hex) = atom.strip_prefix("0x").or_else(|| atom.strip_prefix("0X")) {
            i64::from_str_radix(hex, 16).map_err(|_| "Invalid number.".into())
        } else if let Ok(value) = atom.parse() {
            Ok(value)
        } else {
            Ok(self
                .host
                .environment(atom)
                .and_then(|value| value.parse().ok())
                .unwrap_or(0))
        }
    }

    fn whitespace(&mut self) {
        while self.offset < self.source.len()
            && self.source.as_bytes()[self.offset].is_ascii_whitespace()
        {
            self.offset += 1;
        }
    }

    fn consume(&mut self, expected: char) -> bool {
        if self.source[self.offset..].starts_with(expected) {
            self.offset += expected.len_utf8();
            true
        } else {
            false
        }
    }
}

trait Pipe: Sized {
    fn pipe<T>(self, function: impl FnOnce(Self) -> T) -> T {
        function(self)
    }
}

impl<T> Pipe for T {}
