use crate::runtime::FlowControl;
use crate::{BashEmulator, BashError, CommandOutput};
use emulator_core::{Engine, EventKind, Host, TraceEvent};

pub(crate) fn execute(
    emulator: &mut BashEmulator,
    name: &str,
    arguments: &[String],
    input: &[String],
    host: &mut dyn Host,
    depth: usize,
) -> Result<Option<CommandOutput>, BashError> {
    let output = match name {
        ":" | "true" => success(),
        "false" => status(1),
        "echo" => echo(arguments),
        "printf" => printf(arguments),
        "pwd" => line(emulator.runtime.current_directory.clone()),
        "cd" => cd(emulator, arguments, host),
        "pushd" => pushd(emulator, arguments, host),
        "popd" => popd(emulator),
        "export" => export(emulator, arguments, host, depth),
        "unset" => unset(emulator, arguments, host),
        "set" => set(emulator, arguments, host),
        "shift" => shift(emulator, arguments),
        "exit" => exit(emulator, arguments),
        "return" => return_from_function(emulator, arguments),
        "break" => {
            emulator.runtime.flow = FlowControl::Break;
            success()
        }
        "continue" => {
            emulator.runtime.flow = FlowControl::Continue;
            success()
        }
        "eval" => emulator.execute_source(&arguments.join(" "), host, depth + 1)?,
        "." | "source" => {
            let Some(path) = arguments.first() else {
                return Ok(Some(failure("bash: source: filename argument required")));
            };
            emulator.execute_file(path, &arguments[1..], host, depth + 1)?
        }
        "test" => test(emulator, arguments, host, depth),
        "[" | "[[" => {
            let closing = if name == "[[" { "]]" } else { "]" };
            let arguments = if arguments.last().is_some_and(|argument| argument == closing) {
                &arguments[..arguments.len().saturating_sub(1)]
            } else {
                arguments
            };
            test(emulator, arguments, host, depth)
        }
        "read" => read(emulator, arguments, input),
        "mkdir" => mkdir(emulator, arguments, host, depth)?,
        "rmdir" => rmdir(emulator, arguments, host, depth),
        "rm" => rm(emulator, arguments, host, depth),
        "touch" => touch(emulator, arguments, host, depth)?,
        "cat" => cat(emulator, arguments, input, host, depth),
        "cp" => copy(emulator, arguments, host, depth)?,
        "mv" => move_file(emulator, arguments, host, depth)?,
        "chmod" => chmod(emulator, arguments, host, depth)?,
        "grep" => grep(arguments, input),
        "head" => head(arguments, input),
        "tail" => tail(arguments, input),
        "sort" => sort(input),
        "uniq" => uniq(input),
        "wc" => wc(arguments, input),
        "tee" => tee(emulator, arguments, input, host, depth)?,
        "env" => env(emulator, arguments, host, depth)?,
        "local" | "declare" | "typeset" | "readonly" => {
            assign_shell_variables(emulator, arguments, host, depth)
        }
        "command" | "builtin" => {
            let Some((nested, arguments)) = arguments.split_first() else {
                return Ok(Some(success()));
            };
            if let Some(output) = execute(emulator, nested, arguments, input, host, depth)? {
                return Ok(Some(output));
            }
            return emulator
                .execute_external(nested, arguments, input.to_vec(), host, depth)
                .map(Some);
        }
        "type" => type_builtin(emulator, arguments),
        "umask" => line("0022"),
        _ => return Ok(None),
    };
    Ok(Some(output))
}

fn success() -> CommandOutput {
    CommandOutput::default()
}

fn status(code: i32) -> CommandOutput {
    CommandOutput {
        code,
        ..CommandOutput::default()
    }
}

fn line(value: impl Into<String>) -> CommandOutput {
    CommandOutput {
        stdout: vec![value.into()],
        ..CommandOutput::default()
    }
}

fn failure(value: impl Into<String>) -> CommandOutput {
    CommandOutput {
        stderr: vec![value.into()],
        code: 1,
        ..CommandOutput::default()
    }
}

fn echo(arguments: &[String]) -> CommandOutput {
    let mut newline = true;
    let mut escapes = false;
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        match argument.as_str() {
            "-n" => newline = false,
            "-e" => escapes = true,
            "-E" => escapes = false,
            _ => break,
        }
        index += 1;
    }
    let mut value = arguments[index..].join(" ");
    if escapes {
        value = interpret_escapes(&value);
    }
    if newline || !value.is_empty() {
        line(value)
    } else {
        success()
    }
}

fn printf(arguments: &[String]) -> CommandOutput {
    let Some(format) = arguments.first() else {
        return success();
    };
    let mut output = String::new();
    let mut values = arguments.iter().skip(1);
    let mut chars = format.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '%' {
            match chars.next() {
                Some('%') | None => output.push('%'),
                Some('s') => output.push_str(values.next().map_or("", String::as_str)),
                Some('d' | 'i') => output.push_str(
                    &values
                        .next()
                        .and_then(|value| value.parse::<i64>().ok())
                        .unwrap_or(0)
                        .to_string(),
                ),
                Some(other) => {
                    output.push('%');
                    output.push(other);
                }
            }
        } else if ch == '\\' {
            match chars.next() {
                Some('n') => output.push('\n'),
                Some('t') => output.push('\t'),
                Some('r') => output.push('\r'),
                Some('\\') | None => output.push('\\'),
                Some(other) => output.push(other),
            }
        } else {
            output.push(ch);
        }
    }
    CommandOutput {
        stdout: output.split_terminator('\n').map(str::to_owned).collect(),
        ..CommandOutput::default()
    }
}

fn interpret_escapes(value: &str) -> String {
    value
        .replace("\\n", "\n")
        .replace("\\t", "\t")
        .replace("\\r", "\r")
        .replace("\\\\", "\\")
}

fn cd(emulator: &mut BashEmulator, arguments: &[String], host: &dyn Host) -> CommandOutput {
    let target = arguments
        .first()
        .cloned()
        .unwrap_or_else(|| host.environment("HOME").unwrap_or("/Users/analysis").into());
    let path = if target == "-" {
        emulator
            .runtime
            .directory_stack
            .last()
            .cloned()
            .unwrap_or_else(|| emulator.runtime.current_directory.clone())
    } else {
        emulator.runtime.resolve_path(&target)
    };
    if !host.directory_exists(&path) {
        return failure(format!("bash: cd: {target}: No such file or directory"));
    }
    let previous = std::mem::replace(&mut emulator.runtime.current_directory, path.clone());
    emulator.runtime.directory_stack.push(previous);
    emulator.runtime.variables.insert("PWD".into(), path);
    success()
}

fn pushd(emulator: &mut BashEmulator, arguments: &[String], host: &dyn Host) -> CommandOutput {
    let result = cd(emulator, arguments, host);
    if result.code == 0 {
        let mut paths = vec![emulator.runtime.current_directory.clone()];
        paths.extend(emulator.runtime.directory_stack.iter().rev().cloned());
        return line(paths.join(" "));
    }
    result
}

fn popd(emulator: &mut BashEmulator) -> CommandOutput {
    let Some(path) = emulator.runtime.directory_stack.pop() else {
        return failure("bash: popd: directory stack empty");
    };
    emulator.runtime.current_directory = path;
    line(emulator.runtime.current_directory.clone())
}

fn export(
    emulator: &mut BashEmulator,
    arguments: &[String],
    host: &mut dyn Host,
    depth: usize,
) -> CommandOutput {
    if arguments.is_empty() {
        let mut entries = host.environment_entries();
        entries.sort();
        return CommandOutput {
            stdout: entries
                .into_iter()
                .map(|(name, value)| format!("declare -x {name}=\"{value}\""))
                .collect(),
            ..CommandOutput::default()
        };
    }
    for argument in arguments {
        let argument = argument.trim_start_matches("-n");
        if let Some((name, value)) = argument.split_once('=') {
            emulator.runtime.variables.insert(name.into(), value.into());
            emulator.runtime.exported.insert(name.into());
            host.set_environment(name, value);
            host.emit(
                TraceEvent::new(
                    depth,
                    Engine::Bash,
                    EventKind::VariableAssignment,
                    format!("exported environment variable {name}"),
                )
                .with_data("value", value),
            );
        } else if !argument.is_empty() {
            emulator.runtime.exported.insert(argument.into());
            let value = emulator
                .runtime
                .variables
                .get(argument)
                .cloned()
                .unwrap_or_default();
            host.set_environment(argument, &value);
        }
    }
    success()
}

fn unset(emulator: &mut BashEmulator, arguments: &[String], host: &mut dyn Host) -> CommandOutput {
    for name in arguments {
        emulator.runtime.variables.remove(name);
        emulator.runtime.exported.remove(name);
        emulator.runtime.functions.remove(name);
        host.remove_environment(name);
    }
    success()
}

fn set(emulator: &mut BashEmulator, arguments: &[String], host: &dyn Host) -> CommandOutput {
    if let Some(index) = arguments.iter().position(|argument| argument == "--") {
        emulator.runtime.positional = arguments[index + 1..].to_vec();
        return success();
    }
    let mut entries = host.environment_entries();
    entries.extend(
        emulator
            .runtime
            .variables
            .iter()
            .map(|(name, value)| (name.clone(), value.clone())),
    );
    entries.sort();
    entries.dedup();
    CommandOutput {
        stdout: entries
            .into_iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect(),
        ..CommandOutput::default()
    }
}

fn shift(emulator: &mut BashEmulator, arguments: &[String]) -> CommandOutput {
    let count = arguments
        .first()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(1);
    if count > emulator.runtime.positional.len() {
        return status(1);
    }
    emulator.runtime.positional.drain(..count);
    success()
}

fn exit(emulator: &mut BashEmulator, arguments: &[String]) -> CommandOutput {
    let code = arguments
        .first()
        .and_then(|value| value.parse().ok())
        .unwrap_or(emulator.runtime.last_status);
    emulator.runtime.flow = FlowControl::Exit(code);
    status(code)
}

fn return_from_function(emulator: &mut BashEmulator, arguments: &[String]) -> CommandOutput {
    let code = arguments
        .first()
        .and_then(|value| value.parse().ok())
        .unwrap_or(emulator.runtime.last_status);
    emulator.runtime.flow = FlowControl::Return(code);
    status(code)
}

fn test(
    emulator: &BashEmulator,
    arguments: &[String],
    host: &mut dyn Host,
    depth: usize,
) -> CommandOutput {
    if arguments.first().is_some_and(|argument| argument == "!") {
        let rest = &arguments[1..];
        let mut result = test(emulator, rest, host, depth);
        result.code = i32::from(result.code == 0);
        return result;
    }
    let result = match arguments {
        [value] => !value.is_empty(),
        [operator, value] if matches!(operator.as_str(), "-n" | "-z") => {
            if operator == "-n" {
                !value.is_empty()
            } else {
                value.is_empty()
            }
        }
        [operator, value] if matches!(operator.as_str(), "-e" | "-f" | "-d" | "-x" | "-s") => {
            let path = emulator.runtime.resolve_path(value);
            match operator.as_str() {
                "-e" => {
                    host.directory_exists(&path)
                        || host.read_file(&path, Engine::Bash, depth).is_some()
                }
                "-f" => host.read_file(&path, Engine::Bash, depth).is_some(),
                "-d" => host.directory_exists(&path),
                "-x" => host.is_executable(&path),
                "-s" => host
                    .read_file(&path, Engine::Bash, depth)
                    .is_some_and(|bytes| !bytes.is_empty()),
                _ => false,
            }
        }
        [left, operator, right] => match operator.as_str() {
            "=" | "==" => left == right,
            "!=" => left != right,
            "-eq" => numeric(left) == numeric(right),
            "-ne" => numeric(left) != numeric(right),
            "-lt" => numeric(left) < numeric(right),
            "-le" => numeric(left) <= numeric(right),
            "-gt" => numeric(left) > numeric(right),
            "-ge" => numeric(left) >= numeric(right),
            _ => false,
        },
        _ => false,
    };
    status(i32::from(!result))
}

fn numeric(value: &str) -> i64 {
    value.parse().unwrap_or(0)
}

fn read(emulator: &mut BashEmulator, arguments: &[String], input: &[String]) -> CommandOutput {
    let names = arguments
        .iter()
        .filter(|argument| !argument.starts_with('-'))
        .collect::<Vec<_>>();
    let Some(line) = input.first() else {
        return status(1);
    };
    let values = line.split_whitespace().collect::<Vec<_>>();
    for (index, name) in names.iter().enumerate() {
        let value = if index + 1 == names.len() {
            values.get(index..).unwrap_or_default().join(" ")
        } else {
            values.get(index).copied().unwrap_or_default().into()
        };
        emulator.runtime.variables.insert((*name).clone(), value);
    }
    success()
}

fn mkdir(
    emulator: &BashEmulator,
    arguments: &[String],
    host: &mut dyn Host,
    depth: usize,
) -> Result<CommandOutput, BashError> {
    let parents = arguments.iter().any(|argument| argument == "-p");
    let paths = arguments
        .iter()
        .filter(|argument| !argument.starts_with('-'))
        .collect::<Vec<_>>();
    if paths.is_empty() {
        return Ok(failure("mkdir: missing operand"));
    }
    for path in paths {
        let resolved = emulator.runtime.resolve_path(path);
        if parents {
            let mut current = String::from("/");
            for part in resolved.split('/').filter(|part| !part.is_empty()) {
                if current.len() > 1 {
                    current.push('/');
                }
                current.push_str(part);
                host.create_directory(&current, Engine::Bash, depth)?;
            }
        } else {
            host.create_directory(&resolved, Engine::Bash, depth)?;
        }
    }
    Ok(success())
}

fn rmdir(
    emulator: &BashEmulator,
    arguments: &[String],
    host: &mut dyn Host,
    depth: usize,
) -> CommandOutput {
    for path in arguments
        .iter()
        .filter(|argument| !argument.starts_with('-'))
    {
        if !host.delete_directory(
            &emulator.runtime.resolve_path(path),
            false,
            Engine::Bash,
            depth,
        ) {
            return failure(format!("rmdir: {path}: Directory not empty or not found"));
        }
    }
    success()
}

fn rm(
    emulator: &BashEmulator,
    arguments: &[String],
    host: &mut dyn Host,
    depth: usize,
) -> CommandOutput {
    let recursive = arguments
        .iter()
        .any(|argument| matches!(argument.as_str(), "-r" | "-R" | "-rf" | "-fr"));
    let force = arguments.iter().any(|argument| argument.contains('f'));
    for path in arguments
        .iter()
        .filter(|argument| !argument.starts_with('-'))
    {
        let path = emulator.runtime.resolve_path(path);
        if host.directory_exists(&path) {
            if !host.delete_directory(&path, recursive, Engine::Bash, depth) && !force {
                return failure(format!("rm: {path}: is a directory"));
            }
        } else if !host.delete_file(&path, Engine::Bash, depth) && !force {
            return failure(format!("rm: {path}: No such file or directory"));
        }
    }
    success()
}

fn touch(
    emulator: &BashEmulator,
    arguments: &[String],
    host: &mut dyn Host,
    depth: usize,
) -> Result<CommandOutput, BashError> {
    for path in arguments
        .iter()
        .filter(|argument| !argument.starts_with('-'))
    {
        let path = emulator.runtime.resolve_path(path);
        let bytes = host
            .read_file(&path, Engine::Bash, depth)
            .unwrap_or_default();
        host.write_file(&path, &bytes, false, Engine::Bash, depth)?;
    }
    Ok(success())
}

fn cat(
    emulator: &BashEmulator,
    arguments: &[String],
    input: &[String],
    host: &mut dyn Host,
    depth: usize,
) -> CommandOutput {
    let paths = arguments
        .iter()
        .filter(|argument| !argument.starts_with('-'))
        .collect::<Vec<_>>();
    if paths.is_empty() {
        return CommandOutput {
            stdout: input.to_vec(),
            ..CommandOutput::default()
        };
    }
    let mut output = CommandOutput::default();
    for path in paths {
        let path = emulator.runtime.resolve_path(path);
        let Some(bytes) = host.read_file(&path, Engine::Bash, depth) else {
            output.stderr.push(format!("cat: {path}: No such file"));
            output.code = 1;
            continue;
        };
        output
            .stdout
            .extend(String::from_utf8_lossy(&bytes).lines().map(str::to_owned));
    }
    output
}

fn copy(
    emulator: &BashEmulator,
    arguments: &[String],
    host: &mut dyn Host,
    depth: usize,
) -> Result<CommandOutput, BashError> {
    let paths = arguments
        .iter()
        .filter(|argument| !argument.starts_with('-'))
        .collect::<Vec<_>>();
    let [source, target] = paths.as_slice() else {
        return Ok(failure("cp: expected source and destination"));
    };
    let source = emulator.runtime.resolve_path(source);
    let target = emulator.runtime.resolve_path(target);
    let Some(bytes) = host.read_file(&source, Engine::Bash, depth) else {
        return Ok(failure(format!("cp: {source}: No such file")));
    };
    host.write_file(&target, &bytes, false, Engine::Bash, depth)?;
    Ok(success())
}

fn move_file(
    emulator: &BashEmulator,
    arguments: &[String],
    host: &mut dyn Host,
    depth: usize,
) -> Result<CommandOutput, BashError> {
    let result = copy(emulator, arguments, host, depth)?;
    if result.code == 0 {
        if let Some(source) = arguments.iter().find(|argument| !argument.starts_with('-')) {
            host.delete_file(&emulator.runtime.resolve_path(source), Engine::Bash, depth);
        }
    }
    Ok(result)
}

fn chmod(
    emulator: &BashEmulator,
    arguments: &[String],
    host: &mut dyn Host,
    depth: usize,
) -> Result<CommandOutput, BashError> {
    let executable = arguments
        .first()
        .is_some_and(|mode| mode.contains('x') || mode.ends_with("755"));
    if executable {
        for path in arguments.iter().skip(1) {
            host.register_executable(&emulator.runtime.resolve_path(path), Engine::Bash, depth)?;
        }
    }
    Ok(success())
}

fn grep(arguments: &[String], input: &[String]) -> CommandOutput {
    let ignore_case = arguments.iter().any(|argument| argument == "-i");
    let invert = arguments.iter().any(|argument| argument == "-v");
    let Some(pattern) = arguments.iter().find(|argument| !argument.starts_with('-')) else {
        return failure("grep: missing pattern");
    };
    let needle = if ignore_case {
        pattern.to_ascii_lowercase()
    } else {
        pattern.clone()
    };
    let stdout = input
        .iter()
        .filter(|line| {
            let haystack = if ignore_case {
                line.to_ascii_lowercase()
            } else {
                (*line).clone()
            };
            haystack.contains(&needle) != invert
        })
        .cloned()
        .collect::<Vec<_>>();
    let code = i32::from(stdout.is_empty());
    CommandOutput {
        stdout,
        code,
        ..CommandOutput::default()
    }
}

fn head(arguments: &[String], input: &[String]) -> CommandOutput {
    let count = line_count(arguments, 10);
    CommandOutput {
        stdout: input.iter().take(count).cloned().collect(),
        ..CommandOutput::default()
    }
}

fn tail(arguments: &[String], input: &[String]) -> CommandOutput {
    let count = line_count(arguments, 10);
    CommandOutput {
        stdout: input
            .iter()
            .skip(input.len().saturating_sub(count))
            .cloned()
            .collect(),
        ..CommandOutput::default()
    }
}

fn line_count(arguments: &[String], default: usize) -> usize {
    arguments
        .windows(2)
        .find(|pair| pair[0] == "-n")
        .and_then(|pair| pair[1].parse().ok())
        .or_else(|| {
            arguments
                .iter()
                .find_map(|argument| argument.strip_prefix('-')?.parse().ok())
        })
        .unwrap_or(default)
}

fn sort(input: &[String]) -> CommandOutput {
    let mut stdout = input.to_vec();
    stdout.sort();
    CommandOutput {
        stdout,
        ..CommandOutput::default()
    }
}

fn uniq(input: &[String]) -> CommandOutput {
    let mut stdout = Vec::new();
    for line in input {
        if stdout.last() != Some(line) {
            stdout.push(line.clone());
        }
    }
    CommandOutput {
        stdout,
        ..CommandOutput::default()
    }
}

fn wc(arguments: &[String], input: &[String]) -> CommandOutput {
    let words = input
        .iter()
        .map(|line| line.split_whitespace().count())
        .sum::<usize>();
    let bytes = input.iter().map(|line| line.len() + 1).sum::<usize>();
    let value = if arguments.iter().any(|argument| argument == "-l") {
        input.len()
    } else if arguments.iter().any(|argument| argument == "-w") {
        words
    } else if arguments.iter().any(|argument| argument == "-c") {
        bytes
    } else {
        return line(format!("{} {words} {bytes}", input.len()));
    };
    line(value.to_string())
}

fn tee(
    emulator: &BashEmulator,
    arguments: &[String],
    input: &[String],
    host: &mut dyn Host,
    depth: usize,
) -> Result<CommandOutput, BashError> {
    let append = arguments.iter().any(|argument| argument == "-a");
    let bytes = if input.is_empty() {
        Vec::new()
    } else {
        format!("{}\n", input.join("\n")).into_bytes()
    };
    for path in arguments
        .iter()
        .filter(|argument| !argument.starts_with('-'))
    {
        host.write_file(
            &emulator.runtime.resolve_path(path),
            &bytes,
            append,
            Engine::Bash,
            depth,
        )?;
    }
    Ok(CommandOutput {
        stdout: input.to_vec(),
        ..CommandOutput::default()
    })
}

fn env(
    emulator: &mut BashEmulator,
    arguments: &[String],
    host: &mut dyn Host,
    depth: usize,
) -> Result<CommandOutput, BashError> {
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        let Some((name, value)) = argument.split_once('=') else {
            break;
        };
        host.set_environment(name, value);
        index += 1;
    }
    if let Some((command, rest)) = arguments[index..].split_first() {
        if let Some(output) = execute(emulator, command, rest, &[], host, depth)? {
            return Ok(output);
        }
        return emulator.execute_external(command, rest, Vec::new(), host, depth);
    }
    let mut entries = host.environment_entries();
    entries.sort();
    Ok(CommandOutput {
        stdout: entries
            .into_iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect(),
        ..CommandOutput::default()
    })
}

fn assign_shell_variables(
    emulator: &mut BashEmulator,
    arguments: &[String],
    host: &mut dyn Host,
    depth: usize,
) -> CommandOutput {
    for argument in arguments
        .iter()
        .filter(|argument| !argument.starts_with('-'))
    {
        if let Some((name, value)) = argument.split_once('=') {
            emulator.runtime.variables.insert(name.into(), value.into());
            host.emit(
                TraceEvent::new(
                    depth,
                    Engine::Bash,
                    EventKind::VariableAssignment,
                    format!("assigned local shell variable {name}"),
                )
                .with_data("value", value),
            );
        }
    }
    success()
}

fn type_builtin(emulator: &BashEmulator, arguments: &[String]) -> CommandOutput {
    let mut output = CommandOutput::default();
    for name in arguments {
        if emulator.runtime.functions.contains_key(name) {
            output.stdout.push(format!("{name} is a function"));
        } else if is_builtin(name) {
            output.stdout.push(format!("{name} is a shell builtin"));
        } else {
            output.stdout.push(format!("{name} is /usr/bin/{name}"));
        }
    }
    output
}

fn is_builtin(name: &str) -> bool {
    matches!(
        name,
        ":" | "true"
            | "false"
            | "echo"
            | "printf"
            | "pwd"
            | "cd"
            | "export"
            | "unset"
            | "set"
            | "shift"
            | "exit"
            | "return"
            | "test"
            | "["
            | "read"
            | "source"
            | "."
    )
}
