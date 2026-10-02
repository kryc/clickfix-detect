use crate::runtime::FlowControl;
use crate::{BashEmulator, BashError, CommandOutput};
use base64::Engine as _;
use emulator_core::{
    ArtifactKind, CausalEdge, CausalEntity, CausalRelation, Engine, EventKind, Host, TraceEvent,
};
use std::collections::BTreeMap;

#[allow(clippy::too_many_lines)]
pub(crate) fn execute(
    emulator: &mut BashEmulator,
    name: &str,
    arguments: &[String],
    input: &[String],
    input_causes: &[CausalEntity],
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
        "cat" => cat(emulator, arguments, input, input_causes, host, depth),
        "base64" => base64_command(emulator, arguments, input, input_causes, host, depth),
        "ls" => ls(emulator, arguments, host, depth),
        "cp" => copy(emulator, arguments, host, depth)?,
        "mv" => move_file(emulator, arguments, host, depth)?,
        "chmod" => chmod(emulator, arguments, host, depth)?,
        "grep" => grep(arguments, input),
        "head" => head(arguments, input),
        "tail" => tail(arguments, input),
        "sort" => sort(input),
        "uniq" => uniq(input),
        "wc" => wc(arguments, input),
        "tee" => tee(emulator, arguments, input, input_causes, host, depth)?,
        "env" => env(emulator, arguments, host, depth)?,
        "local" | "declare" | "typeset" | "readonly" => {
            assign_shell_variables(emulator, arguments, host, depth)
        }
        "command" | "builtin" => {
            let Some((nested, arguments)) = arguments.split_first() else {
                return Ok(Some(success()));
            };
            if let Some(output) = execute(
                emulator,
                nested,
                arguments,
                input,
                input_causes,
                host,
                depth,
            )? {
                return Ok(Some(output));
            }
            return emulator
                .execute_external(
                    nested,
                    arguments,
                    input.to_vec(),
                    input_causes.to_vec(),
                    host,
                    depth,
                )
                .map(Some);
        }
        "type" => type_builtin(emulator, arguments),
        "umask" => line("0022"),
        _ => return Ok(None),
    };
    let mut output = output;
    if output.causes.is_empty()
        && matches!(
            name,
            "grep" | "head" | "tail" | "sort" | "uniq" | "wc" | "tee"
        )
    {
        output.causes = input_causes.to_vec();
    }
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
    input_causes: &[CausalEntity],
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
            causes: input_causes.to_vec(),
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
        output
            .causes
            .push(CausalEntity::VirtualFile { path: path.clone() });
    }
    output.causes.sort();
    output.causes.dedup();
    output
}

fn base64_command(
    emulator: &BashEmulator,
    arguments: &[String],
    input: &[String],
    input_causes: &[CausalEntity],
    host: &mut dyn Host,
    depth: usize,
) -> CommandOutput {
    let decode = arguments
        .iter()
        .any(|argument| matches!(argument.as_str(), "-d" | "-D" | "--decode"));
    let file = arguments.iter().find(|argument| !argument.starts_with('-'));
    let bytes = if let Some(path) = file {
        let path = emulator.runtime.resolve_path(path);
        let Some(bytes) = host.read_file(&path, Engine::Bash, depth) else {
            return failure(format!("base64: {path}: No such file or directory"));
        };
        bytes
    } else {
        input.join("\n").into_bytes()
    };
    if !decode {
        return line(base64::engine::general_purpose::STANDARD.encode(bytes));
    }
    let encoded = String::from_utf8_lossy(&bytes)
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>();
    let decoded = match base64::engine::general_purpose::STANDARD.decode(encoded) {
        Ok(decoded) => decoded,
        Err(error) => return failure(format!("base64: invalid input: {error}")),
    };
    let artifact_id = host.add_artifact(
        if std::str::from_utf8(&decoded).is_ok() {
            ArtifactKind::DecodedText
        } else {
            ArtifactKind::Binary
        },
        "base64-decoded",
        "application/octet-stream",
        &decoded,
        depth,
    );
    let artifact = CausalEntity::Artifact { id: artifact_id };
    for source in input_causes {
        host.add_causal_edge(CausalEdge {
            from: source.clone(),
            to: artifact.clone(),
            relation: CausalRelation::Decoded,
            depth,
        });
    }
    host.emit(
        TraceEvent::new(
            depth,
            Engine::Bash,
            EventKind::Decode,
            "decoded Base64 with Bash base64 builtin",
        )
        .with_data("decoded_bytes", decoded.len().to_string()),
    );
    CommandOutput {
        stdout: String::from_utf8_lossy(&decoded)
            .lines()
            .map(str::to_owned)
            .collect(),
        raw_stdout: Some(decoded),
        causes: vec![artifact],
        ..CommandOutput::default()
    }
}

#[derive(Debug, Default)]
struct LsOptions {
    all: bool,
    almost_all: bool,
    long: bool,
}

#[derive(Debug)]
enum LsEntry {
    Directory,
    File { path: String, size: usize },
}

fn ls(
    emulator: &BashEmulator,
    arguments: &[String],
    host: &mut dyn Host,
    depth: usize,
) -> CommandOutput {
    let mut options = LsOptions::default();
    let mut targets = Vec::new();
    let mut parse_options = true;
    for argument in arguments {
        if parse_options && argument == "--" {
            parse_options = false;
            continue;
        }
        if parse_options && argument.starts_with("--") {
            match argument.as_str() {
                "--all" => options.all = true,
                "--almost-all" => options.almost_all = true,
                "--format=single-column" | "--color" | "--color=auto" | "--color=never" => {}
                _ => return failure(format!("ls: unrecognized option '{argument}'")),
            }
            continue;
        }
        if parse_options && argument.starts_with('-') && argument.len() > 1 {
            for option in argument[1..].chars() {
                match option {
                    '1' | 'h' => {}
                    'a' => options.all = true,
                    'A' => options.almost_all = true,
                    'l' => options.long = true,
                    _ => return failure(format!("ls: invalid option -- '{option}'")),
                }
            }
            continue;
        }
        targets.push(argument.clone());
    }
    if targets.is_empty() {
        targets.push(".".into());
    }

    let multiple_targets = targets.len() > 1;
    let mut output = CommandOutput::default();
    for (index, target) in targets.iter().enumerate() {
        let path = emulator.runtime.resolve_path(target);
        if host.directory_exists(&path) {
            if multiple_targets {
                if index > 0 {
                    output.stdout.push(String::new());
                }
                output.stdout.push(format!("{target}:"));
            }
            output
                .stdout
                .extend(list_directory(&path, &options, host, depth));
            continue;
        }
        if let Some(bytes) = host.read_file(&path, Engine::Bash, depth) {
            output.stdout.push(format_ls_entry(
                target,
                &LsEntry::File {
                    path,
                    size: bytes.len(),
                },
                options.long,
                host,
            ));
            continue;
        }
        output.stderr.push(format!(
            "ls: cannot access '{target}': No such file or directory"
        ));
        output.code = 2;
    }
    output
}

fn list_directory(
    path: &str,
    options: &LsOptions,
    host: &mut dyn Host,
    depth: usize,
) -> Vec<String> {
    let mut entries = BTreeMap::new();
    for directory in host.list_directories(path, Engine::Bash, depth) {
        if let Some(name) = direct_child_name(path, &directory) {
            entries.insert(name.to_owned(), LsEntry::Directory);
        }
    }
    for file in host.list_files(path, Engine::Bash, depth) {
        if let Some(name) = direct_child_name(path, &file) {
            let size = host
                .read_file(&file, Engine::Bash, depth)
                .map_or(0, |bytes| bytes.len());
            entries.insert(name.to_owned(), LsEntry::File { path: file, size });
        }
    }
    let mut output = Vec::new();
    if options.all {
        output.push(format_ls_entry(
            ".",
            &LsEntry::Directory,
            options.long,
            host,
        ));
        output.push(format_ls_entry(
            "..",
            &LsEntry::Directory,
            options.long,
            host,
        ));
    }
    output.extend(
        entries
            .into_iter()
            .filter(|(name, _)| options.all || options.almost_all || !name.starts_with('.'))
            .map(|(name, entry)| format_ls_entry(&name, &entry, options.long, host)),
    );
    output
}

fn direct_child_name<'a>(parent: &str, candidate: &'a str) -> Option<&'a str> {
    let prefix = if parent == "/" {
        "/".into()
    } else {
        format!("{}/", parent.trim_end_matches('/'))
    };
    let rest = candidate.strip_prefix(&prefix)?;
    (!rest.is_empty() && !rest.contains('/')).then_some(rest)
}

fn format_ls_entry(name: &str, entry: &LsEntry, long: bool, host: &dyn Host) -> String {
    if !long {
        return name.into();
    }
    match entry {
        LsEntry::Directory => {
            format!("drwxr-xr-x 1 analysis analysis        0 Jan  1 00:00 {name}")
        }
        LsEntry::File { path, size } => {
            let mode = if host.is_executable(path) {
                "-rwxr-xr-x"
            } else {
                "-rw-r--r--"
            };
            format!("{mode} 1 analysis analysis {size:>8} Jan  1 00:00 {name}")
        }
    }
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
    host.write_file_from(
        &target,
        &bytes,
        false,
        Engine::Bash,
        depth,
        &[CausalEntity::VirtualFile {
            path: source.clone(),
        }],
        CausalRelation::Copied,
    )?;
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
    input_causes: &[CausalEntity],
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
        host.write_file_from(
            &emulator.runtime.resolve_path(path),
            &bytes,
            append,
            Engine::Bash,
            depth,
            input_causes,
            CausalRelation::Written,
        )?;
    }
    Ok(CommandOutput {
        stdout: input.to_vec(),
        causes: input_causes.to_vec(),
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
        if let Some(output) = execute(emulator, command, rest, &[], &[], host, depth)? {
            return Ok(output);
        }
        return emulator.execute_external(command, rest, Vec::new(), Vec::new(), host, depth);
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
            | "base64"
            | "ls"
            | "source"
            | "."
    )
}
