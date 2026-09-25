use std::io::{Cursor, Read};

use emulator_core::{ArtifactKind, Engine, Host, ProcessIntent};
use zip::ZipArchive;

use crate::command_line::resolve_process_path;
use crate::{Runbox, RunboxError};

const SYNTHETIC_CAB_MAGIC: &[u8] = b"CFX-CAB\0";

impl Runbox {
    pub(crate) fn emulate_makecab(&mut self, intent: &ProcessIntent) -> Result<(), RunboxError> {
        let files = positional_arguments(&intent.args);
        let Some(source) = files.first() else {
            self.emit_utility_result(&[], &["No source file specified.".into()], 1, intent.depth);
            return Ok(());
        };
        let source = resolve_process_path(&intent.current_directory, source);
        let destination = files.get(1).map_or_else(
            || replace_extension(&source, "cab"),
            |path| resolve_process_path(&intent.current_directory, path),
        );
        let Some(bytes) = self.host.read_file(&source, Engine::Runbox, intent.depth) else {
            self.emit_utility_result(&[], &[format!("File not found: {source}")], 1, intent.depth);
            return Ok(());
        };
        let name = source.rsplit('\\').next().unwrap_or("payload.bin");
        let cabinet = encode_synthetic_cab(name, &bytes);
        self.host
            .write_file(&destination, &cabinet, false, Engine::Runbox, intent.depth)?;
        self.host.add_artifact(
            ArtifactKind::Binary,
            "makecab-output.cab",
            "application/vnd.ms-cab-compressed",
            &cabinet,
            intent.depth,
        );
        self.emit_utility_result(
            &[format!("Cabinet created: {destination}")],
            &[],
            0,
            intent.depth,
        );
        Ok(())
    }

    pub(crate) fn emulate_expand(&mut self, intent: &ProcessIntent) -> Result<(), RunboxError> {
        let files = positional_arguments(&intent.args);
        let Some(source) = files.first() else {
            self.emit_utility_result(&[], &["No source file specified.".into()], 1, intent.depth);
            return Ok(());
        };
        let source = resolve_process_path(&intent.current_directory, source);
        let destination = files.get(1).map_or_else(
            || intent.current_directory.clone(),
            |value| resolve_process_path(&intent.current_directory, value),
        );
        self.extract_archive(&source, &destination, intent.depth)
    }

    pub(crate) fn emulate_extrac32(&mut self, intent: &ProcessIntent) -> Result<(), RunboxError> {
        let source = intent
            .args
            .iter()
            .rev()
            .find(|argument| !argument.starts_with('/'))
            .cloned();
        let destination =
            switch_value(&intent.args, "/l").unwrap_or_else(|| intent.current_directory.clone());
        let Some(source) = source else {
            self.emit_utility_result(&[], &["No cabinet specified.".into()], 1, intent.depth);
            return Ok(());
        };
        let source = resolve_process_path(&intent.current_directory, &source);
        self.extract_archive(&source, &destination, intent.depth)
    }

    pub(crate) fn emulate_tar(&mut self, intent: &ProcessIntent) -> Result<(), RunboxError> {
        let operation = intent
            .args
            .iter()
            .find(|argument| argument.starts_with('-'));
        let Some(operation) = operation else {
            self.emit_utility_result(
                &[],
                &["tar: operation not specified".into()],
                2,
                intent.depth,
            );
            return Ok(());
        };
        let Some(archive) = tar_archive_argument(&intent.args, operation) else {
            self.emit_utility_result(&[], &["tar: archive not specified".into()], 2, intent.depth);
            return Ok(());
        };
        let archive = resolve_process_path(&intent.current_directory, &archive);
        if operation.contains('x') {
            let destination = switch_value(&intent.args, "-c")
                .unwrap_or_else(|| intent.current_directory.clone());
            return self.extract_archive(&archive, &destination, intent.depth);
        }
        if operation.contains('c') {
            let inputs = tar_input_arguments(&intent.args, operation);
            let bytes = self.create_tar(&inputs, &intent.current_directory, intent.depth);
            self.host
                .write_file(&archive, &bytes, false, Engine::Runbox, intent.depth)?;
            self.host.add_artifact(
                ArtifactKind::Binary,
                "tar-output.tar",
                "application/x-tar",
                &bytes,
                intent.depth,
            );
            self.emit_utility_result(&[], &[], 0, intent.depth);
            return Ok(());
        }
        self.host
            .unsupported(Engine::Runbox, intent.depth, "unsupported tar operation");
        Ok(())
    }

    fn extract_archive(
        &mut self,
        source: &str,
        destination: &str,
        depth: usize,
    ) -> Result<(), RunboxError> {
        let Some(bytes) = self.host.read_file(source, Engine::Runbox, depth) else {
            self.emit_utility_result(&[], &[format!("File not found: {source}")], 1, depth);
            return Ok(());
        };
        let entries = if let Some(entry) = decode_synthetic_cab(&bytes) {
            vec![entry]
        } else if bytes.starts_with(b"PK") {
            extract_zip_entries(&bytes)
        } else {
            extract_tar_entries(&bytes)
        };
        if entries.is_empty() {
            self.host.unsupported(
                Engine::Runbox,
                depth,
                &format!("unsupported or empty archive: {source}"),
            );
            self.emit_utility_result(&[], &["Archive format is not modeled.".into()], 1, depth);
            return Ok(());
        }
        for (name, bytes) in entries {
            let Some(name) = safe_archive_path(&name) else {
                self.host
                    .warning(format!("ignored unsafe archive entry {name}"));
                continue;
            };
            let path = format!(
                "{}\\{}",
                destination.trim_end_matches(['\\', '/']),
                name.replace('/', "\\")
            );
            self.host
                .write_file(&path, &bytes, false, Engine::Runbox, depth)?;
        }
        self.emit_utility_result(&["Archive expanded.".into()], &[], 0, depth);
        Ok(())
    }

    fn create_tar(&mut self, inputs: &[String], current_directory: &str, depth: usize) -> Vec<u8> {
        let mut archive = Vec::new();
        for input in inputs {
            let path = resolve_process_path(current_directory, input);
            let Some(bytes) = self.host.read_file(&path, Engine::Runbox, depth) else {
                continue;
            };
            let name = path.rsplit('\\').next().unwrap_or("file.bin");
            append_tar_entry(&mut archive, name, &bytes);
        }
        archive.resize(archive.len() + 1_024, 0);
        archive
    }
}

fn positional_arguments(arguments: &[String]) -> Vec<&str> {
    arguments
        .iter()
        .filter(|argument| !argument.starts_with('/') && !argument.starts_with('-'))
        .map(String::as_str)
        .collect()
}

fn switch_value(arguments: &[String], requested: &str) -> Option<String> {
    arguments.iter().enumerate().find_map(|(index, argument)| {
        argument
            .eq_ignore_ascii_case(requested)
            .then(|| arguments.get(index + 1).cloned())
            .flatten()
    })
}

fn tar_archive_argument(arguments: &[String], operation: &str) -> Option<String> {
    if let Some(index) = operation.find('f') {
        if index + 1 < operation.len() {
            return Some(operation[index + 1..].into());
        }
        let operation_index = arguments.iter().position(|value| value == operation)?;
        return arguments.get(operation_index + 1).cloned();
    }
    switch_value(arguments, "-f")
}

fn tar_input_arguments(arguments: &[String], operation: &str) -> Vec<String> {
    let archive = tar_archive_argument(arguments, operation);
    let mut skip_next = false;
    arguments
        .iter()
        .filter_map(|argument| {
            if skip_next {
                skip_next = false;
                return None;
            }
            if argument == operation || argument.eq_ignore_ascii_case("-f") {
                skip_next = argument.eq_ignore_ascii_case("-f") || operation.ends_with('f');
                return None;
            }
            if argument.eq_ignore_ascii_case("-c") {
                skip_next = true;
                return None;
            }
            if archive.as_ref() == Some(argument) || argument.starts_with('-') {
                None
            } else {
                Some(argument.clone())
            }
        })
        .collect()
}

fn encode_synthetic_cab(name: &str, bytes: &[u8]) -> Vec<u8> {
    let mut output = SYNTHETIC_CAB_MAGIC.to_vec();
    let name = name.as_bytes();
    output.extend(u32::try_from(name.len()).unwrap_or(u32::MAX).to_le_bytes());
    output.extend(name);
    output.extend(bytes);
    output
}

fn decode_synthetic_cab(bytes: &[u8]) -> Option<(String, Vec<u8>)> {
    let header = bytes.strip_prefix(SYNTHETIC_CAB_MAGIC)?;
    let length = u32::from_le_bytes(header.get(..4)?.try_into().ok()?) as usize;
    let name = String::from_utf8_lossy(header.get(4..4 + length)?).into_owned();
    Some((name, header.get(4 + length..)?.to_vec()))
}

fn extract_zip_entries(bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
    let Ok(mut archive) = ZipArchive::new(Cursor::new(bytes)) else {
        return Vec::new();
    };
    let mut entries = Vec::new();
    for index in 0..archive.len() {
        let Ok(mut entry) = archive.by_index(index) else {
            continue;
        };
        if entry.is_dir() {
            continue;
        }
        let mut body = Vec::new();
        if entry.read_to_end(&mut body).is_ok() {
            entries.push((entry.name().into(), body));
        }
    }
    entries
}

fn extract_tar_entries(bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut entries = Vec::new();
    let mut offset = 0_usize;
    while offset + 512 <= bytes.len() {
        let header = &bytes[offset..offset + 512];
        if header.iter().all(|byte| *byte == 0) {
            break;
        }
        let name = nul_string(&header[..100]);
        let size = parse_octal(&header[124..136]).unwrap_or(0);
        let data_start = offset + 512;
        let Some(data_end) = data_start.checked_add(size) else {
            break;
        };
        if data_end > bytes.len() {
            break;
        }
        if header[156] == 0 || header[156] == b'0' {
            entries.push((name, bytes[data_start..data_end].to_vec()));
        }
        offset = data_start + size.div_ceil(512) * 512;
    }
    entries
}

fn append_tar_entry(archive: &mut Vec<u8>, name: &str, bytes: &[u8]) {
    let mut header = [0_u8; 512];
    copy_field(&mut header[..100], name.as_bytes());
    copy_field(&mut header[100..108], b"0000644\0");
    copy_field(&mut header[108..116], b"0000000\0");
    copy_field(&mut header[116..124], b"0000000\0");
    copy_field(
        &mut header[124..136],
        format!("{:011o}\0", bytes.len()).as_bytes(),
    );
    copy_field(&mut header[136..148], b"00000000000\0");
    header[148..156].fill(b' ');
    header[156] = b'0';
    copy_field(&mut header[257..263], b"ustar\0");
    copy_field(&mut header[263..265], b"00");
    let checksum = header.iter().map(|byte| u32::from(*byte)).sum::<u32>();
    copy_field(
        &mut header[148..156],
        format!("{checksum:06o}\0 ").as_bytes(),
    );
    archive.extend(header);
    archive.extend(bytes);
    archive.resize(archive.len().div_ceil(512) * 512, 0);
}

fn safe_archive_path(path: &str) -> Option<String> {
    let normalized = path.replace('\\', "/");
    (!normalized.starts_with('/')
        && !normalized.contains("../")
        && !normalized.contains(":/")
        && normalized != "..")
        .then_some(normalized)
}

fn nul_string(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes.split(|byte| *byte == 0).next().unwrap_or_default()).into_owned()
}

fn parse_octal(bytes: &[u8]) -> Option<usize> {
    usize::from_str_radix(nul_string(bytes).trim(), 8).ok()
}

fn copy_field(destination: &mut [u8], source: &[u8]) {
    let length = destination.len().min(source.len());
    destination[..length].copy_from_slice(&source[..length]);
}

fn replace_extension(path: &str, extension: &str) -> String {
    path.rsplit_once('.').map_or_else(
        || format!("{path}.{extension}"),
        |(stem, _)| format!("{stem}.{extension}"),
    )
}
