use bash_emulator::{tokenizer::tokenize, BashEmulator};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Default)]
struct Summary {
    files: usize,
    bytes: usize,
    tokens: usize,
    commands: usize,
    diagnostics: usize,
    files_with_diagnostics: usize,
    fatal_diagnostics: usize,
    invalid_utf8: usize,
    panics: usize,
    largest_file_bytes: usize,
    diagnostic_messages: BTreeMap<String, usize>,
}

#[allow(clippy::too_many_lines)]
fn main() -> ExitCode {
    let Some(root) = env::args_os().nth(1).map(PathBuf::from) else {
        eprintln!("usage: cargo run -p bash-emulator --example corpus_check -- CORPUS_DIRECTORY");
        return ExitCode::from(2);
    };
    if !root.is_dir() {
        eprintln!("corpus directory does not exist: {}", root.display());
        return ExitCode::from(2);
    }

    let mut paths = Vec::new();
    collect_files(&root, &mut paths);
    paths.sort();
    let mut summary = Summary::default();

    for path in paths {
        let Ok(bytes) = fs::read(&path) else {
            continue;
        };
        let Ok(source) = std::str::from_utf8(&bytes) else {
            summary.invalid_utf8 += 1;
            continue;
        };
        if !looks_like_shell_script(&path, source) {
            continue;
        }

        eprintln!("CHECK\t{}", path.display());
        summary.files += 1;
        summary.bytes += bytes.len();
        summary.largest_file_bytes = summary.largest_file_bytes.max(bytes.len());
        let tokenization = tokenize(source);
        summary.tokens += tokenization.tokens.len();
        summary.fatal_diagnostics += tokenization
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.fatal)
            .count();

        let parsed = std::panic::catch_unwind(|| BashEmulator::parse(source));
        if let Ok(parsed) = parsed {
            summary.commands += parsed.commands;
            summary.diagnostics += parsed.diagnostics.len();
            if !parsed.diagnostics.is_empty() {
                summary.files_with_diagnostics += 1;
                let mut unique = parsed.diagnostics.clone();
                unique.sort();
                unique.dedup();
                let locations = parsed
                    .detailed_diagnostics
                    .iter()
                    .map(|diagnostic| {
                        let (line, column) =
                            line_column(source, diagnostic.start.min(source.len()));
                        format!("{line}:{column}:{}", diagnostic.message)
                    })
                    .collect::<Vec<_>>()
                    .join(" | ");
                eprintln!(
                    "DIAG\t{}\t{}\t{}\t{}",
                    path.display(),
                    parsed.diagnostics.len(),
                    unique.join(" | "),
                    locations
                );
                for diagnostic in &parsed.detailed_diagnostics {
                    let nearby = tokenization
                        .tokens
                        .iter()
                        .filter(|token| {
                            token.span.end.saturating_add(80) >= diagnostic.start
                                && token.span.start <= diagnostic.end.saturating_add(80)
                        })
                        .map(|token| {
                            let text = token
                                .text(source)
                                .replace('\n', "\\n")
                                .replace('\r', "\\r")
                                .replace('\t', "\\t");
                            format!("{:?}:{text}", token.kind)
                        })
                        .collect::<Vec<_>>()
                        .join(" || ");
                    eprintln!(
                        "TOKENS\t{}\t{}:{}\t{}",
                        path.display(),
                        diagnostic.start,
                        diagnostic.end,
                        nearby
                    );
                }
                for diagnostic in parsed.diagnostics {
                    *summary.diagnostic_messages.entry(diagnostic).or_default() += 1;
                }
            }
        } else {
            summary.panics += 1;
            eprintln!("PANIC\t{}", path.display());
        }
    }

    println!("files={}", summary.files);
    println!("bytes={}", summary.bytes);
    println!("tokens={}", summary.tokens);
    println!("commands={}", summary.commands);
    println!("diagnostics={}", summary.diagnostics);
    println!("files_with_diagnostics={}", summary.files_with_diagnostics);
    println!("fatal_diagnostics={}", summary.fatal_diagnostics);
    println!("invalid_utf8={}", summary.invalid_utf8);
    println!("panics={}", summary.panics);
    println!("largest_file_bytes={}", summary.largest_file_bytes);
    println!("top_diagnostics:");
    let mut diagnostics = summary.diagnostic_messages.into_iter().collect::<Vec<_>>();
    diagnostics.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    for (message, count) in diagnostics.into_iter().take(20) {
        println!("{count}\t{message}");
    }

    if summary.panics == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn line_column(source: &str, offset: usize) -> (usize, usize) {
    let prefix = &source[..offset];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let column = prefix
        .rsplit_once('\n')
        .map_or(prefix.len() + 1, |(_, line)| line.len() + 1);
    (line, column)
}

fn collect_files(directory: &Path, output: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, output);
        } else if path.is_file() {
            output.push(path);
        }
    }
}

fn looks_like_shell_script(path: &Path, source: &str) -> bool {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    matches!(extension, "sh" | "bash")
        || source.starts_with("#!/bin/bash")
        || source.starts_with("#!/usr/bin/env bash")
        || source.starts_with("#!/bin/sh")
        || source.starts_with("#!/usr/bin/env sh")
        || source.starts_with("#!/bin/zsh")
        || source.starts_with("#!/usr/bin/env zsh")
}
