use bash_emulator::tokenizer::tokenize;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let Some(path) = env::args_os().nth(1).map(PathBuf::from) else {
        eprintln!("usage: cargo run -p bash-emulator --example token_dump -- FILE [START_LINE] [END_LINE]");
        return ExitCode::from(2);
    };
    let start_line = env::args()
        .nth(2)
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(1);
    let end_line = env::args()
        .nth(3)
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(usize::MAX);
    let Ok(source) = fs::read_to_string(&path) else {
        eprintln!("unable to read {}", path.display());
        return ExitCode::from(2);
    };
    let tokenization = tokenize(&source);
    for token in tokenization.tokens {
        let (line, column) = line_column(&source, token.span.start);
        if line < start_line || line > end_line {
            continue;
        }
        let text = token
            .text(&source)
            .replace('\n', "\\n")
            .replace('\r', "\\r")
            .replace('\t', "\\t");
        println!(
            "{line}:{column}\t{}:{}\t{:?}\t{text}",
            token.span.start, token.span.end, token.kind
        );
    }
    for diagnostic in tokenization.diagnostics {
        let (line, column) = line_column(&source, diagnostic.span.start);
        eprintln!(
            "{line}:{column}\t{}:{}\t{}\tfatal={}",
            diagnostic.span.start, diagnostic.span.end, diagnostic.message, diagnostic.fatal
        );
    }
    ExitCode::SUCCESS
}

fn line_column(source: &str, offset: usize) -> (usize, usize) {
    let prefix = &source[..offset.min(source.len())];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let column = prefix
        .rsplit_once('\n')
        .map_or(prefix.len() + 1, |(_, line)| line.len() + 1);
    (line, column)
}
