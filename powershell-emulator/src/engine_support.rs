use super::{
    bytes_to_value, decode_candidate, extract_delimited, quote_argument, sha256_hex,
    split_windows_command_line, tokenize, unescape_powershell, ArtifactKind, Engine, EventKind,
    Host, PowerShellEmulator, PowerShellError, ProcessIntent, StringKind, TokenKind, TraceEvent,
    Value, VARIABLE_RE,
};
use std::collections::HashSet;

impl PowerShellEmulator {
    pub(crate) fn decode_layers(value: Value, host: &mut dyn Host, depth: usize) -> Value {
        let original = value.clone();
        let mut candidate = value;
        let max_passes = host.limits().max_decode_passes;
        let mut seen = HashSet::new();
        for pass in 0..max_passes {
            let text = candidate.as_string();
            if !seen.insert(text.clone()) {
                break;
            }
            let Some((label, bytes)) = decode_candidate(&text) else {
                break;
            };
            Self::record_decode(label, &bytes, host, depth);
            host.emit(
                TraceEvent::new(
                    depth,
                    Engine::PowerShell,
                    EventKind::Decode,
                    format!("decoded {label} layer {}", pass + 1),
                )
                .with_data("input_bytes", text.len().to_string())
                .with_data("output_bytes", bytes.len().to_string()),
            );
            candidate = bytes_to_value(&bytes);
        }
        original
    }

    pub(crate) fn record_decode(label: &str, bytes: &[u8], host: &mut dyn Host, depth: usize) {
        host.emit(
            TraceEvent::new(
                depth,
                Engine::PowerShell,
                EventKind::Decode,
                format!("decoded {label} content"),
            )
            .with_data("output_bytes", bytes.len().to_string())
            .with_data("output_sha256", sha256_hex(bytes))
            .with_data("transform", label),
        );
        let media_type = if std::str::from_utf8(bytes).is_ok() {
            "text/plain"
        } else {
            "application/octet-stream"
        };
        let kind = if media_type == "text/plain" {
            ArtifactKind::DecodedText
        } else {
            ArtifactKind::Binary
        };
        host.add_artifact(kind, &format!("decoded-{label}"), media_type, bytes, depth);
    }

    pub(crate) fn parse_string(
        &mut self,
        expression: &str,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<String, PowerShellError> {
        let Some(quote) = expression.chars().next() else {
            return Ok(String::new());
        };
        if expression.len() < 2 || !expression.ends_with(quote) {
            return Ok(expression.into());
        }
        let inner = &expression[1..expression.len() - 1];
        if quote == '\'' {
            Ok(inner.replace("''", "'"))
        } else {
            self.interpolate(&unescape_powershell(inner), host, depth)
        }
    }

    pub(crate) fn parse_here_string(
        &mut self,
        expression: &str,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Option<String>, PowerShellError> {
        let tokens = tokenize(expression)
            .tokens
            .into_iter()
            .filter(|token| !token.kind.is_trivia() && token.kind != TokenKind::NewLine)
            .collect::<Vec<_>>();
        let Some(token) = tokens.first().copied() else {
            return Ok(None);
        };
        let kind = match token.kind {
            TokenKind::HereString(kind) if tokens.len() == 1 => kind,
            _ => return Ok(None),
        };
        let lexeme = token.text(expression);
        let Some(after_opening) = lexeme.get(2..) else {
            return Ok(None);
        };
        let opening_newline = if after_opening.starts_with("\r\n") {
            2
        } else {
            1
        };
        let Some(body_end) = lexeme.len().checked_sub(2) else {
            return Ok(None);
        };
        let Some(mut body) = lexeme.get(2 + opening_newline..body_end) else {
            return Ok(None);
        };
        body = body
            .strip_suffix("\r\n")
            .or_else(|| body.strip_suffix('\n'))
            .unwrap_or(body);
        Ok(Some(match kind {
            StringKind::Literal => body.into(),
            StringKind::Expandable => self.interpolate(&unescape_powershell(body), host, depth)?,
        }))
    }

    pub(crate) fn interpolate(
        &mut self,
        input: &str,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<String, PowerShellError> {
        let mut expanded = String::with_capacity(input.len());
        let mut cursor = 0;
        while let Some(relative_start) = input[cursor..].find("$(") {
            let start = cursor + relative_start;
            expanded.push_str(&input[cursor..start]);
            let delimited = &input[start + 1..];
            let Some((inner, remainder)) = extract_delimited(delimited, '(', ')') else {
                expanded.push_str(&input[start..]);
                cursor = input.len();
                break;
            };
            let value = if self.looks_like_command_expression(inner) {
                self.execute_statement(inner, host, depth + 1)?
                    .unwrap_or(Value::Null)
            } else {
                self.eval_expression(inner, host, depth + 1)?
            };
            expanded.push_str(&value.as_string());
            let consumed = delimited.len().saturating_sub(remainder.len());
            cursor = start + 1 + consumed;
        }
        expanded.push_str(&input[cursor..]);
        Ok(VARIABLE_RE
            .replace_all(&expanded, |captures: &regex::Captures<'_>| {
                let name = captures
                    .get(1)
                    .or_else(|| captures.get(2))
                    .map_or("", |capture| capture.as_str());
                if let Some(environment_name) = name
                    .strip_prefix("env:")
                    .or_else(|| name.strip_prefix("ENV:"))
                {
                    host.environment(environment_name).unwrap_or("").to_owned()
                } else {
                    self.variables
                        .get(&name.to_ascii_lowercase())
                        .map_or_else(String::new, Value::as_string)
                }
            })
            .into_owned())
    }

    pub(crate) fn spawn_command_line(
        command_line: &str,
        origin: &str,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<(), PowerShellError> {
        let words = split_windows_command_line(command_line);
        if let Some(program) = words.first() {
            Self::spawn(program, words[1..].to_vec(), origin, host, depth)?;
        }
        Ok(())
    }

    pub(crate) fn spawn(
        program: &str,
        args: Vec<String>,
        origin: &str,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<(), PowerShellError> {
        let command_line = std::iter::once(program.to_owned())
            .chain(args.iter().map(|argument| quote_argument(argument)))
            .collect::<Vec<_>>()
            .join(" ");
        host.process_intent(ProcessIntent {
            program: program.into(),
            args,
            command_line,
            origin: origin.into(),
            depth: depth + 1,
            stdin: Vec::new(),
            current_directory: String::new(),
        })?;
        Ok(())
    }
}
