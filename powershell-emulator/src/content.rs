use crate::syntax::{find_switch, named_or_positional};
use crate::transforms::{
    decode_ascii, decode_utf16_be, decode_utf16_le, decode_utf32_be, decode_utf32_le, decode_utf8,
    encode_utf16_be, encode_utf16_le, encode_utf32_be, encode_utf32_le,
};
use crate::{Engine, Host, PowerShellEmulator, PowerShellError, Value};

pub(crate) enum ContentDispatch {
    NotHandled,
    Handled(Option<Value>),
}

#[derive(Clone, Copy)]
enum TextEncoding {
    Ascii,
    Utf8,
    Utf8Bom,
    Utf16Le,
    Utf16Be,
    Utf32Le,
    Utf32Be,
}

impl PowerShellEmulator {
    pub(crate) fn execute_content_command(
        &mut self,
        command: &str,
        arguments: &[String],
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<ContentDispatch, PowerShellError> {
        match command {
            "set-content" | "add-content" | "out-file" => {
                let append =
                    command == "add-content" || find_switch(arguments, "-append").is_some();
                let path_expression =
                    named_or_positional(arguments, &["-path", "-literalpath", "-filepath"], 0)
                        .unwrap_or_default();
                let value_expression =
                    named_or_positional(arguments, &["-value", "-inputobject"], 1);
                let path = self.eval_content_path(&path_expression, host, depth)?;
                let target = self.resolve_provider_path(&path);
                let value = if let Some(expression) = value_expression {
                    self.eval_expression(&expression, host, depth)?
                } else {
                    self.variables.get("input").cloned().unwrap_or(Value::Null)
                };
                let no_newline = find_switch(arguments, "-nonewline").is_some();
                let text = content_records(&value, no_newline);
                let explicit_encoding = named_or_positional(arguments, &["-encoding"], usize::MAX);
                let encoding = parse_encoding(
                    explicit_encoding.as_deref(),
                    if command == "out-file" {
                        TextEncoding::Utf16Le
                    } else {
                        TextEncoding::Utf8
                    },
                );
                let include_preamble = if append {
                    host.read_file(&target.path, Engine::PowerShell, depth)
                        .is_none_or(|bytes| bytes.is_empty())
                } else {
                    true
                };
                let bytes = encode_text(&text, encoding, include_preamble);
                host.write_file(&target.path, &bytes, append, Engine::PowerShell, depth)?;
                Ok(ContentDispatch::Handled(Some(Value::Null)))
            }
            "get-content" => {
                let path_expression = named_or_positional(arguments, &["-path", "-literalpath"], 0)
                    .unwrap_or_default();
                let path = self.eval_content_path(&path_expression, host, depth)?;
                let target = self.resolve_provider_path(&path);
                let explicit_encoding = named_or_positional(arguments, &["-encoding"], usize::MAX);
                let value = host
                    .read_file(&target.path, Engine::PowerShell, depth)
                    .map_or(Value::Null, |bytes| {
                        let encoding = explicit_encoding
                            .as_deref()
                            .map(|value| parse_encoding(Some(value), TextEncoding::Utf8));
                        let text = decode_text(&bytes, encoding);
                        if find_switch(arguments, "-raw").is_some() {
                            return Value::String(text);
                        }
                        let mut records = if let Some(delimiter) =
                            named_or_positional(arguments, &["-delimiter"], usize::MAX)
                        {
                            let delimiter = delimiter.trim_matches(['\'', '"']);
                            split_with_delimiter(&text, delimiter)
                        } else {
                            text.lines().map(str::to_owned).collect()
                        };
                        if let Some(total) = numeric_argument(arguments, "-totalcount") {
                            records.truncate(total);
                        }
                        if let Some(tail) = numeric_argument(arguments, "-tail") {
                            let start = records.len().saturating_sub(tail);
                            records = records.split_off(start);
                        }
                        Value::Array(records.into_iter().map(Value::String).collect())
                    });
                Ok(ContentDispatch::Handled(Some(value)))
            }
            _ => Ok(ContentDispatch::NotHandled),
        }
    }

    pub(crate) fn write_redirected_output(
        &mut self,
        path: &str,
        values: &[Value],
        append: bool,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<(), PowerShellError> {
        let path = self.eval_content_path(path, host, depth)?;
        let target = self.resolve_provider_path(&path);
        let text = if values.is_empty() {
            String::new()
        } else {
            content_records(&Value::Array(values.to_vec()), false)
        };
        let include_preamble = if append {
            host.read_file(&target.path, Engine::PowerShell, depth)
                .is_none_or(|bytes| bytes.is_empty())
        } else {
            true
        };
        let bytes = encode_text(&text, TextEncoding::Utf16Le, include_preamble);
        host.write_file(&target.path, &bytes, append, Engine::PowerShell, depth)?;
        Ok(())
    }

    fn eval_content_path(
        &mut self,
        path: &str,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<String, PowerShellError> {
        if path.starts_with(['$', '\'', '"', '(']) {
            self.eval_expression(path, host, depth)
                .map(|value| value.as_string())
        } else {
            Ok(path.into())
        }
    }
}

fn content_records(value: &Value, no_newline: bool) -> String {
    let records = match value {
        Value::Array(values) => values.iter().map(Value::as_string).collect::<Vec<_>>(),
        value => vec![value.as_string()],
    };
    let mut text = records.join("\r\n");
    if !no_newline {
        text.push_str("\r\n");
    }
    text
}

fn parse_encoding(value: Option<&str>, default: TextEncoding) -> TextEncoding {
    let value = value
        .unwrap_or_default()
        .trim_matches(['\'', '"'])
        .to_ascii_lowercase()
        .replace(['-', '_'], "");
    match value.as_str() {
        "ascii" | "default" | "oem" | "string" => TextEncoding::Ascii,
        "utf8" | "utf8bom" => TextEncoding::Utf8Bom,
        "utf8nobom" => TextEncoding::Utf8,
        "unicode" | "utf16" | "utf16le" | "littleendianunicode" => TextEncoding::Utf16Le,
        "bigendianunicode" | "utf16be" => TextEncoding::Utf16Be,
        "utf32" | "utf32le" => TextEncoding::Utf32Le,
        "bigendianutf32" | "utf32be" => TextEncoding::Utf32Be,
        _ => default,
    }
}

fn encode_text(text: &str, encoding: TextEncoding, include_preamble: bool) -> Vec<u8> {
    let (preamble, mut bytes): (&[u8], Vec<u8>) = match encoding {
        TextEncoding::Ascii => (
            &[],
            text.chars()
                .map(|character| {
                    if character.is_ascii() {
                        character as u8
                    } else {
                        b'?'
                    }
                })
                .collect(),
        ),
        TextEncoding::Utf8 => (&[], text.as_bytes().to_vec()),
        TextEncoding::Utf8Bom => (&[0xef, 0xbb, 0xbf], text.as_bytes().to_vec()),
        TextEncoding::Utf16Le => (&[0xff, 0xfe], encode_utf16_le(text)),
        TextEncoding::Utf16Be => (&[0xfe, 0xff], encode_utf16_be(text)),
        TextEncoding::Utf32Le => (&[0xff, 0xfe, 0x00, 0x00], encode_utf32_le(text)),
        TextEncoding::Utf32Be => (&[0x00, 0x00, 0xfe, 0xff], encode_utf32_be(text)),
    };
    if include_preamble && !preamble.is_empty() {
        let mut output = Vec::with_capacity(preamble.len() + bytes.len());
        output.extend_from_slice(preamble);
        output.append(&mut bytes);
        output
    } else {
        bytes
    }
}

fn decode_text(bytes: &[u8], encoding: Option<TextEncoding>) -> String {
    let (encoding, bytes) = encoding.map_or_else(
        || {
            if let Some(bytes) = bytes.strip_prefix(&[0xff, 0xfe, 0x00, 0x00]) {
                (TextEncoding::Utf32Le, bytes)
            } else if let Some(bytes) = bytes.strip_prefix(&[0x00, 0x00, 0xfe, 0xff]) {
                (TextEncoding::Utf32Be, bytes)
            } else if let Some(bytes) = bytes.strip_prefix(&[0xff, 0xfe]) {
                (TextEncoding::Utf16Le, bytes)
            } else if let Some(bytes) = bytes.strip_prefix(&[0xfe, 0xff]) {
                (TextEncoding::Utf16Be, bytes)
            } else if let Some(bytes) = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]) {
                (TextEncoding::Utf8, bytes)
            } else {
                (TextEncoding::Utf8, bytes)
            }
        },
        |encoding| {
            let bytes = match encoding {
                TextEncoding::Utf8 | TextEncoding::Utf8Bom => {
                    bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes)
                }
                TextEncoding::Utf16Le => bytes.strip_prefix(&[0xff, 0xfe]).unwrap_or(bytes),
                TextEncoding::Utf16Be => bytes.strip_prefix(&[0xfe, 0xff]).unwrap_or(bytes),
                TextEncoding::Utf32Le => bytes
                    .strip_prefix(&[0xff, 0xfe, 0x00, 0x00])
                    .unwrap_or(bytes),
                TextEncoding::Utf32Be => bytes
                    .strip_prefix(&[0x00, 0x00, 0xfe, 0xff])
                    .unwrap_or(bytes),
                TextEncoding::Ascii => bytes,
            };
            (encoding, bytes)
        },
    );
    match encoding {
        TextEncoding::Ascii => decode_ascii(bytes.to_vec()),
        TextEncoding::Utf8 | TextEncoding::Utf8Bom => decode_utf8(bytes),
        TextEncoding::Utf16Le => decode_utf16_le(bytes),
        TextEncoding::Utf16Be => decode_utf16_be(bytes),
        TextEncoding::Utf32Le => decode_utf32_le(bytes),
        TextEncoding::Utf32Be => decode_utf32_be(bytes),
    }
}

fn split_with_delimiter(text: &str, delimiter: &str) -> Vec<String> {
    if delimiter.is_empty() {
        return vec![text.to_owned()];
    }
    let mut records = Vec::new();
    let mut remainder = text;
    while let Some(index) = remainder.find(delimiter) {
        let end = index + delimiter.len();
        records.push(remainder[..end].to_owned());
        remainder = &remainder[end..];
    }
    if !remainder.is_empty() {
        records.push(remainder.to_owned());
    }
    records
}

fn numeric_argument(arguments: &[String], name: &str) -> Option<usize> {
    named_or_positional(arguments, &[name], usize::MAX)?
        .trim_matches(['\'', '"'])
        .parse()
        .ok()
}
