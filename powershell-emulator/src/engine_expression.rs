use super::{
    com, decode_ascii, decode_base64, decode_utf16_be, decode_utf16_le, decode_utf8, dotnet,
    encode_utf16_le, hex_decode, index_value, named_or_positional, normalize_variable, object_map,
    parse_number, parse_simple_xml, percent_decode, split_powershell_words, split_top_level,
    split_windows_command_line, transforms, Engine, Host, NetworkIntent, NumberLiteral,
    PowerShellEmulator, PowerShellError, Value,
};
use crate::ast::{Expression, ExpressionKind};
use crate::parser::ParsedSource;

fn static_member_default(
    type_name: &str,
    member: &str,
    host: &dyn Host,
    current_location: &str,
) -> Value {
    let type_name = type_name.trim_start_matches("System.").to_ascii_lowercase();
    match (type_name.as_str(), member.to_ascii_lowercase().as_str()) {
        ("net.servicepointmanager", "securityprotocol") => Value::String("Tls12".into()),
        ("ref", "assembly") => Value::Object("Assembly:System.Management.Automation".into()),
        ("environment", "machinename") => environment_value(host, "COMPUTERNAME"),
        ("environment", "username") => environment_value(host, "USERNAME"),
        ("environment", "userdomainname") => environment_value(host, "USERDOMAIN"),
        ("environment", "systemdirectory") => Value::String(format!(
            r"{}\System32",
            host.environment("SystemRoot").unwrap_or(r"C:\Windows")
        )),
        ("environment", "currentdirectory") => Value::String(current_location.into()),
        ("environment", "processorcount") => host
            .environment("NUMBER_OF_PROCESSORS")
            .and_then(|value| value.parse::<i64>().ok())
            .map_or(Value::Number(1), Value::Number),
        ("environment", "is64bitoperatingsystem" | "is64bitprocess" | "userinteractive") => {
            Value::Bool(true)
        }
        ("environment", "newline") => Value::String("\r\n".into()),
        ("environment", "osversion") => Value::Map(
            [
                ("Platform".into(), Value::String("Win32NT".into())),
                ("Version".into(), Value::String("10.0.26100.0".into())),
                (
                    "VersionString".into(),
                    Value::String("Microsoft Windows NT 10.0.26100.0".into()),
                ),
            ]
            .into_iter()
            .collect(),
        ),
        _ => Value::Object(format!("[{type_name}]::{member}")),
    }
}

fn environment_value(host: &dyn Host, name: &str) -> Value {
    host.environment(name)
        .map_or(Value::Null, |value| Value::String(value.into()))
}

impl PowerShellEmulator {
    pub(crate) fn eval_expression(
        &mut self,
        parser: &ParsedSource,
        expression: &str,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Value, PowerShellError> {
        let expression = expression.trim();
        if parser.window(expression).is_none() {
            let generated = ParsedSource::parse(expression)
                .map_err(|diagnostic| PowerShellError::Parser(diagnostic.to_string()))?;
            return self.eval_expression(&generated, generated.source(), host, depth);
        }
        let parsed = parser.expression(expression).ok_or_else(|| {
            PowerShellError::Evaluation(format!(
                "expression is outside parsed source: {expression}"
            ))
        })?;
        self.eval_parsed_expression(parser, &parsed, host, depth)
    }

    #[allow(clippy::too_many_lines)]
    fn eval_parsed_expression(
        &mut self,
        parser: &ParsedSource,
        expression: &Expression,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Value, PowerShellError> {
        host.consume_step(
            Engine::PowerShell,
            depth,
            "evaluating PowerShell expression",
        )?;
        let text = parser.text(expression.range);
        match &expression.kind {
            ExpressionKind::Empty | ExpressionKind::Null => Ok(Value::Null),
            ExpressionKind::Boolean(value) => Ok(Value::Bool(*value)),
            ExpressionKind::Number => Ok(match parse_number(text) {
                Some(NumberLiteral::Integer(value)) => Value::Number(value),
                Some(NumberLiteral::Float(value)) => Value::Float(value),
                None => Value::Null,
            }),
            ExpressionKind::Variable => Ok(self.variable_value(text, host)),
            ExpressionKind::String(kind) => {
                debug_assert!(matches!(
                    kind,
                    crate::tokenizer::StringKind::Literal
                        | crate::tokenizer::StringKind::Expandable
                ));
                Ok(Value::String(self.parse_string(parser, text, host, depth)?))
            }
            ExpressionKind::HereString(kind) => {
                debug_assert!(matches!(
                    kind,
                    crate::tokenizer::StringKind::Literal
                        | crate::tokenizer::StringKind::Expandable
                ));
                Ok(self
                    .parse_here_string(parser, text, host, depth)?
                    .map_or(Value::Null, Value::String))
            }
            ExpressionKind::Parenthesized(inner) => {
                let inner_text = parser.text(inner.range);
                if matches!(inner.kind, ExpressionKind::Bare)
                    && self.looks_like_command_expression(parser, inner_text)
                {
                    return Ok(self
                        .execute_statement(parser, inner_text, host, depth + 1)?
                        .unwrap_or(Value::Null));
                }
                self.eval_parsed_expression(parser, inner, host, depth)
            }
            ExpressionKind::Subexpression(range) => {
                let (result, mut output) =
                    self.execute_script_collect(parser, parser.text(*range), host, depth + 1)?;
                Ok(if output.is_empty() {
                    result.unwrap_or(Value::Null)
                } else if output.len() == 1 {
                    output.pop().unwrap_or(Value::Null)
                } else {
                    Value::Array(output)
                })
            }
            ExpressionKind::Array(values) => values
                .iter()
                .map(|value| self.eval_parsed_expression(parser, value, host, depth))
                .collect::<Result<Vec<_>, _>>()
                .map(Value::Array),
            ExpressionKind::Hashtable(entries) => {
                let mut values = std::collections::BTreeMap::new();
                for entry in entries {
                    values.insert(
                        entry.key.clone(),
                        self.eval_parsed_expression(parser, &entry.value, host, depth)?,
                    );
                }
                Ok(Value::Map(values))
            }
            ExpressionKind::ScriptBlock(range) => Ok(Value::Object(format!(
                "ScriptBlock:{}",
                parser.text(*range)
            ))),
            ExpressionKind::Cast { type_name, value } => {
                let value = self.eval_parsed_expression(parser, value, host, depth)?;
                Ok(Self::apply_ast_cast(type_name, value))
            }
            ExpressionKind::TypeLiteral(type_name) => {
                Ok(Value::Object(format!("Type:{type_name}")))
            }
            ExpressionKind::Unary { operator, value } => {
                let value = self.eval_parsed_expression(parser, value, host, depth)?;
                if operator.eq_ignore_ascii_case("-join") {
                    Ok(Value::String(match value {
                        Value::Array(values) => values.iter().map(Value::as_string).collect(),
                        other => other.as_string(),
                    }))
                } else {
                    Ok(Self::apply_unary(operator, value))
                }
            }
            ExpressionKind::Binary {
                left,
                operator,
                right,
            } => {
                let left = self.eval_parsed_expression(parser, left, host, depth)?;
                let right = self.eval_parsed_expression(parser, right, host, depth)?;
                Ok(self.apply_binary(left, operator, right, host, depth))
            }
            ExpressionKind::Index {
                value,
                index,
                null_conditional,
            } => {
                let value = self.eval_parsed_expression(parser, value, host, depth)?;
                if *null_conditional && matches!(value, Value::Null) {
                    return Ok(Value::Null);
                }
                let index = self.eval_parsed_expression(parser, index, host, depth)?;
                Ok(index_value(value, index))
            }
            ExpressionKind::StaticMember { type_name, member } => {
                let type_name = parser.text(*type_name);
                let member = parser.text(*member);
                let key = format!("__static:{}", type_name.to_ascii_lowercase());
                if let Some(Value::Map(properties)) = self.variables.get(&key) {
                    if let Some(value) = properties
                        .iter()
                        .find(|(name, _)| name.eq_ignore_ascii_case(member))
                        .map(|(_, value)| value.clone())
                    {
                        return Ok(value);
                    }
                }
                Ok(static_member_default(
                    type_name,
                    member,
                    host,
                    &self.current_location,
                ))
            }
            ExpressionKind::StaticCall {
                type_name,
                method,
                arguments,
            } => {
                let type_name = parser.text(*type_name);
                let method_text = parser.text(*method);
                let method = if matches!(
                    parser
                        .expression(method_text)
                        .as_deref()
                        .map(|expression| &expression.kind),
                    Some(ExpressionKind::Variable)
                ) {
                    self.eval_expression(parser, method_text, host, depth)?
                        .as_string()
                } else {
                    method_text.into()
                };
                let arguments = self.eval_ast_arguments(parser, arguments, host, depth)?;
                self.eval_static_call_values(type_name, &method, &arguments, host, depth)
            }
            ExpressionKind::InstanceCall {
                receiver,
                method,
                arguments,
                null_conditional,
            } => {
                let receiver_text = parser.text(receiver.range);
                let receiver_value = self.eval_parsed_expression(parser, receiver, host, depth)?;
                if *null_conditional && matches!(receiver_value, Value::Null) {
                    return Ok(Value::Null);
                }
                let method_text = parser.text(*method);
                let method = if matches!(
                    parser
                        .expression(method_text)
                        .as_deref()
                        .map(|expression| &expression.kind),
                    Some(ExpressionKind::Variable)
                ) {
                    self.eval_expression(parser, method_text, host, depth)?
                        .as_string()
                } else {
                    method_text.into()
                };
                let arguments = self.eval_ast_arguments(parser, arguments, host, depth)?;
                self.eval_instance_call_values(
                    receiver_text,
                    receiver_value,
                    &method,
                    &arguments,
                    host,
                    depth,
                )
            }
            ExpressionKind::Member {
                receiver,
                member,
                null_conditional,
            } => {
                let receiver = self.eval_parsed_expression(parser, receiver, host, depth)?;
                if *null_conditional && matches!(receiver, Value::Null) {
                    return Ok(Value::Null);
                }
                Ok(Self::read_member(receiver, parser.text(*member)))
            }
            ExpressionKind::NewObject { arguments } => {
                self.eval_new_object_spans(parser, arguments, host, depth)
            }
            ExpressionKind::Bare => Ok(Value::String(self.interpolate(parser, text, host, depth)?)),
        }
    }

    fn variable_value(&self, expression: &str, host: &dyn Host) -> Value {
        if let Some(name) = expression
            .strip_prefix("$env:")
            .or_else(|| expression.strip_prefix("$ENV:"))
        {
            return environment_value(host, name);
        }
        let name = normalize_variable(expression);
        self.variables
            .get(&name)
            .cloned()
            .unwrap_or_else(|| match name.as_str() {
                "home" => environment_value(host, "userprofile"),
                "shellid" => Value::String("Microsoft.PowerShell".into()),
                "host" => Value::Object("ConsoleHost".into()),
                "lastexitcode" => Value::Number(0),
                "?" => Value::Bool(true),
                _ => Value::Null,
            })
    }

    fn apply_ast_cast(type_name: &str, value: Value) -> Value {
        match type_name.to_ascii_lowercase().as_str() {
            "char" => value
                .as_i64()
                .and_then(|value| u32::try_from(value).ok())
                .and_then(char::from_u32)
                .map_or(Value::Null, |character| {
                    Value::String(character.to_string())
                }),
            "char[]" => Value::Array(
                value
                    .as_string()
                    .chars()
                    .map(|character| Value::String(character.to_string()))
                    .collect(),
            ),
            "byte[]" => Value::Bytes(value.as_bytes()),
            "int" | "int32" | "int64" | "long" => value.as_i64().map_or(Value::Null, Value::Number),
            "string" => Value::String(value.as_string()),
            "xml" => parse_simple_xml(&value.as_string()),
            "regex" => Value::Object(format!("Regex:{}", value.as_string())),
            "type" => Value::Object(format!("Type:{}", value.as_string())),
            _ => value,
        }
    }

    fn eval_ast_arguments(
        &mut self,
        parser: &ParsedSource,
        arguments: &[Expression],
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Vec<Value>, PowerShellError> {
        arguments
            .iter()
            .map(|argument| self.eval_parsed_expression(parser, argument, host, depth))
            .collect()
    }

    pub(crate) fn eval_statement_or_expression(
        &mut self,
        parser: &ParsedSource,
        input: &str,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Value, PowerShellError> {
        if split_top_level(parser, input, '|').len() > 1
            || self.looks_like_command_expression(parser, input)
        {
            return Ok(self
                .execute_statement(parser, input, host, depth)?
                .unwrap_or(Value::Null));
        }
        self.eval_expression(parser, input, host, depth)
    }

    pub(crate) fn eval_new_object(
        &mut self,
        parser: &ParsedSource,
        expression: &str,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Value, PowerShellError> {
        let words = split_powershell_words(parser, expression);
        self.eval_new_object_arguments(parser, words.get(1..).unwrap_or_default(), host, depth)
    }

    fn eval_new_object_spans(
        &mut self,
        parser: &ParsedSource,
        arguments: &[crate::tokenizer::Span],
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Value, PowerShellError> {
        let words = arguments
            .iter()
            .map(|range| crate::syntax::clean_line_continuations(parser.text(*range)))
            .collect::<Vec<_>>();
        let _bindings = words
            .iter()
            .zip(arguments.iter().copied())
            .map(|(word, range)| parser.bind_external(word, range))
            .collect::<Vec<_>>();
        self.eval_new_object_arguments(parser, &words, host, depth)
    }

    fn eval_new_object_arguments(
        &mut self,
        parser: &ParsedSource,
        arguments: &[String],
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Value, PowerShellError> {
        if let Some(prog_id) = named_or_positional(arguments, &["-comobject"], usize::MAX) {
            let prog_id = if prog_id.starts_with(['$', '\'', '"', '(']) {
                self.eval_expression(parser, prog_id, host, depth)?
                    .as_string()
            } else {
                prog_id.trim_matches(['\'', '"']).into()
            };
            return Ok(Self::create_com_object(&prog_id));
        }
        let type_name =
            named_or_positional(arguments, &["-typename", "-type"], 0).unwrap_or_default();
        let normalized = type_name
            .trim_matches(['\'', '"'])
            .trim_start_matches("System.")
            .to_ascii_lowercase();
        let argument = named_or_positional(arguments, &["-argumentlist"], 1);
        match normalized.as_str() {
            "io.memorystream" => {
                let data = if let Some(argument) = argument {
                    self.eval_expression(parser, argument.trim_start_matches(','), host, depth)?
                        .as_bytes()
                } else {
                    Vec::new()
                };
                Ok(object_map("MemoryStream", Value::Bytes(data)))
            }
            "io.streamreader" => {
                let data = if let Some(argument) = argument {
                    self.eval_expression(parser, argument, host, depth)?
                } else {
                    Value::Null
                };
                Ok(object_map("StreamReader", data))
            }
            "io.compression.gzipstream"
            | "io.compression.deflatestream"
            | "io.compression.zlibstream" => {
                let data = argument
                    .map(|argument| self.eval_expression(parser, argument, host, depth))
                    .transpose()?
                    .unwrap_or(Value::Null);
                let bytes = match data {
                    Value::Map(stream) => stream.get("data").map_or_else(Vec::new, Value::as_bytes),
                    value => value.as_bytes(),
                };
                let decompressed = if normalized.contains("gzip") {
                    transforms::gzip_decompress(&bytes).unwrap_or(bytes)
                } else {
                    transforms::zlib_decompress(&bytes).unwrap_or(bytes)
                };
                Ok(object_map("CompressionStream", Value::Bytes(decompressed)))
            }
            "net.webclient" | "system.net.webclient" => Ok(Value::Object("WebClient".into())),
            "random" | "system.random" => Ok(Value::Object("Random".into())),
            _ => Ok(Value::Object(type_name.into())),
        }
    }

    #[allow(clippy::too_many_lines)]
    pub(crate) fn looks_like_command_expression(
        &self,
        parser: &ParsedSource,
        expression: &str,
    ) -> bool {
        let words = split_powershell_words(parser, expression);
        let Some(command) = words.first() else {
            return false;
        };
        let command = self.resolve_command_name(command.trim_matches(['\'', '"']));
        matches!(
            command.as_str(),
            "echo"
                | "write-output"
                | "write-host"
                | "invoke-expression"
                | "iex"
                | "invoke-webrequest"
                | "iwr"
                | "invoke-restmethod"
                | "irm"
                | "get-content"
                | "gc"
                | "cat"
                | "type"
                | "new-object"
                | "start-process"
                | "get-item"
                | "gi"
                | "set-item"
                | "si"
                | "remove-item"
                | "ri"
                | "get-itemproperty"
                | "get-itempropertyvalue"
                | "gp"
                | "set-itemproperty"
                | "sp"
                | "remove-itemproperty"
                | "rp"
                | "get-childitem"
                | "gci"
                | "dir"
                | "ls"
                | "clear-content"
                | "clc"
                | "new-temporaryfile"
                | "invoke-item"
                | "ii"
                | "get-location"
                | "pwd"
                | "gl"
                | "set-location"
                | "cd"
                | "chdir"
                | "sl"
                | "push-location"
                | "pushd"
                | "pop-location"
                | "popd"
                | "new-item"
                | "ni"
                | "mkdir"
                | "md"
                | "unblock-file"
                | "get-authenticodesignature"
                | "convertfrom-json"
                | "convertto-json"
                | "convertfrom-csv"
                | "convertto-csv"
                | "import-csv"
                | "convertfrom-stringdata"
                | "select-string"
                | "sls"
                | "sort-object"
                | "sort"
                | "group-object"
                | "group"
                | "tee-object"
                | "tee"
                | "compare-object"
                | "compare"
                | "diff"
                | "get-unique"
                | "gu"
                | "format-hex"
                | "fhx"
                | "get-computerinfo"
                | "get-service"
                | "get-hotfix"
                | "get-netipaddress"
                | "get-netadapter"
                | "get-nettcpconnection"
                | "resolve-dnsname"
                | "test-netconnection"
                | "tnc"
                | "get-localuser"
                | "get-localgroupmember"
                | "get-psdrive"
                | "get-ciminstance"
                | "get-wmiobject"
                | "get-mppreference"
                | "get-mpcomputerstatus"
                | "get-executionpolicy"
                | "get-scheduledtask"
        ) || Self::is_bits_command(&command)
            || self.functions.contains_key(&command)
    }

    fn is_bits_command(command: &str) -> bool {
        matches!(
            command,
            "start-bitstransfer"
                | "get-bitstransfer"
                | "complete-bitstransfer"
                | "remove-bitstransfer"
                | "suspend-bitstransfer"
                | "resume-bitstransfer"
        )
    }

    #[allow(clippy::too_many_lines, clippy::unused_self)]
    pub(crate) fn eval_static_call_values(
        &mut self,
        type_name: &str,
        method: &str,
        args: &[Value],
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Value, PowerShellError> {
        let normalized_type = type_name
            .replace("system.", "")
            .replace("System.", "")
            .to_ascii_lowercase();
        let normalized_method = method.to_ascii_lowercase();
        if let dotnet::DotNetDispatch::Handled(value) =
            Self::eval_extended_static_call(type_name, method, args, host, depth)?
        {
            return Ok(value);
        }

        match (normalized_type.as_str(), normalized_method.as_str()) {
            ("convert", "frombase64string") => {
                let input = args.first().map_or_else(String::new, Value::as_string);
                match decode_base64(&input) {
                    Ok(bytes) => {
                        Self::record_decode("base64", &bytes, host, depth);
                        Ok(Value::Bytes(bytes))
                    }
                    Err(error) => Err(PowerShellError::Evaluation(format!(
                        "invalid base64 input: {error}"
                    ))),
                }
            }
            ("convert", "fromhexstring") => {
                let input = args.first().map_or_else(String::new, Value::as_string);
                let bytes = hex_decode(&input).ok_or_else(|| {
                    PowerShellError::Evaluation("invalid hexadecimal input".into())
                })?;
                Self::record_decode("hex", &bytes, host, depth);
                Ok(Value::Bytes(bytes))
            }
            ("text.encoding" | "text.encoding.utf8", "utf8.getstring" | "getstring")
            | ("text.utf8encoding", "getstring") => {
                let bytes = args.first().map_or_else(Vec::new, Value::as_bytes);
                Ok(Value::String(decode_utf8(&bytes)))
            }
            ("text.encoding", "unicode.getstring") | ("text.unicodeencoding", "getstring") => {
                let bytes = args.first().map_or_else(Vec::new, Value::as_bytes);
                Ok(Value::String(decode_utf16_le(&bytes)))
            }
            ("text.encoding", "bigendianunicode.getstring") => {
                let bytes = args.first().map_or_else(Vec::new, Value::as_bytes);
                Ok(Value::String(decode_utf16_be(&bytes)))
            }
            ("text.encoding", "ascii.getstring") => {
                let bytes = args.first().map_or_else(Vec::new, Value::as_bytes);
                Ok(Value::String(decode_ascii(bytes)))
            }
            ("text.encoding" | "text.encoding.utf8", "utf8.getbytes" | "getbytes") => Ok(
                Value::Bytes(args.first().map_or_else(Vec::new, Value::as_bytes)),
            ),
            ("text.encoding", "unicode.getbytes") => {
                let text = args.first().map_or_else(String::new, Value::as_string);
                Ok(Value::Bytes(encode_utf16_le(&text)))
            }
            ("uri", "unescapedatastring") | ("net.webutility", "urldecode") => {
                let text = args.first().map_or_else(String::new, Value::as_string);
                Ok(Value::String(percent_decode(&text)))
            }
            ("io.file", "readalltext") => {
                let path = args.first().map_or_else(String::new, Value::as_string);
                Ok(host
                    .read_file(&path, Engine::PowerShell, depth)
                    .map_or(Value::Null, |bytes| Value::String(decode_utf8(&bytes))))
            }
            ("io.file", "readallbytes") => {
                let path = args.first().map_or_else(String::new, Value::as_string);
                Ok(host
                    .read_file(&path, Engine::PowerShell, depth)
                    .map_or(Value::Null, Value::Bytes))
            }
            ("io.file", "writealltext") => {
                let path = args.first().map_or_else(String::new, Value::as_string);
                let bytes = args.get(1).map_or_else(Vec::new, Value::as_bytes);
                host.write_file(&path, &bytes, false, Engine::PowerShell, depth)?;
                Ok(Value::Null)
            }
            ("io.file", "writeallbytes") => {
                let path = args.first().map_or_else(String::new, Value::as_string);
                let bytes = args.get(1).map_or_else(Vec::new, Value::as_bytes);
                host.write_file(&path, &bytes, false, Engine::PowerShell, depth)?;
                Ok(Value::Null)
            }
            ("diagnostics.process", "start") => {
                let program = args.first().map_or_else(String::new, Value::as_string);
                let command_args = args.get(1).map_or_else(Vec::new, |value| {
                    split_windows_command_line(&value.as_string())
                });
                Ok(
                    match Self::request_process(
                        &program,
                        command_args,
                        "PowerShell Process.Start",
                        host,
                        depth,
                    )? {
                        Some(result) => self.process_result_object(&result, host, depth),
                        None => Value::Object("BlockedProcess".into()),
                    },
                )
            }
            _ => {
                host.unsupported(
                    Engine::PowerShell,
                    depth,
                    &format!("unsupported modeled .NET call [{type_name}]::{method}"),
                );
                Ok(Value::Object(format!("[{type_name}]::{method}")))
            }
        }
    }

    #[allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
    pub(crate) fn eval_instance_call_values(
        &mut self,
        receiver_expression: &str,
        receiver: Value,
        method: &str,
        args: &[Value],
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Value, PowerShellError> {
        if let com::ComDispatch::Handled(value) =
            self.eval_com_instance_call(receiver_expression, &receiver, method, args, host, depth)?
        {
            return Ok(value);
        }
        if let dotnet::DotNetDispatch::Handled(value) = self.eval_extended_instance_call(
            receiver_expression,
            &receiver,
            method,
            args,
            host,
            depth,
        )? {
            return Ok(value);
        }
        let normalized_method = method.to_ascii_lowercase();
        match (&receiver, normalized_method.as_str()) {
            (Value::String(value), "replace") => {
                let from = args.first().map_or_else(String::new, Value::as_string);
                let to = args.get(1).map_or_else(String::new, Value::as_string);
                Ok(Value::String(value.replace(&from, &to)))
            }
            (Value::String(value), "tolower" | "tolowerinvariant") => {
                Ok(Value::String(value.to_ascii_lowercase()))
            }
            (Value::String(value), "toupper" | "toupperinvariant") => {
                Ok(Value::String(value.to_ascii_uppercase()))
            }
            (Value::String(value), "trim") => Ok(Value::String(value.trim().into())),
            (Value::String(value), "split") => {
                let separator = args.first().map_or_else(String::new, Value::as_string);
                Ok(Value::Array(
                    value
                        .split(&separator)
                        .map(|part| Value::String(part.into()))
                        .collect(),
                ))
            }
            (Value::Object(type_name), "downloadstring")
                if type_name.to_ascii_lowercase().contains("webclient") =>
            {
                let url = args.first().map_or_else(String::new, Value::as_string);
                let response = host.network_request(NetworkIntent {
                    method: "GET".into(),
                    url,
                    origin: "PowerShell WebClient.DownloadString".into(),
                    depth,
                });
                Ok(response.map_or_else(
                    || Value::Object("BlockedNetworkResponse".into()),
                    |response| Value::String(decode_utf8(&response.body)),
                ))
            }
            (Value::Object(type_name), "downloaddata")
                if type_name.to_ascii_lowercase().contains("webclient") =>
            {
                let url = args.first().map_or_else(String::new, Value::as_string);
                let response = host.network_request(NetworkIntent {
                    method: "GET".into(),
                    url,
                    origin: "PowerShell WebClient.DownloadData".into(),
                    depth,
                });
                Ok(response.map_or_else(
                    || Value::Object("BlockedNetworkResponse".into()),
                    |response| Value::Bytes(response.body),
                ))
            }
            (Value::Object(type_name), "downloadfile")
                if type_name.to_ascii_lowercase().contains("webclient") =>
            {
                let url = args.first().map_or_else(String::new, Value::as_string);
                let response = host.network_request(NetworkIntent {
                    method: "GET".into(),
                    url,
                    origin: "PowerShell WebClient.DownloadFile".into(),
                    depth,
                });
                if let (Some(response), Some(path)) = (response, args.get(1)) {
                    host.write_file(
                        &path.as_string(),
                        &response.body,
                        false,
                        Engine::PowerShell,
                        depth,
                    )?;
                } else {
                    host.unsupported(
                        Engine::PowerShell,
                        depth,
                        "network response is unavailable; DownloadFile destination was not created",
                    );
                }
                Ok(Value::Null)
            }
            (Value::Object(type_name), "uploadstring" | "uploaddata")
                if type_name.to_ascii_lowercase().contains("webclient") =>
            {
                let url = args.first().map_or_else(String::new, Value::as_string);
                let response = host.network_request(NetworkIntent {
                    method: "POST".into(),
                    url,
                    origin: format!("PowerShell WebClient.{method}"),
                    depth,
                });
                Ok(response.map_or_else(
                    || Value::Object("BlockedNetworkResponse".into()),
                    |response| {
                        if normalized_method == "uploadstring" {
                            Value::String(decode_utf8(&response.body))
                        } else {
                            Value::Bytes(response.body)
                        }
                    },
                ))
            }
            (_, "tostring") => Ok(Value::String(receiver.as_string())),
            _ => {
                host.unsupported(
                    Engine::PowerShell,
                    depth,
                    &format!(
                        "unsupported instance method {}.{}",
                        receiver.as_string(),
                        method
                    ),
                );
                Ok(Value::Null)
            }
        }
    }
}
