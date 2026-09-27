use super::{
    com, decode_ascii, decode_base64, decode_utf16_be, decode_utf16_le, decode_utf8, dotnet,
    encode_utf16_le, extract_delimited, find_top_level_binary, hex_decode, index_value, is_quoted,
    is_variable, named_or_positional, normalize_variable, object_map, parse_instance_call,
    parse_member_access, parse_number, parse_simple_xml, parse_static_call,
    parse_static_member_access, percent_decode, split_index_expression, split_key_value,
    split_powershell_words, split_statements, split_top_level, split_windows_command_line,
    starts_word, strip_balanced_outer, strip_prefix_case_insensitive, transforms, Engine, Host,
    NetworkIntent, NumberLiteral, PowerShellEmulator, PowerShellError, TokenKind, Value,
};
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

fn is_cast_operand(rest: &str) -> bool {
    let rest = rest.trim_start();
    !rest.is_empty() && !rest.starts_with('.') && !rest.starts_with("::")
}

impl PowerShellEmulator {
    #[allow(clippy::too_many_lines)]
    pub(crate) fn eval_expression(
        &mut self,
        parser: &ParsedSource,
        expression: &str,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Value, PowerShellError> {
        host.consume_step(
            Engine::PowerShell,
            depth,
            "evaluating PowerShell expression",
        )?;
        let expression = expression.trim();
        if expression.is_empty() {
            return Ok(Value::Null);
        }
        if parser.window(expression).is_none() {
            let generated = ParsedSource::parse(expression)
                .map_err(|diagnostic| PowerShellError::Parser(diagnostic.to_string()))?;
            return self.eval_expression(&generated, generated.source(), host, depth);
        }
        if let Some(inner) = strip_balanced_outer(parser, expression, '(', ')') {
            if self.looks_like_command_expression(parser, inner) {
                return Ok(self
                    .execute_statement(parser, inner, host, depth + 1)?
                    .unwrap_or(Value::Null));
            }
            return self.eval_expression(parser, inner, host, depth);
        }
        if let Some(inner) = expression
            .strip_prefix("$(")
            .and_then(|value| value.strip_suffix(')'))
        {
            let (result, mut output) =
                self.execute_script_collect(parser, inner, host, depth + 1)?;
            return Ok(if output.is_empty() {
                result.unwrap_or(Value::Null)
            } else if output.len() == 1 {
                output.pop().unwrap_or(Value::Null)
            } else {
                Value::Array(output)
            });
        }
        if expression.eq_ignore_ascii_case("$true") {
            return Ok(Value::Bool(true));
        }
        if expression.eq_ignore_ascii_case("$false") {
            return Ok(Value::Bool(false));
        }
        if expression.eq_ignore_ascii_case("$null") {
            return Ok(Value::Null);
        }
        if let Some(name) = expression.strip_prefix("$env:") {
            return Ok(host
                .environment(name)
                .map_or(Value::Null, |value| Value::String(value.into())));
        }
        if is_variable(parser, expression) {
            let name = normalize_variable(expression);
            if let Some(value) = self.variables.get(&name).cloned() {
                return Ok(value);
            }
            let automatic = match name.as_str() {
                "home" => host
                    .environment("userprofile")
                    .map_or(Value::Null, |value| Value::String(value.into())),
                "shellid" => Value::String("Microsoft.PowerShell".into()),
                "host" => Value::Object("ConsoleHost".into()),
                "lastexitcode" => Value::Number(0),
                "?" => Value::Bool(true),
                _ => Value::Null,
            };
            return Ok(automatic);
        }
        if is_quoted(parser, expression) {
            return Ok(Value::String(
                self.parse_string(parser, expression, host, depth)?,
            ));
        }
        if let Some(value) = self.parse_here_string(parser, expression, host, depth)? {
            return Ok(Value::String(value));
        }
        if let Some(number) = parse_number(expression) {
            return Ok(match number {
                NumberLiteral::Integer(value) => Value::Number(value),
                NumberLiteral::Float(value) => Value::Float(value),
            });
        }
        if let Some(inner) = expression
            .strip_prefix("@(")
            .and_then(|value| value.strip_suffix(')'))
        {
            return self.eval_array(parser, inner, host, depth);
        }
        if let Some((body, remainder)) = extract_delimited(parser, expression, '{', '}') {
            if remainder.trim().is_empty() {
                return Ok(Value::Object(format!("ScriptBlock:{body}")));
            }
        }
        if expression.starts_with("@{") && expression.ends_with('}') {
            return self.eval_hashtable(parser, &expression[2..expression.len() - 1], host, depth);
        }
        if let Some(rest) = strip_prefix_case_insensitive(expression, "[char]") {
            if is_cast_operand(rest) {
                let value = self.eval_expression(parser, rest, host, depth)?;
                let number = value.as_i64().and_then(|value| u32::try_from(value).ok());
                return Ok(number
                    .and_then(char::from_u32)
                    .map_or(Value::Null, |character| {
                        Value::String(character.to_string())
                    }));
            }
        }
        if let Some(rest) = strip_prefix_case_insensitive(expression, "[char[]]") {
            if is_cast_operand(rest) {
                let value = self.eval_expression(parser, rest, host, depth)?;
                return Ok(Value::Array(
                    value
                        .as_string()
                        .chars()
                        .map(|character| Value::String(character.to_string()))
                        .collect(),
                ));
            }
        }
        if let Some(rest) = strip_prefix_case_insensitive(expression, "[byte[]]") {
            if is_cast_operand(rest) {
                return Ok(Value::Bytes(
                    self.eval_expression(parser, rest, host, depth)?.as_bytes(),
                ));
            }
        }
        if let Some(rest) = ["[int]", "[int32]", "[int64]", "[long]"]
            .iter()
            .find_map(|type_name| strip_prefix_case_insensitive(expression, type_name))
        {
            if is_cast_operand(rest) {
                let value = self.eval_expression(parser, rest, host, depth)?;
                return Ok(value.as_i64().map_or(Value::Null, Value::Number));
            }
        }
        if let Some(rest) = strip_prefix_case_insensitive(expression, "[string]") {
            if is_cast_operand(rest) {
                return Ok(Value::String(
                    self.eval_expression(parser, rest, host, depth)?.as_string(),
                ));
            }
        }
        if let Some(rest) = strip_prefix_case_insensitive(expression, "[pscustomobject]") {
            return self.eval_expression(parser, rest, host, depth);
        }
        if let Some(rest) = strip_prefix_case_insensitive(expression, "[xml]") {
            let xml = self.eval_expression(parser, rest, host, depth)?.as_string();
            return Ok(parse_simple_xml(&xml));
        }
        if let Some(rest) = strip_prefix_case_insensitive(expression, "[regex]") {
            if !rest.trim_start().starts_with("::") {
                let pattern = self.eval_expression(parser, rest, host, depth)?.as_string();
                return Ok(Value::Object(format!("Regex:{pattern}")));
            }
        }
        if let Some(rest) = strip_prefix_case_insensitive(expression, "[type]") {
            if !rest.trim_start().starts_with("::") {
                let type_name = self.eval_expression(parser, rest, host, depth)?.as_string();
                return Ok(Value::Object(format!("Type:{type_name}")));
            }
        }
        if expression.starts_with('[') && expression.ends_with(']') {
            return Ok(Value::Object(format!(
                "Type:{}",
                expression[1..expression.len() - 1].trim()
            )));
        }
        if let Some(rest) = strip_prefix_case_insensitive(expression, "-join") {
            let value = self.eval_expression(parser, rest, host, depth)?;
            return Ok(Value::String(match value {
                Value::Array(values) => values.iter().map(Value::as_string).collect(),
                other => other.as_string(),
            }));
        }
        for operators in [
            &["-or"][..],
            &["-xor"][..],
            &["-and"][..],
            &[
                "-eq",
                "-ieq",
                "-ceq",
                "-ne",
                "-ine",
                "-cne",
                "-lt",
                "-le",
                "-gt",
                "-ge",
                "-ilt",
                "-ile",
                "-igt",
                "-ige",
                "-clt",
                "-cle",
                "-cgt",
                "-cge",
                "-like",
                "-ilike",
                "-clike",
                "-notlike",
                "-inotlike",
                "-cnotlike",
                "-match",
                "-imatch",
                "-cmatch",
                "-notmatch",
                "-inotmatch",
                "-cnotmatch",
                "-contains",
                "-icontains",
                "-ccontains",
                "-notcontains",
                "-inotcontains",
                "-cnotcontains",
                "-in",
                "-notin",
                "-is",
                "-isnot",
            ][..],
            &["-bor"][..],
            &["-bxor"][..],
            &["-band"][..],
            &["-shl", "-shr"][..],
            &[
                "-replace",
                "-ireplace",
                "-creplace",
                "-split",
                "-isplit",
                "-csplit",
                "-join",
                "-f",
            ][..],
            &["+", "-"][..],
            &["*", "/", "%"][..],
            &[".."][..],
        ] {
            if let Some((left, operator, right)) =
                find_top_level_binary(parser, expression, operators)
            {
                let left_value = self.eval_expression(parser, left, host, depth)?;
                let right_value = self.eval_expression(parser, right, host, depth)?;
                return Ok(self.apply_binary(left_value, operator, right_value, host, depth));
            }
        }
        for unary in ["-not", "!", "-bnot", "-", "+"] {
            if let Some(rest) = strip_prefix_case_insensitive(expression, unary) {
                if !rest.trim().is_empty() {
                    let value = self.eval_expression(parser, rest, host, depth)?;
                    return Ok(Self::apply_unary(unary, value));
                }
            }
        }
        if let Some((base, index)) = split_index_expression(parser, expression) {
            let base = self.eval_expression(parser, base, host, depth)?;
            let index = self.eval_expression(parser, index, host, depth)?;
            return Ok(index_value(base, index));
        }
        if let Some((type_name, method, arguments)) = parse_static_call(parser, expression) {
            let method = if is_variable(parser, &method) {
                self.eval_expression(parser, &method, host, depth)?
                    .as_string()
            } else {
                method
            };
            return self.eval_static_call(parser, &type_name, &method, &arguments, host, depth);
        }
        if let Some((type_name, member)) = parse_static_member_access(expression) {
            let key = format!("__static:{}", type_name.to_ascii_lowercase());
            if let Some(Value::Map(properties)) = self.variables.get(&key) {
                if let Some(value) = properties
                    .iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case(&member))
                    .map(|(_, value)| value.clone())
                {
                    return Ok(value);
                }
            }
            return Ok(static_member_default(
                &type_name,
                &member,
                host,
                &self.current_location,
            ));
        }
        if let Some((receiver, method, arguments)) = parse_instance_call(parser, expression) {
            let method = if is_variable(parser, &method) {
                self.eval_expression(parser, &method, host, depth)?
                    .as_string()
            } else {
                method
            };
            return self.eval_instance_call(parser, receiver, &method, &arguments, host, depth);
        }
        if let Some((receiver, member)) = parse_member_access(parser, expression) {
            let receiver = self.eval_expression(parser, receiver, host, depth)?;
            return Ok(Self::read_member(receiver, member));
        }
        if starts_word(expression, "new-object") {
            return self.eval_new_object(parser, expression, host, depth);
        }
        let comma_values = split_top_level(parser, expression, ',');
        if comma_values.len() > 1 {
            return self.eval_array(parser, expression, host, depth);
        }

        Ok(Value::String(
            self.interpolate(parser, expression, host, depth)?,
        ))
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
        let arguments = words.get(1..).unwrap_or_default();
        if let Some(prog_id) = named_or_positional(arguments, &["-comobject"], usize::MAX) {
            let prog_id = if prog_id.starts_with(['$', '\'', '"', '(']) {
                self.eval_expression(parser, &prog_id, host, depth)?
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
                    self.eval_expression(parser, &argument, host, depth)?
                } else {
                    Value::Null
                };
                Ok(object_map("StreamReader", data))
            }
            "io.compression.gzipstream"
            | "io.compression.deflatestream"
            | "io.compression.zlibstream" => {
                let data = argument
                    .as_deref()
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
            _ => Ok(Value::Object(type_name)),
        }
    }

    pub(crate) fn eval_array(
        &mut self,
        parser: &ParsedSource,
        expression: &str,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Value, PowerShellError> {
        split_top_level(parser, expression, ',')
            .into_iter()
            .filter(|item| !item.trim().is_empty())
            .map(|item| self.eval_expression(parser, item.trim(), host, depth))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array)
    }

    pub(crate) fn eval_hashtable(
        &mut self,
        parser: &ParsedSource,
        expression: &str,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Value, PowerShellError> {
        let mut values = std::collections::BTreeMap::new();
        for statement in split_statements(parser, expression) {
            for entry in split_top_level(parser, statement, ',') {
                let Some((key, value)) = split_key_value(parser, entry) else {
                    continue;
                };
                let key = key.trim().trim_matches(['\'', '"']).to_string();
                values.insert(key, self.eval_expression(parser, value, host, depth)?);
            }
        }
        Ok(Value::Map(values))
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

    pub(crate) fn looks_like_value_expression(parser: &ParsedSource, expression: &str) -> bool {
        let words = split_powershell_words(parser, expression);
        if words.len() > 1 {
            let first = parser
                .window(expression)
                .into_iter()
                .flat_map(|window| window.tokens().iter().copied())
                .find(|token| !token.kind.is_trivia() && token.kind != TokenKind::NewLine);
            if first.is_some_and(|token| {
                matches!(token.kind, TokenKind::Identifier | TokenKind::Keyword)
            }) {
                return false;
            }
        }
        if is_quoted(parser, expression)
            || is_variable(parser, expression)
            || parse_number(expression).is_some()
            || split_top_level(parser, expression, ',').len() > 1
            || matches!(expression.chars().next(), Some('[' | '@' | '!' | '+' | '-'))
        {
            return true;
        }
        [
            "-or",
            "-xor",
            "-and",
            "-eq",
            "-ne",
            "-lt",
            "-le",
            "-gt",
            "-ge",
            "-like",
            "-match",
            "-contains",
            "-in",
            "-replace",
            "-split",
            "-join",
            "-f",
            "-band",
            "-bor",
            "-bxor",
            "-shl",
            "-shr",
            "+",
            "-",
            "*",
            "/",
            "%",
            "..",
        ]
        .iter()
        .any(|operator| find_top_level_binary(parser, expression, &[*operator]).is_some())
    }

    #[allow(clippy::too_many_lines)]
    pub(crate) fn eval_static_call(
        &mut self,
        parser: &ParsedSource,
        type_name: &str,
        method: &str,
        arguments: &str,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Value, PowerShellError> {
        let normalized_type = type_name
            .replace("system.", "")
            .replace("System.", "")
            .to_ascii_lowercase();
        let normalized_method = method.to_ascii_lowercase();
        let args = self.eval_call_arguments(parser, arguments, host, depth)?;
        if let dotnet::DotNetDispatch::Handled(value) =
            Self::eval_extended_static_call(type_name, method, &args, host, depth)?
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
                Self::spawn(
                    &program,
                    command_args,
                    "PowerShell Process.Start",
                    host,
                    depth,
                )?;
                Ok(Value::Object("BlockedProcess".into()))
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

    #[allow(clippy::too_many_lines)]
    pub(crate) fn eval_instance_call(
        &mut self,
        parser: &ParsedSource,
        receiver_expression: &str,
        method: &str,
        arguments: &str,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Value, PowerShellError> {
        let receiver = self.eval_expression(parser, receiver_expression, host, depth)?;
        let args = self.eval_call_arguments(parser, arguments, host, depth)?;
        if let com::ComDispatch::Handled(value) =
            self.eval_com_instance_call(receiver_expression, &receiver, method, &args, host, depth)?
        {
            return Ok(value);
        }
        if let dotnet::DotNetDispatch::Handled(value) = self.eval_extended_instance_call(
            receiver_expression,
            &receiver,
            method,
            &args,
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

    pub(crate) fn eval_call_arguments(
        &mut self,
        parser: &ParsedSource,
        arguments: &str,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Vec<Value>, PowerShellError> {
        split_top_level(parser, arguments, ',')
            .into_iter()
            .filter(|argument| !argument.trim().is_empty())
            .map(|argument| self.eval_expression(parser, argument.trim(), host, depth))
            .collect()
    }
}
