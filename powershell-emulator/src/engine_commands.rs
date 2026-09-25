use super::{
    bits, builtins, content, decode_utf8, find_switch, is_quoted, is_variable, limited,
    named_or_positional, parse_number, parse_simple_xml, pipeline, providers, recon,
    security_cmdlets, split_powershell_words, split_windows_command_line, trim_url_punctuation,
    wildcard_match, ArtifactKind, Engine, EventKind, FlowControl, FunctionDefinition, Host,
    NetworkIntent, NetworkRequest, PowerShellEmulator, PowerShellError, TraceEvent, Value, URL_RE,
};
use std::collections::BTreeMap;

fn splat_variable_name(argument: &str) -> Option<String> {
    let name = argument.strip_prefix('@')?;
    if name.starts_with('(') || name.starts_with('{') {
        return None;
    }
    Some(
        name.trim_start_matches('{')
            .trim_end_matches('}')
            .to_ascii_lowercase(),
    )
}

fn powershell_argument(value: &Value) -> String {
    match value {
        Value::Null => "$null".into(),
        Value::Bool(true) => "$true".into(),
        Value::Bool(false) => "$false".into(),
        Value::Number(value) => value.to_string(),
        Value::Float(value) => value.to_string(),
        Value::String(value) | Value::Object(value) => {
            format!("'{}'", value.replace('\'', "''"))
        }
        Value::Bytes(values) => values
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(","),
        Value::Array(_) | Value::Map(_) => {
            format!("'{}'", value.as_string().replace('\'', "''"))
        }
    }
}

fn output_value(output: &[Value]) -> Option<Value> {
    match output {
        [] => None,
        [value] => Some(value.clone()),
        values => Some(Value::Array(values.to_vec())),
    }
}

impl PowerShellEmulator {
    #[allow(clippy::too_many_lines)]
    pub(crate) fn execute_command(
        &mut self,
        statement: &str,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Option<Value>, PowerShellError> {
        let words = split_powershell_words(statement);
        let Some(raw_command) = words.first() else {
            return Ok(None);
        };
        let command = self
            .expand_command_name(raw_command, host, depth)?
            .to_ascii_lowercase();
        let arguments = self.expand_splat_arguments(&words[1..]);
        let arguments = arguments.as_slice();
        host.emit(
            TraceEvent::new(
                depth,
                Engine::PowerShell,
                EventKind::Command,
                format!("emulated PowerShell command {command}"),
            )
            .with_data("statement", limited(statement, 1_024)),
        );

        if let pipeline::PipelineDispatch::Handled(value) =
            self.execute_pipeline_command(&command, arguments, host, depth)?
        {
            return Ok(value);
        }

        if let content::ContentDispatch::Handled(value) =
            self.execute_content_command(&command, arguments, host, depth)?
        {
            return Ok(value);
        }

        if let providers::ProviderDispatch::Handled(value) =
            self.execute_provider_command(&command, arguments, host, depth)?
        {
            return Ok(value);
        }

        if let security_cmdlets::SecurityDispatch::Handled(value) =
            self.execute_security_command(&command, arguments, statement, host, depth)?
        {
            return Ok(value);
        }

        if let recon::ReconDispatch::Handled(value) =
            self.execute_recon_command(&command, arguments, host, depth)
        {
            return Ok(value);
        }

        if let bits::BitsDispatch::Handled(value) =
            self.execute_bits_command(&command, arguments, host, depth)?
        {
            return Ok(value);
        }

        if let builtins::BuiltinDispatch::Handled(value) =
            self.execute_extended_command(&command, arguments, statement, host, depth)?
        {
            return Ok(value);
        }

        match command.as_str() {
            "write-output" | "echo" => {
                let no_enumerate_index = find_switch(arguments, "-noenumerate");
                let no_enumerate = no_enumerate_index.is_some();
                let expressions = arguments
                    .iter()
                    .enumerate()
                    .filter(|(index, _)| Some(*index) != no_enumerate_index)
                    .map(|(_, argument)| argument)
                    .collect::<Vec<_>>();
                let mut values = Vec::new();
                for expression in expressions {
                    let value = self.eval_command_argument(expression, host, depth)?;
                    if !no_enumerate {
                        if let Value::Array(items) = value {
                            values.extend(items);
                            continue;
                        }
                    }
                    values.push(value);
                }
                if values.is_empty() {
                    values.push(self.variables.get("input").cloned().unwrap_or(Value::Null));
                }
                for value in &values {
                    self.stdout.push(value.as_string());
                }
                host.emit(
                    TraceEvent::new(
                        depth,
                        Engine::PowerShell,
                        EventKind::Output,
                        "captured PowerShell output",
                    )
                    .with_data(
                        "value",
                        limited(
                            &values
                                .iter()
                                .map(Value::as_string)
                                .collect::<Vec<_>>()
                                .join("\n"),
                            1_024,
                        ),
                    ),
                );
                Ok(Some(output_value(&values).unwrap_or(Value::Null)))
            }
            "write-host" => {
                let output = arguments
                    .iter()
                    .map(|argument| {
                        self.eval_command_argument(argument, host, depth)
                            .map(|value| value.as_string())
                    })
                    .collect::<Result<Vec<_>, _>>()?
                    .join(" ");
                self.stdout.push(output.clone());
                host.emit(
                    TraceEvent::new(
                        depth,
                        Engine::PowerShell,
                        EventKind::Output,
                        "captured PowerShell host output",
                    )
                    .with_data("value", limited(&output, 1_024)),
                );
                Ok(Some(Value::String(output)))
            }
            "invoke-expression" | "iex" => {
                let value = self.eval_joined_arguments(arguments, host, depth)?;
                let script = value.as_string();
                host.add_artifact(
                    ArtifactKind::Script,
                    "invoke-expression.ps1",
                    "text/x-powershell",
                    script.as_bytes(),
                    depth,
                );
                host.emit(
                    TraceEvent::new(
                        depth,
                        Engine::PowerShell,
                        EventKind::Command,
                        "recursively emulating Invoke-Expression",
                    )
                    .with_data("script", limited(&script, 1_024)),
                );
                self.execute_script(&script, host, depth + 1)
            }
            "invoke-webrequest" | "iwr" | "invoke-restmethod" | "irm" => {
                let uri_expression =
                    named_or_positional(arguments, &["-uri"], 0).unwrap_or_default();
                let uri = self
                    .eval_expression(&uri_expression, host, depth)?
                    .as_string();
                let method_expression = named_or_positional(arguments, &["-method"], usize::MAX)
                    .unwrap_or_else(|| "GET".into());
                let method = self
                    .eval_expression(&method_expression, host, depth)?
                    .as_string()
                    .to_ascii_uppercase();
                let body_value = named_or_positional(arguments, &["-body"], usize::MAX)
                    .map(|value| self.eval_expression(&value, host, depth))
                    .transpose()?;
                let headers_value = named_or_positional(arguments, &["-headers"], usize::MAX)
                    .map(|value| self.eval_expression(&value, host, depth))
                    .transpose()?;
                let content_type = named_or_positional(arguments, &["-contenttype"], usize::MAX)
                    .map(|value| self.eval_expression(&value, host, depth))
                    .transpose()?
                    .map(|value| value.as_string());
                let session_variable =
                    named_or_positional(arguments, &["-sessionvariable"], usize::MAX).map(
                        |value| {
                            value
                                .trim_matches(['\'', '"'])
                                .trim_start_matches('$')
                                .to_ascii_lowercase()
                        },
                    );
                let web_session =
                    named_or_positional(arguments, &["-websession"], usize::MAX).map(|value| {
                        value
                            .trim_matches(['\'', '"'])
                            .trim_start_matches('$')
                            .to_ascii_lowercase()
                    });
                let mut request_headers = BTreeMap::new();
                if let Some(Value::Map(headers)) = &headers_value {
                    request_headers.extend(
                        headers
                            .iter()
                            .map(|(name, value)| (name.clone(), value.as_string())),
                    );
                }
                if let Some(user_agent) =
                    named_or_positional(arguments, &["-useragent"], usize::MAX)
                {
                    request_headers.insert(
                        "User-Agent".into(),
                        self.eval_expression(&user_agent, host, depth)?.as_string(),
                    );
                }
                if let Some(content_type) = &content_type {
                    request_headers.insert("Content-Type".into(), content_type.clone());
                }
                if let Some(session_name) = &web_session {
                    if let Some(session) = self.web_sessions.get(session_name) {
                        if let Some(Value::String(cookie)) = session.get("Cookie") {
                            request_headers.insert("Cookie".into(), cookie.clone());
                        }
                    }
                }
                let mut request_event = TraceEvent::new(
                    depth,
                    Engine::PowerShell,
                    EventKind::Command,
                    "modeled PowerShell HTTP request options",
                )
                .with_data("method", &method)
                .with_data(
                    "use_default_credentials",
                    find_switch(arguments, "-usedefaultcredentials")
                        .is_some()
                        .to_string(),
                )
                .with_data(
                    "maximum_redirection",
                    named_or_positional(arguments, &["-maximumredirection"], usize::MAX)
                        .unwrap_or_else(|| "5".into()),
                )
                .with_data(
                    "timeout_seconds",
                    named_or_positional(arguments, &["-timeoutsec"], usize::MAX)
                        .unwrap_or_else(|| "0".into()),
                );
                if let Some(body) = &body_value {
                    request_event =
                        request_event.with_data("body", limited(&body.as_string(), 2_048));
                }
                if !request_headers.is_empty() {
                    request_event = request_event.with_data(
                        "headers",
                        request_headers
                            .iter()
                            .map(|(name, value)| format!("{name}: {value}"))
                            .collect::<Vec<_>>()
                            .join("\n"),
                    );
                }
                host.emit(request_event);
                let response = host.network_request_detailed(NetworkRequest {
                    method,
                    url: uri,
                    headers: request_headers,
                    body: body_value.map_or_else(Vec::new, |value| value.as_bytes()),
                    origin: format!("PowerShell {command}"),
                    depth,
                });
                if let Some(session_name) = session_variable.or(web_session) {
                    let mut session = self.web_sessions.remove(&session_name).unwrap_or_default();
                    if let Some(response) = &response {
                        if let Some(cookie) = response
                            .headers
                            .iter()
                            .find(|(name, _)| name.eq_ignore_ascii_case("set-cookie"))
                            .map(|(_, value)| value.clone())
                        {
                            session.insert("Cookie".into(), Value::String(cookie));
                        }
                    }

                    session.insert("__type".into(), Value::String("WebRequestSession".into()));
                    self.variables
                        .insert(session_name.clone(), Value::Map(session.clone()));
                    self.web_sessions.insert(session_name, session);
                }
                let output_path = named_or_positional(arguments, &["-outfile"], usize::MAX);
                if let (Some(response), Some(output_path)) = (&response, output_path) {
                    let output_path = self.eval_expression(&output_path, host, depth)?.as_string();
                    host.write_file(
                        &output_path,
                        &response.body,
                        false,
                        Engine::PowerShell,
                        depth,
                    )?;
                    return Ok(Some(Value::String(output_path)));
                }
                if response.is_none() && find_switch(arguments, "-outfile").is_some() {
                    host.unsupported(
                        Engine::PowerShell,
                        depth,
                        "network response is unavailable; -OutFile was not created",
                    );
                }
                Ok(Some(response.map_or_else(
                    || Value::Object("BlockedNetworkResponse".into()),
                    |response| {
                        if command == "invoke-restmethod" {
                            let text = decode_utf8(&response.body);
                            if let Ok(json) = serde_json::from_str(&text) {
                                return builtins::json_to_value(json);
                            }
                            if text.trim_start().starts_with('<') {
                                return parse_simple_xml(&text);
                            }
                            Value::String(text)
                        } else {
                            builtins::network_response_value(response)
                        }
                    },
                )))
            }
            "start-process" | "saps" => {
                let program_expression =
                    named_or_positional(arguments, &["-filepath"], 0).unwrap_or_default();
                let program = self
                    .eval_expression(&program_expression, host, depth)?
                    .as_string();
                let argument_list =
                    named_or_positional(arguments, &["-argumentlist"], 1).unwrap_or_default();
                let args_value = self.eval_expression(&argument_list, host, depth)?;
                let args = match args_value {
                    Value::Array(values) => {
                        values.into_iter().map(|value| value.as_string()).collect()
                    }
                    Value::Null => Vec::new(),
                    value => split_windows_command_line(&value.as_string()),
                };
                Self::spawn(&program, args, "PowerShell Start-Process", host, depth)?;
                Ok(Some(Value::Object("BlockedProcess".into())))
            }
            "powershell" | "powershell.exe" | "pwsh" | "pwsh.exe" | "cmd" | "cmd.exe" | "mshta"
            | "mshta.exe" | "wscript" | "wscript.exe" | "cscript" | "cscript.exe" | "rundll32"
            | "rundll32.exe" | "regsvr32" | "regsvr32.exe" | "regasm" | "regasm.exe"
            | "msbuild" | "msbuild.exe" | "wmic" | "wmic.exe" | "schtasks" | "schtasks.exe"
            | "cmdkey" | "cmdkey.exe" | "certutil" | "certutil.exe" | "bitsadmin"
            | "bitsadmin.exe" => {
                let args = arguments
                    .iter()
                    .map(|argument| {
                        self.eval_expression(argument, host, depth)
                            .map(|value| value.as_string())
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Self::spawn(&command, args, "PowerShell command", host, depth)?;
                Ok(Some(Value::Object("BlockedProcess".into())))
            }
            _ if self.functions.contains_key(&command) => {
                if let Some(function) = self.functions.get(&command).cloned() {
                    self.execute_function(&function, arguments, host, depth + 1)
                } else {
                    Ok(None)
                }
            }
            _ => {
                for url in URL_RE.find_iter(statement) {
                    host.network_intent(NetworkIntent {
                        method: "GET".into(),
                        url: trim_url_punctuation(url.as_str()),
                        origin: format!("unmodeled PowerShell command {command}"),
                        depth,
                    });
                }
                host.unsupported(
                    Engine::PowerShell,
                    depth,
                    &format!("unsupported PowerShell command: {command}"),
                );
                Ok(None)
            }
        }
    }

    pub(crate) fn execute_function(
        &mut self,
        function: &FunctionDefinition,
        arguments: &[String],
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Option<Value>, PowerShellError> {
        let values = arguments
            .iter()
            .map(|argument| self.eval_expression(argument, host, depth))
            .collect::<Result<Vec<_>, _>>()?;
        let outer_variables = self.variables.clone();
        self.variables
            .insert("args".into(), Value::Array(values.clone()));
        for (index, parameter) in function.parameters.iter().enumerate() {
            let value = if let Some(value) = values.get(index).cloned() {
                value
            } else if let Some(default) = &parameter.default {
                self.eval_expression(default, host, depth)?
            } else {
                Value::Null
            };
            self.variables.insert(parameter.name.clone(), value);
        }
        let (result, output) = self.execute_script_collect(&function.body, host, depth)?;
        let flow = self.flow.take();
        let globals = self
            .variables
            .iter()
            .filter(|(name, _)| name.starts_with("global:"))
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect::<Vec<_>>();
        self.variables = outer_variables;
        self.variables.extend(globals);
        match flow {
            FlowControl::Return(value) => Ok(value.or_else(|| output_value(&output)).or(result)),
            FlowControl::Exit(value) => {
                self.flow = FlowControl::Exit(value.clone());
                Ok(value.or_else(|| output_value(&output)).or(result))
            }
            FlowControl::Break | FlowControl::Continue => {
                host.unsupported(
                    Engine::PowerShell,
                    depth,
                    "break or continue escaped a function body",
                );
                Ok(output_value(&output).or(result))
            }
            FlowControl::None => Ok(output_value(&output).or(result)),
        }
    }

    pub(crate) fn eval_joined_arguments(
        &mut self,
        arguments: &[String],
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Value, PowerShellError> {
        if arguments.is_empty() {
            return Ok(self.variables.get("input").cloned().unwrap_or(Value::Null));
        }
        self.eval_expression(&arguments.join(" "), host, depth)
    }

    fn eval_command_argument(
        &mut self,
        argument: &str,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Value, PowerShellError> {
        let argument = argument.trim();
        let expression_like = is_quoted(argument)
            || is_variable(argument)
            || parse_number(argument).is_some()
            || argument.starts_with('(')
            || argument.starts_with('[')
            || argument.starts_with("@(")
            || argument.starts_with("@{")
            || argument.starts_with("$(")
            || (argument.starts_with('$') && argument.contains('.'));
        if expression_like {
            self.eval_expression(argument, host, depth)
        } else {
            Ok(Value::String(self.interpolate(argument, host, depth)?))
        }
    }

    pub(crate) fn expand_command_name(
        &mut self,
        raw: &str,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<String, PowerShellError> {
        if raw.starts_with('$') || is_quoted(raw) || raw.starts_with('(') {
            let command = self.eval_expression(raw, host, depth)?.as_string();
            Ok(self.resolve_command_name(&command))
        } else {
            let command = raw
                .trim_matches(|character| character == '\'' || character == '"')
                .to_ascii_lowercase();
            Ok(self.resolve_command_name(&command))
        }
    }

    pub(crate) fn resolve_command_name(&self, command: &str) -> String {
        let command = command
            .strip_prefix("CommandInfo:")
            .unwrap_or(command)
            .rsplit_once('\\')
            .map_or(command, |(_, command)| command)
            .to_ascii_lowercase();
        if let Some(resolved) = self.aliases.get(&command) {
            return resolved.clone();
        }
        if command.contains(['*', '?']) {
            let candidates = [
                "invoke-expression",
                "invoke-webrequest",
                "invoke-restmethod",
                "write-output",
                "write-host",
                "start-process",
                "set-content",
                "get-content",
                "foreach-object",
                "where-object",
            ];
            if let Some(candidate) = candidates
                .iter()
                .find(|candidate| wildcard_match(candidate, &command, false))
            {
                return (*candidate).into();
            }
        }
        command
    }

    fn expand_splat_arguments(&self, arguments: &[String]) -> Vec<String> {
        let mut expanded = Vec::new();
        for argument in arguments {
            let Some(name) = splat_variable_name(argument) else {
                expanded.push(argument.clone());
                continue;
            };
            match self.variables.get(&name) {
                Some(Value::Array(values)) => {
                    expanded.extend(values.iter().map(powershell_argument));
                }
                Some(Value::Map(values)) => {
                    for (name, value) in values {
                        match value {
                            Value::Bool(false) => {}
                            Value::Bool(true) | Value::Null => {
                                expanded.push(format!("-{name}"));
                            }
                            value => {
                                expanded.push(format!("-{name}"));
                                expanded.push(powershell_argument(value));
                            }
                        }
                    }
                }
                Some(value) => expanded.push(powershell_argument(value)),
                None => expanded.push(argument.clone()),
            }
        }
        expanded
    }
}
