use super::{
    assign_index, decode_utf8, extract_delimited, find_word_case_insensitive, is_variable, limited,
    looks_like_script, merge_branch_variables, normalize_variable, parse_instance_call,
    parse_member_access, parse_named_block, parse_redirections, parse_static_call,
    parse_static_member_access, quote_argument, split_assignment, split_compound_assignment,
    split_increment, split_index_expression, split_key_value, split_labeled_blocks,
    split_powershell_words, split_statements, split_top_level, starts_word, strip_comments,
    values_equal, wildcard_match, ArtifactKind, Engine, EventKind, FlowControl, FunctionDefinition,
    Host, PowerShellEmulator, PowerShellError, TokenKind, TraceEvent, Value,
};
use crate::parser::ParsedSource;

fn value_from_outputs(mut output: Vec<Value>) -> Value {
    if output.len() == 1 {
        output.pop().unwrap_or(Value::Null)
    } else {
        Value::Array(output)
    }
}

fn append_stdout(stdout: &mut Vec<String>, value: Value) {
    match value {
        Value::Null => {}
        Value::Array(values) => {
            for value in values {
                append_stdout(stdout, value);
            }
        }
        value => stdout.push(value.as_string()),
    }
}

impl PowerShellEmulator {
    pub(crate) fn execute_source(
        &mut self,
        script: &str,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Option<Value>, PowerShellError> {
        let parser = ParsedSource::parse(script)
            .map_err(|diagnostic| PowerShellError::Parser(diagnostic.to_string()))?;
        self.execute_script(&parser, parser.source(), host, depth)
    }

    pub(crate) fn execute_script(
        &mut self,
        parser: &ParsedSource,
        script: &str,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Option<Value>, PowerShellError> {
        let mut last = None;
        for statement in split_statements(parser, script) {
            if statement.trim().is_empty() {
                continue;
            }
            host.consume_step(Engine::PowerShell, depth, "executing PowerShell statement")?;
            if let Some(value) = self.execute_statement(parser, statement.trim(), host, depth)? {
                last = Some(value.clone());
                if Self::statement_emits_value(parser, statement.trim()) {
                    self.emit_value(value.clone());
                    if self.output_capture_depth == 0
                        && !self.statement_writes_stdout(parser, statement.trim())
                    {
                        append_stdout(&mut self.stdout, value);
                    }
                }
            }
            if self.flow.is_active() {
                break;
            }
        }
        Ok(last)
    }

    pub(crate) fn execute_script_collect(
        &mut self,
        parser: &ParsedSource,
        script: &str,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<(Option<Value>, Vec<Value>), PowerShellError> {
        let start = self.emitted_values.len();
        let stdout_start = self.stdout.len();
        self.output_capture_depth += 1;
        let result = self.execute_script(parser, script, host, depth);
        self.output_capture_depth = self.output_capture_depth.saturating_sub(1);
        let result = result?;
        self.stdout.truncate(stdout_start);
        let output = self.emitted_values.split_off(start);
        Ok((result, output))
    }

    #[allow(clippy::too_many_lines)]
    pub(crate) fn execute_statement(
        &mut self,
        parser: &ParsedSource,
        statement: &str,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Option<Value>, PowerShellError> {
        let raw_statement = statement;
        let statement_without_comments = strip_comments(parser, statement);
        let statement = statement_without_comments.trim();
        if statement.is_empty() {
            return Ok(None);
        }
        if let Some((command, redirections)) = parse_redirections(parser, raw_statement) {
            return self.execute_redirected(parser, command, &redirections, host, depth);
        }

        if let Some((name, body)) = parse_named_block(parser, raw_statement, "function") {
            let function_name = name.split('(').next().unwrap_or(name).trim();
            let definition = if let Some(open) = name.find('(') {
                let source = format!("param{}\n{body}", &name[open..]);
                let definition_parser = ParsedSource::parse(&source)
                    .map_err(|diagnostic| PowerShellError::Parser(diagnostic.to_string()))?;
                FunctionDefinition::parse(&definition_parser, definition_parser.source())
            } else {
                FunctionDefinition::parse(parser, body)
            };
            self.functions
                .insert(function_name.to_ascii_lowercase(), definition);
            host.emit(
                TraceEvent::new(
                    depth,
                    Engine::PowerShell,
                    EventKind::Command,
                    format!("defined function {function_name}"),
                )
                .with_data("body_bytes", body.len().to_string()),
            );
            return Ok(None);
        }
        if let Some((name, body)) = parse_named_block(parser, raw_statement, "filter") {
            self.functions.insert(
                name.to_ascii_lowercase(),
                FunctionDefinition::parse(parser, body),
            );
            return Ok(None);
        }
        if ["class", "enum", "data"]
            .iter()
            .any(|keyword| starts_word(statement, keyword))
        {
            host.emit(
                TraceEvent::new(
                    depth,
                    Engine::PowerShell,
                    EventKind::Parse,
                    "recorded opaque PowerShell type/data declaration",
                )
                .with_data("declaration", limited(statement, 1_024)),
            );
            return Ok(None);
        }
        if starts_word(statement, "param") {
            let after_keyword = statement["param".len()..].trim_start();
            if let Some((parameters, _)) = extract_delimited(parser, after_keyword, '(', ')') {
                for parameter in split_top_level(parser, parameters, ',') {
                    let (declaration, default) = split_key_value(parser, parameter)
                        .map_or((parameter, None), |(declaration, default)| {
                            (declaration, Some(default))
                        });
                    let name = parser
                        .window(declaration)
                        .into_iter()
                        .flat_map(|window| window.tokens().iter().copied())
                        .find(|token| token.kind == TokenKind::Variable)
                        .map_or_else(String::new, |token| {
                            normalize_variable(token.text(parser.source()))
                        });
                    if !name.is_empty() && !self.variables.contains_key(&name) {
                        let value = default
                            .map(|default| self.eval_expression(parser, default, host, depth))
                            .transpose()?
                            .unwrap_or(Value::Null);
                        self.variables.insert(name, value);
                    }
                }
            }
            return Ok(None);
        }

        if starts_word(statement, "if") {
            return self.execute_if(parser, raw_statement, host, depth);
        }
        if starts_word(statement, "foreach") {
            return self.execute_foreach(parser, raw_statement, host, depth);
        }
        if starts_word(statement, "while") {
            return self.execute_while(parser, raw_statement, host, depth);
        }
        if starts_word(statement, "for") {
            return self.execute_for(parser, raw_statement, host, depth);
        }
        if starts_word(statement, "switch") {
            return self.execute_switch(parser, raw_statement, host, depth);
        }
        if starts_word(statement, "do") {
            return self.execute_do(parser, raw_statement, host, depth);
        }
        if starts_word(statement, "try") {
            return self.execute_try(parser, raw_statement, host, depth);
        }
        if statement.eq_ignore_ascii_case("break") {
            self.flow = FlowControl::Break;
            return Ok(None);
        }
        if statement.eq_ignore_ascii_case("continue") {
            self.flow = FlowControl::Continue;
            return Ok(None);
        }
        if starts_word(statement, "return") {
            let expression = statement["return".len()..].trim();
            let value = if expression.is_empty() {
                None
            } else {
                Some(self.eval_expression(parser, expression, host, depth)?)
            };
            self.flow = FlowControl::Return(value.clone());
            return Ok(value);
        }
        if starts_word(statement, "exit") {
            let expression = statement["exit".len()..].trim();
            let value = if expression.is_empty() {
                None
            } else {
                Some(self.eval_expression(parser, expression, host, depth)?)
            };
            self.flow = FlowControl::Exit(value.clone());
            return Ok(value);
        }
        if starts_word(statement, "throw") {
            let expression = statement["throw".len()..].trim();
            let value = self.eval_expression(parser, expression, host, depth)?;
            return Err(PowerShellError::Evaluation(value.as_string()));
        }

        if let Some((variable, delta)) = split_increment(parser, raw_statement) {
            let name = normalize_variable(variable);
            let value = self
                .variables
                .get(&name)
                .and_then(Value::as_i64)
                .unwrap_or_default()
                .saturating_add(delta);
            let value = Value::Number(value);
            self.variables.insert(name, value.clone());
            return Ok(Some(value));
        }

        if let Some((left, operator, right)) = split_compound_assignment(parser, raw_statement) {
            let name = normalize_variable(left);
            let current = self.variables.get(&name).cloned().unwrap_or(Value::Null);
            let right = self.eval_expression(parser, right, host, depth)?;
            let value = self.apply_binary(current, operator, right, host, depth);
            self.variables.insert(name, value.clone());
            return Ok(Some(value));
        }

        if let Some((left, right)) = split_assignment(parser, raw_statement) {
            if let Some((type_name, member)) = parse_static_member_access(left) {
                let value = self.eval_expression(parser, right, host, depth)?;
                let key = format!("__static:{}", type_name.to_ascii_lowercase());
                let state = self
                    .variables
                    .entry(key)
                    .or_insert_with(|| Value::Map(std::collections::BTreeMap::default()));
                if let Value::Map(properties) = state {
                    properties.insert(member.clone(), value.clone());
                }
                host.emit(
                    TraceEvent::new(
                        depth,
                        Engine::PowerShell,
                        EventKind::Command,
                        format!("modeled static property assignment [{type_name}]::{member}"),
                    )
                    .with_data("value", limited(&value.as_string(), 512)),
                );
                return Ok(Some(value));
            }
            if let Some((receiver, index_expression)) = split_index_expression(parser, left) {
                if is_variable(parser, receiver) {
                    let index = self.eval_expression(parser, index_expression, host, depth)?;
                    let value = self.eval_expression(parser, right, host, depth)?;
                    let name = normalize_variable(receiver);
                    if let Some(target) = self.variables.get_mut(&name) {
                        assign_index(target, &index, &value);
                        return Ok(Some(value));
                    }
                }
            }
            if let Some((receiver, member)) = parse_member_access(parser, left) {
                if is_variable(parser, receiver) {
                    let value = self.eval_expression(parser, right, host, depth)?;
                    let name = normalize_variable(receiver);
                    let target = self
                        .variables
                        .entry(name)
                        .or_insert_with(|| Value::Map(std::collections::BTreeMap::default()));
                    if let Value::Map(properties) = target {
                        properties.insert(member.into(), value.clone());
                        return Ok(Some(value));
                    }
                    host.unsupported(
                        Engine::PowerShell,
                        depth,
                        &format!("member assignment requires a modeled object: {left}"),
                    );
                    return Ok(None);
                }
            }
            let name = normalize_variable(left);
            if name.is_empty() {
                host.unsupported(
                    Engine::PowerShell,
                    depth,
                    &format!("unsupported assignment target: {left}"),
                );
                return Ok(None);
            }
            let mut value = self.eval_statement_or_expression(parser, right, host, depth)?;
            value = Self::decode_layers(value, host, depth);
            if let Some(environment_name) = name.strip_prefix("env:") {
                host.set_environment(environment_name, &value.as_string());
            }
            self.variables.insert(name.clone(), value.clone());
            host.emit(
                TraceEvent::new(
                    depth,
                    Engine::PowerShell,
                    EventKind::VariableAssignment,
                    format!("assigned ${name}"),
                )
                .with_data("value", limited(&value.as_string(), 512)),
            );
            return Ok(Some(value));
        }

        let pipeline = split_top_level(parser, raw_statement, '|');
        if pipeline.len() > 1 {
            let mut input = Value::Null;
            for segment in pipeline {
                self.variables.insert("input".into(), input.clone());
                let start = self.emitted_values.len();
                let result = self.execute_statement(parser, segment.trim(), host, depth)?;
                let output = self.emitted_values.split_off(start);
                input = if output.is_empty() {
                    result.unwrap_or(Value::Null)
                } else {
                    value_from_outputs(output)
                };
            }
            return Ok(Some(input));
        }

        if statement.starts_with('&') || statement.starts_with(". ") {
            let invocation = statement[1..].trim();
            let words = split_powershell_words(parser, invocation);
            let Some(target_expression) = words.first() else {
                return Ok(None);
            };
            let target = self.eval_expression(parser, target_expression, host, depth)?;
            let target_text = target.as_string();
            let evaluated_arguments = words[1..]
                .iter()
                .map(|argument| {
                    self.eval_expression(parser, argument, host, depth)
                        .map(|value| quote_argument(&value.as_string()))
                })
                .collect::<Result<Vec<_>, _>>()?;
            if looks_like_script(&target_text) {
                host.add_artifact(
                    ArtifactKind::Script,
                    "invoked-powershell.ps1",
                    "text/x-powershell",
                    target_text.as_bytes(),
                    depth,
                );
                return self.execute_source(&target_text, host, depth + 1);
            }
            let expanded_command = format!("{} {}", target_text, evaluated_arguments.join(" "));
            let expanded_parser = ParsedSource::parse(&expanded_command)
                .map_err(|diagnostic| PowerShellError::Parser(diagnostic.to_string()))?;
            if self.looks_like_command_expression(&expanded_parser, expanded_parser.source()) {
                return self.execute_command(
                    &expanded_parser,
                    expanded_parser.source(),
                    host,
                    depth + 1,
                );
            }
            if let Some(bytes) = host.read_file(&target_text, Engine::PowerShell, depth) {
                let script = decode_utf8(&bytes);
                return self.execute_source(&script, host, depth + 1);
            }
            let command_line = std::iter::once(target_text.as_str())
                .chain(evaluated_arguments.iter().map(String::as_str))
                .collect::<Vec<_>>()
                .join(" ");
            Self::spawn_command_line(&command_line, "PowerShell invocation operator", host, depth)?;
            return Ok(Some(target));
        }

        if split_powershell_words(parser, raw_statement).len() == 1
            && (parse_static_call(parser, raw_statement).is_some()
                || parse_instance_call(parser, raw_statement).is_some())
        {
            return self
                .eval_expression(parser, raw_statement, host, depth)
                .map(Some);
        }
        if self.looks_like_command_expression(parser, raw_statement) {
            return self.execute_command(parser, raw_statement, host, depth);
        }
        if Self::looks_like_value_expression(parser, raw_statement) {
            return self
                .eval_expression(parser, raw_statement, host, depth)
                .map(Some);
        }

        self.execute_command(parser, raw_statement, host, depth)
    }

    fn emit_value(&mut self, value: Value) {
        match value {
            Value::Null => {}
            Value::Array(values) => {
                for value in values {
                    self.emit_value(value);
                }
            }
            value => self.emitted_values.push(value),
        }
    }

    fn statement_emits_value(parser: &ParsedSource, statement: &str) -> bool {
        if split_assignment(parser, statement).is_some()
            || split_compound_assignment(parser, statement).is_some()
            || split_increment(parser, statement).is_some()
            || statement.starts_with('&')
            || statement.starts_with(". ")
        {
            return false;
        }
        let first = split_powershell_words(parser, statement)
            .first()
            .map(|value| value.to_ascii_lowercase())
            .unwrap_or_default();
        if matches!(
            first.as_str(),
            "function"
                | "filter"
                | "class"
                | "enum"
                | "data"
                | "param"
                | "if"
                | "foreach"
                | "for"
                | "while"
                | "do"
                | "switch"
                | "try"
                | "invoke-expression"
                | "iex"
        ) {
            return false;
        }
        true
    }

    fn statement_writes_stdout(&self, parser: &ParsedSource, statement: &str) -> bool {
        if parse_redirections(parser, statement).is_some() {
            return false;
        }
        split_powershell_words(parser, statement)
            .first()
            .is_some_and(|command| {
                matches!(
                    self.resolve_command_name(command).as_str(),
                    "write-output" | "write-host"
                )
            })
    }

    pub(crate) fn execute_if(
        &mut self,
        parser: &ParsedSource,
        statement: &str,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Option<Value>, PowerShellError> {
        let after_if = statement[2..].trim_start();
        let Some((condition, after_condition)) = extract_delimited(parser, after_if, '(', ')')
        else {
            host.unsupported(Engine::PowerShell, depth, "malformed if statement");
            return Ok(None);
        };
        let Some((then_body, remainder)) =
            extract_delimited(parser, after_condition.trim_start(), '{', '}')
        else {
            host.unsupported(
                Engine::PowerShell,
                depth,
                "if statement without a statement block",
            );
            return Ok(None);
        };

        let condition_value = self.eval_expression(parser, condition, host, depth)?;
        if condition_value.truthy() {
            return self.execute_script(parser, then_body, host, depth + 1);
        }

        let remainder = remainder.trim_start();
        if starts_word(remainder, "elseif") {
            let nested = format!("if {}", remainder["elseif".len()..].trim_start());
            let nested_parser = ParsedSource::parse(&nested)
                .map_err(|diagnostic| PowerShellError::Parser(diagnostic.to_string()))?;
            return self.execute_if(&nested_parser, nested_parser.source(), host, depth);
        }
        let else_body = if starts_word(remainder, "else") {
            let after_else = remainder[4..].trim_start();
            extract_delimited(parser, after_else, '{', '}').map(|(body, _)| body)
        } else {
            None
        };
        if matches!(condition_value, Value::Null) && !condition.trim().eq_ignore_ascii_case("$null")
        {
            host.unsupported(
                Engine::PowerShell,
                depth,
                "condition could not be resolved; emulating both branches speculatively",
            );
            let baseline = self.variables.clone();
            let baseline_stdout = self.stdout.len();
            let mut then_branch = self.clone();
            let then_value = then_branch.execute_script(parser, then_body, host, depth + 1)?;
            let mut else_branch = self.clone();
            let else_value = if let Some(else_body) = else_body {
                else_branch.execute_script(parser, else_body, host, depth + 1)?
            } else {
                None
            };
            self.variables =
                merge_branch_variables(&baseline, &then_branch.variables, &else_branch.variables);
            self.stdout
                .extend(then_branch.stdout.into_iter().skip(baseline_stdout));
            self.stdout
                .extend(else_branch.stdout.into_iter().skip(baseline_stdout));
            return Ok(then_value.or(else_value));
        }
        if let Some(else_body) = else_body {
            return self.execute_script(parser, else_body, host, depth + 1);
        }
        Ok(None)
    }

    pub(crate) fn execute_foreach(
        &mut self,
        parser: &ParsedSource,
        statement: &str,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Option<Value>, PowerShellError> {
        let after_keyword = statement["foreach".len()..].trim_start();
        let Some((header, after_header)) = extract_delimited(parser, after_keyword, '(', ')')
        else {
            host.unsupported(Engine::PowerShell, depth, "malformed foreach statement");
            return Ok(None);
        };
        let Some((body, _)) = extract_delimited(parser, after_header.trim_start(), '{', '}') else {
            host.unsupported(
                Engine::PowerShell,
                depth,
                "foreach statement without a block",
            );
            return Ok(None);
        };
        let Some(index) = find_word_case_insensitive(header, " in ") else {
            host.unsupported(Engine::PowerShell, depth, "malformed foreach header");
            return Ok(None);
        };
        let variable = normalize_variable(header[..index].trim());
        let values = self.eval_expression(parser, header[index + 4..].trim(), host, depth)?;
        let values = match values {
            Value::Array(values) => values,
            value => vec![value],
        };
        let max = host.limits().max_loop_iterations;
        let mut last = None;
        for (index, value) in values.into_iter().enumerate() {
            if index >= max {
                host.emit(TraceEvent::new(
                    depth,
                    Engine::PowerShell,
                    EventKind::LimitReached,
                    "foreach iteration limit reached",
                ));
                break;
            }
            self.variables.insert(variable.clone(), value);
            last = self.execute_script(parser, body, host, depth + 1)?;
            match self.flow.take() {
                FlowControl::None => {}
                FlowControl::Continue => continue,
                FlowControl::Break => break,
                flow @ (FlowControl::Return(_) | FlowControl::Exit(_)) => {
                    self.flow = flow;
                    break;
                }
            }
        }
        Ok(last)
    }

    pub(crate) fn execute_while(
        &mut self,
        parser: &ParsedSource,
        statement: &str,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Option<Value>, PowerShellError> {
        let after_keyword = statement["while".len()..].trim_start();
        let Some((condition, after_condition)) = extract_delimited(parser, after_keyword, '(', ')')
        else {
            host.unsupported(Engine::PowerShell, depth, "malformed while statement");
            return Ok(None);
        };
        let Some((body, _)) = extract_delimited(parser, after_condition.trim_start(), '{', '}')
        else {
            host.unsupported(Engine::PowerShell, depth, "while statement without a block");
            return Ok(None);
        };
        self.execute_loop(parser, condition, body, None, false, host, depth)
    }

    pub(crate) fn execute_for(
        &mut self,
        parser: &ParsedSource,
        statement: &str,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Option<Value>, PowerShellError> {
        let after_keyword = statement["for".len()..].trim_start();
        let Some((header, after_header)) = extract_delimited(parser, after_keyword, '(', ')')
        else {
            host.unsupported(Engine::PowerShell, depth, "malformed for statement");
            return Ok(None);
        };
        let Some((body, _)) = extract_delimited(parser, after_header.trim_start(), '{', '}') else {
            host.unsupported(Engine::PowerShell, depth, "for statement without a block");
            return Ok(None);
        };
        let parts = split_top_level(parser, header, ';');
        if parts.len() != 3 {
            host.unsupported(Engine::PowerShell, depth, "malformed for loop header");
            return Ok(None);
        }
        self.execute_statement(parser, parts[0].trim(), host, depth)?;
        self.execute_loop(
            parser,
            parts[1].trim(),
            body,
            Some(parts[2].trim()),
            false,
            host,
            depth,
        )
    }

    pub(crate) fn execute_do(
        &mut self,
        parser: &ParsedSource,
        statement: &str,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Option<Value>, PowerShellError> {
        let after_keyword = statement["do".len()..].trim_start();
        let Some((body, remainder)) = extract_delimited(parser, after_keyword, '{', '}') else {
            host.unsupported(Engine::PowerShell, depth, "malformed do statement");
            return Ok(None);
        };
        let remainder = remainder.trim_start();
        let (until, after_condition_keyword) = if starts_word(remainder, "until") {
            (true, remainder["until".len()..].trim_start())
        } else if starts_word(remainder, "while") {
            (false, remainder["while".len()..].trim_start())
        } else {
            host.unsupported(
                Engine::PowerShell,
                depth,
                "do statement requires while or until",
            );
            return Ok(None);
        };
        let Some((condition, _)) = extract_delimited(parser, after_condition_keyword, '(', ')')
        else {
            host.unsupported(Engine::PowerShell, depth, "malformed do-loop condition");
            return Ok(None);
        };
        let mut last = None;
        for index in 0..host.limits().max_loop_iterations {
            last = self.execute_script(parser, body, host, depth + 1)?;
            match self.flow.take() {
                FlowControl::None | FlowControl::Continue => {}
                FlowControl::Break => break,
                flow @ (FlowControl::Return(_) | FlowControl::Exit(_)) => {
                    self.flow = flow;
                    break;
                }
            }
            let condition_matches = self
                .eval_expression(parser, condition, host, depth)?
                .truthy();
            if condition_matches == until {
                break;
            }
            if index + 1 == host.limits().max_loop_iterations {
                host.emit(TraceEvent::new(
                    depth,
                    Engine::PowerShell,
                    EventKind::LimitReached,
                    "do-loop iteration limit reached",
                ));
            }
        }
        Ok(last)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn execute_loop(
        &mut self,
        parser: &ParsedSource,
        condition: &str,
        body: &str,
        iteration: Option<&str>,
        until: bool,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Option<Value>, PowerShellError> {
        let mut last = None;
        for index in 0..host.limits().max_loop_iterations {
            let condition_matches = self
                .eval_expression(parser, condition, host, depth)?
                .truthy();
            if condition_matches == until {
                break;
            }
            last = self.execute_script(parser, body, host, depth + 1)?;
            match self.flow.take() {
                FlowControl::None | FlowControl::Continue => {}
                FlowControl::Break => break,
                flow @ (FlowControl::Return(_) | FlowControl::Exit(_)) => {
                    self.flow = flow;
                    break;
                }
            }
            if let Some(iteration) = iteration {
                self.execute_statement(parser, iteration, host, depth)?;
            }
            if index + 1 == host.limits().max_loop_iterations {
                host.emit(TraceEvent::new(
                    depth,
                    Engine::PowerShell,
                    EventKind::LimitReached,
                    "loop iteration limit reached",
                ));
            }
        }
        Ok(last)
    }

    pub(crate) fn execute_switch(
        &mut self,
        parser: &ParsedSource,
        statement: &str,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Option<Value>, PowerShellError> {
        let after_keyword = statement["switch".len()..].trim_start();
        let Some(condition_start) = after_keyword.find('(') else {
            host.unsupported(Engine::PowerShell, depth, "malformed switch statement");
            return Ok(None);
        };
        let options = after_keyword[..condition_start].to_ascii_lowercase();
        let Some((condition, after_condition)) =
            extract_delimited(parser, &after_keyword[condition_start..], '(', ')')
        else {
            host.unsupported(Engine::PowerShell, depth, "malformed switch statement");
            return Ok(None);
        };
        let Some((body, _)) = extract_delimited(parser, after_condition.trim_start(), '{', '}')
        else {
            host.unsupported(
                Engine::PowerShell,
                depth,
                "switch statement without a block",
            );
            return Ok(None);
        };
        let value = self.eval_expression(parser, condition, host, depth)?;
        let values = if options.contains("-file") {
            let path = value.as_string();
            host.read_file(&path, Engine::PowerShell, depth)
                .map_or_else(
                    || vec![Value::Null],
                    |bytes| {
                        decode_utf8(&bytes)
                            .lines()
                            .map(|line| Value::String(line.into()))
                            .collect()
                    },
                )
        } else if let Value::Array(values) = value {
            values
        } else {
            vec![value]
        };
        let case_sensitive = options.contains("-casesensitive");
        let regex_mode = options.contains("-regex");
        let wildcard_mode = options.contains("-wildcard");
        let mut default_body = None;
        let blocks = split_labeled_blocks(parser, body);
        let mut last = None;
        let mut matched_any = false;
        for value in values {
            self.variables.insert("_".into(), value.clone());
            for (label, block) in &blocks {
                if label.eq_ignore_ascii_case("default") {
                    default_body = Some(*block);
                    continue;
                }
                let pattern = self.eval_expression(parser, label, host, depth)?;
                let matched = if regex_mode {
                    let mut builder = regex::RegexBuilder::new(&pattern.as_string());
                    builder.case_insensitive(!case_sensitive);
                    builder
                        .build()
                        .is_ok_and(|regex| regex.is_match(&value.as_string()))
                } else if wildcard_mode {
                    wildcard_match(&value.as_string(), &pattern.as_string(), case_sensitive)
                } else {
                    values_equal(&value, &pattern, case_sensitive)
                };
                if matched {
                    matched_any = true;
                    last = self.execute_script(parser, block, host, depth + 1)?;
                    match self.flow.take() {
                        FlowControl::Break => return Ok(last),
                        flow @ (FlowControl::Return(_) | FlowControl::Exit(_)) => {
                            self.flow = flow;
                            return Ok(last);
                        }
                        FlowControl::None | FlowControl::Continue => {}
                    }
                }
            }
        }
        if !matched_any {
            if let Some(default_body) = default_body {
                last = self.execute_script(parser, default_body, host, depth + 1)?;
            }
        }
        Ok(last)
    }

    pub(crate) fn execute_try(
        &mut self,
        parser: &ParsedSource,
        statement: &str,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Option<Value>, PowerShellError> {
        let after_try = statement[3..].trim_start();
        let Some((try_body, remainder)) = extract_delimited(parser, after_try, '{', '}') else {
            host.unsupported(Engine::PowerShell, depth, "malformed try statement");
            return Ok(None);
        };
        let mut remainder = remainder.trim_start();
        let mut catch_body = None;
        if starts_word(remainder, "catch") {
            let after_catch = remainder["catch".len()..].trim_start();
            if let Some((body, after_body)) = extract_delimited(parser, after_catch, '{', '}') {
                catch_body = Some(body);
                remainder = after_body.trim_start();
            }
        }
        let finally_body = if starts_word(remainder, "finally") {
            extract_delimited(parser, remainder["finally".len()..].trim_start(), '{', '}')
                .map(|(body, _)| body)
        } else {
            None
        };

        let mut result = match self.execute_script(parser, try_body, host, depth + 1) {
            Ok(value) => Ok(value),
            Err(error) => {
                if let Some(catch_body) = catch_body {
                    self.variables
                        .insert("_".into(), Value::String(error.to_string()));
                    self.variables.insert(
                        "error".into(),
                        Value::Array(vec![Value::String(error.to_string())]),
                    );
                    self.execute_script(parser, catch_body, host, depth + 1)
                } else {
                    Err(error)
                }
            }
        };
        if let Some(finally_body) = finally_body {
            match self.execute_script(parser, finally_body, host, depth + 1) {
                Err(error) => result = Err(error),
                Ok(Some(value)) => result = Ok(Some(value)),
                Ok(None) => {}
            }
        }
        result
    }
}
