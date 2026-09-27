use super::{
    assign_index, decode_utf8, is_variable, limited, looks_like_script, merge_branch_variables,
    normalize_variable, parse_member_access, parse_redirections, parse_static_member_access,
    quote_argument, split_index_expression, split_powershell_words, values_equal, wildcard_match,
    ArtifactKind, Engine, EventKind, FlowControl, FunctionDefinition, Host, PowerShellEmulator,
    PowerShellError, TraceEvent, Value,
};
use crate::ast::{
    DoStatement, ForStatement, ForeachStatement, IfBranch, IfStatement, Statement, StatementKind,
    SwitchInput, SwitchMatching, SwitchStatement, TryStatement, WhileStatement,
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
        let statements = parser.statements(script).ok_or_else(|| {
            PowerShellError::Evaluation("script is outside parsed PowerShell source".into())
        })?;
        for statement in statements.iter() {
            let statement_text = parser.text(statement.range).trim();
            if statement_text.is_empty() {
                continue;
            }
            host.consume_step(Engine::PowerShell, depth, "executing PowerShell statement")?;
            if let Some(value) = self.execute_parsed_statement(parser, statement, host, depth)? {
                last = Some(value.clone());
                if Self::parsed_statement_emits_value(statement) {
                    self.emit_value(value.clone());
                    if self.output_capture_depth == 0
                        && !self.statement_writes_stdout(parser, statement_text)
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

    #[allow(clippy::too_many_lines)]
    fn execute_parsed_statement(
        &mut self,
        parser: &ParsedSource,
        statement: &Statement,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Option<Value>, PowerShellError> {
        let text = parser.text(statement.range).trim();
        match &statement.kind {
            StatementKind::Empty => Ok(None),
            StatementKind::Function {
                name,
                parameters,
                body,
                filter,
            } => {
                let function_name = parser.text(*name);
                let definition = FunctionDefinition {
                    parser: parser.clone(),
                    parameters: parameters
                        .iter()
                        .map(|parameter| crate::runtime::FunctionParameter {
                            name: normalize_variable(parser.text(parameter.name)),
                            default: parameter.default.as_ref().map(|value| value.range),
                        })
                        .collect(),
                    body: *body,
                };
                self.functions
                    .insert(function_name.to_ascii_lowercase(), definition);
                if !filter {
                    host.emit(
                        TraceEvent::new(
                            depth,
                            Engine::PowerShell,
                            EventKind::Command,
                            format!("defined function {function_name}"),
                        )
                        .with_data("body_bytes", body.len().to_string()),
                    );
                }
                Ok(None)
            }
            StatementKind::OpaqueDeclaration => {
                host.emit(
                    TraceEvent::new(
                        depth,
                        Engine::PowerShell,
                        EventKind::Parse,
                        "recorded opaque PowerShell type/data declaration",
                    )
                    .with_data("declaration", limited(text, 1_024)),
                );
                Ok(None)
            }
            StatementKind::Param(parameters) => {
                for parameter in parameters {
                    let name = normalize_variable(parser.text(parameter.name));
                    if !name.is_empty() && !self.variables.contains_key(&name) {
                        let value = parameter
                            .default
                            .as_ref()
                            .map(|default| {
                                self.eval_expression(
                                    parser,
                                    parser.text(default.range),
                                    host,
                                    depth,
                                )
                            })
                            .transpose()?
                            .unwrap_or(Value::Null);
                        self.variables.insert(name, value);
                    }
                }
                Ok(None)
            }
            StatementKind::If(statement) => self.execute_ast_if(parser, statement, host, depth),
            StatementKind::Foreach(statement) => {
                self.execute_ast_foreach(parser, statement, host, depth)
            }
            StatementKind::While(statement) => {
                self.execute_ast_while(parser, statement, host, depth)
            }
            StatementKind::For(statement) => self.execute_ast_for(parser, statement, host, depth),
            StatementKind::Switch(statement) => {
                self.execute_ast_switch(parser, statement, host, depth)
            }
            StatementKind::Do(statement) => self.execute_ast_do(parser, statement, host, depth),
            StatementKind::Try(statement) => self.execute_ast_try(parser, statement, host, depth),
            StatementKind::Break => {
                self.flow = FlowControl::Break;
                Ok(None)
            }
            StatementKind::Continue => {
                self.flow = FlowControl::Continue;
                Ok(None)
            }
            StatementKind::Return(expression) => {
                let value = expression
                    .as_ref()
                    .map(|expression| {
                        self.eval_expression(parser, parser.text(expression.range), host, depth)
                    })
                    .transpose()?;
                self.flow = FlowControl::Return(value.clone());
                Ok(value)
            }
            StatementKind::Exit(expression) => {
                let value = expression
                    .as_ref()
                    .map(|expression| {
                        self.eval_expression(parser, parser.text(expression.range), host, depth)
                    })
                    .transpose()?;
                self.flow = FlowControl::Exit(value.clone());
                Ok(value)
            }
            StatementKind::Throw(expression) => {
                let value =
                    self.eval_expression(parser, parser.text(expression.range), host, depth)?;
                Err(PowerShellError::Evaluation(value.as_string()))
            }
            StatementKind::Increment { variable, delta } => {
                let name = normalize_variable(parser.text(*variable));
                let value = self
                    .variables
                    .get(&name)
                    .and_then(Value::as_i64)
                    .unwrap_or_default()
                    .saturating_add(*delta);
                let value = Value::Number(value);
                self.variables.insert(name, value.clone());
                Ok(Some(value))
            }
            StatementKind::CompoundAssignment {
                target,
                operator,
                value,
            } => {
                let name = normalize_variable(parser.text(*target));
                let current = self.variables.get(&name).cloned().unwrap_or(Value::Null);
                let right = self.eval_expression(parser, parser.text(value.range), host, depth)?;
                let value = self.apply_binary(current, operator, right, host, depth);
                self.variables.insert(name, value.clone());
                Ok(Some(value))
            }
            StatementKind::Assignment { target, value } => {
                self.execute_ast_assignment(parser, *target, value, host, depth)
            }
            StatementKind::Redirected {
                command,
                redirections,
            } => self.execute_redirected(
                parser,
                parser.text(command.range),
                redirections,
                host,
                depth,
            ),
            StatementKind::Invocation {
                target,
                arguments,
                dot_source,
            } => self.execute_ast_invocation(parser, target, arguments, *dot_source, host, depth),
            StatementKind::Pipeline(segments) => {
                let mut input = Value::Null;
                for segment in segments {
                    self.variables.insert("input".into(), input.clone());
                    let start = self.emitted_values.len();
                    let result = self.execute_parsed_statement(parser, segment, host, depth)?;
                    let output = self.emitted_values.split_off(start);
                    input = if output.is_empty() {
                        result.unwrap_or(Value::Null)
                    } else {
                        value_from_outputs(output)
                    };
                }
                Ok(Some(input))
            }
            StatementKind::Expression(expression) => self
                .eval_expression(parser, parser.text(expression.range), host, depth)
                .map(Some),
            StatementKind::Command { command, arguments } => {
                self.execute_command_spans(parser, text, *command, arguments, host, depth)
            }
        }
    }

    fn execute_ast_invocation(
        &mut self,
        parser: &ParsedSource,
        target: &crate::ast::Expression,
        arguments: &[crate::ast::Expression],
        dot_source: bool,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Option<Value>, PowerShellError> {
        let target = self.eval_expression(parser, parser.text(target.range), host, depth)?;
        let target_text = target.as_string();
        let evaluated_arguments = arguments
            .iter()
            .map(|argument| {
                self.eval_expression(parser, parser.text(argument.range), host, depth)
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
            return self.execute_source(&decode_utf8(&bytes), host, depth + 1);
        }
        let command_line = std::iter::once(target_text.as_str())
            .chain(evaluated_arguments.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join(" ");
        let origin = if dot_source {
            "PowerShell dot-source operator"
        } else {
            "PowerShell invocation operator"
        };
        Self::spawn_command_line(&command_line, origin, host, depth)?;
        Ok(Some(target))
    }

    fn execute_ast_assignment(
        &mut self,
        parser: &ParsedSource,
        target: crate::tokenizer::Span,
        expression: &crate::ast::Expression,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Option<Value>, PowerShellError> {
        let left = parser.text(target);
        let right = parser.text(expression.range);
        if let Some((type_name, member)) = parse_static_member_access(left) {
            let value = self.eval_expression(parser, right, host, depth)?;
            let key = format!("__static:{}", type_name.to_ascii_lowercase());
            let state = self
                .variables
                .entry(key)
                .or_insert_with(|| Value::Map(std::collections::BTreeMap::default()));
            if let Value::Map(properties) = state {
                properties.insert(member.to_owned(), value.clone());
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
        Ok(Some(value))
    }

    fn execute_ast_if(
        &mut self,
        parser: &ParsedSource,
        statement: &IfStatement,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Option<Value>, PowerShellError> {
        let condition =
            self.eval_expression(parser, parser.text(statement.condition.range), host, depth)?;
        if condition.truthy() {
            return self.execute_script(parser, parser.text(statement.then_body), host, depth + 1);
        }

        if matches!(condition, Value::Null) {
            host.unsupported(
                Engine::PowerShell,
                depth,
                "condition could not be resolved; emulating both branches speculatively",
            );
            let baseline = self.variables.clone();
            let baseline_stdout = self.stdout.len();
            let mut then_branch = self.clone();
            let then_value = then_branch.execute_script(
                parser,
                parser.text(statement.then_body),
                host,
                depth + 1,
            )?;
            let mut else_branch = self.clone();
            let else_value = match &statement.else_branch {
                Some(IfBranch::ElseIf(nested)) => {
                    else_branch.execute_ast_if(parser, nested, host, depth)?
                }
                Some(IfBranch::Else(body)) => {
                    else_branch.execute_script(parser, parser.text(*body), host, depth + 1)?
                }
                None => None,
            };
            self.variables =
                merge_branch_variables(&baseline, &then_branch.variables, &else_branch.variables);
            self.stdout
                .extend(then_branch.stdout.into_iter().skip(baseline_stdout));
            self.stdout
                .extend(else_branch.stdout.into_iter().skip(baseline_stdout));
            return Ok(then_value.or(else_value));
        }
        match &statement.else_branch {
            Some(IfBranch::ElseIf(nested)) => self.execute_ast_if(parser, nested, host, depth),
            Some(IfBranch::Else(body)) => {
                self.execute_script(parser, parser.text(*body), host, depth + 1)
            }
            None => Ok(None),
        }
    }

    fn execute_ast_foreach(
        &mut self,
        parser: &ParsedSource,
        statement: &ForeachStatement,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Option<Value>, PowerShellError> {
        let variable = normalize_variable(parser.text(statement.variable));
        let values =
            self.eval_expression(parser, parser.text(statement.values.range), host, depth)?;
        let values = match values {
            Value::Array(values) => values,
            value => vec![value],
        };
        let mut last = None;
        for (index, value) in values.into_iter().enumerate() {
            if index >= host.limits().max_loop_iterations {
                host.emit(TraceEvent::new(
                    depth,
                    Engine::PowerShell,
                    EventKind::LimitReached,
                    "foreach iteration limit reached",
                ));
                break;
            }
            self.variables.insert(variable.clone(), value);
            last = self.execute_script(parser, parser.text(statement.body), host, depth + 1)?;
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

    fn execute_ast_while(
        &mut self,
        parser: &ParsedSource,
        statement: &WhileStatement,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Option<Value>, PowerShellError> {
        self.execute_ast_loop(
            parser,
            &statement.condition,
            statement.body,
            None,
            false,
            host,
            depth,
        )
    }

    fn execute_ast_for(
        &mut self,
        parser: &ParsedSource,
        statement: &ForStatement,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Option<Value>, PowerShellError> {
        self.execute_parsed_statement(parser, &statement.initialization, host, depth)?;
        self.execute_ast_loop(
            parser,
            &statement.condition,
            statement.body,
            Some(&statement.iteration),
            false,
            host,
            depth,
        )
    }

    fn execute_ast_do(
        &mut self,
        parser: &ParsedSource,
        statement: &DoStatement,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Option<Value>, PowerShellError> {
        let mut last = None;
        for index in 0..host.limits().max_loop_iterations {
            last = self.execute_script(parser, parser.text(statement.body), host, depth + 1)?;
            match self.flow.take() {
                FlowControl::None | FlowControl::Continue => {}
                FlowControl::Break => break,
                flow @ (FlowControl::Return(_) | FlowControl::Exit(_)) => {
                    self.flow = flow;
                    break;
                }
            }
            let matches = self
                .eval_expression(parser, parser.text(statement.condition.range), host, depth)?
                .truthy();
            if matches == statement.until {
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

    fn execute_ast_switch(
        &mut self,
        parser: &ParsedSource,
        statement: &SwitchStatement,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Option<Value>, PowerShellError> {
        let value =
            self.eval_expression(parser, parser.text(statement.condition.range), host, depth)?;
        let values = if statement.input == SwitchInput::File {
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
        let mut last = None;
        let mut matched_any = false;
        for value in values {
            self.variables.insert("_".into(), value.clone());
            for case in &statement.cases {
                let Some(label) = &case.label else {
                    continue;
                };
                let pattern =
                    self.eval_expression(parser, parser.text(label.range), host, depth)?;
                let matched = match statement.matching {
                    SwitchMatching::Regex => {
                        let mut builder = regex::RegexBuilder::new(&pattern.as_string());
                        builder.case_insensitive(!statement.case_sensitive);
                        builder
                            .build()
                            .is_ok_and(|regex| regex.is_match(&value.as_string()))
                    }
                    SwitchMatching::Wildcard => wildcard_match(
                        &value.as_string(),
                        &pattern.as_string(),
                        statement.case_sensitive,
                    ),
                    SwitchMatching::Exact => {
                        values_equal(&value, &pattern, statement.case_sensitive)
                    }
                };
                if matched {
                    matched_any = true;
                    last = self.execute_script(parser, parser.text(case.body), host, depth + 1)?;
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
            if let Some(default) = statement.cases.iter().find(|case| case.label.is_none()) {
                last = self.execute_script(parser, parser.text(default.body), host, depth + 1)?;
            }
        }
        Ok(last)
    }

    fn execute_ast_try(
        &mut self,
        parser: &ParsedSource,
        statement: &TryStatement,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Option<Value>, PowerShellError> {
        let mut result =
            match self.execute_script(parser, parser.text(statement.body), host, depth + 1) {
                Ok(value) => Ok(value),
                Err(error) => {
                    if let Some(catch_body) = statement.catch_body {
                        self.variables
                            .insert("_".into(), Value::String(error.to_string()));
                        self.variables.insert(
                            "error".into(),
                            Value::Array(vec![Value::String(error.to_string())]),
                        );
                        self.execute_script(parser, parser.text(catch_body), host, depth + 1)
                    } else {
                        Err(error)
                    }
                }
            };
        if let Some(finally_body) = statement.finally_body {
            match self.execute_script(parser, parser.text(finally_body), host, depth + 1) {
                Err(error) => result = Err(error),
                Ok(Some(value)) => result = Ok(Some(value)),
                Ok(None) => {}
            }
        }
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_ast_loop(
        &mut self,
        parser: &ParsedSource,
        condition: &crate::ast::Expression,
        body: crate::tokenizer::Span,
        iteration: Option<&Statement>,
        until: bool,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Option<Value>, PowerShellError> {
        let mut last = None;
        for index in 0..host.limits().max_loop_iterations {
            let matches = self
                .eval_expression(parser, parser.text(condition.range), host, depth)?
                .truthy();
            if matches == until {
                break;
            }
            last = self.execute_script(parser, parser.text(body), host, depth + 1)?;
            match self.flow.take() {
                FlowControl::None | FlowControl::Continue => {}
                FlowControl::Break => break,
                flow @ (FlowControl::Return(_) | FlowControl::Exit(_)) => {
                    self.flow = flow;
                    break;
                }
            }
            if let Some(iteration) = iteration {
                self.execute_parsed_statement(parser, iteration, host, depth)?;
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
        let statement =
            crate::statement_parser::parse_statement(parser, statement).ok_or_else(|| {
                PowerShellError::Evaluation("statement is outside parsed source".into())
            })?;
        self.execute_parsed_statement(parser, &statement, host, depth)
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

    fn parsed_statement_emits_value(statement: &Statement) -> bool {
        !matches!(
            statement.kind,
            StatementKind::Assignment { .. }
                | StatementKind::CompoundAssignment { .. }
                | StatementKind::Increment { .. }
                | StatementKind::Invocation { .. }
                | StatementKind::Function { .. }
                | StatementKind::OpaqueDeclaration
                | StatementKind::Param(_)
                | StatementKind::If(_)
                | StatementKind::Foreach(_)
                | StatementKind::While(_)
                | StatementKind::For(_)
                | StatementKind::Switch(_)
                | StatementKind::Do(_)
                | StatementKind::Try(_)
                | StatementKind::Break
                | StatementKind::Continue
        )
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
}
