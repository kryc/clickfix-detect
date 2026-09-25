use crate::com::{self, ComObject};
use crate::expression::{self, Expr};
use crate::host;
use crate::value::Value;
use crate::{ScriptError, ScriptHost, ScriptLanguage, ScriptResult};
use base64::Engine as _;
use emulator_core::{Engine, EventKind, Host, TraceEvent};
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub(crate) struct FunctionDef {
    pub params: Vec<String>,
    pub body: String,
    pub language: ScriptLanguage,
    pub is_sub: bool,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct Runtime {
    variables: BTreeMap<String, Value>,
    pub functions: BTreeMap<String, FunctionDef>,
    pub com_objects: Vec<ComObject>,
    stdout: Vec<String>,
    stderr: Vec<String>,
    diagnostics: Vec<String>,
    exit_code: i32,
    exited: bool,
    language: Option<ScriptLanguage>,
    host_kind: Option<ScriptHost>,
    eval_passes: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Flow {
    Continue,
    Return(Value),
    Break,
}

impl Runtime {
    pub fn prepare(
        &mut self,
        language: ScriptLanguage,
        host_kind: ScriptHost,
        arguments: &[String],
    ) {
        self.stdout.clear();
        self.stderr.clear();
        self.diagnostics.clear();
        self.exit_code = 0;
        self.exited = false;
        self.eval_passes = 0;
        self.language = Some(language);
        self.host_kind = Some(host_kind);
        for (name, value) in host::globals(host_kind, arguments) {
            let name = if language == ScriptLanguage::JScript {
                match name.as_str() {
                    "wscript" => "WScript",
                    "string" => "String",
                    "math" => "Math",
                    _ => name.as_str(),
                }
                .to_owned()
            } else {
                name
            };
            self.variables.insert(name, value);
        }
    }

    pub fn diagnostic(&mut self, message: String) {
        self.diagnostics.push(message);
    }

    pub fn take_result(&self) -> ScriptResult {
        ScriptResult {
            stdout: self.stdout.clone(),
            stderr: self.stderr.clone(),
            exit_code: self.exit_code,
            exited: self.exited,
            diagnostics: self.diagnostics.clone(),
            variables: self
                .variables
                .iter()
                .filter(|(name, _)| !matches!(name.as_str(), "wscript" | "window" | "document"))
                .map(|(name, value)| (name.clone(), value.string()))
                .collect(),
        }
    }

    pub fn define_function(&mut self, name: &str, function: FunctionDef) {
        self.functions.insert(self.normalize(name), function);
    }

    pub fn set_variable(&mut self, name: &str, value: Value, host: &mut dyn Host, depth: usize) {
        let normalized = self.normalize(name);
        host.emit(
            TraceEvent::new(
                depth,
                self.engine(),
                EventKind::VariableAssignment,
                format!("assigned script variable {name}"),
            )
            .with_data("value", value.string()),
        );
        self.variables.insert(normalized, value);
    }

    #[must_use]
    pub fn get_variable(&self, name: &str) -> Value {
        self.variables
            .get(&self.normalize(name))
            .or_else(|| {
                self.variables
                    .iter()
                    .find(|(key, _)| key.eq_ignore_ascii_case(name))
                    .map(|(_, value)| value)
            })
            .cloned()
            .unwrap_or(Value::Undefined)
    }

    pub fn evaluate(
        &mut self,
        source: &str,
        language: ScriptLanguage,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Value, ScriptError> {
        let previous_language = self.language;
        self.language = Some(language);
        let result = expression::parse(source.trim(), language)
            .and_then(|expression| self.eval(&expression, host, depth));
        self.language = previous_language;
        result
    }

    pub fn assign_target(
        &mut self,
        target: &str,
        value: Value,
        language: ScriptLanguage,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<(), ScriptError> {
        let previous_language = self.language;
        self.language = Some(language);
        let result = expression::parse(target.trim(), language)
            .and_then(|expression| self.assign(&expression, value, host, depth));
        self.language = previous_language;
        result
    }

    pub fn execute_decoded(
        &mut self,
        source: &str,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Value, ScriptError> {
        self.eval_script(source, host, depth)
    }

    fn eval(
        &mut self,
        expression: &Expr,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Value, ScriptError> {
        host.consume_step(self.engine(), depth, "evaluating script expression")?;
        match expression {
            Expr::Value(value) => Ok(value.clone()),
            Expr::Ident(name) => Ok(self.get_variable(name)),
            Expr::Array(items) => items
                .iter()
                .map(|item| self.eval(item, host, depth))
                .collect::<Result<Vec<_>, _>>()
                .map(Value::Array),
            Expr::Object(entries) => entries
                .iter()
                .map(|(key, value)| Ok((key.clone(), self.eval(value, host, depth)?)))
                .collect::<Result<BTreeMap<_, _>, _>>()
                .map(Value::Object),
            Expr::Unary(operator, value) => {
                let value = self.eval(value, host, depth)?;
                Ok(eval_unary(operator, &value))
            }
            Expr::Binary(operator, left, right) => {
                let left = self.eval(left, host, depth)?;
                if operator == "&&" && !left.truthy() {
                    return Ok(left);
                }
                if operator == "||" && left.truthy() {
                    return Ok(left);
                }
                let right = self.eval(right, host, depth)?;
                Ok(eval_binary(
                    operator,
                    &left,
                    &right,
                    self.current_language(),
                ))
            }
            Expr::Assign(operator, target, right) => {
                let right = self.eval(right, host, depth)?;
                let value = if operator == "=" {
                    right
                } else {
                    let current = self.eval(target, host, depth)?;
                    eval_binary(
                        operator.trim_end_matches('='),
                        &current,
                        &right,
                        self.current_language(),
                    )
                };
                self.assign(target, value.clone(), host, depth)?;
                Ok(value)
            }
            Expr::Member(target, member) => {
                let value = self.eval(target, host, depth)?;
                Ok(self.get_member(&value, member))
            }
            Expr::Index(target, index) => {
                let value = self.eval(target, host, depth)?;
                let index = self.eval(index, host, depth)?;
                Ok(self.get_member(&value, &index.string()))
            }
            Expr::Call(callee, arguments) | Expr::New(callee, arguments) => {
                let arguments = arguments
                    .iter()
                    .map(|argument| self.eval(argument, host, depth))
                    .collect::<Result<Vec<_>, _>>()?;
                self.call(callee, &arguments, host, depth)
            }
            Expr::Conditional(condition, truthy, falsey) => {
                if self.eval(condition, host, depth)?.truthy() {
                    self.eval(truthy, host, depth)
                } else {
                    self.eval(falsey, host, depth)
                }
            }
        }
    }

    fn assign(
        &mut self,
        target: &Expr,
        value: Value,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<(), ScriptError> {
        match target {
            Expr::Ident(name) => {
                self.set_variable(name, value, host, depth);
                Ok(())
            }
            Expr::Member(receiver, member) => {
                let receiver = self.eval(receiver, host, depth)?;
                self.set_member(receiver, member, value, host, depth)
            }
            Expr::Index(receiver, index) => {
                let receiver = self.eval(receiver, host, depth)?;
                let index = self.eval(index, host, depth)?.string();
                self.set_member(receiver, &index, value, host, depth)
            }
            _ => Err(ScriptError::Syntax("invalid assignment target".into())),
        }
    }

    fn call(
        &mut self,
        callee: &Expr,
        arguments: &[Value],
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Value, ScriptError> {
        match callee {
            Expr::Ident(name) => self.call_global(name, arguments, host, depth),
            Expr::Member(receiver, member) => {
                let receiver = self.eval(receiver, host, depth)?;
                self.call_member(receiver, member, arguments, host, depth)
            }
            Expr::Index(receiver, member) => {
                let receiver = self.eval(receiver, host, depth)?;
                let member = self.eval(member, host, depth)?.string();
                self.call_member(receiver, &member, arguments, host, depth)
            }
            _ => Ok(Value::Undefined),
        }
    }

    fn call_global(
        &mut self,
        name: &str,
        arguments: &[Value],
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Value, ScriptError> {
        let normalized = self.normalize(name);
        if let Some(function) = self.functions.get(&normalized).cloned() {
            return self.call_user_function(name, &function, arguments, host, depth + 1);
        }
        let builtin = name.to_ascii_lowercase();
        match builtin.as_str() {
            "activexobject" | "createobject" | "getobject" => {
                let program_id = argument(arguments, 0).string();
                Ok(Value::Com(com::create(self, &program_id)))
            }
            "array" => Ok(Value::Array(arguments.to_vec())),
            "ubound" => Ok(Value::Number(
                as_array(argument(arguments, 0)).len().saturating_sub(1) as f64,
            )),
            "lbound" => Ok(Value::Number(0.0)),
            "eval" => self.eval_script(&argument(arguments, 0).string(), host, depth + 1),
            "execute" | "executeglobal" => {
                self.eval_script(&argument(arguments, 0).string(), host, depth + 1)?;
                Ok(Value::Undefined)
            }
            "parseint" | "cint" | "clng" => {
                let text = argument(arguments, 0).string();
                let radix = argument(arguments, 1).number();
                let radix = if radix.is_nan() { 10 } else { radix as u32 };
                Ok(Value::Number(
                    i64::from_str_radix(text.trim().trim_start_matches("0x"), radix.clamp(2, 36))
                        .unwrap_or_default() as f64,
                ))
            }
            "chr" | "chrw" => Ok(Value::String(
                char::from_u32(argument(arguments, 0).number() as u32)
                    .unwrap_or('\u{fffd}')
                    .to_string(),
            )),
            "asc" => Ok(Value::Number(
                argument(arguments, 0)
                    .string()
                    .chars()
                    .next()
                    .map_or(0, u32::from) as f64,
            )),
            "mid" => Ok(vb_mid(arguments)),
            "left" => Ok(Value::String(
                argument(arguments, 0)
                    .string()
                    .chars()
                    .take(argument(arguments, 1).number().max(0.0) as usize)
                    .collect(),
            )),
            "right" => {
                let text = argument(arguments, 0).string();
                let count = argument(arguments, 1).number().max(0.0) as usize;
                Ok(Value::String(
                    text.chars()
                        .skip(text.chars().count().saturating_sub(count))
                        .collect(),
                ))
            }
            "replace" => Ok(Value::String(argument(arguments, 0).string().replace(
                &argument(arguments, 1).string(),
                &argument(arguments, 2).string(),
            ))),
            "split" => Ok(Value::Array(
                argument(arguments, 0)
                    .string()
                    .split(&argument(arguments, 1).string())
                    .map(|part| Value::String(part.into()))
                    .collect(),
            )),
            "join" => Ok(Value::String(
                as_array(argument(arguments, 0))
                    .iter()
                    .map(Value::string)
                    .collect::<Vec<_>>()
                    .join(&argument(arguments, 1).string()),
            )),
            "strreverse" => Ok(Value::String(
                argument(arguments, 0).string().chars().rev().collect(),
            )),
            "hex" => Ok(Value::String(format!(
                "{:X}",
                argument(arguments, 0).number() as i64
            ))),
            "atob" => Ok(Value::String(
                String::from_utf8_lossy(
                    &base64::engine::general_purpose::STANDARD
                        .decode(argument(arguments, 0).string())
                        .unwrap_or_default(),
                )
                .into_owned(),
            )),
            "btoa" => Ok(Value::String(
                base64::engine::general_purpose::STANDARD
                    .encode(argument(arguments, 0).string().as_bytes()),
            )),
            "escape" | "encodeuricomponent" => Ok(Value::String(
                urlencoding::encode(&argument(arguments, 0).string()).into_owned(),
            )),
            "unescape" | "decodeuricomponent" => Ok(Value::String(
                urlencoding::decode(&argument(arguments, 0).string()).map_or_else(
                    |_| argument(arguments, 0).string(),
                    |value| value.into_owned(),
                ),
            )),
            _ => {
                host.unsupported(
                    self.engine(),
                    depth,
                    &format!("unsupported script function {name}"),
                );
                Ok(Value::Undefined)
            }
        }
    }

    fn call_member(
        &mut self,
        receiver: Value,
        member: &str,
        arguments: &[Value],
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Value, ScriptError> {
        let lower = member.to_ascii_lowercase();
        if let Value::Com(id) = receiver {
            return com::call(self, id, &lower, arguments, host, depth);
        }
        if let Value::Object(object) = &receiver {
            let kind = object.get("__kind").map(Value::string).unwrap_or_default();
            match (kind.as_str(), lower.as_str()) {
                ("wscript", "echo") => {
                    let output = arguments
                        .iter()
                        .map(Value::string)
                        .collect::<Vec<_>>()
                        .join(" ");
                    self.stdout.push(output.clone());
                    host.emit(TraceEvent::new(
                        depth,
                        self.engine(),
                        EventKind::Output,
                        output,
                    ));
                    return Ok(Value::Undefined);
                }
                ("wscript", "sleep") => return Ok(Value::Undefined),
                ("wscript", "quit") => {
                    self.exit_code = argument(arguments, 0).number() as i32;
                    self.exited = true;
                    return Ok(Value::Undefined);
                }
                ("wscript", "createobject") | ("wscript", "getobject") => {
                    return Ok(Value::Com(com::create(
                        self,
                        &argument(arguments, 0).string(),
                    )));
                }
                ("wscript", "arguments") => {
                    let values = object
                        .get("arguments")
                        .and_then(|value| match value {
                            Value::Array(values) => Some(values),
                            _ => None,
                        })
                        .cloned()
                        .unwrap_or_default();
                    return Ok(values
                        .get(argument(arguments, 0).number().max(0.0) as usize)
                        .cloned()
                        .unwrap_or(Value::Undefined));
                }
                ("string_constructor", "fromcharcode") => {
                    return Ok(Value::String(
                        arguments
                            .iter()
                            .map(|value| {
                                char::from_u32(value.number() as u32).unwrap_or('\u{fffd}')
                            })
                            .collect(),
                    ));
                }
                ("document", "write" | "writeln") => {
                    let output = argument(arguments, 0).string();
                    self.stdout.push(output.clone());
                    host.emit(TraceEvent::new(
                        depth,
                        self.engine(),
                        EventKind::Output,
                        output,
                    ));
                    return Ok(Value::Undefined);
                }
                ("window", "close") => {
                    self.exited = true;
                    return Ok(Value::Undefined);
                }
                _ => {}
            }
        }
        match (&receiver, lower.as_str()) {
            (Value::String(text), "charcodeat") => Ok(Value::Number(
                text.chars()
                    .nth(argument(arguments, 0).number().max(0.0) as usize)
                    .map_or(f64::NAN, |value| u32::from(value) as f64),
            )),
            (Value::String(text), "substring" | "substr" | "slice") => {
                Ok(Value::String(string_slice(text, &lower, arguments)))
            }
            (Value::String(text), "split") => Ok(Value::Array(
                text.split(&argument(arguments, 0).string())
                    .map(|part| Value::String(part.into()))
                    .collect(),
            )),
            (Value::String(text), "replace") => Ok(Value::String(text.replacen(
                &argument(arguments, 0).string(),
                &argument(arguments, 1).string(),
                1,
            ))),
            (Value::String(text), "tolowercase") => Ok(Value::String(text.to_lowercase())),
            (Value::String(text), "touppercase") => Ok(Value::String(text.to_uppercase())),
            (Value::Array(values), "join") => Ok(Value::String(
                values
                    .iter()
                    .map(Value::string)
                    .collect::<Vec<_>>()
                    .join(&argument(arguments, 0).string()),
            )),
            (Value::Array(values), "reverse") => {
                let mut values = values.clone();
                values.reverse();
                Ok(Value::Array(values))
            }
            (Value::Array(values), "item") => Ok(values
                .get(argument(arguments, 0).number().max(0.0) as usize)
                .cloned()
                .unwrap_or(Value::Undefined)),
            (Value::Array(values), "push") => {
                Ok(Value::Number((values.len() + arguments.len()) as f64))
            }
            _ => {
                host.unsupported(
                    self.engine(),
                    depth,
                    &format!("unsupported script member call {member}"),
                );
                Ok(Value::Undefined)
            }
        }
    }

    pub fn get_member(&self, receiver: &Value, member: &str) -> Value {
        let lower = member.to_ascii_lowercase();
        match receiver {
            Value::String(text) if lower == "length" => Value::Number(text.chars().count() as f64),
            Value::Array(values) if lower == "length" || lower == "count" => {
                Value::Number(values.len() as f64)
            }
            Value::Array(values) => member
                .parse::<usize>()
                .ok()
                .and_then(|index| values.get(index).cloned())
                .unwrap_or(Value::Undefined),
            Value::Object(values) => values
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(member))
                .map_or(Value::Undefined, |(_, value)| value.clone()),
            Value::Com(id) => com::get(self, *id, &lower),
            _ => Value::Undefined,
        }
    }

    fn set_member(
        &mut self,
        receiver: Value,
        member: &str,
        value: Value,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<(), ScriptError> {
        if let Value::Com(id) = receiver {
            com::set(self, id, &member.to_ascii_lowercase(), value, host, depth)?;
        } else if member.eq_ignore_ascii_case("location") {
            self.variables.insert("location".into(), value);
        }
        Ok(())
    }

    fn call_user_function(
        &mut self,
        name: &str,
        function: &FunctionDef,
        arguments: &[Value],
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Value, ScriptError> {
        let saved = function
            .params
            .iter()
            .map(|param| {
                let key = self.normalize(param);
                (key.clone(), self.variables.get(&key).cloned())
            })
            .collect::<Vec<_>>();
        for (index, param) in function.params.iter().enumerate() {
            self.set_variable(
                param,
                arguments.get(index).cloned().unwrap_or(Value::Undefined),
                host,
                depth,
            );
        }
        if function.language == ScriptLanguage::VBScript {
            self.set_variable(name, Value::Undefined, host, depth);
        }
        let flow = execute_source(&function.body, function.language, self, host, depth)?;
        let value = match flow {
            Flow::Return(value) => value,
            _ if function.language == ScriptLanguage::VBScript && !function.is_sub => {
                self.get_variable(name)
            }
            _ => Value::Undefined,
        };
        for (key, previous) in saved {
            if let Some(previous) = previous {
                self.variables.insert(key, previous);
            } else {
                self.variables.remove(&key);
            }
        }
        Ok(value)
    }

    fn eval_script(
        &mut self,
        source: &str,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Value, ScriptError> {
        if self.eval_passes >= host.limits().max_decode_passes {
            host.unsupported(self.engine(), depth, "decoded eval pass limit reached");
            return Ok(Value::Undefined);
        }
        self.eval_passes += 1;
        host.emit(
            TraceEvent::new(
                depth,
                self.engine(),
                EventKind::Decode,
                "executing decoded script text",
            )
            .with_data("pass", self.eval_passes.to_string())
            .with_data("bytes", source.len().to_string()),
        );
        match execute_source(source, self.current_language(), self, host, depth)? {
            Flow::Return(value) => Ok(value),
            _ => Ok(Value::Undefined),
        }
    }

    fn normalize(&self, name: &str) -> String {
        if self.current_language() == ScriptLanguage::VBScript {
            name.to_ascii_lowercase()
        } else {
            name.into()
        }
    }

    fn current_language(&self) -> ScriptLanguage {
        self.language.unwrap_or(ScriptLanguage::JScript)
    }

    pub fn engine(&self) -> Engine {
        match self.host_kind.unwrap_or(ScriptHost::WScript) {
            ScriptHost::Mshta => Engine::Mshta,
            _ => Engine::Wscript,
        }
    }

    #[must_use]
    pub fn exited(&self) -> bool {
        self.exited
    }
}

pub(crate) fn execute_source(
    source: &str,
    language: ScriptLanguage,
    runtime: &mut Runtime,
    host: &mut dyn Host,
    depth: usize,
) -> Result<Flow, ScriptError> {
    match language {
        ScriptLanguage::JScript => crate::jscript::execute(source, runtime, host, depth),
        ScriptLanguage::VBScript => crate::vbscript::execute(source, runtime, host, depth),
    }
}

fn argument(arguments: &[Value], index: usize) -> Value {
    arguments.get(index).cloned().unwrap_or(Value::Undefined)
}

fn as_array(value: Value) -> Vec<Value> {
    match value {
        Value::Array(values) => values,
        other => vec![other],
    }
}

fn eval_unary(operator: &str, value: &Value) -> Value {
    match operator {
        "!" | "not" => Value::Bool(!value.truthy()),
        "~" => Value::Number((!(value.number() as i32)) as f64),
        "-" => Value::Number(-value.number()),
        "+" => Value::Number(value.number()),
        _ => Value::Undefined,
    }
}

fn eval_binary(operator: &str, left: &Value, right: &Value, language: ScriptLanguage) -> Value {
    match operator {
        "+" if language == ScriptLanguage::JScript
            && (matches!(left, Value::String(_)) || matches!(right, Value::String(_))) =>
        {
            Value::String(format!("{}{}", left.string(), right.string()))
        }
        "+" => Value::Number(left.number() + right.number()),
        "-" => Value::Number(left.number() - right.number()),
        "*" => Value::Number(left.number() * right.number()),
        "/" => Value::Number(left.number() / right.number()),
        "%" | "mod" => Value::Number(left.number() % right.number()),
        "&" if language == ScriptLanguage::VBScript => {
            Value::String(format!("{}{}", left.string(), right.string()))
        }
        "&" => Value::Number(((left.number() as i32) & (right.number() as i32)) as f64),
        "|" => Value::Number(((left.number() as i32) | (right.number() as i32)) as f64),
        "^" | "xor" => Value::Number(((left.number() as i32) ^ (right.number() as i32)) as f64),
        "<<" => Value::Number(((left.number() as i32) << (right.number() as u32)) as f64),
        ">>" | ">>>" => Value::Number(((left.number() as i32) >> (right.number() as u32)) as f64),
        "==" | "===" | "=" => Value::Bool(left.string() == right.string()),
        "!=" | "!==" | "<>" => Value::Bool(left.string() != right.string()),
        "<" => Value::Bool(left.number() < right.number()),
        "<=" => Value::Bool(left.number() <= right.number()),
        ">" => Value::Bool(left.number() > right.number()),
        ">=" => Value::Bool(left.number() >= right.number()),
        "&&" | "and" => Value::Bool(left.truthy() && right.truthy()),
        "||" | "or" => Value::Bool(left.truthy() || right.truthy()),
        _ => Value::Undefined,
    }
}

fn string_slice(text: &str, method: &str, arguments: &[Value]) -> String {
    let chars = text.chars().collect::<Vec<_>>();
    let length = chars.len() as isize;
    let mut start = argument(arguments, 0).number() as isize;
    if start < 0 && method == "slice" {
        start += length;
    }
    start = start.clamp(0, length);
    let end = if method == "substr" {
        start + argument(arguments, 1).number().max(0.0) as isize
    } else {
        let mut value = if arguments.len() > 1 {
            argument(arguments, 1).number() as isize
        } else {
            length
        };
        if value < 0 && method == "slice" {
            value += length;
        }
        value
    }
    .clamp(start, length);
    chars[start as usize..end as usize].iter().collect()
}

fn vb_mid(arguments: &[Value]) -> Value {
    let text = argument(arguments, 0).string();
    let start = (argument(arguments, 1).number() as usize).saturating_sub(1);
    let count = if arguments.len() > 2 {
        argument(arguments, 2).number().max(0.0) as usize
    } else {
        usize::MAX
    };
    Value::String(text.chars().skip(start).take(count).collect())
}
