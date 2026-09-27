use super::{
    find_switch, named_or_positional, wildcard_match, Engine, EventKind, FunctionDefinition, Host,
    PowerShellEmulator, PowerShellError, ProcessIntent, TraceEvent, Value,
};
use crate::parser::ParsedSource;
use crate::provider_paths::{
    add_filesystem_child, display_provider_path, is_absolute_windows_path, item_base,
    join_provider_path, member_bool, member_string, named_value_item, parent_path,
    parse_explicit_provider_path, positional_argument, provider_name, registry_property_path,
    sorted_named_values, Provider, ProviderPath,
};
use emulator_core::normalize_windows_path;
use std::collections::{BTreeMap, BTreeSet};

pub(crate) enum ProviderDispatch {
    NotHandled,
    Handled(Option<Value>),
}

impl PowerShellEmulator {
    #[allow(clippy::too_many_lines)]
    pub(crate) fn execute_provider_command(
        &mut self,
        parser: &ParsedSource,
        command: &str,
        arguments: &[String],
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<ProviderDispatch, PowerShellError> {
        let value = match command {
            "get-item" | "gi" => {
                let path = self.provider_argument(
                    parser,
                    arguments,
                    &["-path", "-literalpath"],
                    0,
                    host,
                    depth,
                )?;
                self.get_provider_item(&path, host, depth)
            }
            "set-item" | "si" => {
                let path = self.provider_argument(
                    parser,
                    arguments,
                    &["-path", "-literalpath"],
                    0,
                    host,
                    depth,
                )?;
                let value = self.provider_value_argument(parser, arguments, 1, host, depth)?;
                self.set_provider_item(&path, value, host, depth)?
            }
            "remove-item" | "del" | "erase" | "rm" | "rmdir" | "ri" => {
                let path = self.provider_argument(
                    parser,
                    arguments,
                    &["-path", "-literalpath"],
                    0,
                    host,
                    depth,
                )?;
                let recurse = find_switch(arguments, "-recurse").is_some();
                Some(Value::Bool(
                    self.remove_provider_item(&path, recurse, host, depth),
                ))
            }
            "get-itemproperty" | "gp" => {
                let path = self.provider_argument(
                    parser,
                    arguments,
                    &["-path", "-literalpath"],
                    0,
                    host,
                    depth,
                )?;
                let name = named_or_positional(arguments, &["-name"], 1)
                    .map(|name| self.eval_expression(parser, &name, host, depth))
                    .transpose()?
                    .map(|name| name.as_string());
                self.get_item_property(&path, name.as_deref(), host, depth)
            }
            "get-itempropertyvalue" => {
                let path = self.provider_argument(
                    parser,
                    arguments,
                    &["-path", "-literalpath"],
                    0,
                    host,
                    depth,
                )?;
                let name = named_or_positional(arguments, &["-name"], 1).unwrap_or_default();
                let name = self
                    .eval_expression(parser, &name, host, depth)?
                    .as_string();
                self.get_item_property(&path, Some(&name), host, depth)
                    .map(|value| Self::read_member(value, &name))
            }
            "set-itemproperty" | "new-itemproperty" | "sp" => {
                let path = self.provider_argument(
                    parser,
                    arguments,
                    &["-path", "-literalpath"],
                    0,
                    host,
                    depth,
                )?;
                let name =
                    named_or_positional(arguments, &["-name"], usize::MAX).unwrap_or_default();
                let name = self
                    .eval_expression(parser, &name, host, depth)?
                    .as_string();
                let value = self.provider_value_argument(parser, arguments, 2, host, depth)?;
                Some(self.set_item_property(&path, &name, value, host, depth))
            }
            "remove-itemproperty" | "rp" => {
                let path = self.provider_argument(
                    parser,
                    arguments,
                    &["-path", "-literalpath"],
                    0,
                    host,
                    depth,
                )?;
                let name = named_or_positional(arguments, &["-name"], 1).unwrap_or_default();
                let name = self
                    .eval_expression(parser, &name, host, depth)?
                    .as_string();
                Some(Value::Bool(
                    self.remove_item_property(&path, &name, host, depth),
                ))
            }
            "get-childitem" | "gci" | "dir" | "ls" => {
                let path = self.provider_argument(
                    parser,
                    arguments,
                    &["-path", "-literalpath"],
                    0,
                    host,
                    depth,
                )?;
                Some(self.get_provider_children(&path, arguments, host, depth))
            }
            "clear-content" | "clc" => {
                let path = self.provider_argument(
                    parser,
                    arguments,
                    &["-path", "-literalpath"],
                    0,
                    host,
                    depth,
                )?;
                let target = self.resolve_provider_path(&path);
                if target.provider == Provider::FileSystem {
                    host.write_file(&target.path, b"", false, Engine::PowerShell, depth)?;
                    self.get_provider_item(&target.path, host, depth)
                } else {
                    host.unsupported(
                        Engine::PowerShell,
                        depth,
                        "Clear-Content is modeled only for the virtual filesystem",
                    );
                    Some(Value::Null)
                }
            }
            "new-temporaryfile" => {
                self.temporary_file_counter = self.temporary_file_counter.saturating_add(1);
                let temp = host
                    .environment("temp")
                    .unwrap_or(r"C:\Users\analysis\AppData\Local\Temp");
                let path = format!(
                    "{}\\emulator-{:04}.tmp",
                    temp.trim_end_matches(['\\', '/']),
                    self.temporary_file_counter
                );
                host.write_file(&path, b"", false, Engine::PowerShell, depth)?;
                Some(Self::file_item(&path, &[], false))
            }
            "invoke-item" | "ii" => {
                let path = self.provider_argument(
                    parser,
                    arguments,
                    &["-path", "-literalpath"],
                    0,
                    host,
                    depth,
                )?;
                let target = self.resolve_provider_path(&path);
                if target.provider == Provider::FileSystem {
                    host.process_intent(ProcessIntent {
                        program: target.path.clone(),
                        args: Vec::new(),
                        command_line: target.path.clone(),
                        origin: "PowerShell Invoke-Item shell association".into(),
                        depth: depth + 1,
                        stdin: Vec::new(),
                        current_directory: self.current_location.clone(),
                    })?;
                    Some(Value::Object("BlockedShellAssociation".into()))
                } else {
                    host.unsupported(
                        Engine::PowerShell,
                        depth,
                        "Invoke-Item requires a virtual filesystem item",
                    );
                    Some(Value::Null)
                }
            }
            "get-location" | "pwd" | "gl" => Some(self.location_value()),
            "set-location" | "cd" | "chdir" | "sl" => {
                let path = self.provider_argument(
                    parser,
                    arguments,
                    &["-path", "-literalpath"],
                    0,
                    host,
                    depth,
                )?;
                self.set_current_location(&path);
                find_switch(arguments, "-passthru")
                    .is_some()
                    .then(|| self.location_value())
            }
            "push-location" | "pushd" => {
                self.location_stack.push(self.current_location.clone());
                let path = self.provider_argument(
                    parser,
                    arguments,
                    &["-path", "-literalpath"],
                    0,
                    host,
                    depth,
                )?;
                self.set_current_location(&path);
                find_switch(arguments, "-passthru")
                    .is_some()
                    .then(|| self.location_value())
            }
            "pop-location" | "popd" => {
                if let Some(path) = self.location_stack.pop() {
                    self.current_location = path;
                    self.sync_pwd();
                }
                find_switch(arguments, "-passthru")
                    .is_some()
                    .then(|| self.location_value())
            }
            "new-item" | "ni" | "mkdir" | "md" => {
                let path = self.provider_argument(parser, arguments, &["-path"], 0, host, depth)?;
                let item_type = if matches!(command, "mkdir" | "md") {
                    "directory".into()
                } else {
                    named_or_positional(arguments, &["-itemtype", "-type"], usize::MAX)
                        .unwrap_or_default()
                        .trim_matches(['\'', '"'])
                        .to_ascii_lowercase()
                };
                let value = self.provider_value_argument(parser, arguments, 1, host, depth)?;
                self.new_provider_item(&path, &item_type, value, host, depth)?
            }
            "unblock-file" => {
                let path = self.provider_argument(
                    parser,
                    arguments,
                    &["-path", "-literalpath"],
                    0,
                    host,
                    depth,
                )?;
                let target = self.resolve_provider_path(&path);
                host.emit(
                    TraceEvent::new(
                        depth,
                        Engine::PowerShell,
                        EventKind::Command,
                        "removed virtual file zone metadata",
                    )
                    .with_data("path", target.path.clone())
                    .with_data("metadata", "Zone.Identifier"),
                );
                self.get_provider_item(&target.path, host, depth)
            }
            "get-authenticodesignature" => {
                let path = self.provider_argument(
                    parser,
                    arguments,
                    &["-filepath", "-literalpath"],
                    0,
                    host,
                    depth,
                )?;
                let target = self.resolve_provider_path(&path);
                let exists = target.provider == Provider::FileSystem
                    && (self
                        .directories
                        .contains_key(&normalize_windows_path(&target.path))
                        || host.directory_exists(&target.path)
                        || host
                            .read_file(&target.path, Engine::PowerShell, depth)
                            .is_some());
                Some(Value::Map(
                    [
                        ("Path".into(), Value::String(target.path.clone())),
                        (
                            "Status".into(),
                            Value::String(if exists { "NotSigned" } else { "UnknownError" }.into()),
                        ),
                        (
                            "StatusMessage".into(),
                            Value::String(
                                if exists {
                                    "The file is not digitally signed."
                                } else {
                                    "The virtual file does not exist."
                                }
                                .into(),
                            ),
                        ),
                        ("SignatureType".into(), Value::String("None".into())),
                        ("IsOSBinary".into(), Value::Bool(false)),
                        ("SignerCertificate".into(), Value::Null),
                        ("TimeStamperCertificate".into(), Value::Null),
                    ]
                    .into_iter()
                    .collect(),
                ))
            }
            _ => return Ok(ProviderDispatch::NotHandled),
        };
        Ok(ProviderDispatch::Handled(value))
    }

    fn provider_argument(
        &mut self,
        parser: &ParsedSource,
        arguments: &[String],
        names: &[&str],
        position: usize,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<String, PowerShellError> {
        let expression =
            named_or_positional(arguments, names, position).unwrap_or_else(|| ".".into());
        if !expression.starts_with('$')
            && !expression.starts_with(['\'', '"'])
            && (expression.contains(':') || expression.starts_with(r"\\"))
        {
            return Ok(expression);
        }
        Ok(self
            .eval_expression(parser, &expression, host, depth)?
            .as_string())
    }

    fn provider_value_argument(
        &mut self,
        parser: &ParsedSource,
        arguments: &[String],
        position: usize,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Value, PowerShellError> {
        let expression = named_or_positional(arguments, &["-value"], usize::MAX)
            .or_else(|| positional_argument(arguments, position))
            .unwrap_or_default();
        self.eval_expression(parser, &expression, host, depth)
    }

    fn get_provider_item(
        &mut self,
        path: &str,
        host: &mut dyn Host,
        depth: usize,
    ) -> Option<Value> {
        let target = self.resolve_provider_path(path);
        match target.provider {
            Provider::FileSystem => {
                let normalized = normalize_windows_path(&target.path);
                if self.directories.contains_key(&normalized) {
                    Some(Self::file_item(&target.path, &[], true))
                } else {
                    host.read_file(&target.path, Engine::PowerShell, depth)
                        .map(|bytes| Self::file_item(&target.path, &bytes, false))
                }
            }
            Provider::Environment => host.environment(&target.path).map(|value| {
                named_value_item("Environment", &target.path, Value::String(value.into()))
            }),
            Provider::Variable => self
                .variables
                .get(&target.path.to_ascii_lowercase())
                .cloned()
                .map(|value| named_value_item("Variable", &target.path, value)),
            Provider::Alias => self
                .aliases
                .get(&target.path.to_ascii_lowercase())
                .cloned()
                .map(|value| named_value_item("Alias", &target.path, Value::String(value))),
            Provider::Function => {
                self.functions
                    .get(&target.path.to_ascii_lowercase())
                    .map(|function| {
                        named_value_item(
                            "Function",
                            &target.path,
                            Value::String(function.body.clone()),
                        )
                    })
            }
            Provider::Registry => {
                let value = host.read_registry(&target.path, Engine::PowerShell, depth);
                let has_children = !host
                    .list_registry(&target.path, Engine::PowerShell, depth)
                    .is_empty();
                (value.is_some() || has_children).then(|| {
                    let mut properties = item_base("Registry", &target.path);
                    properties.insert("(default)".into(), value.map_or(Value::Null, Value::String));
                    Value::Map(properties)
                })
            }
        }
    }

    fn set_provider_item(
        &mut self,
        path: &str,
        value: Value,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Option<Value>, PowerShellError> {
        let target = self.resolve_provider_path(path);
        match target.provider {
            Provider::FileSystem => {
                host.write_file(
                    &target.path,
                    &value.as_bytes(),
                    false,
                    Engine::PowerShell,
                    depth,
                )?;
            }
            Provider::Environment => host.set_environment(&target.path, &value.as_string()),
            Provider::Variable => {
                self.variables
                    .insert(target.path.to_ascii_lowercase(), value.clone());
            }
            Provider::Alias => {
                self.aliases.insert(
                    target.path.to_ascii_lowercase(),
                    value.as_string().to_ascii_lowercase(),
                );
            }
            Provider::Function => {
                let text = value.as_string();
                let body = text
                    .strip_prefix("ScriptBlock:")
                    .unwrap_or(&text)
                    .to_owned();
                let parser = ParsedSource::parse(&body)
                    .map_err(|diagnostic| PowerShellError::Parser(diagnostic.to_string()))?;
                self.functions.insert(
                    target.path.to_ascii_lowercase(),
                    FunctionDefinition::parse(&parser, parser.source()),
                );
            }
            Provider::Registry => {
                host.write_registry(&target.path, &value.as_string(), Engine::PowerShell, depth);
            }
        }
        Ok(self.get_provider_item(path, host, depth).or(Some(value)))
    }

    fn remove_provider_item(
        &mut self,
        path: &str,
        recurse: bool,
        host: &mut dyn Host,
        depth: usize,
    ) -> bool {
        let target = self.resolve_provider_path(path);
        match target.provider {
            Provider::FileSystem => {
                let normalized = normalize_windows_path(&target.path);
                let prefix = format!("{}\\", normalized.trim_end_matches('\\'));
                let listed = host.list_files(&target.path, Engine::PowerShell, depth);
                let descendants = listed
                    .into_iter()
                    .filter(|child| normalize_windows_path(child).starts_with(&prefix))
                    .collect::<Vec<_>>();
                let has_directory_descendants = self
                    .directories
                    .keys()
                    .any(|directory| directory.starts_with(&prefix))
                    || host
                        .list_directories(&target.path, Engine::PowerShell, depth)
                        .iter()
                        .any(|directory| normalize_windows_path(directory).starts_with(&prefix));
                let is_directory = self.directories.contains_key(&normalized)
                    || host.directory_exists(&target.path)
                    || !descendants.is_empty();
                if is_directory
                    && !recurse
                    && (!descendants.is_empty() || has_directory_descendants)
                {
                    host.unsupported(
                        Engine::PowerShell,
                        depth,
                        "Remove-Item requires -Recurse for a non-empty virtual directory",
                    );
                    return false;
                }
                let mut removed = if is_directory {
                    false
                } else {
                    host.delete_file(&target.path, Engine::PowerShell, depth)
                };
                if recurse {
                    let limit = virtual_traversal_limit(host);
                    if descendants.len() > limit {
                        host.emit(
                            TraceEvent::new(
                                depth,
                                Engine::PowerShell,
                                EventKind::LimitReached,
                                "bounded recursive virtual directory removal",
                            )
                            .with_data("limit", limit.to_string()),
                        );
                    }
                    for child in descendants.into_iter().take(limit) {
                        removed |= host.delete_file(&child, Engine::PowerShell, depth);
                    }
                    self.directories
                        .retain(|directory, _| !directory.starts_with(&prefix));
                }
                removed |= self.directories.remove(&normalized).is_some();
                removed |= host.delete_directory(&target.path, recurse, Engine::PowerShell, depth);
                removed
            }
            Provider::Environment => host.remove_environment(&target.path),
            Provider::Variable => self
                .variables
                .remove(&target.path.to_ascii_lowercase())
                .is_some(),
            Provider::Alias => self
                .aliases
                .remove(&target.path.to_ascii_lowercase())
                .is_some(),
            Provider::Function => self
                .functions
                .remove(&target.path.to_ascii_lowercase())
                .is_some(),
            Provider::Registry => {
                host.delete_registry(&target.path, recurse, Engine::PowerShell, depth) > 0
            }
        }
    }

    fn get_item_property(
        &mut self,
        path: &str,
        name: Option<&str>,
        host: &mut dyn Host,
        depth: usize,
    ) -> Option<Value> {
        let target = self.resolve_provider_path(path);
        if target.provider != Provider::Registry {
            return self.get_provider_item(path, host, depth);
        }
        let mut properties = item_base("Registry", &target.path);
        if let Some(name) = name {
            let property_path = registry_property_path(&target.path, name);
            let value = host.read_registry(&property_path, Engine::PowerShell, depth)?;
            properties.insert(name.into(), Value::String(value));
        } else {
            let prefix = format!("{}\\", target.path.trim_end_matches('\\'));
            for (property_path, value) in
                host.list_registry(&target.path, Engine::PowerShell, depth)
            {
                if let Some(property_name) = property_path.strip_prefix(&prefix) {
                    if !property_name.contains('\\') {
                        properties.insert(property_name.into(), Value::String(value));
                    }
                }
            }
        }
        Some(Value::Map(properties))
    }

    fn set_item_property(
        &mut self,
        path: &str,
        name: &str,
        value: Value,
        host: &mut dyn Host,
        depth: usize,
    ) -> Value {
        let target = self.resolve_provider_path(path);
        if target.provider != Provider::Registry {
            host.unsupported(
                Engine::PowerShell,
                depth,
                "Set-ItemProperty is modeled only for the registry provider",
            );
            return Value::Null;
        }
        host.write_registry(
            &registry_property_path(&target.path, name),
            &value.as_string(),
            Engine::PowerShell,
            depth,
        );
        value
    }

    fn remove_item_property(
        &mut self,
        path: &str,
        name: &str,
        host: &mut dyn Host,
        depth: usize,
    ) -> bool {
        let target = self.resolve_provider_path(path);
        target.provider == Provider::Registry
            && host.delete_registry(
                &registry_property_path(&target.path, name),
                false,
                Engine::PowerShell,
                depth,
            ) > 0
    }

    fn get_provider_children(
        &mut self,
        path: &str,
        arguments: &[String],
        host: &mut dyn Host,
        depth: usize,
    ) -> Value {
        let target = self.resolve_provider_path(path);
        let recurse = find_switch(arguments, "-recurse").is_some();
        let names_only = find_switch(arguments, "-name").is_some();
        let filter = named_or_positional(arguments, &["-filter"], usize::MAX)
            .map(|filter| filter.trim_matches(['\'', '"']).to_owned());
        let include = wildcard_patterns(arguments, "-include");
        let exclude = wildcard_patterns(arguments, "-exclude");
        let mut values = match target.provider {
            Provider::FileSystem => self.filesystem_children(&target.path, recurse, host, depth),
            Provider::Environment => host
                .environment_entries()
                .into_iter()
                .map(|(name, value)| named_value_item("Environment", &name, Value::String(value)))
                .collect(),
            Provider::Variable => sorted_named_values("Variable", &self.variables),
            Provider::Alias => self
                .aliases
                .iter()
                .map(|(name, value)| named_value_item("Alias", name, Value::String(value.clone())))
                .collect(),
            Provider::Function => self
                .functions
                .iter()
                .map(|(name, function)| {
                    named_value_item("Function", name, Value::String(function.body.clone()))
                })
                .collect(),
            Provider::Registry => Self::registry_children(&target.path, recurse, host, depth),
        };
        values.sort_by_key(|value| member_string(value, "FullName"));
        if let Some(filter) = filter {
            values.retain(|value| wildcard_match(&member_string(value, "Name"), &filter, false));
        }
        if !include.is_empty() {
            values.retain(|value| {
                let name = member_string(value, "Name");
                include
                    .iter()
                    .any(|pattern| wildcard_match(&name, pattern, false))
            });
        }
        if !exclude.is_empty() {
            values.retain(|value| {
                let name = member_string(value, "Name");
                !exclude
                    .iter()
                    .any(|pattern| wildcard_match(&name, pattern, false))
            });
        }
        if find_switch(arguments, "-file").is_some() {
            values.retain(|value| !member_bool(value, "PSIsContainer"));
        }
        if find_switch(arguments, "-directory").is_some() {
            values.retain(|value| member_bool(value, "PSIsContainer"));
        }
        if names_only {
            Value::Array(
                values
                    .into_iter()
                    .map(|value| Value::String(member_string(&value, "Name")))
                    .collect(),
            )
        } else {
            Value::Array(values)
        }
    }

    fn filesystem_children(
        &mut self,
        path: &str,
        recurse: bool,
        host: &mut dyn Host,
        depth: usize,
    ) -> Vec<Value> {
        let root = normalize_windows_path(path)
            .trim_end_matches('\\')
            .to_owned();
        let mut entries = BTreeMap::<String, bool>::new();
        for file in host.list_files(&root, Engine::PowerShell, depth) {
            if recurse {
                add_filesystem_ancestors(&mut entries, &root, &file);
            }
            add_filesystem_child(&mut entries, &root, &file, false, recurse);
        }
        for directory in self.directories.values() {
            add_filesystem_child(&mut entries, &root, directory, true, recurse);
        }
        for directory in host.list_directories(&root, Engine::PowerShell, depth) {
            add_filesystem_child(&mut entries, &root, &directory, true, recurse);
        }
        let limit = virtual_traversal_limit(host);
        if entries.len() > limit {
            host.emit(
                TraceEvent::new(
                    depth,
                    Engine::PowerShell,
                    EventKind::LimitReached,
                    "bounded virtual filesystem traversal",
                )
                .with_data("limit", limit.to_string()),
            );
        }
        entries
            .into_iter()
            .take(limit)
            .map(|(path, directory)| {
                if directory {
                    Self::file_item(&path, &[], true)
                } else {
                    host.read_file(&path, Engine::PowerShell, depth)
                        .map_or_else(
                            || Self::file_item(&path, &[], false),
                            |bytes| Self::file_item(&path, &bytes, false),
                        )
                }
            })
            .collect()
    }

    fn registry_children(
        path: &str,
        recurse: bool,
        host: &mut dyn Host,
        depth: usize,
    ) -> Vec<Value> {
        let root = path.trim_end_matches('\\');
        let prefix = format!("{root}\\");
        let mut children = BTreeSet::new();
        for (entry, _) in host.list_registry(root, Engine::PowerShell, depth) {
            let Some(remainder) = entry.strip_prefix(&prefix) else {
                continue;
            };
            let child = if recurse {
                entry
            } else {
                let first = remainder.split('\\').next().unwrap_or(remainder);
                format!("{root}\\{first}")
            };
            children.insert(child);
        }
        children
            .into_iter()
            .map(|path| Value::Map(item_base("Registry", &path)))
            .collect()
    }

    fn new_provider_item(
        &mut self,
        path: &str,
        item_type: &str,
        value: Value,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Option<Value>, PowerShellError> {
        let target = self.resolve_provider_path(path);
        if target.provider == Provider::FileSystem && matches!(item_type, "directory" | "container")
        {
            let normalized = normalize_windows_path(&target.path);
            self.directories.insert(normalized, target.path.clone());
            host.create_directory(&target.path, Engine::PowerShell, depth)?;
            return Ok(Some(Self::file_item(&target.path, &[], true)));
        }
        if target.provider == Provider::Registry || item_type == "registrykey" {
            host.write_registry(&target.path, "", Engine::PowerShell, depth);
            return Ok(self.get_provider_item(path, host, depth));
        }
        self.set_provider_item(path, value, host, depth)
    }

    pub(crate) fn resolve_provider_path(&self, input: &str) -> ProviderPath {
        let input = input.trim().trim_matches(['\'', '"']);
        let input = if input.is_empty() || input == "." {
            self.current_location.as_str()
        } else {
            input
        };
        if let Some(path) = parse_explicit_provider_path(input) {
            return path;
        }
        if let Some(current) = parse_explicit_provider_path(&self.current_location) {
            if current.provider != Provider::FileSystem {
                return ProviderPath {
                    provider: current.provider,
                    path: join_provider_path(&current.path, input),
                };
            }
        }
        let path = if is_absolute_windows_path(input) {
            input.to_owned()
        } else if input == ".." {
            parent_path(&self.current_location)
        } else {
            format!(
                "{}\\{}",
                self.current_location.trim_end_matches(['\\', '/']),
                input.trim_start_matches(['\\', '/'])
            )
        };
        ProviderPath {
            provider: Provider::FileSystem,
            path: normalize_windows_path(&path),
        }
    }

    fn set_current_location(&mut self, path: &str) {
        let target = self.resolve_provider_path(path);
        self.current_location = display_provider_path(&target);
        self.sync_pwd();
    }

    fn sync_pwd(&mut self) {
        self.variables
            .insert("pwd".into(), Value::String(self.current_location.clone()));
    }

    fn location_value(&self) -> Value {
        let target = self.resolve_provider_path(&self.current_location);
        Value::Map(
            [
                ("Path".into(), Value::String(self.current_location.clone())),
                (
                    "Provider".into(),
                    Value::String(provider_name(target.provider).into()),
                ),
            ]
            .into_iter()
            .collect(),
        )
    }

    fn file_item(path: &str, bytes: &[u8], directory: bool) -> Value {
        let normalized = normalize_windows_path(path);
        let name = normalized
            .trim_end_matches('\\')
            .rsplit('\\')
            .next()
            .unwrap_or(&normalized)
            .to_owned();
        let directory_name = parent_path(&normalized);
        let extension = if directory {
            String::new()
        } else {
            name.rsplit_once('.')
                .filter(|(stem, extension)| !stem.is_empty() && !extension.is_empty())
                .map_or_else(String::new, |(_, extension)| format!(".{extension}"))
        };
        Value::Map(
            [
                ("__type".into(), Value::String("FileSystemInfo".into())),
                ("PSProvider".into(), Value::String("FileSystem".into())),
                ("PSPath".into(), Value::String(normalized.clone())),
                ("FullName".into(), Value::String(normalized)),
                ("Name".into(), Value::String(name)),
                ("Extension".into(), Value::String(extension)),
                (
                    "Length".into(),
                    Value::Number(i64::try_from(bytes.len()).unwrap_or(i64::MAX)),
                ),
                ("DirectoryName".into(), Value::String(directory_name)),
                ("PSIsContainer".into(), Value::Bool(directory)),
            ]
            .into_iter()
            .collect(),
        )
    }

    pub(crate) fn copy_filesystem_item(
        &mut self,
        source: &str,
        destination: &str,
        move_item: bool,
        recurse: bool,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Option<Value>, PowerShellError> {
        let source = self.resolve_provider_path(source);
        let destination = self.resolve_provider_path(destination);
        if source.provider != Provider::FileSystem || destination.provider != Provider::FileSystem {
            host.unsupported(
                Engine::PowerShell,
                depth,
                "Copy-Item and Move-Item are modeled only for the virtual filesystem",
            );
            return Ok(Some(Value::Null));
        }
        if let Some(bytes) = host.read_file(&source.path, Engine::PowerShell, depth) {
            let destination_path =
                if self.filesystem_directory_exists(&destination.path, host, depth) {
                    format!(
                        "{}\\{}",
                        destination.path.trim_end_matches('\\'),
                        filesystem_leaf(&source.path)
                    )
                } else {
                    destination.path
                };
            host.write_file(&destination_path, &bytes, false, Engine::PowerShell, depth)?;
            if move_item {
                host.delete_file(&source.path, Engine::PowerShell, depth);
            }
            return Ok(Some(Value::String(destination_path)));
        }

        let source_root = normalize_windows_path(&source.path)
            .trim_end_matches('\\')
            .to_owned();
        let source_prefix = format!("{source_root}\\");
        let all_files = host
            .list_files(&source_root, Engine::PowerShell, depth)
            .into_iter()
            .filter(|path| normalize_windows_path(path).starts_with(&source_prefix))
            .collect::<Vec<_>>();
        let is_directory = self.directories.contains_key(&source_root) || !all_files.is_empty();
        if !is_directory {
            return Ok(Some(Value::Null));
        }
        if !recurse {
            host.unsupported(
                Engine::PowerShell,
                depth,
                "Copy-Item and Move-Item require -Recurse for virtual directories",
            );
            return Ok(Some(Value::Null));
        }

        let destination_root = if self.filesystem_directory_exists(&destination.path, host, depth) {
            format!(
                "{}\\{}",
                destination.path.trim_end_matches('\\'),
                filesystem_leaf(&source_root)
            )
        } else {
            normalize_windows_path(&destination.path)
        };
        let limit = virtual_traversal_limit(host);
        if all_files.len() > limit {
            host.emit(
                TraceEvent::new(
                    depth,
                    Engine::PowerShell,
                    EventKind::LimitReached,
                    "bounded recursive virtual directory copy",
                )
                .with_data("limit", limit.to_string()),
            );
        }
        let files = all_files.into_iter().take(limit).collect::<Vec<_>>();
        let directories = self
            .directories
            .keys()
            .filter(|directory| **directory == source_root || directory.starts_with(&source_prefix))
            .cloned()
            .collect::<Vec<_>>();
        self.directories
            .insert(destination_root.clone(), destination_root.clone());
        for directory in &directories {
            let suffix = directory.strip_prefix(&source_root).unwrap_or_default();
            let target = format!("{destination_root}{suffix}");
            self.directories.insert(target.clone(), target);
        }
        for file in &files {
            let normalized = normalize_windows_path(file);
            let suffix = normalized.strip_prefix(&source_root).unwrap_or_default();
            let target = format!("{destination_root}{suffix}");
            if let Some(bytes) = host.read_file(file, Engine::PowerShell, depth) {
                host.write_file(&target, &bytes, false, Engine::PowerShell, depth)?;
            }
        }
        if move_item {
            for file in files {
                host.delete_file(&file, Engine::PowerShell, depth);
            }
            self.directories.retain(|directory, _| {
                directory != &source_root && !directory.starts_with(&source_prefix)
            });
        }
        Ok(Some(Value::String(destination_root)))
    }

    fn filesystem_directory_exists(&self, path: &str, host: &mut dyn Host, depth: usize) -> bool {
        let normalized = normalize_windows_path(path)
            .trim_end_matches('\\')
            .to_owned();
        if self.directories.contains_key(&normalized) {
            return true;
        }
        if host.directory_exists(&normalized) {
            return true;
        }
        let prefix = format!("{normalized}\\");
        host.list_files(&normalized, Engine::PowerShell, depth)
            .iter()
            .any(|file| normalize_windows_path(file).starts_with(&prefix))
    }
}

fn wildcard_patterns(arguments: &[String], name: &str) -> Vec<String> {
    named_or_positional(arguments, &[name], usize::MAX)
        .map(|patterns| {
            patterns
                .trim()
                .trim_start_matches("@(")
                .trim_end_matches(')')
                .split(',')
                .map(|pattern| pattern.trim().trim_matches(['\'', '"']).to_owned())
                .filter(|pattern| !pattern.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn add_filesystem_ancestors(entries: &mut BTreeMap<String, bool>, root: &str, path: &str) {
    let path = normalize_windows_path(path);
    let prefix = format!("{}\\", root.trim_end_matches('\\'));
    let Some(remainder) = path.strip_prefix(&prefix) else {
        return;
    };
    let mut current = root.trim_end_matches('\\').to_owned();
    let mut components = remainder.split('\\').peekable();
    while let Some(component) = components.next() {
        if components.peek().is_none() {
            break;
        }
        current.push('\\');
        current.push_str(component);
        entries.insert(current.clone(), true);
    }
}

fn filesystem_leaf(path: &str) -> &str {
    path.trim_end_matches(['\\', '/'])
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(path)
}

fn virtual_traversal_limit(host: &dyn Host) -> usize {
    host.limits()
        .max_virtual_files
        .min(host.limits().max_loop_iterations)
}
