use super::Value;
use emulator_core::normalize_windows_path;
use std::collections::{BTreeMap, HashMap};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Provider {
    FileSystem,
    Environment,
    Variable,
    Alias,
    Function,
    Registry,
}

#[derive(Debug)]
pub(crate) struct ProviderPath {
    pub(crate) provider: Provider,
    pub(crate) path: String,
}

pub(crate) fn parse_explicit_provider_path(input: &str) -> Option<ProviderPath> {
    let normalized = input.replace('/', "\\");
    let lower = normalized.to_ascii_lowercase();
    for (prefix, provider) in [
        ("env:", Provider::Environment),
        ("environment:", Provider::Environment),
        ("variable:", Provider::Variable),
        ("alias:", Provider::Alias),
        ("function:", Provider::Function),
    ] {
        if lower.starts_with(prefix) {
            return Some(ProviderPath {
                provider,
                path: normalized[prefix.len()..]
                    .trim_start_matches('\\')
                    .to_owned(),
            });
        }
    }
    for (prefix, root) in [
        ("registry::hkey_current_user", "HKCU"),
        ("registry::hkey_local_machine", "HKLM"),
        ("hkey_current_user", "HKCU"),
        ("hkey_local_machine", "HKLM"),
        ("hkcu:", "HKCU"),
        ("hklm:", "HKLM"),
        ("hkcu\\", "HKCU"),
        ("hklm\\", "HKLM"),
    ] {
        if lower.starts_with(prefix) {
            let suffix = normalized[prefix.len()..].trim_start_matches('\\');
            return Some(ProviderPath {
                provider: Provider::Registry,
                path: if suffix.is_empty() {
                    root.into()
                } else {
                    format!("{root}\\{suffix}").to_ascii_lowercase()
                },
            });
        }
    }
    if lower == "hkcu" || lower == "hklm" {
        return Some(ProviderPath {
            provider: Provider::Registry,
            path: normalized.to_ascii_lowercase(),
        });
    }
    (normalized.len() >= 2 && normalized.as_bytes()[1] == b':').then(|| ProviderPath {
        provider: Provider::FileSystem,
        path: normalize_windows_path(&normalized),
    })
}

pub(crate) fn display_provider_path(path: &ProviderPath) -> String {
    match path.provider {
        Provider::FileSystem => path.path.clone(),
        Provider::Environment => format!("Env:\\{}", path.path),
        Provider::Variable => format!("Variable:\\{}", path.path),
        Provider::Alias => format!("Alias:\\{}", path.path),
        Provider::Function => format!("Function:\\{}", path.path),
        Provider::Registry => {
            let (root, rest) = path.path.split_once('\\').unwrap_or((&path.path, ""));
            if rest.is_empty() {
                format!("{root}:\\")
            } else {
                format!("{root}:\\{rest}")
            }
        }
    }
}

pub(crate) fn provider_name(provider: Provider) -> &'static str {
    match provider {
        Provider::FileSystem => "FileSystem",
        Provider::Environment => "Environment",
        Provider::Variable => "Variable",
        Provider::Alias => "Alias",
        Provider::Function => "Function",
        Provider::Registry => "Registry",
    }
}

pub(crate) fn named_value_item(provider: &str, name: &str, value: Value) -> Value {
    Value::Map(
        [
            ("__type".into(), Value::String(format!("{provider}Item"))),
            ("PSProvider".into(), Value::String(provider.into())),
            (
                "PSPath".into(),
                Value::String(format!("{provider}:\\{name}")),
            ),
            ("FullName".into(), Value::String(name.into())),
            ("Name".into(), Value::String(name.into())),
            ("Value".into(), value),
            ("PSIsContainer".into(), Value::Bool(false)),
        ]
        .into_iter()
        .collect(),
    )
}

pub(crate) fn item_base(provider: &str, path: &str) -> BTreeMap<String, Value> {
    let name = path.rsplit('\\').next().unwrap_or(path);
    [
        ("__type".into(), Value::String(format!("{provider}Item"))),
        ("PSProvider".into(), Value::String(provider.into())),
        ("PSPath".into(), Value::String(path.into())),
        ("FullName".into(), Value::String(path.into())),
        ("Name".into(), Value::String(name.into())),
        ("PSIsContainer".into(), Value::Bool(true)),
    ]
    .into_iter()
    .collect()
}

pub(crate) fn sorted_named_values(provider: &str, values: &HashMap<String, Value>) -> Vec<Value> {
    let mut names = values.keys().collect::<Vec<_>>();
    names.sort();
    names
        .into_iter()
        .filter(|name| name.as_str() != "input")
        .map(|name| named_value_item(provider, name, values[name].clone()))
        .collect()
}

pub(crate) fn add_filesystem_child(
    entries: &mut BTreeMap<String, bool>,
    root: &str,
    path: &str,
    directory: bool,
    recurse: bool,
) {
    let path = normalize_windows_path(path);
    let prefix = format!("{}\\", root.trim_end_matches('\\'));
    let Some(remainder) = path.strip_prefix(&prefix) else {
        return;
    };
    if remainder.is_empty() {
        return;
    }
    if recurse || !remainder.contains('\\') {
        entries.insert(path, directory);
    } else if let Some(first) = remainder.split('\\').next() {
        entries.insert(format!("{root}\\{first}"), true);
    }
}

pub(crate) fn registry_property_path(path: &str, name: &str) -> String {
    format!(
        "{}\\{}",
        path.trim_end_matches('\\'),
        name.trim_matches(['\\', '/', '\'', '"'])
    )
}

pub(crate) fn join_provider_path(parent: &str, child: &str) -> String {
    if child == "." || child.is_empty() {
        parent.into()
    } else if child == ".." {
        parent_path(parent)
    } else if parent.is_empty() {
        child.trim_start_matches(['\\', '/']).into()
    } else {
        format!(
            "{}\\{}",
            parent.trim_end_matches('\\'),
            child.trim_start_matches(['\\', '/'])
        )
    }
}

pub(crate) fn parent_path(path: &str) -> String {
    let path = path.trim_end_matches(['\\', '/']);
    path.rsplit_once(['\\', '/'])
        .map_or_else(|| path.into(), |(parent, _)| parent.into())
}

pub(crate) fn is_absolute_windows_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 3 && bytes[1] == b':' && matches!(bytes[2], b'\\' | b'/')
}

pub(crate) fn positional_argument(arguments: &[String], position: usize) -> Option<String> {
    let mut positional = Vec::new();
    let mut skip = false;
    for argument in arguments {
        if skip {
            skip = false;
            continue;
        }
        if matches!(
            argument.to_ascii_lowercase().as_str(),
            "-path" | "-literalpath" | "-value" | "-itemtype" | "-type" | "-name"
        ) {
            skip = true;
        } else if !argument.starts_with('-') {
            positional.push(argument.clone());
        }
    }
    positional.get(position).cloned()
}

pub(crate) fn member_string(value: &Value, member: &str) -> String {
    if let Value::Map(values) = value {
        return values
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(member))
            .map_or_else(String::new, |(_, value)| value.as_string());
    }
    String::new()
}

pub(crate) fn member_bool(value: &Value, member: &str) -> bool {
    if let Value::Map(values) = value {
        return values
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(member))
            .is_some_and(|(_, value)| value.truthy());
    }
    false
}
