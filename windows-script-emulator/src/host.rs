use crate::value::Value;
use crate::ScriptHost;
use std::collections::BTreeMap;

pub(crate) fn globals(host: ScriptHost, arguments: &[String]) -> BTreeMap<String, Value> {
    let mut globals = BTreeMap::new();
    let mut wscript = BTreeMap::new();
    wscript.insert("__kind".into(), Value::String("wscript".into()));
    wscript.insert(
        "arguments".into(),
        Value::Array(arguments.iter().cloned().map(Value::String).collect()),
    );
    wscript.insert(
        "fullname".into(),
        Value::String(
            match host {
                ScriptHost::CScript => r"C:\Windows\System32\cscript.exe",
                _ => r"C:\Windows\System32\wscript.exe",
            }
            .into(),
        ),
    );
    globals.insert("wscript".into(), Value::Object(wscript));
    globals.insert("string".into(), object_with_kind("string_constructor"));
    globals.insert("math".into(), object_with_kind("math"));
    if host == ScriptHost::Mshta {
        globals.insert("window".into(), object_with_kind("window"));
        globals.insert("document".into(), object_with_kind("document"));
        globals.insert("location".into(), Value::String("about:blank".into()));
    }
    globals
}

fn object_with_kind(kind: &str) -> Value {
    Value::Object(BTreeMap::from([(
        "__kind".into(),
        Value::String(kind.into()),
    )]))
}
