use clickfix_detect::{Detector, DetectorInput};
use serde::Serialize;
use wasm_bindgen::prelude::*;

#[derive(Debug, Clone, Copy)]
enum InputMode {
    Auto,
    Command,
    PowerShell,
}

impl InputMode {
    fn parse(value: &str) -> Result<Self, JsValue> {
        match value.to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "command" | "cmd" => Ok(Self::Command),
            "powershell" | "ps1" => Ok(Self::PowerShell),
            _ => Err(JsValue::from_str(
                "input kind must be auto, command, or powershell",
            )),
        }
    }
}

#[derive(Serialize)]
struct WasmAnalysis<T> {
    input_kind: &'static str,
    report: T,
}

/// Analyze one payload and return the complete detector report as a JavaScript value.
///
/// # Errors
///
/// Returns a JavaScript error when the input kind is invalid, analysis fails,
/// or the report cannot be converted to a JavaScript value.
#[wasm_bindgen]
pub fn analyze_payload(payload: &str, input_kind: &str) -> Result<JsValue, JsValue> {
    let mode = InputMode::parse(input_kind)?;
    let (kind, input) = match mode {
        InputMode::PowerShell => ("powershell", DetectorInput::powershell_script(payload)),
        InputMode::Auto if looks_like_powershell(payload) => {
            ("powershell", DetectorInput::powershell_script(payload))
        }
        InputMode::Auto | InputMode::Command => ("command", DetectorInput::raw_command(payload)),
    };
    let report = Detector::default()
        .analyze(input)
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    serde_wasm_bindgen::to_value(&WasmAnalysis {
        input_kind: kind,
        report,
    })
    .map_err(|error| JsValue::from_str(&error.to_string()))
}

#[wasm_bindgen]
#[must_use]
pub fn detector_version() -> String {
    env!("CARGO_PKG_VERSION").into()
}

fn looks_like_powershell(content: &str) -> bool {
    let lowercase = content.to_ascii_lowercase();
    content.contains('\n')
        || content.trim_start().starts_with('$')
        || lowercase.contains("invoke-webrequest")
        || lowercase.contains("invoke-restmethod")
        || lowercase.contains("invoke-expression")
        || lowercase.contains("set-content")
        || lowercase.contains("[system.")
        || lowercase.contains("[text.")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_mode_recognizes_powershell() {
        assert!(looks_like_powershell(
            "Invoke-WebRequest https://example.invalid"
        ));
        assert!(!looks_like_powershell("mshta https://example.invalid"));
    }
}
