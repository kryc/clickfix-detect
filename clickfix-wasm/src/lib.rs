use clickfix_detect::{AnalysisMode, Detector, DetectorInput, InputKind};
use serde::Serialize;
use wasm_bindgen::prelude::*;

#[derive(Debug, Clone, Copy)]
enum InputMode {
    Auto,
    Command,
    PowerShell,
    Bash,
    LinuxBash,
}

impl InputMode {
    fn parse(value: &str) -> Result<Self, JsValue> {
        match value.to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "command" | "cmd" => Ok(Self::Command),
            "powershell" | "ps1" => Ok(Self::PowerShell),
            "bash" | "sh" | "zsh" => Ok(Self::Bash),
            "linux" | "linux-bash" => Ok(Self::LinuxBash),
            _ => Err(JsValue::from_str(
                "input kind must be auto, command, powershell, bash, or linux-bash",
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
    analyze_payload_with_mode(payload, input_kind, AnalysisMode::HotPath)
}

/// Analyze one payload without allowing the prefilter to skip emulation.
///
/// # Errors
///
/// Returns a JavaScript error when the input kind is invalid, analysis fails,
/// or the report cannot be converted to a JavaScript value.
#[wasm_bindgen]
pub fn analyze_payload_thorough(payload: &str, input_kind: &str) -> Result<JsValue, JsValue> {
    analyze_payload_with_mode(payload, input_kind, AnalysisMode::Thorough)
}

fn analyze_payload_with_mode(
    payload: &str,
    input_kind: &str,
    analysis_mode: AnalysisMode,
) -> Result<JsValue, JsValue> {
    let mode = InputMode::parse(input_kind)?;
    let kind = match mode {
        InputMode::PowerShell => InputKind::PowerShellScript,
        InputMode::Bash => InputKind::BashScript,
        InputMode::LinuxBash => InputKind::LinuxShellScript,
        InputMode::Command => InputKind::RawCommand,
        InputMode::Auto => Detector::infer_input_kind(payload),
    };
    let (kind_name, input) = match kind {
        InputKind::PowerShellScript => ("powershell", DetectorInput::powershell_script(payload)),
        InputKind::BashScript => ("bash", DetectorInput::bash_script(payload)),
        InputKind::LinuxShellScript => ("linux-bash", DetectorInput::linux_shell_script(payload)),
        InputKind::RawCommand => ("command", DetectorInput::raw_command(payload)),
    };
    let report = Detector::default()
        .analyze_with_mode(input, analysis_mode)
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    serde_wasm_bindgen::to_value(&WasmAnalysis {
        input_kind: kind_name,
        report,
    })
    .map_err(|error| JsValue::from_str(&error.to_string()))
}

/// Classify clipboard text before full detector analysis.
///
/// # Errors
///
/// Returns a JavaScript error when the prefilter result cannot be converted to
/// a JavaScript value.
#[wasm_bindgen]
pub fn prefilter_payload(payload: &str) -> Result<JsValue, JsValue> {
    serde_wasm_bindgen::to_value(&Detector::prefilter(payload))
        .map_err(|error| JsValue::from_str(&error.to_string()))
}

#[wasm_bindgen]
#[must_use]
pub fn detector_version() -> String {
    env!("CARGO_PKG_VERSION").into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_mode_recognizes_script_kinds() {
        assert_eq!(
            Detector::infer_input_kind("Invoke-WebRequest https://example.invalid"),
            InputKind::PowerShellScript
        );
        assert_eq!(
            Detector::infer_input_kind("mshta https://example.invalid"),
            InputKind::RawCommand
        );
        assert_eq!(
            Detector::infer_input_kind("name=world; echo \"$name\""),
            InputKind::LinuxShellScript
        );
    }
}
