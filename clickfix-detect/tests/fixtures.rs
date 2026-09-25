use clickfix_detect::{Detector, DetectorInput, Verdict};
use emulator_core::EventKind;

const BENIGN_COMMAND: &str = include_str!("fixtures/benign_prompt_command.txt");
const BENIGN_OBFUSCATED: &str = include_str!("fixtures/benign_obfuscated.ps1");
const SUSPICIOUS_ENCODED: &str = include_str!("fixtures/suspicious_inert_encoded_command.txt");

#[test]
fn benign_clickfix_style_prompt_has_no_effects() {
    let report = Detector::default()
        .analyze(DetectorInput::raw_command(BENIGN_COMMAND.trim()))
        .unwrap();

    assert_eq!(report.verdict, Verdict::Benign);
    assert!(report.iocs.is_empty());
    assert!(report.virtual_files.is_empty());
    assert!(!report
        .trace
        .iter()
        .any(|event| event.kind == EventKind::NetworkIntent));
}

#[test]
fn benign_obfuscation_is_explainable_but_not_malicious() {
    let report = Detector::default()
        .analyze(DetectorInput::powershell_script(BENIGN_OBFUSCATED))
        .unwrap();

    assert_eq!(report.verdict, Verdict::Benign);
    assert!(report
        .trace
        .iter()
        .any(|event| event.kind == EventKind::Decode));
    assert!(!report
        .trace
        .iter()
        .any(|event| event.kind == EventKind::NetworkIntent));
}

#[test]
fn inert_encoded_network_fixture_is_detected_without_fetching() {
    let report = Detector::default()
        .analyze(DetectorInput::raw_command(SUSPICIOUS_ENCODED.trim()))
        .unwrap();

    assert_eq!(report.verdict, Verdict::Malicious);
    assert!(report
        .iocs
        .iter()
        .any(|ioc| { ioc.value == "https://example.invalid/clickfix-test" }));
    assert_eq!(
        report.network_urls,
        ["https://example.invalid/clickfix-test"]
    );
    assert_eq!(report.network_activity.len(), 1);
    assert!(report.virtual_files.is_empty());
}
