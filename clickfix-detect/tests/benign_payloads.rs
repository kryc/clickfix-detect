use clickfix_detect::{Detector, DetectorInput, Verdict};

struct BenignCase {
    id: &'static str,
    input: &'static str,
    powershell: bool,
}

const BENIGN_CASES: &[BenignCase] = &[
    BenignCase {
        id: "cmd-echo",
        input: "cmd.exe /c echo deployment complete",
        powershell: false,
    },
    BenignCase {
        id: "powershell-output",
        input: "Write-Output 'deployment complete'",
        powershell: true,
    },
    BenignCase {
        id: "local-msi-install",
        input: r"msiexec.exe /i C:\Packages\approved.msi /quiet",
        powershell: false,
    },
    BenignCase {
        id: "control-panel-rundll32",
        input: "rundll32.exe shell32.dll,Control_RunDLL",
        powershell: false,
    },
    BenignCase {
        id: "local-mshta",
        input: r#"mshta.exe "C:\Program Files\Example\help.hta""#,
        powershell: false,
    },
    BenignCase {
        id: "local-logon-script",
        input: r#"wscript.exe "C:\Scripts\logon.vbs""#,
        powershell: false,
    },
    BenignCase {
        id: "local-archive-list",
        input: r"tar.exe -tf C:\Backups\archive.tar",
        powershell: false,
    },
    BenignCase {
        id: "curl-download-without-execution",
        input: r"curl.exe -o C:\Temp\status.json https://example.invalid/status.json",
        powershell: false,
    },
    BenignCase {
        id: "powershell-download-without-execution",
        input: r"Invoke-WebRequest -Uri https://example.invalid/status.json -OutFile C:\Temp\status.json",
        powershell: true,
    },
    BenignCase {
        id: "powershell-download-near-startup-folder",
        input: r"Invoke-WebRequest -Uri https://example.invalid/update.cmd -OutFile 'C:\Users\analysis\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Utilities\update.cmd'",
        powershell: true,
    },
    BenignCase {
        id: "powershell-service-inventory",
        input: "Get-Service | Select-Object Name, Status",
        powershell: true,
    },
    BenignCase {
        id: "local-file-copy",
        input: r"cmd.exe /c copy C:\Data\input.txt C:\Data\backup.txt",
        powershell: false,
    },
    BenignCase {
        id: "ordinary-conhost",
        input: "conhost.exe",
        powershell: false,
    },
    BenignCase {
        id: "copilot-cli-safe-installer",
        input: r#"curl -fsSL https://gh.io/copilot-install | VERSION="v0.0.369" PREFIX="$HOME/custom" bash"#,
        powershell: false,
    },
];

#[test]
fn benign_samples_remain_benign() {
    let failures = BENIGN_CASES
        .iter()
        .filter_map(|case| {
            let input = if case.powershell {
                DetectorInput::powershell_script(case.input)
            } else {
                DetectorInput::raw_command(case.input)
            };
            let report = Detector::default().analyze(input).unwrap();
            (report.verdict != Verdict::Benign).then(move || {
                (
                    case.id,
                    report.verdict,
                    report.risk.score,
                    report
                        .findings
                        .iter()
                        .map(|finding| finding.rule_id.clone())
                        .collect::<Vec<_>>(),
                )
            })
        })
        .collect::<Vec<_>>();

    assert!(
        failures.is_empty(),
        "benign samples were over-classified: {failures:?}"
    );
}
