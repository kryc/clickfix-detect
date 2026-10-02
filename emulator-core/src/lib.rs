use binary_inspector::{
    inspect as inspect_binary, probe_format, BinaryInspection, BinaryInspectionLimits,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use thiserror::Error;

mod network;
pub mod windows;

pub use binary_inspector::{
    BinaryCapability, BinaryFormat, BinaryHardening, BinaryImport, BinaryIndicator,
    BinaryIndicatorKind, BinaryKind, BinarySection, InspectionStatus,
};
pub use network::NetworkPolicy;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AnalysisLimits {
    pub max_steps: usize,
    pub max_depth: usize,
    pub max_loop_iterations: usize,
    pub max_decode_passes: usize,
    pub max_child_processes: usize,
    pub max_artifact_bytes: usize,
    pub max_artifacts: usize,
    pub max_total_artifact_bytes: usize,
    pub max_virtual_files: usize,
    pub max_total_virtual_file_bytes: usize,
    pub max_binary_inspections: usize,
    pub max_binary_inspection_bytes: usize,
    pub max_causal_edges: usize,
    pub max_trace_events: usize,
    pub max_iocs: usize,
    pub max_warnings: usize,
}

impl Default for AnalysisLimits {
    fn default() -> Self {
        Self {
            max_steps: 20_000,
            max_depth: 12,
            max_loop_iterations: 1_000,
            max_decode_passes: 12,
            max_child_processes: 64,
            max_artifact_bytes: 4 * 1024 * 1024,
            max_artifacts: 256,
            max_total_artifact_bytes: 16 * 1024 * 1024,
            max_virtual_files: 1_024,
            max_total_virtual_file_bytes: 16 * 1024 * 1024,
            max_binary_inspections: 64,
            max_binary_inspection_bytes: 8 * 1024 * 1024,
            max_causal_edges: 4_096,
            max_trace_events: 50_000,
            max_iocs: 4_096,
            max_warnings: 1_024,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Engine {
    Runbox,
    PowerShell,
    Cmd,
    Bash,
    Mshta,
    Wscript,
    Rundll32,
    Regsvr32,
    ShellAssociation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostPlatform {
    Windows,
    MacOs,
    Linux,
}

impl Default for HostPlatform {
    fn default() -> Self {
        Self::Windows
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Input,
    Parse,
    VariableAssignment,
    Decode,
    Command,
    ProcessIntent,
    NetworkIntent,
    FileRead,
    FileWrite,
    FileDelete,
    RegistryRead,
    RegistryWrite,
    Persistence,
    Output,
    Artifact,
    Unsupported,
    LimitReached,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEvent {
    pub sequence: usize,
    pub depth: usize,
    pub engine: Engine,
    pub kind: EventKind,
    pub message: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub data: BTreeMap<String, String>,
}

impl TraceEvent {
    #[must_use]
    pub fn new(depth: usize, engine: Engine, kind: EventKind, message: impl Into<String>) -> Self {
        Self {
            sequence: 0,
            depth,
            engine,
            kind,
            message: message.into(),
            data: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn with_data(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.data.insert(key.into(), value.into());
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IocKind {
    Url,
    Domain,
    IpAddress,
    FilePath,
    RegistryPath,
    Command,
    Sha256,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ioc {
    pub kind: IocKind,
    pub value: String,
    pub source: String,
    pub depth: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    DecodedText,
    Script,
    VirtualFile,
    Binary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    pub id: usize,
    pub kind: ArtifactKind,
    pub name: String,
    pub media_type: String,
    pub size: usize,
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary_inspection_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualFileSnapshot {
    pub path: String,
    pub size: usize,
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    pub truncated: bool,
    #[serde(default)]
    pub executable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary_inspection_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualDirectorySnapshot {
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CausalEntity {
    NetworkActivity { id: usize },
    Artifact { id: usize },
    VirtualFile { path: String },
    Process { command_line: String },
    TraceEvent { sequence: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CausalRelation {
    Downloaded,
    Decoded,
    Written,
    Copied,
    Extracted,
    MarkedExecutable,
    Executed,
    Derived,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CausalEdge {
    pub from: CausalEntity,
    pub to: CausalEntity,
    pub relation: CausalRelation,
    pub depth: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessIntent {
    pub program: String,
    pub args: Vec<String>,
    pub command_line: String,
    pub origin: String,
    pub depth: usize,
    #[serde(default)]
    pub stdin: Vec<String>,
    #[serde(default)]
    pub current_directory: String,
    #[serde(default)]
    pub causes: Vec<CausalEntity>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessResult {
    pub stdout: Vec<String>,
    pub stderr: Vec<String>,
    pub exit_code: i32,
    #[serde(default)]
    pub causes: Vec<CausalEntity>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkIntent {
    pub method: String,
    pub url: String,
    pub origin: String,
    pub depth: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkRequest {
    pub method: String,
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
    pub origin: String,
    pub depth: usize,
}

impl From<NetworkRequest> for NetworkIntent {
    fn from(request: NetworkRequest) -> Self {
        Self {
            method: request.method,
            url: request.url,
            origin: request.origin,
            depth: request.depth,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkOutcome {
    Attempted,
    Blocked,
    Fixture,
    Fetched,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkActivity {
    pub method: String,
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_url: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redirect_urls: Vec<String>,
    pub origin: String,
    pub depth: usize,
    pub outcome: NetworkOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_bytes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl NetworkResponse {
    #[must_use]
    pub fn text(body: impl Into<String>) -> Self {
        Self {
            status: 200,
            headers: BTreeMap::from([("content-type".into(), "text/plain; charset=utf-8".into())]),
            body: body.into().into_bytes(),
        }
    }
}

#[derive(Debug, Clone)]
struct VirtualFile {
    bytes: Vec<u8>,
    truncated: bool,
    executable: bool,
    baseline: bool,
    binary_inspection_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryInspectionSource {
    pub name: String,
    pub engine: Engine,
    pub depth: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryInspectionRecord {
    pub inspection: BinaryInspection,
    pub sources: Vec<BinaryInspectionSource>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum RetentionLimit {
    Trace,
    Ioc,
    Artifact,
    Warning,
    BinaryInspection,
    CausalEdge,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostSnapshot {
    #[serde(default)]
    pub platform: HostPlatform,
    pub trace: Vec<TraceEvent>,
    pub iocs: Vec<Ioc>,
    pub artifacts: Vec<Artifact>,
    pub virtual_files: Vec<VirtualFileSnapshot>,
    #[serde(default)]
    pub virtual_directories: Vec<VirtualDirectorySnapshot>,
    #[serde(default)]
    pub binary_inspections: Vec<BinaryInspectionRecord>,
    #[serde(default)]
    pub causal_edges: Vec<CausalEdge>,
    #[serde(default)]
    pub network_activity: Vec<NetworkActivity>,
    pub warnings: Vec<String>,
    pub unsupported_operations: usize,
    pub limits_reached: usize,
    pub steps_used: usize,
}

#[derive(Debug, Error)]
pub enum HostError {
    #[error("analysis step limit reached")]
    StepLimit,
    #[error("analysis depth {depth} exceeds limit {limit}")]
    DepthLimit { depth: usize, limit: usize },
    #[error("virtual file limit reached")]
    FileLimit,
    #[error("child process limit reached")]
    ChildProcessLimit,
}

pub trait Host {
    fn limits(&self) -> &AnalysisLimits;

    /// Consume one operation from the analysis budget.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::StepLimit`] or [`HostError::DepthLimit`] when the
    /// configured budget has been exhausted.
    fn consume_step(
        &mut self,
        engine: Engine,
        depth: usize,
        operation: &str,
    ) -> Result<(), HostError>;
    fn emit(&mut self, event: TraceEvent);
    fn add_ioc(&mut self, ioc: Ioc);
    fn add_artifact(
        &mut self,
        kind: ArtifactKind,
        name: &str,
        media_type: &str,
        bytes: &[u8],
        depth: usize,
    ) -> usize;

    /// Create or append to a file in the virtual filesystem.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::FileLimit`] when no additional virtual file can be
    /// created.
    fn write_file(
        &mut self,
        path: &str,
        bytes: &[u8],
        append: bool,
        engine: Engine,
        depth: usize,
    ) -> Result<(), HostError>;
    /// Writes a virtual file and records typed causal edges from its sources.
    ///
    /// # Errors
    ///
    /// Returns the same virtual-host limit errors as [`Host::write_file`].
    #[allow(clippy::too_many_arguments)]
    fn write_file_from(
        &mut self,
        path: &str,
        bytes: &[u8],
        append: bool,
        engine: Engine,
        depth: usize,
        sources: &[CausalEntity],
        relation: CausalRelation,
    ) -> Result<(), HostError> {
        self.write_file(path, bytes, append, engine, depth)?;
        let target = CausalEntity::VirtualFile { path: path.into() };
        for source in sources {
            self.add_causal_edge(CausalEdge {
                from: source.clone(),
                to: target.clone(),
                relation,
                depth,
            });
        }
        Ok(())
    }
    fn read_file(&mut self, path: &str, engine: Engine, depth: usize) -> Option<Vec<u8>>;
    fn delete_file(&mut self, path: &str, engine: Engine, depth: usize) -> bool;
    fn list_files(&mut self, prefix: &str, engine: Engine, depth: usize) -> Vec<String>;
    /// Create a directory in the virtual filesystem.
    ///
    /// # Errors
    ///
    /// Returns a host resource-limit error when the environment cannot accept the entry.
    fn create_directory(
        &mut self,
        path: &str,
        engine: Engine,
        depth: usize,
    ) -> Result<(), HostError>;
    fn directory_exists(&self, path: &str) -> bool;
    fn list_directories(&mut self, prefix: &str, engine: Engine, depth: usize) -> Vec<String>;
    fn delete_directory(&mut self, path: &str, recurse: bool, engine: Engine, depth: usize)
        -> bool;
    /// Register an executable file in the virtual filesystem.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::FileLimit`] when the virtual file limit is reached.
    fn register_executable(
        &mut self,
        path: &str,
        engine: Engine,
        depth: usize,
    ) -> Result<(), HostError>;
    fn is_executable(&self, path: &str) -> bool;
    fn set_environment(&mut self, name: &str, value: &str);
    fn environment(&self, name: &str) -> Option<&str>;
    fn environment_entries(&self) -> Vec<(String, String)>;
    fn remove_environment(&mut self, name: &str) -> bool;
    fn write_registry(&mut self, path: &str, value: &str, engine: Engine, depth: usize);
    fn read_registry(&mut self, path: &str, engine: Engine, depth: usize) -> Option<String>;
    fn list_registry(
        &mut self,
        prefix: &str,
        engine: Engine,
        depth: usize,
    ) -> Vec<(String, String)>;
    fn delete_registry(&mut self, path: &str, recurse: bool, engine: Engine, depth: usize)
        -> usize;
    fn network_intent(&mut self, intent: NetworkIntent);
    fn network_request(&mut self, intent: NetworkIntent) -> Option<NetworkResponse> {
        self.network_intent(intent);
        None
    }
    fn network_request_detailed(&mut self, request: NetworkRequest) -> Option<NetworkResponse> {
        self.network_request(request.into())
    }
    fn latest_network_activity_id(&self) -> Option<usize> {
        None
    }
    fn add_causal_edge(&mut self, edge: CausalEdge);

    /// Queue a process intent for recursive runbox dispatch.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::ChildProcessLimit`] when the configured child
    /// process budget has been exhausted.
    fn process_intent(&mut self, intent: ProcessIntent) -> Result<(), HostError>;

    /// Requests synchronous modeled process execution when the host supports
    /// it, otherwise queues the process intent and returns `None`.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::ChildProcessLimit`] when the configured child
    /// process budget has been exhausted.
    fn process_request(
        &mut self,
        intent: ProcessIntent,
    ) -> Result<Option<ProcessResult>, HostError> {
        self.process_intent(intent)?;
        Ok(None)
    }
    fn unsupported(&mut self, engine: Engine, depth: usize, operation: &str);
    fn warning(&mut self, warning: String);
}

#[derive(Debug, Clone)]
pub struct VirtualHost {
    platform: HostPlatform,
    limits: AnalysisLimits,
    trace: Vec<TraceEvent>,
    iocs: Vec<Ioc>,
    artifacts: Vec<Artifact>,
    binary_inspections: BTreeMap<String, BinaryInspectionRecord>,
    causal_edges: Vec<CausalEdge>,
    files: BTreeMap<String, VirtualFile>,
    directories: BTreeMap<String, bool>,
    environment: BTreeMap<String, String>,
    registry: BTreeMap<String, String>,
    network_responses: BTreeMap<(String, String), NetworkResponse>,
    default_network_response: Option<NetworkResponse>,
    network_policy: NetworkPolicy,
    network_activity: Vec<NetworkActivity>,
    process_intents: VecDeque<ProcessIntent>,
    warnings: Vec<String>,
    steps_used: usize,
    unsupported_operations: usize,
    limits_reached: usize,
    child_processes: usize,
    retention_limits_reached: BTreeSet<RetentionLimit>,
}

impl VirtualHost {
    #[must_use]
    pub fn new(limits: AnalysisLimits) -> Self {
        Self::with_platform(limits, HostPlatform::Windows)
    }

    #[must_use]
    pub fn macos(limits: AnalysisLimits) -> Self {
        Self::with_platform(limits, HostPlatform::MacOs)
    }

    #[must_use]
    pub fn linux(limits: AnalysisLimits) -> Self {
        Self::with_platform(limits, HostPlatform::Linux)
    }

    #[must_use]
    pub fn with_platform(limits: AnalysisLimits, platform: HostPlatform) -> Self {
        let environment = match platform {
            HostPlatform::Windows => Self::windows_11_environment(),
            HostPlatform::MacOs => Self::macos_environment(),
            HostPlatform::Linux => Self::linux_environment(),
        };
        let directory_paths = match platform {
            HostPlatform::Windows => Self::windows_11_directories(),
            HostPlatform::MacOs => Self::macos_directories(),
            HostPlatform::Linux => Self::linux_directories(),
        };
        let executable_paths = match platform {
            HostPlatform::Windows => Self::windows_11_executables(),
            HostPlatform::MacOs => Self::macos_executables(),
            HostPlatform::Linux => Self::linux_executables(),
        };
        let directories = directory_paths
            .into_iter()
            .map(|path| (normalize_path_for(platform, path), true))
            .collect();
        let mut files: BTreeMap<String, VirtualFile> = executable_paths
            .into_iter()
            .map(|path| {
                (
                    normalize_path_for(platform, path),
                    VirtualFile {
                        bytes: Vec::new(),
                        truncated: false,
                        executable: true,
                        baseline: true,
                        binary_inspection_sha256: None,
                    },
                )
            })
            .collect();
        if platform == HostPlatform::Linux {
            for (path, bytes) in Self::linux_baseline_files() {
                files.insert(
                    normalize_posix_path(path),
                    VirtualFile {
                        bytes: bytes.as_bytes().to_vec(),
                        truncated: false,
                        executable: false,
                        baseline: true,
                        binary_inspection_sha256: None,
                    },
                );
            }
        }

        Self {
            platform,
            limits,
            trace: Vec::new(),
            iocs: Vec::new(),
            artifacts: Vec::new(),
            binary_inspections: BTreeMap::new(),
            causal_edges: Vec::new(),
            files,
            directories,
            environment,
            registry: BTreeMap::new(),
            network_responses: BTreeMap::new(),
            default_network_response: Some(NetworkResponse::text("")),
            network_policy: NetworkPolicy::default(),
            network_activity: Vec::new(),
            process_intents: VecDeque::new(),
            warnings: Vec::new(),
            steps_used: 0,
            unsupported_operations: 0,
            limits_reached: 0,
            child_processes: 0,
            retention_limits_reached: BTreeSet::new(),
        }
    }

    #[must_use]
    pub const fn platform(&self) -> HostPlatform {
        self.platform
    }

    #[must_use]
    pub fn windows_11_directories() -> Vec<&'static str> {
        vec![
            r"C:\",
            r"C:\Program Files",
            r"C:\Program Files\Common Files",
            r"C:\Program Files (x86)",
            r"C:\ProgramData",
            r"C:\Users",
            r"C:\Users\analysis",
            r"C:\Users\analysis\Desktop",
            r"C:\Users\analysis\Documents",
            r"C:\Users\analysis\Downloads",
            r"C:\Users\analysis\OneDrive",
            r"C:\Users\analysis\AppData",
            r"C:\Users\analysis\AppData\Local",
            r"C:\Users\analysis\AppData\Local\Temp",
            r"C:\Users\analysis\AppData\Roaming",
            r"C:\Users\analysis\AppData\Roaming\Microsoft",
            r"C:\Users\analysis\AppData\Roaming\Microsoft\Windows",
            r"C:\Users\analysis\AppData\Roaming\Microsoft\Windows\Start Menu",
            r"C:\Users\analysis\AppData\Roaming\Microsoft\Windows\Start Menu\Programs",
            r"C:\Users\analysis\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
            r"C:\Users\Public",
            r"C:\Windows",
            r"C:\Windows\Microsoft.NET",
            r"C:\Windows\Microsoft.NET\Framework64",
            r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319",
            r"C:\Windows\System32",
            r"C:\Windows\System32\Drivers",
            r"C:\Windows\System32\Drivers\DriverData",
            r"C:\Windows\System32\OpenSSH",
            r"C:\Windows\System32\Tasks",
            r"C:\Windows\System32\Wbem",
            r"C:\Windows\System32\WindowsPowerShell",
            r"C:\Windows\System32\WindowsPowerShell\v1.0",
            r"C:\Windows\SysWOW64",
            r"C:\Windows\Tasks",
            r"C:\Windows\Temp",
        ]
    }

    #[must_use]
    pub fn windows_11_executables() -> Vec<&'static str> {
        vec![
            r"C:\Windows\System32\attrib.exe",
            r"C:\Windows\System32\auditpol.exe",
            r"C:\Windows\System32\bitsadmin.exe",
            r"C:\Windows\System32\certutil.exe",
            r"C:\Windows\System32\chcp.com",
            r"C:\Windows\System32\cmd.exe",
            r"C:\Windows\System32\cmdkey.exe",
            r"C:\Windows\System32\conhost.exe",
            r"C:\Windows\System32\control.exe",
            r"C:\Windows\System32\cscript.exe",
            r"C:\Windows\System32\curl.exe",
            r"C:\Windows\System32\expand.exe",
            r"C:\Windows\System32\extrac32.exe",
            r"C:\Windows\System32\find.exe",
            r"C:\Windows\System32\findstr.exe",
            r"C:\Windows\System32\finger.exe",
            r"C:\Windows\System32\forfiles.exe",
            r"C:\Windows\System32\makecab.exe",
            r"C:\Windows\System32\more.com",
            r"C:\Windows\System32\mshta.exe",
            r"C:\Windows\System32\msiexec.exe",
            r"C:\Windows\System32\netsh.exe",
            r"C:\Windows\System32\reg.exe",
            r"C:\Windows\System32\regsvr32.exe",
            r"C:\Windows\System32\robocopy.exe",
            r"C:\Windows\System32\rundll32.exe",
            r"C:\Windows\System32\sc.exe",
            r"C:\Windows\System32\schtasks.exe",
            r"C:\Windows\System32\sort.exe",
            r"C:\Windows\System32\tar.exe",
            r"C:\Windows\System32\wevtutil.exe",
            r"C:\Windows\System32\where.exe",
            r"C:\Windows\System32\wmic.exe",
            r"C:\Windows\System32\wscript.exe",
            r"C:\Windows\System32\xcopy.exe",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe",
            r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe",
        ]
    }

    #[must_use]
    pub fn windows_11_environment() -> BTreeMap<String, String> {
        [
                ("allusersprofile", r"C:\ProgramData"),
                ("appdata", r"C:\Users\analysis\AppData\Roaming"),
                (
                    "commonprogramfiles",
                    r"C:\Program Files\Common Files",
                ),
                (
                    "commonprogramfiles(x86)",
                    r"C:\Program Files (x86)\Common Files",
                ),
                (
                    "commonprogramw6432",
                    r"C:\Program Files\Common Files",
                ),
                ("computername", "ANALYSIS-HOST"),
                ("comspec", r"C:\Windows\System32\cmd.exe"),
                ("driverdata", r"C:\Windows\System32\Drivers\DriverData"),
                ("homedrive", "C:"),
                ("homepath", r"\Users\analysis"),
                ("localappdata", r"C:\Users\analysis\AppData\Local"),
                ("logonserver", r"\\ANALYSIS-HOST"),
                ("number_of_processors", "8"),
                ("onedrive", r"C:\Users\analysis\OneDrive"),
                ("os", "Windows_NT"),
                (
                    "path",
                    r"C:\Windows\System32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH\",
                ),
                ("pathext", ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC;.CPL"),
                ("processor_architecture", "AMD64"),
                (
                    "processor_identifier",
                    "Intel64 Family 6 Model 158 Stepping 10, GenuineIntel",
                ),
                ("processor_level", "6"),
                ("processor_revision", "9e0a"),
                ("programdata", r"C:\ProgramData"),
                ("programfiles", r"C:\Program Files"),
                ("programfiles(x86)", r"C:\Program Files (x86)"),
                ("programw6432", r"C:\Program Files"),
                ("prompt", "$P$G"),
                (
                    "psmodulepath",
                    r"C:\Users\analysis\Documents\WindowsPowerShell\Modules;C:\Program Files\WindowsPowerShell\Modules;C:\Windows\System32\WindowsPowerShell\v1.0\Modules",
                ),
                ("public", r"C:\Users\Public"),
                ("sessionname", "Console"),
                ("systemdrive", "C:"),
                ("systemroot", r"C:\Windows"),
                ("temp", r"C:\Users\analysis\AppData\Local\Temp"),
                ("tmp", r"C:\Users\analysis\AppData\Local\Temp"),
                ("userdnsdomain", "ANALYSIS.LOCAL"),
                ("userdomain", "ANALYSIS"),
                ("userdomain_roamingprofile", "ANALYSIS"),
                ("username", "analysis"),
                ("userprofile", r"C:\Users\analysis"),
                ("windir", r"C:\Windows"),
            ]
            .into_iter()
            .map(|(name, value)| (name.into(), value.into()))
            .collect()
    }

    #[must_use]
    pub fn macos_directories() -> Vec<&'static str> {
        vec![
            "/",
            "/Applications",
            "/Library",
            "/Library/LaunchAgents",
            "/Library/LaunchDaemons",
            "/System",
            "/System/Library",
            "/Users",
            "/Users/analysis",
            "/Users/analysis/Desktop",
            "/Users/analysis/Documents",
            "/Users/analysis/Downloads",
            "/Users/analysis/Library",
            "/Users/analysis/Library/Application Support",
            "/Users/analysis/Library/Caches",
            "/Users/analysis/Library/LaunchAgents",
            "/Users/analysis/Library/Preferences",
            "/bin",
            "/private",
            "/private/tmp",
            "/tmp",
            "/usr",
            "/usr/bin",
            "/usr/local",
            "/usr/local/bin",
            "/usr/sbin",
            "/var",
            "/var/tmp",
        ]
    }

    #[must_use]
    pub fn macos_executables() -> Vec<&'static str> {
        vec![
            "/bin/bash",
            "/bin/cat",
            "/bin/chmod",
            "/bin/cp",
            "/bin/date",
            "/bin/echo",
            "/bin/kill",
            "/bin/launchctl",
            "/bin/ls",
            "/bin/mkdir",
            "/bin/mv",
            "/bin/pwd",
            "/bin/rm",
            "/bin/sh",
            "/bin/sleep",
            "/bin/test",
            "/bin/zsh",
            "/usr/bin/awk",
            "/usr/bin/base64",
            "/usr/bin/curl",
            "/usr/bin/defaults",
            "/usr/bin/dscl",
            "/usr/bin/env",
            "/usr/bin/find",
            "/usr/bin/grep",
            "/usr/bin/head",
            "/usr/bin/nohup",
            "/usr/bin/open",
            "/usr/bin/osascript",
            "/usr/bin/perl",
            "/usr/bin/python3",
            "/usr/bin/sed",
            "/usr/bin/sort",
            "/usr/bin/sudo",
            "/usr/bin/tail",
            "/usr/bin/tar",
            "/usr/bin/tee",
            "/usr/bin/uname",
            "/usr/bin/wc",
            "/usr/bin/xattr",
            "/usr/bin/security",
            "/usr/bin/setsid",
            "/usr/bin/timeout",
            "/usr/sbin/scutil",
        ]
    }

    #[must_use]
    pub fn macos_environment() -> BTreeMap<String, String> {
        [
            ("HOME", "/Users/analysis"),
            ("LOGNAME", "analysis"),
            ("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"),
            ("PWD", "/Users/analysis"),
            ("SHELL", "/bin/zsh"),
            ("SHLVL", "1"),
            ("TMPDIR", "/private/tmp"),
            ("USER", "analysis"),
            ("LANG", "en_US.UTF-8"),
            ("LC_ALL", "en_US.UTF-8"),
            ("HOSTNAME", "analysis-mac"),
            ("TERM", "xterm-256color"),
        ]
        .into_iter()
        .map(|(name, value)| (name.into(), value.into()))
        .collect()
    }

    #[must_use]
    pub fn linux_directories() -> Vec<&'static str> {
        vec![
            "/",
            "/bin",
            "/boot",
            "/dev",
            "/dev/shm",
            "/etc",
            "/etc/cron.d",
            "/etc/cron.daily",
            "/etc/init.d",
            "/etc/systemd",
            "/etc/systemd/system",
            "/home",
            "/home/analysis",
            "/home/analysis/.cache",
            "/home/analysis/.config",
            "/home/analysis/.config/autostart",
            "/home/analysis/.config/systemd",
            "/home/analysis/.config/systemd/user",
            "/home/analysis/.local",
            "/home/analysis/.local/bin",
            "/home/analysis/Downloads",
            "/lib",
            "/lib/systemd",
            "/lib/systemd/system",
            "/opt",
            "/proc",
            "/root",
            "/run",
            "/sbin",
            "/srv",
            "/sys",
            "/tmp",
            "/usr",
            "/usr/bin",
            "/usr/local",
            "/usr/local/bin",
            "/usr/sbin",
            "/var",
            "/var/lib",
            "/var/log",
            "/var/spool",
            "/var/spool/cron",
            "/var/tmp",
        ]
    }

    #[must_use]
    pub fn linux_executables() -> Vec<&'static str> {
        vec![
            "/bin/bash",
            "/bin/cat",
            "/bin/chmod",
            "/bin/chown",
            "/bin/cp",
            "/bin/date",
            "/bin/echo",
            "/bin/kill",
            "/bin/ls",
            "/bin/mkdir",
            "/bin/mv",
            "/bin/pwd",
            "/bin/rm",
            "/bin/sh",
            "/bin/sleep",
            "/bin/systemctl",
            "/bin/tar",
            "/bin/test",
            "/bin/zsh",
            "/usr/bin/apt",
            "/usr/bin/apt-get",
            "/usr/bin/awk",
            "/usr/bin/base64",
            "/usr/bin/crontab",
            "/usr/bin/curl",
            "/usr/bin/dnf",
            "/usr/bin/dpkg",
            "/usr/bin/env",
            "/usr/bin/find",
            "/usr/bin/grep",
            "/usr/bin/head",
            "/usr/bin/id",
            "/usr/bin/nc",
            "/usr/bin/nohup",
            "/usr/bin/perl",
            "/usr/bin/python",
            "/usr/bin/python3",
            "/usr/bin/rpm",
            "/usr/bin/sed",
            "/usr/bin/setsid",
            "/usr/bin/sort",
            "/usr/bin/ssh",
            "/usr/bin/sudo",
            "/usr/bin/systemctl",
            "/usr/bin/tail",
            "/usr/bin/tee",
            "/usr/bin/timeout",
            "/usr/bin/uname",
            "/usr/bin/unzip",
            "/usr/bin/wc",
            "/usr/bin/wget",
            "/usr/bin/whoami",
            "/usr/bin/yum",
            "/usr/sbin/chroot",
            "/usr/sbin/iptables",
            "/usr/sbin/nft",
            "/usr/sbin/service",
            "/usr/sbin/ufw",
        ]
    }

    #[must_use]
    pub fn linux_environment() -> BTreeMap<String, String> {
        [
            ("HOME", "/home/analysis"),
            ("HOSTNAME", "analysis-linux"),
            ("LANG", "en_US.UTF-8"),
            ("LC_ALL", "en_US.UTF-8"),
            ("LOGNAME", "analysis"),
            (
                "PATH",
                "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin",
            ),
            ("PWD", "/home/analysis"),
            ("SHELL", "/bin/bash"),
            ("SHLVL", "1"),
            ("TERM", "xterm-256color"),
            ("TMPDIR", "/tmp"),
            ("USER", "analysis"),
        ]
        .into_iter()
        .map(|(name, value)| (name.into(), value.into()))
        .collect()
    }

    #[must_use]
    pub fn linux_baseline_files() -> Vec<(&'static str, &'static str)> {
        vec![
            (
                "/etc/os-release",
                "NAME=\"Analysis Linux\"\nID=analysis\nVERSION_ID=\"1\"\nPRETTY_NAME=\"Analysis Linux 1\"\n",
            ),
            (
                "/etc/passwd",
                "root:x:0:0:root:/root:/bin/bash\nanalysis:x:1000:1000:Analysis User:/home/analysis:/bin/bash\n",
            ),
            (
                "/etc/hosts",
                "127.0.0.1 localhost\n127.0.1.1 analysis-linux\n::1 localhost ip6-localhost\n",
            ),
            (
                "/proc/version",
                "Linux version 6.8.0-analysis (analysis@analysis-linux) #1 SMP x86_64 GNU/Linux\n",
            ),
        ]
    }

    pub fn take_process_intents(&mut self) -> Vec<ProcessIntent> {
        self.process_intents.drain(..).collect()
    }

    /// Records a synchronous child-process request without adding it to the
    /// deferred process-intent queue.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::ChildProcessLimit`] when the configured child
    /// process budget has been exhausted.
    pub fn record_process_request(&mut self, intent: &ProcessIntent) -> Result<(), HostError> {
        if self.child_processes >= self.limits.max_child_processes {
            self.record_limit(Engine::Runbox, intent.depth, "child process limit reached");
            return Err(HostError::ChildProcessLimit);
        }
        self.child_processes += 1;
        self.add_ioc(Ioc {
            kind: IocKind::Command,
            value: intent.command_line.clone(),
            source: intent.origin.clone(),
            depth: intent.depth,
        });
        let process = CausalEntity::Process {
            command_line: intent.command_line.clone(),
        };
        let mut causes = intent.causes.clone();
        if let Some(path) = self.process_file_path(intent) {
            causes.push(CausalEntity::VirtualFile { path });
        }
        for cause in causes {
            self.push_causal_edge(CausalEdge {
                from: cause,
                to: process.clone(),
                relation: CausalRelation::Executed,
                depth: intent.depth,
            });
        }
        self.emit(
            TraceEvent::new(
                intent.depth,
                Engine::Runbox,
                EventKind::ProcessIntent,
                format!("requested process launch: {}", intent.command_line),
            )
            .with_data("program", &intent.program)
            .with_data("command_line", &intent.command_line)
            .with_data("origin", &intent.origin),
        );
        Ok(())
    }

    pub fn register_network_response(
        &mut self,
        method: impl Into<String>,
        url: impl Into<String>,
        response: NetworkResponse,
    ) {
        self.network_responses
            .insert((method.into(), url.into()), response);
    }

    pub fn set_default_network_response(&mut self, response: NetworkResponse) {
        self.default_network_response = Some(response);
    }

    pub fn set_default_network_response_text(&mut self, body: impl Into<String>) {
        self.set_default_network_response(NetworkResponse::text(body));
    }

    pub fn clear_default_network_response(&mut self) {
        self.default_network_response = None;
    }

    pub fn remove_network_response(&mut self, method: &str, url: &str) -> bool {
        self.network_responses
            .remove(&(method.to_owned(), url.to_owned()))
            .is_some()
    }

    pub fn set_network_policy(&mut self, policy: NetworkPolicy) {
        self.network_policy = policy;
    }

    #[must_use]
    pub const fn network_policy(&self) -> &NetworkPolicy {
        &self.network_policy
    }

    fn normalize_path(&self, path: &str) -> String {
        normalize_path_for(self.platform, path)
    }

    fn environment_name(&self, name: &str) -> String {
        match self.platform {
            HostPlatform::Windows => name.to_ascii_lowercase(),
            HostPlatform::MacOs | HostPlatform::Linux => name.into(),
        }
    }

    const fn path_separator(&self) -> char {
        match self.platform {
            HostPlatform::Windows => '\\',
            HostPlatform::MacOs | HostPlatform::Linux => '/',
        }
    }

    /// Add or replace a file in the virtual filesystem.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::FileLimit`] when the virtual file limit is reached.
    pub fn add_virtual_file(&mut self, path: &str, bytes: &[u8]) -> Result<(), HostError> {
        self.write_file(path, bytes, false, Engine::Runbox, 0)
    }

    pub fn remove_virtual_file(&mut self, path: &str) -> bool {
        self.delete_file(path, Engine::Runbox, 0)
    }

    /// Add a directory to the virtual filesystem.
    ///
    /// # Errors
    ///
    /// Returns a host resource-limit error when the environment cannot accept the entry.
    pub fn add_virtual_directory(&mut self, path: &str) -> Result<(), HostError> {
        self.create_directory(path, Engine::Runbox, 0)
    }

    pub fn remove_virtual_directory(&mut self, path: &str, recurse: bool) -> bool {
        self.delete_directory(path, recurse, Engine::Runbox, 0)
    }

    /// Add an executable to the virtual filesystem.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::FileLimit`] when the virtual file limit is reached.
    pub fn add_virtual_executable(&mut self, path: &str) -> Result<(), HostError> {
        self.register_executable(path, Engine::Runbox, 0)
    }

    pub fn remove_virtual_executable(&mut self, path: &str) -> bool {
        self.delete_file(path, Engine::Runbox, 0)
    }

    #[must_use]
    pub fn virtual_file(&self, path: &str) -> Option<&[u8]> {
        self.files
            .get(&self.normalize_path(path))
            .map(|file| file.bytes.as_slice())
    }

    #[must_use]
    pub fn virtual_file_paths(&self) -> Vec<String> {
        self.files.keys().cloned().collect()
    }

    #[must_use]
    pub fn virtual_directory_paths(&self) -> Vec<String> {
        self.directories.keys().cloned().collect()
    }

    #[must_use]
    pub fn virtual_executable_paths(&self) -> Vec<String> {
        self.files
            .iter()
            .filter(|(_, file)| file.executable)
            .map(|(path, _)| path.clone())
            .collect()
    }

    pub fn inspect_binary_bytes(
        &mut self,
        name: &str,
        bytes: &[u8],
        engine: Engine,
        depth: usize,
    ) -> Option<String> {
        probe_format(bytes)?;
        let sha256 = sha256_hex(bytes);
        let source = BinaryInspectionSource {
            name: name.into(),
            engine,
            depth,
        };
        if let Some(record) = self.binary_inspections.get_mut(&sha256) {
            if !record.sources.contains(&source) {
                if record.sources.len() < 32 {
                    record.sources.push(source);
                } else if !record
                    .inspection
                    .warnings
                    .iter()
                    .any(|warning| warning == "binary inspection source list truncated")
                {
                    record.inspection.status = InspectionStatus::Partial;
                    record
                        .inspection
                        .warnings
                        .push("binary inspection source list truncated".into());
                }
            }
            let format = format!("{:?}", record.inspection.format).to_ascii_lowercase();
            self.emit(
                TraceEvent::new(
                    depth,
                    engine,
                    EventKind::Parse,
                    format!("reused cached binary inspection for {name}"),
                )
                .with_data("sha256", &sha256)
                .with_data("format", format)
                .with_data("cached", "true"),
            );
            return Some(sha256);
        }
        if self.binary_inspections.len() >= self.limits.max_binary_inspections {
            if self
                .retention_limits_reached
                .insert(RetentionLimit::BinaryInspection)
            {
                self.record_limit(engine, depth, "binary inspection count limit reached");
            }
            return None;
        }
        let inspection_limits = BinaryInspectionLimits {
            max_inspected_bytes: self.limits.max_binary_inspection_bytes,
            ..BinaryInspectionLimits::default()
        };
        let inspection = inspect_binary(bytes, &inspection_limits)?;
        let partial = inspection.status == InspectionStatus::Partial;
        let format = format!("{:?}", inspection.format).to_ascii_lowercase();
        for indicator in &inspection.indicators {
            let kind = match indicator.kind {
                BinaryIndicatorKind::Url => IocKind::Url,
                BinaryIndicatorKind::Domain => IocKind::Domain,
                BinaryIndicatorKind::IpAddress => IocKind::IpAddress,
                BinaryIndicatorKind::Path => IocKind::FilePath,
            };
            self.add_ioc(Ioc {
                kind,
                value: indicator.value.clone(),
                source: format!("{engine:?} static binary string"),
                depth,
            });
        }
        self.add_ioc(Ioc {
            kind: IocKind::Sha256,
            value: sha256.clone(),
            source: format!("{engine:?} static binary inspection"),
            depth,
        });
        self.binary_inspections.insert(
            sha256.clone(),
            BinaryInspectionRecord {
                inspection,
                sources: vec![source],
            },
        );
        self.emit(
            TraceEvent::new(
                depth,
                engine,
                EventKind::Parse,
                format!("statically inspected binary {name}"),
            )
            .with_data("sha256", &sha256)
            .with_data("format", format)
            .with_data("bytes", bytes.len().to_string())
            .with_data("partial", partial.to_string()),
        );
        Some(sha256)
    }

    #[must_use]
    pub fn latest_network_activity_id(&self) -> Option<usize> {
        (!self.network_activity.is_empty()).then_some(self.network_activity.len())
    }

    pub fn inspect_virtual_binary(
        &mut self,
        path: &str,
        engine: Engine,
        depth: usize,
    ) -> Option<String> {
        let normalized = self.normalize_path(path);
        let bytes = self.files.get(&normalized)?.bytes.clone();
        let sha256 = self.inspect_binary_bytes(&normalized, &bytes, engine, depth)?;
        if let Some(file) = self.files.get_mut(&normalized) {
            file.binary_inspection_sha256 = Some(sha256.clone());
        }
        Some(sha256)
    }

    pub fn set_environment_variable(&mut self, name: &str, value: &str) {
        self.set_environment(name, value);
    }

    pub fn remove_environment_variable(&mut self, name: &str) -> bool {
        self.remove_environment(name)
    }

    #[must_use]
    pub fn environment_variable(&self, name: &str) -> Option<&str> {
        self.environment(name)
    }

    pub fn set_registry_value(&mut self, path: &str, value: &str) {
        self.write_registry(path, value, Engine::Runbox, 0);
    }

    pub fn remove_registry_value(&mut self, path: &str, recurse: bool) -> usize {
        self.delete_registry(path, recurse, Engine::Runbox, 0)
    }

    #[must_use]
    pub fn registry_value(&self, path: &str) -> Option<&str> {
        self.registry
            .get(&path.to_ascii_lowercase())
            .map(String::as_str)
    }

    #[must_use]
    pub fn snapshot(&self) -> HostSnapshot {
        let virtual_files = self
            .files
            .iter()
            .filter(|(_, file)| !file.baseline)
            .map(|(path, file)| VirtualFileSnapshot {
                path: path.clone(),
                size: file.bytes.len(),
                sha256: sha256_hex(&file.bytes),
                text: String::from_utf8(file.bytes.clone()).ok(),
                truncated: file.truncated,
                executable: file.executable,
                binary_inspection_sha256: file.binary_inspection_sha256.clone(),
            })
            .collect();
        let virtual_directories = self
            .directories
            .iter()
            .filter(|(_, baseline)| !**baseline)
            .map(|(path, _)| VirtualDirectorySnapshot { path: path.clone() })
            .collect();

        HostSnapshot {
            platform: self.platform,
            trace: self.trace.clone(),
            iocs: self.iocs.clone(),
            artifacts: self.artifacts.clone(),
            virtual_files,
            virtual_directories,
            binary_inspections: self.binary_inspections.values().cloned().collect(),
            causal_edges: self.causal_edges.clone(),
            network_activity: self.network_activity.clone(),
            warnings: self.warnings.clone(),
            unsupported_operations: self.unsupported_operations,
            limits_reached: self.limits_reached,
            steps_used: self.steps_used,
        }
    }

    fn record_limit(&mut self, engine: Engine, depth: usize, message: impl Into<String>) {
        self.limits_reached += 1;
        self.emit(TraceEvent::new(
            depth,
            engine,
            EventKind::LimitReached,
            message,
        ));
    }

    fn push_bounded_warning(&mut self, warning: String) {
        if self.warnings.contains(&warning) {
            return;
        }
        if self.warnings.len() >= self.limits.max_warnings {
            if self
                .retention_limits_reached
                .insert(RetentionLimit::Warning)
            {
                self.limits_reached += 1;
            }
            return;
        }
        self.warnings.push(warning);
    }

    fn push_causal_edge(&mut self, edge: CausalEdge) {
        if self.causal_edges.contains(&edge) {
            return;
        }
        if self.causal_edges.len() >= self.limits.max_causal_edges {
            if self
                .retention_limits_reached
                .insert(RetentionLimit::CausalEdge)
            {
                self.limits_reached += 1;
                self.push_bounded_warning("causal edge limit reached".into());
            }
            return;
        }
        self.causal_edges.push(edge);
    }

    fn process_file_path(&self, intent: &ProcessIntent) -> Option<String> {
        let direct = self.normalize_path(&intent.program);
        if self.files.contains_key(&direct) {
            return Some(direct);
        }
        if intent.current_directory.is_empty()
            || intent.program.starts_with(['/', '\\'])
            || intent
                .program
                .as_bytes()
                .get(1)
                .is_some_and(|separator| *separator == b':')
        {
            return None;
        }
        let candidate = format!(
            "{}{}{}",
            intent.current_directory.trim_end_matches(['/', '\\']),
            self.path_separator(),
            intent.program
        );
        let normalized = self.normalize_path(&candidate);
        self.files.contains_key(&normalized).then_some(normalized)
    }

    fn ensure_parent_directories(&mut self, path: &str) {
        let separator = self.path_separator();
        let Some((parent, _)) = path.rsplit_once(separator) else {
            return;
        };
        if matches!(self.platform, HostPlatform::MacOs | HostPlatform::Linux) {
            let mut current = String::from("/");
            for part in parent.split('/').filter(|part| !part.is_empty()) {
                if current.len() > 1 {
                    current.push('/');
                }
                current.push_str(part);
                self.directories.entry(current.clone()).or_insert(false);
            }
            return;
        }
        let mut current = String::new();
        for (index, part) in parent.split('\\').enumerate() {
            if index == 0 {
                current.push_str(part);
                current.push('\\');
            } else if !part.is_empty() {
                if !current.ends_with('\\') {
                    current.push('\\');
                }
                current.push_str(part);
                self.directories.entry(current.clone()).or_insert(false);
            }
        }
    }

    fn record_network_intent(&mut self, intent: NetworkIntent, access: &str) -> usize {
        self.add_ioc(Ioc {
            kind: IocKind::Url,
            value: intent.url.clone(),
            source: intent.origin.clone(),
            depth: intent.depth,
        });
        if let Some(domain) = extract_url_host(&intent.url) {
            self.add_ioc(Ioc {
                kind: IocKind::Domain,
                value: domain,
                source: intent.origin.clone(),
                depth: intent.depth,
            });
        }
        let action = match access {
            "real" => "allowed network request",
            "fixture" => "modeled network request",
            _ => "blocked network request",
        };
        let outcome = match access {
            "real" => NetworkOutcome::Attempted,
            "fixture" => NetworkOutcome::Fixture,
            _ => NetworkOutcome::Blocked,
        };
        self.network_activity.push(NetworkActivity {
            method: intent.method.clone(),
            url: intent.url.clone(),
            final_url: None,
            redirect_urls: Vec::new(),
            origin: intent.origin.clone(),
            depth: intent.depth,
            outcome,
            status: None,
            response_bytes: None,
            error: None,
        });
        let activity_index = self.network_activity.len() - 1;
        self.emit(
            TraceEvent::new(
                intent.depth,
                Engine::Runbox,
                EventKind::NetworkIntent,
                format!("{action}: {} {}", intent.method, intent.url),
            )
            .with_data("method", intent.method)
            .with_data("url", intent.url)
            .with_data("origin", intent.origin)
            .with_data("network_access", access),
        );
        activity_index
    }

    fn record_network_response(
        &mut self,
        activity_index: usize,
        response: &NetworkResponse,
        outcome: NetworkOutcome,
    ) {
        if let Some(activity) = self.network_activity.get_mut(activity_index) {
            activity.outcome = outcome;
            activity.status = Some(response.status);
            activity.response_bytes = Some(response.body.len());
        }
        if let Some(event) = self.trace.last_mut() {
            event
                .data
                .insert("response_status".into(), response.status.to_string());
            event
                .data
                .insert("response_bytes".into(), response.body.len().to_string());
        }
    }

    fn record_network_fetch(&mut self, activity_index: usize, fetch: &network::NetworkFetch) {
        self.record_network_response(activity_index, &fetch.response, NetworkOutcome::Fetched);
        if let Some(activity) = self.network_activity.get_mut(activity_index) {
            activity.final_url = Some(fetch.final_url.clone());
            activity.redirect_urls.clone_from(&fetch.redirects);
        }
        let depth = self
            .network_activity
            .get(activity_index)
            .map_or(0, |activity| activity.depth);
        for url in &fetch.redirects {
            self.add_ioc(Ioc {
                kind: IocKind::Url,
                value: url.clone(),
                source: "network redirect".into(),
                depth,
            });
            if let Some(domain) = extract_url_host(url) {
                self.add_ioc(Ioc {
                    kind: IocKind::Domain,
                    value: domain,
                    source: "network redirect".into(),
                    depth,
                });
            }
        }
        if let Some(event) = self.trace.last_mut() {
            event
                .data
                .insert("final_url".into(), fetch.final_url.clone());
            event
                .data
                .insert("redirects".into(), fetch.redirects.len().to_string());
        }
    }

    fn record_network_failure(&mut self, activity_index: usize, error: &str) {
        if let Some(activity) = self.network_activity.get_mut(activity_index) {
            activity.outcome = NetworkOutcome::Failed;
            activity.error = Some(error.into());
        }
    }
}

impl Host for VirtualHost {
    fn limits(&self) -> &AnalysisLimits {
        &self.limits
    }

    fn consume_step(
        &mut self,
        engine: Engine,
        depth: usize,
        operation: &str,
    ) -> Result<(), HostError> {
        if depth > self.limits.max_depth {
            self.record_limit(
                engine,
                depth,
                format!(
                    "depth limit reached while {operation}: {} > {}",
                    depth, self.limits.max_depth
                ),
            );
            return Err(HostError::DepthLimit {
                depth,
                limit: self.limits.max_depth,
            });
        }
        if self.steps_used >= self.limits.max_steps {
            self.record_limit(
                engine,
                depth,
                format!("step limit reached while {operation}"),
            );
            return Err(HostError::StepLimit);
        }
        self.steps_used += 1;
        Ok(())
    }

    fn emit(&mut self, mut event: TraceEvent) {
        if self.trace.len() >= self.limits.max_trace_events {
            if self.retention_limits_reached.insert(RetentionLimit::Trace) {
                self.limits_reached += 1;
                self.push_bounded_warning("trace event limit reached".into());
            }
            return;
        }
        event.sequence = self.trace.len() + 1;
        self.trace.push(event);
    }

    fn add_ioc(&mut self, ioc: Ioc) {
        if !self
            .iocs
            .iter()
            .any(|existing| existing.kind == ioc.kind && existing.value == ioc.value)
        {
            if self.iocs.len() >= self.limits.max_iocs {
                if self.retention_limits_reached.insert(RetentionLimit::Ioc) {
                    self.limits_reached += 1;
                    self.push_bounded_warning("IOC limit reached".into());
                }

                return;
            }
            self.iocs.push(ioc);
        }
    }

    fn add_causal_edge(&mut self, edge: CausalEdge) {
        self.push_causal_edge(edge);
    }

    fn add_artifact(
        &mut self,
        kind: ArtifactKind,
        name: &str,
        media_type: &str,
        bytes: &[u8],
        depth: usize,
    ) -> usize {
        if self.artifacts.len() >= self.limits.max_artifacts {
            if self
                .retention_limits_reached
                .insert(RetentionLimit::Artifact)
            {
                self.record_limit(Engine::Runbox, depth, "artifact count limit reached");
            }
            return 0;
        }
        let retained_bytes = self
            .artifacts
            .iter()
            .filter_map(|artifact| artifact.text.as_ref())
            .map(String::len)
            .sum::<usize>();
        let retained_limit = self
            .limits
            .max_total_artifact_bytes
            .saturating_sub(retained_bytes)
            .min(self.limits.max_artifact_bytes)
            .min(bytes.len());
        let stored = &bytes[..retained_limit];
        let truncated = retained_limit < bytes.len();
        let id = self.artifacts.len() + 1;
        let binary_inspection_sha256 =
            self.inspect_binary_bytes(name, bytes, Engine::Runbox, depth);
        self.artifacts.push(Artifact {
            id,
            kind,
            name: name.into(),
            media_type: media_type.into(),
            size: bytes.len(),
            sha256: sha256_hex(bytes),
            text: String::from_utf8(stored.to_vec()).ok(),
            truncated,
            binary_inspection_sha256,
        });
        self.emit(
            TraceEvent::new(
                depth,
                Engine::Runbox,
                EventKind::Artifact,
                format!("captured artifact {name}"),
            )
            .with_data("artifact_id", id.to_string())
            .with_data("sha256", sha256_hex(bytes)),
        );
        if truncated {
            self.record_limit(
                Engine::Runbox,
                depth,
                format!("artifact {name} was truncated by retention limits"),
            );
        }
        id
    }

    fn write_file(
        &mut self,
        path: &str,
        bytes: &[u8],
        append: bool,
        engine: Engine,
        depth: usize,
    ) -> Result<(), HostError> {
        let normalized = self.normalize_path(path);
        self.ensure_parent_directories(&normalized);
        let consumes_slot = self.files.get(&normalized).is_none_or(|file| file.baseline);
        if consumes_slot
            && self.files.values().filter(|file| !file.baseline).count()
                >= self.limits.max_virtual_files
        {
            self.record_limit(engine, depth, "virtual file limit reached");
            return Err(HostError::FileLimit);
        }

        let existing_len = self
            .files
            .get(&normalized)
            .filter(|file| !file.baseline)
            .map_or(0, |file| file.bytes.len());
        let retained_file_bytes = self
            .files
            .values()
            .filter(|file| !file.baseline)
            .map(|file| file.bytes.len())
            .sum::<usize>();
        let retained_without_target = if append {
            retained_file_bytes
        } else {
            retained_file_bytes.saturating_sub(existing_len)
        };
        let total_remaining = self
            .limits
            .max_total_virtual_file_bytes
            .saturating_sub(retained_without_target);
        let file = self.files.entry(normalized.clone()).or_insert(VirtualFile {
            bytes: Vec::new(),
            truncated: false,
            executable: false,
            baseline: false,
            binary_inspection_sha256: None,
        });
        file.baseline = false;
        if !append {
            file.bytes.clear();
            file.truncated = false;
            file.binary_inspection_sha256 = None;
        }
        let remaining = self
            .limits
            .max_artifact_bytes
            .saturating_sub(file.bytes.len());
        let accepted = bytes.len().min(remaining).min(total_remaining);
        file.bytes.extend_from_slice(&bytes[..accepted]);
        if accepted < bytes.len() {
            file.truncated = true;
            self.record_limit(
                engine,
                depth,
                format!("virtual file {normalized} was truncated"),
            );
        }
        let final_bytes = self
            .files
            .get(&normalized)
            .map_or_else(Vec::new, |entry| entry.bytes.clone());
        let final_sha256 = sha256_hex(&final_bytes);
        let inspection_bytes = if append {
            final_bytes.as_slice()
        } else {
            bytes
        };
        let binary_inspection_sha256 =
            self.inspect_binary_bytes(&normalized, inspection_bytes, engine, depth);
        if let Some(file) = self.files.get_mut(&normalized) {
            file.binary_inspection_sha256 =
                binary_inspection_sha256.filter(|sha256| sha256 == &final_sha256);
        }
        self.add_ioc(Ioc {
            kind: IocKind::FilePath,
            value: normalized.clone(),
            source: format!("{engine:?} file write"),
            depth,
        });
        self.emit(
            TraceEvent::new(
                depth,
                engine,
                EventKind::FileWrite,
                format!("wrote virtual file {normalized}"),
            )
            .with_data("path", &normalized)
            .with_data("bytes", bytes.len().to_string())
            .with_data("append", append.to_string())
            .with_data("sha256", final_sha256),
        );
        Ok(())
    }

    fn read_file(&mut self, path: &str, engine: Engine, depth: usize) -> Option<Vec<u8>> {
        let normalized = self.normalize_path(path);
        let bytes = self.files.get(&normalized).map(|file| file.bytes.clone());
        self.emit(
            TraceEvent::new(
                depth,
                engine,
                EventKind::FileRead,
                format!("read virtual file {normalized}"),
            )
            .with_data("found", bytes.is_some().to_string()),
        );
        bytes
    }

    fn delete_file(&mut self, path: &str, engine: Engine, depth: usize) -> bool {
        let normalized = self.normalize_path(path);
        let removed = self.files.remove(&normalized).is_some();
        self.emit(
            TraceEvent::new(
                depth,
                engine,
                EventKind::FileDelete,
                format!("deleted virtual file {normalized}"),
            )
            .with_data("found", removed.to_string()),
        );
        removed
    }

    fn list_files(&mut self, prefix: &str, engine: Engine, depth: usize) -> Vec<String> {
        let normalized = self.normalize_path(prefix);
        let files = self
            .files
            .keys()
            .filter(|path| path.starts_with(&normalized))
            .cloned()
            .collect::<Vec<_>>();
        self.emit(
            TraceEvent::new(
                depth,
                engine,
                EventKind::FileRead,
                format!("listed virtual files under {normalized}"),
            )
            .with_data("count", files.len().to_string()),
        );
        files
    }

    fn create_directory(
        &mut self,
        path: &str,
        engine: Engine,
        depth: usize,
    ) -> Result<(), HostError> {
        let normalized = self.normalize_path(path);
        self.ensure_parent_directories(&normalized);
        self.directories.entry(normalized.clone()).or_insert(false);
        self.emit(
            TraceEvent::new(
                depth,
                engine,
                EventKind::FileWrite,
                format!("created virtual directory {normalized}"),
            )
            .with_data("path", normalized)
            .with_data("entry_type", "directory"),
        );
        Ok(())
    }

    fn directory_exists(&self, path: &str) -> bool {
        self.directories.contains_key(&self.normalize_path(path))
    }

    fn list_directories(&mut self, prefix: &str, engine: Engine, depth: usize) -> Vec<String> {
        let normalized = self.normalize_path(prefix);
        let directories = self
            .directories
            .keys()
            .filter(|path| path.starts_with(&normalized))
            .cloned()
            .collect::<Vec<_>>();
        self.emit(
            TraceEvent::new(
                depth,
                engine,
                EventKind::FileRead,
                format!("listed virtual directories under {normalized}"),
            )
            .with_data("count", directories.len().to_string())
            .with_data("entry_type", "directory"),
        );
        directories
    }

    fn delete_directory(
        &mut self,
        path: &str,
        recurse: bool,
        engine: Engine,
        depth: usize,
    ) -> bool {
        let normalized = self.normalize_path(path);
        let separator = self.path_separator();
        let prefix = format!("{}{separator}", normalized.trim_end_matches(separator));
        let has_children = self
            .directories
            .keys()
            .any(|candidate| candidate.starts_with(&prefix))
            || self
                .files
                .keys()
                .any(|candidate| candidate.starts_with(&prefix));
        if has_children && !recurse {
            return false;
        }
        if recurse {
            self.directories
                .retain(|candidate, _| !candidate.starts_with(&prefix));
            self.files
                .retain(|candidate, _| !candidate.starts_with(&prefix));
        }
        let removed = self.directories.remove(&normalized).is_some();
        self.emit(
            TraceEvent::new(
                depth,
                engine,
                EventKind::FileDelete,
                format!("deleted virtual directory {normalized}"),
            )
            .with_data("found", removed.to_string())
            .with_data("recurse", recurse.to_string()),
        );
        removed
    }

    fn register_executable(
        &mut self,
        path: &str,
        engine: Engine,
        depth: usize,
    ) -> Result<(), HostError> {
        let normalized = self.normalize_path(path);
        self.ensure_parent_directories(&normalized);
        let consumes_slot = self.files.get(&normalized).is_none_or(|file| file.baseline);
        if consumes_slot
            && self.files.values().filter(|file| !file.baseline).count()
                >= self.limits.max_virtual_files
        {
            self.record_limit(engine, depth, "virtual file limit reached");
            return Err(HostError::FileLimit);
        }
        let file = self.files.entry(normalized.clone()).or_insert(VirtualFile {
            bytes: Vec::new(),
            truncated: false,
            executable: true,
            baseline: false,
            binary_inspection_sha256: None,
        });
        file.executable = true;
        file.baseline = false;
        let bytes = file.bytes.clone();
        let binary_inspection_sha256 =
            self.inspect_binary_bytes(&normalized, &bytes, engine, depth);
        if let Some(file) = self.files.get_mut(&normalized) {
            file.binary_inspection_sha256 = binary_inspection_sha256;
        }
        self.emit(
            TraceEvent::new(
                depth,
                engine,
                EventKind::FileWrite,
                format!("registered virtual executable {normalized}"),
            )
            .with_data("path", &normalized)
            .with_data("entry_type", "executable"),
        );
        if let Some(sequence) = self.trace.last().map(|event| event.sequence) {
            self.push_causal_edge(CausalEdge {
                from: CausalEntity::VirtualFile {
                    path: normalized.clone(),
                },
                to: CausalEntity::TraceEvent { sequence },
                relation: CausalRelation::MarkedExecutable,
                depth,
            });
        }
        Ok(())
    }

    fn is_executable(&self, path: &str) -> bool {
        self.files
            .get(&self.normalize_path(path))
            .is_some_and(|file| file.executable)
    }

    fn set_environment(&mut self, name: &str, value: &str) {
        self.environment
            .insert(self.environment_name(name), value.into());
    }

    fn environment(&self, name: &str) -> Option<&str> {
        self.environment
            .get(&self.environment_name(name))
            .map(String::as_str)
    }

    fn environment_entries(&self) -> Vec<(String, String)> {
        self.environment
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect()
    }

    fn remove_environment(&mut self, name: &str) -> bool {
        self.environment
            .remove(&self.environment_name(name))
            .is_some()
    }

    fn write_registry(&mut self, path: &str, value: &str, engine: Engine, depth: usize) {
        let normalized = path.to_ascii_lowercase();
        self.registry.insert(normalized.clone(), value.into());
        self.add_ioc(Ioc {
            kind: IocKind::RegistryPath,
            value: path.into(),
            source: format!("{engine:?} registry write"),
            depth,
        });
        self.emit(
            TraceEvent::new(
                depth,
                engine,
                EventKind::RegistryWrite,
                format!("wrote virtual registry value {path}"),
            )
            .with_data("value", value),
        );
    }

    fn read_registry(&mut self, path: &str, engine: Engine, depth: usize) -> Option<String> {
        let value = self.registry.get(&path.to_ascii_lowercase()).cloned();
        self.emit(
            TraceEvent::new(
                depth,
                engine,
                EventKind::RegistryRead,
                format!("read virtual registry value {path}"),
            )
            .with_data("found", value.is_some().to_string()),
        );
        value
    }

    fn list_registry(
        &mut self,
        prefix: &str,
        engine: Engine,
        depth: usize,
    ) -> Vec<(String, String)> {
        let normalized = prefix.trim_end_matches('\\').to_ascii_lowercase();
        let child_prefix = format!("{normalized}\\");
        let values = self
            .registry
            .iter()
            .filter(|(path, _)| path.as_str() == normalized || path.starts_with(&child_prefix))
            .map(|(path, value)| (path.clone(), value.clone()))
            .collect::<Vec<_>>();
        self.emit(
            TraceEvent::new(
                depth,
                engine,
                EventKind::RegistryRead,
                format!("listed virtual registry values under {prefix}"),
            )
            .with_data("count", values.len().to_string()),
        );
        values
    }

    fn delete_registry(
        &mut self,
        path: &str,
        recurse: bool,
        engine: Engine,
        depth: usize,
    ) -> usize {
        let normalized = path.to_ascii_lowercase();
        let prefix = format!("{}\\", normalized.trim_end_matches('\\'));
        let keys = self
            .registry
            .keys()
            .filter(|candidate| {
                candidate.as_str() == normalized
                    || (recurse && candidate.starts_with(prefix.as_str()))
            })
            .cloned()
            .collect::<Vec<_>>();
        for key in &keys {
            self.registry.remove(key);
        }
        self.emit(
            TraceEvent::new(
                depth,
                engine,
                EventKind::RegistryWrite,
                format!("deleted virtual registry item {path}"),
            )
            .with_data("removed", keys.len().to_string())
            .with_data("recurse", recurse.to_string()),
        );
        keys.len()
    }

    fn network_intent(&mut self, intent: NetworkIntent) {
        self.record_network_intent(intent, "blocked");
    }

    fn network_request(&mut self, intent: NetworkIntent) -> Option<NetworkResponse> {
        let exact = self
            .network_responses
            .get(&(intent.method.clone(), intent.url.clone()))
            .cloned();
        let request = NetworkRequest {
            method: intent.method.clone(),
            url: intent.url.clone(),
            headers: BTreeMap::new(),
            body: Vec::new(),
            origin: intent.origin.clone(),
            depth: intent.depth,
        };
        let access = if exact.is_some() {
            "fixture"
        } else if self.network_policy.enabled {
            "real"
        } else {
            "blocked"
        };
        let activity_index = self.record_network_intent(intent, access);
        if let Some(response) = exact {
            self.record_network_response(activity_index, &response, NetworkOutcome::Fixture);
            return Some(response);
        }
        if self.network_policy.enabled {
            return match network::send(&self.network_policy, &request) {
                Ok(fetch) => {
                    self.record_network_fetch(activity_index, &fetch);
                    Some(fetch.response)
                }
                Err(error) => {
                    self.record_network_failure(activity_index, &error);
                    self.unsupported(
                        Engine::Runbox,
                        request.depth,
                        &format!("network request failed for {}: {error}", request.url),
                    );
                    None
                }
            };
        }
        let response = self.default_network_response.clone();
        if let Some(response) = &response {
            self.record_network_response(activity_index, response, NetworkOutcome::Blocked);
        }
        response
    }

    fn network_request_detailed(&mut self, request: NetworkRequest) -> Option<NetworkResponse> {
        let exact = self
            .network_responses
            .get(&(request.method.clone(), request.url.clone()))
            .cloned();
        let body_sha256 = sha256_hex(&request.body);
        let headers = request.headers.len();
        let intent = NetworkIntent {
            method: request.method.clone(),
            url: request.url.clone(),
            origin: request.origin.clone(),
            depth: request.depth,
        };
        let access = if exact.is_some() {
            "fixture"
        } else if self.network_policy.enabled {
            "real"
        } else {
            "blocked"
        };
        let activity_index = self.record_network_intent(intent, access);
        if let Some(event) = self.trace.last_mut() {
            event
                .data
                .insert("request_body_bytes".into(), request.body.len().to_string());
            event.data.insert("request_body_sha256".into(), body_sha256);
            event
                .data
                .insert("request_headers".into(), headers.to_string());
        }

        if let Some(response) = exact {
            self.record_network_response(activity_index, &response, NetworkOutcome::Fixture);
            return Some(response);
        }
        if self.network_policy.enabled {
            return match network::send(&self.network_policy, &request) {
                Ok(fetch) => {
                    self.record_network_fetch(activity_index, &fetch);
                    Some(fetch.response)
                }
                Err(error) => {
                    self.record_network_failure(activity_index, &error);
                    self.unsupported(
                        Engine::Runbox,
                        request.depth,
                        &format!("network request failed for {}: {error}", request.url),
                    );
                    None
                }
            };
        }
        let response = self.default_network_response.clone();
        if let Some(response) = &response {
            self.record_network_response(activity_index, response, NetworkOutcome::Blocked);
        }
        response
    }

    fn latest_network_activity_id(&self) -> Option<usize> {
        VirtualHost::latest_network_activity_id(self)
    }

    fn process_intent(&mut self, intent: ProcessIntent) -> Result<(), HostError> {
        self.record_process_request(&intent)?;
        self.process_intents.push_back(intent);
        Ok(())
    }

    fn unsupported(&mut self, engine: Engine, depth: usize, operation: &str) {
        self.unsupported_operations += 1;
        self.emit(TraceEvent::new(
            depth,
            engine,
            EventKind::Unsupported,
            operation,
        ));
    }

    fn warning(&mut self, warning: String) {
        self.push_bounded_warning(warning);
    }
}

#[must_use]
pub fn normalize_path_for(platform: HostPlatform, path: &str) -> String {
    match platform {
        HostPlatform::Windows => normalize_windows_path(path),
        HostPlatform::MacOs | HostPlatform::Linux => normalize_posix_path(path),
    }
}

#[must_use]
pub fn normalize_posix_path(path: &str) -> String {
    let path = path.trim().trim_matches('"').replace('\\', "/");
    let absolute = path.starts_with('/');
    let mut parts = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            _ => parts.push(part),
        }
    }
    if absolute {
        if parts.is_empty() {
            "/".into()
        } else {
            format!("/{}", parts.join("/"))
        }
    } else if parts.is_empty() {
        ".".into()
    } else {
        parts.join("/")
    }
}

#[must_use]
pub fn normalize_windows_path(path: &str) -> String {
    let mut normalized = path.trim().trim_matches('"').replace('/', "\\");
    while normalized.contains("\\\\") {
        normalized = normalized.replace("\\\\", "\\");
    }
    normalized.to_ascii_lowercase()
}

#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[must_use]
fn extract_url_host(url: &str) -> Option<String> {
    let (_, remainder) = url.split_once("://")?;
    let authority = remainder.split(['/', '?', '#']).next()?;
    let host = authority.rsplit('@').next()?.split(':').next()?;
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_elf64() -> Vec<u8> {
        let mut bytes = vec![0_u8; 120];
        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
        bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&0x0040_0078_u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&1_u16.to_le_bytes());
        bytes[58..60].copy_from_slice(&64_u16.to_le_bytes());
        bytes[64..68].copy_from_slice(&1_u32.to_le_bytes());
        bytes[68..72].copy_from_slice(&5_u32.to_le_bytes());
        bytes[80..88].copy_from_slice(&0x0040_0000_u64.to_le_bytes());
        bytes[88..96].copy_from_slice(&0x0040_0000_u64.to_le_bytes());
        bytes[96..104].copy_from_slice(&120_u64.to_le_bytes());
        bytes[104..112].copy_from_slice(&120_u64.to_le_bytes());
        bytes[112..120].copy_from_slice(&0x1000_u64.to_le_bytes());
        bytes
    }

    #[test]
    fn virtual_host_records_but_does_not_execute_network_intents() {
        let mut host = VirtualHost::new(AnalysisLimits::default());
        host.network_intent(NetworkIntent {
            method: "GET".into(),
            url: "https://example.invalid/payload".into(),
            origin: "unit test".into(),
            depth: 0,
        });

        let snapshot = host.snapshot();
        assert_eq!(snapshot.iocs.len(), 2);
        assert_eq!(snapshot.trace[0].kind, EventKind::NetworkIntent);
        assert_eq!(snapshot.network_activity.len(), 1);
        assert_eq!(
            snapshot.network_activity[0].outcome,
            NetworkOutcome::Blocked
        );
    }

    #[test]
    fn aggregate_retention_limits_bound_host_state() {
        let limits = AnalysisLimits {
            max_artifact_bytes: 8,
            max_artifacts: 1,
            max_total_artifact_bytes: 4,
            max_virtual_files: 4,
            max_total_virtual_file_bytes: 5,
            max_trace_events: 1,
            max_iocs: 1,
            max_warnings: 4,
            ..AnalysisLimits::default()
        };
        let mut host = VirtualHost::new(limits);

        host.add_artifact(
            ArtifactKind::DecodedText,
            "first",
            "text/plain",
            b"abcdefgh",
            0,
        );
        host.add_artifact(
            ArtifactKind::DecodedText,
            "second",
            "text/plain",
            b"ignored",
            0,
        );
        host.add_virtual_file(r"C:\one.bin", b"1234").unwrap();
        host.add_virtual_file(r"C:\two.bin", b"5678").unwrap();
        host.add_ioc(Ioc {
            kind: IocKind::Domain,
            value: "one.invalid".into(),
            source: "test".into(),
            depth: 0,
        });
        host.add_ioc(Ioc {
            kind: IocKind::Domain,
            value: "two.invalid".into(),
            source: "test".into(),
            depth: 0,
        });

        let snapshot = host.snapshot();
        assert_eq!(snapshot.artifacts.len(), 1);
        assert_eq!(snapshot.artifacts[0].text.as_deref(), Some("abcd"));
        assert!(snapshot.artifacts[0].truncated);
        assert_eq!(
            snapshot
                .virtual_files
                .iter()
                .map(|file| file.size)
                .sum::<usize>(),
            5
        );
        assert_eq!(snapshot.trace.len(), 1);
        assert_eq!(snapshot.iocs.len(), 1);
        assert!(snapshot.limits_reached >= 3);
        assert!(!snapshot.warnings.is_empty());
    }

    #[test]
    fn binary_inspection_uses_original_bytes_and_caches_by_hash() {
        let limits = AnalysisLimits {
            max_artifact_bytes: 64,
            max_total_virtual_file_bytes: 256,
            ..AnalysisLimits::default()
        };
        let bytes = minimal_elf64();
        let mut host = VirtualHost::linux(limits);

        host.add_virtual_file("/tmp/payload", &bytes).unwrap();
        host.add_virtual_file("/tmp/copy", &bytes).unwrap();

        let snapshot = host.snapshot();
        assert_eq!(snapshot.binary_inspections.len(), 1);
        assert_eq!(snapshot.binary_inspections[0].inspection.original_size, 120);
        assert_eq!(
            snapshot.binary_inspections[0].inspection.inspected_bytes,
            120
        );
        assert_eq!(snapshot.binary_inspections[0].sources.len(), 2);
        assert_eq!(
            snapshot
                .virtual_files
                .iter()
                .find(|file| file.path == "/tmp/payload")
                .map(|file| file.size),
            Some(64)
        );
        assert!(snapshot
            .virtual_files
            .iter()
            .all(|file| file.binary_inspection_sha256.is_none()));
    }

    #[test]
    fn malformed_binary_magic_is_retained_as_partial_inspection() {
        let mut host = VirtualHost::new(AnalysisLimits::default());

        host.add_virtual_file(r"C:\Temp\broken.exe", b"MZ-broken")
            .unwrap();

        let snapshot = host.snapshot();
        assert_eq!(snapshot.binary_inspections.len(), 1);
        assert_eq!(
            snapshot.binary_inspections[0].inspection.status,
            InspectionStatus::Partial
        );
        assert!(!snapshot.binary_inspections[0]
            .inspection
            .warnings
            .is_empty());
    }

    #[test]
    fn virtual_host_uses_windows_11_environment_defaults() {
        let host = VirtualHost::new(AnalysisLimits::default());

        assert_eq!(host.environment("OS"), Some("Windows_NT"));
        assert_eq!(host.environment("COMPUTERNAME"), Some("ANALYSIS-HOST"));
        assert_eq!(host.environment("USERNAME"), Some("analysis"));
        assert_eq!(host.environment("USERDOMAIN"), Some("ANALYSIS"));
        assert_eq!(host.environment("PROCESSOR_ARCHITECTURE"), Some("AMD64"));
        assert_eq!(host.environment("ProgramFiles"), Some(r"C:\Program Files"));
        assert_eq!(
            host.environment("LOCALAPPDATA"),
            Some(r"C:\Users\analysis\AppData\Local")
        );
        assert!(host
            .environment("PATH")
            .is_some_and(|path| path.contains("WindowsPowerShell")));
        assert!(host.environment_entries().len() >= 35);
        assert!(host.directory_exists(r"C:\Users\analysis\Desktop"));
        assert!(host.is_executable(r"C:\Windows\System32\cmd.exe"));
        assert!(host.is_executable(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"));
        assert!(host.snapshot().virtual_files.is_empty());
        assert!(host.snapshot().virtual_directories.is_empty());
    }

    #[test]
    fn virtual_host_supports_macos_paths_and_case_sensitive_environment() {
        let mut host = VirtualHost::macos(AnalysisLimits::default());

        assert_eq!(host.platform(), HostPlatform::MacOs);
        assert_eq!(host.environment("HOME"), Some("/Users/analysis"));
        assert_eq!(host.environment("home"), None);
        assert!(host.directory_exists("/Users/analysis/Downloads"));
        assert!(host.is_executable("/bin/bash"));
        host.add_virtual_file("/Users/analysis/Test.sh", b"echo safe")
            .unwrap();
        assert_eq!(
            host.virtual_file("/Users/analysis/Test.sh"),
            Some(&b"echo safe"[..])
        );
        assert!(host.virtual_file("/users/analysis/test.sh").is_none());
    }

    #[test]
    fn virtual_host_supports_linux_paths_environment_and_executables() {
        let mut host = VirtualHost::linux(AnalysisLimits::default());

        assert_eq!(host.platform(), HostPlatform::Linux);
        assert_eq!(host.environment("HOME"), Some("/home/analysis"));
        assert_eq!(host.environment("home"), None);
        assert!(host.directory_exists("/etc/systemd/system"));
        assert!(host.directory_exists("/home/analysis/.config/systemd/user"));
        assert!(host.is_executable("/bin/bash"));
        assert!(host.is_executable("/usr/bin/systemctl"));
        assert!(host
            .virtual_file("/etc/os-release")
            .is_some_and(|bytes| bytes.starts_with(b"NAME=\"Analysis Linux\"")));
        host.add_virtual_file("/etc/systemd/system/example.service", b"[Service]\n")
            .unwrap();
        assert_eq!(
            host.virtual_file("/etc/systemd/system/example.service"),
            Some(&b"[Service]\n"[..])
        );
    }

    #[test]
    fn virtual_environment_mutation_api_adds_and_removes_entries() {
        let mut host = VirtualHost::new(AnalysisLimits::default());
        host.add_virtual_directory(r"C:\Tools").unwrap();
        host.add_virtual_file(r"C:\Tools\config.txt", b"safe")
            .unwrap();
        host.add_virtual_executable(r"C:\Tools\tool.exe").unwrap();
        host.set_environment_variable("TOOL_HOME", r"C:\Tools");
        host.set_registry_value(r"HKCU\Software\Example\Path", r"C:\Tools");

        assert_eq!(
            host.virtual_file(r"C:\Tools\config.txt"),
            Some(&b"safe"[..])
        );
        assert!(host
            .virtual_directory_paths()
            .contains(&r"c:\tools".to_owned()));
        assert!(host
            .virtual_executable_paths()
            .contains(&r"c:\tools\tool.exe".to_owned()));
        assert_eq!(host.environment_variable("tool_home"), Some(r"C:\Tools"));
        assert_eq!(
            host.registry_value(r"HKCU\Software\Example\Path"),
            Some(r"C:\Tools")
        );

        assert!(host.remove_virtual_executable(r"C:\Tools\tool.exe"));
        assert!(host.remove_virtual_file(r"C:\Tools\config.txt"));
        assert!(host.remove_virtual_directory(r"C:\Tools", false));
        assert!(host.remove_environment_variable("TOOL_HOME"));
        assert_eq!(
            host.remove_registry_value(r"HKCU\Software\Example\Path", false),
            1
        );
    }

    #[test]
    fn enabled_network_rejects_private_destinations() {
        let mut host = VirtualHost::new(AnalysisLimits::default());
        host.set_network_policy(NetworkPolicy::public_http());
        let response = host.network_request(NetworkIntent {
            method: "GET".into(),
            url: "http://127.0.0.1/private".into(),
            origin: "unit test".into(),
            depth: 0,
        });

        assert!(response.is_none());
        let snapshot = host.snapshot();
        assert!(snapshot
            .trace
            .iter()
            .any(|event| event.kind == EventKind::Unsupported
                && event.message.contains("destination is not public")));
        assert_eq!(snapshot.network_activity[0].outcome, NetworkOutcome::Failed);
        assert!(snapshot.network_activity[0]
            .error
            .as_deref()
            .is_some_and(|error| error.contains("destination is not public")));
    }

    #[test]
    fn exact_network_fixtures_override_enabled_network() {
        let mut host = VirtualHost::new(AnalysisLimits::default());
        host.set_network_policy(NetworkPolicy::public_http());
        host.register_network_response(
            "GET",
            "http://127.0.0.1/fixture",
            NetworkResponse::text("fixture"),
        );

        let response = host.network_request(NetworkIntent {
            method: "GET".into(),
            url: "http://127.0.0.1/fixture".into(),
            origin: "unit test".into(),
            depth: 0,
        });

        assert_eq!(response, Some(NetworkResponse::text("fixture")));
        let activity = &host.snapshot().network_activity[0];
        assert_eq!(activity.outcome, NetworkOutcome::Fixture);
        assert_eq!(activity.status, Some(200));
        assert_eq!(activity.response_bytes, Some(7));
    }

    #[test]
    fn virtual_host_returns_cloned_registered_network_responses() {
        let mut host = VirtualHost::new(AnalysisLimits::default());
        let response = NetworkResponse {
            status: 200,
            headers: BTreeMap::from([("content-type".into(), "text/plain".into())]),
            body: b"fixture body".to_vec(),
        };
        host.register_network_response("GET", "https://example.invalid/payload", response.clone());

        let intent = NetworkIntent {
            method: "GET".into(),
            url: "https://example.invalid/payload".into(),
            origin: "unit test".into(),
            depth: 2,
        };
        let host_api: &mut dyn Host = &mut host;
        let mut first = host_api.network_request(intent.clone()).unwrap();
        first.body.clear();
        assert_eq!(host_api.network_request(intent), Some(response));

        let snapshot = host.snapshot();
        assert_eq!(snapshot.trace.len(), 2);
        assert!(snapshot
            .trace
            .iter()
            .all(|event| event.kind == EventKind::NetworkIntent));
        assert_eq!(snapshot.trace[0].data["method"], "GET");
        assert_eq!(
            snapshot.trace[0].data["url"],
            "https://example.invalid/payload"
        );
        assert_eq!(snapshot.iocs.len(), 2);
    }

    #[test]
    fn virtual_host_requires_an_exact_method_and_url_fixture_match() {
        let mut host = VirtualHost::new(AnalysisLimits::default());
        host.clear_default_network_response();
        host.register_network_response(
            "GET",
            "https://example.invalid/payload",
            NetworkResponse {
                status: 204,
                headers: BTreeMap::new(),
                body: Vec::new(),
            },
        );

        assert!(host
            .network_request(NetworkIntent {
                method: "POST".into(),
                url: "https://example.invalid/payload".into(),
                origin: "unit test".into(),
                depth: 0,
            })
            .is_none());
        assert!(host
            .network_request(NetworkIntent {
                method: "GET".into(),
                url: "https://example.invalid/other".into(),
                origin: "unit test".into(),
                depth: 0,
            })
            .is_none());

        assert_eq!(host.snapshot().trace.len(), 2);
    }

    #[test]
    fn virtual_host_returns_an_empty_blocked_response_by_default() {
        let mut host = VirtualHost::new(AnalysisLimits::default());

        let response = host
            .network_request(NetworkIntent {
                method: "GET".into(),
                url: "https://example.invalid/default".into(),
                origin: "unit test".into(),
                depth: 0,
            })
            .unwrap();

        assert_eq!(response, NetworkResponse::text(""));
        assert_eq!(host.snapshot().trace[0].kind, EventKind::NetworkIntent);
    }

    #[test]
    fn default_process_requests_remain_deferred() {
        let mut host = VirtualHost::new(AnalysisLimits::default());
        let intent = ProcessIntent {
            program: "tool.exe".into(),
            args: vec!["safe".into()],
            command_line: "tool.exe safe".into(),
            origin: "unit test".into(),
            depth: 1,
            stdin: Vec::new(),
            current_directory: r"C:\Users\analysis".into(),
            causes: Vec::new(),
        };

        assert_eq!(host.process_request(intent.clone()).unwrap(), None);
        assert_eq!(host.take_process_intents().len(), 1);
        assert_eq!(host.snapshot().trace[0].kind, EventKind::ProcessIntent);
    }

    #[test]
    fn exact_network_fixture_overrides_default_response() {
        let mut host = VirtualHost::new(AnalysisLimits::default());
        host.set_default_network_response_text("fallback");
        host.register_network_response(
            "GET",
            "https://example.invalid/exact",
            NetworkResponse::text("exact"),
        );

        let exact = host
            .network_request(NetworkIntent {
                method: "GET".into(),
                url: "https://example.invalid/exact".into(),
                origin: "unit test".into(),
                depth: 0,
            })
            .unwrap();
        let fallback = host
            .network_request(NetworkIntent {
                method: "GET".into(),
                url: "https://example.invalid/other".into(),
                origin: "unit test".into(),
                depth: 0,
            })
            .unwrap();

        assert_eq!(exact.body, b"exact");
        assert_eq!(fallback.body, b"fallback");
    }

    #[test]
    fn virtual_files_are_case_insensitive() {
        let mut host = VirtualHost::new(AnalysisLimits::default());
        host.write_file(
            r"C:\Temp\Drop.txt",
            b"payload",
            false,
            Engine::PowerShell,
            0,
        )
        .unwrap();

        assert_eq!(
            host.read_file(r"c:\temp\drop.txt", Engine::PowerShell, 0),
            Some(b"payload".to_vec())
        );
    }

    #[test]
    fn virtual_host_enumerates_and_removes_provider_state() {
        let mut host = VirtualHost::new(AnalysisLimits::default());
        host.set_environment("Demo", "safe");
        host.write_registry(r"HKCU\Software\Demo\Name", "safe", Engine::PowerShell, 0);
        host.write_registry(r"HKCU\Software\Demo2\Name", "other", Engine::PowerShell, 0);

        assert!(host
            .environment_entries()
            .contains(&("demo".into(), "safe".into())));
        assert_eq!(
            host.list_registry(r"hkcu\software\demo", Engine::PowerShell, 0),
            [(r"hkcu\software\demo\name".into(), "safe".into())]
        );
        assert!(host.remove_environment("DEMO"));
        assert_eq!(
            host.delete_registry(r"HKCU\Software\Demo", true, Engine::PowerShell, 0),
            1
        );
        assert!(host.environment("demo").is_none());
        assert!(host
            .read_registry(r"HKCU\Software\Demo\Name", Engine::PowerShell, 0)
            .is_none());
        assert_eq!(
            host.read_registry(r"HKCU\Software\Demo2\Name", Engine::PowerShell, 0),
            Some("other".into())
        );
    }
}
