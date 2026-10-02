use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BinaryFormat {
    Pe,
    Elf,
    MachO,
    MachOFat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BinaryKind {
    Executable,
    SharedLibrary,
    Object,
    Core,
    Bundle,
    Driver,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InspectionStatus {
    Complete,
    Partial,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureValidationStatus {
    NotPresent,
    IntegrityValid,
    CryptographicallyValid,
    Invalid,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureValidation {
    pub status: SignatureValidationStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_digest_valid: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_signature_valid: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_chain_valid: Option<bool>,
    pub signer_count: usize,
    pub certificate_count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinarySection {
    pub name: String,
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entropy_milli_bits: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryImport {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub library: Option<String>,
    pub symbol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ordinal: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryHardening {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub position_independent: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub non_executable_stack: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stack_canary: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub control_flow_guard: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub high_entropy_va: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relro: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BinaryCapability {
    CredentialAccess,
    DynamicLoading,
    MemoryInjection,
    Network,
    Persistence,
    ProcessExecution,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BinaryIndicatorKind {
    Url,
    Domain,
    IpAddress,
    Path,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryIndicator {
    pub kind: BinaryIndicatorKind,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryInspection {
    pub sha256: String,
    pub original_size: usize,
    pub inspected_bytes: usize,
    pub format: BinaryFormat,
    pub kind: BinaryKind,
    pub status: InspectionStatus,
    pub architectures: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_point: Option<u64>,
    pub little_endian: bool,
    pub is_64_bit: bool,
    pub sections: Vec<BinarySection>,
    pub imports: Vec<BinaryImport>,
    pub exports: Vec<String>,
    pub dependencies: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub runtime_paths: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interpreter: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_id: Option<String>,
    pub hardening: BinaryHardening,
    pub overlay_bytes: usize,
    pub certificate_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_bytes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_validation: Option<SignatureValidation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entitlement_keys: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub packer_markers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub high_entropy_sections: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gnu_properties: Vec<String>,
    pub capabilities: Vec<BinaryCapability>,
    pub indicators: Vec<BinaryIndicator>,
    pub warnings: Vec<String>,
    pub truncated: bool,
}

impl BinaryInspection {
    pub(crate) fn partial(
        sha256: String,
        original_size: usize,
        inspected_bytes: usize,
        format: BinaryFormat,
        warning: String,
        truncated: bool,
    ) -> Self {
        Self {
            sha256,
            original_size,
            inspected_bytes,
            format,
            kind: BinaryKind::Unknown,
            status: InspectionStatus::Partial,
            architectures: Vec::new(),
            entry_point: None,
            little_endian: true,
            is_64_bit: false,
            sections: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            dependencies: Vec::new(),
            runtime_paths: Vec::new(),
            interpreter: None,
            build_id: None,
            hardening: BinaryHardening::default(),
            overlay_bytes: 0,
            certificate_count: 0,
            signature_bytes: None,
            signature_validation: None,
            entitlement_keys: Vec::new(),
            packer_markers: Vec::new(),
            high_entropy_sections: Vec::new(),
            gnu_properties: Vec::new(),
            capabilities: Vec::new(),
            indicators: Vec::new(),
            warnings: vec![warning],
            truncated,
        }
    }
}
