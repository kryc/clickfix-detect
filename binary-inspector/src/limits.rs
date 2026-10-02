#[derive(Debug, Clone)]
pub struct BinaryInspectionLimits {
    pub max_inspected_bytes: usize,
    pub max_architectures: usize,
    pub max_sections: usize,
    pub max_imports: usize,
    pub max_exports: usize,
    pub max_dependencies: usize,
    pub max_indicators: usize,
    pub max_strings: usize,
    pub max_entitlement_keys: usize,
    pub max_string_scan_bytes: usize,
    pub min_string_length: usize,
    pub max_string_length: usize,
}

impl Default for BinaryInspectionLimits {
    fn default() -> Self {
        Self {
            max_inspected_bytes: 8 * 1024 * 1024,
            max_architectures: 8,
            max_sections: 128,
            max_imports: 512,
            max_exports: 256,
            max_dependencies: 128,
            max_indicators: 128,
            max_strings: 1_024,
            max_entitlement_keys: 64,
            max_string_scan_bytes: 1024 * 1024,
            min_string_length: 6,
            max_string_length: 512,
        }
    }
}
