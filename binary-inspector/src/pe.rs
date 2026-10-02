use crate::{
    heuristics, BinaryHardening, BinaryImport, BinaryInspection, BinaryInspectionLimits,
    BinaryKind, BinarySection, InspectionStatus,
};
use goblin::pe::{
    dll_characteristic::{
        IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE, IMAGE_DLLCHARACTERISTICS_GUARD_CF,
        IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA, IMAGE_DLLCHARACTERISTICS_NX_COMPAT,
        IMAGE_DLLCHARACTERISTICS_WDM_DRIVER,
    },
    header::machine_to_str,
    section_table::{IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE},
    PE,
};

#[allow(clippy::too_many_lines)]
pub(crate) fn inspect(
    binary: &PE<'_>,
    bytes: &[u8],
    sha256: String,
    original_size: usize,
    inspected_bytes: usize,
    limits: &BinaryInspectionLimits,
) -> BinaryInspection {
    let characteristics = binary
        .header
        .optional_header
        .as_ref()
        .map_or(0, |header| header.windows_fields.dll_characteristics);
    let kind = if characteristics & IMAGE_DLLCHARACTERISTICS_WDM_DRIVER != 0 {
        BinaryKind::Driver
    } else if binary.is_lib {
        BinaryKind::SharedLibrary
    } else {
        BinaryKind::Executable
    };
    let sections = binary
        .sections
        .iter()
        .take(limits.max_sections)
        .map(|section| {
            let start = section.pointer_to_raw_data as usize;
            let size = section.size_of_raw_data as usize;
            let data = start
                .checked_add(size)
                .and_then(|end| bytes.get(start..end))
                .unwrap_or_default();
            BinarySection {
                name: section
                    .name()
                    .map_or_else(|_| "<invalid>".into(), str::to_owned),
                virtual_address: u64::from(section.virtual_address),
                virtual_size: u64::from(section.virtual_size),
                file_offset: u64::from(section.pointer_to_raw_data),
                file_size: u64::from(section.size_of_raw_data),
                readable: section.characteristics & IMAGE_SCN_MEM_READ != 0,
                writable: section.characteristics & IMAGE_SCN_MEM_WRITE != 0,
                executable: section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0,
                entropy_milli_bits: heuristics::entropy_milli(data),
            }
        })
        .collect::<Vec<_>>();
    let imports = binary
        .imports
        .iter()
        .take(limits.max_imports)
        .map(|import| BinaryImport {
            library: Some(import.dll.to_owned()),
            symbol: import.name.to_string(),
            ordinal: Some(u64::from(import.ordinal)),
        })
        .collect();
    let exports = binary
        .exports
        .iter()
        .filter_map(|export| export.name.map(str::to_owned))
        .take(limits.max_exports)
        .collect();
    let dependencies = binary
        .libraries
        .iter()
        .map(|library| (*library).to_owned())
        .take(limits.max_dependencies)
        .collect();
    let mut warnings = Vec::new();
    if binary.sections.len() > limits.max_sections {
        warnings.push("PE section list truncated".into());
    }
    if binary.imports.len() > limits.max_imports {
        warnings.push("PE import list truncated".into());
    }
    if binary.exports.len() > limits.max_exports {
        warnings.push("PE export list truncated".into());
    }
    if binary.libraries.len() > limits.max_dependencies {
        warnings.push("PE dependency list truncated".into());
    }
    let status = if warnings.is_empty() {
        InspectionStatus::Complete
    } else {
        InspectionStatus::Partial
    };
    let overlay_bytes = heuristics::overlay_bytes(
        inspected_bytes,
        binary.sections.iter().filter_map(|section| {
            usize::try_from(section.pointer_to_raw_data)
                .ok()?
                .checked_add(usize::try_from(section.size_of_raw_data).ok()?)
        }),
    );
    let signature_bytes = binary
        .certificates
        .iter()
        .map(|certificate| certificate.length as usize)
        .sum::<usize>();
    let packer_markers = heuristics::packer_markers(bytes, &sections);
    let high_entropy_sections = heuristics::high_entropy_sections(&sections);
    BinaryInspection {
        sha256,
        original_size,
        inspected_bytes,
        format: crate::BinaryFormat::Pe,
        kind,
        status,
        architectures: vec![machine_to_str(binary.header.coff_header.machine).to_ascii_lowercase()],
        entry_point: Some(binary.entry.into()),
        little_endian: true,
        is_64_bit: binary.is_64,
        sections,
        imports,
        exports,
        dependencies,
        runtime_paths: Vec::new(),
        interpreter: None,
        build_id: None,
        hardening: BinaryHardening {
            position_independent: Some(
                characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE != 0,
            ),
            non_executable_stack: Some(characteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT != 0),
            signed: Some(!binary.certificates.is_empty()),
            control_flow_guard: Some(characteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF != 0),
            high_entropy_va: Some(characteristics & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA != 0),
            ..BinaryHardening::default()
        },
        overlay_bytes,
        certificate_count: binary.certificates.len(),
        signature_bytes: (signature_bytes != 0).then_some(signature_bytes),
        entitlement_keys: Vec::new(),
        packer_markers,
        high_entropy_sections,
        capabilities: Vec::new(),
        indicators: Vec::new(),
        warnings,
        truncated: false,
    }
}
