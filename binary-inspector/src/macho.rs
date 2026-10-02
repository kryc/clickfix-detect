use crate::{
    heuristics, BinaryHardening, BinaryImport, BinaryInspection, BinaryInspectionLimits,
    BinaryKind, BinarySection, InspectionStatus,
};
use goblin::mach::{
    constants::{cputype::get_arch_name_from_types, VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE},
    header::{MH_ALLOW_STACK_EXECUTION, MH_BUNDLE, MH_DYLIB, MH_EXECUTE, MH_OBJECT, MH_PIE},
    load_command::CommandVariant,
    Mach, MachO, SingleArch,
};

pub(crate) fn inspect(
    binary: Mach<'_>,
    bytes: &[u8],
    sha256: String,
    original_size: usize,
    inspected_bytes: usize,
    limits: &BinaryInspectionLimits,
) -> BinaryInspection {
    match binary {
        Mach::Binary(binary) => inspect_thin(
            &binary,
            bytes,
            sha256,
            original_size,
            inspected_bytes,
            limits,
        ),
        Mach::Fat(binary) => {
            let mut inspection = BinaryInspection {
                sha256,
                original_size,
                inspected_bytes,
                format: crate::BinaryFormat::MachOFat,
                kind: BinaryKind::Unknown,
                status: InspectionStatus::Complete,
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
                entitlement_keys: Vec::new(),
                packer_markers: Vec::new(),
                high_entropy_sections: Vec::new(),
                capabilities: Vec::new(),
                indicators: Vec::new(),
                warnings: Vec::new(),
                truncated: false,
            };
            for (index, arch) in binary.iter_arches().enumerate() {
                if index >= limits.max_architectures {
                    inspection.status = InspectionStatus::Partial;
                    inspection
                        .warnings
                        .push("Mach-O architecture list truncated".into());
                    break;
                }
                match arch {
                    Ok(arch) => inspection.architectures.push(
                        get_arch_name_from_types(arch.cputype, arch.cpusubtype).map_or_else(
                            || format!("cpu_{:#x}_{:#x}", arch.cputype, arch.cpusubtype),
                            str::to_owned,
                        ),
                    ),
                    Err(error) => {
                        inspection.status = InspectionStatus::Partial;
                        inspection
                            .warnings
                            .push(format!("Mach-O architecture header failed: {error}"));
                    }
                }
                match binary.get(index) {
                    Ok(SingleArch::MachO(arch)) => merge_arch(&mut inspection, &arch, limits),
                    Ok(SingleArch::Archive(_)) => {
                        inspection.status = InspectionStatus::Partial;
                        inspection
                            .warnings
                            .push("fat Mach-O member is an archive".into());
                    }
                    Err(error) => {
                        inspection.status = InspectionStatus::Partial;
                        inspection
                            .warnings
                            .push(format!("Mach-O architecture parse failed: {error}"));
                    }
                }
            }
            inspection.entitlement_keys =
                heuristics::entitlement_keys(bytes, limits.max_entitlement_keys);
            inspection.packer_markers = heuristics::packer_markers(bytes, &inspection.sections);
            inspection.high_entropy_sections =
                heuristics::high_entropy_sections(&inspection.sections);
            inspection
        }
    }
}

fn inspect_thin(
    binary: &MachO<'_>,
    bytes: &[u8],
    sha256: String,
    original_size: usize,
    inspected_bytes: usize,
    limits: &BinaryInspectionLimits,
) -> BinaryInspection {
    let architecture = get_arch_name_from_types(binary.header.cputype, binary.header.cpusubtype)
        .map_or_else(
            || {
                format!(
                    "cpu_{:#x}_{:#x}",
                    binary.header.cputype, binary.header.cpusubtype
                )
            },
            str::to_owned,
        );
    let mut inspection = BinaryInspection {
        sha256,
        original_size,
        inspected_bytes,
        format: crate::BinaryFormat::MachO,
        kind: macho_kind(binary.header.filetype),
        status: InspectionStatus::Complete,
        architectures: vec![architecture],
        entry_point: Some(binary.entry),
        little_endian: binary.little_endian,
        is_64_bit: binary.is_64,
        sections: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        dependencies: Vec::new(),
        runtime_paths: binary
            .rpaths
            .iter()
            .map(|path| (*path).to_owned())
            .collect(),
        interpreter: None,
        build_id: None,
        hardening: BinaryHardening {
            position_independent: Some(binary.header.flags & MH_PIE != 0),
            non_executable_stack: Some(binary.header.flags & MH_ALLOW_STACK_EXECUTION == 0),
            signed: Some(
                binary
                    .load_commands
                    .iter()
                    .any(|command| matches!(command.command, CommandVariant::CodeSignature(_))),
            ),
            ..BinaryHardening::default()
        },
        overlay_bytes: 0,
        certificate_count: 0,
        signature_bytes: signature_bytes(binary),
        entitlement_keys: heuristics::entitlement_keys(bytes, limits.max_entitlement_keys),
        packer_markers: Vec::new(),
        high_entropy_sections: Vec::new(),
        capabilities: Vec::new(),
        indicators: Vec::new(),
        warnings: Vec::new(),
        truncated: false,
    };
    merge_arch(&mut inspection, binary, limits);
    inspection.overlay_bytes = heuristics::overlay_bytes(
        inspected_bytes,
        binary.segments.iter().filter_map(|segment| {
            usize::try_from(segment.fileoff)
                .ok()?
                .checked_add(usize::try_from(segment.filesize).ok()?)
        }),
    );
    inspection.packer_markers = heuristics::packer_markers(bytes, &inspection.sections);
    inspection.high_entropy_sections = heuristics::high_entropy_sections(&inspection.sections);
    inspection
}

fn merge_arch(
    inspection: &mut BinaryInspection,
    binary: &MachO<'_>,
    limits: &BinaryInspectionLimits,
) {
    merge_metadata(inspection, binary);
    merge_segments(inspection, binary, limits.max_sections);
    merge_imports(inspection, binary, limits.max_imports);
    merge_exports(inspection, binary, limits.max_exports);
    merge_dependencies(inspection, binary, limits.max_dependencies);
}

fn merge_metadata(inspection: &mut BinaryInspection, binary: &MachO<'_>) {
    if inspection.kind == BinaryKind::Unknown {
        inspection.kind = macho_kind(binary.header.filetype);
    }
    if inspection.entry_point.is_none() {
        inspection.entry_point = Some(binary.entry);
    }
    if inspection.architectures.len() <= 1 {
        inspection.little_endian = binary.little_endian;
    } else if inspection.little_endian != binary.little_endian {
        inspection.status = InspectionStatus::Partial;
        inspection
            .warnings
            .push("fat Mach-O contains mixed endianness".into());
    }
    inspection.is_64_bit |= binary.is_64;
    merge_hardening_flag(
        &mut inspection.hardening.position_independent,
        binary.header.flags & MH_PIE != 0,
    );
    if inspection.signature_bytes.is_none() {
        inspection.signature_bytes = signature_bytes(binary);
    }
    for path in &binary.rpaths {
        if !inspection
            .runtime_paths
            .iter()
            .any(|existing| existing == path)
        {
            inspection.runtime_paths.push((*path).to_owned());
        }
    }
    merge_hardening_flag(
        &mut inspection.hardening.non_executable_stack,
        binary.header.flags & MH_ALLOW_STACK_EXECUTION == 0,
    );
    merge_hardening_flag(
        &mut inspection.hardening.signed,
        binary
            .load_commands
            .iter()
            .any(|command| matches!(command.command, CommandVariant::CodeSignature(_))),
    );
}

fn merge_segments(inspection: &mut BinaryInspection, binary: &MachO<'_>, limit: usize) {
    for segment in &binary.segments {
        if inspection.sections.len() >= limit {
            inspection.status = InspectionStatus::Partial;
            inspection
                .warnings
                .push("Mach-O segment list truncated".into());
            break;
        }

        inspection.sections.push(BinarySection {
            name: c_name(&segment.segname),
            virtual_address: segment.vmaddr,
            virtual_size: segment.vmsize,
            file_offset: segment.fileoff,
            file_size: segment.filesize,
            readable: segment.initprot & VM_PROT_READ != 0,
            writable: segment.initprot & VM_PROT_WRITE != 0,
            executable: segment.initprot & VM_PROT_EXECUTE != 0,
            entropy_milli_bits: heuristics::entropy_milli(segment.data),
        });
    }
}

fn signature_bytes(binary: &MachO<'_>) -> Option<usize> {
    let size = binary
        .load_commands
        .iter()
        .filter_map(|command| match command.command {
            CommandVariant::CodeSignature(signature) => usize::try_from(signature.datasize).ok(),
            _ => None,
        })
        .sum::<usize>();
    (size != 0).then_some(size)
}

fn merge_imports(inspection: &mut BinaryInspection, binary: &MachO<'_>, limit: usize) {
    match binary.imports() {
        Ok(imports) => {
            for import in imports {
                if inspection.imports.len() >= limit {
                    inspection.status = InspectionStatus::Partial;
                    inspection
                        .warnings
                        .push("Mach-O import list truncated".into());
                    break;
                }
                inspection.imports.push(BinaryImport {
                    library: Some(import.dylib.to_owned()),
                    symbol: import.name.to_owned(),
                    ordinal: None,
                });
            }
        }
        Err(error) => {
            inspection.status = InspectionStatus::Partial;
            inspection
                .warnings
                .push(format!("Mach-O imports failed: {error}"));
        }
    }
}

fn merge_exports(inspection: &mut BinaryInspection, binary: &MachO<'_>, limit: usize) {
    match binary.exports() {
        Ok(exports) => {
            for export in exports {
                if inspection.exports.len() >= limit {
                    inspection.status = InspectionStatus::Partial;
                    inspection
                        .warnings
                        .push("Mach-O export list truncated".into());
                    break;
                }
                inspection.exports.push(export.name.clone());
            }
        }
        Err(error) => {
            inspection.status = InspectionStatus::Partial;
            inspection
                .warnings
                .push(format!("Mach-O exports failed: {error}"));
        }
    }
}

fn merge_dependencies(inspection: &mut BinaryInspection, binary: &MachO<'_>, limit: usize) {
    for library in &binary.libs {
        if inspection.dependencies.len() >= limit {
            inspection.status = InspectionStatus::Partial;
            inspection
                .warnings
                .push("Mach-O dependency list truncated".into());
            break;
        }
        if !inspection.dependencies.iter().any(|item| item == library) {
            inspection.dependencies.push((*library).to_owned());
        }
    }
}

fn merge_hardening_flag(slot: &mut Option<bool>, value: bool) {
    *slot = Some(slot.unwrap_or(true) && value);
}

const fn macho_kind(filetype: u32) -> BinaryKind {
    match filetype {
        MH_EXECUTE => BinaryKind::Executable,
        MH_DYLIB => BinaryKind::SharedLibrary,
        MH_OBJECT => BinaryKind::Object,
        MH_BUNDLE => BinaryKind::Bundle,
        _ => BinaryKind::Unknown,
    }
}

fn c_name(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}
