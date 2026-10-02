use crate::{
    heuristics, BinaryHardening, BinaryImport, BinaryInspection, BinaryInspectionLimits,
    BinaryKind, BinarySection, InspectionStatus,
};
use goblin::elf::{
    header::{ET_CORE, ET_DYN, ET_EXEC, ET_REL},
    note::NT_GNU_BUILD_ID,
    program_header::{PF_X, PT_GNU_RELRO, PT_GNU_STACK},
    section_header::{SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE},
    sym::STB_GLOBAL,
    Elf,
};
use std::collections::BTreeSet;

pub(crate) fn inspect(
    binary: &Elf<'_>,
    bytes: &[u8],
    sha256: String,
    original_size: usize,
    inspected_bytes: usize,
    limits: &BinaryInspectionLimits,
) -> BinaryInspection {
    let kind = match binary.header.e_type {
        ET_EXEC => BinaryKind::Executable,
        ET_DYN if binary.interpreter.is_some() => BinaryKind::Executable,
        ET_DYN => BinaryKind::SharedLibrary,
        ET_REL => BinaryKind::Object,
        ET_CORE => BinaryKind::Core,
        _ => BinaryKind::Unknown,
    };
    let sections = sections(binary, bytes, limits.max_sections);
    let imports = imports(binary, limits.max_imports);
    let exports = exports(binary, limits.max_exports);
    let dependencies = dependencies(binary, limits.max_dependencies);
    let stack = binary
        .program_headers
        .iter()
        .find(|header| header.p_type == PT_GNU_STACK);
    let relro = binary
        .program_headers
        .iter()
        .any(|header| header.p_type == PT_GNU_RELRO);
    let mut warnings = truncation_warnings(binary, limits);
    let build_id = build_id(binary, bytes, &mut warnings);
    let mut runtime_paths = binary
        .runpaths
        .iter()
        .chain(binary.rpaths.iter())
        .map(|path| (*path).to_owned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .take(limits.max_dependencies)
        .collect::<Vec<_>>();
    runtime_paths.sort();
    let stack_canary = imports
        .iter()
        .any(|import| import.symbol == "__stack_chk_fail");
    let overlay_bytes = heuristics::overlay_bytes(
        inspected_bytes,
        binary
            .section_headers
            .iter()
            .filter_map(|section| {
                usize::try_from(section.sh_offset)
                    .ok()?
                    .checked_add(usize::try_from(section.sh_size).ok()?)
            })
            .chain(binary.program_headers.iter().filter_map(|header| {
                usize::try_from(header.p_offset)
                    .ok()?
                    .checked_add(usize::try_from(header.p_filesz).ok()?)
            })),
    );
    let packer_markers = heuristics::packer_markers(bytes, &sections);
    let high_entropy_sections = heuristics::high_entropy_sections(&sections);
    BinaryInspection {
        sha256,
        original_size,
        inspected_bytes,
        format: crate::BinaryFormat::Elf,
        kind,
        status: if warnings.is_empty() {
            InspectionStatus::Complete
        } else {
            InspectionStatus::Partial
        },
        architectures: vec![elf_architecture(binary.header.e_machine)],
        entry_point: Some(binary.entry),
        little_endian: binary.little_endian,
        is_64_bit: binary.is_64,
        sections,
        imports,
        exports,
        dependencies,
        runtime_paths,
        interpreter: binary.interpreter.map(str::to_owned),
        build_id,
        hardening: BinaryHardening {
            position_independent: Some(binary.header.e_type == ET_DYN),
            non_executable_stack: stack.map(|header| header.p_flags & PF_X == 0),
            stack_canary: Some(stack_canary),
            relro: Some(relro),
            ..BinaryHardening::default()
        },
        overlay_bytes,
        certificate_count: 0,
        signature_bytes: None,
        entitlement_keys: Vec::new(),
        packer_markers,
        high_entropy_sections,
        capabilities: Vec::new(),
        indicators: Vec::new(),
        warnings,
        truncated: false,
    }
}

fn sections(binary: &Elf<'_>, bytes: &[u8], limit: usize) -> Vec<BinarySection> {
    binary
        .section_headers
        .iter()
        .take(limit)
        .map(|section| {
            let data = usize::try_from(section.sh_offset)
                .ok()
                .and_then(|start| {
                    usize::try_from(section.sh_size)
                        .ok()
                        .and_then(|size| start.checked_add(size))
                        .and_then(|end| bytes.get(start..end))
                })
                .unwrap_or_default();
            BinarySection {
                name: binary
                    .shdr_strtab
                    .get_at(section.sh_name)
                    .unwrap_or("<unnamed>")
                    .to_owned(),
                virtual_address: section.sh_addr,
                virtual_size: section.sh_size,
                file_offset: section.sh_offset,
                file_size: section.sh_size,
                readable: section.sh_flags & u64::from(SHF_ALLOC) != 0,
                writable: section.sh_flags & u64::from(SHF_WRITE) != 0,
                executable: section.sh_flags & u64::from(SHF_EXECINSTR) != 0,
                entropy_milli_bits: heuristics::entropy_milli(data),
            }
        })
        .collect()
}

fn build_id(binary: &Elf<'_>, bytes: &[u8], warnings: &mut Vec<String>) -> Option<String> {
    let notes = binary.iter_note_headers(bytes)?;
    for note in notes {
        match note {
            Ok(note) if note.name == "GNU" && note.n_type == NT_GNU_BUILD_ID => {
                return Some(hex::encode(note.desc));
            }
            Ok(_) => {}
            Err(error) => {
                warnings.push(format!("ELF note parse failed: {error}"));
                return None;
            }
        }
    }
    None
}

fn imports(binary: &Elf<'_>, limit: usize) -> Vec<BinaryImport> {
    binary
        .dynsyms
        .iter()
        .filter(|symbol| symbol.st_shndx == 0)
        .filter_map(|symbol| {
            binary
                .dynstrtab
                .get_at(symbol.st_name)
                .filter(|name| !name.is_empty())
                .map(|name| BinaryImport {
                    library: None,
                    symbol: name.to_owned(),
                    ordinal: None,
                })
        })
        .take(limit)
        .collect()
}

fn exports(binary: &Elf<'_>, limit: usize) -> Vec<String> {
    binary
        .dynsyms
        .iter()
        .filter(|symbol| symbol.st_shndx != 0 && symbol.st_bind() == STB_GLOBAL)
        .filter_map(|symbol| binary.dynstrtab.get_at(symbol.st_name))
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .take(limit)
        .collect()
}

fn dependencies(binary: &Elf<'_>, limit: usize) -> Vec<String> {
    binary
        .libraries
        .iter()
        .map(|library| (*library).to_owned())
        .take(limit)
        .collect()
}

fn truncation_warnings(binary: &Elf<'_>, limits: &BinaryInspectionLimits) -> Vec<String> {
    let mut warnings = Vec::new();
    if binary.section_headers.len() > limits.max_sections {
        warnings.push("ELF section list truncated".into());
    }
    if binary
        .dynsyms
        .iter()
        .filter(|symbol| symbol.st_shndx == 0)
        .count()
        > limits.max_imports
    {
        warnings.push("ELF import list truncated".into());
    }
    if binary
        .dynsyms
        .iter()
        .filter(|symbol| symbol.st_shndx != 0 && symbol.st_bind() == STB_GLOBAL)
        .count()
        > limits.max_exports
    {
        warnings.push("ELF export list truncated".into());
    }
    if binary.libraries.len() > limits.max_dependencies {
        warnings.push("ELF dependency list truncated".into());
    }
    warnings
}

fn elf_architecture(machine: u16) -> String {
    match machine {
        3 => "x86".into(),
        8 => "mips".into(),
        20 => "powerpc".into(),
        21 => "powerpc64".into(),
        40 => "arm".into(),
        62 => "x86_64".into(),
        183 => "aarch64".into(),
        243 => "riscv".into(),
        other => format!("machine_{other:#x}"),
    }
}
