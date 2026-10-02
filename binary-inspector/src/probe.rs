use crate::BinaryFormat;

#[must_use]
pub fn probe_format(bytes: &[u8]) -> Option<BinaryFormat> {
    if bytes.starts_with(b"MZ") {
        return Some(BinaryFormat::Pe);
    }
    if bytes.starts_with(b"\x7fELF") {
        return Some(BinaryFormat::Elf);
    }
    let magic = bytes.get(..4)?;
    match magic {
        [0xfe, 0xed, 0xfa, 0xce | 0xcf] | [0xce | 0xcf, 0xfa, 0xed, 0xfe] => {
            Some(BinaryFormat::MachO)
        }
        [0xca, 0xfe, 0xba, 0xbe] | [0xbe, 0xba, 0xfe, 0xca] => Some(BinaryFormat::MachOFat),
        _ => None,
    }
}
