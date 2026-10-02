use binary_inspector::{
    inspect, probe_format, BinaryFormat, BinaryInspectionLimits, BinaryKind, InspectionStatus,
};

#[test]
fn probes_supported_magic_without_parsing() {
    assert_eq!(probe_format(b"MZ"), Some(BinaryFormat::Pe));
    assert_eq!(probe_format(b"\x7fELF"), Some(BinaryFormat::Elf));
    assert_eq!(
        probe_format(&[0xcf, 0xfa, 0xed, 0xfe]),
        Some(BinaryFormat::MachO)
    );
    assert_eq!(probe_format(b"plain text"), None);
}

#[test]
fn malformed_recognized_binaries_return_partial_reports() {
    let cases: [(&[u8], BinaryFormat); 3] = [
        (b"MZ-not-a-valid-pe", BinaryFormat::Pe),
        (b"\x7fELF-not-valid", BinaryFormat::Elf),
        (&[0xcf, 0xfa, 0xed, 0xfe], BinaryFormat::MachO),
    ];

    for (bytes, format) in cases {
        let inspection = inspect(bytes, &BinaryInspectionLimits::default()).unwrap();
        assert_eq!(inspection.format, format);
        assert_eq!(inspection.status, InspectionStatus::Partial);
        assert!(!inspection.warnings.is_empty());
    }
}

#[test]
fn parses_minimal_elf64_executable() {
    let bytes = minimal_elf64();
    let inspection = inspect(&bytes, &BinaryInspectionLimits::default()).unwrap();

    assert_eq!(inspection.format, BinaryFormat::Elf);
    assert_eq!(inspection.kind, BinaryKind::Executable);
    assert_eq!(inspection.architectures, ["x86_64"]);
    assert_eq!(inspection.entry_point, Some(0x0040_0078));
    assert!(inspection.is_64_bit);
}

#[test]
fn parses_minimal_macho64_executable() {
    let bytes = minimal_macho64();
    let inspection = inspect(&bytes, &BinaryInspectionLimits::default()).unwrap();

    assert_eq!(inspection.format, BinaryFormat::MachO);
    assert_eq!(inspection.kind, BinaryKind::Executable);
    assert_eq!(inspection.architectures, ["x86_64"]);
    assert!(inspection.is_64_bit);
}

#[test]
fn parses_minimal_pe64_executable() {
    let bytes = minimal_pe64();
    let inspection = inspect(&bytes, &BinaryInspectionLimits::default()).unwrap();

    assert_eq!(inspection.format, BinaryFormat::Pe);
    assert_eq!(inspection.kind, BinaryKind::Executable);
    assert_eq!(inspection.architectures, ["x86_64"]);
    assert_eq!(inspection.entry_point, Some(0x1000));
    assert!(inspection.is_64_bit);
    assert_eq!(inspection.sections[0].name, ".text");
}

#[test]
fn reports_pe_overlay_entropy_and_packer_markers() {
    let mut bytes = minimal_pe64();
    let section = 0x98 + 0xf0;
    bytes[section..section + 8].copy_from_slice(b"UPX0\0\0\0\0");
    for (index, byte) in bytes[0x200..0x400].iter_mut().enumerate() {
        *byte = u8::try_from(index % 256).unwrap();
    }
    bytes[0x220..0x224].copy_from_slice(b"UPX!");
    bytes.extend_from_slice(b"overlay-data");

    let inspection = inspect(&bytes, &BinaryInspectionLimits::default()).unwrap();

    assert_eq!(inspection.overlay_bytes, b"overlay-data".len());
    assert!(inspection
        .packer_markers
        .iter()
        .any(|marker| marker == "upx"));
    assert_eq!(inspection.high_entropy_sections, ["UPX0"]);
}

#[test]
fn inspection_limits_produce_partial_reports() {
    let mut bytes = minimal_elf64();
    bytes.resize(512, 0);
    let limits = BinaryInspectionLimits {
        max_inspected_bytes: 64,
        ..BinaryInspectionLimits::default()
    };
    let inspection = inspect(&bytes, &limits).unwrap();

    assert_eq!(inspection.status, InspectionStatus::Partial);
    assert!(inspection.truncated);
    assert_eq!(inspection.inspected_bytes, 64);
}

fn minimal_elf64() -> Vec<u8> {
    let mut bytes = vec![0_u8; 120];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    put_u16(&mut bytes, 16, 2);
    put_u16(&mut bytes, 18, 62);
    put_u32(&mut bytes, 20, 1);
    put_u64(&mut bytes, 24, 0x0040_0078);
    put_u64(&mut bytes, 32, 64);
    put_u16(&mut bytes, 52, 64);
    put_u16(&mut bytes, 54, 56);
    put_u16(&mut bytes, 56, 1);
    put_u16(&mut bytes, 58, 64);
    put_u32(&mut bytes, 64, 1);
    put_u32(&mut bytes, 68, 5);
    put_u64(&mut bytes, 72, 0);
    put_u64(&mut bytes, 80, 0x0040_0000);
    put_u64(&mut bytes, 88, 0x0040_0000);
    put_u64(&mut bytes, 96, 120);
    put_u64(&mut bytes, 104, 120);
    put_u64(&mut bytes, 112, 0x1000);
    bytes
}

fn minimal_macho64() -> Vec<u8> {
    let mut bytes = vec![0_u8; 32];
    bytes[0..4].copy_from_slice(&0xfeed_facf_u32.to_le_bytes());
    put_u32(&mut bytes, 4, 0x0100_0007);
    put_u32(&mut bytes, 8, 3);
    put_u32(&mut bytes, 12, 2);
    put_u32(&mut bytes, 16, 0);
    put_u32(&mut bytes, 20, 0);
    put_u32(&mut bytes, 24, 0x0020_0000);
    bytes
}

fn minimal_pe64() -> Vec<u8> {
    let mut bytes = vec![0_u8; 0x400];
    bytes[0..2].copy_from_slice(b"MZ");
    put_u32(&mut bytes, 0x3c, 0x80);
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    put_u16(&mut bytes, 0x84, 0x8664);
    put_u16(&mut bytes, 0x86, 1);
    put_u16(&mut bytes, 0x94, 0xf0);
    put_u16(&mut bytes, 0x96, 0x22);

    let optional = 0x98;
    put_u16(&mut bytes, optional, 0x20b);
    put_u32(&mut bytes, optional + 4, 0x200);
    put_u32(&mut bytes, optional + 16, 0x1000);
    put_u32(&mut bytes, optional + 20, 0x1000);
    put_u64(&mut bytes, optional + 24, 0x1_4000_0000);
    put_u32(&mut bytes, optional + 32, 0x1000);
    put_u32(&mut bytes, optional + 36, 0x200);
    put_u16(&mut bytes, optional + 40, 6);
    put_u16(&mut bytes, optional + 48, 6);
    put_u32(&mut bytes, optional + 56, 0x2000);
    put_u32(&mut bytes, optional + 60, 0x200);
    put_u16(&mut bytes, optional + 68, 3);
    put_u16(&mut bytes, optional + 70, 0x160);
    put_u64(&mut bytes, optional + 72, 0x10_0000);
    put_u64(&mut bytes, optional + 80, 0x1000);
    put_u64(&mut bytes, optional + 88, 0x10_0000);
    put_u64(&mut bytes, optional + 96, 0x1000);
    put_u32(&mut bytes, optional + 108, 16);

    let section = optional + 0xf0;
    bytes[section..section + 5].copy_from_slice(b".text");
    put_u32(&mut bytes, section + 8, 1);
    put_u32(&mut bytes, section + 12, 0x1000);
    put_u32(&mut bytes, section + 16, 0x200);
    put_u32(&mut bytes, section + 20, 0x200);
    put_u32(&mut bytes, section + 36, 0x6000_0020);
    bytes[0x200] = 0xc3;
    bytes
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
