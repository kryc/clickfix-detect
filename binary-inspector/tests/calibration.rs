use binary_inspector::{
    calibrate, BinaryInspectionLimits, CalibrationClass, CalibrationFeature, CalibrationInput,
};

#[test]
fn generated_cross_format_corpus_keeps_heuristics_non_scoring_and_measurable() {
    let benign_pe = minimal_pe64();
    let suspicious_pe = packed_pe64();
    let benign_elf = minimal_elf64(false);
    let suspicious_elf = minimal_elf64(true);
    let benign_macho = minimal_macho64();
    let samples = [
        CalibrationInput {
            name: "benign-pe",
            class: CalibrationClass::Benign,
            bytes: &benign_pe,
        },
        CalibrationInput {
            name: "benign-elf",
            class: CalibrationClass::Benign,
            bytes: &benign_elf,
        },
        CalibrationInput {
            name: "benign-macho",
            class: CalibrationClass::Benign,
            bytes: &benign_macho,
        },
        CalibrationInput {
            name: "packed-pe",
            class: CalibrationClass::Suspicious,
            bytes: &suspicious_pe,
        },
        CalibrationInput {
            name: "rwx-elf",
            class: CalibrationClass::Suspicious,
            bytes: &suspicious_elf,
        },
    ];

    let report = calibrate(&samples, &BinaryInspectionLimits::default());
    assert_eq!(report.inspected_samples, samples.len());
    assert!(report.rejected_samples.is_empty());
    let benign = report
        .summaries
        .iter()
        .find(|summary| summary.class == CalibrationClass::Benign)
        .unwrap();
    let suspicious = report
        .summaries
        .iter()
        .find(|summary| summary.class == CalibrationClass::Suspicious)
        .unwrap();
    assert_eq!(frequency(benign, CalibrationFeature::PackerMarker), 0);
    assert_eq!(
        frequency(benign, CalibrationFeature::WritableExecutableSection),
        0
    );
    assert!(frequency(suspicious, CalibrationFeature::PackerMarker) >= 5_000);
    assert!(frequency(suspicious, CalibrationFeature::WritableExecutableSection) >= 5_000);
}

fn frequency(summary: &binary_inspector::CalibrationSummary, feature: CalibrationFeature) -> u16 {
    summary
        .frequencies
        .iter()
        .find(|frequency| frequency.feature == feature)
        .map_or(0, |frequency| frequency.rate_basis_points)
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
    put_u32(&mut bytes, optional + 16, 0x1000);
    put_u64(&mut bytes, optional + 24, 0x1_4000_0000);
    put_u32(&mut bytes, optional + 32, 0x1000);
    put_u32(&mut bytes, optional + 36, 0x200);
    put_u32(&mut bytes, optional + 56, 0x2000);
    put_u32(&mut bytes, optional + 60, 0x200);
    put_u16(&mut bytes, optional + 68, 3);
    put_u16(&mut bytes, optional + 70, 0x160);
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

fn packed_pe64() -> Vec<u8> {
    let mut bytes = minimal_pe64();
    let section = 0x98 + 0xf0;
    bytes[section..section + 8].copy_from_slice(b"UPX0\0\0\0\0");
    for (index, byte) in bytes[0x200..0x400].iter_mut().enumerate() {
        *byte = u8::try_from(index % 256).unwrap();
    }
    bytes[0x220..0x224].copy_from_slice(b"UPX!");
    bytes.extend_from_slice(b"overlay");
    bytes
}

fn minimal_elf64(writable_executable: bool) -> Vec<u8> {
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
    put_u32(&mut bytes, 68, if writable_executable { 7 } else { 5 });
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
    put_u32(&mut bytes, 24, 0x0020_0000);
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
