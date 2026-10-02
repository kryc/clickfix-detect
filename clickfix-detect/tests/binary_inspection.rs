use base64::Engine as _;
use clickfix_detect::{Detector, DetectorInput, InputKind, REPORT_SCHEMA_VERSION};
use emulator_core::{BinaryFormat, InspectionStatus};

#[test]
fn decoded_linux_binary_is_exposed_in_detector_report() {
    let encoded = base64::engine::general_purpose::STANDARD.encode(minimal_elf64());
    let report = Detector::default()
        .analyze_full(DetectorInput {
            kind: InputKind::LinuxShellScript,
            content: format!("echo '{encoded}' | base64 -d > /tmp/payload"),
        })
        .unwrap();

    assert_eq!(REPORT_SCHEMA_VERSION, "5");
    assert_eq!(report.binary_inspections.len(), 1);
    assert_eq!(
        report.binary_inspections[0].inspection.format,
        BinaryFormat::Elf
    );
    assert_eq!(
        report.binary_inspections[0].inspection.status,
        InspectionStatus::Complete
    );
    assert!(report.artifacts.iter().any(|artifact| {
        artifact.binary_inspection_sha256.as_deref()
            == Some(report.binary_inspections[0].inspection.sha256.as_str())
    }));
}

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
