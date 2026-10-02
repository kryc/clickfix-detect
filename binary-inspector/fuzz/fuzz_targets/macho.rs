#![no_main]

use binary_inspector::{inspect, BinaryInspectionLimits};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 8 * 1024 * 1024 {
        return;
    }
    let mut bytes = vec![0xcf, 0xfa, 0xed, 0xfe];
    bytes.extend_from_slice(data);
    let _ = inspect(&bytes, &BinaryInspectionLimits::default());
});
