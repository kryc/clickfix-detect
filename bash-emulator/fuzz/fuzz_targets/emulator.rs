#![no_main]

use bash_emulator::BashEmulator;
use emulator_core::{AnalysisLimits, VirtualHost};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 64 * 1024 {
        return;
    }
    let Ok(source) = std::str::from_utf8(data) else {
        return;
    };
    let mut host = VirtualHost::macos(AnalysisLimits {
        max_steps: 2_000,
        max_depth: 8,
        max_loop_iterations: 64,
        max_decode_passes: 8,
        max_child_processes: 16,
        max_artifact_bytes: 64 * 1024,
        max_virtual_files: 128,
        ..AnalysisLimits::default()
    });
    let mut emulator = BashEmulator::new();
    let _ = emulator.emulate(source, &mut host, 0);
});
