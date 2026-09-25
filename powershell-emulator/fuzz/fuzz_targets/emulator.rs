#![no_main]

use emulator_core::{AnalysisLimits, VirtualHost};
use libfuzzer_sys::fuzz_target;
use powershell_emulator::PowerShellEmulator;

const MAX_INPUT_BYTES: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }
    let Ok(script) = std::str::from_utf8(data) else {
        return;
    };

    let mut host = VirtualHost::new(AnalysisLimits {
        max_steps: 2_000,
        max_depth: 8,
        max_loop_iterations: 64,
        max_decode_passes: 8,
        max_child_processes: 16,
        max_artifact_bytes: 64 * 1024,
        max_virtual_files: 128,
    });
    let mut emulator = PowerShellEmulator::new();

    let _ = emulator.emulate(script, &mut host, 0);
});
