use clickfix_detect::{Detector, DetectorInput};
use std::time::{Duration, Instant};

const HOT_ITERATIONS: usize = 20_000;
const THOROUGH_ITERATIONS: usize = 200;
const HOT_LIMIT: Duration = Duration::from_secs(5);
const THOROUGH_LIMIT: Duration = Duration::from_secs(15);

fn main() {
    let detector = Detector::default();
    let hot_started = Instant::now();
    for _ in 0..HOT_ITERATIONS {
        let report = detector
            .analyze(DetectorInput::raw_command("Quarterly roadmap review notes"))
            .expect("hot-path analysis succeeds");
        assert!(report.input.sha256.is_none());
    }
    let hot_elapsed = hot_started.elapsed();

    let thorough_started = Instant::now();
    for _ in 0..THOROUGH_ITERATIONS {
        detector
            .analyze_full(DetectorInput::powershell_script("Write-Output safe"))
            .expect("thorough analysis succeeds");
    }
    let thorough_elapsed = thorough_started.elapsed();

    println!(
        "{{\"hot_iterations\":{HOT_ITERATIONS},\"hot_ms\":{},\"thorough_iterations\":{THOROUGH_ITERATIONS},\"thorough_ms\":{}}}",
        hot_elapsed.as_millis(),
        thorough_elapsed.as_millis()
    );
    assert!(
        hot_elapsed <= HOT_LIMIT,
        "hot-path regression: {hot_elapsed:?} exceeds {HOT_LIMIT:?}"
    );
    assert!(
        thorough_elapsed <= THOROUGH_LIMIT,
        "thorough regression: {thorough_elapsed:?} exceeds {THOROUGH_LIMIT:?}"
    );
}
