use clickfix_detect::{Detector, DetectorInput};
use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;

fn hot_path(c: &mut Criterion) {
    let detector = Detector::default();
    c.bench_function("prefilter_plain_text", |bench| {
        bench.iter(|| Detector::prefilter(black_box("Quarterly roadmap review notes")));
    });
    c.bench_function("prefilter_clickfix_candidate", |bench| {
        bench.iter(|| {
            Detector::prefilter(black_box(
                "powershell.exe -NoProfile -EncodedCommand SQBFAFgA",
            ))
        });
    });
    c.bench_function("analyze_prefilter_only", |bench| {
        bench.iter(|| {
            detector
                .analyze(DetectorInput::raw_command(black_box(
                    "Quarterly roadmap review notes",
                )))
                .unwrap()
        });
    });
    c.bench_function("analyze_thorough_simple", |bench| {
        bench.iter(|| {
            detector
                .analyze_full(DetectorInput::powershell_script(black_box(
                    "Write-Output safe",
                )))
                .unwrap()
        });
    });
}

criterion_group!(benches, hot_path);
criterion_main!(benches);
