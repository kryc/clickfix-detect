use crate::{inspect, BinaryInspection, BinaryInspectionLimits, InspectionStatus};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CalibrationClass {
    Benign,
    Suspicious,
}

#[derive(Debug, Clone, Copy)]
pub struct CalibrationInput<'a> {
    pub name: &'a str,
    pub class: CalibrationClass,
    pub bytes: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CalibrationFeature {
    HighEntropySection,
    InvalidSignature,
    Overlay,
    PackerMarker,
    WritableExecutableSection,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalibrationFrequency {
    pub feature: CalibrationFeature,
    pub count: usize,
    pub rate_basis_points: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalibrationSummary {
    pub class: CalibrationClass,
    pub samples: usize,
    pub frequencies: Vec<CalibrationFrequency>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalibrationReport {
    pub inspected_samples: usize,
    pub rejected_samples: Vec<String>,
    pub summaries: Vec<CalibrationSummary>,
}

#[must_use]
pub fn calibrate(
    samples: &[CalibrationInput<'_>],
    limits: &BinaryInspectionLimits,
) -> CalibrationReport {
    let mut counts = BTreeMap::<(CalibrationClass, CalibrationFeature), usize>::new();
    let mut class_counts = BTreeMap::<CalibrationClass, usize>::new();
    let mut rejected_samples = Vec::new();
    for sample in samples {
        let Some(inspection) = inspect(sample.bytes, limits) else {
            rejected_samples.push(sample.name.into());
            continue;
        };
        *class_counts.entry(sample.class).or_default() += 1;
        for feature in features(&inspection) {
            *counts.entry((sample.class, feature)).or_default() += 1;
        }
    }
    let summaries = [CalibrationClass::Benign, CalibrationClass::Suspicious]
        .into_iter()
        .map(|class| {
            let samples = class_counts.get(&class).copied().unwrap_or_default();
            let frequencies = [
                CalibrationFeature::HighEntropySection,
                CalibrationFeature::InvalidSignature,
                CalibrationFeature::Overlay,
                CalibrationFeature::PackerMarker,
                CalibrationFeature::WritableExecutableSection,
            ]
            .into_iter()
            .map(|feature| {
                let count = counts.get(&(class, feature)).copied().unwrap_or_default();
                CalibrationFrequency {
                    feature,
                    count,
                    rate_basis_points: basis_points(count, samples),
                }
            })
            .collect();
            CalibrationSummary {
                class,
                samples,
                frequencies,
            }
        })
        .collect();
    CalibrationReport {
        inspected_samples: class_counts.values().sum(),
        rejected_samples,
        summaries,
    }
}

fn features(inspection: &BinaryInspection) -> Vec<CalibrationFeature> {
    let mut features = Vec::new();
    if !inspection.high_entropy_sections.is_empty() {
        features.push(CalibrationFeature::HighEntropySection);
    }
    if inspection
        .signature_validation
        .as_ref()
        .is_some_and(|signature| {
            matches!(signature.status, crate::SignatureValidationStatus::Invalid)
        })
        || inspection.status == InspectionStatus::Partial
            && inspection
                .warnings
                .iter()
                .any(|warning| warning.to_ascii_lowercase().contains("signature"))
    {
        features.push(CalibrationFeature::InvalidSignature);
    }
    if inspection.overlay_bytes != 0 {
        features.push(CalibrationFeature::Overlay);
    }
    if !inspection.packer_markers.is_empty() {
        features.push(CalibrationFeature::PackerMarker);
    }
    if inspection
        .sections
        .iter()
        .any(|section| section.writable && section.executable)
    {
        features.push(CalibrationFeature::WritableExecutableSection);
    }
    features
}

fn basis_points(count: usize, total: usize) -> u16 {
    if total == 0 {
        return 0;
    }
    let rate = count.saturating_mul(10_000) / total;
    u16::try_from(rate.min(10_000)).unwrap_or(10_000)
}
