mod calibration;
mod capabilities;
mod elf;
mod heuristics;
mod limits;
mod macho;
mod model;
mod pe;
mod probe;
mod signatures;
mod strings;

pub use calibration::{
    calibrate, CalibrationClass, CalibrationFeature, CalibrationFrequency, CalibrationInput,
    CalibrationReport, CalibrationSummary,
};
pub use limits::BinaryInspectionLimits;
pub use model::{
    BinaryCapability, BinaryFormat, BinaryHardening, BinaryImport, BinaryIndicator,
    BinaryIndicatorKind, BinaryInspection, BinaryKind, BinarySection, InspectionStatus,
    SignatureValidation, SignatureValidationStatus,
};
pub use probe::probe_format;

use goblin::Object;
use sha2::{Digest, Sha256};

#[must_use]
pub fn inspect(bytes: &[u8], limits: &BinaryInspectionLimits) -> Option<BinaryInspection> {
    let format = probe_format(bytes)?;
    let sha256 = hex::encode(Sha256::digest(bytes));
    let inspected_bytes = bytes.len().min(limits.max_inspected_bytes);
    let truncated = inspected_bytes < bytes.len();
    let inspected = &bytes[..inspected_bytes];
    let mut inspection = match Object::parse(inspected) {
        Ok(Object::PE(binary)) => pe::inspect(
            &binary,
            inspected,
            sha256,
            bytes.len(),
            inspected_bytes,
            limits,
        ),
        Ok(Object::Elf(binary)) => elf::inspect(
            &binary,
            inspected,
            sha256,
            bytes.len(),
            inspected_bytes,
            limits,
        ),
        Ok(Object::Mach(binary)) => macho::inspect(
            binary,
            inspected,
            sha256,
            bytes.len(),
            inspected_bytes,
            limits,
        ),
        Ok(_) => BinaryInspection::partial(
            sha256,
            bytes.len(),
            inspected_bytes,
            format,
            "recognized binary magic parsed as an unsupported container".into(),
            truncated,
        ),
        Err(error) => BinaryInspection::partial(
            sha256,
            bytes.len(),
            inspected_bytes,
            format,
            format!("strict binary parse failed: {error}"),
            truncated,
        ),
    };
    inspection.truncated = truncated;
    if truncated {
        inspection.status = InspectionStatus::Partial;
        inspection.warnings.push(format!(
            "binary inspection truncated at {} of {} bytes",
            inspected_bytes,
            bytes.len()
        ));
    }
    inspection.indicators = strings::indicators(inspected, limits);
    inspection.capabilities = capabilities::infer(&inspection.imports, &inspection.dependencies);
    Some(inspection)
}
