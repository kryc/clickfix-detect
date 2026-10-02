use crate::{BinaryIndicator, BinaryIndicatorKind, BinaryInspectionLimits};
use std::collections::BTreeSet;

pub(crate) fn indicators(bytes: &[u8], limits: &BinaryInspectionLimits) -> Vec<BinaryIndicator> {
    let mut values = BTreeSet::new();
    let scan = &bytes[..bytes.len().min(limits.max_string_scan_bytes)];
    collect_ascii(scan, limits, &mut values);
    collect_utf16le(scan, 0, limits, &mut values);
    collect_utf16le(scan, 1, limits, &mut values);
    values
        .into_iter()
        .filter_map(|value| classify(&value))
        .take(limits.max_indicators)
        .collect()
}

fn collect_ascii(bytes: &[u8], limits: &BinaryInspectionLimits, values: &mut BTreeSet<String>) {
    let mut start = None;
    for (index, byte) in bytes.iter().copied().chain(std::iter::once(0)).enumerate() {
        if byte.is_ascii_graphic() || byte == b' ' || byte == b'\t' {
            start.get_or_insert(index);
            continue;
        }
        if let Some(offset) = start.take() {
            let length = index.saturating_sub(offset);
            if length >= limits.min_string_length {
                if values.len() >= limits.max_strings {
                    return;
                }
                let end = offset + length.min(limits.max_string_length);
                values.insert(String::from_utf8_lossy(&bytes[offset..end]).into_owned());
            }
        }
    }
}

fn collect_utf16le(
    bytes: &[u8],
    alignment: usize,
    limits: &BinaryInspectionLimits,
    values: &mut BTreeSet<String>,
) {
    let mut current = Vec::new();
    for pair in bytes.get(alignment..).unwrap_or_default().chunks_exact(2) {
        let unit = u16::from_le_bytes([pair[0], pair[1]]);
        let printable = matches!(unit, 0x09 | 0x20..=0x7e);
        if printable {
            if current.len() < limits.max_string_length {
                current.push(unit);
            }
        } else {
            if current.len() >= limits.min_string_length {
                if values.len() >= limits.max_strings {
                    return;
                }
                values.insert(String::from_utf16_lossy(&current));
            }
            current.clear();
        }
    }
    if current.len() >= limits.min_string_length && values.len() < limits.max_strings {
        values.insert(String::from_utf16_lossy(&current));
    }
}

fn classify(value: &str) -> Option<BinaryIndicator> {
    if let Some(url) = extract_url(value) {
        return Some(BinaryIndicator {
            kind: BinaryIndicatorKind::Url,
            value: url,
        });
    }
    if value.starts_with(r"\\") || value.starts_with('/') || looks_like_windows_path(value) {
        return Some(BinaryIndicator {
            kind: BinaryIndicatorKind::Path,
            value: value.trim().to_owned(),
        });
    }
    if looks_like_ip(value.trim()) {
        return Some(BinaryIndicator {
            kind: BinaryIndicatorKind::IpAddress,
            value: value.trim().to_owned(),
        });
    }
    if looks_like_domain(value.trim()) {
        return Some(BinaryIndicator {
            kind: BinaryIndicatorKind::Domain,
            value: value.trim().to_owned(),
        });
    }
    None
}

fn extract_url(value: &str) -> Option<String> {
    let lower = value.to_ascii_lowercase();
    let offset = lower.find("https://").or_else(|| lower.find("http://"))?;
    let value = &value[offset..];
    let end = value
        .find(|ch: char| ch.is_whitespace() || matches!(ch, '"' | '\'' | '<' | '>' | '`'))
        .unwrap_or(value.len());
    Some(
        value[..end]
            .trim_end_matches([')', ']', '}', ',', ';'])
            .to_owned(),
    )
}

fn looks_like_windows_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/')
}

fn looks_like_ip(value: &str) -> bool {
    value.parse::<std::net::IpAddr>().is_ok()
}

fn looks_like_domain(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    let excluded_suffix = [
        ".dll",
        ".exe",
        ".sys",
        ".dylib",
        ".framework",
        ".bundle",
        ".so",
        ".o",
    ]
    .iter()
    .any(|suffix| lower.ends_with(suffix));
    let top_level = value.rsplit_once('.').map(|(_, suffix)| suffix);
    !excluded_suffix
        && !value.contains(char::is_whitespace)
        && !value.contains(['/', '\\', ':'])
        && value.contains('.')
        && value.len() <= 253
        && top_level.is_some_and(|suffix| {
            (2..=24).contains(&suffix.len())
                && suffix.bytes().all(|byte| byte.is_ascii_alphabetic())
        })
        && value.split('.').all(|label| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}
