use crate::BinarySection;
use std::collections::BTreeSet;

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]
pub(crate) fn entropy_milli(bytes: &[u8]) -> Option<u16> {
    if bytes.is_empty() {
        return None;
    }
    let mut counts = [0_usize; 256];
    for byte in bytes {
        counts[usize::from(*byte)] += 1;
    }
    let length = bytes.len() as f64;
    let entropy = counts
        .into_iter()
        .filter(|count| *count != 0)
        .map(|count| {
            let probability = count as f64 / length;
            -probability * probability.log2()
        })
        .sum::<f64>();
    Some((entropy * 1_000.0).round().clamp(0.0, 8_000.0) as u16)
}

pub(crate) fn packer_markers(bytes: &[u8], sections: &[BinarySection]) -> Vec<String> {
    const BYTE_MARKERS: [(&str, &[u8]); 5] = [
        ("upx", b"UPX!"),
        ("mpress", b"MPRESS"),
        ("aspack", b"ASPack"),
        ("themida", b"Themida"),
        ("vmprotect", b"VMProtect"),
    ];
    const NAME_MARKERS: [&str; 8] = [
        "upx", "mpress", "aspack", "packed", "petite", "themida", ".vmp", "vmp0",
    ];
    let mut markers = BTreeSet::new();
    for (name, marker) in BYTE_MARKERS {
        if bytes.windows(marker.len()).any(|window| window == marker) {
            markers.insert(name.to_owned());
        }
    }
    for section in sections {
        let lower = section.name.to_ascii_lowercase();
        for marker in NAME_MARKERS {
            if lower.contains(marker) {
                markers.insert(marker.trim_start_matches('.').to_owned());
            }
        }
    }
    markers.into_iter().collect()
}

pub(crate) fn high_entropy_sections(sections: &[BinarySection]) -> Vec<String> {
    sections
        .iter()
        .filter(|section| section.file_size >= 256)
        .filter(|section| {
            section
                .entropy_milli_bits
                .is_some_and(|entropy| entropy >= 7_200)
        })
        .map(|section| section.name.clone())
        .collect()
}

pub(crate) fn overlay_bytes(total: usize, ends: impl Iterator<Item = usize>) -> usize {
    total.saturating_sub(ends.max().unwrap_or(0).min(total))
}

pub(crate) fn entitlement_keys(bytes: &[u8], limit: usize) -> Vec<String> {
    let text = String::from_utf8_lossy(bytes);
    let mut keys = BTreeSet::new();
    let mut remaining = text.as_ref();
    while keys.len() < limit {
        let Some(start) = remaining.find("<key>") else {
            break;
        };
        remaining = &remaining[start + 5..];
        let Some(end) = remaining.find("</key>") else {
            break;
        };
        let key = remaining[..end].trim();
        if !key.is_empty()
            && (key.starts_with("com.apple.")
                || key.contains("application-identifier")
                || key.contains("team-identifier")
                || key.contains("keychain-access-groups"))
        {
            keys.insert(key.to_owned());
        }
        remaining = &remaining[end + 6..];
    }
    keys.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_distinguishes_uniform_and_varied_data() {
        assert_eq!(entropy_milli(&[0; 512]), Some(0));
        let varied = (0_u8..=255).cycle().take(1_024).collect::<Vec<_>>();
        assert!(entropy_milli(&varied).is_some_and(|value| value >= 7_900));
    }

    #[test]
    fn extracts_bounded_entitlement_keys() {
        let keys = entitlement_keys(
            b"<plist><dict><key>com.apple.security.cs.allow-jit</key><true/><key>ignored</key></dict></plist>",
            8,
        );
        assert_eq!(keys, ["com.apple.security.cs.allow-jit"]);
    }
}
