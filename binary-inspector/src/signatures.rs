use crate::{SignatureValidation, SignatureValidationStatus};

#[cfg(not(target_arch = "wasm32"))]
#[allow(clippy::too_many_lines)]
pub(crate) fn validate_authenticode(bytes: &[u8], certificate_count: usize) -> SignatureValidation {
    use authenticode::{authenticode_digest, AttributeCertificateIterator};
    use cryptographic_message_syntax::SignedData;
    use sha1::Sha1;
    use sha2::{Digest, Sha256};

    if certificate_count == 0 {
        return not_present();
    }
    let view = match PeView::parse(bytes) {
        Ok(view) => view,
        Err(issue) => return invalid(certificate_count, issue),
    };
    let certificates = match AttributeCertificateIterator::new(&view) {
        Ok(Some(certificates)) => certificates,
        Ok(None) => return not_present(),
        Err(error) => return invalid(certificate_count, error.to_string()),
    };
    let mut issues = Vec::new();
    let mut content_valid = true;
    let mut crypto_valid = true;
    let mut signer_count = 0_usize;
    let mut parsed_certificates = 0_usize;
    let mut algorithm = None;
    for certificate in certificates.take(16) {
        let certificate = match certificate {
            Ok(certificate) => certificate,
            Err(error) => {
                content_valid = false;
                crypto_valid = false;
                issues.push(error.to_string());
                continue;
            }
        };
        let signature = match certificate.get_authenticode_signature() {
            Ok(signature) => signature,
            Err(error) => {
                content_valid = false;
                crypto_valid = false;
                issues.push(error.to_string());
                continue;
            }
        };
        let oid = signature.digest_algorithm().oid.to_string();
        algorithm.get_or_insert_with(|| digest_name(&oid).to_owned());
        let actual = match oid.as_str() {
            "1.3.14.3.2.26" => {
                let mut digest = Sha1::new();
                if let Err(error) = authenticode_digest(&view, &mut digest) {
                    issues.push(error.to_string());
                    content_valid = false;
                    Vec::new()
                } else {
                    digest.finalize().to_vec()
                }
            }
            "2.16.840.1.101.3.4.2.1" => {
                let mut digest = Sha256::new();
                if let Err(error) = authenticode_digest(&view, &mut digest) {
                    issues.push(error.to_string());
                    content_valid = false;
                    Vec::new()
                } else {
                    digest.finalize().to_vec()
                }
            }
            _ => {
                content_valid = false;
                issues.push(format!("unsupported Authenticode digest algorithm {oid}"));
                Vec::new()
            }
        };
        if actual.as_slice() != signature.digest() {
            content_valid = false;
            issues.push("Authenticode content digest does not match the PE image".into());
        }
        match SignedData::parse_ber(certificate.data) {
            Ok(signed_data) => {
                parsed_certificates += signed_data.certificates().count();
                for signer in signed_data.signers() {
                    signer_count += 1;
                    if let Err(error) = signer.verify_message_digest_with_signed_data(&signed_data)
                    {
                        crypto_valid = false;
                        issues.push(format!(
                            "Authenticode CMS digest verification failed: {error}"
                        ));
                    }
                    if let Err(error) = signer.verify_signature_with_signed_data(&signed_data) {
                        crypto_valid = false;
                        issues.push(format!(
                            "Authenticode CMS signature verification failed: {error}"
                        ));
                    }
                }
            }
            Err(error) => {
                crypto_valid = false;
                issues.push(format!("Authenticode CMS parse failed: {error}"));
            }
        }
    }
    if signer_count == 0 {
        crypto_valid = false;
        issues.push("Authenticode signature contains no CMS signers".into());
    }
    let valid = content_valid && crypto_valid;
    SignatureValidation {
        status: if valid {
            SignatureValidationStatus::CryptographicallyValid
        } else {
            SignatureValidationStatus::Invalid
        },
        algorithm,
        content_digest_valid: Some(content_valid),
        cryptographic_signature_valid: Some(crypto_valid),
        certificate_chain_valid: None,
        signer_count,
        certificate_count: parsed_certificates.max(certificate_count),
        issues: issues.into_iter().take(16).collect(),
    }
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn validate_authenticode(
    _bytes: &[u8],
    certificate_count: usize,
) -> SignatureValidation {
    if certificate_count == 0 {
        not_present()
    } else {
        unsupported(
            certificate_count,
            "Authenticode validation is unavailable in the browser build",
        )
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn validate_macho(bytes: &[u8], signature_present: bool) -> SignatureValidation {
    if !signature_present {
        return not_present();
    }
    let slices = match macho_slices(bytes) {
        Ok(slices) => slices,
        Err(issue) => return invalid(0, issue),
    };
    let mut issues = Vec::new();
    let mut content_valid = true;
    let mut crypto_valid = true;
    let mut saw_cms = false;
    let mut signer_count = 0_usize;
    let mut certificate_count = 0_usize;
    let mut algorithm = None;
    for slice in slices {
        match validate_macho_slice(slice) {
            Ok(validation) => {
                content_valid &= validation.content_valid;
                crypto_valid &= validation.crypto_valid;
                saw_cms |= validation.saw_cms;
                signer_count += validation.signer_count;
                certificate_count += validation.certificate_count;
                if algorithm.is_none() {
                    algorithm = validation.algorithm;
                }
                issues.extend(validation.issues);
            }
            Err(issue) => {
                content_valid = false;
                crypto_valid = false;
                issues.push(issue);
            }
        }
    }
    let valid = content_valid && (!saw_cms || crypto_valid);
    SignatureValidation {
        status: if valid && saw_cms {
            SignatureValidationStatus::CryptographicallyValid
        } else if valid {
            SignatureValidationStatus::IntegrityValid
        } else {
            SignatureValidationStatus::Invalid
        },
        algorithm,
        content_digest_valid: Some(content_valid),
        cryptographic_signature_valid: saw_cms.then_some(crypto_valid),
        certificate_chain_valid: None,
        signer_count,
        certificate_count,
        issues: issues.into_iter().take(16).collect(),
    }
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn validate_macho(_bytes: &[u8], signature_present: bool) -> SignatureValidation {
    if signature_present {
        unsupported(
            0,
            "Mach-O cryptographic validation is unavailable in the browser build",
        )
    } else {
        not_present()
    }
}

fn not_present() -> SignatureValidation {
    SignatureValidation {
        status: SignatureValidationStatus::NotPresent,
        algorithm: None,
        content_digest_valid: None,
        cryptographic_signature_valid: None,
        certificate_chain_valid: None,
        signer_count: 0,
        certificate_count: 0,
        issues: Vec::new(),
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn invalid(certificate_count: usize, issue: String) -> SignatureValidation {
    SignatureValidation {
        status: SignatureValidationStatus::Invalid,
        algorithm: None,
        content_digest_valid: Some(false),
        cryptographic_signature_valid: None,
        certificate_chain_valid: None,
        signer_count: 0,
        certificate_count,
        issues: vec![issue],
    }
}

#[cfg(target_arch = "wasm32")]
fn unsupported(certificate_count: usize, issue: &str) -> SignatureValidation {
    SignatureValidation {
        status: SignatureValidationStatus::Unsupported,
        algorithm: None,
        content_digest_valid: None,
        cryptographic_signature_valid: None,
        certificate_chain_valid: None,
        signer_count: 0,
        certificate_count,
        issues: vec![issue.into()],
    }
}

#[cfg(not(target_arch = "wasm32"))]
struct PeView<'a> {
    bytes: &'a [u8],
    sections: Vec<std::ops::Range<usize>>,
    certificate: Option<std::ops::Range<usize>>,
    offsets: authenticode::PeOffsets,
}

#[cfg(not(target_arch = "wasm32"))]
impl<'a> PeView<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self, String> {
        use authenticode::PeOffsets;

        if !bytes.starts_with(b"MZ") {
            return Err("Authenticode input is not a PE image".into());
        }
        let pe_offset = read_le_u32(bytes, 0x3c).ok_or("PE header offset is truncated")? as usize;
        if bytes.get(pe_offset..pe_offset + 4) != Some(b"PE\0\0") {
            return Err("PE signature is invalid".into());
        }
        let coff = pe_offset + 4;
        let section_count =
            read_le_u16(bytes, coff + 2).ok_or("PE section count is truncated")? as usize;
        let optional_size =
            read_le_u16(bytes, coff + 16).ok_or("PE optional header size is truncated")? as usize;
        let optional = coff + 20;
        let magic = read_le_u16(bytes, optional).ok_or("PE optional header is truncated")?;
        let data_directory_offset = match magic {
            0x10b => optional + 96,
            0x20b => optional + 112,
            _ => return Err(format!("unsupported PE optional header magic {magic:#x}")),
        };
        let checksum = optional + 64;
        let security_directory = data_directory_offset + 4 * 8;
        let size_of_headers =
            read_le_u32(bytes, optional + 60).ok_or("PE SizeOfHeaders is truncated")? as usize;
        if size_of_headers > bytes.len() {
            return Err("PE headers extend beyond the input".into());
        }
        let certificate_offset =
            read_le_u32(bytes, security_directory).unwrap_or_default() as usize;
        let certificate_size =
            read_le_u32(bytes, security_directory + 4).unwrap_or_default() as usize;
        let certificate = if certificate_offset == 0 || certificate_size == 0 {
            None
        } else {
            let end = certificate_offset
                .checked_add(certificate_size)
                .ok_or("PE certificate table range overflowed")?;
            bytes
                .get(certificate_offset..end)
                .ok_or("PE certificate table is out of bounds")?;
            Some(certificate_offset..end)
        };
        let section_table = optional + optional_size;
        let mut sections = Vec::new();
        for index in 0..section_count.min(1_024) {
            let offset = section_table + index * 40;
            let start =
                read_le_u32(bytes, offset + 20).ok_or("PE section table is truncated")? as usize;
            let size =
                read_le_u32(bytes, offset + 16).ok_or("PE section table is truncated")? as usize;
            let end = start
                .checked_add(size)
                .ok_or("PE section range overflowed")?;
            bytes
                .get(start..end)
                .ok_or("PE section range is out of bounds")?;
            sections.push(start..end);
        }
        Ok(Self {
            bytes,
            sections,
            certificate,
            offsets: PeOffsets {
                check_sum: checksum,
                after_check_sum: checksum + 4,
                security_data_dir: security_directory,
                after_security_data_dir: security_directory + 8,
                after_header: size_of_headers,
            },
        })
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl authenticode::PeTrait for PeView<'_> {
    fn data(&self) -> &[u8] {
        self.bytes
    }

    fn num_sections(&self) -> usize {
        self.sections.len()
    }

    fn section_data_range(
        &self,
        index: usize,
    ) -> Result<std::ops::Range<usize>, authenticode::PeOffsetError> {
        self.sections
            .get(index.saturating_sub(1))
            .cloned()
            .ok_or(authenticode::PeOffsetError)
    }

    fn certificate_table_range(
        &self,
    ) -> Result<Option<std::ops::Range<usize>>, authenticode::PeOffsetError> {
        Ok(self.certificate.clone())
    }

    fn offsets(&self) -> Result<authenticode::PeOffsets, authenticode::PeOffsetError> {
        Ok(self.offsets.clone())
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn digest_name(oid: &str) -> &str {
    match oid {
        "1.3.14.3.2.26" => "sha1",
        "2.16.840.1.101.3.4.2.1" => "sha256",
        _ => oid,
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn read_le_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

#[cfg(not(target_arch = "wasm32"))]
fn read_le_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

#[cfg(not(target_arch = "wasm32"))]
struct MachSliceValidation {
    content_valid: bool,
    crypto_valid: bool,
    saw_cms: bool,
    signer_count: usize,
    certificate_count: usize,
    algorithm: Option<String>,
    issues: Vec<String>,
}

#[cfg(not(target_arch = "wasm32"))]
fn validate_macho_slice(bytes: &[u8]) -> Result<MachSliceValidation, String> {
    use cryptographic_message_syntax::SignedData;

    let signature = macho_signature_blob(bytes)?;
    let blobs = superblob_entries(signature)?;
    let code_directories = blobs
        .iter()
        .filter_map(|blob| (read_be_u32(blob, 0) == Some(0xfade_0c02)).then_some(*blob))
        .collect::<Vec<_>>();
    if code_directories.is_empty() {
        return Err("Mach-O signature contains no code directory".into());
    }
    let mut issues = Vec::new();
    let mut content_valid = true;
    let mut algorithm = None;
    for directory in &code_directories {
        match verify_code_directory(bytes, directory) {
            Ok(name) => {
                algorithm.get_or_insert(name);
            }
            Err(issue) => {
                content_valid = false;
                issues.push(issue);
            }
        }
    }
    let cms = blobs
        .iter()
        .find_map(|blob| (read_be_u32(blob, 0) == Some(0xfade_0b01)).then_some(&blob[8..]));
    let Some(cms) = cms else {
        issues.push("Mach-O signature is ad hoc and has no CMS signer".into());
        return Ok(MachSliceValidation {
            content_valid,
            crypto_valid: false,
            saw_cms: false,
            signer_count: 0,
            certificate_count: 0,
            algorithm,
            issues,
        });
    };
    let signed_data =
        SignedData::parse_ber(cms).map_err(|error| format!("Mach-O CMS parse failed: {error}"))?;
    let mut signer_count = 0_usize;
    let mut crypto_valid = true;
    for signer in signed_data.signers() {
        signer_count += 1;
        if let Err(error) = signer.verify_message_digest_with_content(code_directories[0]) {
            content_valid = false;
            issues.push(format!("Mach-O CMS content digest mismatch: {error}"));
        }
        if let Err(error) = signer.verify_signature_with_signed_data(&signed_data) {
            crypto_valid = false;
            issues.push(format!("Mach-O CMS signature verification failed: {error}"));
        }
    }
    if signer_count == 0 {
        crypto_valid = false;
        issues.push("Mach-O CMS contains no signers".into());
    }
    Ok(MachSliceValidation {
        content_valid,
        crypto_valid,
        saw_cms: true,
        signer_count,
        certificate_count: signed_data.certificates().count(),
        algorithm,
        issues,
    })
}

#[cfg(not(target_arch = "wasm32"))]
fn macho_slices(bytes: &[u8]) -> Result<Vec<&[u8]>, String> {
    let magic = bytes.get(..4).ok_or("Mach-O input is too short")?;
    let (little_endian, is_64) = match magic {
        [0xca, 0xfe, 0xba, 0xbe] => (false, false),
        [0xbe, 0xba, 0xfe, 0xca] => (true, false),
        [0xca, 0xfe, 0xba, 0xbf] => (false, true),
        [0xbf, 0xba, 0xfe, 0xca] => (true, true),
        _ => return Ok(vec![bytes]),
    };
    let count = read_u32(bytes, 4, little_endian)
        .ok_or("fat Mach-O header is truncated")?
        .min(8) as usize;
    let entry_size = if is_64 { 32 } else { 20 };
    let mut slices = Vec::new();
    for index in 0..count {
        let start = 8 + index * entry_size;
        let (offset, size) = if is_64 {
            (
                read_u64(bytes, start + 8, little_endian),
                read_u64(bytes, start + 16, little_endian),
            )
        } else {
            (
                read_u32(bytes, start + 8, little_endian).map(u64::from),
                read_u32(bytes, start + 12, little_endian).map(u64::from),
            )
        };
        let offset = usize::try_from(offset.ok_or("fat Mach-O offset is truncated")?)
            .map_err(|_| "fat Mach-O offset does not fit in memory")?;
        let size = usize::try_from(size.ok_or("fat Mach-O size is truncated")?)
            .map_err(|_| "fat Mach-O size does not fit in memory")?;
        let end = offset
            .checked_add(size)
            .ok_or("fat Mach-O slice range overflowed")?;
        slices.push(
            bytes
                .get(offset..end)
                .ok_or("fat Mach-O slice is out of bounds")?,
        );
    }
    Ok(slices)
}

#[cfg(not(target_arch = "wasm32"))]
fn macho_signature_blob(bytes: &[u8]) -> Result<&[u8], String> {
    let magic = bytes.get(..4).ok_or("Mach-O input is too short")?;
    let (little_endian, header_size) = match magic {
        [0xce, 0xfa, 0xed, 0xfe] => (true, 28),
        [0xcf, 0xfa, 0xed, 0xfe] => (true, 32),
        [0xfe, 0xed, 0xfa, 0xce] => (false, 28),
        [0xfe, 0xed, 0xfa, 0xcf] => (false, 32),
        _ => return Err("unsupported Mach-O magic".into()),
    };
    let command_count =
        read_u32(bytes, 16, little_endian).ok_or("Mach-O header is truncated")? as usize;
    let mut offset = header_size;
    for _ in 0..command_count.min(4_096) {
        let command =
            read_u32(bytes, offset, little_endian).ok_or("Mach-O load command is truncated")?;
        let command_size = read_u32(bytes, offset + 4, little_endian)
            .ok_or("Mach-O load command size is truncated")? as usize;
        if command_size < 8 {
            return Err("Mach-O load command size is invalid".into());
        }
        if command == 0x1d {
            let data_offset = read_u32(bytes, offset + 8, little_endian)
                .ok_or("Mach-O signature offset is truncated")?
                as usize;
            let data_size = read_u32(bytes, offset + 12, little_endian)
                .ok_or("Mach-O signature size is truncated")? as usize;
            let end = data_offset
                .checked_add(data_size)
                .ok_or("Mach-O signature range overflowed")?;
            return bytes
                .get(data_offset..end)
                .ok_or_else(|| "Mach-O signature is out of bounds".into());
        }
        offset = offset
            .checked_add(command_size)
            .ok_or("Mach-O load command range overflowed")?;
    }
    Err("Mach-O signature load command was not found".into())
}

#[cfg(not(target_arch = "wasm32"))]
fn superblob_entries(blob: &[u8]) -> Result<Vec<&[u8]>, String> {
    if read_be_u32(blob, 0) != Some(0xfade_0cc0) {
        return Err("Mach-O signature superblob magic is invalid".into());
    }
    let length = read_be_u32(blob, 4).ok_or("Mach-O superblob length is truncated")? as usize;
    let count = read_be_u32(blob, 8).ok_or("Mach-O superblob count is truncated")? as usize;
    let blob = blob
        .get(..length)
        .ok_or("Mach-O signature superblob is truncated")?;
    let mut entries = Vec::new();
    for index in 0..count.min(64) {
        let entry = 12 + index * 8;
        let offset =
            read_be_u32(blob, entry + 4).ok_or("Mach-O superblob index is truncated")? as usize;
        let child_length =
            read_be_u32(blob, offset + 4).ok_or("Mach-O signature blob is truncated")? as usize;
        let end = offset
            .checked_add(child_length)
            .ok_or("Mach-O signature blob range overflowed")?;
        entries.push(
            blob.get(offset..end)
                .ok_or("Mach-O signature child blob is out of bounds")?,
        );
    }
    Ok(entries)
}

#[cfg(not(target_arch = "wasm32"))]
fn verify_code_directory(bytes: &[u8], directory: &[u8]) -> Result<String, String> {
    use sha1::Sha1;
    use sha2::{Digest, Sha256};

    let hash_offset = read_be_u32(directory, 16)
        .ok_or("Mach-O code directory hash offset is truncated")? as usize;
    let code_slots =
        read_be_u32(directory, 28).ok_or("Mach-O code slot count is truncated")? as usize;
    let code_limit = read_be_u32(directory, 32).ok_or("Mach-O code limit is truncated")? as usize;
    let hash_size = usize::from(*directory.get(36).ok_or("Mach-O hash size is truncated")?);
    let hash_type = *directory.get(37).ok_or("Mach-O hash type is truncated")?;
    let page_exponent = *directory.get(39).ok_or("Mach-O page size is truncated")?;
    let page_size = if page_exponent == 0 {
        code_limit.max(1)
    } else {
        1_usize
            .checked_shl(u32::from(page_exponent))
            .ok_or("Mach-O page size exponent is invalid")?
    };
    let expected_slots = code_limit.div_ceil(page_size);
    if expected_slots != code_slots {
        return Err(format!(
            "Mach-O code directory declares {code_slots} slots but {expected_slots} are required"
        ));
    }
    let code = bytes
        .get(..code_limit)
        .ok_or("Mach-O code limit is out of bounds")?;
    let algorithm = match hash_type {
        1 => "sha1",
        2 | 3 => "sha256",
        _ => return Err(format!("unsupported Mach-O code hash type {hash_type}")),
    };
    for (index, chunk) in code.chunks(page_size).enumerate() {
        let actual = if hash_type == 1 {
            Sha1::digest(chunk).to_vec()
        } else {
            Sha256::digest(chunk).to_vec()
        };
        let start = hash_offset
            .checked_add(index.saturating_mul(hash_size))
            .ok_or("Mach-O code hash offset overflowed")?;
        let expected = directory
            .get(start..start + hash_size)
            .ok_or("Mach-O code hash table is truncated")?;
        if actual.get(..hash_size) != Some(expected) {
            return Err(format!("Mach-O code hash mismatch at slot {index}"));
        }
    }
    Ok(algorithm.into())
}

#[cfg(not(target_arch = "wasm32"))]
fn read_be_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let bytes = bytes.get(offset..offset + 4)?;
    Some(u32::from_be_bytes(bytes.try_into().ok()?))
}

#[cfg(not(target_arch = "wasm32"))]
fn read_u32(bytes: &[u8], offset: usize, little_endian: bool) -> Option<u32> {
    let bytes: [u8; 4] = bytes.get(offset..offset + 4)?.try_into().ok()?;
    Some(if little_endian {
        u32::from_le_bytes(bytes)
    } else {
        u32::from_be_bytes(bytes)
    })
}

#[cfg(not(target_arch = "wasm32"))]
fn read_u64(bytes: &[u8], offset: usize, little_endian: bool) -> Option<u64> {
    let bytes: [u8; 8] = bytes.get(offset..offset + 8)?.try_into().ok()?;
    Some(if little_endian {
        u64::from_le_bytes(bytes)
    } else {
        u64::from_be_bytes(bytes)
    })
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn verifies_macho_code_directory_hashes() {
        let code = b"abcd";
        let mut directory = vec![0_u8; 44 + 32];
        let directory_len = u32::try_from(directory.len()).unwrap();
        put_be_u32(&mut directory, 0, 0xfade_0c02);
        put_be_u32(&mut directory, 4, directory_len);
        put_be_u32(&mut directory, 8, 0x0002_0200);
        put_be_u32(&mut directory, 16, 44);
        put_be_u32(&mut directory, 28, 1);
        put_be_u32(&mut directory, 32, u32::try_from(code.len()).unwrap());
        directory[36] = 32;
        directory[37] = 2;
        directory[39] = 0;
        directory[44..].copy_from_slice(&Sha256::digest(code));

        assert_eq!(verify_code_directory(code, &directory).unwrap(), "sha256");
        directory[44] ^= 0xff;
        assert!(verify_code_directory(code, &directory).is_err());
    }

    fn put_be_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }
}
