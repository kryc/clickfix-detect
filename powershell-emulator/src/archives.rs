use std::io::{Cursor, Read, Write};
use thiserror::Error;
use zip::write::FileOptions;

#[derive(Debug, Error)]
pub(crate) enum ArchiveError {
    #[error(transparent)]
    Zip(#[from] zip::result::ZipError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub(crate) fn extract_zip(bytes: &[u8]) -> Result<Vec<(String, Vec<u8>)>, ArchiveError> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))?;
    let mut files = Vec::new();
    for index in 0..archive.len() {
        let mut file = archive.by_index(index)?;
        if file.is_dir() {
            continue;
        }
        let Some(path) = file.enclosed_name().map(std::path::Path::to_path_buf) else {
            continue;
        };
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;
        files.push((path.to_string_lossy().replace('/', "\\"), contents));
    }
    Ok(files)
}

pub(crate) fn create_zip(name: &str, bytes: &[u8]) -> Result<Vec<u8>, ArchiveError> {
    let mut output = Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut output);
        writer.start_file(name, FileOptions::default())?;
        writer.write_all(bytes)?;
        writer.finish()?;
    }
    Ok(output.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zip_round_trip_is_deterministic() {
        let archive = create_zip("safe.txt", b"safe").unwrap();
        let files = extract_zip(&archive).unwrap();

        assert_eq!(files, vec![("safe.txt".into(), b"safe".to_vec())]);
    }
}
