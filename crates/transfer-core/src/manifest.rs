use std::collections::BTreeMap;

use transfer_protocol::{Digest, FileId, FileMetadata, MAX_MANIFEST_FILES, MAX_PATH_LEN};

use crate::CoreError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestEntry {
    pub file_id: FileId,
    pub relative_path: String,
    pub size: u64,
    pub content_hash: Digest,
    pub metadata: FileMetadata,
}

impl ManifestEntry {
    pub fn new(
        file_id: FileId,
        relative_path: String,
        size: u64,
        content_hash: Digest,
        metadata: FileMetadata,
    ) -> Result<Self, CoreError> {
        validate_relative_path(&relative_path)?;
        Ok(Self {
            file_id,
            relative_path,
            size,
            content_hash,
            metadata,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    digest: Digest,
    entries: Vec<ManifestEntry>,
    total_size: u64,
}

impl Manifest {
    pub fn new(digest: Digest, entries: Vec<ManifestEntry>) -> Result<Self, CoreError> {
        if entries.len() > MAX_MANIFEST_FILES {
            return Err(CoreError::ManifestCountMismatch {
                expected: MAX_MANIFEST_FILES as u64,
                actual: entries.len(),
            });
        }

        let mut ids = BTreeMap::new();
        let mut paths = BTreeMap::new();
        let mut total_size = 0_u64;
        for entry in &entries {
            validate_relative_path(&entry.relative_path)?;
            if ids.insert(entry.file_id, ()).is_some() {
                return Err(CoreError::DuplicateFile {
                    file_id: entry.file_id,
                });
            }
            if paths.insert(entry.relative_path.as_str(), ()).is_some() {
                return Err(CoreError::InvalidPath);
            }
            total_size = total_size
                .checked_add(entry.size)
                .ok_or(CoreError::InvalidFileSize {
                    file_id: entry.file_id,
                })?;
        }

        Ok(Self {
            digest,
            entries,
            total_size,
        })
    }

    pub fn digest(&self) -> Digest {
        self.digest
    }

    pub fn entries(&self) -> &[ManifestEntry] {
        &self.entries
    }

    pub fn file_count(&self) -> u64 {
        self.entries.len() as u64
    }

    pub fn total_size(&self) -> u64 {
        self.total_size
    }

    pub fn entry(&self, file_id: FileId) -> Option<&ManifestEntry> {
        self.entries.iter().find(|entry| entry.file_id == file_id)
    }

    pub fn position(&self, file_id: FileId) -> Option<usize> {
        self.entries
            .iter()
            .position(|entry| entry.file_id == file_id)
    }
}

pub fn validate_relative_path(path: &str) -> Result<(), CoreError> {
    if path.is_empty() || path.len() > MAX_PATH_LEN || path.contains('\0') {
        return Err(CoreError::InvalidPath);
    }
    if path.starts_with('/') || path.contains('\\') {
        return Err(CoreError::InvalidPath);
    }
    for component in path.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(CoreError::InvalidPath);
        }
    }
    Ok(())
}
