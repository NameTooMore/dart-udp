use std::{
    collections::BTreeMap,
    fs::{self, Metadata},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use sha2::Digest as _;
use transfer_core::{Manifest, ManifestEntry, validate_relative_path};
use transfer_protocol::{
    Digest, FileId, FileMetadata, HashAlgorithm, MAX_MANIFEST_FILES, MAX_PATH_LEN,
};

use crate::{StorageError, hash::open_read_only};

const DEFAULT_MAX_FILE_SIZE: u64 = 1024 * 1024 * 1024 * 1024;
const DEFAULT_MAX_TOTAL_SIZE: u64 = 4 * 1024 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymlinkPolicy {
    Reject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManifestBuildConfig {
    pub hash_algorithm: HashAlgorithm,
    pub max_files: usize,
    pub max_file_size: u64,
    pub max_total_size: u64,
    pub max_path_len: usize,
    pub symlink_policy: SymlinkPolicy,
}

impl Default for ManifestBuildConfig {
    fn default() -> Self {
        Self {
            hash_algorithm: HashAlgorithm::Blake3,
            max_files: MAX_MANIFEST_FILES,
            max_file_size: DEFAULT_MAX_FILE_SIZE,
            max_total_size: DEFAULT_MAX_TOTAL_SIZE,
            max_path_len: MAX_PATH_LEN,
            symlink_policy: SymlinkPolicy::Reject,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileSignature {
    size: u64,
    modified_time: Option<SystemTime>,
    identity: Option<(u64, u64)>,
}

impl FileSignature {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            size: metadata.len(),
            modified_time: modified_time(metadata),
            identity: file_identity(metadata),
        }
    }
}

pub struct ManifestBuilder {
    config: ManifestBuildConfig,
}

impl ManifestBuilder {
    pub fn new(config: ManifestBuildConfig) -> Self {
        Self { config }
    }

    pub fn with_config(config: ManifestBuildConfig) -> Self {
        Self::new(config)
    }

    pub fn build_manifest<I, P>(&self, sources: I) -> Result<Manifest, StorageError>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        self.build(sources)
    }

    pub fn config(&self) -> ManifestBuildConfig {
        self.config
    }

    pub fn build<I, P>(&self, sources: I) -> Result<Manifest, StorageError>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        let mut candidates = Vec::new();
        for source in sources {
            let source = source.as_ref();
            let metadata = fs::symlink_metadata(source)
                .map_err(|source| StorageError::io("inspect manifest source", source))?;
            if metadata.file_type().is_symlink() {
                return self.reject_symlink(source);
            }

            let absolute = source
                .canonicalize()
                .map_err(|source| StorageError::io("canonicalize manifest source", source))?;
            if metadata.is_file() {
                let name = absolute
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or_else(|| StorageError::InvalidPath {
                        path: absolute.display().to_string(),
                    })?;
                let name = name.to_owned();
                candidates.push((absolute, name));
            } else if metadata.is_dir() {
                let name = absolute
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or_else(|| StorageError::InvalidPath {
                        path: absolute.display().to_string(),
                    })?;
                self.collect_directory(&absolute, name, &mut candidates)?;
            } else {
                return Err(StorageError::UnsupportedFileType { path: absolute });
            }
        }
        self.build_from_candidates(candidates)
    }

    pub fn build_relative_to<I, P>(
        &self,
        root: impl AsRef<Path>,
        sources: I,
    ) -> Result<Manifest, StorageError>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        let root = root
            .as_ref()
            .canonicalize()
            .map_err(|source| StorageError::io("canonicalize manifest root", source))?;
        let mut candidates = Vec::new();
        for source in sources {
            let source = source.as_ref();
            let metadata = fs::symlink_metadata(source)
                .map_err(|source| StorageError::io("inspect manifest source", source))?;
            if metadata.file_type().is_symlink() {
                return self.reject_symlink(source);
            }
            let absolute = source
                .canonicalize()
                .map_err(|source| StorageError::io("canonicalize manifest source", source))?;
            let relative = absolute
                .strip_prefix(&root)
                .map_err(|_| StorageError::PathEscapesRoot {
                    path: absolute.display().to_string(),
                })?
                .to_str()
                .ok_or_else(|| StorageError::InvalidPath {
                    path: absolute.display().to_string(),
                })?
                .replace(std::path::MAIN_SEPARATOR, "/");
            if metadata.is_file() {
                candidates.push((absolute, relative));
            } else if metadata.is_dir() {
                self.collect_directory(&absolute, &relative, &mut candidates)?;
            } else {
                return Err(StorageError::UnsupportedFileType { path: absolute });
            }
        }
        self.build_from_candidates(candidates)
    }

    fn reject_symlink<T>(&self, path: &Path) -> Result<T, StorageError> {
        match self.config.symlink_policy {
            SymlinkPolicy::Reject => Err(StorageError::SymbolicLinkNotAllowed {
                path: path.to_path_buf(),
            }),
        }
    }

    fn collect_directory(
        &self,
        root: &Path,
        relative_root: &str,
        candidates: &mut Vec<(PathBuf, String)>,
    ) -> Result<(), StorageError> {
        let mut pending = vec![(root.to_path_buf(), relative_root.to_owned())];
        while let Some((directory, relative_directory)) = pending.pop() {
            let mut children = fs::read_dir(&directory)
                .map_err(|source| StorageError::io("read manifest directory", source))?
                .map(|entry| {
                    let entry = entry.map_err(|source| {
                        StorageError::io("read manifest directory entry", source)
                    })?;
                    let name = entry.file_name().into_string().map_err(|name| {
                        StorageError::InvalidPath {
                            path: name.to_string_lossy().into_owned(),
                        }
                    })?;
                    Ok((entry.path(), name))
                })
                .collect::<Result<Vec<_>, StorageError>>()?;
            children.sort_by(|left, right| left.1.cmp(&right.1));
            for (path, name) in children.into_iter().rev() {
                let relative = format!("{relative_directory}/{name}");
                let relative = if relative_directory.is_empty() {
                    name.clone()
                } else {
                    relative
                };
                let metadata = fs::symlink_metadata(&path)
                    .map_err(|source| StorageError::io("inspect manifest entry", source))?;
                if metadata.file_type().is_symlink() {
                    return self.reject_symlink(&path);
                }
                if metadata.is_dir() {
                    pending.push((path, relative));
                } else if metadata.is_file() {
                    candidates.push((path, relative));
                    if candidates.len() > self.config.max_files {
                        return Err(StorageError::TooManyFiles {
                            maximum: self.config.max_files,
                        });
                    }
                } else {
                    return Err(StorageError::UnsupportedFileType { path });
                }
            }
        }
        Ok(())
    }

    fn build_from_candidates(
        &self,
        mut candidates: Vec<(PathBuf, String)>,
    ) -> Result<Manifest, StorageError> {
        candidates.sort_by(|left, right| left.1.cmp(&right.1));
        let mut seen = BTreeMap::new();
        let mut entries = Vec::with_capacity(candidates.len());
        let mut total_size = 0_u64;
        for (path, relative_path) in candidates {
            if seen.insert(relative_path.clone(), ()).is_some() {
                return Err(StorageError::ManifestPathCollision {
                    path: relative_path,
                });
            }
            if entries.len() >= self.config.max_files {
                return Err(StorageError::TooManyFiles {
                    maximum: self.config.max_files,
                });
            }
            self.validate_path(&relative_path)?;
            let metadata = fs::symlink_metadata(&path)
                .map_err(|source| StorageError::io("inspect source file", source))?;
            if metadata.file_type().is_symlink() {
                return self.reject_symlink(&path);
            }
            if !metadata.is_file() {
                return Err(StorageError::UnsupportedFileType { path });
            }
            let signature_before = FileSignature::from_metadata(&metadata);
            if signature_before.size > self.config.max_file_size {
                return Err(StorageError::FileTooLarge {
                    file_id: None,
                    maximum: self.config.max_file_size,
                    actual: signature_before.size,
                });
            }
            total_size = total_size.checked_add(signature_before.size).ok_or(
                StorageError::TotalSizeTooLarge {
                    maximum: self.config.max_total_size,
                    actual: u64::MAX,
                },
            )?;
            if total_size > self.config.max_total_size {
                return Err(StorageError::TotalSizeTooLarge {
                    maximum: self.config.max_total_size,
                    actual: total_size,
                });
            }

            let file_id = FileId::random().map_err(|_| StorageError::RandomnessUnavailable)?;
            let file = open_read_only(&path)?;
            let content_hash = crate::hash_reader(file, self.config.hash_algorithm)?;
            let signature_after = FileSignature::from_metadata(
                &fs::symlink_metadata(&path)
                    .map_err(|source| StorageError::io("recheck source file", source))?,
            );
            if signature_before != signature_after {
                return Err(StorageError::SourceChanged { path });
            }
            let metadata = FileMetadata {
                modified_time_unix_seconds: modified_time_unix_seconds(&metadata),
                mode: file_mode(&metadata),
            };
            entries.push(
                ManifestEntry::new(
                    file_id,
                    relative_path,
                    signature_before.size,
                    content_hash,
                    metadata,
                )
                .map_err(|error| StorageError::Core(error.to_string()))?,
            );
        }

        let digest = manifest_digest(&entries, self.config.hash_algorithm);
        Manifest::new(digest, entries).map_err(|error| StorageError::Core(error.to_string()))
    }

    fn validate_path(&self, path: &str) -> Result<(), StorageError> {
        if path.len() > self.config.max_path_len {
            return Err(StorageError::InvalidPath {
                path: path.to_owned(),
            });
        }
        validate_relative_path(path).map_err(|_| StorageError::InvalidPath {
            path: path.to_owned(),
        })
    }
}

impl Default for ManifestBuilder {
    fn default() -> Self {
        Self::new(ManifestBuildConfig::default())
    }
}

enum ManifestHasher {
    Blake3(Box<blake3::Hasher>),
    Sha256(sha2::Sha256),
}

impl ManifestHasher {
    fn new(algorithm: HashAlgorithm) -> Self {
        match algorithm {
            HashAlgorithm::Blake3 => Self::Blake3(Box::new(blake3::Hasher::new())),
            HashAlgorithm::Sha256 => Self::Sha256(sha2::Sha256::new()),
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Blake3(hasher) => {
                hasher.update(bytes);
            }
            Self::Sha256(hasher) => {
                use sha2::Digest as _;
                hasher.update(bytes);
            }
        }
    }

    fn finalize(self, algorithm: HashAlgorithm) -> Digest {
        match self {
            Self::Blake3(hasher) => Digest::new(algorithm, *hasher.finalize().as_bytes()),
            Self::Sha256(hasher) => {
                use sha2::Digest as _;
                Digest::new(algorithm, hasher.finalize().into())
            }
        }
    }
}

fn manifest_digest(entries: &[ManifestEntry], algorithm: HashAlgorithm) -> Digest {
    let mut hasher = ManifestHasher::new(algorithm);
    hasher.update(b"udp-transfer-manifest-v1\0");
    for entry in entries {
        hasher.update(entry.file_id.as_bytes());
        update_bytes(&mut hasher, entry.relative_path.as_bytes());
        hasher.update(&entry.size.to_be_bytes());
        hasher.update(&[entry.content_hash.algorithm as u8]);
        hasher.update(&entry.content_hash.bytes);
        match entry.metadata.modified_time_unix_seconds {
            Some(value) => {
                hasher.update(&[1]);
                hasher.update(&value.to_be_bytes());
            }
            None => hasher.update(&[0]),
        }
        match entry.metadata.mode {
            Some(value) => {
                hasher.update(&[1]);
                hasher.update(&value.to_be_bytes());
            }
            None => hasher.update(&[0]),
        }
    }
    hasher.finalize(algorithm)
}

fn update_bytes(hasher: &mut ManifestHasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn modified_time(metadata: &Metadata) -> Option<SystemTime> {
    metadata.modified().ok()
}

fn modified_time_unix_seconds(metadata: &Metadata) -> Option<i64> {
    metadata
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_secs()
        .try_into()
        .ok()
}

#[cfg(unix)]
fn file_identity(metadata: &Metadata) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    Some((metadata.dev(), metadata.ino()))
}

#[cfg(not(unix))]
fn file_identity(_metadata: &Metadata) -> Option<(u64, u64)> {
    None
}

#[cfg(unix)]
fn file_mode(metadata: &Metadata) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    Some(metadata.permissions().mode())
}

#[cfg(not(unix))]
fn file_mode(_metadata: &Metadata) -> Option<u32> {
    None
}
