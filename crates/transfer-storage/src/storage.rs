use std::{
    fs::{self, File, OpenOptions},
    io::{Cursor, Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use filetime::{FileTime, set_file_times};
use transfer_core::{
    DurableState, Manifest, ManifestEntry, Storage as CoreStorage, validate_relative_path,
};
use transfer_protocol::{
    Digest, FileId, FileMetadata, HashAlgorithm, MAX_PATH_LEN, OverwritePolicy, TransferId,
};

use crate::{
    StorageError,
    hash::{hash_file, open_read_only, read_exact_or_eof},
};

const STORAGE_DIRECTORY: &str = ".udp-transfer";
const SESSIONS_DIRECTORY: &str = "sessions";
const PARTIAL_DIRECTORY: &str = "partial";
const STATE_SUFFIX: &str = ".state";
const STATE_MAGIC: &[u8; 8] = b"UDPTST01";
const STATE_VERSION: u8 = 2;
const MAX_STATE_SIZE: usize = 1024 * 1024;
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageConfig {
    pub overwrite_policy: OverwritePolicy,
    pub sync_data: bool,
    pub sync_all: bool,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            overwrite_policy: OverwritePolicy::Ask,
            sync_data: true,
            sync_all: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRegistration {
    pub transfer_id: TransferId,
    pub file_id: FileId,
    pub relative_path: String,
    pub size: u64,
    pub content_hash: Digest,
    pub metadata: FileMetadata,
}

impl FileRegistration {
    pub fn from_manifest_entry(transfer_id: TransferId, entry: &ManifestEntry) -> Self {
        Self {
            transfer_id,
            file_id: entry.file_id,
            relative_path: entry.relative_path.clone(),
            size: entry.size,
            content_hash: entry.content_hash,
            metadata: entry.metadata,
        }
    }
}

#[derive(Debug, Clone)]
struct StateRecord {
    registration: FileRegistration,
    durable_offset: u64,
    checkpoint_id: u64,
    state_hash: Digest,
    complete: bool,
    installed_relative_path: Option<String>,
}

impl StateRecord {
    fn new(registration: FileRegistration) -> Self {
        Self {
            state_hash: Digest::new(registration.content_hash.algorithm, [0; 32]),
            registration,
            durable_offset: 0,
            checkpoint_id: 0,
            complete: false,
            installed_relative_path: None,
        }
    }

    fn durable_state(&self) -> DurableState {
        DurableState {
            durable_offset: self.durable_offset,
            checkpoint_id: self.checkpoint_id,
            state_hash: self.state_hash,
        }
    }
}

pub struct FileStorage {
    root: PathBuf,
    config: StorageConfig,
}

impl FileStorage {
    pub fn new(root: impl AsRef<Path>) -> Result<Self, StorageError> {
        Self::open(root)
    }

    pub fn open(root: impl AsRef<Path>) -> Result<Self, StorageError> {
        Self::open_with_config(root, StorageConfig::default())
    }

    pub fn open_with_config(
        root: impl AsRef<Path>,
        config: StorageConfig,
    ) -> Result<Self, StorageError> {
        let root = root.as_ref();
        if !root.exists() {
            fs::create_dir_all(root)
                .map_err(|source| StorageError::io("create storage root", source))?;
        }
        let root = root
            .canonicalize()
            .map_err(|source| StorageError::io("canonicalize storage root", source))?;
        if !root.is_dir() {
            return Err(StorageError::InvalidRoot);
        }
        let mut storage = Self { root, config };
        storage.ensure_layout()?;
        storage.recover_states()?;
        Ok(storage)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn config(&self) -> StorageConfig {
        self.config
    }

    pub fn register_manifest(
        &mut self,
        transfer_id: TransferId,
        manifest: &Manifest,
    ) -> Result<(), StorageError> {
        for entry in manifest.entries() {
            self.register_entry(transfer_id, entry)?;
        }
        Ok(())
    }

    pub fn register_entry(
        &mut self,
        transfer_id: TransferId,
        entry: &ManifestEntry,
    ) -> Result<(), StorageError> {
        self.register_file(FileRegistration::from_manifest_entry(transfer_id, entry))
    }

    pub fn register_file(&mut self, registration: FileRegistration) -> Result<(), StorageError> {
        validate_storage_path(&registration.relative_path)?;
        self.ensure_transfer_directories(registration.transfer_id)?;
        let state_path = self.state_path(registration.transfer_id, registration.file_id);
        let partial_path = self.partial_path(registration.transfer_id, registration.file_id);
        let mut record = match read_state_if_exists(&state_path)? {
            Some(existing) if registration_matches(&existing.registration, &registration) => {
                existing
            }
            Some(_) => {
                remove_file_if_exists(&state_path)?;
                remove_file_if_exists(&partial_path)?;
                StateRecord::new(registration)
            }
            None => {
                remove_file_if_exists(&partial_path)?;
                StateRecord::new(registration)
            }
        };
        self.recover_record(&mut record)?;
        write_state(&state_path, &record, self.config.sync_all)?;
        Ok(())
    }

    pub fn durable_state(
        &self,
        transfer_id: TransferId,
        file_id: FileId,
    ) -> Result<DurableState, StorageError> {
        let record = self.load_record(transfer_id, file_id)?;
        let partial_path = self.partial_path(transfer_id, file_id);
        if !record.complete {
            let length = file_length_if_exists(&partial_path)?;
            if (length.is_none() && record.durable_offset != 0)
                || length.is_some_and(|length| length < record.durable_offset)
                || record.durable_offset > record.registration.size
            {
                return Err(StorageError::CheckpointCorrupt { file_id });
            }
        }
        Ok(record.durable_state())
    }

    pub fn resume_state(
        &self,
        transfer_id: TransferId,
        file_id: FileId,
    ) -> Result<DurableState, StorageError> {
        self.durable_state(transfer_id, file_id)
    }

    pub fn write_data(
        &mut self,
        transfer_id: TransferId,
        file_id: FileId,
        absolute_offset: u64,
        data: &[u8],
    ) -> Result<(), StorageError> {
        self.write_data_inner(transfer_id, file_id, absolute_offset, data)
    }

    pub fn checkpoint(
        &mut self,
        transfer_id: TransferId,
        file_id: FileId,
        state: DurableState,
    ) -> Result<(), StorageError> {
        self.checkpoint_inner(transfer_id, file_id, state)
    }

    pub fn complete_file(
        &mut self,
        transfer_id: TransferId,
        file_id: FileId,
        final_size: u64,
        content_hash: Digest,
    ) -> Result<(), StorageError> {
        self.complete_inner(transfer_id, file_id, final_size, content_hash)
    }

    pub fn partial_path_for(&self, transfer_id: TransferId, file_id: FileId) -> PathBuf {
        self.partial_path(transfer_id, file_id)
    }

    pub fn state_path_for(&self, transfer_id: TransferId, file_id: FileId) -> PathBuf {
        self.state_path(transfer_id, file_id)
    }

    pub fn destination_path(&self, relative_path: &str) -> Result<PathBuf, StorageError> {
        validate_storage_path(relative_path)?;
        Ok(self
            .root
            .join(relative_path.replace('/', std::path::MAIN_SEPARATOR_STR)))
    }

    pub fn reset_file(
        &mut self,
        transfer_id: TransferId,
        file_id: FileId,
    ) -> Result<(), StorageError> {
        let record = self.load_record(transfer_id, file_id)?;
        remove_file_if_exists(&self.partial_path(transfer_id, file_id))?;
        let fresh = StateRecord::new(record.registration);
        write_state(
            &self.state_path(transfer_id, file_id),
            &fresh,
            self.config.sync_all,
        )?;
        Ok(())
    }

    pub fn cleanup_transfer(&mut self, transfer_id: TransferId) -> Result<(), StorageError> {
        let session = self.session_directory(transfer_id);
        let partial = self.partial_directory(transfer_id);
        remove_directory_if_exists(&session)?;
        remove_directory_if_exists(&partial)?;
        Ok(())
    }

    fn ensure_layout(&self) -> Result<(), StorageError> {
        let storage = self.root.join(STORAGE_DIRECTORY);
        ensure_directory(&storage)?;
        ensure_directory(&storage.join(SESSIONS_DIRECTORY))?;
        ensure_directory(&storage.join(PARTIAL_DIRECTORY))?;
        Ok(())
    }

    fn ensure_transfer_directories(&self, transfer_id: TransferId) -> Result<(), StorageError> {
        ensure_directory(&self.session_directory(transfer_id))?;
        ensure_directory(&self.partial_directory(transfer_id))
    }

    fn session_directory(&self, transfer_id: TransferId) -> PathBuf {
        self.root
            .join(STORAGE_DIRECTORY)
            .join(SESSIONS_DIRECTORY)
            .join(transfer_id.to_string())
    }

    fn partial_directory(&self, transfer_id: TransferId) -> PathBuf {
        self.root
            .join(STORAGE_DIRECTORY)
            .join(PARTIAL_DIRECTORY)
            .join(transfer_id.to_string())
    }

    fn state_path(&self, transfer_id: TransferId, file_id: FileId) -> PathBuf {
        self.session_directory(transfer_id)
            .join(format!("{file_id}{STATE_SUFFIX}"))
    }

    fn partial_path(&self, transfer_id: TransferId, file_id: FileId) -> PathBuf {
        self.partial_directory(transfer_id)
            .join(format!("{file_id}.part"))
    }

    fn load_record(
        &self,
        transfer_id: TransferId,
        file_id: FileId,
    ) -> Result<StateRecord, StorageError> {
        read_state_if_exists(&self.state_path(transfer_id, file_id))?.ok_or(
            StorageError::UnknownFile {
                transfer_id,
                file_id,
            },
        )
    }

    fn recover_states(&mut self) -> Result<(), StorageError> {
        let sessions = self.root.join(STORAGE_DIRECTORY).join(SESSIONS_DIRECTORY);
        let transfers = fs::read_dir(&sessions)
            .map_err(|source| StorageError::io("scan storage sessions", source))?;
        for transfer in transfers {
            let transfer =
                transfer.map_err(|source| StorageError::io("scan storage session", source))?;
            let transfer_path = transfer.path();
            if !transfer
                .file_type()
                .map_err(|source| StorageError::io("inspect storage session", source))?
                .is_dir()
            {
                continue;
            }
            let files = fs::read_dir(&transfer_path)
                .map_err(|source| StorageError::io("scan checkpoint files", source))?;
            for file in files {
                let file =
                    file.map_err(|source| StorageError::io("scan checkpoint file", source))?;
                if file
                    .path()
                    .extension()
                    .and_then(|extension| extension.to_str())
                    != Some("state")
                {
                    continue;
                }
                let state_path = file.path();
                let mut record = match read_state(&state_path) {
                    Ok(record) => record,
                    Err(_) => {
                        remove_file_if_exists(&state_path)?;
                        continue;
                    }
                };
                self.recover_record(&mut record)?;
                write_state(&state_path, &record, self.config.sync_all)?;
            }
        }
        Ok(())
    }

    fn recover_record(&self, record: &mut StateRecord) -> Result<(), StorageError> {
        validate_storage_path(&record.registration.relative_path)?;
        let partial_path =
            self.partial_path(record.registration.transfer_id, record.registration.file_id);
        if record.complete {
            remove_file_if_exists(&partial_path)?;
            let installed_path = record
                .installed_relative_path
                .as_deref()
                .unwrap_or(&record.registration.relative_path);
            if !destination_matches(
                &self.destination_path(installed_path)?,
                &record.registration,
            )? {
                record.durable_offset = 0;
                record.checkpoint_id = 0;
                record.state_hash =
                    Digest::new(record.registration.content_hash.algorithm, [0; 32]);
                record.complete = false;
                record.installed_relative_path = None;
            }
            return Ok(());
        }
        let Some(length) = file_length_if_exists(&partial_path)? else {
            if record.durable_offset != 0 || record.checkpoint_id != 0 {
                record.durable_offset = 0;
                record.checkpoint_id = 0;
                record.state_hash =
                    Digest::new(record.registration.content_hash.algorithm, [0; 32]);
            }
            return Ok(());
        };
        if record.durable_offset > record.registration.size {
            record.durable_offset = 0;
            record.checkpoint_id = 0;
            record.state_hash = Digest::new(record.registration.content_hash.algorithm, [0; 32]);
            truncate_file(&partial_path, 0)?;
        } else if length > record.registration.size || length != record.durable_offset {
            truncate_file(&partial_path, record.durable_offset)?;
        }
        let length = file_length_if_exists(&partial_path)?.unwrap_or(0);
        if length < record.durable_offset {
            record.durable_offset = 0;
            record.checkpoint_id = 0;
            record.state_hash = Digest::new(record.registration.content_hash.algorithm, [0; 32]);
            truncate_file(&partial_path, 0)?;
        }
        Ok(())
    }

    fn write_data_inner(
        &mut self,
        transfer_id: TransferId,
        file_id: FileId,
        absolute_offset: u64,
        data: &[u8],
    ) -> Result<(), StorageError> {
        let record = self.load_record(transfer_id, file_id)?;
        if record.complete {
            return Err(StorageError::InvalidRegistration {
                file_id,
                reason: "file is already complete",
            });
        }
        let end =
            absolute_offset
                .checked_add(data.len() as u64)
                .ok_or(StorageError::InvalidOffset {
                    file_id,
                    offset: absolute_offset,
                    maximum: record.registration.size,
                })?;
        if end > record.registration.size {
            return Err(StorageError::InvalidOffset {
                file_id,
                offset: end,
                maximum: record.registration.size,
            });
        }
        let partial_path = self.partial_path(transfer_id, file_id);
        let mut file = open_partial(&partial_path)?;
        let length = file
            .metadata()
            .map_err(|source| StorageError::io("inspect partial file", source))?
            .len();
        if length < record.durable_offset || length > record.registration.size {
            return Err(StorageError::CheckpointCorrupt { file_id });
        }
        if absolute_offset > length {
            return Err(StorageError::InvalidOffset {
                file_id,
                offset: absolute_offset,
                maximum: length,
            });
        }
        let overlap_end = end.min(length);
        if overlap_end > absolute_offset {
            let overlap_len = usize::try_from(overlap_end - absolute_offset).map_err(|_| {
                StorageError::InvalidOffset {
                    file_id,
                    offset: overlap_end,
                    maximum: length,
                }
            })?;
            file.seek(SeekFrom::Start(absolute_offset))
                .map_err(|source| StorageError::io("seek partial file", source))?;
            let mut existing = vec![0_u8; overlap_len];
            file.read_exact(&mut existing)
                .map_err(|source| StorageError::io("read partial file", source))?;
            if existing != data[..overlap_len] {
                return Err(StorageError::DataConflict {
                    file_id,
                    offset: absolute_offset,
                });
            }
        }
        if end > length {
            let already_present =
                usize::try_from(length.saturating_sub(absolute_offset)).unwrap_or(data.len());
            file.seek(SeekFrom::Start(length))
                .map_err(|source| StorageError::io("seek partial file for append", source))?;
            file.write_all(&data[already_present..])
                .map_err(|source| StorageError::io("write partial file", source))?;
        }
        Ok(())
    }

    fn checkpoint_inner(
        &mut self,
        transfer_id: TransferId,
        file_id: FileId,
        state: DurableState,
    ) -> Result<(), StorageError> {
        let mut record = self.load_record(transfer_id, file_id)?;
        if record.complete {
            return Ok(());
        }
        let partial_path = self.partial_path(transfer_id, file_id);
        let length = file_length_if_exists(&partial_path)?.unwrap_or(0);
        if state.durable_offset > record.registration.size || state.durable_offset > length {
            return Err(StorageError::InvalidOffset {
                file_id,
                offset: state.durable_offset,
                maximum: length.min(record.registration.size),
            });
        }
        if state.checkpoint_id < record.checkpoint_id
            || state.durable_offset < record.durable_offset
            || (state.checkpoint_id == record.checkpoint_id
                && state.durable_offset == record.durable_offset
                && state.state_hash != record.state_hash)
        {
            return Err(StorageError::CheckpointRegression { file_id });
        }
        if state.checkpoint_id == record.checkpoint_id
            && state.durable_offset == record.durable_offset
        {
            return Ok(());
        }
        let partial_exists = file_length_if_exists(&partial_path)?.is_some();
        if !partial_exists && record.registration.size == 0 {
            let partial = open_partial(&partial_path)?;
            if self.config.sync_data {
                partial
                    .sync_data()
                    .map_err(|source| StorageError::io("sync partial file", source))?;
            }
        } else if partial_exists {
            let partial = open_partial_existing(&partial_path)?;
            if self.config.sync_data {
                partial
                    .sync_data()
                    .map_err(|source| StorageError::io("sync partial file", source))?;
            }
        } else if state.durable_offset == 0 {
            // 尚未写入任何分块时记录 checkpoint，无需 sync 尚未创建的 partial 文件
        } else {
            let partial = open_partial_existing(&partial_path)?;
            if self.config.sync_data {
                partial
                    .sync_data()
                    .map_err(|source| StorageError::io("sync partial file", source))?;
            }
        }
        record.durable_offset = state.durable_offset;
        record.checkpoint_id = state.checkpoint_id;
        record.state_hash = state.state_hash;
        write_state(
            &self.state_path(transfer_id, file_id),
            &record,
            self.config.sync_all,
        )
    }

    fn complete_inner(
        &mut self,
        transfer_id: TransferId,
        file_id: FileId,
        final_size: u64,
        content_hash: Digest,
    ) -> Result<(), StorageError> {
        let mut record = self.load_record(transfer_id, file_id)?;
        if final_size != record.registration.size {
            return Err(StorageError::SizeMismatch {
                file_id,
                expected: record.registration.size,
                actual: final_size,
            });
        }
        if content_hash != record.registration.content_hash {
            return Err(StorageError::IntegrityMismatch {
                file_id,
                expected: record.registration.content_hash,
                actual: content_hash,
            });
        }
        if record.complete {
            let installed_path = record
                .installed_relative_path
                .as_deref()
                .unwrap_or(&record.registration.relative_path);
            if destination_matches(
                &self.destination_path(installed_path)?,
                &record.registration,
            )? {
                return Ok(());
            }
            return Err(StorageError::CheckpointCorrupt { file_id });
        }
        if record.durable_offset != record.registration.size {
            return Err(StorageError::InvalidOffset {
                file_id,
                offset: record.durable_offset,
                maximum: record.registration.size,
            });
        }
        let partial_path = self.partial_path(transfer_id, file_id);
        let destination = self.destination_path(&record.registration.relative_path)?;
        let mut source_exists = file_length_if_exists(&partial_path)?.is_some();
        if !source_exists && record.registration.size == 0 {
            let partial = open_partial(&partial_path)?;
            partial
                .sync_all()
                .map_err(|source| StorageError::io("sync empty partial file", source))?;
            source_exists = true;
        }
        if source_exists {
            let actual_size = file_length_if_exists(&partial_path)?.unwrap_or(0);
            if actual_size != record.registration.size {
                return Err(StorageError::SizeMismatch {
                    file_id,
                    expected: record.registration.size,
                    actual: actual_size,
                });
            }
            let actual_hash = hash_file(&partial_path, record.registration.content_hash.algorithm)?;
            if actual_hash != record.registration.content_hash {
                return Err(StorageError::IntegrityMismatch {
                    file_id,
                    expected: record.registration.content_hash,
                    actual: actual_hash,
                });
            }
            let partial = open_partial_existing(&partial_path)?;
            partial
                .sync_all()
                .map_err(|source| StorageError::io("sync completed partial file", source))?;
            ensure_safe_parent(&self.root, &destination)?;
            let destination = self.choose_destination(&destination, file_id)?;
            move_into_place(
                &partial_path,
                &destination,
                self.config.overwrite_policy,
                file_id,
            )?;
            if self.config.sync_all
                && let Some(parent) = destination.parent()
            {
                sync_directory(parent)?;
            }
            apply_metadata(&destination, record.registration.metadata)?;
            if self.config.sync_all {
                sync_file(&destination)?;
            }
            record.installed_relative_path = Some(
                destination
                    .strip_prefix(&self.root)
                    .map_err(|_| StorageError::PathEscapesRoot {
                        path: destination.display().to_string(),
                    })?
                    .to_string_lossy()
                    .replace(std::path::MAIN_SEPARATOR, "/"),
            );
        } else if !destination_matches(&destination, &record.registration)? {
            return Err(StorageError::CheckpointCorrupt { file_id });
        } else {
            record.installed_relative_path = Some(
                record
                    .registration
                    .relative_path
                    .replace(std::path::MAIN_SEPARATOR, "/"),
            );
        }
        record.durable_offset = record.registration.size;
        record.complete = true;
        write_state(
            &self.state_path(transfer_id, file_id),
            &record,
            self.config.sync_all,
        )
    }

    fn choose_destination(
        &self,
        destination: &Path,
        file_id: FileId,
    ) -> Result<PathBuf, StorageError> {
        match self.config.overwrite_policy {
            OverwritePolicy::RenameWithSuffix => {
                if !path_exists(destination)? {
                    return Ok(destination.to_path_buf());
                }
                for index in 1_u32..=u32::MAX {
                    let candidate = suffixed_path(destination, index);
                    if !path_exists(&candidate)? {
                        return Ok(candidate);
                    }
                }
                Err(StorageError::AlreadyExists { file_id })
            }
            _ => Ok(destination.to_path_buf()),
        }
    }
}

impl CoreStorage for FileStorage {
    fn durable_state(
        &self,
        transfer_id: TransferId,
        file_id: FileId,
    ) -> Result<DurableState, transfer_core::CoreError> {
        FileStorage::durable_state(self, transfer_id, file_id).map_err(storage_core_error)
    }

    fn write_data(
        &mut self,
        transfer_id: TransferId,
        file_id: FileId,
        absolute_offset: u64,
        data: &[u8],
    ) -> Result<(), transfer_core::CoreError> {
        self.write_data_inner(transfer_id, file_id, absolute_offset, data)
            .map_err(storage_core_error)
    }

    fn checkpoint(
        &mut self,
        transfer_id: TransferId,
        file_id: FileId,
        state: DurableState,
    ) -> Result<(), transfer_core::CoreError> {
        self.checkpoint_inner(transfer_id, file_id, state)
            .map_err(storage_core_error)
    }

    fn complete_file(
        &mut self,
        transfer_id: TransferId,
        file_id: FileId,
        final_size: u64,
        content_hash: Digest,
    ) -> Result<(), transfer_core::CoreError> {
        self.complete_inner(transfer_id, file_id, final_size, content_hash)
            .map_err(storage_core_error)
    }
}

fn storage_core_error(error: StorageError) -> transfer_core::CoreError {
    transfer_core::CoreError::Storage(error.to_string())
}

fn registration_matches(left: &FileRegistration, right: &FileRegistration) -> bool {
    left.transfer_id == right.transfer_id
        && left.file_id == right.file_id
        && left.relative_path == right.relative_path
        && left.size == right.size
        && left.content_hash == right.content_hash
}

fn validate_storage_path(path: &str) -> Result<(), StorageError> {
    if path.len() > MAX_PATH_LEN {
        return Err(StorageError::InvalidPath {
            path: path.to_owned(),
        });
    }
    validate_relative_path(path).map_err(|_| StorageError::InvalidPath {
        path: path.to_owned(),
    })?;
    let path = Path::new(path);
    if path
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(StorageError::PathEscapesRoot {
            path: path.display().to_string(),
        });
    }
    Ok(())
}

fn ensure_directory(path: &Path) -> Result<(), StorageError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(StorageError::SymbolicLinkNotAllowed {
                    path: path.to_path_buf(),
                });
            }
            if !metadata.is_dir() {
                return Err(StorageError::InvalidRoot);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path)
                .map_err(|source| StorageError::io("create storage directory", source))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                    .map_err(|source| StorageError::io("restrict storage directory", source))?;
            }
        }
        Err(source) => return Err(StorageError::io("inspect storage directory", source)),
    }
    Ok(())
}

fn ensure_safe_parent(root: &Path, path: &Path) -> Result<(), StorageError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| StorageError::PathEscapesRoot {
            path: path.display().to_string(),
        })?;
    let mut current = root.to_path_buf();
    let components = relative.components().collect::<Vec<_>>();
    for component in components.iter().take(components.len().saturating_sub(1)) {
        let Component::Normal(name) = component else {
            return Err(StorageError::PathEscapesRoot {
                path: path.display().to_string(),
            });
        };
        current.push(name);
        ensure_directory(&current)?;
    }
    Ok(())
}

fn open_partial(path: &Path) -> Result<File, StorageError> {
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    configure_no_follow(&mut options);
    options
        .open(path)
        .map_err(|source| StorageError::io("open partial file", source))
}

fn open_partial_existing(path: &Path) -> Result<File, StorageError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    configure_no_follow(&mut options);
    options
        .open(path)
        .map_err(|source| StorageError::io("open existing partial file", source))
}

fn configure_no_follow(options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
}

fn move_into_place(
    partial: &Path,
    destination: &Path,
    policy: OverwritePolicy,
    file_id: FileId,
) -> Result<(), StorageError> {
    match policy {
        OverwritePolicy::Ask => {
            if path_exists(destination)? {
                return Err(StorageError::OverwriteNeedsConfirmation { file_id });
            }
            fs::rename(partial, destination)
                .map_err(|source| StorageError::io("atomically rename completed file", source))
        }
        OverwritePolicy::NoReplace => {
            if path_exists(destination)? {
                return Err(StorageError::AlreadyExists { file_id });
            }
            fs::hard_link(partial, destination)
                .map_err(|source| StorageError::io("atomically install file", source))?;
            fs::remove_file(partial)
                .map_err(|source| StorageError::io("remove installed partial file", source))
        }
        OverwritePolicy::ReplaceAfterConfirm | OverwritePolicy::RenameWithSuffix => {
            fs::rename(partial, destination)
                .map_err(|source| StorageError::io("atomically rename completed file", source))
        }
    }
}

fn apply_metadata(path: &Path, metadata: FileMetadata) -> Result<(), StorageError> {
    if let Some(mode) = metadata.mode {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = fs::Permissions::from_mode(mode & 0o7777);
            fs::set_permissions(path, permissions)
                .map_err(|source| StorageError::io("apply file permissions", source))?;
        }
    }
    if let Some(seconds) = metadata.modified_time_unix_seconds
        && seconds >= 0
    {
        let time = FileTime::from_unix_time(seconds, 0);
        set_file_times(path, time, time)
            .map_err(|source| StorageError::io("apply file timestamps", source))?;
    }
    Ok(())
}

fn destination_matches(path: &Path, registration: &FileRegistration) -> Result<bool, StorageError> {
    let Some(metadata) = fs::symlink_metadata(path).ok() else {
        return Ok(false);
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() != registration.size
    {
        return Ok(false);
    }
    Ok(hash_file(path, registration.content_hash.algorithm)? == registration.content_hash)
}

fn file_length_if_exists(path: &Path) -> Result<Option<u64>, StorageError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(StorageError::SymbolicLinkNotAllowed {
                path: path.to_path_buf(),
            })
        }
        Ok(metadata) if metadata.is_file() => Ok(Some(metadata.len())),
        Ok(_) => Err(StorageError::UnsupportedFileType {
            path: path.to_path_buf(),
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(StorageError::io("inspect storage file", source)),
    }
}

fn truncate_file(path: &Path, length: u64) -> Result<(), StorageError> {
    let file = open_partial_existing(path)?;
    file.set_len(length)
        .map_err(|source| StorageError::io("truncate partial file", source))?;
    Ok(())
}

fn path_exists(path: &Path) -> Result<bool, StorageError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(StorageError::io("inspect destination path", source)),
    }
}

fn suffixed_path(path: &Path, index: u32) -> PathBuf {
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return path.with_file_name(format!("file.{index}"));
    };
    path.with_file_name(format!("{file_name}.{index}"))
}

fn remove_file_if_exists(path: &Path) -> Result<(), StorageError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            Err(StorageError::UnsupportedFileType {
                path: path.to_path_buf(),
            })
        }
        Ok(_) => {
            fs::remove_file(path).map_err(|source| StorageError::io("remove storage file", source))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(StorageError::io("inspect storage file", source)),
    }
}

fn remove_directory_if_exists(path: &Path) -> Result<(), StorageError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(StorageError::SymbolicLinkNotAllowed {
                path: path.to_path_buf(),
            })
        }
        Ok(metadata) if metadata.is_dir() => fs::remove_dir_all(path)
            .map_err(|source| StorageError::io("remove transfer storage directory", source)),
        Ok(_) => Err(StorageError::UnsupportedFileType {
            path: path.to_path_buf(),
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(StorageError::io(
            "inspect transfer storage directory",
            source,
        )),
    }
}

fn write_state(path: &Path, record: &StateRecord, sync_all: bool) -> Result<(), StorageError> {
    let parent = path.parent().ok_or(StorageError::MalformedState)?;
    ensure_directory(parent)?;
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temp = parent.join(format!(".state.tmp.{}.{}", std::process::id(), counter));
    let bytes = encode_state(record);
    let result = (|| {
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temp)
            .map_err(|source| StorageError::io("create checkpoint state", source))?;
        file.write_all(&bytes)
            .map_err(|source| StorageError::io("write checkpoint state", source))?;
        file.sync_all()
            .map_err(|source| StorageError::io("sync checkpoint state", source))?;
        fs::rename(&temp, path)
            .map_err(|source| StorageError::io("atomically replace checkpoint state", source))?;
        if sync_all {
            sync_directory(parent)?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn encode_state(record: &StateRecord) -> Vec<u8> {
    let registration = &record.registration;
    let path = registration.relative_path.as_bytes();
    let mut bytes = Vec::with_capacity(192 + path.len());
    bytes.extend_from_slice(STATE_MAGIC);
    bytes.push(STATE_VERSION);
    bytes.extend_from_slice(registration.transfer_id.as_bytes());
    bytes.extend_from_slice(registration.file_id.as_bytes());
    bytes.extend_from_slice(&(path.len() as u32).to_be_bytes());
    bytes.extend_from_slice(path);
    bytes.extend_from_slice(&registration.size.to_be_bytes());
    encode_digest(&mut bytes, registration.content_hash);
    encode_metadata(&mut bytes, registration.metadata);
    bytes.extend_from_slice(&record.durable_offset.to_be_bytes());
    bytes.extend_from_slice(&record.checkpoint_id.to_be_bytes());
    encode_digest(&mut bytes, record.state_hash);
    bytes.push(u8::from(record.complete));
    match &record.installed_relative_path {
        Some(path) => {
            bytes.push(1);
            bytes.extend_from_slice(&(path.len() as u32).to_be_bytes());
            bytes.extend_from_slice(path.as_bytes());
        }
        None => bytes.push(0),
    }
    bytes
}

fn encode_digest(bytes: &mut Vec<u8>, digest: Digest) {
    bytes.push(digest.algorithm as u8);
    bytes.extend_from_slice(&digest.bytes);
}

fn encode_metadata(bytes: &mut Vec<u8>, metadata: FileMetadata) {
    match metadata.modified_time_unix_seconds {
        Some(value) => {
            bytes.push(1);
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        None => bytes.push(0),
    }
    match metadata.mode {
        Some(value) => {
            bytes.push(1);
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        None => bytes.push(0),
    }
}

fn read_state_if_exists(path: &Path) -> Result<Option<StateRecord>, StorageError> {
    match fs::read(path) {
        Ok(bytes) => {
            if bytes.len() > MAX_STATE_SIZE {
                return Err(StorageError::MalformedState);
            }
            read_state_bytes(&bytes).map(Some)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(StorageError::io("read checkpoint state", source)),
    }
}

fn read_state(path: &Path) -> Result<StateRecord, StorageError> {
    let bytes =
        fs::read(path).map_err(|source| StorageError::io("read checkpoint state", source))?;
    if bytes.len() > MAX_STATE_SIZE {
        return Err(StorageError::MalformedState);
    }
    read_state_bytes(&bytes)
}

fn read_state_bytes(bytes: &[u8]) -> Result<StateRecord, StorageError> {
    let mut reader = Cursor::new(bytes);
    let mut magic = [0_u8; STATE_MAGIC.len()];
    read_exact_or_eof(&mut reader, &mut magic)?;
    if &magic != STATE_MAGIC || read_u8(&mut reader)? != STATE_VERSION {
        return Err(StorageError::MalformedState);
    }
    let transfer_id = read_transfer_id(&mut reader)?;
    let file_id = read_file_id(&mut reader)?;
    let relative_path = read_string(&mut reader)?;
    validate_storage_path(&relative_path)?;
    let size = read_u64(&mut reader)?;
    let content_hash = read_digest(&mut reader)?;
    let metadata = read_metadata(&mut reader)?;
    let durable_offset = read_u64(&mut reader)?;
    let checkpoint_id = read_u64(&mut reader)?;
    let state_hash = read_digest(&mut reader)?;
    let complete = match read_u8(&mut reader)? {
        0 => false,
        1 => true,
        _ => return Err(StorageError::MalformedState),
    };
    let installed_relative_path = match read_u8(&mut reader)? {
        0 => None,
        1 => Some(read_string(&mut reader)?),
        _ => return Err(StorageError::MalformedState),
    };
    if let Some(path) = &installed_relative_path {
        validate_storage_path(path)?;
    }
    if usize::try_from(reader.position()).ok() != Some(bytes.len()) {
        return Err(StorageError::MalformedState);
    }
    Ok(StateRecord {
        registration: FileRegistration {
            transfer_id,
            file_id,
            relative_path,
            size,
            content_hash,
            metadata,
        },
        durable_offset,
        checkpoint_id,
        state_hash,
        complete,
        installed_relative_path,
    })
}

fn read_transfer_id(reader: &mut Cursor<&[u8]>) -> Result<TransferId, StorageError> {
    let mut bytes = [0_u8; 16];
    read_exact_or_eof(reader, &mut bytes)?;
    Ok(TransferId::from_bytes(bytes))
}

fn read_file_id(reader: &mut Cursor<&[u8]>) -> Result<FileId, StorageError> {
    let mut bytes = [0_u8; 16];
    read_exact_or_eof(reader, &mut bytes)?;
    Ok(FileId::from_bytes(bytes))
}

fn read_string(reader: &mut Cursor<&[u8]>) -> Result<String, StorageError> {
    let length = read_u32(reader)? as usize;
    if length > MAX_PATH_LEN {
        return Err(StorageError::MalformedState);
    }
    let mut bytes = vec![0_u8; length];
    read_exact_or_eof(reader, &mut bytes)?;
    String::from_utf8(bytes).map_err(|_| StorageError::MalformedState)
}

fn read_digest(reader: &mut Cursor<&[u8]>) -> Result<Digest, StorageError> {
    let algorithm = match read_u8(reader)? {
        1 => HashAlgorithm::Blake3,
        2 => HashAlgorithm::Sha256,
        _ => return Err(StorageError::MalformedState),
    };
    let mut bytes = [0_u8; 32];
    read_exact_or_eof(reader, &mut bytes)?;
    Ok(Digest::new(algorithm, bytes))
}

fn read_metadata(reader: &mut Cursor<&[u8]>) -> Result<FileMetadata, StorageError> {
    let modified_time_unix_seconds = match read_u8(reader)? {
        0 => None,
        1 => Some(read_i64(reader)?),
        _ => return Err(StorageError::MalformedState),
    };
    let mode = match read_u8(reader)? {
        0 => None,
        1 => Some(read_u32(reader)?),
        _ => return Err(StorageError::MalformedState),
    };
    Ok(FileMetadata {
        modified_time_unix_seconds,
        mode,
    })
}

fn read_u8(reader: &mut Cursor<&[u8]>) -> Result<u8, StorageError> {
    let mut bytes = [0_u8; 1];
    read_exact_or_eof(reader, &mut bytes)?;
    Ok(bytes[0])
}

fn read_u32(reader: &mut Cursor<&[u8]>) -> Result<u32, StorageError> {
    let mut bytes = [0_u8; 4];
    read_exact_or_eof(reader, &mut bytes)?;
    Ok(u32::from_be_bytes(bytes))
}

fn read_i64(reader: &mut Cursor<&[u8]>) -> Result<i64, StorageError> {
    let mut bytes = [0_u8; 8];
    read_exact_or_eof(reader, &mut bytes)?;
    Ok(i64::from_be_bytes(bytes))
}

fn read_u64(reader: &mut Cursor<&[u8]>) -> Result<u64, StorageError> {
    let mut bytes = [0_u8; 8];
    read_exact_or_eof(reader, &mut bytes)?;
    Ok(u64::from_be_bytes(bytes))
}

fn sync_directory(path: &Path) -> Result<(), StorageError> {
    #[cfg(unix)]
    {
        File::open(path)
            .map_err(|source| StorageError::io("open storage directory for sync", source))?
            .sync_all()
            .map_err(|source| StorageError::io("sync storage directory", source))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn sync_file(path: &Path) -> Result<(), StorageError> {
    open_read_only(path)?
        .sync_all()
        .map_err(|source| StorageError::io("sync completed file", source))
}
