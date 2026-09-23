use std::{
    fs,
    io::{self, Cursor, Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use transfer_core::{Manifest, ManifestEntry};
use transfer_protocol::{
    Digest, FileId, FileMetadata, HashAlgorithm, MAX_MANIFEST_FILES, MAX_PATH_LEN, MAX_TICKET_LEN,
    PairingId, SessionTicket, TransferId, TransferRole,
};

use crate::ClientError;

const STORAGE_DIRECTORY: &str = ".udp-transfer";
const SESSIONS_DIRECTORY: &str = "sessions";
const PARTIAL_DIRECTORY: &str = "partial";
const RESUME_TICKET_SUFFIX: &str = ".resume";
const RESUME_TICKET_MAGIC: &[u8; 8] = b"UDPRSM01";
const RESUME_TICKET_VERSION: u8 = 1;
const MAX_RESUME_TICKET_FILE_SIZE: usize = 16 * 1024 * 1024;

/// 可跨进程保存的传输恢复凭据。
///
/// 凭据只允许恢复它绑定的 transfer、角色和 manifest，不能替代配对码或作为长期身份。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeTicket {
    pairing_id: PairingId,
    transfer_id: TransferId,
    role: TransferRole,
    manifest_digest: Digest,
    expires_at_millis: u64,
    ticket: SessionTicket,
    manifest: Option<Manifest>,
}

impl ResumeTicket {
    pub(crate) fn from_wire(
        pairing_id: PairingId,
        transfer_id: TransferId,
        role: TransferRole,
        manifest_digest: Digest,
        expires_at_millis: u64,
        ticket: SessionTicket,
    ) -> Result<Self, ClientError> {
        validate_ticket_bytes(&ticket)?;
        Ok(Self {
            pairing_id,
            transfer_id,
            role,
            manifest_digest,
            expires_at_millis,
            ticket,
            manifest: None,
        })
    }

    pub(crate) fn with_manifest(mut self, manifest: Manifest) -> Self {
        self.manifest = Some(manifest);
        self
    }

    pub fn pairing_id(&self) -> PairingId {
        self.pairing_id
    }

    pub fn transfer_id(&self) -> TransferId {
        self.transfer_id
    }

    pub fn role(&self) -> TransferRole {
        self.role
    }

    pub fn manifest_digest(&self) -> Digest {
        self.manifest_digest
    }

    pub fn expires_at_millis(&self) -> u64 {
        self.expires_at_millis
    }

    pub fn is_expired(&self) -> bool {
        unix_millis_now() >= self.expires_at_millis
    }

    pub fn manifest(&self) -> Option<&Manifest> {
        self.manifest.as_ref()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(256);
        bytes.extend_from_slice(RESUME_TICKET_MAGIC);
        bytes.push(RESUME_TICKET_VERSION);
        bytes.extend_from_slice(self.pairing_id.as_bytes());
        bytes.extend_from_slice(self.transfer_id.as_bytes());
        bytes.push(self.role as u8);
        encode_digest(&mut bytes, self.manifest_digest);
        bytes.extend_from_slice(&self.expires_at_millis.to_be_bytes());
        encode_blob(&mut bytes, self.ticket.as_bytes());
        match &self.manifest {
            Some(manifest) => {
                bytes.push(1);
                bytes.extend_from_slice(&(manifest.file_count() as u32).to_be_bytes());
                for entry in manifest.entries() {
                    bytes.extend_from_slice(entry.file_id.as_bytes());
                    encode_string(&mut bytes, &entry.relative_path);
                    bytes.extend_from_slice(&entry.size.to_be_bytes());
                    encode_digest(&mut bytes, entry.content_hash);
                    encode_metadata(&mut bytes, entry.metadata);
                }
            }
            None => bytes.push(0),
        }
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ClientError> {
        if bytes.len() > MAX_RESUME_TICKET_FILE_SIZE {
            return Err(invalid_resume_data("resume ticket 文件过大"));
        }
        let mut reader = Cursor::new(bytes);
        let mut magic = [0_u8; RESUME_TICKET_MAGIC.len()];
        read_exact(&mut reader, &mut magic)?;
        if &magic != RESUME_TICKET_MAGIC || read_u8(&mut reader)? != RESUME_TICKET_VERSION {
            return Err(invalid_resume_data("resume ticket 版本或 magic 无效"));
        }
        let pairing_id = PairingId::from_bytes(read_array(&mut reader)?);
        let transfer_id = TransferId::from_bytes(read_array(&mut reader)?);
        let role = read_enum(&mut reader, "transfer role")?;
        let manifest_digest = read_digest(&mut reader)?;
        let expires_at_millis = read_u64(&mut reader)?;
        let ticket = SessionTicket::new(read_blob(&mut reader, MAX_TICKET_LEN)?);
        validate_ticket_bytes(&ticket)?;
        let manifest = match read_u8(&mut reader)? {
            0 => None,
            1 => {
                let count = usize::try_from(read_u32(&mut reader)?)
                    .map_err(|_| invalid_resume_data("manifest 文件数溢出"))?;
                if count > MAX_MANIFEST_FILES {
                    return Err(invalid_resume_data("manifest 文件数超限"));
                }
                let mut entries = Vec::with_capacity(count);
                for _ in 0..count {
                    let file_id = FileId::from_bytes(read_array(&mut reader)?);
                    let relative_path = read_string(&mut reader, MAX_PATH_LEN)?;
                    let size = read_u64(&mut reader)?;
                    let content_hash = read_digest(&mut reader)?;
                    let metadata = read_metadata(&mut reader)?;
                    entries.push(
                        ManifestEntry::new(file_id, relative_path, size, content_hash, metadata)
                            .map_err(ClientError::from)?,
                    );
                }
                Some(Manifest::new(manifest_digest, entries).map_err(ClientError::from)?)
            }
            _ => return Err(invalid_resume_data("manifest 标记无效")),
        };
        if reader.position() != bytes.len() as u64 {
            return Err(invalid_resume_data("resume ticket 包含尾部数据"));
        }
        Ok(Self {
            pairing_id,
            transfer_id,
            role,
            manifest_digest,
            expires_at_millis,
            ticket,
            manifest,
        })
    }

    pub fn save_to(&self, root: impl AsRef<Path>) -> Result<PathBuf, ClientError> {
        let directory = root
            .as_ref()
            .join(STORAGE_DIRECTORY)
            .join(SESSIONS_DIRECTORY)
            .join(self.transfer_id.to_string());
        fs::create_dir_all(&directory)?;
        let path = directory.join(format!("resume{RESUME_TICKET_SUFFIX}"));
        let temporary = directory.join(format!(
            ".resume.{}.{}",
            std::process::id(),
            unix_millis_now()
        ));
        let result = (|| {
            let mut options = fs::OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temporary)?;
            file.write_all(&self.encode())?;
            file.sync_all()?;
            fs::rename(&temporary, &path)?;
            Ok::<(), io::Error>(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result.map_err(ClientError::from)?;
        Ok(path)
    }

    pub fn load_from(root: impl AsRef<Path>, transfer_id: TransferId) -> Result<Self, ClientError> {
        let path = root
            .as_ref()
            .join(STORAGE_DIRECTORY)
            .join(SESSIONS_DIRECTORY)
            .join(transfer_id.to_string())
            .join(format!("resume{RESUME_TICKET_SUFFIX}"));
        let bytes = fs::read(path)?;
        let ticket = Self::decode(&bytes)?;
        if ticket.transfer_id != transfer_id {
            return Err(invalid_resume_data("resume ticket 的 transfer_id 不匹配"));
        }
        Ok(ticket)
    }

    pub(crate) fn wire_ticket(&self) -> SessionTicket {
        self.ticket.clone()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeSession {
    pub transfer_id: String,
    pub partial_bytes: u64,
    pub state_files: usize,
}

pub fn list_resume_sessions(root: impl AsRef<Path>) -> Result<Vec<ResumeSession>, ClientError> {
    let sessions = root
        .as_ref()
        .join(STORAGE_DIRECTORY)
        .join(SESSIONS_DIRECTORY);
    let entries = match fs::read_dir(&sessions) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut result = Vec::new();
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let transfer_id = entry.file_name().to_string_lossy().into_owned();
        if !is_transfer_id(&transfer_id) {
            continue;
        }
        let mut state_files = 0;
        for file in fs::read_dir(entry.path())? {
            if file?
                .path()
                .extension()
                .is_some_and(|extension| extension == "state")
            {
                state_files += 1;
            }
        }
        let partial = root
            .as_ref()
            .join(STORAGE_DIRECTORY)
            .join(PARTIAL_DIRECTORY)
            .join(&transfer_id);
        let partial_bytes = directory_size(&partial)?;
        result.push(ResumeSession {
            transfer_id,
            partial_bytes,
            state_files,
        });
    }
    result.sort_by(|left, right| left.transfer_id.cmp(&right.transfer_id));
    Ok(result)
}

pub fn cleanup_resume_session(
    root: impl AsRef<Path>,
    transfer_id: &str,
) -> Result<(), ClientError> {
    if !is_transfer_id(transfer_id) {
        return Err(ClientError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "transfer_id 必须是 32 位十六进制字符串",
        )));
    }
    let root = root.as_ref();
    let sessions = root
        .join(STORAGE_DIRECTORY)
        .join(SESSIONS_DIRECTORY)
        .join(transfer_id);
    let partial = root
        .join(STORAGE_DIRECTORY)
        .join(PARTIAL_DIRECTORY)
        .join(transfer_id);
    remove_directory_if_exists(&sessions)?;
    remove_directory_if_exists(&partial)?;
    Ok(())
}

fn directory_size(path: &Path) -> Result<u64, ClientError> {
    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error.into()),
    };
    let mut size = 0_u64;
    for entry in entries {
        let entry = entry?;
        let metadata = entry.metadata()?;
        if metadata.is_dir() {
            size = size.saturating_add(directory_size(&entry.path())?);
        } else {
            size = size.saturating_add(metadata.len());
        }
    }
    Ok(size)
}

fn remove_directory_if_exists(path: &Path) -> Result<(), ClientError> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn is_transfer_id(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_ticket_bytes(ticket: &SessionTicket) -> Result<(), ClientError> {
    if ticket.as_bytes().is_empty() || ticket.as_bytes().len() > MAX_TICKET_LEN {
        return Err(invalid_resume_data("resume ticket 长度无效"));
    }
    Ok(())
}

fn encode_blob(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
    bytes.extend_from_slice(value);
}

fn encode_string(bytes: &mut Vec<u8>, value: &str) {
    encode_blob(bytes, value.as_bytes());
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

fn read_exact(reader: &mut Cursor<&[u8]>, target: &mut [u8]) -> Result<(), ClientError> {
    reader
        .read_exact(target)
        .map_err(|_| invalid_resume_data("resume ticket 数据截断"))
}

fn read_u8(reader: &mut Cursor<&[u8]>) -> Result<u8, ClientError> {
    let mut value = [0_u8; 1];
    read_exact(reader, &mut value)?;
    Ok(value[0])
}

fn read_u32(reader: &mut Cursor<&[u8]>) -> Result<u32, ClientError> {
    let mut value = [0_u8; 4];
    read_exact(reader, &mut value)?;
    Ok(u32::from_be_bytes(value))
}

fn read_u64(reader: &mut Cursor<&[u8]>) -> Result<u64, ClientError> {
    let mut value = [0_u8; 8];
    read_exact(reader, &mut value)?;
    Ok(u64::from_be_bytes(value))
}

fn read_array<const N: usize>(reader: &mut Cursor<&[u8]>) -> Result<[u8; N], ClientError> {
    let mut value = [0_u8; N];
    read_exact(reader, &mut value)?;
    Ok(value)
}

fn read_blob(reader: &mut Cursor<&[u8]>, maximum: usize) -> Result<Vec<u8>, ClientError> {
    let length = usize::try_from(read_u32(reader)?)
        .map_err(|_| invalid_resume_data("resume ticket 字段长度溢出"))?;
    if length > maximum {
        return Err(invalid_resume_data("resume ticket 字段过大"));
    }
    let mut value = vec![0_u8; length];
    read_exact(reader, &mut value)?;
    Ok(value)
}

fn read_string(reader: &mut Cursor<&[u8]>, maximum: usize) -> Result<String, ClientError> {
    let bytes = read_blob(reader, maximum)?;
    String::from_utf8(bytes).map_err(|_| invalid_resume_data("resume ticket 路径不是 UTF-8"))
}

fn read_digest(reader: &mut Cursor<&[u8]>) -> Result<Digest, ClientError> {
    let algorithm = match read_u8(reader)? {
        1 => HashAlgorithm::Blake3,
        2 => HashAlgorithm::Sha256,
        _ => return Err(invalid_resume_data("resume ticket hash 算法无效")),
    };
    Ok(Digest::new(algorithm, read_array(reader)?))
}

fn read_metadata(reader: &mut Cursor<&[u8]>) -> Result<FileMetadata, ClientError> {
    let modified_time_unix_seconds = match read_u8(reader)? {
        0 => None,
        1 => Some(i64::from_be_bytes(read_array(reader)?)),
        _ => return Err(invalid_resume_data("resume ticket metadata 无效")),
    };
    let mode = match read_u8(reader)? {
        0 => None,
        1 => Some(u32::from_be_bytes(read_array(reader)?)),
        _ => return Err(invalid_resume_data("resume ticket metadata 无效")),
    };
    Ok(FileMetadata {
        modified_time_unix_seconds,
        mode,
    })
}

fn read_enum(reader: &mut Cursor<&[u8]>, field: &'static str) -> Result<TransferRole, ClientError> {
    TransferRole::try_from(read_u8(reader)?).map_err(|_| invalid_resume_data(field))
}

fn invalid_resume_data(message: &'static str) -> ClientError {
    ClientError::Io(io::Error::new(io::ErrorKind::InvalidData, message))
}

fn unix_millis_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use std::fs;

    use transfer_core::ManifestEntry;
    use transfer_protocol::{FileMetadata, HashAlgorithm};

    use super::*;

    #[test]
    fn lists_and_cleans_only_valid_transfer_directories() {
        let root = std::env::temp_dir().join(format!("udp-file-resume-{}", std::process::id()));
        let valid = root
            .join(STORAGE_DIRECTORY)
            .join(SESSIONS_DIRECTORY)
            .join("00112233445566778899aabbccddeeff");
        let partial = root
            .join(STORAGE_DIRECTORY)
            .join(PARTIAL_DIRECTORY)
            .join("00112233445566778899aabbccddeeff");
        let invalid = root
            .join(STORAGE_DIRECTORY)
            .join(SESSIONS_DIRECTORY)
            .join("not-a-transfer");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&valid).unwrap();
        fs::create_dir_all(&partial).unwrap();
        fs::create_dir_all(&invalid).unwrap();
        fs::write(valid.join("file.state"), b"state").unwrap();
        fs::write(partial.join("file.part"), b"partial").unwrap();

        let sessions = list_resume_sessions(&root).unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].state_files, 1);
        assert_eq!(sessions[0].partial_bytes, 7);

        cleanup_resume_session(&root, &sessions[0].transfer_id).unwrap();
        assert!(!valid.exists());
        assert!(!partial.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn resume_ticket_round_trips_and_is_stored_atomically() {
        let root = std::env::temp_dir().join(format!(
            "udp-file-resume-ticket-{}-{}",
            std::process::id(),
            unix_millis_now()
        ));
        let transfer_id = TransferId::from_bytes([3; 16]);
        let manifest_digest = Digest::new(HashAlgorithm::Blake3, [4; 32]);
        let manifest = Manifest::new(
            manifest_digest,
            vec![
                ManifestEntry::new(
                    FileId::from_bytes([5; 16]),
                    "folder/file.bin".to_owned(),
                    3,
                    Digest::new(HashAlgorithm::Blake3, [6; 32]),
                    FileMetadata {
                        modified_time_unix_seconds: Some(7),
                        mode: Some(0o600),
                    },
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let ticket = ResumeTicket::from_wire(
            PairingId::from_bytes([8; 16]),
            transfer_id,
            TransferRole::Offerer,
            manifest_digest,
            u64::MAX,
            SessionTicket::new(vec![9; 32]),
        )
        .unwrap()
        .with_manifest(manifest);

        let encoded = ticket.encode();
        assert_eq!(ResumeTicket::decode(&encoded).unwrap(), ticket);
        let path = ticket.save_to(&root).unwrap();
        assert_eq!(ResumeTicket::load_from(&root, transfer_id).unwrap(), ticket);
        assert!(!fs::metadata(path).unwrap().permissions().readonly());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn malformed_resume_ticket_is_rejected_without_large_allocation() {
        let mut bytes = Vec::from(*RESUME_TICKET_MAGIC);
        bytes.push(RESUME_TICKET_VERSION);
        bytes.extend_from_slice(&[0; 32]);
        bytes.push(0xff);
        assert!(ResumeTicket::decode(&bytes).is_err());
    }
}
