use std::{
    fs::File,
    io::{self, Read},
    path::Path,
};

use sha2::{Digest as ShaDigest, Sha256};
use transfer_protocol::{Digest, HashAlgorithm};

use crate::StorageError;

const HASH_BUFFER_SIZE: usize = 1024 * 1024;

pub fn hash_reader<R: Read>(
    mut reader: R,
    algorithm: HashAlgorithm,
) -> Result<Digest, StorageError> {
    let mut buffer = vec![0_u8; HASH_BUFFER_SIZE];
    match algorithm {
        HashAlgorithm::Blake3 => {
            let mut hasher = blake3::Hasher::new();
            loop {
                let read = reader
                    .read(&mut buffer)
                    .map_err(|source| StorageError::io("read file for hashing", source))?;
                if read == 0 {
                    break;
                }
                hasher.update(&buffer[..read]);
            }
            Ok(Digest::new(
                HashAlgorithm::Blake3,
                *hasher.finalize().as_bytes(),
            ))
        }
        HashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            loop {
                let read = reader
                    .read(&mut buffer)
                    .map_err(|source| StorageError::io("read file for hashing", source))?;
                if read == 0 {
                    break;
                }
                hasher.update(&buffer[..read]);
            }
            let bytes: [u8; 32] = hasher.finalize().into();
            Ok(Digest::new(HashAlgorithm::Sha256, bytes))
        }
    }
}

pub fn hash_file(path: &Path, algorithm: HashAlgorithm) -> Result<Digest, StorageError> {
    let file = open_read_only(path)?;
    hash_reader(file, algorithm)
}

pub fn hash_bytes(bytes: &[u8], algorithm: HashAlgorithm) -> Digest {
    match algorithm {
        HashAlgorithm::Blake3 => {
            Digest::new(HashAlgorithm::Blake3, *blake3::hash(bytes).as_bytes())
        }
        HashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(bytes);
            Digest::new(HashAlgorithm::Sha256, hasher.finalize().into())
        }
    }
}

pub fn verify_file(path: &Path, expected: Digest) -> Result<(), StorageError> {
    let actual = hash_file(path, expected.algorithm)?;
    if actual == expected {
        Ok(())
    } else {
        Err(StorageError::FileIntegrityMismatch { expected, actual })
    }
}

pub(crate) fn open_read_only(path: &Path) -> Result<File, StorageError> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options
        .open(path)
        .map_err(|source| StorageError::io("open file for reading", source))
}

pub(crate) fn read_exact_or_eof<R: Read>(
    reader: &mut R,
    bytes: &mut [u8],
) -> Result<(), StorageError> {
    reader
        .read_exact(bytes)
        .map_err(|source| match source.kind() {
            io::ErrorKind::UnexpectedEof => StorageError::MalformedState,
            _ => StorageError::io("read checkpoint state", source),
        })
}
