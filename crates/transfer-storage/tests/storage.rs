use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use transfer_core::DurableState;
use transfer_protocol::{Digest, FileId, FileMetadata, HashAlgorithm, OverwritePolicy, TransferId};
use transfer_storage::{
    FileRegistration, FileStorage, ManifestBuilder, StorageConfig, StorageError, hash_bytes,
    hash_file,
};

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn new() -> Self {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is before epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("udp-transfer-storage-test-{suffix}"));
        fs::create_dir(&path).expect("create test directory");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn transfer_id(value: u8) -> TransferId {
    TransferId::from_bytes([value; 16])
}

fn file_id(value: u8) -> FileId {
    FileId::from_bytes([value; 16])
}

fn registration(transfer: u8, file: u8, path: &str, bytes: &[u8]) -> FileRegistration {
    FileRegistration {
        transfer_id: transfer_id(transfer),
        file_id: file_id(file),
        relative_path: path.to_owned(),
        size: bytes.len() as u64,
        content_hash: hash_bytes(bytes, HashAlgorithm::Blake3),
        metadata: FileMetadata {
            modified_time_unix_seconds: None,
            mode: None,
        },
    }
}

fn storage_config(overwrite_policy: OverwritePolicy) -> StorageConfig {
    StorageConfig {
        overwrite_policy,
        sync_data: true,
        sync_all: true,
    }
}

#[test]
fn hashes_files_without_loading_the_whole_file() {
    let directory = TestDirectory::new();
    let path = directory.path().join("input.bin");
    let mut file = File::create(&path).expect("create input");
    file.write_all(&vec![0x5a; 2 * 1024 * 1024 + 17])
        .expect("write input");
    let expected = hash_bytes(&fs::read(&path).expect("read input"), HashAlgorithm::Blake3);
    assert_eq!(
        hash_file(&path, HashAlgorithm::Blake3).expect("hash input"),
        expected
    );
}

#[test]
fn builds_sorted_manifest_and_rejects_symlinks() {
    let directory = TestDirectory::new();
    let source = directory.path().join("source");
    fs::create_dir(&source).expect("create source");
    fs::create_dir(source.join("nested")).expect("create nested");
    fs::write(source.join("z.txt"), b"z").expect("write z");
    fs::write(source.join("nested/a.txt"), b"a").expect("write a");

    let manifest = ManifestBuilder::default()
        .build([source.clone()])
        .expect("build manifest");
    let paths = manifest
        .entries()
        .iter()
        .map(|entry| entry.relative_path.as_str())
        .collect::<Vec<_>>();
    assert_eq!(paths, ["source/nested/a.txt", "source/z.txt"]);
    assert_eq!(manifest.total_size(), 2);

    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(source.join("z.txt"), directory.path().join("link"))
            .expect("create source symlink");
        assert!(matches!(
            ManifestBuilder::default().build([directory.path().join("link")]),
            Err(StorageError::SymbolicLinkNotAllowed { .. })
        ));
    }
}

#[test]
fn checkpoint_recovery_discards_uncheckpointed_tail_and_completes_atomically() {
    let directory = TestDirectory::new();
    let bytes = b"hello world";
    let registration = registration(1, 2, "nested/result.bin", bytes);
    let transfer = registration.transfer_id;
    let file = registration.file_id;

    {
        let mut storage = FileStorage::open_with_config(
            directory.path(),
            storage_config(OverwritePolicy::ReplaceAfterConfirm),
        )
        .expect("open storage");
        storage
            .register_file(registration.clone())
            .expect("register file");
        storage
            .write_data(transfer, file, 0, b"hello")
            .expect("write first chunk");
        storage
            .checkpoint(
                transfer,
                file,
                DurableState {
                    durable_offset: 5,
                    checkpoint_id: 1,
                    state_hash: hash_bytes(b"hello", HashAlgorithm::Blake3),
                },
            )
            .expect("checkpoint first chunk");
        storage
            .write_data(transfer, file, 5, b" world")
            .expect("write second chunk");
    }

    {
        let mut storage = FileStorage::open_with_config(
            directory.path(),
            storage_config(OverwritePolicy::ReplaceAfterConfirm),
        )
        .expect("reopen storage");
        assert_eq!(
            storage
                .durable_state(transfer, file)
                .expect("read durable state")
                .durable_offset,
            5
        );
        assert_eq!(
            fs::read(storage.partial_path_for(transfer, file)).expect("read partial"),
            b"hello"
        );
        storage
            .write_data(transfer, file, 5, b" world")
            .expect("rewrite uncheckpointed chunk");
        storage
            .checkpoint(
                transfer,
                file,
                DurableState {
                    durable_offset: bytes.len() as u64,
                    checkpoint_id: 2,
                    state_hash: hash_bytes(bytes, HashAlgorithm::Blake3),
                },
            )
            .expect("checkpoint complete data");
        storage
            .complete_file(
                transfer,
                file,
                bytes.len() as u64,
                registration.content_hash,
            )
            .expect("complete file");
    }

    assert_eq!(
        fs::read(directory.path().join("nested/result.bin")).expect("read result"),
        bytes
    );
    let storage = FileStorage::open_with_config(
        directory.path(),
        storage_config(OverwritePolicy::ReplaceAfterConfirm),
    )
    .expect("reopen completed storage");
    assert_eq!(
        storage
            .durable_state(transfer, file)
            .expect("read completed state")
            .durable_offset,
        bytes.len() as u64
    );
}

#[test]
fn overwrite_policies_are_explicit() {
    let directory = TestDirectory::new();
    let first = registration(3, 1, "same.txt", b"first");
    let second = registration(4, 1, "same.txt", b"second");
    let destination = directory.path().join("same.txt");

    let mut storage = FileStorage::open_with_config(
        directory.path(),
        storage_config(OverwritePolicy::ReplaceAfterConfirm),
    )
    .expect("open storage");
    storage
        .register_file(first.clone())
        .expect("register first");
    storage
        .write_data(first.transfer_id, first.file_id, 0, b"first")
        .expect("write first");
    storage
        .checkpoint(
            first.transfer_id,
            first.file_id,
            DurableState {
                durable_offset: 5,
                checkpoint_id: 1,
                state_hash: hash_bytes(b"first", HashAlgorithm::Blake3),
            },
        )
        .expect("checkpoint first");
    storage
        .complete_file(first.transfer_id, first.file_id, 5, first.content_hash)
        .expect("complete first");

    let mut no_replace =
        FileStorage::open_with_config(directory.path(), storage_config(OverwritePolicy::NoReplace))
            .expect("open no replace storage");
    no_replace
        .register_file(second.clone())
        .expect("register second");
    no_replace
        .write_data(second.transfer_id, second.file_id, 0, b"second")
        .expect("write second");
    no_replace
        .checkpoint(
            second.transfer_id,
            second.file_id,
            DurableState {
                durable_offset: 6,
                checkpoint_id: 1,
                state_hash: hash_bytes(b"second", HashAlgorithm::Blake3),
            },
        )
        .expect("checkpoint second");
    assert!(matches!(
        no_replace.complete_file(second.transfer_id, second.file_id, 6, second.content_hash),
        Err(StorageError::AlreadyExists { .. })
    ));
    assert_eq!(
        fs::read(&destination).expect("read original destination"),
        b"first"
    );
}

#[test]
fn completion_requires_a_durable_end_offset() {
    let directory = TestDirectory::new();
    let registration = registration(7, 1, "not-yet-durable.txt", b"data");
    let mut storage = FileStorage::open_with_config(
        directory.path(),
        storage_config(OverwritePolicy::ReplaceAfterConfirm),
    )
    .expect("open storage");
    storage
        .register_file(registration.clone())
        .expect("register file");
    storage
        .write_data(registration.transfer_id, registration.file_id, 0, b"data")
        .expect("write data");
    assert!(matches!(
        storage.complete_file(
            registration.transfer_id,
            registration.file_id,
            4,
            registration.content_hash
        ),
        Err(StorageError::InvalidOffset { .. })
    ));
    assert!(!directory.path().join("not-yet-durable.txt").exists());
}

#[test]
fn rename_with_suffix_is_idempotent_after_restart() {
    let directory = TestDirectory::new();
    let registration = registration(9, 1, "same.txt", b"suffix");
    let mut storage = FileStorage::open_with_config(
        directory.path(),
        storage_config(OverwritePolicy::RenameWithSuffix),
    )
    .expect("open storage");
    fs::write(directory.path().join("same.txt"), b"existing").expect("write existing file");
    storage
        .register_file(registration.clone())
        .expect("register file");
    storage
        .write_data(registration.transfer_id, registration.file_id, 0, b"suffix")
        .expect("write data");
    storage
        .checkpoint(
            registration.transfer_id,
            registration.file_id,
            DurableState {
                durable_offset: 6,
                checkpoint_id: 1,
                state_hash: hash_bytes(b"suffix", HashAlgorithm::Blake3),
            },
        )
        .expect("checkpoint data");
    storage
        .complete_file(
            registration.transfer_id,
            registration.file_id,
            6,
            registration.content_hash,
        )
        .expect("complete file");
    assert_eq!(
        fs::read(directory.path().join("same.txt.1")).expect("read suffixed file"),
        b"suffix"
    );
    drop(storage);
    let mut reopened = FileStorage::open_with_config(
        directory.path(),
        storage_config(OverwritePolicy::RenameWithSuffix),
    )
    .expect("reopen storage");
    reopened
        .complete_file(
            registration.transfer_id,
            registration.file_id,
            6,
            registration.content_hash,
        )
        .expect("repeat complete file");
}

#[test]
fn empty_files_are_installed_without_a_data_write() {
    let directory = TestDirectory::new();
    let registration = registration(8, 1, "empty.txt", b"");
    let mut storage = FileStorage::open_with_config(
        directory.path(),
        storage_config(OverwritePolicy::ReplaceAfterConfirm),
    )
    .expect("open storage");
    storage
        .register_file(registration.clone())
        .expect("register file");
    storage
        .complete_file(
            registration.transfer_id,
            registration.file_id,
            0,
            registration.content_hash,
        )
        .expect("complete empty file");
    assert_eq!(
        fs::metadata(directory.path().join("empty.txt"))
            .expect("read empty file")
            .len(),
        0
    );
}

#[cfg(unix)]
#[test]
fn destination_symlink_cannot_escape_storage_root() {
    let directory = TestDirectory::new();
    let outside = TestDirectory::new();
    std::os::unix::fs::symlink(outside.path(), directory.path().join("escape"))
        .expect("create directory symlink");
    let registration = registration(5, 1, "escape/file.bin", b"data");
    let mut storage = FileStorage::open_with_config(
        directory.path(),
        storage_config(OverwritePolicy::ReplaceAfterConfirm),
    )
    .expect("open storage");
    storage
        .register_file(registration.clone())
        .expect("register file");
    storage
        .write_data(registration.transfer_id, registration.file_id, 0, b"data")
        .expect("write data");
    storage
        .checkpoint(
            registration.transfer_id,
            registration.file_id,
            DurableState {
                durable_offset: 4,
                checkpoint_id: 1,
                state_hash: hash_bytes(b"data", HashAlgorithm::Blake3),
            },
        )
        .expect("checkpoint data");
    assert!(matches!(
        storage.complete_file(
            registration.transfer_id,
            registration.file_id,
            4,
            registration.content_hash
        ),
        Err(StorageError::SymbolicLinkNotAllowed { .. })
    ));
    assert!(!outside.path().join("file.bin").exists());
}

#[test]
fn malformed_relative_paths_are_rejected() {
    let directory = TestDirectory::new();
    let mut storage = FileStorage::open(directory.path()).expect("open storage");
    let mut registration = registration(6, 1, "ok.txt", b"data");
    registration.relative_path = "../escape.txt".to_owned();
    assert!(matches!(
        storage.register_file(registration),
        Err(StorageError::InvalidPath { .. })
    ));
}

#[test]
fn manifest_digest_uses_the_selected_hash_algorithm() {
    let directory = TestDirectory::new();
    fs::write(directory.path().join("a.txt"), b"a").expect("write source");
    let config = transfer_storage::ManifestBuildConfig {
        hash_algorithm: HashAlgorithm::Sha256,
        ..Default::default()
    };
    let manifest = ManifestBuilder::new(config)
        .build([directory.path().join("a.txt")])
        .expect("build sha manifest");
    assert_eq!(manifest.digest().algorithm, HashAlgorithm::Sha256);
    assert_eq!(
        manifest.entries()[0].content_hash.algorithm,
        HashAlgorithm::Sha256
    );
}

#[test]
fn digest_type_is_constructible_for_storage_state() {
    let digest = Digest::new(HashAlgorithm::Blake3, [7; 32]);
    assert_eq!(digest.bytes, [7; 32]);
}
