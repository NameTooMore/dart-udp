use std::{
    collections::HashMap,
    fs, io,
    path::{Path, PathBuf},
};

pub(crate) fn collect_source_files(sources: &[PathBuf]) -> io::Result<HashMap<String, PathBuf>> {
    let mut files = HashMap::new();
    for source in sources {
        let metadata = fs::symlink_metadata(source)?;
        if metadata.file_type().is_symlink() {
            return Err(invalid_path("symbolic links are not allowed"));
        }
        let source = source.canonicalize()?;
        if metadata.is_file() {
            let name = source
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| invalid_path("source file name is not UTF-8"))?;
            insert(&mut files, name.to_owned(), source)?;
        } else if metadata.is_dir() {
            let root = source
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| invalid_path("source directory name is not UTF-8"))?;
            collect_directory(&source, root, &mut files)?;
        } else {
            return Err(invalid_path("unsupported source file type"));
        }
    }
    Ok(files)
}

fn collect_directory(
    directory: &Path,
    relative: &str,
    files: &mut HashMap<String, PathBuf>,
) -> io::Result<()> {
    let mut entries = fs::read_dir(directory)?.collect::<Result<Vec<_>, io::Error>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(invalid_path("symbolic links are not allowed"));
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| invalid_path("source path is not UTF-8"))?;
        let child = format!("{relative}/{name}");
        if metadata.is_dir() {
            collect_directory(&path, &child, files)?;
        } else if metadata.is_file() {
            insert(files, child, path)?;
        } else {
            return Err(invalid_path("unsupported source file type"));
        }
    }
    Ok(())
}

fn insert(files: &mut HashMap<String, PathBuf>, relative: String, path: PathBuf) -> io::Result<()> {
    if files.insert(relative, path).is_some() {
        return Err(invalid_path("source paths collide"));
    }
    Ok(())
}

fn invalid_path(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
