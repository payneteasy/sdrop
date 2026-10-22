//! Saving a received secret (README): new files with mode 0600, new private directories with mode
//! 0700, nothing ever overwritten, a failed write removes what it wrote. Shared by CLI and TUI.

use crate::api::{self, CliError, err};
use std::io::Write;
use std::path::{Path, PathBuf};

/// `-o` path before consume: the parent is an existing directory, the path itself does not exist.
pub fn check_target(p: &Path) -> Result<(), CliError> {
    let shown = api::printable(&p.display().to_string());
    let parent = match p.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    if !parent.is_dir() {
        return err(format!("{shown}: the directory does not exist"));
    }
    if std::fs::symlink_metadata(p).is_ok() {
        return err(format!("{shown} already exists; choose another path"));
    }
    Ok(())
}

/// New file with mode 0600; a partially written one is removed.
pub fn write_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let mut f = opts.open(path)?;
    if let Err(e) = f.write_all(bytes).and_then(|_| f.sync_all()) {
        drop(f);
        let _ = std::fs::remove_file(path);
        return Err(e);
    }
    Ok(())
}

/// Directory builder with mode 0700 on Unix; on Windows the directory inherits the parent's ACL.
pub fn private_dir_builder() -> std::fs::DirBuilder {
    #[allow(unused_mut)]
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder
}

/// New private directory `sdrop-<id8>[-N]` (0700) and a `data` file in it.
pub fn save_default(id: &str, bytes: &[u8]) -> std::io::Result<PathBuf> {
    let builder = private_dir_builder();
    for n in 0..100 {
        let dir = if n == 0 {
            PathBuf::from(format!("sdrop-{}", &id[..8]))
        } else {
            PathBuf::from(format!("sdrop-{}-{n}", &id[..8]))
        };
        match builder.create(&dir) {
            Ok(()) => {
                let file = dir.join("data");
                write_new(&file, bytes)?;
                return Ok(file);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::from(std::io::ErrorKind::AlreadyExists))
}

/// New private directory (0700) with the given files (0600). On any error everything written is
/// removed, so a retry starts clean.
pub fn write_dir(dir: &Path, entries: &[(String, &[u8])]) -> std::io::Result<()> {
    let builder = private_dir_builder();
    builder.create(dir)?;
    for (i, (name, bytes)) in entries.iter().enumerate() {
        if let Err(e) = write_new(&dir.join(name), bytes) {
            for (done, _) in &entries[..i] {
                let _ = std::fs::remove_file(dir.join(done));
            }
            let _ = std::fs::remove_dir(dir);
            return Err(e);
        }
    }
    Ok(())
}

/// New private directory `sdrop-<id8>[-N]` with the given files.
pub fn save_dir_default(id: &str, entries: &[(String, &[u8])]) -> std::io::Result<PathBuf> {
    for n in 0..100 {
        let dir = if n == 0 {
            PathBuf::from(format!("sdrop-{}", &id[..8]))
        } else {
            PathBuf::from(format!("sdrop-{}-{n}", &id[..8]))
        };
        match write_dir(&dir, entries) {
            Ok(()) => return Ok(dir),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::from(std::io::ErrorKind::AlreadyExists))
}
