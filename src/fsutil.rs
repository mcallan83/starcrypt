//! Filesystem validation, output cleanup, and timestamp helpers.
use anyhow::{Context, Result, ensure};
use std::{
    fs,
    path::{Component, Path, PathBuf},
};

pub(crate) fn destination_path(path: &Path, source: &Path) -> Result<PathBuf> {
    let name = path
        .file_name()
        .context("Destination needs a folder name")?;
    ensure!(
        path.components()
            .all(|c| !matches!(c, Component::ParentDir)),
        "Destination cannot contain '..'"
    );
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let destination = parent
        .canonicalize()
        .context("Destination parent must exist")?
        .join(name);
    ensure!(
        !destination.starts_with(source),
        "Destination cannot be inside the source"
    );
    ensure!(
        fs::symlink_metadata(&destination).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "Destination already exists or cannot be accessed"
    );
    Ok(destination)
}

// Reserve the destination exclusively. Clean up incomplete output on ordinary errors.
pub(crate) fn new_output(path: &Path, work: impl FnOnce() -> Result<()>) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .context("Cannot create new destination")?;
    if let Err(error) = work() {
        if let Err(cleanup) = fs::remove_dir_all(path) {
            return Err(error.context(format!(
                "Incomplete output remains at {}: {cleanup}",
                path.display()
            )));
        }
        return Err(error);
    }
    Ok(())
}
pub(crate) fn copy_times(destination: &Path, metadata: &fs::Metadata) -> Result<()> {
    let times = fs::FileTimes::new()
        .set_accessed(metadata.accessed()?)
        .set_modified(metadata.modified()?);
    fs::File::open(destination)?
        .set_times(times)
        .with_context(|| format!("Cannot preserve timestamps for {}", destination.display()))?;
    Ok(())
}
pub(crate) fn safe_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty() && name != "." && name != ".." && !name.contains(['/', '\\', '\0']),
        "Unsafe vault entry name"
    );
    Ok(())
}

// Archive components also exclude Windows drive prefixes and alternate streams.
// Use the same rule when choosing the internal vault name and unpacking entries.
pub(crate) fn safe_archive_component(name: &str) -> Result<()> {
    safe_name(name)?;
    ensure!(!name.contains(':'), "Unsafe archive entry path");
    Ok(())
}

#[cfg(unix)]
pub(crate) fn copy_symlink_times(destination: &Path, metadata: &fs::Metadata) -> Result<()> {
    use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};
    let path = std::ffi::CString::new(destination.as_os_str().as_bytes())?;
    let times = [
        libc::timespec {
            tv_sec: metadata.atime(),
            tv_nsec: metadata.atime_nsec(),
        },
        libc::timespec {
            tv_sec: metadata.mtime(),
            tv_nsec: metadata.mtime_nsec(),
        },
    ];
    // SAFETY: path is NUL-terminated and times points to two initialized timespecs.
    // AT_SYMLINK_NOFOLLOW updates the link itself, including dangling links.
    let result = unsafe {
        libc::utimensat(
            libc::AT_FDCWD,
            path.as_ptr(),
            times.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!(
                "Cannot preserve symlink timestamps for {}",
                destination.display()
            )
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_unsafe_names() {
        for name in ["", ".", "..", "../escape", "/absolute", "a\\b"] {
            assert!(safe_name(name).is_err());
        }
    }
}

/// The caller passes the canonical source. Use the actual mount table rather
/// than guessing from /Volumes or matching names in an ordinary directory.
#[cfg(target_os = "macos")]
pub(crate) fn is_macos_volume_root(source: &Path) -> Result<bool> {
    use std::{
        ffi::{CStr, CString},
        os::unix::ffi::OsStrExt,
    };
    let path = CString::new(source.as_os_str().as_bytes())?;
    let mut stats = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: path is NUL-terminated; stats is writable and correctly sized.
    if unsafe { libc::statfs(path.as_ptr(), stats.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("Cannot inspect source mount for {}", source.display()));
    }
    // SAFETY: successful statfs initialized stats, including f_mntonname.
    let stats = unsafe { stats.assume_init() };
    // Bound the scan to the field rather than relying on a terminator.
    let bytes: Vec<u8> = stats.f_mntonname.iter().map(|b| *b as u8).collect();
    let mount = CStr::from_bytes_until_nul(&bytes).context("Invalid macOS mount path")?;
    let mount = Path::new(std::ffi::OsStr::from_bytes(mount.to_bytes()));
    Ok(source
        == mount
            .canonicalize()
            .with_context(|| format!("Cannot resolve source mount {}", mount.display()))?)
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn is_macos_volume_root(_source: &Path) -> Result<bool> {
    Ok(false)
}

#[cfg(all(test, target_os = "macos"))]
mod macos_tests {
    use super::*;
    #[test]
    fn detects_actual_mount_root_not_normal_directories() -> Result<()> {
        assert!(is_macos_volume_root(Path::new("/"))?);
        let temp = tempfile::tempdir()?;
        fs::create_dir(temp.path().join(".Trashes"))?;
        assert!(!is_macos_volume_root(&temp.path().canonicalize()?)?);
        Ok(())
    }
}
