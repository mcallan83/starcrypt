#![allow(dead_code)] // Shared helpers are used by different integration targets.
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path};

pub fn compare_tree(source: &Path, output: &Path) -> Result<()> {
    let expected = fs::read_dir(source)?.collect::<std::io::Result<Vec<_>>>()?;
    ensure!(
        expected.len() == fs::read_dir(output)?.count(),
        "Entry count differs: {}",
        source.display()
    );
    for entry in expected {
        let actual = output.join(entry.file_name());
        let kind = entry.file_type()?;
        let metadata = fs::symlink_metadata(&actual)
            .with_context(|| format!("Missing extracted entry {}", actual.display()))?;
        ensure!(
            kind.is_file() == metadata.is_file()
                && kind.is_dir() == metadata.is_dir()
                && kind.is_symlink() == metadata.file_type().is_symlink(),
            "Entry type mismatch"
        );
        if kind.is_dir() {
            compare_tree(&entry.path(), &actual)?;
        } else if kind.is_symlink() {
            ensure!(
                fs::read_link(entry.path())? == fs::read_link(actual)?,
                "Symlink target mismatch"
            );
        } else {
            ensure!(
                fs::read(entry.path())? == fs::read(actual)?,
                "File bytes mismatch"
            );
        }
    }
    Ok(())
}
pub fn copy_tree(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let target = destination.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else {
            fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}
#[cfg(unix)]
pub fn copy_symlink_times(destination: &Path, metadata: &fs::Metadata) -> Result<()> {
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
