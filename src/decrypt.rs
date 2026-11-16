//! Bounded parallel decryption of files and chunk-aligned ranges.
use anyhow::{Context, Result, anyhow, ensure};
use oxcrypt_core::{fs::streaming::VaultFileReaderSync, vault::operations::VaultOperations};
use std::{
    fs::{self, File},
    io::{Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    thread,
};
use zeroize::Zeroizing;

// Each task handles 32 format chunks. The bounded queue contains descriptors,
// not plaintext; each worker holds at most one range's plaintext at a time.
const BATCH_SIZE: usize = 1024 * 1024;

pub(crate) struct Source {
    pub reader: VaultFileReaderSync,
    pub path: PathBuf,
    pub metadata: fs::Metadata,
}

struct Output {
    file: Mutex<File>,
    source: PathBuf,
    metadata: fs::Metadata,
    size: u64,
    pending: AtomicUsize,
    progress: crate::Progress,
}
impl Output {
    fn complete(&self) -> Result<()> {
        if self.pending.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.file
                .lock()
                .map_err(|_| anyhow!("Decryption output lock poisoned"))?
                .set_times(
                    fs::FileTimes::new()
                        .set_accessed(self.metadata.accessed()?)
                        .set_modified(self.metadata.modified()?),
                )?;
            self.progress.advance(0, 1);
        }
        Ok(())
    }
}

struct Batch {
    output: Arc<Output>,
    offset: u64,
    // Reuse the reader opened by traversal for the first range (and empty files).
    reader: Option<VaultFileReaderSync>,
}
impl Batch {
    fn decrypt(self, ops: &VaultOperations) -> Result<()> {
        let mut reader = match self.reader {
            Some(reader) => reader,
            None => VaultFileReaderSync::open_with_cipher(
                &self.output.source,
                ops.master_key(),
                ops.cipher_combo(),
            )?,
        };
        ensure!(
            reader.plaintext_size() == self.output.size,
            "Encrypted file changed during extraction"
        );
        let count = (self.output.size - self.offset).min(BATCH_SIZE as u64) as usize;
        let plaintext = Zeroizing::new(reader.read_range(self.offset, count)?);
        ensure!(plaintext.len() == count, "Unexpected end of encrypted file");
        {
            // Only seek/write is serialized; authentication runs in parallel.
            let mut file = self
                .output
                .file
                .lock()
                .map_err(|_| anyhow!("Decryption output lock poisoned"))?;
            file.seek(SeekFrom::Start(self.offset))?;
            file.write_all(&plaintext)?;
        }
        self.output.progress.advance(count as u64, 0);
        self.output.complete()
    }
}

pub(crate) struct DecryptionPool {
    sender: mpsc::SyncSender<Batch>,
    cancelled: Arc<AtomicBool>,
    progress: crate::Progress,
}
impl DecryptionPool {
    fn submit(&self, batch: Batch) -> Result<()> {
        ensure!(
            !self.cancelled.load(Ordering::Acquire),
            "Decryption workers stopped"
        );
        self.sender
            .send(batch)
            .map_err(|_| anyhow!("Decryption workers stopped"))
    }

    pub(crate) fn decrypt_file(&self, source: Source, destination: &Path) -> Result<()> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        // Reserve files on the traversal thread, before restoring directory times.
        let output = Arc::new(Output {
            file: Mutex::new(options.open(destination)?),
            source: source.path,
            metadata: source.metadata,
            size: source.reader.plaintext_size(),
            pending: AtomicUsize::new(1),
            progress: self.progress.clone(),
        });
        let mut reader = Some(source.reader);
        for offset in (0..output.size.max(1)).step_by(BATCH_SIZE) {
            output.pending.fetch_add(1, Ordering::Relaxed);
            self.submit(Batch {
                output: Arc::clone(&output),
                offset,
                reader: reader.take(),
            })?;
        }
        output.complete()
    }
}

pub(crate) fn with_pool(
    ops: &VaultOperations,
    progress: &crate::Progress,
    work: impl FnOnce(&DecryptionPool) -> Result<()>,
) -> Result<()> {
    let workers = thread::available_parallelism().map_or(1, usize::from);
    with_workers(ops, progress, workers, work)
}

fn with_workers(
    ops: &VaultOperations,
    progress: &crate::Progress,
    workers: usize,
    work: impl FnOnce(&DecryptionPool) -> Result<()>,
) -> Result<()> {
    let (sender, receiver) = mpsc::sync_channel::<Batch>(workers);
    let receiver = Arc::new(Mutex::new(receiver));
    let cancelled = Arc::new(AtomicBool::new(false));
    let error = Mutex::new(None);
    thread::scope(|scope| {
        let mut handles = Vec::new();
        for _ in 0..workers {
            let receiver = Arc::clone(&receiver);
            let cancelled = Arc::clone(&cancelled);
            let error = &error;
            handles.push(scope.spawn(move || -> Result<()> {
                loop {
                    let batch = receiver
                        .lock()
                        .map_err(|_| anyhow!("Decryption queue poisoned"))?
                        .recv();
                    let Ok(batch) = batch else { return Ok(()) };
                    // Drain on failure to release a producer blocked on send.
                    if !cancelled.load(Ordering::Acquire) {
                        let source = batch.output.source.clone();
                        if let Err(failure) = batch.decrypt(ops).with_context(|| {
                            format!("Cannot decrypt encrypted file {}", source.display())
                        }) {
                            let mut first = error.lock().unwrap();
                            if first.is_none() {
                                *first = Some(failure);
                            }
                            cancelled.store(true, Ordering::Release);
                        }
                    }
                }
            }));
        }
        drop(receiver);
        let pool = DecryptionPool {
            sender,
            cancelled,
            progress: progress.clone(),
        };
        let mut result = work(&pool);
        drop(pool);
        for handle in handles {
            let worker = handle
                .join()
                .unwrap_or_else(|_| Err(anyhow!("Decryption worker panicked")));
            if result.is_ok() {
                result = worker;
            }
        }
        // Prefer the actual authentication/write failure over cancellation.
        if let Some(failure) = error.lock().unwrap().take() {
            return Err(failure);
        }
        result
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxcrypt_core::{crypto::keys::MasterKey, vault::config::CipherCombo};

    fn source(ops: &VaultOperations, path: &Path) -> Result<Source> {
        let metadata = fs::metadata(path)?;
        crate::vault_read::validate_file(ops, path, metadata.len())?;
        Ok(Source {
            reader: VaultFileReaderSync::open_with_cipher(
                path,
                ops.master_key(),
                ops.cipher_combo(),
            )?,
            path: path.to_owned(),
            metadata,
        })
    }

    #[test]
    fn files_and_parallel_ranges_round_trip_for_both_ciphers() -> Result<()> {
        for cipher in [CipherCombo::SivGcm, CipherCombo::SivCtrMac] {
            let temp = tempfile::tempdir()?;
            let ops = VaultOperations::with_options(temp.path(), MasterKey::random()?, 220, cipher);
            let mut fixtures = Vec::new();
            let modified =
                std::time::UNIX_EPOCH + std::time::Duration::new(1_600_000_000, 123_456_789);
            for (index, size) in [
                0,
                1,
                32_767,
                32_768,
                32_769,
                BATCH_SIZE - 1,
                BATCH_SIZE,
                BATCH_SIZE + 1,
                3 * BATCH_SIZE + 19,
            ]
            .into_iter()
            .enumerate()
            {
                let bytes = (0..size).map(|n| (n % 251) as u8).collect::<Vec<_>>();
                let path = temp.path().join(format!("encrypted-{index}"));
                fs::write(&path, cipher.encrypt_file(&bytes, ops.master_key())?)?;
                File::open(&path)?.set_times(fs::FileTimes::new().set_modified(modified))?;
                fixtures.push((path, bytes));
            }
            for workers in [1, 4] {
                let progress = crate::Progress::default();
                with_workers(&ops, &progress, workers, |pool| {
                    for (index, (path, _)) in fixtures.iter().enumerate() {
                        pool.decrypt_file(
                            source(&ops, path)?,
                            &temp.path().join(format!("output-{workers}-{index}")),
                        )?;
                    }
                    Ok(())
                })?;
                for (index, (_, expected)) in fixtures.iter().enumerate() {
                    let path = temp.path().join(format!("output-{workers}-{index}"));
                    assert_eq!(fs::metadata(&path)?.modified()?, modified);
                    assert_eq!(&fs::read(path)?, expected);
                }
                assert_eq!(progress.snapshot().files, fixtures.len() as u64);
                assert_eq!(
                    progress.snapshot().bytes,
                    fixtures
                        .iter()
                        .map(|(_, bytes)| bytes.len() as u64)
                        .sum::<u64>()
                );
            }
        }
        Ok(())
    }

    #[test]
    fn failed_writes_release_a_full_queue_before_output_cleanup() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let ops = VaultOperations::new(temp.path(), MasterKey::random()?);
        let encrypted = temp.path().join("encrypted");
        fs::write(
            &encrypted,
            ops.cipher_combo()
                .encrypt_file(b"payload", ops.master_key())?,
        )?;
        let destination = temp.path().join("output");
        let error = crate::fsutil::new_output(&destination, || {
            let path = destination.join("readonly-handle");
            fs::write(&path, b"sentinel")?;
            let output = Arc::new(Output {
                file: Mutex::new(File::open(path)?), // Writes reliably fail without filling the disk.
                source: encrypted.clone(),
                metadata: fs::metadata(&encrypted)?,
                size: 7,
                pending: AtomicUsize::new(21),
                progress: crate::Progress::default(),
            });
            with_workers(&ops, &crate::Progress::default(), 2, |pool| {
                for _ in 0..20 {
                    pool.submit(Batch {
                        output: Arc::clone(&output),
                        offset: 0,
                        reader: None,
                    })?;
                }
                Ok(())
            })
        })
        .unwrap_err();
        assert!(
            error.downcast_ref::<std::io::Error>().is_some(),
            "{error:#}"
        );
        assert!(error.to_string().contains("Cannot decrypt encrypted file"));
        assert!(!destination.exists());
        Ok(())
    }
}
