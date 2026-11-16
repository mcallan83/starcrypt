//! Bounded chunk scheduling shared by all files in a vault creation.
use crate::fsutil::copy_times;
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{AeadInPlace, KeyInit, OsRng, rand_core::RngCore},
};
use anyhow::{Context, Result, anyhow, ensure};
use oxcrypt_core::vault::operations::VaultOperations;
use std::{
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    thread,
};
use zeroize::Zeroizing;

const CHUNK_SIZE: usize = 32 * 1024;
// Amortize queue and output-lock overhead across 32 format chunks.
const BATCH_SIZE: usize = 1024 * 1024;

// Ignore access time: our own reads may change it.
fn validate_source(expected: &fs::Metadata, actual: &fs::Metadata) -> Result<()> {
    ensure!(
        actual.is_file()
            && expected.len() == actual.len()
            && expected.modified()? == actual.modified()?,
        "Source file changed during encryption"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            expected.dev() == actual.dev()
                && expected.ino() == actual.ino()
                && expected.ctime() == actual.ctime()
                && expected.ctime_nsec() == actual.ctime_nsec(),
            "Source file changed during encryption"
        );
    }
    Ok(())
}

fn read_batch(input: &mut impl Read, capacity: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut plaintext = Zeroizing::new(vec![0u8; capacity]);
    let mut count = 0;
    while count < plaintext.len() {
        match input.read(&mut plaintext[count..]) {
            Ok(0) => break,
            Ok(n) => count += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    plaintext.truncate(count);
    Ok(plaintext)
}

struct Output {
    file: Mutex<File>,
    key: Zeroizing<[u8; 32]>,
    header_nonce: [u8; 12],
    path: PathBuf,
    source: PathBuf,
    metadata: fs::Metadata,
    // Includes a producer reference until all batches have been submitted.
    pending: AtomicUsize,
    progress: crate::Progress,
}
impl Output {
    fn complete(&self) -> Result<()> {
        if self.pending.fetch_sub(1, Ordering::AcqRel) == 1 {
            copy_times(&self.path, &self.metadata)?;
            self.progress.advance(0, 1);
        }
        Ok(())
    }
}
struct Batch {
    output: Arc<Output>,
    first_chunk: u64,
    plaintext: Zeroizing<Vec<u8>>,
}
impl Batch {
    fn encrypt(self) -> Result<()> {
        let cipher = Aes256Gcm::new_from_slice(&*self.output.key)
            .map_err(|_| anyhow!("Invalid content key"))?;
        let chunks = self.plaintext.len().div_ceil(CHUNK_SIZE);
        // Fill all chunk nonces in one OS call; every nonce is still random.
        let mut nonces = vec![0u8; chunks * 12];
        OsRng.fill_bytes(&mut nonces);
        // This buffer briefly contains plaintext before in-place encryption.
        // Clear it on errors as well as success.
        let mut ciphertext = Zeroizing::new(Vec::with_capacity(self.plaintext.len() + chunks * 28));
        for (index, (chunk, nonce)) in self
            .plaintext
            .chunks(CHUNK_SIZE)
            .zip(nonces.as_chunks::<12>().0)
            .enumerate()
        {
            let mut aad = [0u8; 20];
            aad[..8].copy_from_slice(&(self.first_chunk + index as u64).to_be_bytes());
            aad[8..].copy_from_slice(&self.output.header_nonce);
            ciphertext.extend_from_slice(nonce);
            let start = ciphertext.len();
            ciphertext.extend_from_slice(chunk);
            let tag = cipher
                .encrypt_in_place_detached(Nonce::from_slice(nonce), &aad, &mut ciphertext[start..])
                .map_err(|_| anyhow!("Chunk encryption failed"))?;
            ciphertext.extend_from_slice(&tag);
        }
        {
            // Batches may finish out of order. Position each batch explicitly;
            // the lock keeps seek+write atomic on every supported platform.
            let mut file = self
                .output
                .file
                .lock()
                .map_err(|_| anyhow!("Output lock poisoned"))?;
            file.seek(SeekFrom::Start(
                68 + self.first_chunk * (CHUNK_SIZE as u64 + 28),
            ))?;
            file.write_all(&ciphertext)?;
        }
        self.output.progress.advance(self.plaintext.len() as u64, 0);
        self.output.complete()
    }
}

pub(crate) struct EncryptionPool {
    sender: mpsc::SyncSender<Batch>,
    progress: crate::Progress,
}
impl EncryptionPool {
    pub(crate) fn encrypt_file(
        &self,
        ops: &VaultOperations,
        source: &Path,
        encrypted: &Path,
        metadata: fs::Metadata,
    ) -> Result<()> {
        let result = (|| -> Result<()> {
            let mut input = File::open(source)?;
            validate_source(&metadata, &input.metadata()?)?;
            let mut key = Zeroizing::new([0u8; 32]);
            OsRng.fill_bytes(&mut *key);
            let header = oxcrypt_core::fs::file::encrypt_file_header(&key, ops.master_key())?;
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(encrypted)?;
            file.write_all(&header)?;
            // Every non-final batch must end on a format chunk boundary, even
            // if the source grows after its metadata was collected.
            let read_size = (metadata.len().min(BATCH_SIZE as u64) as usize)
                .max(1)
                .next_multiple_of(CHUNK_SIZE);
            let output = Arc::new(Output {
                file: Mutex::new(file),
                key,
                header_nonce: header[..12].try_into()?,
                path: encrypted.to_owned(),
                source: source.to_owned(),
                metadata,
                pending: AtomicUsize::new(1),
                progress: self.progress.clone(),
            });
            let mut first_chunk = 0;
            let mut bytes_read = 0u64;
            loop {
                let plaintext = read_batch(&mut input, read_size)?;
                let count = plaintext.len();
                if count == 0 {
                    break;
                }
                bytes_read += count as u64;
                output.pending.fetch_add(1, Ordering::Relaxed);
                self.sender
                    .send(Batch {
                        output: Arc::clone(&output),
                        first_chunk,
                        plaintext,
                    })
                    .map_err(|_| anyhow!("Encryption workers stopped"))?;
                first_chunk += count.div_ceil(CHUNK_SIZE) as u64;
                // A short batch reached EOF. Never resume after publishing a
                // partial chunk, even if another process subsequently appends.
                if count < read_size {
                    break;
                }
            }
            ensure!(
                bytes_read == output.metadata.len(),
                "Source file changed during encryption"
            );
            validate_source(&output.metadata, &input.metadata()?)?;
            validate_source(&output.metadata, &fs::metadata(source)?)?;
            // Empty files retain only the authenticated header.
            output.complete()
        })();
        result.with_context(|| format!("Cannot encrypt source file {}", source.display()))
    }
}

pub(crate) fn with_pool(
    progress: &crate::Progress,
    work: impl FnOnce(&EncryptionPool) -> Result<()>,
) -> Result<()> {
    let workers = thread::available_parallelism().map_or(1, usize::from);
    with_workers_progress(workers, progress, work)
}

fn with_workers_progress(
    workers: usize,
    progress: &crate::Progress,
    work: impl FnOnce(&EncryptionPool) -> Result<()>,
) -> Result<()> {
    let (sender, receiver) = mpsc::sync_channel::<Batch>(workers);
    let receiver = Arc::new(Mutex::new(receiver));
    thread::scope(|scope| {
        let mut handles = Vec::new();
        for _ in 0..workers {
            let receiver = Arc::clone(&receiver);
            handles.push(scope.spawn(move || -> Result<()> {
                let mut result = Ok(());
                loop {
                    let batch = receiver
                        .lock()
                        .map_err(|_| anyhow!("Work queue poisoned"))?
                        .recv();
                    let Ok(batch) = batch else { return result };
                    // Drain after an error so a producer blocked on the bounded
                    // queue can finish and all workers join before cleanup.
                    if result.is_ok() {
                        let output = Arc::clone(&batch.output);
                        result = batch.encrypt().with_context(|| {
                            format!("Cannot encrypt source file {}", output.source.display())
                        });
                    }
                }
            }));
        }
        drop(receiver);
        let pool = EncryptionPool {
            sender,
            progress: progress.clone(),
        };
        let mut result = work(&pool);
        drop(pool);
        for handle in handles {
            let worker = handle
                .join()
                .unwrap_or_else(|_| Err(anyhow!("Encryption worker panicked")));
            if result.is_ok() {
                result = worker;
            }
        }
        result
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxcrypt_core::{crypto::keys::MasterKey, vault::path::DirId};

    fn with_workers(
        workers: usize,
        work: impl FnOnce(&EncryptionPool) -> Result<()>,
    ) -> Result<()> {
        with_workers_progress(workers, &crate::Progress::default(), work)
    }

    #[test]
    fn changed_source_size_is_rejected_before_creating_ciphertext() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let ops = VaultOperations::new(temp.path(), MasterKey::random()?);
        let source = temp.path().join("source");
        let destination = temp.path().join("encrypted");
        for (before, after) in [
            (0, 1),
            (1, 2), // Previously succeeded with corrupt ciphertext.
            (CHUNK_SIZE - 1, CHUNK_SIZE + 1),
            (CHUNK_SIZE + 1, 2 * CHUNK_SIZE + 1),
            (BATCH_SIZE - 1, BATCH_SIZE + 1),
            (2, 1),
            (CHUNK_SIZE + 1, 0),
        ] {
            fs::write(&source, vec![7; before])?;
            let metadata = fs::metadata(&source)?;
            fs::write(&source, vec![8; after])?;
            let error = with_workers(2, |pool| {
                pool.encrypt_file(&ops, &source, &destination, metadata)
            })
            .unwrap_err();
            assert!(format!("{error:#}").contains("Source file changed during encryption"));
            assert!(error.to_string().contains(&source.display().to_string()));
            assert!(!destination.exists());
        }
        Ok(())
    }

    #[test]
    fn source_validation_detects_changes_after_reading() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let source = temp.path().join("source");
        fs::write(&source, b"a")?;
        let mut input = File::open(&source)?;
        let metadata = input.metadata()?;
        assert_eq!(&**read_batch(&mut input, CHUNK_SIZE)?, b"a");
        fs::OpenOptions::new()
            .append(true)
            .open(&source)?
            .write_all(b"b")?;
        assert!(validate_source(&metadata, &input.metadata()?).is_err());

        let metadata = input.metadata()?;
        fs::write(&source, b"cd")?;
        input.set_times(
            fs::FileTimes::new()
                .set_modified(metadata.modified()? + std::time::Duration::from_secs(1)),
        )?;
        assert!(validate_source(&metadata, &input.metadata()?).is_err());

        #[cfg(unix)]
        {
            let metadata = input.metadata()?;
            let replacement = temp.path().join("replacement");
            fs::write(&replacement, b"ef")?;
            File::open(&replacement)?
                .set_times(fs::FileTimes::new().set_modified(metadata.modified()?))?;
            fs::rename(replacement, &source)?;
            assert!(validate_source(&metadata, &fs::metadata(&source)?).is_err());
        }
        Ok(())
    }

    #[test]
    fn batch_reads_fill_chunks_across_short_reads_and_interruptions() -> Result<()> {
        struct ShortReader {
            bytes: std::io::Cursor<Vec<u8>>,
            interrupt: bool,
        }
        impl Read for ShortReader {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                self.interrupt = !self.interrupt;
                if self.interrupt {
                    return Err(std::io::ErrorKind::Interrupted.into());
                }
                let count = buffer.len().min(17);
                self.bytes.read(&mut buffer[..count])
            }
        }
        let bytes = vec![42; CHUNK_SIZE + 1];
        let mut input = ShortReader {
            bytes: std::io::Cursor::new(bytes.clone()),
            interrupt: false,
        };
        assert_eq!(&**read_batch(&mut input, CHUNK_SIZE)?, &bytes[..CHUNK_SIZE]);
        assert_eq!(&**read_batch(&mut input, CHUNK_SIZE)?, &bytes[CHUNK_SIZE..]);
        assert!(read_batch(&mut input, CHUNK_SIZE)?.is_empty());
        Ok(())
    }

    #[test]
    fn existing_ciphertext_is_never_overwritten() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let ops = VaultOperations::new(temp.path(), MasterKey::random()?);
        let source = temp.path().join("source");
        let destination = temp.path().join("existing");
        fs::write(&source, b"source bytes")?;
        fs::write(&destination, b"keep existing ciphertext")?;
        let result = with_workers(1, |pool| {
            pool.encrypt_file(&ops, &source, &destination, fs::metadata(&source)?)
        });
        assert!(result.is_err());
        assert_eq!(fs::read(&destination)?, b"keep existing ciphertext");
        assert_eq!(fs::read(&source)?, b"source bytes");
        Ok(())
    }

    #[test]
    fn one_file_spans_many_parallel_batches() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let ops = VaultOperations::new(temp.path(), MasterKey::random()?);
        let source = temp.path().join("source");
        let bytes = (0..(8 * BATCH_SIZE + 19))
            .map(|n| (n % 251) as u8)
            .collect::<Vec<_>>();
        fs::write(&source, &bytes)?;
        let metadata = fs::metadata(&source)?;
        let modified = metadata.modified()?;
        let path = ops.write_file(&DirId::root(), "large", &[])?;
        fs::remove_file(&path)?;
        with_workers(4, |pool| pool.encrypt_file(&ops, &source, &path, metadata))?;
        assert_eq!(fs::metadata(&path)?.modified()?, modified);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
        }
        assert_eq!(ops.read_file(&DirId::root(), "large")?.content, bytes);
        assert_eq!(
            fs::metadata(&path)?.len(),
            68 + bytes.len() as u64 + bytes.len().div_ceil(CHUNK_SIZE) as u64 * 28
        );
        Ok(())
    }

    #[test]
    fn failed_workers_drain_a_full_queue() -> Result<()> {
        // A read-only output handle forces writes to fail. More jobs than
        // queue slots verifies errors cannot strand the producer.
        let temp = tempfile::tempdir()?;
        let source = temp.path().join("source");
        fs::write(&source, b"data")?;
        let output = Arc::new(Output {
            file: Mutex::new(File::open(&source)?),
            key: Zeroizing::new([1u8; 32]),
            header_nonce: [2; 12],
            path: temp.path().join("unused"),
            source: source.clone(),
            metadata: fs::metadata(&source)?,
            pending: AtomicUsize::new(100),
            progress: crate::Progress::default(),
        });
        let result = with_workers(2, |pool| {
            for index in 0..20 {
                pool.sender
                    .send(Batch {
                        output: Arc::clone(&output),
                        first_chunk: index,
                        plaintext: Zeroizing::new(vec![3; CHUNK_SIZE]),
                    })
                    .map_err(|_| anyhow!("Workers stopped"))?;
            }
            Ok(())
        });
        assert!(result.is_err());
        Ok(())
    }
}
