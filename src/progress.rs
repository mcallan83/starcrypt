//! Shared counters for optional operation progress reporting.
use std::sync::{Arc, Mutex};

/// A thread-safe progress handle. Library operations do not print progress.
#[derive(Clone, Default)]
pub struct Progress {
    state: Arc<Mutex<State>>,
    buffered_messages: bool,
}
#[derive(Default)]
struct State {
    snapshot: ProgressSnapshot,
    messages: Vec<String>,
}

/// Counters describe completed plaintext work; archive phases report status only.
#[derive(Clone, Debug)]
pub struct ProgressSnapshot {
    pub phase: &'static str,
    pub bytes: u64,
    pub files: u64,
    /// Known after the metadata scan; excludes symlinks and skipped entries.
    pub total_bytes: Option<u64>,
    pub total_files: Option<u64>,
}
impl Default for ProgressSnapshot {
    fn default() -> Self {
        Self {
            phase: "Preparing",
            bytes: 0,
            files: 0,
            total_bytes: None,
            total_files: None,
        }
    }
}
impl Progress {
    /// Queue informational messages for a renderer instead of writing to stderr.
    pub fn with_buffered_messages() -> Self {
        Self {
            buffered_messages: true,
            ..Self::default()
        }
    }
    /// Take queued messages, leaving the queue empty.
    pub fn drain_messages(&self) -> Vec<String> {
        std::mem::take(&mut self.state.lock().unwrap().messages)
    }
    pub fn snapshot(&self) -> ProgressSnapshot {
        self.state.lock().unwrap().snapshot.clone()
    }
    pub(crate) fn message(&self, message: String) {
        if self.buffered_messages {
            self.state.lock().unwrap().messages.push(message);
        } else {
            eprintln!("{message}");
        }
    }
    pub(crate) fn phase(&self, phase: &'static str) {
        self.state.lock().unwrap().snapshot.phase = phase;
    }
    pub(crate) fn totals(&self, bytes: u64, files: u64) {
        let mut state = self.state.lock().unwrap();
        state.snapshot.total_bytes = Some(bytes);
        state.snapshot.total_files = Some(files);
    }
    pub(crate) fn advance(&self, bytes: u64, files: u64) {
        let mut state = self.state.lock().unwrap();
        state.snapshot.bytes += bytes;
        state.snapshot.files += files;
    }
}
