//! Terminal progress rendering and plain-text status formatting.
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use starcrypt::ProgressSnapshot;
use std::{
    io::{self, Write},
    time::Duration,
};

pub(crate) fn line(
    snapshot: &ProgressSnapshot,
    finished: Option<bool>,
    elapsed: Duration,
) -> String {
    let phase = match finished {
        Some(true) => "Completed",
        Some(false) => "Failed",
        None => snapshot.phase,
    };
    let count = number(snapshot.files);
    let elapsed = duration(elapsed);
    if finished == Some(true) {
        return format!("Completed  100.0%  {count} files  {elapsed}");
    }
    match (snapshot.total_bytes, snapshot.total_files) {
        (Some(total), Some(files)) => {
            let ratio = if total > 0 {
                snapshot.bytes as f64 / total as f64
            } else if files > 0 {
                snapshot.files as f64 / files as f64
            } else {
                0.0
            };
            // Finishing timestamps or packaging an archive is still work.
            let percent = (ratio * 100.0).clamp(0.0, 99.9);
            format!(
                "{phase}  {percent:.1}%  {count}/{} files  {elapsed}",
                number(files)
            )
        }
        _ => format!("{phase}  {count} files  {elapsed}"),
    }
}

fn number(value: u64) -> String {
    let digits = value.to_string();
    let mut result = String::new();
    for (index, ch) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            result.push(',');
        }
        result.push(ch);
    }
    result
}

fn duration(elapsed: Duration) -> String {
    let seconds = elapsed.as_secs();
    match seconds {
        0..60 => format!("{seconds}s"),
        60..3600 => format!("{}m {:02}s", seconds / 60, seconds % 60),
        _ => format!(
            "{}h {:02}m {:02}s",
            seconds / 3600,
            seconds / 60 % 60,
            seconds % 60
        ),
    }
}

pub(crate) struct Display {
    bar: ProgressBar,
    bounded: bool,
}
impl Display {
    pub(crate) fn new() -> Self {
        let bar = ProgressBar::with_draw_target(None, ProgressDrawTarget::stderr_with_hz(10));
        bar.set_style(Self::style(false));
        Self {
            bar,
            bounded: false,
        }
    }

    fn style(bounded: bool) -> ProgressStyle {
        ProgressStyle::with_template(if bounded {
            "{spinner} [{bar:12.cyan/blue}] {msg}"
        } else {
            "{spinner} {msg}"
        })
        .expect("valid progress template")
        .progress_chars("=> ")
    }

    pub(crate) fn render(
        &mut self,
        snapshot: &ProgressSnapshot,
        status: String,
        messages: Vec<String>,
        finished: Option<bool>,
    ) {
        // Scanning and archive packaging have no measurable byte progress.
        let bounded =
            snapshot.total_bytes.is_some() && matches!(snapshot.phase, "Encrypting" | "Decrypting");
        if bounded != self.bounded {
            self.bar.set_style(Self::style(bounded));
            self.bounded = bounded;
        }
        if bounded {
            let (done, total) = match snapshot.total_bytes {
                Some(total) if total > 0 => (snapshot.bytes, total),
                _ => (snapshot.files, snapshot.total_files.unwrap_or(0)),
            };
            self.bar.set_length(total.max(1));
            self.bar.set_position(done.min(total));
        }
        // Write permanent lines normally, without indicatif's terminal-width padding.
        // Suspend clears the live bar and restores it after the messages.
        if !messages.is_empty() {
            self.bar.suspend(|| {
                let mut stderr = io::stderr().lock();
                for message in messages {
                    let _ = writeln!(stderr, "{}", escape_message(&message));
                }
                let _ = stderr.flush();
            });
        }
        if finished.is_some() {
            self.bar.finish_and_clear();
            let _ = writeln!(io::stderr().lock(), "{status}");
        } else {
            self.bar.set_message(status);
            self.bar.tick();
        }
    }
}

fn escape_message(message: &str) -> String {
    use std::fmt::Write;
    let mut escaped = String::with_capacity(message.len());
    for ch in message.chars() {
        if ch.is_control() {
            write!(escaped, "{}", ch.escape_default()).expect("writing to a String cannot fail");
        } else {
            escaped.push(ch);
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn progress_uses_bytes_and_waits_for_success() {
        let mut snapshot = ProgressSnapshot {
            phase: "Encrypting",
            bytes: 25,
            files: 1,
            total_bytes: Some(100),
            total_files: Some(2),
        };
        assert!(line(&snapshot, None, Duration::ZERO).contains("25.0%"));
        snapshot.bytes = 100;
        assert!(line(&snapshot, None, Duration::ZERO).contains("99.9%"));
        assert!(line(&snapshot, Some(false), Duration::ZERO).contains("99.9%"));
        assert!(line(&snapshot, Some(true), Duration::ZERO).contains("100.0%"));
        snapshot.total_bytes = Some(0);
        assert!(line(&snapshot, None, Duration::ZERO).contains("50.0%"));
        snapshot.total_files = Some(0);
        assert!(line(&snapshot, None, Duration::ZERO).contains("0.0%"));
    }
    #[test]
    fn messages_preserve_paths_and_escape_controls() {
        assert_eq!(
            escape_message("Skipping: 日本語/path"),
            "Skipping: 日本語/path"
        );
        assert_eq!(escape_message("bad\x1b[31m\n"), "bad\\u{1b}[31m\\n");
    }
}
