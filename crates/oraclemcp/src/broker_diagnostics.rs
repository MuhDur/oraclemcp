//! Bounded local diagnostics for a detached broker, independent of client pipes.

use cap_fs_ext::{FollowSymlinks, MetadataExt as _, OpenOptionsFollowExt as _};
use cap_std::fs::{Dir, File, OpenOptions};
use oraclemcp_error::{ErrorClass, ErrorEnvelope};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, SyncSender};

const FILE_BYTES: usize = 512 * 1024;
const FILE_COUNT: usize = 3;
const EVENT_BYTES: usize = 16 * 1024;
const QUEUED_EVENTS: usize = 64;
/// Private record of the last failure before a broker started serving. Its
/// stdio is `/dev/null`, so this is how the spawning client learns why.
pub(super) const STARTUP_ERROR_FILE: &str = "broker-startup-error.json";
const STARTUP_RECORD_BYTES: u64 = 64 * 1024;

/// Why the private diagnostics ring could not be opened.
#[derive(Debug)]
pub(super) enum OpenError {
    /// A pre-existing slot is readable or writable by group or others.
    NotPrivate {
        path: PathBuf,
        mode: u32,
    },
    /// A slot is a hard link or not a regular file.
    NotLoneRegularFile {
        path: PathBuf,
    },
    Io(io::Error),
}

impl From<io::Error> for OpenError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotPrivate { path, mode } => write!(
                f,
                "diagnostic sink {} must be private (0600), found {mode:04o}",
                path.display()
            ),
            Self::NotLoneRegularFile { path } => write!(
                f,
                "diagnostic sink {} must be a lone regular file",
                path.display()
            ),
            Self::Io(error) => error.fmt(f),
        }
    }
}

impl OpenError {
    /// The typed, actionable refusal a broker reports for this sink.
    pub(super) fn into_envelope(self) -> ErrorEnvelope {
        match self {
            Self::NotPrivate { path, mode } => ErrorEnvelope::new(
                ErrorClass::RuntimeStateRequired,
                format!(
                    "ORACLEMCP_BROKER_DIAGNOSTICS_NOT_PRIVATE: broker diagnostics file {} has mode {mode:04o}; \
                     the broker writes diagnostics only to a private 0600 file and was not started",
                    path.display()
                ),
            )
            .with_next_step(format!(
                "run `chmod 600 {}` (or remove the file), then reconnect",
                path.display()
            )),
            Self::NotLoneRegularFile { path } => ErrorEnvelope::new(
                ErrorClass::RuntimeStateRequired,
                format!(
                    "ORACLEMCP_BROKER_DIAGNOSTICS_UNSAFE: broker diagnostics file {} is a hard link or not a regular file; \
                     the broker was not started",
                    path.display()
                ),
            )
            .with_next_step(format!(
                "remove {} and reconnect; the broker recreates it privately",
                path.display()
            )),
            Self::Io(error) => ErrorEnvelope::new(
                ErrorClass::Internal,
                format!("cannot open broker diagnostics: {error}"),
            ),
        }
    }
}

/// Create-or-open without following links. Never truncates on open: an unsafe
/// pre-existing file must be refused unmodified.
fn private_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options
}

/// Authenticate an opened sink file: a lone regular file, private on Unix.
fn check_private(file: &File, path: PathBuf) -> Result<(), OpenError> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(OpenError::NotLoneRegularFile { path });
    }
    #[cfg(unix)]
    {
        use cap_std::fs::PermissionsExt as _;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(OpenError::NotPrivate { path, mode });
        }
    }
    Ok(())
}

/// Record why this broker process failed before serving. Best effort: the
/// record is written only to a private lone regular file, never through a link.
pub(super) fn record_startup_failure(root: &Path, error: &ErrorEnvelope) -> Result<(), OpenError> {
    let directory = Dir::open_ambient_dir(root, cap_std::ambient_authority())?;
    // Open without truncating so an unsafe pre-existing file is never modified.
    let mut file = directory.open_with(STARTUP_ERROR_FILE, &private_options())?;
    check_private(&file, root.join(STARTUP_ERROR_FILE))?;
    let record = serde_json::json!({"pid": std::process::id(), "error": error});
    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;
    serde_json::to_writer(&mut file, &record).map_err(io::Error::other)?;
    file.write_all(b"\n")?;
    Ok(())
}

/// Forget an earlier failure once a broker has started serving, so neither a
/// later client nor doctor reports it as current.
pub(super) fn clear_startup_failure(root: &Path) -> Result<(), OpenError> {
    let directory = Dir::open_ambient_dir(root, cap_std::ambient_authority())?;
    let file = match directory.open_with(STARTUP_ERROR_FILE, &{
        let mut options = OpenOptions::new();
        options.read(true).write(true).follow(FollowSymlinks::No);
        options
    }) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    check_private(&file, root.join(STARTUP_ERROR_FILE))?;
    file.set_len(0)?;
    Ok(())
}

/// The typed startup failure recorded by broker process `pid`, if any.
pub(super) fn startup_failure_for(root: &Path, pid: u32) -> Option<ErrorEnvelope> {
    let directory = Dir::open_ambient_dir(root, cap_std::ambient_authority()).ok()?;
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let file = directory.open_with(STARTUP_ERROR_FILE, &options).ok()?;
    check_private(&file, root.join(STARTUP_ERROR_FILE)).ok()?;
    let mut text = String::new();
    file.take(STARTUP_RECORD_BYTES)
        .read_to_string(&mut text)
        .ok()?;
    let record: serde_json::Value = serde_json::from_str(&text).ok()?;
    if record.get("pid")?.as_u64()? != u64::from(pid) {
        return None;
    }
    serde_json::from_value(record.get("error")?.clone()).ok()
}

#[derive(Clone)]
pub(super) struct Diagnostics {
    sender: SyncSender<Vec<u8>>,
    dropped: Arc<AtomicU64>,
}

impl Diagnostics {
    pub fn open(root: &Path) -> Result<Self, OpenError> {
        let directory = Dir::open_ambient_dir(root, cap_std::ambient_authority())?;
        let mut files = Vec::new();
        for index in 0..FILE_COUNT {
            let name = format!("broker-diagnostics.{index}.jsonl");
            let file = directory.open_with(&name, &private_options())?;
            check_private(&file, root.join(&name))?;
            files.push(file);
        }
        let ring = Ring {
            files,
            index: 0,
            bytes: 0,
        };
        let (sender, receiver) = mpsc::sync_channel::<Vec<u8>>(QUEUED_EVENTS);
        let dropped = Arc::new(AtomicU64::new(0));
        let lost = dropped.clone();
        std::thread::Builder::new().name("broker-diagnostics".into()).spawn(move || {
            let mut ring = ring;
            // Reusing a slot only truncates the descriptor authenticated above.
            // No rename/unlink or mutable-path reopen is needed during rotation.
            if ring.clear_current().is_err() { return; }
            while let Ok(event) = receiver.recv() {
                let count = lost.swap(0, Ordering::Relaxed);
                if count > 0 {
                    let notice = format!("{{\"level\":\"WARN\",\"fields\":{{\"message\":\"broker diagnostics dropped\",\"events\":{count}}}}}\n");
                    if ring.write(notice.as_bytes()).is_err() { return; }
                }
                if ring.write(&event).is_err() { return; }
            }
        })?;
        Ok(Self { sender, dropped })
    }
}

struct Ring {
    files: Vec<File>,
    index: usize,
    bytes: usize,
}
impl Ring {
    fn clear_current(&mut self) -> io::Result<()> {
        self.files[self.index].set_len(0)?;
        self.files[self.index].seek(SeekFrom::Start(0))?;
        self.bytes = 0;
        Ok(())
    }
    fn write(&mut self, event: &[u8]) -> io::Result<()> {
        if self.bytes + event.len() > FILE_BYTES {
            self.index = (self.index + 1) % FILE_COUNT;
            self.clear_current()?;
        }
        self.files[self.index].write_all(event)?;
        self.bytes += event.len();
        Ok(())
    }
}

pub(super) struct EventWriter {
    sink: Diagnostics,
    event: Vec<u8>,
    oversized: bool,
}
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Diagnostics {
    type Writer = EventWriter;
    fn make_writer(&'a self) -> Self::Writer {
        EventWriter {
            sink: self.clone(),
            event: Vec::new(),
            oversized: false,
        }
    }
}
impl Write for EventWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.event.len().saturating_add(bytes.len()) > EVENT_BYTES {
            self.oversized = true;
            self.event.clear();
        } else if !self.oversized {
            self.event.extend_from_slice(bytes);
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.oversized {
            self.sink.dropped.fetch_add(1, Ordering::Relaxed);
            self.oversized = false;
        } else if !self.event.is_empty()
            && self
                .sink
                .sender
                .try_send(std::mem::take(&mut self.event))
                .is_err()
        {
            self.sink.dropped.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }
}
impl Drop for EventWriter {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::fmt::MakeWriter as _;

    #[test]
    fn a_stalled_sink_never_blocks_producers_and_caps_events() {
        let (sender, _unread) = mpsc::sync_channel(1);
        let sink = Diagnostics {
            sender,
            dropped: Arc::new(AtomicU64::new(0)),
        };
        let started = std::time::Instant::now();
        for _ in 0..1024 {
            let mut writer = sink.make_writer();
            writer.write_all(&[b'x'; EVENT_BYTES]).unwrap();
        }
        let mut oversized = sink.make_writer();
        oversized.write_all(&vec![b'x'; EVENT_BYTES + 1]).unwrap();
        assert!(oversized.event.is_empty());
        oversized.flush().unwrap();
        assert_eq!(sink.dropped.load(Ordering::Relaxed), 1024);
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }

    #[test]
    fn rotation_is_bounded_and_preserves_complete_events() {
        let root = tempfile::tempdir().unwrap();
        let directory = Dir::open_ambient_dir(root.path(), cap_std::ambient_authority()).unwrap();
        let files = (0..FILE_COUNT)
            .map(|i| directory.create(format!("slot-{i}")).unwrap())
            .collect();
        let mut ring = Ring {
            files,
            index: 0,
            bytes: 0,
        };
        let line = format!("{{\"message\":\"{}\"}}\n", "x".repeat(4000));
        for _ in 0..1000 {
            ring.write(line.as_bytes()).unwrap();
        }
        for file in &ring.files {
            assert!(file.metadata().unwrap().len() <= FILE_BYTES as u64);
        }
        for entry in std::fs::read_dir(root.path()).unwrap() {
            for event in std::fs::read_to_string(entry.unwrap().path())
                .unwrap()
                .lines()
            {
                serde_json::from_str::<serde_json::Value>(event).unwrap();
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn wide_mode_sink_is_a_typed_actionable_refusal_and_is_left_unchanged() {
        use std::os::unix::fs::PermissionsExt as _;
        let root = tempfile::tempdir().unwrap();
        let wide = root.path().join("broker-diagnostics.1.jsonl");
        std::fs::write(&wide, "earlier event\n").unwrap();
        std::fs::set_permissions(&wide, std::fs::Permissions::from_mode(0o644)).unwrap();
        let Err(error) = Diagnostics::open(root.path()) else {
            panic!("a group/other-readable sink must be refused");
        };
        assert!(
            matches!(&error, OpenError::NotPrivate { path, mode } if path == &wide && *mode == 0o644),
            "{error:?}"
        );
        let envelope = error.into_envelope();
        assert_eq!(envelope.error_class, ErrorClass::RuntimeStateRequired);
        assert!(
            envelope
                .message
                .starts_with("ORACLEMCP_BROKER_DIAGNOSTICS_NOT_PRIVATE:"),
            "{}",
            envelope.message
        );
        assert!(envelope.message.contains(&wide.display().to_string()));
        assert!(envelope.message.contains("0644"));
        assert_eq!(
            envelope.next_steps,
            [format!(
                "run `chmod 600 {}` (or remove the file), then reconnect",
                wide.display()
            )]
        );
        assert_eq!(std::fs::read_to_string(&wide).unwrap(), "earlier event\n");
        let mode = std::fs::metadata(&wide).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644, "refusal must not silently chmod the file");
    }

    #[cfg(unix)]
    #[test]
    fn startup_failure_record_is_private_pid_bound_and_clearable() {
        use std::os::unix::fs::PermissionsExt as _;
        let root = tempfile::tempdir().unwrap();
        let error = ErrorEnvelope::new(ErrorClass::InvalidArguments, "synthetic startup failure")
            .with_next_step("fix the synthetic cause");
        assert_eq!(startup_failure_for(root.path(), std::process::id()), None);
        record_startup_failure(root.path(), &error).unwrap();
        let path = root.path().join(STARTUP_ERROR_FILE);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(
            startup_failure_for(root.path(), std::process::id()),
            Some(error.clone())
        );
        // Another process's (stale) record is never reported for this child.
        assert_eq!(
            startup_failure_for(root.path(), std::process::id() + 1),
            None
        );
        clear_startup_failure(root.path()).unwrap();
        assert_eq!(startup_failure_for(root.path(), std::process::id()), None);

        // The record follows the sink's rules: no link is ever written through.
        let linked = tempfile::tempdir().unwrap();
        let victim = linked.path().join("victim");
        std::fs::write(&victim, "unchanged").unwrap();
        std::os::unix::fs::symlink(&victim, linked.path().join(STARTUP_ERROR_FILE)).unwrap();
        assert!(record_startup_failure(linked.path(), &error).is_err());
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "unchanged");
    }

    #[cfg(unix)]
    #[test]
    fn diagnostic_sink_refuses_links_and_never_writes_the_victim() {
        let root = tempfile::tempdir().unwrap();
        let victim = root.path().join("victim");
        std::fs::write(&victim, "unchanged").unwrap();
        std::os::unix::fs::symlink(&victim, root.path().join("broker-diagnostics.0.jsonl"))
            .unwrap();
        assert!(Diagnostics::open(root.path()).is_err());
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "unchanged");
        let second = tempfile::tempdir().unwrap();
        std::fs::hard_link(&victim, second.path().join("broker-diagnostics.0.jsonl")).unwrap();
        assert!(Diagnostics::open(second.path()).is_err());
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "unchanged");
    }
}
