//! Bounded local diagnostics for a detached broker, independent of client pipes.

use cap_fs_ext::{FollowSymlinks, MetadataExt as _, OpenOptionsFollowExt as _};
use cap_std::fs::{Dir, File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, SyncSender};

const FILE_BYTES: usize = 512 * 1024;
const FILE_COUNT: usize = 3;
const EVENT_BYTES: usize = 16 * 1024;
const QUEUED_EVENTS: usize = 64;

#[derive(Clone)]
pub(super) struct Diagnostics {
    sender: SyncSender<Vec<u8>>,
    dropped: Arc<AtomicU64>,
}

impl Diagnostics {
    pub fn open(root: &Path) -> io::Result<Self> {
        let directory = Dir::open_ambient_dir(root, cap_std::ambient_authority())?;
        let mut files = Vec::new();
        for index in 0..FILE_COUNT {
            let mut options = OpenOptions::new();
            options
                .read(true)
                .write(true)
                .create(true)
                .follow(FollowSymlinks::No);
            #[cfg(unix)]
            {
                use cap_std::fs::OpenOptionsExt as _;
                options.mode(0o600);
            }
            let file =
                directory.open_with(format!("broker-diagnostics.{index}.jsonl"), &options)?;
            let metadata = file.metadata()?;
            if !metadata.is_file() || metadata.nlink() != 1 {
                return Err(io::Error::other(
                    "diagnostic sink must be a lone regular file",
                ));
            }
            #[cfg(unix)]
            {
                use cap_std::fs::PermissionsExt as _;
                if metadata.permissions().mode() & 0o077 != 0 {
                    return Err(io::Error::other("diagnostic sink must be private (0600)"));
                }
            }
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
