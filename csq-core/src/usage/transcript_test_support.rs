//! Test-only observations of actual transcript reads and deserialize attempts.
//! No paths, bytes or transcript content are retained. Scoped to the calling thread.
use std::cell::Cell;
use std::fs::{File, Metadata};
use std::io::{Read, Seek, SeekFrom};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    pub read_calls: usize,
    pub read_bytes: usize,
    pub parses: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CacheObservation {
    pub files: usize,
    pub seen: usize,
    pub records: usize,
    pub payload_bytes: usize,
    pub file_limit: usize,
}

std::thread_local! {
    static ACTIVE: Cell<Option<Counts>> = const { Cell::new(None) };
}

/// Real reads/parses in this thread only. Nested scopes restore the prior scope;
/// unwind also restores it. Reference aggregation should run outside this scope.
pub fn observe<T>(operation: impl FnOnce() -> T) -> (T, Counts) {
    struct Restore(Option<Counts>);
    impl Drop for Restore {
        fn drop(&mut self) {
            ACTIVE.with(|slot| slot.set(self.0));
        }
    }
    let previous = ACTIVE.with(|slot| slot.replace(Some(Counts::default())));
    let _restore = Restore(previous);
    let result = operation();
    let counts = ACTIVE.with(|slot| slot.get().expect("active transcript observation"));
    (result, counts)
}

pub(super) fn note_parse() {
    ACTIVE.with(|slot| {
        if let Some(mut counts) = slot.get() {
            counts.parses += 1;
            slot.set(Some(counts));
        }
    });
}

pub(super) struct TranscriptFile(File);
impl From<File> for TranscriptFile {
    fn from(file: File) -> Self {
        Self(file)
    }
}
impl TranscriptFile {
    pub(super) fn metadata(&self) -> std::io::Result<Metadata> {
        self.0.metadata()
    }
}
impl Read for TranscriptFile {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let result = self.0.read(buffer);
        ACTIVE.with(|slot| {
            if let Some(mut counts) = slot.get() {
                counts.read_calls += 1;
                counts.read_bytes += result.as_ref().copied().unwrap_or(0);
                slot.set(Some(counts));
            }
        });
        result
    }
}
impl Seek for TranscriptFile {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        self.0.seek(position)
    }
}
