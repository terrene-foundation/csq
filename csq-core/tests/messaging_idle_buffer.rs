//! Allocation-lifetime regression for the real MCP request loop, not an RSS test.
//! This integration executable has its own allocator; only its fixture thread is measured.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::{Cell, RefCell};
use std::io::{self, BufRead, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use csq_core::messaging::mcp::{serve_with_lifecycle_and_image_report, Backend, MAX_LINE_BYTES};
use csq_core::sessions::directives::real_fs;
use serde_json::{json, Value};

struct MeasuredSystem;

#[global_allocator]
static ALLOCATOR: MeasuredSystem = MeasuredSystem;

// Fixed bookkeeping cannot recursively allocate. Exhaustion invalidates measurement;
// this is an instrument capacity, never an allowed number of retained request bytes.
const LEDGER_SLOTS: usize = 512;
static UNAVAILABLE: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy)]
struct Allocation {
    address: usize,
    bytes: usize,
}

const EMPTY: Allocation = Allocation {
    address: 0,
    bytes: 0,
};

struct Ledger {
    entries: [Allocation; LEDGER_SLOTS],
    allocations: usize,
    fault: bool,
}

impl Ledger {
    const fn new() -> Self {
        Self {
            entries: [EMPTY; LEDGER_SLOTS],
            allocations: 0,
            fault: false,
        }
    }

    fn remove(&mut self, address: usize) {
        // An owned fixture allocated before measurement may be freed while active.
        // It contributes nothing to this epoch, so absence is not an underflow.
        if let Some(entry) = self.entries.iter_mut().find(|e| e.address == address) {
            *entry = EMPTY;
        }
    }

    fn insert(&mut self, address: usize, bytes: usize) {
        if self.entries.iter().any(|e| e.address == address) {
            self.fault = true;
            return;
        }
        let Some(entry) = self.entries.iter_mut().find(|e| e.address == 0) else {
            self.fault = true;
            return;
        };
        *entry = Allocation { address, bytes };
        match self.allocations.checked_add(1) {
            Some(n) => self.allocations = n,
            None => self.fault = true,
        }
    }

    fn snapshot(&self) -> Snapshot {
        let mut snapshot = Snapshot {
            allocations: self.allocations,
            fault: self.fault,
            ..Snapshot::default()
        };
        for entry in self.entries.iter().filter(|e| e.address != 0) {
            snapshot.live += 1;
            match snapshot.bytes.checked_add(entry.bytes) {
                Some(bytes) => snapshot.bytes = bytes,
                None => snapshot.fault = true,
            }
        }
        snapshot
    }
}

thread_local! {
    static ACTIVE: Cell<bool> = const { Cell::new(false) };
    static LEDGER: RefCell<Ledger> = const { RefCell::new(Ledger::new()) };
}

fn record(change: impl FnOnce(&mut Ledger)) {
    if !matches!(ACTIVE.try_with(Cell::get), Ok(true)) {
        return;
    }
    if LEDGER
        .try_with(|ledger| match ledger.try_borrow_mut() {
            Ok(mut ledger) => change(&mut ledger),
            Err(_) => UNAVAILABLE.store(true, Ordering::Relaxed),
        })
        .is_err()
    {
        UNAVAILABLE.store(true, Ordering::Relaxed);
    }
}

// SAFETY: every operation delegates its original pointer/layout unchanged to System.
// Bookkeeping stores addresses as integers and never dereferences or owns them.
unsafe impl GlobalAlloc for MeasuredSystem {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller supplies the GlobalAlloc layout contract.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            record(|ledger| ledger.insert(pointer as usize, layout.size()));
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller supplies the GlobalAlloc layout contract.
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            record(|ledger| ledger.insert(pointer as usize, layout.size()));
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        record(|ledger| ledger.remove(pointer as usize));
        // SAFETY: the caller supplies this live allocation and its original layout.
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: the caller supplies the live allocation, layout and valid new size.
        let replacement = unsafe { System.realloc(pointer, layout, new_size) };
        if !replacement.is_null() {
            record(|ledger| {
                ledger.remove(pointer as usize);
                ledger.insert(replacement as usize, new_size);
            });
        }
        // Failure leaves the original allocation live, including its ledger entry.
        replacement
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct Snapshot {
    live: usize,
    bytes: usize,
    allocations: usize,
    fault: bool,
}

fn snapshot() -> Snapshot {
    LEDGER.with(|ledger| ledger.borrow().snapshot())
}

fn start_epoch() {
    // Warm both TLS cells before enabling allocator callbacks.
    ACTIVE.with(|active| active.set(false));
    LEDGER.with(|ledger| *ledger.borrow_mut() = Ledger::new());
    UNAVAILABLE.store(false, Ordering::Relaxed);
    ACTIVE.with(|active| active.set(true));
}

fn stop_epoch() {
    ACTIVE.with(|active| active.set(false));
}

fn require_available(samples: &[Snapshot]) {
    assert!(
        !UNAVAILABLE.load(Ordering::Relaxed) && samples.iter().all(|s| !s.fault),
        "UNDETERMINED: allocator ledger unavailable, reentrant, overflowed or exhausted"
    );
}

fn allocator_controls() {
    let original = Layout::from_size_align(64, 8).unwrap();
    let grown = Layout::from_size_align(128, 8).unwrap();
    let zeroed = Layout::from_size_align(32, 8).unwrap();
    start_epoch();
    // SAFETY: nonzero valid layouts; each successful pointer is freed once with
    // its current layout. A failed realloc leaves the original pointer intact.
    let (retained, resized, freed, zero_retained, zero_freed, allocation_failed) = unsafe {
        let pointer = ALLOCATOR.alloc(original);
        let retained = snapshot();
        let replacement = if pointer.is_null() {
            std::ptr::null_mut()
        } else {
            ALLOCATOR.realloc(pointer, original, grown.size())
        };
        let resized = snapshot();
        if !replacement.is_null() {
            ALLOCATOR.dealloc(replacement, grown);
        } else if !pointer.is_null() {
            ALLOCATOR.dealloc(pointer, original);
        }
        let freed = snapshot();
        let zero_pointer = ALLOCATOR.alloc_zeroed(zeroed);
        let zero_retained = snapshot();
        if !zero_pointer.is_null() {
            ALLOCATOR.dealloc(zero_pointer, zeroed);
        }
        (
            retained,
            resized,
            freed,
            zero_retained,
            snapshot(),
            pointer.is_null() || replacement.is_null() || zero_pointer.is_null(),
        )
    };
    stop_epoch();
    let samples = [retained, resized, freed, zero_retained, zero_freed];
    require_available(&samples);
    assert!(
        !allocation_failed,
        "UNDETERMINED: allocator control allocation failed"
    );
    assert_eq!(
        (retained.live, retained.bytes),
        (1, 64),
        "UNDETERMINED: alloc tracking control"
    );
    assert_eq!(
        (resized.live, resized.bytes),
        (1, 128),
        "UNDETERMINED: realloc tracking control"
    );
    assert_eq!(
        (freed.live, freed.bytes),
        (0, 0),
        "UNDETERMINED: dealloc tracking control"
    );
    assert_eq!(
        (zero_retained.live, zero_retained.bytes),
        (1, 32),
        "UNDETERMINED: alloc_zeroed control"
    );
    assert_eq!(
        (zero_freed.live, zero_freed.bytes),
        (0, 0),
        "UNDETERMINED: final free control"
    );
    assert_eq!(
        zero_freed.allocations, 3,
        "UNDETERMINED: allocation event control"
    );
}

#[derive(Default)]
struct Progress {
    boundaries: Cell<usize>,
    consumed_lines: Cell<usize>,
    ordering_failed: Cell<bool>,
    eof_reads: Cell<usize>,
}

struct OwnedLines<'a> {
    lines: Vec<Vec<u8>>,
    offset: usize,
    progress: &'a Progress,
}

impl Read for OwnedLines<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let available = self.fill_buf()?;
        let count = available.len().min(output.len());
        output[..count].copy_from_slice(&available[..count]);
        self.consume(count);
        Ok(count)
    }
}

impl BufRead for OwnedLines<'_> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        let index = self.progress.consumed_lines.get();
        let Some(line) = self.lines.get(index) else {
            // An unterminated last line probes EOF once within its own read,
            // then the server probes it again after the next lifecycle boundary.
            let boundary = self.progress.boundaries.get();
            if boundary != index && boundary != index + 1 {
                self.progress.ordering_failed.set(true);
            }
            self.progress
                .eof_reads
                .set(self.progress.eof_reads.get() + 1);
            return Ok(&[]);
        };
        if self.progress.boundaries.get() != index + 1 {
            self.progress.ordering_failed.set(true);
        }
        // Expose one line only, in bounded chunks: neither this reader nor the
        // loop may prefetch the following request across its lifecycle boundary.
        Ok(&line[self.offset..(self.offset + 4096).min(line.len())])
    }

    fn consume(&mut self, count: usize) {
        self.offset += count;
        let index = self.progress.consumed_lines.get();
        if self
            .lines
            .get(index)
            .is_some_and(|line| self.offset == line.len())
        {
            self.progress.consumed_lines.set(index + 1);
            self.offset = 0;
        }
    }
}

// Responses are tiny for this workload. Fixed storage permits full JSON checks
// after measurement without retaining any heap-allocated output during it.
#[derive(Clone, Copy)]
struct Reply {
    bytes: [u8; 192],
    length: usize,
}

const EMPTY_REPLY: Reply = Reply {
    bytes: [0; 192],
    length: 0,
};

struct Output {
    replies: [Reply; 7],
    completed: usize,
    dirty: bool,
    invalid: bool,
}

impl Output {
    fn new() -> Self {
        Self {
            replies: [EMPTY_REPLY; 7],
            completed: 0,
            dirty: false,
            invalid: false,
        }
    }
}

impl Write for Output {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.dirty = true;
        for &byte in bytes {
            let Some(reply) = self.replies.get_mut(self.completed) else {
                self.invalid = true;
                continue;
            };
            if byte == b'\n' {
                self.completed += 1;
            } else if let Some(slot) = reply.bytes.get_mut(reply.length) {
                *slot = byte;
                reply.length += 1;
            } else {
                self.invalid = true;
            }
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.dirty = false;
        Ok(())
    }
}

fn padded_ping(id: u8) -> Vec<u8> {
    let mut line = format!("{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"ping\"}}").into_bytes();
    // Exactly the public accepted line length, followed by its terminator.
    line.resize(MAX_LINE_BYTES, b' ');
    line.push(b'\n');
    line
}

#[test]
fn completed_request_allocations_are_released_before_the_next_read() {
    allocator_controls();
    // All fixture storage and callback construction precedes measurement. Ping
    // and protocol-error paths must never invoke backend or filesystem callbacks.
    let fs = real_fs();
    let be = Backend {
        base_dir: Path::new("unused-inert-mcp-fixture"),
        now: &|| panic!("unexpected clock callback"),
        fs: &fs,
        live: &|_| panic!("unexpected liveness callback"),
        caller: &|| panic!("unexpected caller callback"),
        resolve: &|_, _| panic!("unexpected resolver callback"),
        sessions: &|| panic!("unexpected session discovery"),
        set_name: &|_, _| panic!("unexpected name write"),
        wake: &|_| panic!("unexpected wake callback"),
    };
    let lines = vec![
        padded_ping(1),
        b"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\n".to_vec(),
        padded_ping(3),
        b"{\"jsonrpc\":\"2.0\",\"method\":\"ping\"}\n".to_vec(),
        vec![0xff, b'\n'],
        b"{\n".to_vec(),
        {
            let mut line = vec![b'a'; MAX_LINE_BYTES + 2];
            line.push(b'\n');
            line
        },
        b"{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"ping\"}".to_vec(),
    ];
    // Warm the same real routes before resetting the ledger. Output and parser
    // allocations from warm-up are gone when this invocation returns.
    let warm_progress = Progress::default();
    let mut warm_input = OwnedLines {
        lines: lines.clone(),
        offset: 0,
        progress: &warm_progress,
    };
    let mut warm_output = Output::new();
    serve_with_lifecycle_and_image_report(
        &mut warm_input,
        &mut warm_output,
        &be,
        &mut |_| {
            warm_progress
                .boundaries
                .set(warm_progress.boundaries.get() + 1);
            Ok(())
        },
        None,
    )
    .unwrap();
    drop(warm_input);

    let progress = Progress::default();
    let mut input = OwnedLines {
        lines,
        offset: 0,
        progress: &progress,
    };
    let mut output = Output::new();
    let expected_replies = [0, 1, 2, 3, 3, 4, 5, 6, 7];
    let mut samples = [Snapshot::default(); 9];
    let mut boundary_failed = false;
    start_epoch();
    let served = serve_with_lifecycle_and_image_report(
        &mut input,
        &mut output,
        &be,
        &mut |out| {
            let index = progress.boundaries.get();
            if index >= samples.len() {
                boundary_failed = true;
                return Err(io::ErrorKind::InvalidData.into());
            }
            samples[index] = snapshot();
            boundary_failed |= out.dirty
                || out.completed != expected_replies[index]
                || progress.consumed_lines.get() != index;
            progress.boundaries.set(index + 1);
            Ok(())
        },
        None,
    );
    let after_eof = snapshot();
    stop_epoch();

    require_available(&samples);
    require_available(&[after_eof]);
    assert!(served.is_ok(), "serve failed: {served:?}");
    assert!(
        !boundary_failed && !progress.ordering_failed.get(),
        "flush/lifecycle/read ordering changed"
    );
    assert_eq!(
        progress.boundaries.get(),
        samples.len(),
        "missing request/EOF boundary"
    );
    assert_eq!(
        progress.consumed_lines.get(),
        8,
        "oversize drain or EOF handling changed"
    );
    assert_eq!(
        progress.eof_reads.get(),
        2,
        "unterminated final line and terminal EOF must both be read"
    );
    assert!(!output.invalid, "response exceeded fixed capture capacity");
    assert_eq!(
        output.completed, 7,
        "notification emitted a response or a request was lost"
    );
    for (index, reply) in output.replies.iter().enumerate() {
        let actual: Value = serde_json::from_slice(&reply.bytes[..reply.length]).unwrap();
        let expected = match index {
            0..=2 => json!({"jsonrpc":"2.0", "id": index + 1, "result":{}}),
            3..=4 => {
                json!({"jsonrpc":"2.0", "id":null, "error":{"code":-32700,"message":"parse error"}})
            }
            5 => {
                json!({"jsonrpc":"2.0", "id":null, "error":{"code":-32600,"message":"request too large"}})
            }
            6 => json!({"jsonrpc":"2.0", "id":4, "result":{}}),
            _ => unreachable!(),
        };
        assert_eq!(actual, expected, "response {index}");
    }
    assert!(
        samples.last().unwrap().allocations > 0,
        "UNDETERMINED: real loop allocations were not observed"
    );
    assert_eq!(
        (after_eof.live, after_eof.bytes),
        (0, 0),
        "serve retained measured allocations after return"
    );
    for (boundary, sample) in samples.iter().enumerate() {
        assert_eq!(
            (sample.live, sample.bytes),
            (0, 0),
            "completed request storage retained at lifecycle boundary {boundary}: {sample:?}"
        );
    }
}
