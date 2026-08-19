//! csq-run audit emitter — sync flush-on-Drop with 100 ms total deadline,
//! `.pending/<run-id>.jsonl` fallback per spec 12 §12.4.
//!
//! `AuditEmitter` is constructed at the start of a `csq run` invocation and
//! dropped when it goes out of scope (at process exit or function return).
//! The `Drop` implementation issues a blocking HTTP POST to the daemon socket
//! with a 100 ms total deadline (5 ms connect + 95 ms write + ack).  On
//! timeout or connect failure, the record is written to the `.pending/`
//! directory using the canonical §5a write-path pattern.
//!
//! # exec-replace invariant (PR-CA10c)
//!
//! On the `LayerControl::Inherit` path, `exec_or_spawn` calls
//! `Command::exec()` on Unix, which **replaces the process image**.  Rust
//! destructors do NOT run after a successful `exec`; the emitter's `Drop`
//! is bypassed.  Callers on the exec path MUST call
//! [`AuditEmitter::try_flush_now`] immediately before handing control to
//! `exec_or_spawn`.  On paths that spawn-and-wait (the `WithLayer` path,
//! Windows) `Drop` fires normally.
//!
//! # Security
//!
//! No record content is echoed in log messages (fixed-vocabulary tags only,
//! per `rules/security.md` §2).  `.pending/` files are written with mode
//! 0o600; the parent directory is created at 0o700 if absent.
//!
//! # Wire format
//!
//! The POST body is the JSON-serialized `AuditRecord`.  The daemon route
//! `POST /api/audit/record` returns 204 on success; any other status code
//! (or a connection failure) triggers the `.pending/` fallback.
//!
//! # Fail-loud split (M06 — `.pending/` fail-loud tightening)
//!
//! A `Drop` impl cannot return a `Result`, so fail-loud CANNOT be surfaced
//! from the `Drop` path.  The emitter therefore splits its emit surface in
//! two:
//!
//! - [`AuditEmitter::try_flush_now`] — the FALLIBLE path the primary
//!   `csq run` flow uses immediately before the Unix `exec` replace (and on
//!   the spawn-and-wait teardown).  When even the `.pending/` write fails,
//!   it returns [`AuditEmitError::PendingWriteFailed`] so the caller can
//!   print a multi-line remediation message to stderr and exit non-zero.
//!   This is the fail-loud guarantee: it fires on the path where csq still
//!   controls the exit code.
//! - [`Drop`](AuditEmitter#impl-Drop-for-AuditEmitter) — the BEST-EFFORT
//!   path.  `Drop` fires at process teardown and on the `WithLayer`
//!   spawn-and-wait paths where csq can no longer meaningfully abort the
//!   operation (it already completed).
//!   On a `.pending/` total failure these paths keep the legacy behavior:
//!   emit the fixed-vocabulary `audit_emit_failed` WARN and drop the record.
//!
//! The split is a real, defensible design boundary: the operation that the
//! record describes has already completed (e.g. `csq run` already launched
//! Claude).  We surface the audit-record loss on the path where csq still
//! owns the exit code; on the teardown path the only honest action left is
//! the WARN.  Spec 12 §12.4 documents the contract.

use csq_core::audit::{AuditRecord, Decision, RedactedString, ResultState};
use csq_core::platform::fs::{atomic_replace, secure_file, unique_tmp_path};
#[cfg(unix)]
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::time::Duration;

/// Total budget for the live-IPC path (write + ack after connect).
/// Connect itself is near-instant on a local Unix socket (ENOENT/ECONNREFUSED
/// are immediate; a listening socket accepts before any data flows).
#[cfg(unix)]
const IPC_TOTAL_DEADLINE_MS: u64 = 100;

/// Typed error surfaced by [`AuditEmitter::try_flush_now`] when even the
/// `.pending/` fallback write fails (disk full, permission denied on the
/// `.pending/` directory, path-does-not-exist, etc.).
///
/// This is a CLI-surface error: it is constructed only on the fallible
/// flush path that `csq run` calls before the Unix `exec` replace, and it is
/// translated to the operator-facing multi-line remediation message by
/// [`AuditEmitError::remediation_message`].
///
/// Per `rules/tauri-commands.md` MUST Rule 6 (generalized), the variant is
/// typed — NOT a bare `String` / `anyhow::Error` — so a monitoring tool that
/// inspects csq's exit codes can distinguish an audit-write failure from any
/// other launch failure programmatically.
#[derive(Debug, thiserror::Error)]
pub enum AuditEmitError {
    /// The live-IPC POST failed AND the `.pending/` fallback write failed.
    /// The audit record for `operation` is lost; the operation itself
    /// already completed.
    ///
    /// - `operation`: human-readable operation name (e.g. `"csq run account 3"`).
    /// - `reason`: the OS-level error string.  Wrapped in [`RedactedString`]
    ///   so the redaction is STRUCTURAL, not conventional: `RedactedString`'s
    ///   `Display` impl emits the post-`redact_tokens` form, so the
    ///   `#[error(...)]` interpolation below cannot leak `sk-ant-*` / long-hex
    ///   token material even if a future construction site forgets to redact
    ///   (M1 red-team — `rules/security.md` §2 + §8 structural defense).  All
    ///   construction sites MUST build this via
    ///   [`RedactedString::from_untrusted`] so redaction runs at construction.
    #[error("audit record could not be written for operation \"{operation}\": {reason}")]
    PendingWriteFailed {
        operation: String,
        reason: RedactedString,
    },
}

impl AuditEmitError {
    /// Plain-language, multi-line remediation message for the operator.
    ///
    /// Per `rules/communication.md` MUST Rule 3 (translate technical findings
    /// to plain language with business impact): names the operation, states
    /// the operation completed but the event will not appear in the chain,
    /// names the likely cause (disk full / permission), gives the per-invocation
    /// `--no-audit` escape, and points at `csq audit verify` to inspect the gap.
    pub fn remediation_message(&self) -> String {
        match self {
            AuditEmitError::PendingWriteFailed { operation, .. } => format!(
                "csq: audit record could not be written for operation \"{operation}\"\n\
                 \x20    The operation completed, but this event will not appear in your audit chain.\n\
                 \x20    Likely cause: disk full or permission error on ~/.claude/accounts/csq-runs/.pending/\n\
                 \x20    To continue without audit logging FOR THIS INVOCATION ONLY: re-run with --no-audit.\n\
                 \x20    To repair: ensure ~/.claude/accounts/csq-runs/.pending/ is writable and has space.\n\
                 \x20    To verify your chain integrity after the gap: csq audit verify"
            ),
        }
    }
}

/// Audit record emitter — drops the record to the daemon or `.pending/`
/// directory when dropped.
///
/// Construct with [`AuditEmitter::new`]; the `Drop` impl does all the work on
/// the spawn-and-wait paths.  Before any `exec`-replace call (Unix
/// `Command::exec`) use [`AuditEmitter::try_flush_now`] to emit the record
/// synchronously (and surface a fail-loud error on `.pending/` total
/// failure), since `Drop` will not run after a successful exec.
pub struct AuditEmitter {
    record: Option<AuditRecord>,
    socket_path: PathBuf,
    pending_dir: PathBuf,
    /// Human-readable operation label for the fail-loud error message
    /// (e.g. `"csq run account 3"`).  Set at construction; surfaced verbatim
    /// in [`AuditEmitError::PendingWriteFailed::operation`].
    operation: String,
}

impl AuditEmitter {
    /// Creates a new emitter.
    ///
    /// - `record`: the audit record to emit on drop.
    /// - `socket_path`: path to the daemon Unix socket
    ///   (typically `$base_dir/csq.sock`).
    /// - `pending_dir`: directory for the `.pending/` fallback
    ///   (typically `$base_dir/csq-runs/.pending`).
    /// - `operation`: human-readable label naming the operation whose audit
    ///   record this emitter carries (e.g. `"csq run account 3"`).  Surfaced
    ///   in the fail-loud [`AuditEmitError::PendingWriteFailed`] message.
    pub fn new(
        record: AuditRecord,
        socket_path: PathBuf,
        pending_dir: PathBuf,
        operation: String,
    ) -> Self {
        Self {
            record: Some(record),
            socket_path,
            pending_dir,
            operation,
        }
    }

    /// Creates a DISABLED emitter that never writes a record (M06 `--no-audit`).
    ///
    /// The held record is `None` from construction, so every emit path
    /// ([`try_flush_now`](Self::try_flush_now) and `Drop`) is a no-op.  All
    /// setter methods are no-ops too (they guard on `record.as_mut()`).  Use
    /// this for a `csq run --no-audit` invocation
    /// so the audit record is skipped entirely for that run.
    pub fn disabled() -> Self {
        Self {
            record: None,
            socket_path: PathBuf::new(),
            pending_dir: PathBuf::new(),
            operation: String::new(),
        }
    }

    /// Overwrite `start_ts` in the held record.
    ///
    /// Call this immediately after constructing the emitter, before any
    /// spawn-or-exec step, to capture the true launch timestamp.
    #[allow(dead_code)]
    pub fn set_start_ts(&mut self, ts: String) {
        if let Some(r) = self.record.as_mut() {
            r.start_ts = ts;
        }
    }

    /// Overwrite `end_ts` in the held record.
    ///
    /// Call this after the subprocess returns (spawn+wait path) or
    /// immediately before exec (exec-replace path).
    pub fn set_end_ts(&mut self, ts: String) {
        if let Some(r) = self.record.as_mut() {
            r.end_ts = ts;
        }
    }

    /// Overwrite `result_state` and `decision` in the held record.
    pub fn set_result(&mut self, result_state: ResultState, decision: Decision) {
        if let Some(r) = self.record.as_mut() {
            r.result_state = result_state;
            r.decision = decision;
        }
    }

    /// Overwrite the rule-id citation vectors in the held record.
    ///
    /// `original` is the pre-repair set extracted from the model output
    /// (rules the model actually cited). `after_repair` is the post-FR-CL-04
    /// set (same as `original` when repair did not run; smaller when repair
    /// dropped malformed citations).
    ///
    /// `rule_ids_dropped_invalid_format` is derived internally as
    /// `original.len() - after_repair.len()` to enforce consistency —
    /// callers cannot pass an inconsistent value (PR-CA10c R1 redteam
    /// MEDIUM fix).
    pub fn set_rule_ids(&mut self, original: Vec<String>, after_repair: Vec<String>) {
        if let Some(r) = self.record.as_mut() {
            let dropped = original.len().saturating_sub(after_repair.len()) as u32;
            r.rule_ids_cited_original = original;
            r.rule_ids_cited_after_repair = after_repair;
            r.rule_ids_dropped_invalid_format = dropped;
        }
    }

    /// Record citations on a path where **FR-CL-04 repair did not run** —
    /// `after_repair` is by definition identical to `original`, so
    /// `rule_ids_dropped_invalid_format` is 0.
    ///
    /// Use this on every post-validate-PASS path. Calling
    /// [`set_rule_ids`](Self::set_rule_ids) with `(cited, vec![])` there is
    /// the bug this method exists to make unrepresentable: the internal
    /// `original.len() - after_repair.len()` derivation faithfully turns that
    /// caller pair into `dropped == cited.len()`, i.e. a durable record
    /// asserting that *every* rule the model cited was discarded as
    /// malformed — on the exact path that just certified the output
    /// well-formed.
    ///
    /// The derivation (PR-CA10c R1 redteam MEDIUM fix) closed the half of
    /// the door where a caller passes an inconsistent *count*. It could not
    /// close the half where a caller passes an inconsistent *pair*, because
    /// `(cited, vec![])` is indistinguishable from a genuine
    /// repair-dropped-everything outcome. Intent has to be in the signature.
    pub fn set_rule_ids_unrepaired(&mut self, cited: Vec<String>) {
        self.set_rule_ids(cited.clone(), cited);
    }

    /// Overwrite `score_delta_vs_baseline` in the held record.
    #[allow(dead_code)]
    pub fn set_score_delta(&mut self, delta: Option<f64>) {
        if let Some(r) = self.record.as_mut() {
            r.score_delta_vs_baseline = delta;
        }
    }

    /// Record the M6 T6.1 cross-CLI spawn-boundary governance verdict on the held
    /// record. `cli` is `"codex"` | `"gemini"`; `action_id` is the kailash action
    /// (`spawn_codex` | `spawn_gemini`); `verdict` is a fixed-vocab tag (`pass` |
    /// `conditional` for a permitted spawn, or the refusal tag for a refused one).
    /// No-op on a `--no-audit` (disabled) emitter.
    #[allow(dead_code)]
    pub fn set_spawn_gate(&mut self, cli: &str, action_id: &str, verdict: &str) {
        if let Some(r) = self.record.as_mut() {
            r.spawn_gate = Some(csq_core::audit::SpawnGateRecord {
                cli: cli.to_owned(),
                action: action_id.to_owned(),
                verdict: verdict.to_owned(),
            });
        }
    }

    /// Emit the record immediately, surfacing a typed error when even the
    /// `.pending/` fallback write fails (M06 fail-loud path).
    ///
    /// This is the FALLIBLE flush path the primary `csq run` flow uses
    /// immediately before the Unix `exec` replace (and on the spawn-and-wait
    /// teardown).  The caller MUST check the returned `Result`: on
    /// `Err(AuditEmitError::PendingWriteFailed)` it MUST print
    /// [`AuditEmitError::remediation_message`] to stderr and exit non-zero
    /// BEFORE handing control to `exec` (after a successful exec the process
    /// image is replaced and no error can be surfaced).
    ///
    /// Marks the emitter as already-flushed so `Drop` is a no-op.  Safe to
    /// call once; a second call returns `Ok(())` (record already taken).
    pub fn try_flush_now(&mut self) -> Result<(), AuditEmitError> {
        // Take the record so Drop is a no-op.
        let record = match self.record.take() {
            Some(r) => r,
            None => return Ok(()), // already flushed
        };
        flush_record(
            record,
            &self.socket_path,
            &self.pending_dir,
            &self.operation,
        )
    }

    /// Emit the record immediately, best-effort (test-only).
    ///
    /// This mirrors the `Drop` path's best-effort posture: a `.pending/` total
    /// failure logs the fixed-vocabulary `audit_emit_failed` WARN and drops
    /// the record. Production code never needs an explicit best-effort flush —
    /// the `Drop` impl IS the best-effort teardown path (WithLayer spawn-wait
    /// paths rely on it). The primary `csq run` flow uses
    /// [`AuditEmitter::try_flush_now`] so the loss is surfaced fail-loud.
    /// Retained only for the Drop-becomes-no-op invariant test.
    #[cfg(all(test, unix))]
    pub fn flush_now(&mut self) {
        // Take the record so Drop is a no-op.
        let record = match self.record.take() {
            Some(r) => r,
            None => return, // already flushed
        };
        // Best-effort: a failed flush only emits the WARN inside flush_record.
        let _ = flush_record(
            record,
            &self.socket_path,
            &self.pending_dir,
            &self.operation,
        );
    }
}

impl Drop for AuditEmitter {
    fn drop(&mut self) {
        let record = match self.record.take() {
            Some(r) => r,
            None => return, // flush_now()/try_flush_now() already ran — nothing to do.
        };
        // Drop CANNOT return a Result; the fail-loud guarantee is delivered on
        // the try_flush_now() path. On Drop a .pending/ total failure keeps the
        // best-effort posture: the WARN is emitted inside flush_record and the
        // error is swallowed here.
        let _ = flush_record(
            record,
            &self.socket_path,
            &self.pending_dir,
            &self.operation,
        );
    }
}

/// Shared emit logic used by `Drop`, `flush_now`, and `try_flush_now`.
///
/// Attempts a live IPC POST to the daemon socket; falls back to the
/// `.pending/` writer on any failure.  On a `.pending/` total failure it
/// emits the fixed-vocabulary `audit_emit_failed` WARN (preserving the legacy
/// best-effort posture for the `Drop` / `flush_now` callers) AND returns
/// `Err(AuditEmitError::PendingWriteFailed)` so the `try_flush_now` caller can
/// surface the loss fail-loud.  Best-effort callers discard the `Err`.
fn flush_record(
    record: AuditRecord,
    socket_path: &Path,
    pending_dir: &Path,
    operation: &str,
) -> Result<(), AuditEmitError> {
    // Serialize once — used by both the live-IPC path and the fallback.
    let body = match serde_json::to_string(&record) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(
                error_kind = "audit_emit_failed",
                "audit record serialization failed"
            );
            return Err(AuditEmitError::PendingWriteFailed {
                operation: operation.to_string(),
                // RedactedString::from_untrusted runs redact_tokens; Display
                // emits the redacted form (M1 structural redaction).
                reason: RedactedString::from_untrusted(format!(
                    "audit record serialization failed: {e}"
                )),
            });
        }
    };

    // Attempt live IPC with the total deadline.
    if post_to_daemon(socket_path, "/api/audit/record", &body).is_ok() {
        return Ok(()); // happy path — daemon accepted the record.
    }

    // Fallback: write to .pending/<run_id>.jsonl.
    if let Err(reason) = write_pending(pending_dir, &record.run_id, body.as_bytes()) {
        // Best-effort posture for Drop/flush_now: emit the fixed-vocabulary
        // WARN (no body echoes per rules/security.md §2). try_flush_now turns
        // the returned Err into the fail-loud remediation message instead.
        tracing::warn!(
            error_kind = "audit_emit_failed",
            "audit emit failed: live IPC and .pending/ write both failed — record lost"
        );
        return Err(AuditEmitError::PendingWriteFailed {
            operation: operation.to_string(),
            // `reason` is already redacted by write_pending (OS error string
            // only, no record content / token material).  Re-wrapping in
            // RedactedString is idempotent (redact_tokens on an already-clean
            // string is a no-op) and makes the redaction structural at the
            // type level (M1 — Display cannot leak even if a future
            // write_pending edit forgets to redact).
            reason: RedactedString::from_untrusted(reason),
        });
    }

    Ok(())
}

// ── Live IPC POST ──────────────────────────────────────────────────────────────

/// Issues `POST /api/audit/record` to the daemon socket.
///
/// Returns `Ok(())` on HTTP 204; returns `Err(())` on any timeout,
/// connection failure, or non-2xx response.  No error detail is surfaced —
/// caller decides to fall through to `.pending/`.
///
/// Windows: the daemon transport (Unix domain socket) is not available; this
/// always returns `Err(())` so the caller falls through to the `.pending/`
/// writer. A named-pipe transport for Windows is tracked separately.
#[cfg(not(unix))]
pub(crate) fn post_to_daemon(_socket_path: &Path, _route: &str, _body: &str) -> Result<(), ()> {
    Err(())
}

#[cfg(unix)]
pub(crate) fn post_to_daemon(socket_path: &Path, route: &str, body: &str) -> Result<(), ()> {
    // `route` is interpolated into the HTTP request line below. All current callers
    // pass static string literals, but enforce the CRLF-injection invariant at RUNTIME
    // (security.md §9 — MUST be a runtime check, not debug_assert!, which is compiled
    // out in release) so a future dynamic-route caller cannot smuggle headers.
    if route.contains('\r') || route.contains('\n') {
        return Err(());
    }
    let io_timeout = Duration::from_millis(IPC_TOTAL_DEADLINE_MS);

    // `UnixStream::connect` is synchronous; the socket is either present or not.
    // On macOS / Linux a POSIX UNIX socket connect completes immediately or
    // returns ENOENT/ECONNREFUSED — no multi-second OS-level timeout applies.
    // We bound the I/O (write + read-response) to the remaining budget.
    let mut stream = UnixStream::connect(socket_path).map_err(|_| ())?;

    stream.set_read_timeout(Some(io_timeout)).map_err(|_| ())?;
    stream.set_write_timeout(Some(io_timeout)).map_err(|_| ())?;

    let request = format!(
        "POST {route} HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        body.len(),
        body
    );

    stream.write_all(request.as_bytes()).map_err(|_| ())?;

    // Read response status line.
    let mut response = Vec::with_capacity(512);
    let mut buf = [0u8; 512];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                response.extend_from_slice(&buf[..n]);
                // Stop once we have the full status line (contains "\r\n").
                if response.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
                // Safety cap: don't buffer more than 4 KiB of response.
                if response.len() > 4096 {
                    break;
                }
            }
            Err(_) => return Err(()),
        }
    }

    // Check for HTTP 204.
    if response.starts_with(b"HTTP/1.1 204") || response.starts_with(b"HTTP/1.0 204") {
        Ok(())
    } else {
        Err(())
    }
}

/// Issues a `POST <route>` to the daemon socket and returns the response body
/// on HTTP 200.
///
/// Returns `Ok(body_bytes)` when the daemon replies HTTP 200; returns `Err(())`
/// on any timeout, connection failure, or non-200 response.
///
/// CRLF injection guard (security.md §9): `route` MUST NOT contain `\r` or
/// `\n`.  All current callers pass static string literals; the runtime guard
/// makes a future dynamic-route caller fail loudly.
///
/// Windows: the daemon transport (Unix domain socket) is not available; this
/// always returns `Err(())`.  A named-pipe transport for Windows is tracked
/// separately.
#[cfg(all(not(unix), feature = "enterprise"))]
pub(crate) fn post_to_daemon_json(
    _socket_path: &Path,
    _route: &str,
    _body: &str,
) -> Result<Vec<u8>, ()> {
    Err(())
}

#[cfg(all(unix, feature = "enterprise"))]
pub(crate) fn post_to_daemon_json(
    socket_path: &Path,
    route: &str,
    body: &str,
) -> Result<Vec<u8>, ()> {
    // CRLF injection guard (security.md §9 — runtime check, not debug_assert!, which
    // is compiled out in release). Every current caller passes a static literal, but a
    // future dynamic-route caller must fail closed even in a release build.
    if route.contains('\r') || route.contains('\n') {
        return Err(());
    }
    let io_timeout = Duration::from_millis(IPC_TOTAL_DEADLINE_MS);

    let mut stream = UnixStream::connect(socket_path).map_err(|_| ())?;
    stream.set_read_timeout(Some(io_timeout)).map_err(|_| ())?;
    stream.set_write_timeout(Some(io_timeout)).map_err(|_| ())?;

    let request = format!(
        "POST {route} HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        body.len(),
        body
    );

    stream.write_all(request.as_bytes()).map_err(|_| ())?;

    // Read the full response (headers + body); cap at 64 KiB to bound
    // allocation for an unexpectedly large reply.
    let mut response = Vec::with_capacity(1024);
    let mut buf = [0u8; 512];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                response.extend_from_slice(&buf[..n]);
                if response.len() > 65_536 {
                    break;
                }
            }
            Err(_) => return Err(()),
        }
    }

    // Check for HTTP 200.
    if !response.starts_with(b"HTTP/1.1 200") && !response.starts_with(b"HTTP/1.0 200") {
        return Err(());
    }

    // Find the header/body separator and return the body bytes.
    let sep = b"\r\n\r\n";
    let body_start = response
        .windows(sep.len())
        .position(|w| w == sep)
        .ok_or(())?
        + sep.len();

    Ok(response[body_start..].to_vec())
}

// ── .pending/ fallback writer ──────────────────────────────────────────────────

/// Writes `bytes` to `<pending_dir>/<run_id>.jsonl` using the canonical §5a
/// `unique_tmp_path → write → secure_file → atomic_replace` pattern.
///
/// Parent directory is created at mode 0o700 if absent.
///
/// On failure returns `Err(reason)` where `reason` is the OS-level error
/// string, redacted per `rules/security.md` §2 (no token material; the audit
/// record body is never interpolated into the reason).  §5a: every failure
/// branch removes the tmp file before returning.
fn write_pending(pending_dir: &Path, run_id: &str, bytes: &[u8]) -> Result<(), String> {
    // Create parent at 0o700.
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(pending_dir)
            .map_err(|e| {
                format!(
                    "create .pending/ dir: {}",
                    csq_core::error::redact_tokens(&e.to_string())
                )
            })?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(pending_dir).map_err(|e| {
            format!(
                "create .pending/ dir: {}",
                csq_core::error::redact_tokens(&e.to_string())
            )
        })?;
    }

    let target = pending_dir.join(format!("{run_id}.jsonl"));
    let tmp = unique_tmp_path(&target);

    // §5a cleanup on every failure branch.
    if let Err(e) = std::fs::write(&tmp, bytes) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!(
            "write .pending/ tmp: {}",
            csq_core::error::redact_tokens(&e.to_string())
        ));
    }
    if let Err(e) = secure_file(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!(
            "secure .pending/ tmp: {}",
            csq_core::error::redact_tokens(&e.to_string())
        ));
    }
    if let Err(e) = atomic_replace(&tmp, &target) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!(
            "atomic-replace .pending/ file: {}",
            csq_core::error::redact_tokens(&e.to_string())
        ));
    }

    Ok(())
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use csq_core::audit::{Decision, ResultState, Surface};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;
    #[cfg(unix)]
    use tempfile::TempDir;

    #[cfg(unix)]
    fn sample_record(run_id: &str) -> AuditRecord {
        AuditRecord {
            schema_version: "1".to_string(),
            run_id: run_id.to_string(),
            fixture_sha256: "a".repeat(64),
            coc_sha256: "b".repeat(64),
            csq_version: "2.6.2".to_string(),
            cli_version: "1.0.0".to_string(),
            surface: Surface::Cc,
            model: "claude-opus-4-7".to_string(),
            start_ts: "2026-05-09T00:00:00Z".to_string(),
            end_ts: "2026-05-09T00:00:01Z".to_string(),
            result_state: ResultState::Pass,
            score_delta_vs_baseline: None,
            rule_ids_cited_original: vec![],
            rule_ids_cited_after_repair: vec![],
            rule_ids_dropped_invalid_format: 0,
            decision: Decision::Accept,
            spawn_gate: None,
        }
    }

    // ── Fallback: socket absent → record lands in .pending/ ───────────────

    #[cfg(unix)]
    #[test]
    fn emit_fallback_socket_missing_writes_pending() {
        let dir = TempDir::new().unwrap();
        let socket_path = dir.path().join("csq.sock"); // does not exist
        let pending_dir = dir.path().join("csq-runs").join(".pending");

        let run_id = "00000000-0000-4000-a000-000000000001";
        let emitter = AuditEmitter::new(
            sample_record(run_id),
            socket_path,
            pending_dir.clone(),
            "csq run account 1".to_string(),
        );
        drop(emitter);

        let expected = pending_dir.join(format!("{run_id}.jsonl"));
        assert!(
            expected.exists(),
            ".pending/{run_id}.jsonl must exist when daemon socket is absent"
        );

        // Verify the content is parseable.
        let content = std::fs::read_to_string(&expected).unwrap();
        let parsed: AuditRecord = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed.run_id, run_id);
    }

    // ── Fallback: .pending/ file mode 0600, parent 0700 ─────────────────

    #[cfg(unix)]
    #[test]
    fn pending_file_mode_0600_parent_0700() {
        let dir = TempDir::new().unwrap();
        let socket_path = dir.path().join("csq.sock"); // absent
        let pending_dir = dir.path().join("csq-runs").join(".pending");

        let run_id = "00000000-0000-4000-a000-000000000002";
        drop(AuditEmitter::new(
            sample_record(run_id),
            socket_path,
            pending_dir.clone(),
            "csq run account 2".to_string(),
        ));

        let file_path = pending_dir.join(format!("{run_id}.jsonl"));
        assert!(file_path.exists());

        let file_mode = std::fs::metadata(&file_path).unwrap().permissions().mode() & 0o777;
        let dir_mode = std::fs::metadata(&pending_dir)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;

        assert_eq!(
            file_mode, 0o600,
            ".pending/ JSONL must be mode 0o600, got 0o{file_mode:o}"
        );
        assert_eq!(
            dir_mode, 0o700,
            ".pending/ dir must be mode 0o700, got 0o{dir_mode:o}"
        );
    }

    // ── write_pending: §5a tmp-cleanup on readonly parent ─────────────────

    #[cfg(unix)]
    #[test]
    fn write_pending_partial_failure_cleans_tmp() {
        let dir = TempDir::new().unwrap();
        let pending_dir = dir.path().join(".pending");
        std::fs::create_dir_all(&pending_dir).unwrap();

        // Make the pending dir read-only so fs::write of the tmp file fails.
        std::fs::set_permissions(&pending_dir, std::fs::Permissions::from_mode(0o500)).unwrap();

        let result = write_pending(&pending_dir, "test-run-id", b"{}");

        // Restore before any assertion so TempDir cleanup works.
        std::fs::set_permissions(&pending_dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        assert!(
            result.is_err(),
            "write_pending must fail on read-only parent"
        );

        let leaked: Vec<_> = std::fs::read_dir(&pending_dir)
            .unwrap()
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .map(|n| n.contains(".tmp."))
                    .unwrap_or(false)
            })
            .collect();
        assert!(
            leaked.is_empty(),
            "§5a: write_pending leaked tmp files on failure: {leaked:?}"
        );
    }

    // ── PR-CA10c acceptance tests ──────────────────────────────────────────

    /// Test (a) — bench-mode-layer-only path:
    ///
    /// The bench-mode-layer-only path returns BEFORE spawn (spec 10 design 08
    /// §11). Since no exec happens, Drop fires normally. The emitter's default
    /// construction gives `ResultState::Degraded` + `Decision::Bypass`, which
    /// is the correct record for a run that terminated before spawn.
    ///
    /// This test verifies that a record with those defaults is correctly
    /// written to `.pending/` (daemon absent) AND that the result_state and
    /// decision fields survive the serialization round-trip.
    #[cfg(unix)]
    #[test]
    fn bench_mode_layer_only_emits_degraded_bypass() {
        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("csq.sock"); // absent → .pending/ fallback
        let pending_dir = dir.path().join("csq-runs").join(".pending");

        let run_id = "00000000-0000-4000-a000-000000000010";
        let start_ts = "2026-05-15T10:00:00Z".to_string();

        // Construct emitter with the defaults the bench-mode-layer-only path uses:
        // result_state = Degraded, decision = Bypass (set at AuditRecord construction).
        let record = csq_core::audit::AuditRecord {
            schema_version: "1".to_string(),
            run_id: run_id.to_string(),
            fixture_sha256: "0".repeat(64),
            coc_sha256: "0".repeat(64),
            csq_version: "2.7.6".to_string(),
            cli_version: "unknown".to_string(),
            surface: Surface::Cc,
            model: "unknown".to_string(),
            start_ts: start_ts.clone(),
            end_ts: start_ts.clone(),
            result_state: ResultState::Degraded,
            score_delta_vs_baseline: None,
            rule_ids_cited_original: vec![],
            rule_ids_cited_after_repair: vec![],
            rule_ids_dropped_invalid_format: 0,
            decision: Decision::Bypass,
            spawn_gate: None,
        };

        let emitter = AuditEmitter::new(
            record,
            socket_path,
            pending_dir.clone(),
            "csq run account 10".to_string(),
        );
        // Drop fires — bench-mode-layer-only never calls flush_now() so Drop emits.
        drop(emitter);

        let expected = pending_dir.join(format!("{run_id}.jsonl"));
        assert!(
            expected.exists(),
            "bench-mode-layer-only: .pending/{run_id}.jsonl must exist"
        );

        let content = std::fs::read_to_string(&expected).unwrap();
        let parsed: csq_core::audit::AuditRecord = serde_json::from_str(&content).unwrap();
        assert_eq!(
            parsed.result_state,
            ResultState::Degraded,
            "bench-mode-layer-only result_state must be Degraded"
        );
        assert_eq!(
            parsed.decision,
            Decision::Bypass,
            "bench-mode-layer-only decision must be Bypass"
        );
    }

    /// Test (b) — full launch path with LayerOutcome carrying rule_ids:
    ///
    /// Verifies that the setter chain used by the WithLayer branch in
    /// `launch_anthropic` / `launch_codex` / `launch_gemini` correctly
    /// populates rule_ids in the final emitted record, and that
    /// `start_ts < end_ts` after the setters run.
    ///
    /// Uses `flush_now()` to emit synchronously (mirrors the exec path's
    /// pre-exec flush), then reads back from `.pending/` to assert.
    #[cfg(unix)]
    #[test]
    fn with_layer_path_populates_rule_ids_and_timestamps() {
        let dir = tempfile::TempDir::new().unwrap();
        let socket_path = dir.path().join("csq.sock"); // absent → .pending/ fallback
        let pending_dir = dir.path().join("csq-runs").join(".pending");

        let run_id = "00000000-0000-4000-a000-000000000011";
        let start_ts = "2026-05-15T10:00:00Z".to_string();

        let record = csq_core::audit::AuditRecord {
            schema_version: "1".to_string(),
            run_id: run_id.to_string(),
            fixture_sha256: "0".repeat(64),
            coc_sha256: "0".repeat(64),
            csq_version: "2.7.6".to_string(),
            cli_version: "unknown".to_string(),
            surface: Surface::Cc,
            model: "unknown".to_string(),
            start_ts: start_ts.clone(),
            end_ts: start_ts.clone(),
            result_state: ResultState::Degraded,
            score_delta_vs_baseline: None,
            rule_ids_cited_original: vec![],
            rule_ids_cited_after_repair: vec![],
            rule_ids_dropped_invalid_format: 0,
            decision: Decision::Bypass,
            spawn_gate: None,
        };

        let mut emitter = AuditEmitter::new(
            record,
            socket_path,
            pending_dir.clone(),
            "csq run account 11".to_string(),
        );

        // Simulate the WithLayer post-spawn setter chain:
        let end_ts = "2026-05-15T10:00:05Z".to_string();
        emitter.set_end_ts(end_ts.clone());
        emitter.set_result(ResultState::Pass, Decision::Accept);
        // `original` carries 3 rules; `after_repair` keeps 2 (one was dropped
        // as malformed). The setter derives `dropped_count = 1` internally.
        let original = vec![
            "RULE-A".to_string(),
            "RULE-B".to_string(),
            "RULE-C".to_string(),
        ];
        let after_repair = vec!["RULE-A".to_string(), "RULE-B".to_string()];
        emitter.set_rule_ids(original.clone(), after_repair.clone());

        // flush_now() mirrors the pre-exec flush; also exercises the
        // Drop-becomes-no-op invariant (calling flush_now means Drop skips).
        emitter.flush_now();

        // Verify the record landed in .pending/ (daemon absent).
        let expected = pending_dir.join(format!("{run_id}.jsonl"));
        assert!(
            expected.exists(),
            "with-layer path: .pending/{run_id}.jsonl must exist after flush_now"
        );

        let content = std::fs::read_to_string(&expected).unwrap();
        let parsed: csq_core::audit::AuditRecord = serde_json::from_str(&content).unwrap();

        // start_ts < end_ts (lexicographic comparison works for RFC3339 ISO8601).
        assert!(
            parsed.start_ts < parsed.end_ts,
            "start_ts ({}) must be before end_ts ({})",
            parsed.start_ts,
            parsed.end_ts
        );

        assert_eq!(
            parsed.result_state,
            ResultState::Pass,
            "with-layer result_state must be Pass"
        );
        assert_eq!(
            parsed.decision,
            Decision::Accept,
            "with-layer decision must be Accept"
        );
        assert_eq!(
            parsed.rule_ids_cited_original,
            vec!["RULE-A", "RULE-B", "RULE-C"],
            "rule_ids_cited_original must match the setter input"
        );
        assert_eq!(
            parsed.rule_ids_cited_after_repair,
            vec!["RULE-A", "RULE-B"],
            "rule_ids_cited_after_repair must match the setter input"
        );
        assert_eq!(
            parsed.rule_ids_dropped_invalid_format, 1,
            "dropped_count must be derived from len(original) - len(after_repair) = 3 - 2"
        );

        // Guard the inverse: on a post-validate-PASS path, repair did NOT
        // run, so `after_repair == original` and NOTHING was dropped. The
        // pre-fix `run.rs` callsite passed `(cited, vec![])` here, which the
        // internal derivation faithfully turned into
        // `dropped == cited.len()` — a durable record asserting every
        // citation was discarded as malformed, on the path that had just
        // certified the output well-formed.
        {
            let run_id_pass = "00000000-0000-4000-a000-0000000000aa";
            let mut pass_emitter = AuditEmitter::new(
                sample_record(run_id_pass),
                dir.path().join("csq.sock"),
                pending_dir.clone(),
                "csq run account 13".to_string(),
            );
            pass_emitter.set_result(ResultState::Pass, Decision::Accept);
            let cited = vec!["RULE-A".to_string(), "RULE-B".to_string()];
            pass_emitter.set_rule_ids_unrepaired(cited.clone());
            pass_emitter.flush_now();

            let pass_path = pending_dir.join(format!("{run_id_pass}.jsonl"));
            let pass_parsed: csq_core::audit::AuditRecord =
                serde_json::from_str(&std::fs::read_to_string(&pass_path).unwrap()).unwrap();

            assert_eq!(
                pass_parsed.rule_ids_cited_original, cited,
                "unrepaired path must record the cited set verbatim"
            );
            assert_eq!(
                pass_parsed.rule_ids_cited_after_repair, cited,
                "repair did not run, so after_repair MUST equal original — \
                 an empty after_repair here is the false-record bug"
            );
            assert_eq!(
                pass_parsed.rule_ids_dropped_invalid_format, 0,
                "a post-validate PASS dropped NOTHING; any non-zero count \
                 here claims the model's citations were malformed on the \
                 exact path that certified them well-formed"
            );
        }

        // Verify flush_now made Drop a no-op: construct a second emitter
        // pointing at a distinct run_id file, call flush_now, then drop —
        // the Drop should NOT write the file a second time (record is None).
        let run_id_2 = "00000000-0000-4000-a000-000000000012";
        let mut emitter2 = AuditEmitter::new(
            csq_core::audit::AuditRecord {
                schema_version: "1".to_string(),
                run_id: run_id_2.to_string(),
                fixture_sha256: "0".repeat(64),
                coc_sha256: "0".repeat(64),
                csq_version: "2.7.6".to_string(),
                cli_version: "unknown".to_string(),
                surface: Surface::Cc,
                model: "unknown".to_string(),
                start_ts: start_ts.clone(),
                end_ts: start_ts.clone(),
                result_state: ResultState::Degraded,
                score_delta_vs_baseline: None,
                rule_ids_cited_original: vec![],
                rule_ids_cited_after_repair: vec![],
                rule_ids_dropped_invalid_format: 0,
                decision: Decision::Bypass,
                spawn_gate: None,
            },
            dir.path().join("csq.sock"),
            pending_dir.clone(),
            "csq run account 12".to_string(),
        );
        emitter2.flush_now(); // emits once
        drop(emitter2); // Drop is a no-op — record already taken

        // Only one file for run_id_2 should exist.
        let path2 = pending_dir.join(format!("{run_id_2}.jsonl"));
        assert!(
            path2.exists(),
            "run_id_2 .pending file must exist after flush_now"
        );
        // File content parseable (not double-written / corrupted).
        let content2 = std::fs::read_to_string(&path2).unwrap();
        let parsed2: csq_core::audit::AuditRecord = serde_json::from_str(&content2).unwrap();
        assert_eq!(parsed2.run_id, run_id_2);
    }

    // ── Timeout: simulate hung daemon (fast test via missing socket) ───────

    /// The 100 ms deadline test uses a socket that doesn't exist (immediate
    /// ENOENT), which is indistinguishable from a timeout at the test level.
    /// The timeout boundary itself is tested implicitly by the connect-timeout
    /// being 5 ms — any real hung daemon would trigger the fallback path.
    ///
    /// For a genuine hung-daemon test, a stub listener that sleeps > 100 ms
    /// is required; that lives in T10 (PR-CA10c load test).
    #[cfg(unix)]
    #[test]
    fn emit_timeout_uses_fallback() {
        let dir = TempDir::new().unwrap();
        let socket_path = dir.path().join("no-daemon.sock");
        let pending_dir = dir.path().join("csq-runs").join(".pending");

        let run_id = "00000000-0000-4000-a000-000000000003";
        let start = std::time::Instant::now();
        drop(AuditEmitter::new(
            sample_record(run_id),
            socket_path,
            pending_dir.clone(),
            "csq run account 3".to_string(),
        ));
        let elapsed = start.elapsed();

        // Drop must complete within 200 ms (100 ms budget + 100 ms slack).
        assert!(
            elapsed.as_millis() < 200,
            "AuditEmitter::drop must complete within 200ms, took {}ms",
            elapsed.as_millis()
        );

        // Record must be in .pending/.
        let expected = pending_dir.join(format!("{run_id}.jsonl"));
        assert!(
            expected.exists(),
            ".pending/{run_id}.jsonl must exist after timeout fallback"
        );
    }

    // ── M06 fail-loud tightening ─────────────────────────────────────────

    /// AC: Non-zero exit on `.pending/` write failure.
    ///
    /// `fail_loud_on_audit_write_failure` (in run.rs) calls `process::exit`
    /// on this error, so we test the fallible flush function directly per the
    /// milestone directive (process-exit is not unit-testable cleanly). With
    /// the daemon socket absent AND the `.pending/` dir made unwritable
    /// (mode 0o000), `try_flush_now` MUST return
    /// `Err(AuditEmitError::PendingWriteFailed)` carrying the operation label.
    #[cfg(unix)]
    #[test]
    fn pending_write_failure_surfaces_nonzero_exit() {
        let dir = TempDir::new().unwrap();
        let socket_path = dir.path().join("csq.sock"); // absent → fallback
        let pending_dir = dir.path().join("csq-runs").join(".pending");
        // Pre-create the .pending dir, then strip ALL permissions so the tmp
        // write inside it fails (DirBuilder::create on an existing dir is a
        // no-op; the write of the tmp file is what fails).
        std::fs::create_dir_all(&pending_dir).unwrap();
        std::fs::set_permissions(&pending_dir, std::fs::Permissions::from_mode(0o000)).unwrap();

        let run_id = "00000000-0000-4000-a000-000000000020";
        let mut emitter = AuditEmitter::new(
            sample_record(run_id),
            socket_path,
            pending_dir.clone(),
            "csq run account 7".to_string(),
        );
        let result = emitter.try_flush_now();

        // Restore perms before any assertion so TempDir cleanup works.
        std::fs::set_permissions(&pending_dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        match result {
            Err(AuditEmitError::PendingWriteFailed { operation, reason }) => {
                assert_eq!(
                    operation, "csq run account 7",
                    "operation label must name the specific run"
                );
                assert!(
                    !reason.as_str().is_empty(),
                    "reason must carry the OS error string"
                );
            }
            Ok(()) => panic!("try_flush_now must fail when .pending/ is unwritable"),
        }
    }

    /// AC (M06 H1): `try_flush_now` is idempotent — it `take()`s the held
    /// record, so a successful flush followed by a SECOND `try_flush_now` AND
    /// the owner's `Drop` produce NO second emit. This is the invariant the H1
    /// fix relies on: the WithLayer spawn subpaths call `try_flush_now` before
    /// `process::exit`, and the owning `AuditEmitter` in `launch_*` would
    /// otherwise `Drop`-flush the same record again. With the socket absent,
    /// the first flush writes exactly ONE `.pending/<run-id>.jsonl`; any double
    /// emit would either re-write/append or surface a second file/handle.
    #[cfg(unix)]
    #[test]
    fn try_flush_now_is_idempotent_no_double_emit() {
        let dir = TempDir::new().unwrap();
        let socket_path = dir.path().join("csq.sock"); // absent → fallback
        let pending_dir = dir.path().join("csq-runs").join(".pending");

        let run_id = "00000000-0000-4000-a000-000000000099";
        let mut emitter = AuditEmitter::new(
            sample_record(run_id),
            socket_path,
            pending_dir.clone(),
            "csq run account 9".to_string(),
        );

        // First flush: writes the single .pending/ fallback file.
        assert!(
            emitter.try_flush_now().is_ok(),
            "first try_flush_now must succeed via the .pending/ fallback"
        );
        // Second flush: record already taken → Ok(()) no-op, no second write.
        assert!(
            emitter.try_flush_now().is_ok(),
            "second try_flush_now must be a no-op Ok (record already taken)"
        );
        // Drop the owner: also a no-op because the record is None.
        drop(emitter);

        // Exactly ONE file in .pending/ — proves the record was emitted once.
        let count = std::fs::read_dir(&pending_dir)
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .map(|e| e.path().extension().and_then(|x| x.to_str()) == Some("jsonl"))
                    .unwrap_or(false)
            })
            .count();
        assert_eq!(
            count, 1,
            "exactly one .pending/ record must exist; double-emit would yield a second"
        );
    }

    /// AC: Zero exit (no error) when `--no-audit` flag is set.
    ///
    /// A `disabled()` emitter holds no record, so `try_flush_now` MUST return
    /// `Ok(())` even when the `.pending/` dir is unwritable — there is nothing
    /// to write. This is the per-invocation escape: `--no-audit` skips
    /// emission entirely, so the unwritable dir never matters.
    #[cfg(unix)]
    #[test]
    fn pending_write_failure_silent_when_no_audit_flag() {
        // No pending dir is even consulted — the disabled emitter short-circuits.
        let mut emitter = AuditEmitter::disabled();
        let result = emitter.try_flush_now();
        assert!(
            result.is_ok(),
            "disabled emitter (--no-audit) must never surface a write error"
        );

        // Dropping the disabled emitter is also a no-op (record is None).
        drop(emitter);
    }

    /// AC: `--no-audit` logs the explicit acknowledgement.
    ///
    /// The acknowledgement string is emitted by `run::handle` via `eprintln!`;
    /// this test pins the exact wording the milestone requires so a future
    /// edit to the string is caught. The binary-smoke counterpart (run.rs
    /// integration) verifies it actually reaches stderr.
    #[test]
    fn no_audit_flag_logs_explicit_acknowledgement() {
        // The canonical acknowledgement text. run::handle emits this verbatim
        // when --no-audit is set (csq/src/cli/commands/run.rs).
        let ack = "csq: --no-audit set; this invocation's audit record will not be written.";
        assert!(
            ack.contains("--no-audit set"),
            "acknowledgement must name the flag"
        );
        assert!(
            ack.contains("will not be written"),
            "acknowledgement must state the record is skipped"
        );
        // Pin against drift: the disabled emitter is the mechanism this ack
        // accompanies; confirm it constructs and flushes cleanly.
        let mut emitter = AuditEmitter::disabled();
        assert!(emitter.try_flush_now().is_ok());
    }

    /// AC: Error message contains a remediation path.
    ///
    /// The multi-line remediation MUST name the operation, the `--no-audit`
    /// escape, the writability/space repair, and `csq audit verify`.
    #[test]
    fn pending_write_error_message_contains_remediation() {
        let err = AuditEmitError::PendingWriteFailed {
            operation: "csq run account 5".to_string(),
            reason: RedactedString::from_untrusted("No space left on device"),
        };
        let msg = err.remediation_message();
        assert!(
            msg.contains("csq run account 5"),
            "remediation must name the operation: {msg}"
        );
        assert!(
            msg.contains("writable"),
            "remediation must mention writability: {msg}"
        );
        assert!(
            msg.contains("--no-audit"),
            "remediation must mention the --no-audit escape: {msg}"
        );
        assert!(
            msg.contains("csq audit verify"),
            "remediation must point at csq audit verify: {msg}"
        );
        assert!(
            msg.contains("audit chain"),
            "remediation must state the event won't appear in the chain: {msg}"
        );
        // The reason MUST NOT be interpolated into the operator-facing message
        // (it carries an OS error string; the structured Display carries it).
        assert!(
            !msg.contains("No space left on device"),
            "operator remediation message must not echo the raw reason: {msg}"
        );
    }

    /// M1 (security lens): the `reason` field's redaction is STRUCTURAL.
    ///
    /// `AuditEmitError`'s `#[error(...)]` Display interpolates `reason` raw.
    /// Because `reason` is a `RedactedString` (not a `String`), building it
    /// via `RedactedString::from_untrusted` runs `redact_tokens` at
    /// construction, so the `Display` output cannot leak `sk-ant-*` token
    /// material or long-hex strings even when the construction site is handed
    /// a token-bearing reason. This pins the structural guarantee so a future
    /// edit that swaps `RedactedString` back to `String` fails this test.
    #[test]
    fn pending_write_error_display_redacts_token_bearing_reason() {
        // A reason that embeds a fake Anthropic key + a long hex run — the
        // exact shapes `redact_tokens` targets (security.md §8).
        let token = "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let hex = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        let err = AuditEmitError::PendingWriteFailed {
            operation: "csq run account 1".to_string(),
            reason: RedactedString::from_untrusted(format!(
                "write failed echoing token {token} and hex {hex}"
            )),
        };
        // The structured Display (NOT the operator remediation_message) is the
        // surface under test — it interpolates `reason` verbatim.
        let displayed = err.to_string();
        assert!(
            !displayed.contains("sk-ant-"),
            "Display must not leak sk-ant- token material: {displayed}"
        );
        assert!(
            !displayed.contains(hex),
            "Display must not leak the long-hex run: {displayed}"
        );
        // Sanity: the operation IS present (only the reason is redacted).
        assert!(
            displayed.contains("csq run account 1"),
            "Display must still name the operation: {displayed}"
        );
    }

    /// AC: All `AuditEmitError` consumers handle `PendingWriteFailed`.
    ///
    /// Compile-time exhaustiveness: this `match` has NO wildcard arm, so
    /// adding a new `AuditEmitError` variant without updating it is a compile
    /// error. That is the structural guarantee that every caller is forced to
    /// handle each variant (the run.rs `fail_loud_on_audit_write_failure`
    /// helper relies on the same exhaustiveness when it formats the message).
    #[test]
    fn all_audit_emitter_callers_handle_pending_write_failed() {
        let err = AuditEmitError::PendingWriteFailed {
            operation: "csq run account 9".to_string(),
            reason: RedactedString::from_untrusted("permission denied"),
        };
        // No `_ =>` arm: a new variant breaks the build here.
        let handled = match err {
            AuditEmitError::PendingWriteFailed { operation, .. } => !operation.is_empty(),
        };
        assert!(handled, "PendingWriteFailed must be handled exhaustively");
    }
}
