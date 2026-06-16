//! End-to-end integration tests for the csq-ledger server (M10).
//!
//! These tests spawn the real `csq-ledger` binary as a child process against a
//! tempdir data directory and an ephemeral port, then drive it over HTTP with
//! `reqwest`. They exercise the user-facing path: build → run → submit → query
//! → verify, plus the crash-safety (fsync-before-200) and anchor-cadence
//! properties.
//!
//! Per `rules/testing.md` Rule 4 + 4a: the child is spawned with `env_clear()`
//! + a stdlib whitelist, and all paths are tempdir-rooted.

use std::process::{Child, Command, Stdio};
use std::time::Duration;

use serde_json::Value;
use tempfile::TempDir;

/// Path to the built `csq-ledger` binary (cargo sets CARGO_BIN_EXE_<name>).
const LEDGER_BIN: &str = env!("CARGO_BIN_EXE_csq-ledger");

/// Picks an ephemeral free TCP port by binding to :0 and reading it back.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    listener.local_addr().unwrap().port()
}

/// A spawned ledger server child + its base URL.
struct LedgerServer {
    child: Child,
    base_url: String,
    #[allow(dead_code)]
    data_dir: TempDir,
}

impl LedgerServer {
    /// Spawns the binary against a fresh tempdir + ephemeral port, waiting for
    /// `/v1/health` to answer. `extra_args` appends anchor flags when needed.
    fn spawn(extra_args: &[&str]) -> Self {
        let data_dir = TempDir::new().unwrap();
        let port = free_port();
        let mut cmd = clean_command();
        cmd.arg("--data-dir")
            .arg(data_dir.path())
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .args(extra_args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child = cmd.spawn().expect("spawn csq-ledger");
        let base_url = format!("http://127.0.0.1:{port}");
        let server = Self {
            child,
            base_url,
            data_dir,
        };
        server.wait_for_health();
        server
    }

    /// Polls `/v1/health` until it answers 200 (or times out).
    fn wait_for_health(&self) {
        let client = reqwest::blocking::Client::new();
        for _ in 0..100 {
            if let Ok(resp) = client.get(format!("{}/v1/health", self.base_url)).send() {
                if resp.status().is_success() {
                    return;
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("csq-ledger did not become healthy in time");
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }
}

/// POSTs `body` as JSON (the workspace reqwest pin lacks the `json` feature, so
/// we serialize + set the header manually). Returns `(status, parsed_json)`.
fn post_json(client: &reqwest::blocking::Client, url: &str, body: &Value) -> (u16, Value) {
    let resp = client
        .post(url)
        .header("content-type", "application/json")
        .body(serde_json::to_vec(body).unwrap())
        .send()
        .expect("post");
    let status = resp.status().as_u16();
    let text = resp.text().unwrap_or_default();
    let json = serde_json::from_str(&text).unwrap_or(Value::Null);
    (status, json)
}

/// GETs `url`, returning `(status, parsed_json)`.
fn get_json(client: &reqwest::blocking::Client, url: &str) -> (u16, Value) {
    let resp = client.get(url).send().expect("get");
    let status = resp.status().as_u16();
    let text = resp.text().unwrap_or_default();
    let json = serde_json::from_str(&text).unwrap_or(Value::Null);
    (status, json)
}

impl Drop for LedgerServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Builds a Command with env_clear() + stdlib whitelist (rules/testing.md 4a).
///
/// The whitelist carries both the Unix stdlib vars and the Windows-essential
/// vars. `SYSTEMROOT`/`SystemRoot` is load-bearing on Windows: a process that
/// opens TCP sockets needs it for winsock DLL initialization, without which
/// `TcpListener::bind` fails and the server never becomes healthy. The temp +
/// profile vars (`TEMP`/`TMP`/`USERPROFILE`/`APPDATA`/`LOCALAPPDATA`/`WINDIR`/
/// `ComSpec`/`PATHEXT`/`NUMBER_OF_PROCESSORS`) cover normal Windows operation.
/// Vars absent on the current OS are simply skipped by the `if let Ok` guard,
/// so listing the Windows vars unconditionally has no effect on Unix.
fn clean_command() -> Command {
    let mut cmd = Command::new(LEDGER_BIN);
    cmd.env_clear();
    for k in [
        // Unix stdlib whitelist.
        "HOME",
        "PATH",
        "LANG",
        "LC_ALL",
        "TERM",
        "USER",
        "TMPDIR",
        // Windows-essential: winsock + temp/profile dirs. Absent on Unix.
        "SYSTEMROOT",
        "SystemRoot",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "WINDIR",
        "ComSpec",
        "PATHEXT",
        "NUMBER_OF_PROCESSORS",
    ] {
        if let Ok(v) = std::env::var(k) {
            cmd.env(k, v);
        }
    }
    cmd
}

/// Builds a minimal valid SignedRecord JSON for a given ULID record id.
fn record_json(record_id: &str, run_id: &str) -> Value {
    serde_json::json!({
        "schema_version": "2",
        "record_id": record_id,
        "chain_id": "01JZ00000000000000000000XY",
        "seq": 0,
        "prev_hash": "0".repeat(64),
        "kind": "csq_run",
        "payload": { "kind": "csq_run", "data": { "run_id": run_id } },
        "ts": "2026-05-29T00:00:00+00:00",
        "key_id": format!("ed25519:{}", "0".repeat(64)),
        "canonical_hash": "0".repeat(64),
        "signature": "0".repeat(128)
    })
}

/// Generates a 26-char Crockford-Base32 ULID-shaped id for index `i`.
fn ulid_for(i: usize) -> String {
    // Fixed 20-char prefix + 6-digit zero-padded index (digits are Crockford).
    format!("01JZ00000000000000{i:08}")
}

/// `test csq_ledger_server_submit_100_records_and_verify_proofs`
///
/// Spawn the server, submit 100 records, verify each submit returns a proof
/// that verifies against the returned checkpoint, and assert the final
/// checkpoint tree size is 100.
#[test]
fn csq_ledger_server_submit_100_records_and_verify_proofs() {
    let server = LedgerServer::spawn(&[]);
    let client = reqwest::blocking::Client::new();

    let mut last_checkpoint_size = 0u64;
    for i in 0..100usize {
        let id = ulid_for(i);
        let body = record_json(&id, &format!("run-{i}"));
        let (status, json) = post_json(&client, &server.url("/v1/log/entries"), &body);
        assert_eq!(status, 200, "submit {i} should 200");
        assert_eq!(json["log_index"].as_u64().unwrap(), i as u64);
        assert!(json["inclusion_proof"].is_array());
        last_checkpoint_size = json["checkpoint_at_submit"]["tree_size"].as_u64().unwrap();
    }
    assert_eq!(
        last_checkpoint_size, 100,
        "final checkpoint tree_size == 100"
    );

    // Independent checkpoint fetch confirms the persisted tree size.
    let (_, cp) = get_json(&client, &server.url("/v1/checkpoint"));
    assert_eq!(cp["tree_size"].as_u64().unwrap(), 100);

    // Spot-check: GET a sample record back by id.
    let sample_id = ulid_for(42);
    let (_, entry) = get_json(
        &client,
        &server.url(&format!("/v1/log/entries/{sample_id}")),
    );
    assert_eq!(entry["record"]["record_id"].as_str().unwrap(), sample_id);
    assert_eq!(entry["log_index"].as_u64().unwrap(), 42);
}

/// `test csq_ledger_record_durable_before_200`
///
/// fsync-before-200 crash-safety: submit records, SIGKILL the server, restart
/// against the SAME data dir, and assert every previously-200'd record is
/// still queryable. Because `append` fsyncs before returning 200, every record
/// the client saw a 200 for survives an abrupt kill.
#[test]
fn csq_ledger_record_durable_before_200() {
    let data_dir = TempDir::new().unwrap();
    let client = reqwest::blocking::Client::new();

    // Phase 1: spawn, submit 25 records (each 200'd ⇒ fsync'd), then SIGKILL.
    // We spawn directly (not via the LedgerServer helper) so the data dir is
    // shared across the restart in phase 2.
    let acked_ids: Vec<String> = {
        let mut ids = Vec::new();
        let port = free_port();
        let mut child = clean_command()
            .arg("--data-dir")
            .arg(data_dir.path())
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn");
        let base = format!("http://127.0.0.1:{port}");
        // Wait for health.
        for _ in 0..100 {
            if client
                .get(format!("{base}/v1/health"))
                .send()
                .map(|r| r.status().is_success())
                .unwrap_or(false)
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        for i in 0..25usize {
            let id = ulid_for(i);
            let (status, _) = post_json(
                &client,
                &format!("{base}/v1/log/entries"),
                &record_json(&id, &format!("run-{i}")),
            );
            assert_eq!(status, 200);
            ids.push(id);
        }
        // SIGKILL — abrupt termination, no graceful shutdown.
        child.kill().expect("kill");
        child.wait().expect("wait");
        ids
    };

    // Phase 2: restart against the SAME data dir, assert all acked records present.
    let port = free_port();
    let mut child = clean_command()
        .arg("--data-dir")
        .arg(data_dir.path())
        .arg("--bind")
        .arg("127.0.0.1")
        .arg("--port")
        .arg(port.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("respawn");
    let base = format!("http://127.0.0.1:{port}");
    for _ in 0..100 {
        if client
            .get(format!("{base}/v1/health"))
            .send()
            .map(|r| r.status().is_success())
            .unwrap_or(false)
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    let (_, cp) = get_json(&client, &format!("{base}/v1/checkpoint"));
    assert_eq!(
        cp["tree_size"].as_u64().unwrap(),
        25,
        "all fsync'd records recovered after SIGKILL"
    );
    for id in &acked_ids {
        let (status, _) = get_json(&client, &format!("{base}/v1/log/entries/{id}"));
        assert_eq!(status, 200, "record {id} queryable after restart");
    }

    let _ = child.kill();
    let _ = child.wait();
}

/// `test csq_ledger_anchor_to_sink_populates_checkpoint_anchored_to_field`
///
/// Spawn with `--anchor-to-sink rekor --anchor-cadence 1` (1-second cadence so
/// the test does not wait a day), submit a record, wait for the cadence task to
/// anchor, then assert `GET /v1/checkpoint` surfaces the `anchored_to` field.
///
/// Requires the binary built with `--features anchor-rekor`.
#[cfg(feature = "anchor-rekor")]
#[test]
fn csq_ledger_anchor_to_sink_populates_checkpoint_anchored_to_field() {
    let server = LedgerServer::spawn(&["--anchor-to-sink", "rekor", "--anchor-cadence", "1"]);
    let client = reqwest::blocking::Client::new();

    // Submit one record so the tree is non-empty.
    post_json(
        &client,
        &server.url("/v1/log/entries"),
        &record_json(&ulid_for(0), "run-0"),
    );

    // Wait up to ~15s for the cadence task to anchor (cadence is 1s). The loop
    // exits early on success, so the happy path stays fast (~1-2s); only a stuck
    // anchor pays the full ceiling. Widened from ~5s to remove a latent flake
    // under the load the M10 test binary adds (deep-F5).
    let mut anchored = false;
    for _ in 0..150 {
        let (_, cp) = get_json(&client, &server.url("/v1/checkpoint"));
        if cp.get("anchored_to").map(|v| !v.is_null()).unwrap_or(false) {
            assert_eq!(cp["anchored_to"]["sink"].as_str().unwrap(), "rekor");
            assert!(cp["anchored_to"]["anchor_id"]
                .as_str()
                .unwrap()
                .starts_with("rekor-log-"));
            anchored = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        anchored,
        "anchored_to field should populate after the cadence interval"
    );
}

/// `test csq_ledger_first_boot_auto_generates_key_and_warns`
///
/// Fresh data dir, no CSQ_LEDGER_SIGNING_KEY_PATH → the key file is created and
/// `/v1/health` surfaces the backup WARN. The stderr also carries the WARN.
#[test]
fn csq_ledger_first_boot_auto_generates_key_and_warns() {
    let data_dir = TempDir::new().unwrap();
    let port = free_port();
    let mut child = clean_command()
        .arg("--data-dir")
        .arg(data_dir.path())
        .arg("--bind")
        .arg("127.0.0.1")
        .arg("--port")
        .arg(port.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    let base = format!("http://127.0.0.1:{port}");
    let client = reqwest::blocking::Client::new();
    for _ in 0..100 {
        if client
            .get(format!("{base}/v1/health"))
            .send()
            .map(|r| r.status().is_success())
            .unwrap_or(false)
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // Key file created at 0o600.
    let key_path = data_dir.path().join("signing-key.pem");
    assert!(key_path.exists(), "signing key auto-generated");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "signing key is 0o600");
    }

    // Health surfaces the WARN.
    let (_, health) = get_json(&client, &format!("{base}/v1/health"));
    assert_eq!(health["status"].as_str().unwrap(), "ok");
    assert!(
        health
            .get("signing_key_warning")
            .map(|v| !v.is_null())
            .unwrap_or(false),
        "first-boot auto-key WARN surfaced on /v1/health"
    );

    let _ = child.kill();
    let _ = child.wait();

    // Restart WITH the env var set → WARN cleared.
    let port2 = free_port();
    let mut child2 = clean_command()
        .env("CSQ_LEDGER_SIGNING_KEY_PATH", &key_path)
        .arg("--data-dir")
        .arg(data_dir.path())
        .arg("--bind")
        .arg("127.0.0.1")
        .arg("--port")
        .arg(port2.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("respawn");
    let base2 = format!("http://127.0.0.1:{port2}");
    for _ in 0..100 {
        if client
            .get(format!("{base2}/v1/health"))
            .send()
            .map(|r| r.status().is_success())
            .unwrap_or(false)
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let (_, health2) = get_json(&client, &format!("{base2}/v1/health"));
    assert!(
        health2
            .get("signing_key_warning")
            .map(|v| v.is_null())
            .unwrap_or(true),
        "explicit CSQ_LEDGER_SIGNING_KEY_PATH clears the WARN"
    );

    let _ = child2.kill();
    let _ = child2.wait();
}

/// `test csq_ledger_oversized_body_is_rejected`
///
/// An unauthenticated client cannot OOM/disk-fill the server with a giant body:
/// the router pins a 64 KiB `DefaultBodyLimit`, so a body well over that cap is
/// rejected with 413 (Payload Too Large) and NEVER reaches the durability path.
/// (security-M1 + rust-R4.)
#[test]
fn csq_ledger_oversized_body_is_rejected() {
    let server = LedgerServer::spawn(&[]);
    let client = reqwest::blocking::Client::new();

    // A 256 KiB body — 4x the 64 KiB cap.
    let oversized = vec![b'x'; 256 * 1024];
    match client
        .post(server.url("/v1/log/entries"))
        .header("content-type", "application/json")
        .body(oversized)
        .send()
    {
        Ok(resp) => {
            let status = resp.status().as_u16();
            assert!(
                status == 413 || status == 400,
                "oversized body must be rejected (413/400); got {status}"
            );
        }
        // The server may emit 413 and close the socket before the client has
        // finished writing the 256 KiB body; reqwest then surfaces a
        // body-write/connection-reset error instead of the response (observed
        // on macOS CI: hyper BodyWrite, ECONNRESET os error 54). Either
        // outcome proves the body was refused — the empty-tree assertion
        // below is the authoritative check that nothing reached the
        // durability path.
        Err(e) => {
            assert!(
                !e.is_timeout(),
                "oversized post must be rejected promptly, not hang: {e:?}"
            );
        }
    }

    // The server is still healthy + the tree is still empty (the oversized body
    // never reached the durability path).
    let (_, cp) = get_json(&client, &server.url("/v1/checkpoint"));
    assert_eq!(
        cp["tree_size"].as_u64().unwrap(),
        0,
        "oversized body did not append a record"
    );
}

/// `test csq_ledger_unknown_record_returns_404`
#[test]
fn csq_ledger_unknown_record_returns_404() {
    let server = LedgerServer::spawn(&[]);
    let client = reqwest::blocking::Client::new();
    let (status, _) = get_json(
        &client,
        &server.url("/v1/log/entries/01JZ00000000000000000000ZZ"),
    );
    assert_eq!(status, 404);
}

/// `test csq_ledger_overload_sheds_503_not_crash`
///
/// Defense-in-depth (M10 NIT): verifies that `POST /v1/log/entries` returns
/// HTTP 503 (service unavailable) when the `MAX_INFLIGHT_SUBMITS` semaphore is
/// exhausted — NOT a panic, NOT a 500 — and that permits release cleanly so a
/// subsequent request gets 200.
///
/// # Mechanism — deterministic pre-exhaustion (no wall-clock race)
///
/// The original test fired 96 concurrent HTTP threads at a live TCP server and
/// raced fsync latency to saturate a 32-permit semaphore. On fast-fsync runners
/// (GitHub ubuntu-latest) permits could release faster than requests piled up →
/// 0 × 503 → flaky `assert!(n_503 >= 1)` panic. Racing wall-clock timing is
/// fundamentally non-deterministic regardless of N_BURST.
///
/// This replacement is in-process (`#[tokio::test]`) with zero timing
/// dependence:
///
/// 1. Build `AppState` + `build_router` from the crate's lib API (TempDir-backed
///    store, auto-generated signing key, no anchor).
/// 2. **Acquire ALL `MAX_INFLIGHT_SUBMITS` permits upfront and hold them.**
///    `state.submit_limit.available_permits() == 0` is now a structural fact,
///    not a race outcome.
/// 3. Drive one submit through the router via `tower::ServiceExt::oneshot`.
///    Assert **503** — deterministic because the semaphore is provably exhausted.
/// 4. Assert the 503 body carries `error: "overloaded"` (proves it is the shed
///    path, not some other 503).
/// 5. Drop the permit guard (releases all permits). Assert
///    `available_permits() == MAX_INFLIGHT_SUBMITS` again.
/// 6. Drive a second submit (unique record_id) → assert **200** (proves permits
///    released, server is not permanently wedged).
///
/// The `clean_command()` helper and env-whitelist rules (testing.md Rule 4a)
/// do NOT apply here — there is no subprocess, no TCP bind, and no OS socket.
#[tokio::test]
async fn csq_ledger_overload_sheds_503_not_crash() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use csq_ledger::server::{build_router, AppState, MAX_INFLIGHT_SUBMITS};
    use csq_ledger::signing::ServerSigningKey;
    use csq_ledger::storage::LedgerStore;
    use std::sync::Arc;
    use tower::ServiceExt as _;

    // ── Step 1: build in-process AppState + router ───────────────────────────
    let dir = TempDir::new().unwrap();
    let store = LedgerStore::open(dir.path()).unwrap();
    let signing_key = ServerSigningKey::load_or_generate(dir.path(), None).unwrap();
    let state = Arc::new(AppState::new(store, signing_key, None));
    let router = build_router(Arc::clone(&state));

    // ── Step 2: pre-exhaust the semaphore — zero permits remain ──────────────
    // `try_acquire_many_owned` on the Arc clone is Send + 'static so the guard
    // may outlive the local frame. It returns Err only when n > total capacity,
    // which cannot happen here.
    let held = state
        .submit_limit
        .clone()
        .try_acquire_many_owned(MAX_INFLIGHT_SUBMITS as u32)
        .expect("acquire all permits: capacity is exactly MAX_INFLIGHT_SUBMITS");
    assert_eq!(
        state.submit_limit.available_permits(),
        0,
        "semaphore must be fully exhausted before the 503 probe"
    );

    // ── Step 3: one submit while the semaphore is exhausted → expect 503 ─────
    // Use an index outside the ranges used by the spawned-server tests (0..99,
    // 100..195) so records are disjoint even if tests somehow share state.
    let shed_body = serde_json::to_vec(&record_json(&ulid_for(500), "shed-run-0")).unwrap();
    let shed_req = Request::builder()
        .method("POST")
        .uri("/v1/log/entries")
        .header("content-type", "application/json")
        .body(Body::from(shed_body))
        .unwrap();

    let shed_resp: axum::response::Response = router
        .clone()
        .oneshot(shed_req)
        .await
        .expect("oneshot must not fail at the transport layer");

    assert_eq!(
        shed_resp.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "exhausted semaphore must produce 503 SERVICE_UNAVAILABLE, not {:?}",
        shed_resp.status()
    );

    // ── Step 4: assert 503 body is the "overloaded" shed path ────────────────
    let shed_bytes = axum::body::to_bytes(shed_resp.into_body(), 4096)
        .await
        .unwrap();
    let shed_json: serde_json::Value = serde_json::from_slice(&shed_bytes).unwrap();
    assert_eq!(
        shed_json["error"].as_str(),
        Some("overloaded"),
        "503 body must carry error=overloaded (the shed path, not an internal 500); \
         got: {shed_json}"
    );

    // ── Step 5: release all permits ──────────────────────────────────────────
    drop(held);
    assert_eq!(
        state.submit_limit.available_permits(),
        MAX_INFLIGHT_SUBMITS,
        "all permits must be returned after the guard is dropped"
    );

    // ── Step 6: a normal submit after release must succeed ───────────────────
    // Proves the server is not permanently wedged; permits genuinely released.
    let ok_body = serde_json::to_vec(&record_json(&ulid_for(501), "shed-run-1")).unwrap();
    let ok_req = Request::builder()
        .method("POST")
        .uri("/v1/log/entries")
        .header("content-type", "application/json")
        .body(Body::from(ok_body))
        .unwrap();

    let ok_resp: axum::response::Response = router
        .oneshot(ok_req)
        .await
        .expect("post-release oneshot must not fail");

    assert_eq!(
        ok_resp.status(),
        StatusCode::OK,
        "post-release submit must return 200 OK (server not permanently wedged)"
    );
}
