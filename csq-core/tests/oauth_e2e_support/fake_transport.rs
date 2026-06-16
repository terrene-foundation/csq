//! Fake `http_post` closures for the E2E harness.
//!
//! `csq_core::oauth::exchange_code` takes any
//! `Fn(&str, &str) -> Result<Vec<u8>, String>` for the transport. The
//! closures here return canned responses, capture the URL+body for
//! later assertion, or simulate a transport-level error.
//!
//! Each factory returns an `impl Fn(...)` rather than `Arc<dyn Fn>`
//! so it satisfies `exchange_code`'s `F: Fn(&str, &str)` bound
//! directly. The recorder is shared via `Arc<Mutex<...>>` internally
//! so a clone of the recorder handed to the test still sees the
//! captured request after the closure has been moved into
//! `exchange_code`.

use std::sync::{Arc, Mutex};

use super::canned_responses::{invalid_grant_response, ok_response};

/// One captured request: the URL and serialized JSON body.
///
/// `url` is kept on the struct (rather than discarded in the
/// recorder) so future tests can assert "every exchange went to the
/// production token endpoint" without having to re-thread the URL
/// through. Today no test asserts on `url`, hence the
/// `dead_code` allow.
#[derive(Debug, Clone)]
pub struct CapturedRequest {
    #[allow(dead_code)]
    pub url: String,
    pub body: String,
}

/// Recorder shared across producer (the closure) and consumer (the
/// assertion path). Cloning the recorder hands out additional handles
/// to the SAME inner buffer.
#[derive(Default, Clone)]
pub struct RequestRecorder {
    inner: Arc<Mutex<Vec<CapturedRequest>>>,
}

impl RequestRecorder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn last(&self) -> Option<CapturedRequest> {
        let guard = self.inner.lock().expect("recorder mutex poisoned");
        guard.last().cloned()
    }

    /// Returns the number of recorded requests. Useful for asserting
    /// "exchange was called exactly once" in failure-path tests.
    /// Currently unused by any existing test; kept on the API surface
    /// so a future regression can reach for it without re-plumbing
    /// the recorder.
    #[allow(dead_code)]
    pub fn count(&self) -> usize {
        let guard = self.inner.lock().expect("recorder mutex poisoned");
        guard.len()
    }

    fn push(&self, req: CapturedRequest) {
        let mut guard = self.inner.lock().expect("recorder mutex poisoned");
        guard.push(req);
    }
}

/// Returns a transport that records the request and returns the
/// canned 200 token response.
pub fn ok_recording(
    recorder: RequestRecorder,
) -> impl Fn(&str, &str) -> Result<Vec<u8>, String> + Send + Sync + 'static {
    move |url: &str, body: &str| {
        recorder.push(CapturedRequest {
            url: url.to_string(),
            body: body.to_string(),
        });
        Ok(ok_response())
    }
}

/// Returns a transport that records the request and returns the
/// canned 400 `invalid_grant` body.
pub fn invalid_grant_recording(
    recorder: RequestRecorder,
) -> impl Fn(&str, &str) -> Result<Vec<u8>, String> + Send + Sync + 'static {
    move |url: &str, body: &str| {
        recorder.push(CapturedRequest {
            url: url.to_string(),
            body: body.to_string(),
        });
        Ok(invalid_grant_response())
    }
}

/// Returns a transport that simulates a transport-level failure
/// (network unreachable, TLS handshake aborted, DNS fail). The string
/// is fixed-vocabulary, no token material.
pub fn network_error() -> impl Fn(&str, &str) -> Result<Vec<u8>, String> + Send + Sync + 'static {
    |_url: &str, _body: &str| Err("simulated network unreachable".to_string())
}
