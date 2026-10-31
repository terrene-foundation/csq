//! Synthetic transport contract; no network, native vault, or environment mutation.
//! Registered only after the parent has observed the causal CLI baseline RED.

use super::*;
use crate::pool::execution::PoolExecRequest;
use reqwest::header::{HeaderMap, HeaderValue};
use secrecy::SecretString;
use serde_json::{json, Value};
use std::io::Write as _;
use std::net::TcpListener;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    mpsc, Arc,
};
use std::time::Duration;

const TEST_SECRET: &str = "synthetic-private-pool-key";

fn key() -> SecretString {
    SecretString::from(TEST_SECRET.to_owned())
}

fn request(provider: &str) -> PoolExecRequest {
    PoolExecRequest {
        provider: provider.into(),
        model: "synthetic-model".into(),
        prompt: "literal @file /command ${TOKEN} <tool> 🦀".into(),
        system: Some("literal system\nnot an instruction file".into()),
        max_tokens: 17,
        max_input_bytes: 200_000,
        timeout_secs: 2,
    }
}

fn anthropic_body() -> Value {
    json!({
        "id": "synthetic-message", "type": "message", "role": "assistant",
        "model": "actual-served-model",
        "content": [{"type": "text", "text": "literal completion"}],
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 11, "output_tokens": 7,
            "cache_creation_input_tokens": 2, "cache_read_input_tokens": 3}
    })
}

fn openai_body() -> Value {
    json!({
        "id": "synthetic-completion", "object": "chat.completion",
        "model": "actual-served-model",
        "choices": [{"index": 0,
            "message": {"role": "assistant", "content": "literal completion"},
            "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18,
            "prompt_tokens_details": {"cached_tokens": 3},
            "completion_tokens_details": {"reasoning_tokens": 5}}
    })
}

fn response(status: u16, body: Value) -> TransportResponse {
    TransportResponse {
        status,
        headers: HeaderMap::new(),
        body: serde_json::to_vec(&body).unwrap(),
    }
}

fn simulate(
    provider: &str,
    response: TransportResponse,
) -> Result<csq_sdk::Completion, TransportError> {
    complete_with_exchange(
        &request(provider),
        key(),
        crate::pool::REAL_WAIT_CAP,
        move |_, _| Ok(response),
    )
}

#[test]
fn request_shape_is_literal_allowlisted_https_and_sensitive_in_process_auth() {
    for (provider, endpoint, auth_name, auth_value) in [
        (
            "anthropic",
            "https://api.anthropic.com/v1/messages",
            "x-api-key",
            TEST_SECRET.to_owned(),
        ),
        (
            "openai",
            "https://api.openai.com/v1/chat/completions",
            "authorization",
            format!("Bearer {TEST_SECRET}"),
        ),
    ] {
        let req = request(provider);
        let prepared = prepare_request(&req, key()).unwrap();
        assert_eq!(prepared.url, endpoint);
        let url = reqwest::Url::parse(prepared.url).unwrap();
        assert_eq!(url.scheme(), "https");
        assert!(url.username().is_empty());
        assert!(url.password().is_none());
        assert!(url.query().is_none());
        assert!(url.fragment().is_none());
        let auth = prepared.headers.get(auth_name).unwrap();
        assert!(auth.is_sensitive());
        assert_eq!(auth.to_str().unwrap(), auth_value);
        assert!(!format!("{:?}", prepared.headers).contains(TEST_SECRET));
        assert_eq!(prepared.headers["content-type"], "application/json");
        assert!(!prepared.body.to_string().contains(TEST_SECRET));
        if provider == "anthropic" {
            assert!(!prepared.headers.contains_key("authorization"));
            assert_eq!(prepared.headers["anthropic-version"], "2023-06-01");
            assert_eq!(
                prepared.body,
                json!({"model": req.model, "max_tokens": 17,
                "system": req.system.unwrap(),
                "messages": [{"role": "user", "content": req.prompt}]})
            );
        } else {
            assert!(!prepared.headers.contains_key("x-api-key"));
            // Provider-enforced ceiling includes reasoning; max_tokens alone does not.
            // https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create
            assert_eq!(
                prepared.body,
                json!({"model": req.model, "max_completion_tokens": 17,
                "messages": [{"role": "system", "content": req.system.unwrap()},
                    {"role": "user", "content": req.prompt}]})
            );
        }
        // Exact body equality also excludes tools, cache controls, streaming and n>1.
    }
}

#[test]
fn optional_system_is_omitted_and_provider_or_header_injection_never_dispatches() {
    for provider in ["anthropic", "openai"] {
        let mut req = request(provider);
        req.system = None;
        let prepared = prepare_request(&req, key()).unwrap();
        assert!(prepared.body.get("system").is_none());
        assert_eq!(prepared.body["messages"].as_array().unwrap().len(), 1);
        assert_eq!(prepared.body["messages"][0]["role"], "user");
        for hostile in ["synthetic\r\nx-injected: yes", "synthetic\nvalue"] {
            assert!(matches!(
                prepare_request(&req, SecretString::from(hostile.to_owned())),
                Err(TransportError::LocalFailure)
            ));
        }
    }
    for provider in [
        "OPENAI",
        "openai.evil.invalid",
        "https://api.openai.com",
        "anthropic/../openai",
        "unsupported",
    ] {
        let result = complete_with_exchange(
            &request(provider),
            key(),
            crate::pool::REAL_WAIT_CAP,
            |_, _| panic!("unsupported provider reached exchange"),
        );
        assert!(matches!(result, Err(TransportError::Unsupported)));
    }
}

#[test]
fn successful_completion_preserves_actual_model_and_complete_raw_usage() {
    for (provider, body) in [("anthropic", anthropic_body()), ("openai", openai_body())] {
        let completion = simulate(provider, response(200, body)).unwrap();
        assert_eq!(completion.model, "actual-served-model");
        assert_eq!(completion.provider, provider);
        assert_eq!(completion.text, "literal completion");
        assert_eq!(completion.finish_reason, csq_sdk::FinishReason::Stop);
        let usage = completion.usage.unwrap();
        assert_eq!(usage.input_tokens, Some(11));
        // OpenAI completion_tokens already contains its five reasoning tokens.
        assert_eq!(usage.output_tokens, Some(7));
        assert_eq!(usage.cache_read_input_tokens, Some(3));
        assert_eq!(
            usage.cache_creation_input_tokens,
            if provider == "anthropic" {
                Some(2)
            } else {
                None
            }
        );
    }
    let mut body = anthropic_body();
    body["stop_reason"] = json!("max_tokens");
    let completion = simulate("anthropic", response(200, body)).unwrap();
    assert_eq!(completion.finish_reason, csq_sdk::FinishReason::Length);
    assert_eq!(completion.finish_reason_raw.as_deref(), Some("max_tokens"));
    let mut body = openai_body();
    body["choices"][0]["finish_reason"] = json!("length");
    assert_eq!(
        simulate("openai", response(200, body))
            .unwrap()
            .finish_reason,
        csq_sdk::FinishReason::Length
    );
}

#[test]
fn missing_malformed_or_overflowed_accounting_is_unknown_instead_of_zero() {
    for (provider, base, input_field, output_field) in [
        (
            "anthropic",
            anthropic_body(),
            "input_tokens",
            "output_tokens",
        ),
        (
            "openai",
            openai_body(),
            "prompt_tokens",
            "completion_tokens",
        ),
    ] {
        for field in [input_field, output_field] {
            for bad in [
                Value::Null,
                json!(-1),
                json!(1.25),
                json!("11"),
                json!(18446744073709551616.0),
            ] {
                let mut body = base.clone();
                body["usage"][field] = bad;
                assert!(matches!(
                    simulate(provider, response(200, body)),
                    Err(TransportError::Unknown)
                ));
            }
            let mut body = base.clone();
            body["usage"].as_object_mut().unwrap().remove(field);
            assert!(matches!(
                simulate(provider, response(200, body)),
                Err(TransportError::Unknown)
            ));
        }
        for field in ["usage", "model"] {
            let mut body = base.clone();
            body.as_object_mut().unwrap().remove(field);
            assert!(matches!(
                simulate(provider, response(200, body)),
                Err(TransportError::Unknown)
            ));
        }
        let mut body = base.clone();
        body["model"] = json!("");
        assert!(matches!(
            simulate(provider, response(200, body)),
            Err(TransportError::Unknown)
        ));
        let mut body = base;
        body["usage"][input_field] = json!(0);
        body["usage"][output_field] = json!(0);
        if provider == "openai" {
            body["usage"]["prompt_tokens_details"] = json!({"cached_tokens": 0});
            body["usage"]["completion_tokens_details"] = json!({"reasoning_tokens": 0});
        }
        assert_eq!(
            simulate(provider, response(200, body))
                .unwrap()
                .usage
                .unwrap()
                .output_tokens,
            Some(0)
        );
    }
    let mut body = anthropic_body();
    body["usage"]["cache_read_input_tokens"] = json!(-1);
    assert!(matches!(
        simulate("anthropic", response(200, body)),
        Err(TransportError::Unknown)
    ));
    let mut body = openai_body();
    body["usage"]["prompt_tokens_details"]["cached_tokens"] = json!(18446744073709551616.0);
    assert!(matches!(
        simulate("openai", response(200, body)),
        Err(TransportError::Unknown)
    ));
}

#[test]
fn malformed_truncated_or_oversized_success_is_unknown() {
    for provider in ["anthropic", "openai"] {
        for body in [
            b"{\"model\":".to_vec(),
            vec![0xff],
            b"null".to_vec(),
            vec![b'x'; MAX_RESPONSE_BYTES + 1],
        ] {
            assert!(matches!(
                simulate(
                    provider,
                    TransportResponse {
                        status: 200,
                        headers: HeaderMap::new(),
                        body
                    }
                ),
                Err(TransportError::Unknown)
            ));
        }
    }
    let mut body = anthropic_body();
    body["content"] = json!([{"type": "text"}]);
    assert!(matches!(
        simulate("anthropic", response(200, body)),
        Err(TransportError::Unknown)
    ));
    let mut body = openai_body();
    body["choices"] = json!([]);
    assert!(matches!(
        simulate("openai", response(200, body)),
        Err(TransportError::Unknown)
    ));
}

#[test]
fn quota_retry_after_is_bounded_with_fixed_thirty_second_fallback() {
    for provider in ["anthropic", "openai"] {
        for (header, expected) in [
            (Some("17"), 17),
            (None, 30),
            (Some(""), 30),
            (Some("-1"), 30),
            (Some("1.5"), 30),
            (Some("18446744073709551616"), 30),
            (Some("Wed, 01 Jan 2100 00:00:00 GMT"), 30),
        ] {
            let mut raw = response(
                429,
                json!({"error": {"type": "rate_limit_error", "message": TEST_SECRET}}),
            );
            if let Some(value) = header {
                raw.headers
                    .insert("retry-after", HeaderValue::from_str(value).unwrap());
            }
            assert!(
                matches!(simulate(provider, raw), Err(TransportError::Quota { retry_after_secs }) if retry_after_secs == expected)
            );
        }
        let mut raw = response(429, json!({"error": {"code": "insufficient_quota"}}));
        raw.headers
            .insert("retry-after", HeaderValue::from_static("999999999"));
        assert!(
            matches!(simulate(provider, raw), Err(TransportError::Quota { retry_after_secs }) if (1..=MAX_RETRY_AFTER_SECS).contains(&retry_after_secs))
        );
    }
}

#[test]
fn hostile_error_bodies_are_fixed_vocabulary_and_never_retried_or_redirected() {
    for (status, expected) in [
        (401, "Authentication"),
        (403, "Authentication"),
        (400, "Rejected"),
        (302, "Unknown"),
        (307, "Unknown"),
        (500, "Unknown"),
        (529, "Unknown"),
    ] {
        let attempts = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&attempts);
        let mut raw = response(
            status,
            json!({"error": {"message": format!("{TEST_SECRET} /Users/private/secret\nmalicious")}}),
        );
        raw.headers.insert(
            "location",
            HeaderValue::from_static("https://evil.invalid/steal"),
        );
        let result = complete_with_exchange(
            &request("openai"),
            key(),
            crate::pool::REAL_WAIT_CAP,
            move |_, _| {
                observed.fetch_add(1, Ordering::SeqCst);
                Ok(raw)
            },
        );
        let diagnostic = format!("{:?}", result.unwrap_err());
        assert_eq!(diagnostic, expected);
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }
    let attempts = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&attempts);
    let result = complete_with_exchange(
        &request("anthropic"),
        key(),
        crate::pool::REAL_WAIT_CAP,
        move |_, _| {
            observed.fetch_add(1, Ordering::SeqCst);
            Err(TransportError::Unknown)
        },
    );
    assert!(matches!(result, Err(TransportError::Unknown)));
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
}

#[test]
fn expired_deadline_refuses_before_exchange_and_public_trait_matches_contract() {
    let result = complete_with_exchange(&request("anthropic"), key(), Duration::ZERO, |_, _| {
        panic!("expired deadline reached HTTP exchange")
    });
    assert!(matches!(result, Err(TransportError::Unknown)));
    fn accepts_public_contract(transport: &dyn PoolTransport, request: &PoolExecRequest) {
        let result: Result<csq_sdk::Completion, TransportError> =
            transport.complete(request, key(), Duration::ZERO);
        assert!(matches!(result, Err(TransportError::Unknown)));
    }
    accepts_public_contract(&HttpPoolTransport, &request("openai"));
}

#[tokio::test(flavor = "current_thread")]
async fn blocking_exchange_runs_off_callers_tokio_thread() {
    let caller = std::thread::current().id();
    let completion = complete_with_exchange(
        &request("anthropic"),
        key(),
        crate::pool::REAL_WAIT_CAP,
        move |_, remaining| {
            assert_ne!(std::thread::current().id(), caller);
            assert!(remaining > Duration::ZERO && remaining <= crate::pool::REAL_WAIT_CAP);
            // Construction AND destruction of reqwest blocking's runtime stay off Tokio.
            let client = reqwest::blocking::Client::builder()
                .no_proxy()
                .build()
                .unwrap();
            drop(client);
            Ok(response(200, anthropic_body()))
        },
    )
    .unwrap();
    assert_eq!(completion.text, "literal completion");
}

#[test]
fn observer_deadline_returns_unknown_without_waiting_for_or_replaying_worker() {
    let (release_tx, release_rx) = mpsc::channel();
    let (finished_tx, finished_rx) = mpsc::channel();
    let attempts = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&attempts);
    let result = complete_with_exchange(
        &request("openai"),
        key(),
        Duration::from_millis(100),
        move |_, _| {
            observed.fetch_add(1, Ordering::SeqCst);
            release_rx.recv_timeout(crate::pool::REAL_WAIT_CAP).unwrap();
            finished_tx.send(()).unwrap();
            Ok(response(200, openai_body()))
        },
    );
    // Release even if this assertion fails, so no worker remains blocked.
    release_tx.send(()).unwrap();
    assert!(matches!(result, Err(TransportError::Unknown)));
    finished_rx
        .recv_timeout(crate::pool::REAL_WAIT_CAP)
        .unwrap();
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
}

// Serve a real redirect and record all requests until the client has returned.
// The same-origin target retains both auth header types under reqwest's default
// redirect policy, so removing Policy::none() exposes a semantic failure.
fn local_redirect_fixture() -> (
    String,
    mpsc::Sender<()>,
    std::thread::JoinHandle<Vec<String>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let (stop_tx, stop_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let deadline = Instant::now() + crate::pool::REAL_WAIT_CAP;
        let mut requests = Vec::new();
        loop {
            match listener.accept() {
                Ok((mut socket, _)) => {
                    socket
                        .set_read_timeout(Some(crate::pool::REAL_WAIT_CAP))
                        .unwrap();
                    socket
                        .set_write_timeout(Some(crate::pool::REAL_WAIT_CAP))
                        .unwrap();
                    let mut header = Vec::new();
                    while !header.ends_with(b"\r\n\r\n") {
                        assert!(header.len() < 16 * 1024);
                        let mut byte = [0];
                        socket.read_exact(&mut byte).unwrap();
                        header.push(byte[0]);
                    }
                    let header = String::from_utf8(header).unwrap().to_ascii_lowercase();
                    let length = header
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length:"))
                        .map(|value| value.trim().parse::<usize>().unwrap())
                        .unwrap_or(0);
                    assert!(length <= 1024);
                    socket.read_exact(&mut vec![0; length]).unwrap();
                    let reply = if requests.is_empty() {
                        format!("HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{address}/redirected\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    } else {
                        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            .to_owned()
                    };
                    requests.push(header);
                    socket.write_all(reply.as_bytes()).unwrap();
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    match stop_rx.recv_timeout(Duration::from_millis(5)) {
                        Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => return requests,
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                    }
                    assert!(
                        Instant::now() < deadline,
                        "local redirect fixture did not finish"
                    );
                }
                Err(error) => panic!("local fixture accept: {error}"),
            }
        }
    });
    (format!("http://{address}/initial"), stop_tx, worker)
}

#[test]
fn actual_pool_client_never_forwards_either_auth_header_on_307() {
    for provider in ["anthropic", "openai"] {
        let prepared = prepare_request(&request(provider), key()).unwrap();
        let (url, stop, server) = local_redirect_fixture();
        // Only HTTPS enforcement is relaxed for the loopback fixture. Redirect,
        // retry and proxy configuration are the production client's actual code.
        let client = pool_client(crate::pool::REAL_WAIT_CAP)
            .https_only(false)
            .build()
            .unwrap();
        let result = client
            .post(url)
            .headers(prepared.headers)
            .body("fixture")
            .send();
        stop.send(()).unwrap();
        let requests = server.join().unwrap();
        assert!(requests
            .first()
            .is_some_and(|headers| headers.contains(TEST_SECRET)));
        let forwarded_auth = requests
            .iter()
            .skip(1)
            .any(|headers| headers.contains("x-api-key:") || headers.contains("authorization:"));
        assert!(
            !forwarded_auth,
            "redirect forwarded a synthetic credential header"
        );
        assert_eq!(requests.len(), 1, "client followed a provider redirect");
        assert_eq!(result.unwrap().status().as_u16(), 307);
    }
}

#[test]
fn deterministic_worker_spawn_failure_is_local_and_never_dispatches() {
    let attempted = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&attempted);
    let result = complete_with_spawner(
        &request("openai"),
        key(),
        crate::pool::REAL_WAIT_CAP,
        move |_, _| {
            observed.fetch_add(1, Ordering::SeqCst);
            Ok(response(200, openai_body()))
        },
        |_job| Err(std::io::Error::other("synthetic spawn refusal")),
    );
    assert!(matches!(result, Err(TransportError::LocalFailure)));
    assert_eq!(attempted.load(Ordering::SeqCst), 0);
    assert_eq!(format!("{:?}", result.unwrap_err()), "LocalFailure");
}

#[test]
fn malformed_auth_is_local_and_never_creates_worker_or_exchange() {
    let result = complete_with_spawner(
        &request("anthropic"),
        SecretString::from("synthetic\r\nprivate".to_owned()),
        crate::pool::REAL_WAIT_CAP,
        |_, _| panic!("malformed auth reached exchange"),
        |_job| panic!("malformed auth reached worker spawn"),
    );
    assert!(matches!(result, Err(TransportError::LocalFailure)));
}
