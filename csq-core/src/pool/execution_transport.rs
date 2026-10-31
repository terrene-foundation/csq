//! One bounded, non-replayed community API attempt with in-process credentials.

use super::execution::PoolExecRequest;
use csq_sdk::{Completion, FinishReason, Usage};
use reqwest::header::{HeaderMap, HeaderValue};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{json, Value};
use std::io::Read;
use std::sync::mpsc;
use std::time::{Duration, Instant};

const ANTHROPIC_URL: &str = "https://api.anthropic.com/v1/messages";
const OPENAI_URL: &str = "https://api.openai.com/v1/chat/completions";
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_RETRY_AFTER_SECS: u64 = 3600;

/// Closed vocabulary: never carries an upstream body, header, URL, or secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TransportError {
    Quota {
        retry_after_secs: u64,
    },
    Authentication,
    Rejected,
    Unsupported,
    /// Definitely no HTTP dispatch; the coordinator can release its hold.
    LocalFailure,
    Unknown,
}

pub(crate) trait PoolTransport {
    fn complete(
        &self,
        request: &PoolExecRequest,
        key: SecretString,
        remaining: Duration,
    ) -> Result<Completion, TransportError>;
}

pub(crate) struct HttpPoolTransport;

impl PoolTransport for HttpPoolTransport {
    fn complete(
        &self,
        request: &PoolExecRequest,
        key: SecretString,
        remaining: Duration,
    ) -> Result<Completion, TransportError> {
        complete_with_exchange(request, key, remaining, send_http)
    }
}

// Deliberately no Debug: the prompt and headers are private request data.
struct PreparedRequest {
    url: &'static str,
    headers: HeaderMap,
    body: Value,
    deadline: Option<Instant>,
}

struct TransportResponse {
    status: u16,
    headers: HeaderMap,
    body: Vec<u8>,
}

fn prepare_request(
    request: &PoolExecRequest,
    key: SecretString,
) -> Result<PreparedRequest, TransportError> {
    let (url, auth_name) = match request.provider.as_str() {
        "anthropic" => (ANTHROPIC_URL, "x-api-key"),
        "openai" => (OPENAI_URL, "authorization"),
        _ => return Err(TransportError::Unsupported),
    };
    if request.model.is_empty() || request.max_tokens == 0 || key.expose_secret().is_empty() {
        return Err(TransportError::LocalFailure);
    }
    // The temporary Bearer copy is wiped by SecretString on drop.
    let auth = if auth_name == "authorization" {
        SecretString::from(format!("Bearer {}", key.expose_secret()))
    } else {
        key
    };
    let mut value =
        HeaderValue::from_str(auth.expose_secret()).map_err(|_| TransportError::LocalFailure)?;
    value.set_sensitive(true);
    let mut headers = HeaderMap::new();
    headers.insert(auth_name, value);
    headers.insert("content-type", HeaderValue::from_static("application/json"));
    let body = if request.provider == "anthropic" {
        headers.insert("anthropic-version", HeaderValue::from_static("2023-06-01"));
        let mut body = json!({"model": request.model, "max_tokens": request.max_tokens,
            "messages": [{"role": "user", "content": request.prompt}]});
        if let Some(system) = &request.system {
            body["system"] = json!(system);
        }
        body
    } else {
        let mut messages = Vec::with_capacity(2);
        if let Some(system) = &request.system {
            messages.push(json!({"role": "system", "content": system}));
        }
        messages.push(json!({"role": "user", "content": request.prompt}));
        // Includes visible AND reasoning tokens in the enforced output bound.
        json!({"model": request.model, "max_completion_tokens": request.max_tokens,
            "messages": messages})
    };
    Ok(PreparedRequest {
        url,
        headers,
        body,
        deadline: None,
    })
}

fn complete_with_exchange<F>(
    request: &PoolExecRequest,
    key: SecretString,
    remaining: Duration,
    exchange: F,
) -> Result<Completion, TransportError>
where
    F: FnOnce(PreparedRequest, Duration) -> Result<TransportResponse, TransportError>
        + Send
        + 'static,
{
    complete_with_spawner(request, key, remaining, exchange, |job| {
        std::thread::Builder::new()
            .name("csq-pool-http".into())
            .spawn(job)
            .map(|_| ())
    })
}

/// The wait here is real socket/worker I/O, so it reads the real monotonic clock on
/// purpose: it enforces the `remaining` budget the execution clock already decided.
fn complete_with_spawner<F, S>(
    request: &PoolExecRequest,
    key: SecretString,
    remaining: Duration,
    exchange: F,
    spawn: S,
) -> Result<Completion, TransportError>
where
    F: FnOnce(PreparedRequest, Duration) -> Result<TransportResponse, TransportError>
        + Send
        + 'static,
    S: FnOnce(Box<dyn FnOnce() + Send>) -> std::io::Result<()>,
{
    let deadline = Instant::now()
        .checked_add(remaining)
        .ok_or(TransportError::Unknown)?;
    if remaining.is_zero() {
        return Err(TransportError::Unknown);
    }
    let mut prepared = prepare_request(request, key)?;
    prepared.deadline = Some(deadline);
    let provider = request.provider.clone();
    let (sender, receiver) = mpsc::sync_channel(1);
    // reqwest blocking creates/destroys a runtime. Both operations must happen
    // outside a caller's Tokio runtime, including CLI handlers inside Tokio.
    spawn(Box::new(move || {
        let result = (|| {
            let left = remaining_until(deadline)?;
            let response = exchange(prepared, left)?;
            remaining_until(deadline)?;
            parse_response(&provider, response)
        })();
        // Observer expiry leaves accounting uncertain. Never replay or join the
        // worker; a late result is discarded without releasing the ledger hold.
        let _ = sender.send(result);
    }))
    .map_err(|_| TransportError::LocalFailure)?;
    receiver
        .recv_timeout(remaining_until(deadline)?)
        .map_err(|_| TransportError::Unknown)?
}

fn remaining_until(deadline: Instant) -> Result<Duration, TransportError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
        .ok_or(TransportError::Unknown)
}

fn send_http(
    prepared: PreparedRequest,
    remaining: Duration,
) -> Result<TransportResponse, TransportError> {
    if !matches!(prepared.url, ANTHROPIC_URL | OPENAI_URL) {
        return Err(TransportError::Unsupported);
    }
    let deadline = prepared.deadline.ok_or(TransportError::LocalFailure)?;
    let client = pool_client(remaining)
        .build()
        .map_err(|_| TransportError::LocalFailure)?;
    let body = serde_json::to_vec(&prepared.body).map_err(|_| TransportError::LocalFailure)?;
    // Building the client and serializing the prompt consume the SAME budget.
    let response = client
        .post(prepared.url)
        .headers(prepared.headers)
        .body(body)
        .timeout(remaining_until(deadline)?)
        .send()
        .map_err(|_| TransportError::Unknown)?;
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    // Error bodies are never needed to classify definite status refusals.
    if status != 200 {
        return Ok(TransportResponse {
            status,
            headers,
            body: Vec::new(),
        });
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(TransportError::Unknown);
    }
    let mut body = Vec::new();
    response
        .take(MAX_RESPONSE_BYTES as u64 + 1)
        .read_to_end(&mut body)
        .map_err(|_| TransportError::Unknown)?;
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(TransportError::Unknown);
    }
    Ok(TransportResponse {
        status,
        headers,
        body,
    })
}

/// Tests relax only HTTPS enforcement for loopback. Every other client policy
/// is shared with production, so the redirect regression executes this code.
fn pool_client(remaining: Duration) -> reqwest::blocking::ClientBuilder {
    reqwest::blocking::Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .timeout(remaining)
        .connect_timeout(remaining.min(Duration::from_secs(5)))
}

fn parse_response(
    provider: &str,
    response: TransportResponse,
) -> Result<Completion, TransportError> {
    match response.status {
        429 => {
            return Err(TransportError::Quota {
                retry_after_secs: retry_after(&response.headers),
            })
        }
        401 | 403 => return Err(TransportError::Authentication),
        400 | 404 | 405 | 413 | 415 | 422 => return Err(TransportError::Rejected),
        200 => {}
        _ => return Err(TransportError::Unknown),
    }
    if response.body.len() > MAX_RESPONSE_BYTES {
        return Err(TransportError::Unknown);
    }
    let body: Value =
        serde_json::from_slice(&response.body).map_err(|_| TransportError::Unknown)?;
    let model = body
        .get("model")
        .and_then(Value::as_str)
        .filter(|model| !model.is_empty())
        .ok_or(TransportError::Unknown)?;
    let usage = body
        .get("usage")
        .filter(|usage| usage.is_object())
        .ok_or(TransportError::Unknown)?;
    let (text, raw, finish, usage) = match provider {
        "anthropic" => parse_anthropic(&body, usage)?,
        "openai" => parse_openai(&body, usage)?,
        _ => return Err(TransportError::Unsupported),
    };
    Ok(Completion::new(text, model, provider, finish)
        .with_usage(usage)
        .with_finish_reason_raw(raw))
}

fn retry_after(headers: &HeaderMap) -> u64 {
    headers
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|seconds| (1..=MAX_RETRY_AFTER_SECS).contains(seconds))
        .unwrap_or(30)
}

fn count(value: &Value, field: &str) -> Result<u64, TransportError> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or(TransportError::Unknown)
}

fn optional_count(value: &Value, field: &str) -> Result<Option<u64>, TransportError> {
    value
        .get(field)
        .map(|value| value.as_u64().ok_or(TransportError::Unknown))
        .transpose()
}

fn parse_anthropic(
    body: &Value,
    usage: &Value,
) -> Result<(String, String, FinishReason, Usage), TransportError> {
    let input = count(usage, "input_tokens")?;
    let output = count(usage, "output_tokens")?;
    let creation = optional_count(usage, "cache_creation_input_tokens")?;
    let read = optional_count(usage, "cache_read_input_tokens")?;
    // Anthropic input and cache dimensions are disjoint, unlike OpenAI.
    input
        .checked_add(creation.unwrap_or(0))
        .and_then(|n| n.checked_add(read.unwrap_or(0)))
        .and_then(|n| n.checked_add(output))
        .ok_or(TransportError::Unknown)?;
    let blocks = body
        .get("content")
        .and_then(Value::as_array)
        .filter(|blocks| !blocks.is_empty())
        .ok_or(TransportError::Unknown)?;
    let mut text = String::new();
    for block in blocks {
        if block.get("type").and_then(Value::as_str) != Some("text") {
            return Err(TransportError::Unknown);
        }
        text.push_str(
            block
                .get("text")
                .and_then(Value::as_str)
                .ok_or(TransportError::Unknown)?,
        );
    }
    let raw = body
        .get("stop_reason")
        .and_then(Value::as_str)
        .ok_or(TransportError::Unknown)?;
    let finish = match raw {
        "end_turn" | "stop_sequence" => FinishReason::Stop,
        "max_tokens" => FinishReason::Length,
        "refusal" => FinishReason::ContentFilter,
        _ => return Err(TransportError::Unknown),
    };
    Ok((
        text,
        raw.into(),
        finish,
        Usage::default()
            .with_input_tokens(input)
            .with_output_tokens(output)
            .with_cache_creation_input_tokens(creation)
            .with_cache_read_input_tokens(read),
    ))
}

fn parse_openai(
    body: &Value,
    usage: &Value,
) -> Result<(String, String, FinishReason, Usage), TransportError> {
    let input = count(usage, "prompt_tokens")?;
    let output = count(usage, "completion_tokens")?;
    input.checked_add(output).ok_or(TransportError::Unknown)?;
    let (read, creation) = match usage.get("prompt_tokens_details") {
        Some(details) if details.is_object() => (
            optional_count(details, "cached_tokens")?,
            optional_count(details, "cache_write_tokens")?,
        ),
        Some(_) => return Err(TransportError::Unknown),
        None => (None, None),
    };
    if read
        .unwrap_or(0)
        .checked_add(creation.unwrap_or(0))
        .ok_or(TransportError::Unknown)?
        > input
    {
        return Err(TransportError::Unknown);
    }
    if let Some(details) = usage.get("completion_tokens_details") {
        if !details.is_object()
            || optional_count(details, "reasoning_tokens")?.is_some_and(|n| n > output)
        {
            return Err(TransportError::Unknown);
        }
    }
    let choices = body
        .get("choices")
        .and_then(Value::as_array)
        .filter(|choices| choices.len() == 1)
        .ok_or(TransportError::Unknown)?;
    let choice = &choices[0];
    let text = choice
        .get("message")
        .and_then(|message| message.get("content"))
        .and_then(Value::as_str)
        .ok_or(TransportError::Unknown)?;
    let raw = choice
        .get("finish_reason")
        .and_then(Value::as_str)
        .ok_or(TransportError::Unknown)?;
    let finish = match raw {
        "stop" => FinishReason::Stop,
        "length" => FinishReason::Length,
        "content_filter" => FinishReason::ContentFilter,
        _ => return Err(TransportError::Unknown),
    };
    Ok((
        text.into(),
        raw.into(),
        finish,
        Usage::default()
            .with_input_tokens(input)
            .with_output_tokens(output)
            .with_cache_read_input_tokens(read)
            .with_cache_creation_input_tokens(creation),
    ))
}

#[cfg(test)]
#[path = "execution_transport_tests.rs"]
mod tests;
