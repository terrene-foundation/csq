//! Deterministic scan-work regressions; the counter never retains source bytes.
use std::cell::Cell;

std::thread_local! {
    static INSPECTED: Cell<usize> = const { Cell::new(0) };
}

pub(super) fn record(bytes: usize) {
    INSPECTED.with(|counter| counter.set(counter.get().saturating_add(bytes)));
}

fn bounded(synthetic_case: &'static str, make_input: impl Fn(usize) -> String) {
    let mut diagnostic = true;
    let mut chat = true;
    for repetitions in [128, 256] {
        let input = make_input(repetitions);
        // Metric: bytes traversed by word_value/line_end only, not total CPU.
        // Accepted spans consume input: one value pass plus at most one scheme
        // credential pass. Rejected long paths/URIs are checked before these
        // helpers; remaining rejected numeric/prose words cannot nest markers.
        // 8N leaves 4x slack above those two overlapping accepted-span passes.
        let limit = 8 * input.len();
        INSPECTED.with(|counter| counter.set(0));
        drop(crate::redact_tokens(&input));
        let diagnostic_value_scan_units = INSPECTED.with(|counter| counter.get());
        diagnostic &= diagnostic_value_scan_units <= limit;
        INSPECTED.with(|counter| counter.set(0));
        drop(crate::redact_chat(&input));
        let chat_value_scan_units = INSPECTED.with(|counter| counter.get());
        chat &= chat_value_scan_units <= limit;
        eprintln!("synthetic_case={synthetic_case} n={repetitions} input_bytes={} diagnostic_value_scan_units={diagnostic_value_scan_units} chat_value_scan_units={chat_value_scan_units} allowance8N={limit}", input.len());
    }
    assert!(
        diagnostic && chat,
        "value scan bound exceeded: diagnostic={diagnostic}, chat={chat}"
    );
}

#[test]
fn rejected_url_suffix_context_has_linear_value_scan_work() {
    bounded("url_suffix", |n| {
        format!("{}https://example.invalid", "X_TOKEN=".repeat(n))
    });
}

#[test]
fn rejected_embedded_url_context_has_linear_value_scan_work() {
    bounded("embedded_url", |n| "DEPLOY_KEY=FAKETESThttp://".repeat(n));
}

#[test]
fn rejected_overlong_quoted_path_has_linear_value_scan_work() {
    bounded("quoted_path", |n| {
        format!("X_TOKEN=\"/{} ", "Z".repeat(1025)).repeat(n)
    });
}

#[test]
fn retained_query_xml_and_escaped_quote_boundaries_do_not_rescan_suffixes() {
    bounded("query_boundary", |n| {
        format!(
            "https://example.invalid/?{}",
            "password=FAKETESTopaqueValue&".repeat(n)
        )
    });
    bounded("xml_boundary", |n| {
        format!("<password>\"FAKETEST{} ", "Z".repeat(1025)).repeat(n)
    });
    bounded("escaped_auth_boundary", |n| {
        r"\u0022Authorization\u0022:\u0022FAKETESTopaqueValue\u0022".repeat(n)
    });
}

#[test]
fn authorization_query_values_do_not_scan_the_remaining_query() {
    bounded("authorization_query_boundary", |n| {
        format!(
            "https://example.invalid/?{}",
            "authorization=FAKETESTopaqueValue&note=?&".repeat(n)
        )
    });
}
