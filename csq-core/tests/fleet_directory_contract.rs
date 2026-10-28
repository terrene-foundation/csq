//! S1 synthetic contract fixtures, not evidence of a delivered Trestle adapter.
//! No environment, filesystem, wall clock, subprocess, socket or account access.

use csq_core::messaging::fleet_directory::{
    collect_hosts, decode_list, decode_list_request, decode_resolve, decode_resolve_request,
    AdapterFailure, Coverage, DirectoryClock, DirectoryFailure, DirectoryOutcome, DirectoryResult,
    DirectoryTag, HostDirectory, HostPage, HostReach, ValidationFailure,
};
use serde_json::{json, Value};
use std::cell::RefCell;
use std::collections::VecDeque;

// Year 2100 and an injected clock: these fixtures cannot expire with real time.
const NOW: u64 = 4_102_444_800;

enum Fixture {
    Wire(Vec<u8>),
    Fault(AdapterFailure),
}

struct FakeDirectory {
    pages: RefCell<VecDeque<Fixture>>,
    calls: RefCell<Vec<(u8, Option<String>)>>,
    resolved: Vec<u8>,
}

impl FakeDirectory {
    fn pages(pages: Vec<Value>) -> Self {
        Self::fixtures(
            pages
                .into_iter()
                .map(|v| Fixture::Wire(bytes(&v)))
                .collect(),
        )
    }

    fn fixtures(pages: Vec<Fixture>) -> Self {
        Self {
            pages: RefCell::new(pages.into()),
            calls: RefCell::new(Vec::new()),
            resolved: bytes(&response(host("host_0"))),
        }
    }
}

impl HostDirectory for FakeDirectory {
    fn resolve(&self, host_id: &str) -> DirectoryOutcome<HostReach> {
        match decode_resolve(&self.resolved, host_id, NOW) {
            Ok(result) => DirectoryOutcome::Response(result),
            Err(ValidationFailure::InvalidDescriptor) => {
                DirectoryOutcome::AdapterFailure(AdapterFailure::InvalidDescriptor)
            }
            Err(failure) => DirectoryOutcome::ValidationFailure(failure),
        }
    }

    fn list(&self, limit: u8, cursor: Option<&str>) -> DirectoryOutcome<HostPage> {
        self.calls
            .borrow_mut()
            .push((limit, cursor.map(str::to_owned)));
        match self.pages.borrow_mut().pop_front() {
            Some(Fixture::Wire(raw)) => match decode_list(&raw, limit, NOW) {
                Ok(result) => DirectoryOutcome::Response(result),
                Err(ValidationFailure::InvalidDescriptor) => {
                    DirectoryOutcome::AdapterFailure(AdapterFailure::InvalidDescriptor)
                }
                Err(failure) => DirectoryOutcome::ValidationFailure(failure),
            },
            Some(Fixture::Fault(fault)) => DirectoryOutcome::AdapterFailure(fault),
            None => DirectoryOutcome::AdapterFailure(AdapterFailure::DirectoryUnavailable),
        }
    }
}

fn bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

fn host(id: &str) -> Value {
    json!({"host_id": id, "descriptor_version": 1, "issued_at": NOW,
        "expires_at": NOW + 60,
        "reach": {"transport": "tcp", "address": "192.0.2.10", "port": 443}})
}

fn response(value: Value) -> Value {
    json!({"version": 1, "coverage": "complete", "tag": "ok",
        "issued_at": NOW, "expires_at": NOW + 60, "value": value})
}

fn page(ids: &[String], cursor: Option<&str>) -> Value {
    let mut value = json!({"snapshot_id": "snapshot_1",
        "hosts": ids.iter().map(|id| host(id)).collect::<Vec<_>>()});
    if let Some(cursor) = cursor {
        value["next_cursor"] = json!(cursor);
    }
    response(value)
}

fn empty_page() -> Value {
    page(&[], None)
}

fn expect_invalid(value: Value) {
    assert_eq!(
        decode_resolve(&bytes(&value), "host_0", NOW).unwrap_err(),
        ValidationFailure::InvalidDescriptor
    );
}

#[test]
fn raw_fixture_fake_resolves_through_real_decoder() {
    let fake = FakeDirectory::pages(vec![]);
    let DirectoryOutcome::Response(result) = fake.resolve("host_0") else {
        panic!("valid raw fixture must resolve");
    };
    assert_eq!(result.tag, DirectoryTag::Ok);
    assert_eq!(result.coverage, Coverage::Complete);
    assert_eq!(result.value.unwrap().host_id, "host_0");
    assert!(matches!(
        fake.resolve("other_host"),
        DirectoryOutcome::AdapterFailure(AdapterFailure::InvalidDescriptor)
    ));
}

#[test]
fn complete_and_incomplete_empty_results_remain_distinct() {
    for (coverage, expected) in [
        ("complete", Coverage::Complete),
        ("incomplete", Coverage::Incomplete),
    ] {
        let mut raw = empty_page();
        raw["coverage"] = json!(coverage);
        let result = collect_hosts(&FakeDirectory::pages(vec![raw]), NOW).unwrap();
        assert_eq!(result.coverage, expected);
        assert_eq!(result.tag, DirectoryTag::Ok);
        assert!(result.value.unwrap().hosts.is_empty());
    }
}

#[test]
fn every_wire_negative_survives_without_a_value_and_never_becomes_success() {
    for (tag, expected) in [
        ("unknown_host", DirectoryTag::UnknownHost),
        ("directory_host_offline", DirectoryTag::DirectoryHostOffline),
        ("directory_host_revoked", DirectoryTag::DirectoryHostRevoked),
        ("descriptor_expired", DirectoryTag::DescriptorExpired),
        ("incompatible_version", DirectoryTag::IncompatibleVersion),
        (
            "directory_identity_mismatch",
            DirectoryTag::DirectoryIdentityMismatch,
        ),
        ("directory_rate_limited", DirectoryTag::DirectoryRateLimited),
    ] {
        for coverage in [Coverage::Complete, Coverage::Incomplete] {
            let mut raw = response(host("host_0"));
            raw["tag"] = json!(tag);
            raw["coverage"] = serde_json::to_value(coverage).unwrap();
            if coverage == Coverage::Complete {
                raw["issued_at"] = json!(NOW - 1);
                raw["expires_at"] = json!(NOW + 59);
            }
            raw.as_object_mut().unwrap().remove("value");
            let result = decode_resolve(&bytes(&raw), "host_0", NOW).unwrap();
            assert_eq!(result.tag, expected);
            assert_eq!(result.coverage, coverage);
            assert!(result.value.is_none());
            raw["value"] = host("host_0");
            expect_invalid(raw.clone());
            raw["value"] = Value::Null;
            expect_invalid(raw);
        }
    }
}

#[test]
fn adapter_faults_have_a_separate_arm_and_cannot_be_claimed_by_wire() {
    for (wire, fault) in [
        ("timeout", AdapterFailure::Timeout),
        (
            "directory_unavailable",
            AdapterFailure::DirectoryUnavailable,
        ),
        ("invalid_descriptor", AdapterFailure::InvalidDescriptor),
    ] {
        let mut raw = response(host("host_0"));
        raw["tag"] = json!(wire);
        raw.as_object_mut().unwrap().remove("value");
        expect_invalid(raw);
        assert_eq!(
            collect_hosts(&FakeDirectory::fixtures(vec![Fixture::Fault(fault)]), NOW).unwrap_err(),
            DirectoryFailure::Adapter(fault)
        );
    }
    let mut raw = response(host("host_0"));
    raw["tag"] = json!("clock_skew");
    expect_invalid(raw);
}

#[test]
fn frozen_decoder_cases_enforce_the_declared_denominator() {
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("fixtures/fleet_directory/decoder_cases.json")).unwrap();
    let mut executed = std::collections::BTreeSet::new();
    for case in &cases {
        let id = case["case_id"].as_str().unwrap();
        assert!(executed.insert(id), "duplicate case {id}");
        let raw = if let Some(count) = case["padding"].as_u64() {
            let mut raw = bytes(&case["raw"]);
            raw.resize(count as usize, b' ');
            raw
        } else if case["duplicate"].as_bool() == Some(true) {
            let mut raw = bytes(&case["raw"]);
            raw.extend_from_slice(&raw.clone());
            raw
        } else {
            bytes(&case["raw"])
        };
        let raw = match case["prefix"].as_str() {
            Some(prefix) => [prefix.as_bytes(), raw.as_slice()].concat(),
            None => raw,
        };
        let now = case["now"].as_u64().unwrap_or(NOW);
        let measured = match case["operation"].as_str().unwrap() {
            "resolve" => decode_resolve(&raw, "host_0", now).map(|r| r.coverage),
            "list" => decode_list(&raw, case["limit"].as_u64().unwrap_or(64) as u8, now)
                .map(|r| r.coverage),
            "resolve_request" => decode_resolve_request(&raw).map(|_| Coverage::Complete),
            "list_request" => decode_list_request(&raw).map(|_| Coverage::Complete),
            other => panic!("undeclared operation {other}"),
        };
        let observed = match measured {
            Ok(Coverage::Complete) => "complete",
            Ok(Coverage::Incomplete) => "incomplete",
            Err(ValidationFailure::InvalidDescriptor) => "invalid_descriptor",
            Err(ValidationFailure::IncompatibleVersion) => "incompatible_version",
            Err(ValidationFailure::DescriptorExpired) => "descriptor_expired",
            Err(ValidationFailure::ClockSkew) => "clock_skew",
            Err(ValidationFailure::CoverageIncomplete) => "coverage_incomplete",
        };
        assert_eq!(observed, case["expected"].as_str().unwrap(), "case {id}");
    }
    let expected: Vec<String> = serde_json::from_str(include_str!(
        "fixtures/fleet_directory/decoder_case_ids.json"
    ))
    .unwrap();
    assert_eq!(
        executed.into_iter().collect::<Vec<_>>(),
        expected.iter().map(String::as_str).collect::<Vec<_>>()
    );
}

#[test]
fn list_limit_rejects_overfull_page_without_truncating() {
    let raw = page(&["host_0".to_owned(), "host_1".to_owned()], None);
    assert_eq!(
        decode_list(&bytes(&raw), 1, NOW).unwrap_err(),
        ValidationFailure::InvalidDescriptor
    );
    for limit in [0, 65, u8::MAX] {
        assert_eq!(
            decode_list(&bytes(&empty_page()), limit, NOW).unwrap_err(),
            ValidationFailure::InvalidDescriptor
        );
    }
}

#[test]
fn collector_follows_four_pages_and_preserves_all_256_host_identities() {
    let pages = (0..4)
        .map(|p| {
            let ids = (p * 64..(p + 1) * 64)
                .map(|n| format!("host_{n}"))
                .collect::<Vec<_>>();
            let next = (p < 3).then(|| format!("cursor_{}", p + 1));
            page(&ids, next.as_deref())
        })
        .collect();
    let fake = FakeDirectory::pages(pages);
    let result = collect_hosts(&fake, NOW).unwrap();
    assert_eq!(result.coverage, Coverage::Complete);
    let hosts = result.value.unwrap().hosts;
    assert_eq!(hosts.len(), 256);
    for (n, host) in hosts.iter().enumerate() {
        assert_eq!(host.host_id, format!("host_{n}"));
    }
    assert_eq!(
        *fake.calls.borrow(),
        vec![
            (64, None),
            (64, Some("cursor_1".into())),
            (64, Some("cursor_2".into())),
            (64, Some("cursor_3".into()))
        ]
    );
}

#[test]
fn collector_refuses_fifth_page_and_drift_without_claiming_complete() {
    let mut pages = (0..4)
        .map(|n| page(&[format!("host_{n}")], Some(&format!("cursor_{n}"))))
        .collect::<Vec<_>>();
    let fake = FakeDirectory::pages(pages.clone());
    assert_eq!(
        collect_hosts(&fake, NOW).unwrap_err(),
        DirectoryFailure::Validation(ValidationFailure::CoverageIncomplete)
    );
    assert_eq!(fake.calls.borrow().len(), 4);
    pages.truncate(2);
    pages[1]["issued_at"] = json!(NOW + 1);
    pages[1]["expires_at"] = json!(NOW + 61);
    pages[1]["value"]
        .as_object_mut()
        .unwrap()
        .remove("next_cursor");
    assert_eq!(
        collect_hosts(&FakeDirectory::pages(pages), NOW).unwrap_err(),
        DirectoryFailure::Validation(ValidationFailure::InvalidDescriptor)
    );
}

#[test]
fn list_page_schema_rejects_nested_unknown_fields_and_duplicate_identity() {
    let mut raw = empty_page();
    raw["value"]["path"] = json!("/private/SENTINEL");
    assert_eq!(
        decode_list(&bytes(&raw), 64, NOW).unwrap_err(),
        ValidationFailure::InvalidDescriptor
    );
    let fake = FakeDirectory::pages(vec![
        page(&["host_0".into()], Some("next")),
        page(&["host_0".into()], None),
    ]);
    assert_eq!(
        collect_hosts(&fake, NOW).unwrap_err(),
        DirectoryFailure::Validation(ValidationFailure::InvalidDescriptor)
    );
}

#[test]
fn cursor_loop_fails_before_repeated_request_can_claim_complete() {
    let fake = FakeDirectory::pages(vec![
        page(&["host_0".into()], Some("same")),
        page(&["host_1".into()], Some("same")),
    ]);
    assert_eq!(
        collect_hosts(&fake, NOW).unwrap_err(),
        DirectoryFailure::Validation(ValidationFailure::InvalidDescriptor)
    );
    assert_eq!(fake.calls.borrow().len(), 2);
}

#[test]
fn incomplete_middle_page_is_not_erased_by_complete_last_page() {
    let mut first = page(&["host_0".into()], Some("next"));
    first["coverage"] = json!("incomplete");
    let fake = FakeDirectory::pages(vec![first, page(&["host_1".into()], None)]);
    let result = collect_hosts(&fake, NOW).unwrap();
    assert_eq!(result.coverage, Coverage::Incomplete);
    assert_eq!(result.value.unwrap().hosts.len(), 2);
}

#[test]
fn expired_or_future_page_remains_validation_failure_through_fake_trait() {
    for (issued, expires, expected) in [
        (NOW - 361, NOW - 301, ValidationFailure::DescriptorExpired),
        (NOW + 301, NOW + 361, ValidationFailure::ClockSkew),
    ] {
        let mut second = empty_page();
        second["issued_at"] = json!(issued);
        second["expires_at"] = json!(expires);
        let fake = FakeDirectory::pages(vec![empty_page_with_cursor(), second]);
        assert_eq!(
            collect_hosts(&fake, NOW).unwrap_err(),
            DirectoryFailure::Validation(expected)
        );
    }
}

fn empty_page_with_cursor() -> Value {
    page(&[], Some("next"))
}

#[test]
fn snapshot_identity_cannot_drift_with_identical_timestamps() {
    let mut second = empty_page();
    second["value"]["snapshot_id"] = json!("different_generation");
    let fake = FakeDirectory::pages(vec![empty_page_with_cursor(), second]);
    assert_eq!(
        collect_hosts(&fake, NOW).unwrap_err(),
        DirectoryFailure::Validation(ValidationFailure::InvalidDescriptor)
    );
}

#[test]
fn unsafe_and_unknown_clocks_fail_before_parse_or_directory_access() {
    for clock in [DirectoryClock::Unsafe, DirectoryClock::Unknown] {
        assert_eq!(
            decode_resolve(b"not json", "host_0", clock).unwrap_err(),
            ValidationFailure::ClockSkew
        );
        assert_eq!(
            decode_list(b"not json", 64, clock).unwrap_err(),
            ValidationFailure::ClockSkew
        );
        let fake = FakeDirectory::pages(vec![empty_page()]);
        assert_eq!(
            collect_hosts(&fake, clock).unwrap_err(),
            DirectoryFailure::Validation(ValidationFailure::ClockSkew)
        );
        assert!(fake.calls.borrow().is_empty());
    }
}

#[test]
fn collector_missing_page_and_midstream_fault_do_not_return_partial_success() {
    let first = page(&["host_0".into()], Some("next"));
    assert_eq!(
        collect_hosts(&FakeDirectory::pages(vec![first.clone()]), NOW).unwrap_err(),
        DirectoryFailure::Adapter(AdapterFailure::DirectoryUnavailable)
    );
    assert_eq!(
        collect_hosts(
            &FakeDirectory::fixtures(vec![
                Fixture::Wire(bytes(&first)),
                Fixture::Fault(AdapterFailure::Timeout)
            ]),
            NOW
        )
        .unwrap_err(),
        DirectoryFailure::Adapter(AdapterFailure::Timeout)
    );
}

#[test]
fn private_reach_debug_cannot_render_an_endpoint_or_unknown_payload() {
    let result: DirectoryResult<HostReach> =
        decode_resolve(&bytes(&response(host("host_0"))), "host_0", NOW).unwrap();
    let rendered = format!("{result:?}");
    assert!(!rendered.contains("192.0.2.10"));
    assert!(!rendered.contains("443"));
    let mut malformed = response(host("host_0"));
    malformed["private_error"] = json!("SENTINEL_PRIVATE_PATH");
    let error = decode_resolve(&bytes(&malformed), "host_0", NOW).unwrap_err();
    assert_eq!(format!("{error:?}"), "InvalidDescriptor");
}

#[test]
fn fixed_text_and_failure_coverage_match_the_frozen_contract() {
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("fixtures/fleet_directory/outcome_text.json")).unwrap();
    for case in cases {
        let tag = case["tag"].as_str().unwrap();
        let observed = match tag {
            "timeout" => AdapterFailure::Timeout.text(),
            "invalid_descriptor" => AdapterFailure::InvalidDescriptor.text(),
            "directory_unavailable" => AdapterFailure::DirectoryUnavailable.text(),
            "clock_skew" => ValidationFailure::ClockSkew.text(),
            "coverage_incomplete" => ValidationFailure::CoverageIncomplete.text(),
            _ => serde_json::from_value::<DirectoryTag>(json!(tag))
                .unwrap()
                .text(),
        };
        assert_eq!(observed, case["text"].as_str().unwrap(), "tag {tag}");
    }
    for fault in [
        AdapterFailure::Timeout,
        AdapterFailure::InvalidDescriptor,
        AdapterFailure::DirectoryUnavailable,
    ] {
        let outcome: DirectoryOutcome<HostPage> = DirectoryOutcome::AdapterFailure(fault);
        assert_eq!(outcome.coverage(), Coverage::Incomplete);
    }
    let mut bad = response(host("host_0"));
    bad["path"] = json!("/private/SENTINEL");
    let fake = FakeDirectory::fixtures(vec![Fixture::Wire(bytes(&bad))]);
    assert_eq!(
        collect_hosts(&fake, NOW).unwrap_err(),
        DirectoryFailure::Adapter(AdapterFailure::InvalidDescriptor)
    );
}

#[test]
fn collector_negative_page_never_claims_complete_aggregate_coverage() {
    for preceding in [None, Some("complete"), Some("incomplete")] {
        let mut negative = empty_page();
        negative["tag"] = json!("directory_host_offline");
        negative.as_object_mut().unwrap().remove("value");
        let mut pages = Vec::new();
        if let Some(coverage) = preceding {
            let mut first = page(&["host_0".into()], Some("next"));
            first["coverage"] = json!(coverage);
            pages.push(first);
        }
        pages.push(negative);
        let result = collect_hosts(&FakeDirectory::pages(pages), NOW).unwrap();
        assert_eq!(result.tag, DirectoryTag::DirectoryHostOffline);
        assert_eq!(
            result.coverage,
            Coverage::Incomplete,
            "preceding {preceding:?}"
        );
        assert!(result.value.is_none());
        assert_eq!(
            result.tag.text(),
            "fleet directory reports host offline; reachability undetermined"
        );
    }
}
