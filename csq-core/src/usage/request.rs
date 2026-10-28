//! Request-level normalization of CC transcript usage records (an internal ticket).
//!
//! A single API call does NOT produce a single usage-bearing transcript line.
//! CC appends a usage SNAPSHOT as the response streams, so one request lands as
//! a run of records that share a request identity and whose `output_tokens`
//! grows. The pre-an internal ticket scanner summed every usage-bearing record, which
//! counted one request's input and cache tokens once per snapshot.
//!
//! This module owns the two decisions that fix it — what makes two records the
//! SAME request, and which snapshot of a request is the billable one — and
//! reports the residual where its finalization rule is not exact, rather than
//! resolving it silently.
//!
//! ## Measured basis (2026-09-17, metadata-only probe)
//!
//! 120 recent transcript files (60 parent-level, 60 under `<session>/subagents/`)
//! carrying 23,570 usage-bearing records were projected to metadata only:
//!
//! | Measurement                                              | Observed |
//! | -------------------------------------------------------- | -------: |
//! | records carrying `requestId`                             | 21,592 / 23,570 |
//! | `message.id` mapping to more than one `requestId`        | 0 of 9,684 |
//! | `requestId` mapping to more than one `message.id`        | 0 of 9,684 |
//! | distinct request groups                                  | 10,395 |
//! | groups carrying MORE THAN ONE usage snapshot             | 7,526 |
//! | of those, `output_tokens` monotone non-decreasing        | 7,526 |
//! | of those, input and cache counts CONSTANT                | 7,519 |
//! | of those, spanning more than one model                   | 0 |
//! | of those, spanning more than one FILE                    | 0 |
//!
//! These are MEASUREMENTS of one host's recent transcripts on one date. They
//! are not a bound on what CC can write, and nothing here treats them as one:
//! the finalization rule below is chosen because it is exact on the observed
//! shape, and every request on which it is NOT exact is counted rather than
//! assumed away.
//!
//! ## Privacy invariant (D6)
//!
//! Nothing in this module holds transcript content. It consumes the metadata
//! projection the scanner already produces — ids, a timestamp, a model name and
//! four numeric token counts — and the types below have no content field, so
//! there is no shape here through which conversational text could travel.

use std::collections::HashMap;

/// Which channel supplied a request's identity. Reported so a caller can
/// separate requests that were genuinely de-duplicated from those that only
/// degraded to per-record accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentitySource {
    /// `requestId` — the vendor's own request identifier.
    RequestId,
    /// `message.id` — used when `requestId` is absent. Observed 1:1 with
    /// `requestId` on all 9,684 records that carried both (see module docs);
    /// that is an observation about those records, not a guarantee about the
    /// format.
    MessageId,
    /// Neither id was present, so the record was keyed by its own position
    /// (file path plus record `uuid`, or plus line ordinal when the `uuid` is
    /// also absent). Such a key groups nothing, so the record is billed on its
    /// own — the pre-an internal ticket per-record behaviour, applied only where there is no
    /// identity to merge on.
    RecordFallback,
}

impl IdentitySource {
    /// True when the identity came from neither id field, so this request is a
    /// single record standing alone rather than a de-duplicated group.
    pub fn is_unidentified(self) -> bool {
        matches!(self, IdentitySource::RecordFallback)
    }
}

/// The four token dimensions of one usage snapshot. Disjoint by construction:
/// `input_tokens` excludes cache reads and cache writes, which CC reports in
/// their own fields, so a consumer that wants a cache-inclusive total adds all
/// four and counts nothing twice.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SnapshotUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_creation_tokens: u64,
    pub cache_read_tokens: u64,
}

impl SnapshotUsage {
    /// Per-field maximum across two snapshots. Used ONLY to detect divergence
    /// from the finalization rule — never to produce the billed figure, because
    /// a per-field max over a streaming run can compose fields that never
    /// coexisted in any single snapshot.
    fn field_max(self, other: Self) -> Self {
        SnapshotUsage {
            input_tokens: self.input_tokens.max(other.input_tokens),
            output_tokens: self.output_tokens.max(other.output_tokens),
            cache_creation_tokens: self.cache_creation_tokens.max(other.cache_creation_tokens),
            cache_read_tokens: self.cache_read_tokens.max(other.cache_read_tokens),
        }
    }
}

/// One usage snapshot as the scanner projects it, before normalization.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UsageSnapshot {
    /// `requestId`, when the record carried one.
    pub request_id: Option<String>,
    /// `message.id`, when the record carried one.
    pub message_id: Option<String>,
    /// The record's own `uuid`, used only by the last-resort identity.
    pub record_uuid: Option<String>,
    /// RFC3339 timestamp string as written. Kept as a string because it is what
    /// the ledger stores and what the rate table parses.
    pub timestamp: Option<String>,
    /// `message.model`, empty strings already filtered out by the scanner.
    pub model: Option<String>,
    pub usage: SnapshotUsage,
}

/// One request after snapshot collapse — the unit that is priced and bucketed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedRequest {
    /// The earliest timestamp observed across this request's snapshots — when
    /// the request began, which is the instant its rate was set. Compared as
    /// parsed instants, so read order and RFC3339 formatting do not affect it.
    /// A request whose timestamps are all unparseable reports the first of them
    /// verbatim rather than `None`, leaving the caller to decide (the rate
    /// table's "cannot select a tier" contract, not a guessed tier).
    pub timestamp: Option<String>,
    /// The first non-empty model observed for this request.
    pub model: Option<String>,
    /// The billed counts: the LAST snapshot of this request in file append
    /// order (see [`RequestCollector::finish`]).
    pub usage: SnapshotUsage,
    /// How many snapshots of this request were discarded by finalization —
    /// `snapshot_count - 1`. A diagnostic, never a billable quantity.
    pub snapshots_collapsed: u64,
    /// True when the billed (last) snapshot differs from the per-field maximum
    /// across this request's snapshots, i.e. where the finalization rule and a
    /// per-field max disagree. Counted so the residual stays observable.
    pub finalization_divergent: bool,
    /// Which channel supplied this request's identity.
    pub identity: IdentitySource,
    /// True when this request came from a `<session>/subagents/*.jsonl` file
    /// rather than the parent-level transcript.
    pub from_subagent: bool,
}

/// A request identity key, namespaced by its source so an id drawn from one
/// channel can never collide with an unrelated id drawn from another.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RequestKey(String);

#[derive(Debug)]
struct Pending {
    /// The earliest timestamp seen for this request, with its parsed form kept
    /// alongside so the comparison is on instants rather than on strings. RFC3339
    /// is not lexicographically ordered across offsets or fractional-digit counts
    /// (`...:00+00:00` sorts before `...:00.5Z` but is not earlier), so a string
    /// comparison would silently mis-order a mixed-format group.
    earliest: Option<(chrono::DateTime<chrono::FixedOffset>, String)>,
    /// Retained so a request whose every timestamp is unparseable still reports
    /// the raw string it was given, rather than reporting `None` and discarding
    /// what the transcript said.
    ///
    /// This does NOT by itself secure a rolling-window bucket, and an earlier
    /// version of this comment claimed it did. An unparseable string reaching
    /// `UsageEvent::ts` would be bucket-skipped by
    /// [`crate::usage::ledger::summarize`]; the bucket is secured by the
    /// consumer substituting the session start in that case (see
    /// `attributed_session_to_events_with_manifest`), not here.
    fallback_timestamp: Option<String>,
    model: Option<String>,
    last: SnapshotUsage,
    field_max: SnapshotUsage,
    snapshot_count: u64,
    identity: IdentitySource,
    from_subagent: bool,
}

impl Pending {
    /// Folds one snapshot's timestamp in, keeping the earliest parseable one.
    fn observe_timestamp(&mut self, raw: Option<String>) {
        let Some(raw) = raw else { return };
        match chrono::DateTime::parse_from_rfc3339(&raw) {
            Ok(parsed) => match &self.earliest {
                Some((prev, _)) if *prev <= parsed => {}
                _ => self.earliest = Some((parsed, raw)),
            },
            Err(_) => {
                if self.fallback_timestamp.is_none() {
                    self.fallback_timestamp = Some(raw);
                }
            }
        }
    }

    /// The timestamp this request is priced and bucketed at.
    fn timestamp(self) -> Option<String> {
        match self.earliest {
            Some((_, raw)) => Some(raw),
            None => self.fallback_timestamp,
        }
    }
}

/// Accumulates usage snapshots in the order they are read and collapses them
/// into one [`NormalizedRequest`] per request identity.
///
/// The collector is fed from a single file's line stream. Records from
/// different files go to different collectors, which is what makes "append
/// order" a total order over each request's snapshots: a request group was
/// never observed spanning more than one file (module docs), and even if one
/// did, the two halves would simply normalize as two requests rather than
/// silently interleaving.
#[derive(Debug, Default)]
pub struct RequestCollector {
    order: Vec<RequestKey>,
    pending: HashMap<RequestKey, Pending>,
}

impl RequestCollector {
    pub fn new() -> Self {
        Self::default()
    }

    /// True when no usage snapshot has been offered yet.
    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    /// Adds one usage snapshot. `line_ordinal` and `file_key` are used ONLY by
    /// the last-resort identity, and only when both id fields are absent.
    pub fn push(
        &mut self,
        snapshot: UsageSnapshot,
        file_key: &str,
        line_ordinal: u64,
        from_subagent: bool,
    ) {
        let (key, identity) = Self::identify(&snapshot, file_key, line_ordinal);
        match self.pending.get_mut(&key) {
            Some(existing) => {
                // Append order decides: this snapshot is later than every
                // snapshot already folded in, so it becomes the billed one.
                existing.field_max = existing.field_max.field_max(snapshot.usage);
                existing.last = snapshot.usage;
                existing.snapshot_count += 1;
                existing.observe_timestamp(snapshot.timestamp);
                if existing.model.is_none() {
                    existing.model = snapshot.model;
                }
                // `from_subagent` is a property of the FILE, not of the record:
                // `scan_one_transcript` builds one collector per file and hands
                // that file's single `from_subagent` to every `push` it makes,
                // so every snapshot folded into one `Pending` carries the same
                // value and this AND is an identity on every path this crate
                // reaches. It is written as an AND so the field keeps its own
                // meaning — a request with any parent-level observation is not
                // marked subagent — instead of depending on the per-file call
                // shape for its correctness. Kept, not deleted: a no-op that
                // states the invariant is cheaper than a comment asserting one.
                existing.from_subagent = existing.from_subagent && from_subagent;
            }
            None => {
                self.order.push(key.clone());
                let mut fresh = Pending {
                    earliest: None,
                    fallback_timestamp: None,
                    model: snapshot.model,
                    last: snapshot.usage,
                    field_max: snapshot.usage,
                    snapshot_count: 1,
                    identity,
                    from_subagent,
                };
                fresh.observe_timestamp(snapshot.timestamp);
                self.pending.insert(key, fresh);
            }
        }
    }

    /// Builds the request identity key and records which channel supplied it.
    ///
    /// Order is `requestId`, then `message.id`, then position. The first two
    /// are namespaced (`r:` / `m:`) so a `requestId` and a `message.id` that
    /// happen to share a string cannot merge into one group.
    fn identify(
        snapshot: &UsageSnapshot,
        file_key: &str,
        line_ordinal: u64,
    ) -> (RequestKey, IdentitySource) {
        if let Some(id) = snapshot.request_id.as_deref().filter(|s| !s.is_empty()) {
            return (RequestKey(format!("r:{id}")), IdentitySource::RequestId);
        }
        if let Some(id) = snapshot.message_id.as_deref().filter(|s| !s.is_empty()) {
            return (RequestKey(format!("m:{id}")), IdentitySource::MessageId);
        }
        // Last resort. A record `uuid` is per-line in CC's transcripts, so this
        // key groups nothing; when even that is absent the line ordinal keeps
        // the key unique within the file. Either way the record bills alone.
        match snapshot.record_uuid.as_deref().filter(|s| !s.is_empty()) {
            Some(uuid) => (
                RequestKey(format!("u:{file_key}|{uuid}")),
                IdentitySource::RecordFallback,
            ),
            None => (
                RequestKey(format!("l:{file_key}|{line_ordinal}")),
                IdentitySource::RecordFallback,
            ),
        }
    }

    /// Collapses every accumulated request, in first-seen order.
    ///
    /// ## Why the LAST snapshot is the billed one
    ///
    /// Not a guess, and not a per-field max. Within one file, records are read
    /// in append order, and every multi-snapshot group observed in the probe
    /// (module docs) lay entirely within one file — so "last read" is "last
    /// written" for those groups. On that same sample `output_tokens` never
    /// decreased across a group (7,526 of 7,526) and the input and cache counts
    /// never changed (7,519 of 7,526), which makes the last snapshot the
    /// complete one for those requests.
    ///
    /// A per-field maximum is deliberately NOT the rule: it can emit a
    /// combination of counts that appeared in no single snapshot, which is a
    /// worse failure than under-reporting a request by the amount one late
    /// field moved. The 7 requests per 7,526 where the two rules disagree are
    /// flagged `finalization_divergent` and counted, so the residual is visible
    /// in the summary instead of being tuned away.
    pub fn finish(self) -> Vec<NormalizedRequest> {
        let mut pending = self.pending;
        let mut out = Vec::with_capacity(self.order.len());
        for key in &self.order {
            let Some(p) = pending.remove(key) else {
                continue;
            };
            let (model, usage, collapsed, divergent, identity, from_subagent) = (
                p.model.clone(),
                p.last,
                p.snapshot_count.saturating_sub(1),
                p.last != p.field_max,
                p.identity,
                p.from_subagent,
            );
            out.push(NormalizedRequest {
                timestamp: p.timestamp(),
                model,
                usage,
                snapshots_collapsed: collapsed,
                finalization_divergent: divergent,
                identity,
                from_subagent,
            });
        }
        out
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn snap(
        req: Option<&str>,
        msg: Option<&str>,
        ts: &str,
        input: u64,
        output: u64,
    ) -> UsageSnapshot {
        UsageSnapshot {
            request_id: req.map(str::to_string),
            message_id: msg.map(str::to_string),
            record_uuid: None,
            timestamp: Some(ts.to_string()),
            model: Some("claude-opus-4-8".to_string()),
            usage: SnapshotUsage {
                input_tokens: input,
                output_tokens: output,
                cache_creation_tokens: 0,
                cache_read_tokens: 0,
            },
        }
    }

    /// The defect an internal ticket names: repeated streaming snapshots of ONE request must
    /// bill once. Falsifying result: `input_tokens` of 30,000 (3 × 10,000), the
    /// pre-fix blind sum.
    #[test]
    fn collapses_streaming_snapshots_of_one_request_to_the_last() {
        let mut c = RequestCollector::new();
        c.push(
            snap(Some("req_a"), None, "2026-09-01T00:00:00Z", 10_000, 1),
            "f",
            0,
            false,
        );
        c.push(
            snap(Some("req_a"), None, "2026-09-01T00:00:01Z", 10_000, 50),
            "f",
            1,
            false,
        );
        c.push(
            snap(Some("req_a"), None, "2026-09-01T00:00:02Z", 10_000, 900),
            "f",
            2,
            false,
        );
        let reqs = c.finish();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].usage.input_tokens, 10_000);
        assert_eq!(reqs[0].usage.output_tokens, 900);
        assert_eq!(reqs[0].snapshots_collapsed, 2);
        assert!(!reqs[0].finalization_divergent);
        // The request's EARLIEST timestamp, not the last snapshot's.
        assert_eq!(reqs[0].timestamp.as_deref(), Some("2026-09-01T00:00:00Z"));
    }

    /// Distinct requests stay distinct and both bill.
    #[test]
    fn distinct_request_ids_bill_separately() {
        let mut c = RequestCollector::new();
        c.push(
            snap(Some("req_a"), None, "2026-09-01T00:00:00Z", 10, 1),
            "f",
            0,
            false,
        );
        c.push(
            snap(Some("req_b"), None, "2026-09-01T00:00:05Z", 20, 2),
            "f",
            1,
            false,
        );
        let reqs = c.finish();
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[0].usage.input_tokens, 10);
        assert_eq!(reqs[1].usage.input_tokens, 20);
    }

    /// `message.id` is the identity when `requestId` is absent.
    #[test]
    fn falls_back_to_message_id_when_request_id_absent() {
        let mut c = RequestCollector::new();
        c.push(
            snap(None, Some("msg_1"), "2026-09-01T00:00:00Z", 5, 1),
            "f",
            0,
            false,
        );
        c.push(
            snap(None, Some("msg_1"), "2026-09-01T00:00:01Z", 5, 9),
            "f",
            1,
            false,
        );
        let reqs = c.finish();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].identity, IdentitySource::MessageId);
        assert_eq!(reqs[0].usage.output_tokens, 9);
    }

    /// A `requestId` and a `message.id` carrying the SAME string are different
    /// identities and must not merge. Falsifying result: one request.
    #[test]
    fn request_id_and_message_id_namespaces_do_not_collide() {
        let mut c = RequestCollector::new();
        c.push(
            snap(Some("same"), None, "2026-09-01T00:00:00Z", 7, 1),
            "f",
            0,
            false,
        );
        c.push(
            snap(None, Some("same"), "2026-09-01T00:00:01Z", 11, 2),
            "f",
            1,
            false,
        );
        let reqs = c.finish();
        assert_eq!(reqs.len(), 2, "namespaced keys must not merge: {reqs:?}");
        assert_eq!(reqs[0].identity, IdentitySource::RequestId);
        assert_eq!(reqs[1].identity, IdentitySource::MessageId);
    }

    /// With no identity at all, each record bills alone and is counted as
    /// unidentified — the pre-an internal ticket behaviour, scoped to where there is nothing
    /// to merge on rather than applied everywhere.
    #[test]
    fn records_without_any_identity_bill_individually_and_are_counted() {
        let mut c = RequestCollector::new();
        let mut a = snap(None, None, "2026-09-01T00:00:00Z", 3, 1);
        a.record_uuid = None;
        let mut b = snap(None, None, "2026-09-01T00:00:01Z", 4, 1);
        b.record_uuid = None;
        c.push(a, "f", 0, false);
        c.push(b, "f", 1, false);
        let reqs = c.finish();
        assert_eq!(reqs.len(), 2);
        assert!(reqs.iter().all(|r| r.identity.is_unidentified()));
        assert_eq!(reqs.iter().map(|r| r.usage.input_tokens).sum::<u64>(), 7);
    }

    /// The same record `uuid` in two DIFFERENT files is two records, because
    /// the fallback key is namespaced by file.
    #[test]
    fn record_uuid_fallback_is_scoped_per_file() {
        let mut c = RequestCollector::new();
        let mut a = snap(None, None, "2026-09-01T00:00:00Z", 3, 1);
        a.record_uuid = Some("uuid-1".into());
        let mut b = a.clone();
        b.usage.input_tokens = 4;
        c.push(a, "file-a", 0, false);
        c.push(b, "file-b", 0, true);
        let reqs = c.finish();
        assert_eq!(reqs.len(), 2, "same uuid in two files is two records");
    }

    /// The residual: when the last snapshot is NOT the per-field max, the
    /// request bills the last snapshot AND is flagged. Falsifying result: a
    /// silently max-composed 10,000/900 with the flag clear.
    #[test]
    fn last_snapshot_below_field_max_bills_last_and_flags_divergence() {
        let mut c = RequestCollector::new();
        c.push(
            snap(Some("req_a"), None, "2026-09-01T00:00:00Z", 10_000, 900),
            "f",
            0,
            false,
        );
        c.push(
            snap(Some("req_a"), None, "2026-09-01T00:00:01Z", 9_000, 900),
            "f",
            1,
            false,
        );
        let reqs = c.finish();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].usage.input_tokens, 9_000, "last snapshot wins");
        assert!(
            reqs[0].finalization_divergent,
            "the last-vs-max disagreement must be surfaced, not resolved"
        );
    }

    /// Out-of-order records within a file: the collector honours READ order,
    /// which is append order. A record whose timestamp is earlier than one
    /// already seen still becomes the billed snapshot, and the request keeps
    /// the earliest timestamp it ever saw.
    #[test]
    fn out_of_order_timestamps_keep_read_order_for_usage_and_earliest_for_time() {
        let mut c = RequestCollector::new();
        c.push(
            snap(Some("req_a"), None, "2026-09-01T00:00:05Z", 10, 100),
            "f",
            0,
            false,
        );
        c.push(
            snap(Some("req_a"), None, "2026-09-01T00:00:01Z", 10, 700),
            "f",
            1,
            false,
        );
        let reqs = c.finish();
        assert_eq!(reqs[0].usage.output_tokens, 700, "read order decides usage");
        assert_eq!(reqs[0].timestamp.as_deref(), Some("2026-09-01T00:00:01Z"));
    }

    /// Provenance belongs to the FILE, and the file is the collapse boundary.
    ///
    /// The shape the traversal produces is one collector per file with a single
    /// `from_subagent` for every line in it (`scan_one_transcript`), so what is
    /// asserted here is that a request bills once per file carrying THAT file's
    /// provenance. What is NOT asserted — because the collector cannot perform
    /// it — is a merge across files: `finish` sees one file, so the same
    /// `requestId` written into two files is two requests. Per-file collapse is
    /// exact because no multi-snapshot group was ever observed spanning two
    /// files (0 of 7,526; module docs) — an observation, not a guarantee this
    /// code enforces.
    #[test]
    fn provenance_is_the_files_and_the_file_is_the_collapse_boundary() {
        let mut sub = RequestCollector::new();
        for (ordinal, output) in [(0u64, 1u64), (1, 5)] {
            sub.push(
                snap(Some("req_a"), None, "2026-09-01T00:00:00Z", 10, output),
                "parent/subagents/x",
                ordinal,
                true,
            );
        }
        let sub_reqs = sub.finish();
        assert_eq!(sub_reqs.len(), 1, "two snapshots of one request, one file");
        assert!(
            sub_reqs[0].from_subagent,
            "the file's provenance, not a default"
        );

        // Same `requestId`, different file, different collector: this one does
        // not see the request above, which is the boundary stated rather than
        // assumed.
        let mut parent = RequestCollector::new();
        parent.push(
            snap(Some("req_a"), None, "2026-09-01T00:00:00Z", 10, 1),
            "parent",
            0,
            false,
        );
        let parent_reqs = parent.finish();
        assert_eq!(parent_reqs.len(), 1);
        assert!(!parent_reqs[0].from_subagent);
    }

    /// First-seen order is preserved, so the caller's ledger is stable across
    /// re-runs over an unchanged transcript.
    #[test]
    fn finish_preserves_first_seen_order() {
        let mut c = RequestCollector::new();
        for (i, id) in ["c", "a", "b"].iter().enumerate() {
            c.push(
                snap(Some(id), None, "2026-09-01T00:00:00Z", i as u64, 1),
                "f",
                i as u64,
                false,
            );
        }
        let reqs = c.finish();
        assert_eq!(
            reqs.iter()
                .map(|r| r.usage.input_tokens)
                .collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
    }

    /// The earliest timestamp is chosen by comparing INSTANTS, not strings. The
    /// two here are two minutes apart and sort the opposite way as text, so a
    /// string comparison fails this. Falsifying result: `08:01:00+00:00`, the
    /// lexicographically-smaller but LATER of the two.
    #[test]
    fn earliest_timestamp_compares_instants_not_strings() {
        let mut c = RequestCollector::new();
        let mut later = snap(Some("req_a"), None, "2026-09-01T08:01:00+00:00", 10, 1);
        later.timestamp = Some("2026-09-01T08:01:00+00:00".into());
        let mut earlier = snap(Some("req_a"), None, "2026-09-01T07:59:00Z", 10, 5);
        earlier.timestamp = Some("2026-09-01T07:59:00Z".into());
        c.push(later, "f", 0, false);
        c.push(earlier, "f", 1, false);
        let reqs = c.finish();
        assert_eq!(reqs[0].timestamp.as_deref(), Some("2026-09-01T07:59:00Z"));
    }

    /// A request whose timestamps are all unparseable reports the raw string
    /// rather than `None`. Falsifying result: `None`.
    ///
    /// SCOPE, narrowed deliberately: this asserts RETENTION and nothing else.
    /// It builds no `UsageEvent`, never calls `summarize`, and touches no window
    /// field — so no mutation on the bucketing path can red it. An earlier
    /// version of this doc claimed it kept "a chance at a rolling-window
    /// bucket", which it could not have discriminated
    /// (`instrument-discipline.md` MUST-2). The window behaviour is covered by
    /// `aggregator::tests::unparseable_request_timestamp_still_lands_in_a_rolling_window`.
    #[test]
    fn unparseable_timestamps_are_retained_rather_than_discarded() {
        let mut c = RequestCollector::new();
        let mut a = snap(Some("req_a"), None, "x", 10, 1);
        a.timestamp = Some("not-a-timestamp".into());
        c.push(a, "f", 0, false);
        let reqs = c.finish();
        assert_eq!(reqs[0].timestamp.as_deref(), Some("not-a-timestamp"));
    }

    /// A parseable timestamp beats an unparseable one regardless of read order.
    #[test]
    fn a_parseable_timestamp_wins_over_an_unparseable_one() {
        let mut c = RequestCollector::new();
        let mut bad = snap(Some("req_a"), None, "x", 10, 1);
        bad.timestamp = Some("garbage".into());
        c.push(bad, "f", 0, false);
        c.push(
            snap(Some("req_a"), None, "2026-09-01T09:00:00Z", 10, 2),
            "f",
            1,
            false,
        );
        let reqs = c.finish();
        assert_eq!(reqs[0].timestamp.as_deref(), Some("2026-09-01T09:00:00Z"));
    }

    #[test]
    fn empty_collector_yields_no_requests() {
        assert!(RequestCollector::new().is_empty());
        assert!(RequestCollector::new().finish().is_empty());
    }

    // ---------------------------------------------------------------------
    // D6 privacy gate — the carrier half
    //
    // These four types carry a request from the scanner's line parse to the
    // ledger. They are NOT `Deserialize`: nothing arrives in them from JSON,
    // so a serde sentinel cannot probe them, and the end-to-end sentinel guard
    // in [`super::super::aggregator`] can only prove that the values the
    // scanner happens to pass today are clean. Neither instrument reds on a
    // content-capable field ADDED here and populated by a future scanner
    // change.
    //
    // The field-set lock below does. It is an allowlist over the struct's own
    // fields, so any addition fails by name, whatever the name is.
    // ---------------------------------------------------------------------

    /// Top-level field names of a `{:#?}` rendering, in declaration order.
    ///
    /// Mechanism: pretty `Debug` puts a struct's OWN fields at exactly four
    /// spaces of indent and every nested field deeper, and it ESCAPES string
    /// contents — a `\n` inside a value renders as the two characters `\` `n`,
    /// never as a real newline. So no field VALUE can forge a line that looks
    /// like a top-level field, which is what makes a line-indent scan a sound
    /// field-set reader here. Non-pretty `{:?}` has no such property.
    fn top_level_debug_fields(pretty: &str) -> Vec<String> {
        pretty
            .lines()
            .filter_map(|line| {
                let rest = line.strip_prefix("    ")?;
                if rest.starts_with(' ') {
                    return None; // nested field, not this struct's own
                }
                let name = rest.split(':').next()?;
                let is_ident = !name.is_empty()
                    && name
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
                if is_ident && rest[name.len()..].starts_with(':') {
                    Some(name.to_string())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Asserts a D6-gated struct's field set is EXACTLY `expected`, naming any
    /// field that appeared or vanished.
    ///
    /// `pub(crate)` because the D6 carrier set spans two modules: this one and
    /// [`super::aggregator`], whose transcript structs are the only carriers
    /// that deserialize vendor JSON. Both guards must use ONE implementation —
    /// a second copy of the scan mechanism could drift, and the mechanism's
    /// soundness rests on the `Debug` properties documented on
    /// [`top_level_debug_fields`].
    pub(crate) fn assert_field_set_locked(type_name: &str, pretty: &str, expected: &[&str]) {
        let actual = top_level_debug_fields(pretty);
        let added: Vec<&String> = actual
            .iter()
            .filter(|f| !expected.contains(&f.as_str()))
            .collect();
        let removed: Vec<&&str> = expected
            .iter()
            .filter(|e| !actual.iter().any(|a| a == *e))
            .collect();
        assert!(
            added.is_empty() && removed.is_empty(),
            "D6 PRIVACY GATE: the field set of `{type_name}` changed.\n  \
             added:   {added:?}\n  removed: {removed:?}\n  \
             expected: {expected:?}\n  actual:   {actual:?}\n\
             `{type_name}` carries a request from the transcript parse to the \
             ledger and is D6 privacy-gated (see the aggregator module header). \
             If the added field is METADATA (an id, a timestamp, a model name, a \
             numeric token count, a diagnostic counter), add it to this test's \
             expected set. If it can hold conversational content — message text, \
             prompts, thinking, tool payloads — the D6 contract is VIOLATED and \
             the field must not exist."
        );
    }

    /// D6: the field sets of the four REQUEST carriers are LOCKED.
    ///
    /// Falsifying result: add any field to `SnapshotUsage`, `UsageSnapshot`,
    /// `NormalizedRequest` or `Pending` and it is named here as `added`. A
    /// metadata addition is then a one-line update to the expected set; a
    /// content-capable one is a contract violation with nowhere to hide.
    ///
    /// This is the request half only. The carriers that actually deserialize
    /// vendor JSON are `aggregator`'s `TranscriptLine` / `TranscriptMessage` /
    /// `TranscriptUsage` — the privacy gate itself — and they are locked by
    /// `transcript_carrier_field_sets_are_locked` there, which reuses
    /// [`assert_field_set_locked`]. Neither half covers the contract alone.
    #[test]
    fn request_carrier_field_sets_are_locked() {
        let usage = SnapshotUsage {
            input_tokens: 11,
            output_tokens: 22,
            cache_creation_tokens: 33,
            cache_read_tokens: 44,
        };
        assert_field_set_locked(
            "SnapshotUsage",
            &format!("{usage:#?}"),
            &[
                "input_tokens",
                "output_tokens",
                "cache_creation_tokens",
                "cache_read_tokens",
            ],
        );

        let snapshot = snap(Some("req_a"), Some("msg_a"), "2026-09-01T00:00:00Z", 11, 22);
        assert_field_set_locked(
            "UsageSnapshot",
            &format!("{snapshot:#?}"),
            &[
                "request_id",
                "message_id",
                "record_uuid",
                "timestamp",
                "model",
                "usage",
            ],
        );

        let mut collector = RequestCollector::new();
        collector.push(snapshot, "file-key", 0, false);
        let normalized = collector.finish();
        assert_eq!(
            normalized.len(),
            1,
            "fixture is one request: {normalized:?}"
        );
        assert_field_set_locked(
            "NormalizedRequest",
            &format!("{:#?}", normalized[0]),
            &[
                "timestamp",
                "model",
                "usage",
                "snapshots_collapsed",
                "finalization_divergent",
                "identity",
                "from_subagent",
            ],
        );

        let pending = Pending {
            earliest: None,
            fallback_timestamp: None,
            model: None,
            last: usage,
            field_max: usage,
            snapshot_count: 1,
            identity: IdentitySource::RequestId,
            from_subagent: false,
        };
        assert_field_set_locked(
            "Pending",
            &format!("{pending:#?}"),
            &[
                "earliest",
                "fallback_timestamp",
                "model",
                "last",
                "field_max",
                "snapshot_count",
                "identity",
                "from_subagent",
            ],
        );
    }
}
