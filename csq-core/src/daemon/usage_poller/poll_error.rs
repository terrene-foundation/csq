//! [`PollError`] and its classifier.
//!
//! Split out of `mod.rs` (round-7 redteam A-H1) so [`PollError::Transport`]
//! can carry a **private-field** payload. This module is declared as a
//! private `mod poll_error;` in `mod.rs`, and [`TransportErr`]'s field is
//! declared with NO visibility modifier — private to this module's own
//! subtree. That field privacy is what makes `PollError::Transport`
//! UNCONSTRUCTIBLE outside this file. The only function in the crate that
//! can build one is [`classify_transport_error`], defined below.
//!
//! Precision about the mechanism, because the first draft of this comment
//! got it wrong and round 8 caught it: sibling pollers CAN still *name*
//! `TransportErr` — `mod poll_error;` is module-private, and Rust module
//! privacy grants the whole enclosing `usage_poller` subtree access, which
//! every sibling is inside. Verified by compile: a `type Probe =
//! super::super::poll_error::TransportErr;` in `zai.rs` compiles with zero
//! diagnostics, while `TransportErr("x".to_string())` fails `E0603: private
//! tuple struct constructor` and the round-6 decoy fails `E0308`. Naming is
//! reachable; CONSTRUCTION is not, and construction is the invariant.
//!
//! # What this replaces
//!
//! Before this split, `PollError::Transport(String)` lived in `mod.rs`
//! alongside every poller file (all children of the SAME `usage_poller`
//! module), so the `String` field was visible to all of them — nothing
//! stopped a poller from writing
//! `.map_err(|e| PollError::Transport(format!("zai: {e}")))?` and silently
//! bypassing [`classify_transport_error`] (the exact shape an unwired new
//! poller takes). The only defense was a grep-based blacklist test
//! (`no_poller_bypasses_classify_transport_error`, deleted this round) that
//! matched two known-bad spellings — a THIRD spelling, or a new poller file
//! the scanner's directory walk didn't anticipate, would have passed
//! silently. Moving the enum + classifier into their own module and making
//! the payload's field private converts the invariant into a compile
//! error, for every future call site, with no scanner to keep in sync.

/// Opaque wrapper around the raw transport-error string carried by
/// [`PollError::Transport`].
///
/// The single field is deliberately given NO visibility modifier — private
/// to this module and (vacuously) its descendants, since this module has
/// none. Every sibling poller file lives in `usage_poller/`, a PARENT of
/// this module, so Rust's privacy rules make the field — and therefore any
/// way to construct a `TransportErr` — invisible to them. [`PollError`]
/// itself is `pub(crate)` so the type can still be named and matched
/// (`PollError::Transport(_)`) everywhere; only the wildcard pattern is
/// reachable outside this file, exactly matching the existing "never
/// destructured" contract described on [`PollError::Transport`] below.
#[derive(Debug)]
pub(crate) struct TransportErr(#[allow(dead_code)] String);

/// Error from a single usage poll.
#[derive(Debug)]
pub(crate) enum PollError {
    /// A transport-layer failure (connect refused, timeout, DNS, a
    /// non-UTF8 runtime-spawn error, etc.). The payload is intentionally
    /// never destructured by any poller arm — every match site matches
    /// `Transport(_)` and logs only a fixed-vocabulary tag (`"usage
    /// poller: transport error"` / `error_kind = "..."`), never the raw
    /// string (round-2 redteam NIT — this is deliberate, not an
    /// oversight: don't "fix" this by logging the payload, even post-
    /// `redact_tokens`). Reasons NOT to surface it at any level: (1)
    /// `redact_tokens` targets `sk-ant-*`/hex patterns specifically, not
    /// every possible secret shape a future transport error could echo
    /// (e.g. a URL's userinfo password — see the LOW-2 finding on the
    /// Node transport this error can originate from); (2) the `Debug`
    /// derive above already exposes this string to anyone attaching a
    /// debugger or reading a core dump, so the payload isn't secret-free
    /// even though no *production log path* reads it — narrowing the
    /// derive is a separate, larger discussion this PR does not open.
    ///
    /// As of round-7 redteam A-H1, "never destructured" is also
    /// STRUCTURALLY enforced: the payload's type is [`TransportErr`], a
    /// private-field wrapper only [`classify_transport_error`] (this
    /// file) can construct. A poller arm that tried to bind and inspect
    /// the payload — `PollError::Transport(e) => println!("{e}")` —
    /// would still compile (matching is allowed; only construction is
    /// gated), but `e: &TransportErr` exposes no accessor, so there is
    /// nothing to read.
    #[allow(dead_code)]
    Transport(TransportErr),
    /// A PRE-FLIGHT rejection, BEFORE any network call was attempted.
    /// Despite the name, this is not URL-only and not operator-URL-only:
    /// the Node transport rejects SEVEN things pre-flight — unsafe URL
    /// characters (`http::url_has_unsafe_js_chars`), a non-`https://`
    /// scheme, URL userinfo, a URL the `url` crate cannot parse at all
    /// (round-2 redteam H1), a bearer token carrying control characters,
    /// no JS runtime (`node`/`bun`) found, and a `serde_json` encode
    /// failure (round-2 redteam M3, `ERR_NO_JS_RUNTIME` /
    /// `ERR_ENCODE_FAILED`). All seven are permanent until the operator
    /// acts, and all seven take this arm (cooldown, no quota row,
    /// `warn!`). The `error_kind = "<surface>_poll_bad_url"` tag is kept
    /// stable for log consumers; the human-readable message ("check the
    /// slot's provider settings" / "check the account's stored
    /// credentials") is accurate per-surface. Renaming the variant would
    /// touch 13+ match sites and is deliberately NOT bundled here.
    /// Distinct from [`PollError::Transport`] (MED-3, an internal ticket redteam)
    /// so poller arms can log a specific, actionable `error_kind`
    /// instead of collapsing an operator misconfiguration (e.g. a stray
    /// quote in `GROK_CLI_CHAT_PROXY_BASE_URL`) or a corrupted stored
    /// credential into the same bucket as a genuine network failure —
    /// they have different remediations and, unguarded, were
    /// indistinguishable below `debug!` level.
    ///
    /// Every production call site of the shared `HttpGetFn` closure MUST
    /// route its transport error through [`classify_transport_error`]
    /// (round-2 redteam R6-rust). As of round-7 redteam A-H1 this is a
    /// compile-time property, not a scanner-checked one — see
    /// [`TransportErr`]'s doc. The URL-shaped rejections above (unsafe
    /// chars, https-required, userinfo, unparseable) ARE reachable only
    /// from callers whose URL is built from operator-supplied input
    /// (`grok`, `minimax`) — a FIXED-constant URL (Anthropic, Codex,
    /// Z.AI, DeepSeek, Kimi) can never trip those. But the TOKEN-shaped
    /// rejections (`ERR_TOKEN_UNSAFE_CHARS`, and — process-wide, once —
    /// `ERR_NO_JS_RUNTIME` / `ERR_ENCODE_FAILED`) inspect the credential
    /// or the runtime environment, not the URL, so they are reachable
    /// from EVERY caller regardless of whether that caller's URL is
    /// fixed. The premise "reachable from the same two
    /// operator-configurable callers" (the ORIGINAL rollout's docs, and
    /// this doc's own prior revision) was therefore false for the token
    /// guard — a corrupted stored credential on a fixed-URL surface used
    /// to silently downgrade to `Transport` and retry forever at
    /// `debug!` instead of surfacing here.
    #[allow(dead_code)]
    BadUrl(String),
    RateLimited,
    Unauthorized,
    HttpError(u16),
    #[allow(dead_code)]
    Parse(String),
}

/// Classifies a Node-transport error string into [`PollError::BadUrl`]
/// when it originated from one of the shared pre-flight-rejection
/// constants in `crate::http` (`ERR_URL_UNSAFE_CHARS`,
/// `ERR_HTTPS_REQUIRED`, `ERR_URL_USERINFO`, `ERR_URL_UNPARSEABLE`,
/// `ERR_TOKEN_UNSAFE_CHARS`, `ERR_NO_JS_RUNTIME`, `ERR_ENCODE_FAILED`)
/// — matched by comparing against the constants the guards themselves
/// emit (round-2 redteam NIT: previously this matched on
/// hand-duplicated literal strings with no compile-time link to the
/// guard's actual wording — a future rewording of any message would
/// have silently downgraded `BadUrl` back to `Transport`, with only a
/// wrong `error_kind` tag in logs as the symptom; a shared `const`
/// makes a rewording a single edit both sides see) — or
/// [`PollError::Transport`] otherwise (a genuine network failure:
/// connect refused, timeout, DNS, non-UTF8 runtime spawn error, etc.).
///
/// This is the ONLY function in the crate able to construct
/// `PollError::Transport` (round-7 redteam A-H1 — see [`TransportErr`]'s
/// doc for the private-field mechanism). Every production caller of the
/// shared `HttpGetFn` / `HttpPostProbeFn` closures routes its transport
/// error through this function; the alternative — constructing
/// `PollError::Transport` directly — no longer compiles outside this
/// file. The URL-shaped constants above are reachable only from Grok's
/// `GROK_CLI_CHAT_PROXY_BASE_URL` and MiniMax's per-slot
/// `MINIMAX_GROUP_ID` — genuinely the only production call sites that
/// can trip THOSE. But `ERR_TOKEN_UNSAFE_CHARS` inspects the credential
/// every caller passes, and `ERR_NO_JS_RUNTIME` / `ERR_ENCODE_FAILED`
/// are process-wide pre-flight failures independent of the URL — all
/// three are reachable from EVERY caller, including the five
/// fixed-constant-URL surfaces (Anthropic, Codex, DeepSeek, Kimi, Z.AI)
/// that previously bypassed this classifier entirely.
pub(crate) fn classify_transport_error(e: String) -> PollError {
    if e == crate::http::ERR_URL_UNSAFE_CHARS
        || e == crate::http::ERR_HTTPS_REQUIRED
        || e == crate::http::ERR_URL_USERINFO
        || e == crate::http::ERR_URL_UNPARSEABLE
        || e == crate::http::ERR_TOKEN_UNSAFE_CHARS
        || e == crate::http::ERR_NO_JS_RUNTIME
        || e == crate::http::ERR_ENCODE_FAILED
    {
        PollError::BadUrl(e)
    } else {
        PollError::Transport(TransportErr(e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_transport_error_recognizes_the_guard_s_exact_constants() {
        // Regression test (round-2 redteam NIT): asserts the classifier
        // recognizes every shared `crate::http::ERR_*` pre-flight constant
        // BY THE SHARED CONSTANT, not a re-typed literal — so this test
        // fails to compile (not just fails at runtime) if any side's
        // reference to the constant is ever removed in favor of a
        // hand-typed string again.
        //
        // The test's NAME claims it pins "the guard's exact constants" and
        // has under-pinned before: `ERR_URL_USERINFO` was added as an inline
        // literal the classifier could not match; `ERR_URL_UNPARSEABLE` /
        // `ERR_NO_JS_RUNTIME` / `ERR_ENCODE_FAILED` were added by the M3
        // round-2 redteam followup for the same reason. Any FUTURE
        // pre-flight rejection added to the Node transport belongs here too.
        for constant in [
            crate::http::ERR_URL_UNSAFE_CHARS,
            crate::http::ERR_HTTPS_REQUIRED,
            crate::http::ERR_URL_USERINFO,
            crate::http::ERR_URL_UNPARSEABLE,
            crate::http::ERR_TOKEN_UNSAFE_CHARS,
            crate::http::ERR_NO_JS_RUNTIME,
            crate::http::ERR_ENCODE_FAILED,
        ] {
            assert!(
                matches!(
                    classify_transport_error(constant.to_string()),
                    PollError::BadUrl(_)
                ),
                "constant not classified as BadUrl: {constant}"
            );
        }
    }

    /// Structural guard for the gap above: every `return Err(...)` that
    /// `post_json_node`, `post_json_node_with_date`, and `get_bearer_node`
    /// (all three Node-transport pre-flight guards, round-7 redteam A-M2 —
    /// the ORIGINAL version of this test scanned only `get_bearer_node`,
    /// silently excluding the other two because it anchored on
    /// `get_bearer_node` and kept only the file TAIL, and the other two
    /// functions are defined earlier in `http/mod.rs`) can emit BEFORE the
    /// request leaves the process is a pre-flight URL/credential
    /// rejection, and every one of them must be a shared `ERR_*` constant
    /// the classifier can compare against. An inline literal at a
    /// rejection site is invisible to `classify_transport_error` and
    /// silently downgrades `BadUrl` to `Transport` — which is precisely
    /// how the userinfo rejection shipped mis-classified.
    ///
    /// Extended (M3, round-2 redteam followup) to ALSO cover `?`-terminated
    /// calls in the same pre-flight region: `find_js_runtime()?`,
    /// `js_url_literal(url)?`, `bearer_stdin_payload(...)?`, and
    /// `reject_userinfo(url)?` propagate whatever `Err(String)` those
    /// functions construct WITHOUT a `return Err(ERR_...)` literal at the
    /// call site itself, so the first check alone is blind to them — this is
    /// precisely how `find_js_runtime()?` / `js_url_literal(url)?` /
    /// `bearer_stdin_payload(...)?` shipped unclassified originally. Each is
    /// allow-listed here ONLY because its error is separately pinned to a
    /// shared `ERR_*` constant at its own definition (verified by
    /// `classify_transport_error_recognizes_the_guard_s_exact_constants`
    /// above) — a future pre-flight call NOT on this list fails this test
    /// loudly instead of silently mis-classifying.
    ///
    /// Round-7 redteam A-M3: the per-PHYSICAL-LINE scan (`ends_with("?;")
    /// && contains('(')`) missed a `?`-terminated call whose arguments wrap
    /// across multiple lines (rustfmt's usual shape for a long call: the
    /// opening `name(` on one line, arguments below, a lone `)?;` on the
    /// final line — that final line ends with `"?;"` but has no `(` on it).
    /// This version accumulates lines into one logical STATEMENT by
    /// tracking running parenthesis balance, and only evaluates a chunk
    /// once its parens close — so a wrapped call is scanned as the single
    /// statement it actually is, regardless of how rustfmt wrapped it.
    /// Comment-only lines are dropped before accumulation so a doc
    /// comment's prose (which can itself contain unbalanced parens, e.g.
    /// "a call (like this)") never perturbs the balance tracking.
    #[test]
    fn every_pre_flight_url_rejection_is_a_shared_constant() {
        let src = include_str!("../../http/mod.rs");
        for fn_name in [
            "post_json_node",
            "post_json_node_with_date",
            "get_bearer_node",
        ] {
            assert_pre_flight_region_uses_shared_constants(src, fn_name);
        }
    }

    /// Scans `fn_name`'s pre-flight region (from its `fn` header to its
    /// own `Command::new` spawn) for URL/credential rejections that
    /// bypass the shared `ERR_*` constants `classify_transport_error`
    /// recognises. See the doc on
    /// [`every_pre_flight_url_rejection_is_a_shared_constant`] above for
    /// the round-7 A-M2/A-M3 rationale.
    fn assert_pre_flight_region_uses_shared_constants(src: &str, fn_name: &str) {
        let anchor = format!("fn {fn_name}");
        let guard_body = src
            .split_once(anchor.as_str())
            .unwrap_or_else(|| panic!("{fn_name} must exist in csq-core/src/http/mod.rs"))
            .1;
        // Bound the scan to the pre-flight section: everything before the
        // process spawn. Rejections after that point are runtime/transport.
        let pre_flight = guard_body
            .split_once("Command::new")
            .map(|(before, _)| before)
            .unwrap_or(guard_body);

        // PREFIX form for every entry, deliberately. Two of these used to be
        // full-call-text (`"js_url_literal(url)"`, `"reject_userinfo(url)"`),
        // and the scanner joins a wrapped call with a single space before
        // matching — so the moment `cargo fmt` wraps one of them past the
        // column limit, the joined text reads `reject_userinfo( url, )?;` and
        // no longer contains the literal. Reproduced 2026-08-01 by wrapping
        // `get_bearer_node`'s guard: the test flagged the load-bearing,
        // correctly-pinned guard as unpinned.
        //
        // The fail direction was safe (over-flag, never under-flag), but an
        // audit primitive that cries wolf on correct code is one somebody
        // eventually weakens — `tooling-self-verification.md` Rule 5.
        const KNOWN_CONSTANT_PRODUCING_CALLS: &[&str] = &[
            "find_js_runtime(",
            "js_url_literal(",
            "bearer_stdin_payload(",
            "reject_userinfo(",
        ];

        let mut stmt = String::new();
        let mut depth: i32 = 0;
        for line in pre_flight.lines() {
            let t = line.trim();
            if t.is_empty() || t.starts_with("//") {
                continue;
            }
            if !stmt.is_empty() {
                stmt.push(' ');
            }
            stmt.push_str(t);
            depth += t.matches('(').count() as i32 - t.matches(')').count() as i32;
            if depth > 0 {
                // Statement continues on the next line(s) — this line's
                // parens don't close within itself, so wait for a later
                // line to bring the running balance back to (or below)
                // zero before evaluating the accumulated text.
                continue;
            }
            check_pre_flight_statement(&stmt, fn_name, KNOWN_CONSTANT_PRODUCING_CALLS);
            stmt.clear();
            depth = 0; // defensive: never let a stray negative persist
        }
        assert!(
            stmt.is_empty(),
            "{fn_name}'s pre-flight region ended with unbalanced parens \
             (scanner bug, not necessarily a source bug) — unscanned tail: {stmt}"
        );
    }

    fn check_pre_flight_statement(t: &str, fn_name: &str, known_calls: &[&str]) {
        if let Some(rest) = t.strip_prefix("return Err(") {
            assert!(
                rest.starts_with("ERR_"),
                "pre-flight rejection in {fn_name} is not a shared ERR_* constant, \
                 so classify_transport_error cannot recognise it: {t}"
            );
            return;
        }
        if t.ends_with("?;") || t.ends_with('?') {
            if !t.contains('(') {
                return;
            }
            let known = known_calls.iter().any(|f| t.contains(f));
            assert!(
                known,
                "pre-flight `?`-propagated call in {fn_name} is not a known \
                 constant-producing function, so classify_transport_error may not \
                 recognise its error: {t}"
            );
        }
    }

    #[test]
    fn classify_transport_error_does_not_misclassify_a_genuine_network_error() {
        assert!(matches!(
            classify_transport_error("connection refused".to_string()),
            PollError::Transport(_)
        ));
    }
}
