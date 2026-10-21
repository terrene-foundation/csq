//! `csq sessions list` — live Claude Code sessions (`csq.sessions.v1`).

use anyhow::Result;
use csq_core::messaging::registry;
use csq_core::sdk::{self, Envelope, SdkError, SdkErrorCode};
use csq_core::sdk::{SessionRow, SessionsPayload, SCHEMA_SESSIONS_V1};
use csq_core::sessions::directives::{self, PendingInfo};
use csq_core::sessions::{self, IncompleteCause, SessionRowData};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// `me` is the caller's `(pid, started_at)` when this command runs inside a session; its
/// own row alone is marked `self`. `name` stays Claude Code's registry name; `label` is the
/// registry's effective label (spec 32a 4.3), computed once here for every surface: its own
/// name, else Claude Code's, else a default.
fn to_sdk_row(
    d: SessionRowData,
    pending: &PendingInfo,
    me: Option<(u32, u64)>,
    budget: registry::LookupBudget,
) -> SessionRow {
    let path = |p: &Path| p.to_string_lossy().into_owned();
    let cand = registry::candidate_for_row_checked(&d, budget);
    let is_me = me.is_some_and(|(p, s)| p == d.pid && sessions::same_start(s, d.started_at));
    let row = SessionRow::new(
        d.pid,
        d.started_at,
        d.surface,
        path(&d.cwd),
        path(&d.handle_dir),
    )
    .with_session_id(d.session_id)
    .with_name(d.name)
    .with_account_slot(d.account_slot)
    .with_tty(d.tty)
    .with_terminal_title(d.terminal_title)
    .with_scratch_dir(d.scratch_dir.as_deref().map(path))
    .with_inbox_pending(u32::try_from(pending.pending).unwrap_or(u32::MAX))
    .with_last_directive_at(pending.last_directive_at)
    .with_self(is_me);
    match cand {
        Some((c, timed_out)) => row
            .with_label(c.name)
            .with_label_source(c.name_source.as_str().to_string())
            .with_label_fallback(timed_out)
            .with_repo(c.repo)
            .with_branch(c.branch),
        // A row with no known surface has no registry entry and so no label.
        None => row,
    }
}

/// What the listing could not see: (`incomplete`, `restricted`, unreadable pids).
type Gaps = (bool, bool, Vec<u32>);

/// Build the payload from already-enriched rows (pure; unit-testable).
fn build_payload(
    host: String,
    generated_at: u64,
    rows: Vec<(SessionRowData, PendingInfo)>,
    gaps: Gaps,
    me: Option<(u32, u64)>,
) -> SessionsPayload {
    // One repo/branch lookup budget for the whole listing (a stale mount cannot stall it).
    let budget = registry::LookupBudget::new(registry::LISTING_LOOKUP_BUDGET);
    SessionsPayload::new(
        host,
        generated_at,
        rows.into_iter()
            .map(|(d, pending)| to_sdk_row(d, &pending, me, budget))
            .collect(),
    )
    .with_gaps(gaps.0, gaps.1, gaps.2)
}

/// The one trailing line of the human table naming what was not seen; `None` when whole.
fn gaps_note(payload: &SessionsPayload, cause: Option<IncompleteCause>) -> Option<String> {
    if payload.restricted {
        return Some(
            "Process information is restricted for this caller (a sandbox?); the list above says nothing about what is running. Run csq outside the sandbox.".to_string(),
        );
    }
    if !payload.incomplete {
        return None;
    }
    // A known cause names its own next step, the same one inbox/ack print.
    if let Some(c) = cause {
        return Some(format!("The process table is incomplete: {}", c.describe()));
    }
    let n = payload.unreadable_pids.len();
    Some(if n > 0 {
        format!("{n} process(es) that may be a claude session could not be read; this list is incomplete.")
    } else {
        "The process table hides processes from this caller; this list is incomplete.".to_string()
    })
}

/// `titles`: resolve terminal titles (a bounded `osascript` on macOS). The `--json`
/// machine path passes `false` so it never waits on a terminal app (spec 31 §2).
fn enumerate(
    base_dir: &Path,
    titles: bool,
) -> Result<(SessionsPayload, Option<IncompleteCause>), String> {
    let host = directives::host_name().ok_or_else(|| "host name could not be read".to_string())?;
    let home =
        csq_core::platform::home::home_dir().ok_or_else(|| "home directory unknown".to_string())?;
    let generated_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock before epoch".to_string())?
        .as_secs();
    let listing = sessions::list_rows_detailed(base_dir, &home, titles)
        .ok_or_else(|| "the process table could not be read".to_string())?;
    let cause = listing.incomplete_cause;
    let gaps: Gaps = (
        listing.incomplete,
        listing.restricted,
        listing.unreadable_pids,
    );
    let rows = listing.rows;
    // A directive store that cannot be read makes the whole listing
    // undetermined rather than reporting `inbox_pending: 0`, which would
    // read as a measured "nothing waiting".
    // The store is loaded ONCE for every row, not once per row.
    let targets: Vec<(u32, u64)> = rows.iter().map(|r| (r.pid, r.started_at)).collect();
    let pending = directives::pending_for_targets(base_dir, &targets)
        .map_err(|e| format!("directive store unreadable: {}", e.message))?;
    let with_pending = rows.into_iter().zip(pending).collect();
    // Outside a session the caller is simply not identified: no row is marked `self`.
    let me = sessions::resolve_caller_from_env()
        .ok()
        .map(|c| (c.pid(), c.started_at()));
    Ok((
        build_payload(host, generated_at, with_pending, gaps, me),
        cause,
    ))
}

/// `csq sessions list [--repo <name>]... [--here]`. `here` resolves the current working
/// directory's repo the way a session's own `repo` is derived (`registry::repo_info`); an
/// unresolvable one is refused, never widened to every session.
pub fn handle(base_dir: &Path, json: bool, repos: &[String], here: bool) -> Result<i32> {
    let cwd = if here {
        Some(
            std::env::current_dir()
                .map_err(|e| anyhow::anyhow!("--here: current directory unreadable: {e}"))?,
        )
    } else {
        None
    };
    let wanted = resolve_wanted(repos, cwd.as_deref())?;
    handle_with(base_dir, json, &wanted, &enumerate, &sdk::emit)
}

/// What to keep: `--repo` values match by repo name; `--here` matches by the canonical common
/// git dir (`RepoInfo::repo_key`), so a worktree and its main checkout see each other and two
/// unrelated clones that share a basename stay apart.
#[derive(Debug, Default, PartialEq, Eq)]
struct Wanted {
    names: Vec<String>,
    keys: Vec<String>,
}

impl Wanted {
    fn is_empty(&self) -> bool {
        self.names.is_empty() && self.keys.is_empty()
    }
}

/// The filter for the explicit `--repo` values plus, for `--here`, the repo identity of
/// `cwd`. An empty `--repo` value or an undeterminable `--here` repo is refused rather than
/// widened to every session.
fn resolve_wanted(repos: &[String], cwd: Option<&Path>) -> Result<Wanted> {
    if repos.iter().any(String::is_empty) {
        anyhow::bail!("--repo must not be empty");
    }
    let mut wanted = Wanted {
        names: repos.to_vec(),
        keys: Vec::new(),
    };
    if let Some(cwd) = cwd {
        match csq_core::messaging::registry::repo_info(cwd).repo_key {
            Some(k) => wanted.keys.push(k),
            None => anyhow::bail!("--here: the current directory's repo could not be determined"),
        }
    }
    Ok(wanted)
}

/// Keep only rows matching `wanted`: a repo name (compared through `frame::safe_name`, as the
/// MCP `repo` filter is) or a repo key (`key_of` resolves a row's cwd; a row whose key cannot
/// be resolved is hidden, fail-closed). `wanted` empty keeps everything. Returns
/// `(dropped, unresolved)`: how many rows were dropped and how many of those were dropped only
/// because their key could not be resolved (reported separately, never as "in other repos").
/// A filtered list says nothing about the hidden rows' absence, so the gap flags are left
/// untouched.
fn filter_by_repo(
    payload: &mut SessionsPayload,
    wanted: &Wanted,
    key_of: &dyn Fn(&str) -> Option<String>,
) -> (usize, usize) {
    if wanted.is_empty() {
        return (0, 0);
    }
    let before = payload.sessions.len();
    let mut unresolved = 0usize;
    payload.sessions.retain(|s| {
        let by_name = s
            .repo
            .as_deref()
            .and_then(csq_core::messaging::frame::safe_name)
            .is_some_and(|r| wanted.names.contains(&r));
        if by_name {
            return true;
        }
        if wanted.keys.is_empty() {
            return false;
        }
        match key_of(&s.cwd) {
            Some(k) => wanted.keys.contains(&k),
            None => {
                unresolved += 1;
                false
            }
        }
    });
    (before - payload.sessions.len(), unresolved)
}

/// A row's repo key, resolved from its cwd against the ONE lookup `budget` shared by the whole
/// listing (a stale mount cannot stall it for more than that budget in total).
fn row_key(cwd: &str, budget: registry::LookupBudget) -> Option<String> {
    registry::repo_info_within(Path::new(cwd), budget).repo_key
}

type SessionEnumerator<'a> =
    dyn Fn(&Path, bool) -> Result<(SessionsPayload, Option<IncompleteCause>), String> + 'a;

/// The production handler over its enumeration and envelope-output boundaries. This keeps
/// JSON routing and the emitted full-row contract testable without reading a live host's
/// process table or redirecting process-global stdout.
fn handle_with(
    base_dir: &Path,
    json: bool,
    wanted: &Wanted,
    enumerate: &SessionEnumerator<'_>,
    emit: &dyn Fn(&Envelope<SessionsPayload>) -> std::io::Result<i32>,
) -> Result<i32> {
    let (payload, cause) = match enumerate(base_dir, !json) {
        Ok(p) => p,
        Err(reason) => {
            let msg = format!("could not enumerate sessions: {reason}");
            if json {
                return Ok(emit(&Envelope::<SessionsPayload>::failure(
                    SCHEMA_SESSIONS_V1,
                    None,
                    SdkError::new(SdkErrorCode::Undetermined, msg),
                ))?);
            }
            eprintln!("{msg}");
            return Ok(1);
        }
    };
    let mut payload = payload;
    let budget = registry::LookupBudget::new(registry::LISTING_LOOKUP_BUDGET);
    let (hidden, unresolved) = filter_by_repo(&mut payload, wanted, &|cwd| row_key(cwd, budget));
    // The JSON shape (`csq.sessions.v1`) is deliberately unchanged by the filter.
    if json {
        return Ok(emit(&Envelope::success(SCHEMA_SESSIONS_V1, None, payload))?);
    }
    print!("{}", human_text(&payload, cause));
    if hidden > unresolved {
        println!(
            "({} session(s) in other repos not shown; omit --repo/--here to list all)",
            hidden - unresolved
        );
    }
    if unresolved > 0 {
        println!("({unresolved} session(s) not shown: their repo could not be determined in time)");
    }
    Ok(0)
}

/// The human output: the table (or "No live sessions." when whole and empty) and the gap
/// note. A restricted or incomplete listing cannot vouch for an empty result, so it never
/// claims "No live sessions." — only the gap note is printed.
fn human_text(payload: &SessionsPayload, cause: Option<IncompleteCause>) -> String {
    let mut out = String::new();
    if !payload.sessions.is_empty() {
        out.push_str(&render_table(payload));
    } else if !payload.restricted && !payload.incomplete {
        out.push_str("No live sessions.\n");
    }
    if let Some(note) = gaps_note(payload, cause) {
        out.push_str(&note);
        out.push('\n');
    }
    out
}

/// Session fields are untrusted process data (a terminal title or cwd can hold
/// escape sequences). Printing them raw would let a hostile process rewrite
/// the operator's screen, so each unsafe character is shown as `\u{XXXX}`. "Unsafe" is
/// the directive store's shared predicate (`directives::is_display_unsafe`: controls,
/// every Default_Ignorable_Code_Point, separators, private use, unassigned, U+2800) plus
/// combining marks (Mn/Me).
fn escape_cell(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if directives::is_display_unsafe(c) {
            out.push_str(&format!("\\u{{{:04X}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

/// The human table: every untrusted field passes through [`escape_cell`].
fn render_table(payload: &SessionsPayload) -> String {
    let mut out = format!(
        "{:<8} {:<2} {:<5} {:<22} {:<8} {:<14} {:<18} {:<10} {:<24} CWD\n",
        "PID", "ME", "SLOT", "LABEL", "SRC", "REPO", "BRANCH", "TTY", "TITLE"
    );
    for s in &payload.sessions {
        out.push_str(&format!(
            "{:<8} {:<2} {:<5} {:<22} {:<8} {:<14} {:<18} {:<10} {:<24} {}\n",
            s.pid,
            if s.is_self == Some(true) { "*" } else { "" },
            s.account_slot.map_or("-".to_string(), |n| n.to_string()),
            escape_cell(s.label.as_deref().unwrap_or("-")),
            escape_cell(s.label_source.as_deref().unwrap_or("-")),
            escape_cell(s.repo.as_deref().unwrap_or("-")),
            escape_cell(s.branch.as_deref().unwrap_or("-")),
            escape_cell(s.tty.as_deref().unwrap_or("-")),
            escape_cell(s.terminal_title.as_deref().unwrap_or("-")),
            escape_cell(&s.cwd)
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn data(started_at: u64, scratch: Option<&str>) -> SessionRowData {
        SessionRowData {
            pid: 9,
            started_at,
            surface: "claude-code",
            session_id: None,
            name: None,
            cwd: PathBuf::from("/c"),
            handle_dir: PathBuf::from("/h"),
            account_slot: None,
            tty: None,
            terminal_title: None,
            scratch_dir: scratch.map(PathBuf::from),
        }
    }

    #[test]
    fn table_escapes_control_format_and_separator_chars() {
        let mut d = data(5, None);
        d.cwd = PathBuf::from("/a\x1b[2Jb\u{202E}c\u{2028}d\u{2029}e\u{200B}f\ng");
        d.name = Some("n\x07\u{FEFF}m".into());
        d.tty = Some("tty\r\x1b]0;x\x07".into());
        d.terminal_title = Some("t\u{0085}\u{202A}t".into());
        let none = PendingInfo {
            pending: 0,
            last_directive_at: None,
            first_summary: None,
        };
        let mut p = build_payload("h".into(), 1, vec![(d, none)], Default::default(), None);
        // The registry name is charset-safe by construction; put a hostile one straight on
        // the row so the table's own escaping stays tested.
        p.sessions[0].label = Some("n\x07\u{FEFF}m".into());
        let out = render_table(&p);
        // Header + exactly one data row: the embedded \n did not split it.
        assert_eq!(out.lines().count(), 2, "{out:?}");
        for c in out.chars().filter(|c| *c != '\n') {
            assert!(
                !directives::is_display_unsafe(c),
                "raw {:?} survived: {out:?}",
                c
            );
        }
        assert!(out.contains("\\u{001B}[2J"), "{out:?}");
        assert!(out.contains("\\u{202E}") && out.contains("\\u{2028}"));
        assert!(out.contains("\\u{2029}") && out.contains("\\u{200B}"));
        assert!(out.contains("n\\u{0007}\\u{FEFF}m"), "{out:?}");
        assert!(out.contains("\\u{0085}\\u{202A}"), "{out:?}");
    }

    #[test]
    fn table_escapes_default_ignorable_and_combining_characters() {
        // each class that hides text or alters its neighbour, with the exact escape
        for (ch, esc) in [
            ('\u{FE0F}', "\\u{FE0F}"),
            ('\u{E0100}', "\\u{E0100}"),
            ('\u{034F}', "\\u{034F}"),
            ('\u{180B}', "\\u{180B}"),
            ('\u{17B4}', "\\u{17B4}"),
            ('\u{115F}', "\\u{115F}"),
            ('\u{3164}', "\\u{3164}"),
            ('\u{FFA0}', "\\u{FFA0}"),
            ('\u{2800}', "\\u{2800}"),
            ('\u{0301}', "\\u{0301}"),
            ('\u{20DD}', "\\u{20DD}"),
        ] {
            assert_eq!(
                escape_cell(&format!("a{ch}b")),
                format!("a{esc}b"),
                "U+{:04X}",
                ch as u32
            );
        }
    }

    #[test]
    fn table_leaves_plain_text_unchanged() {
        assert_eq!(
            escape_cell("/Users/x/repos/dev/csq é日本"),
            "/Users/x/repos/dev/csq é日本"
        );
    }

    /// `name` stays Claude Code's registry name (absent for Codex); the registry adds `label`
    /// and `label_source` beside it, and only the caller's own row is `self`.
    #[test]
    fn name_keeps_its_meaning_and_label_is_additive() {
        let none = || PendingInfo {
            pending: 0,
            last_directive_at: None,
            first_summary: None,
        };
        let mut claude = data(5, None);
        claude.name = Some("regname".into());
        let mut codex = data(6, None);
        codex.pid = 10;
        codex.surface = "codex";
        let p = build_payload(
            "h".into(),
            1,
            vec![(claude, none()), (codex, none())],
            Default::default(),
            Some((9, 5)),
        );
        let v = serde_json::to_value(&p).unwrap();
        let (c, x) = (&v["sessions"][0], &v["sessions"][1]);
        assert_eq!(
            (c["name"].as_str(), c["label"].as_str()),
            (Some("regname"), Some("regname"))
        );
        assert_eq!(c["label_source"], "claude");
        assert_eq!(c["self"], true);
        assert!(
            x.get("name").is_none(),
            "Codex rows have no registry name: {x}"
        );
        assert_eq!(x["label"], "c-codex-10");
        assert_eq!(x["label_source"], "default");
        assert!(x.get("self").is_none());
        assert!(c.get("name_source").is_none());
    }

    /// I3: a row whose repo lookup did not finish says its label is a fallback, in agreement
    /// with MCP `list_sessions`; a finished lookup carries no key. Falsifier: with the plain
    /// `candidate_for_row_within` call the spent-budget row has no `label_fallback`.
    #[test]
    fn a_row_with_an_unfinished_lookup_flags_its_fallback_label() {
        let none = PendingInfo {
            pending: 0,
            last_directive_at: None,
            first_summary: None,
        };
        let spent = registry::LookupBudget::new(std::time::Duration::ZERO);
        let private = tempfile::TempDir::new().unwrap();
        let private_cwd = private.path().canonicalize().unwrap();
        let mut codex = data(6, None);
        codex.surface = "codex";
        codex.cwd = private_cwd.clone();
        codex.handle_dir = private_cwd;
        let slow = serde_json::to_value(to_sdk_row(codex.clone(), &none, None, spent)).unwrap();
        assert_eq!(slow["label_fallback"], true, "{slow}");
        // Ample time cannot guarantee a slot in the process-wide four-lookup gate.
        // Retry genuine cap fallbacks until THIS private lookup actually completes;
        // a permanently broken lookup still fails at the bounded readiness deadline.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let ok = loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            assert!(!left.is_zero(), "private lookup never completed");
            let healthy = registry::LookupBudget::new(left);
            let row =
                serde_json::to_value(to_sdk_row(codex.clone(), &none, None, healthy)).unwrap();
            if row.get("label_fallback").is_none() {
                break row;
            }
            assert_eq!(
                row["label_fallback"], true,
                "unexpected fallback mapping: {row}"
            );
            assert!(
                std::time::Instant::now() < deadline,
                "private lookup never completed: {row}"
            );
            std::thread::sleep(std::time::Duration::from_millis(2));
        };
        assert!(ok.get("label_fallback").is_none(), "{ok}");
    }

    /// Pin the production handler's JSON branch and full CLI row. The public `handle`
    /// delegates here with real enumeration and sdk::emit. Fixture enumeration does not
    /// characterize live-host process discovery or shell argument dispatch.
    #[test]
    fn sessions_list_json_retains_full_cli_row_contract() {
        let private = tempfile::TempDir::new().unwrap();
        let private_cwd = private.path().join("c");
        std::fs::create_dir(&private_cwd).unwrap();
        let private_cwd = private_cwd.canonicalize().unwrap();
        let private_handle = private.path().join("h");
        let mut row = data(5, Some("/private/scratch"));
        row.cwd = private_cwd.clone();
        row.handle_dir = private_handle.clone();
        row.session_id = Some("session-id".into());
        row.name = Some("registered".into());
        row.account_slot = Some(7);
        row.tty = Some("ttys007".into());
        row.terminal_title = Some("Review".into());
        let calls = std::cell::Cell::new(0);
        let lines = std::cell::RefCell::new(Vec::new());
        let enumerate = |base: &Path, titles: bool| {
            assert_eq!(base, Path::new("/fixture-base"));
            assert!(!titles, "json=true must disable terminal-title lookup");
            calls.set(calls.get() + 1);
            let pending = PendingInfo {
                pending: 2,
                last_directive_at: Some(77),
                first_summary: None,
            };
            // A shared lookup gate may correctly return fallback under parallel tests.
            // Wait for an actual completed private lookup before pinning its full row.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            let payload = loop {
                assert!(
                    std::time::Instant::now() < deadline,
                    "private JSON lookup never completed"
                );
                let payload = build_payload(
                    "test-host".into(),
                    88,
                    vec![(row.clone(), pending.clone())],
                    Default::default(),
                    Some((9, 5)),
                );
                let wire = serde_json::to_value(&payload).unwrap();
                let actual = &wire["sessions"][0];
                if actual.get("label_fallback").is_none() {
                    break payload;
                }
                assert_eq!(
                    actual["label_fallback"], true,
                    "unexpected fallback mapping: {actual}"
                );
                assert!(
                    std::time::Instant::now() < deadline,
                    "private JSON lookup never completed: {actual}"
                );
                std::thread::sleep(std::time::Duration::from_millis(2));
            };
            Ok((payload, None))
        };
        let emit = |env: &Envelope<SessionsPayload>| {
            lines.borrow_mut().push(env.to_line().unwrap());
            Ok(if env.ok { 0 } else { 1 })
        };
        assert_eq!(
            handle_with(
                Path::new("/fixture-base"),
                true,
                &Wanted::default(),
                &enumerate,
                &emit
            )
            .unwrap(),
            0
        );
        assert_eq!(calls.get(), 1);
        let lines = lines.into_inner();
        assert_eq!(
            lines.len(),
            1,
            "exactly one envelope reaches the output boundary"
        );
        let line = &lines[0];
        assert_eq!(line.lines().count(), 1);
        let wire: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(wire["schema"], "csq.sessions.v1");
        assert_eq!(wire["ok"], true);
        assert_eq!(wire["host"], "test-host");
        assert_eq!(wire["generated_at"], 88);
        assert_eq!(
            wire["sessions"],
            serde_json::json!([{
                "pid":9,"started_at":5,"surface":"claude-code","session_id":"session-id",
                "name":"registered","label":"registered","label_source":"claude","repo":"c",
                "self":true,"cwd":private_cwd.to_string_lossy(),"handle_dir":private_handle.to_string_lossy(),"account_slot":7,"tty":"ttys007",
                "terminal_title":"Review","scratch_dir":"/private/scratch","scratch_dir_verified":true,
                "inbox_pending":2,"last_directive_at":77
            }])
        );
    }

    #[test]
    fn payload_line_has_absent_optionals_and_scratch_pair() {
        let none = PendingInfo {
            pending: 0,
            last_directive_at: None,
            first_summary: None,
        };
        let two = PendingInfo {
            pending: 2,
            last_directive_at: Some(77),
            first_summary: Some("s".into()),
        };
        let p = build_payload(
            "h".into(),
            1,
            vec![
                (data(5, None), none),
                (data(6, Some("/private/tmp/claude-501/p/s")), two),
            ],
            Default::default(),
            None,
        );
        let line = Envelope::success(SCHEMA_SESSIONS_V1, None, p)
            .to_line()
            .unwrap();
        assert!(!line.contains("null"), "absent, never null: {line}");
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["schema"], "csq.sessions.v1");
        assert!(v["sessions"][0].get("scratch_dir").is_none());
        assert_eq!(v["sessions"][1]["scratch_dir_verified"], true);
        assert_eq!(v["sessions"][0]["inbox_pending"], 0);
        assert!(v["sessions"][0].get("last_directive_at").is_none());
        assert_eq!(v["sessions"][1]["inbox_pending"], 2);
        assert_eq!(v["sessions"][1]["last_directive_at"], 77);
    }

    fn row() -> (SessionRowData, PendingInfo) {
        (
            data(5, None),
            PendingInfo {
                pending: 0,
                last_directive_at: None,
                first_summary: None,
            },
        )
    }

    #[test]
    fn json_carries_the_gaps_and_the_human_note_names_them() {
        let whole = build_payload("h".into(), 1, vec![row()], Default::default(), None);
        assert_eq!(
            gaps_note(&whole, None),
            None,
            "a whole listing prints no note"
        );
        let line = Envelope::success(SCHEMA_SESSIONS_V1, None, whole)
            .to_line()
            .unwrap();
        assert!(
            !line.contains("incomplete") && !line.contains("unreadable_pids"),
            "{line}"
        );

        let part = build_payload(
            "h".into(),
            1,
            vec![row()],
            (false, false, vec![41, 42]),
            None,
        );
        let v: serde_json::Value = serde_json::to_value(&part).unwrap();
        assert_eq!(v["incomplete"], true);
        assert_eq!(v["unreadable_pids"], serde_json::json!([41, 42]));
        let note = gaps_note(&part, None).unwrap();
        assert!(
            note.starts_with("2 process(es)") && note.contains("incomplete"),
            "{note}"
        );

        let hid = build_payload("h".into(), 1, vec![], (true, false, vec![]), None);
        assert!(gaps_note(&hid, None).unwrap().contains("hides processes"));
        let res = build_payload("h".into(), 1, vec![], (false, true, vec![1]), None);
        assert!(gaps_note(&res, None).unwrap().contains("restricted"));
        // a known cause names its own next step, even with unreadable pids
        let cause = build_payload("h".into(), 1, vec![], (true, false, vec![3]), None);
        let note = gaps_note(&cause, Some(IncompleteCause::Hidepid)).unwrap();
        assert!(note.contains("remount /proc"), "{note}");
    }

    fn row_in(pid: u32, repo: &str) -> SessionRow {
        SessionRow::new(pid, 1, "claude-code", "/w", "/h").with_repo(Some(repo.to_string()))
    }

    #[test]
    fn repo_filter_keeps_only_named_repos_counts_the_rest_and_empty_keeps_all() {
        let mk = || {
            SessionsPayload::new(
                "h",
                1,
                vec![
                    row_in(1, "csq"),
                    row_in(2, "loom"),
                    row_in(3, "csq"),
                    row_in(4, "trestle"),
                ],
            )
        };
        let names = |v: &[&str]| Wanted {
            names: v.iter().map(|x| x.to_string()).collect(),
            keys: vec![],
        };
        let no_key = |_: &str| None;
        let mut p = mk();
        assert_eq!(filter_by_repo(&mut p, &names(&["csq"]), &no_key).0, 2);
        assert_eq!(
            p.sessions.iter().map(|s| s.pid).collect::<Vec<_>>(),
            vec![1, 3]
        );
        let mut p = mk();
        assert_eq!(
            filter_by_repo(&mut p, &names(&["csq", "loom"]), &no_key).0,
            1
        );
        assert_eq!(p.sessions.len(), 3);
        let mut p = mk();
        assert_eq!(filter_by_repo(&mut p, &Wanted::default(), &no_key).0, 0);
        assert_eq!(p.sessions.len(), 4);
        let mut p = mk();
        assert_eq!(filter_by_repo(&mut p, &names(&["nope"]), &no_key).0, 4);
        assert!(p.sessions.is_empty());
    }

    #[test]
    fn json_output_is_filtered_rows_with_the_schema_unchanged() {
        let lines = std::cell::RefCell::new(Vec::new());
        let enumerate = |_: &Path, _: bool| {
            Ok((
                SessionsPayload::new("h", 1, vec![row_in(1, "csq"), row_in(2, "loom")]),
                None,
            ))
        };
        let emit = |env: &Envelope<SessionsPayload>| {
            lines.borrow_mut().push(env.to_line().unwrap());
            Ok(0)
        };
        handle_with(
            Path::new("/b"),
            true,
            &Wanted {
                names: vec!["loom".to_string()],
                keys: vec![],
            },
            &enumerate,
            &emit,
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(lines.borrow()[0].trim()).unwrap();
        assert_eq!(v["schema"], "csq.sessions.v1");
        let rows = v["sessions"].as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["repo"], "loom");
    }

    #[test]
    fn here_keys_on_the_common_git_dir_so_worktrees_meet_and_same_basename_clones_do_not() {
        let mk = || {
            SessionsPayload::new(
                "h",
                1,
                vec![
                    SessionRow::new(1, 1, "claude-code", "/main/app", "/h")
                        .with_repo(Some("app".into())),
                    SessionRow::new(2, 1, "claude-code", "/wt/feature", "/h")
                        .with_repo(Some("feature".into())),
                    SessionRow::new(3, 1, "claude-code", "/other/app", "/h")
                        .with_repo(Some("app".into())),
                ],
            )
        };
        let key_of = |cwd: &str| match cwd {
            "/main/app" | "/wt/feature" => Some("/k/app/.git".to_string()),
            "/other/app" => Some("/k/other/.git".to_string()),
            _ => None,
        };
        let here = Wanted {
            names: vec![],
            keys: vec!["/k/app/.git".to_string()],
        };
        let mut p = mk();
        assert_eq!(filter_by_repo(&mut p, &here, &key_of), (1, 0));
        assert_eq!(
            p.sessions.iter().map(|s| s.pid).collect::<Vec<_>>(),
            vec![1, 2]
        );
    }

    #[test]
    fn rows_whose_key_cannot_be_resolved_are_hidden_and_counted_separately() {
        let mut p = SessionsPayload::new(
            "h",
            1,
            vec![
                SessionRow::new(1, 1, "claude-code", "/mine", "/h"),
                SessionRow::new(2, 1, "claude-code", "/gone", "/h"),
                SessionRow::new(3, 1, "claude-code", "/theirs", "/h"),
            ],
        );
        let key_of = |cwd: &str| match cwd {
            "/mine" => Some("/k/a".to_string()),
            "/theirs" => Some("/k/b".to_string()),
            _ => None,
        };
        let here = Wanted {
            names: vec![],
            keys: vec!["/k/a".to_string()],
        };
        assert_eq!(filter_by_repo(&mut p, &here, &key_of), (2, 1));
        assert_eq!(p.sessions.len(), 1);
    }

    #[test]
    fn here_resolves_the_cwd_repo_key_and_bad_values_are_refused() {
        let d = tempfile::TempDir::new().unwrap();
        std::fs::create_dir(d.path().join(".git")).unwrap();
        let key = csq_core::messaging::registry::repo_info(d.path())
            .repo_key
            .unwrap();
        let w = resolve_wanted(&["x".to_string()], Some(d.path())).unwrap();
        assert_eq!(w.names, vec!["x".to_string()]);
        assert_eq!(w.keys, vec![key]);
        assert!(resolve_wanted(&[], None).unwrap().is_empty());
        assert!(resolve_wanted(&[String::new()], None).is_err());
    }

    /// A restricted empty listing prints the restricted note and NOT "No live sessions.";
    /// controls: unrestricted empty prints it; a restricted one with rows prints the table.
    #[test]
    fn a_restricted_empty_listing_does_not_claim_no_live_sessions() {
        let res = build_payload("h".into(), 1, vec![], (false, true, vec![]), None);
        let t = human_text(&res, None);
        assert!(
            !t.contains("No live sessions") && t.contains("restricted"),
            "{t}"
        );
        let inc = build_payload("h".into(), 1, vec![], (true, false, vec![]), None);
        let t = human_text(&inc, Some(IncompleteCause::Hidepid));
        assert!(!t.contains("No live sessions"), "incomplete: {t}");
        let whole = build_payload("h".into(), 1, vec![], Default::default(), None);
        assert_eq!(human_text(&whole, None), "No live sessions.\n", "control");
        let rows = build_payload("h".into(), 1, vec![row()], (false, true, vec![]), None);
        assert!(human_text(&rows, None).starts_with("PID"));
    }
}
