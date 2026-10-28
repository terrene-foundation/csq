//! `csq.sessions.v1` — the live-session listing wire payload.
//!
//! The CLI supplies discovered values; this module owns only their public
//! serialized shape. Every optional field is ABSENT on the wire when unknown,
//! never `null` (spec 30 §3).

use serde::Serialize;

/// One live session. Identity is `(pid, started_at)` (INV-31-01): both are
/// always present, so a row can always be targeted safely.
///
/// Construct with [`Self::new`], then the `with_*` builders.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct SessionRow {
    /// OS process id.
    pub pid: u32,
    /// OS process start time, unix seconds.
    pub started_at: u64,
    /// Session surface: `"claude-code"` or `"codex"`.
    pub surface: String,
    /// Claude Code session id, from its own registry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Claude Code session name, from its own registry. Unchanged by the session registry:
    /// absent for a Codex row.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The session's effective label (spec 32a §4.3): its own name, else Claude Code's
    /// registry name, else `<repo>-<surface>-<pid>`. What `send` resolves a name against;
    /// a label, never an identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Where `label` came from: `"self"`, `"claude"` or `"default"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label_source: Option<String>,
    /// `true` when this row's repo lookup did not finish in time (whatever `label_source` is).
    /// `repo`/`branch` then come from the cwd basename, and a `"default"` label may differ from
    /// the one the session really holds (spec 32a §4.3). Absent when `false`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub label_fallback: bool,
    /// Git toplevel basename of the session's cwd (never a path).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    /// Git branch of the session's cwd, or `"detached"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    /// `true` on the caller's own row only; absent elsewhere.
    #[serde(rename = "self", skip_serializing_if = "Option::is_none")]
    pub is_self: Option<bool>,
    /// Working directory at process creation.
    pub cwd: String,
    /// The session's handle dir (`CLAUDE_CONFIG_DIR`, or `CODEX_HOME` for a Codex row).
    pub handle_dir: String,
    /// Account slot from the handle dir's `.csq-account` marker.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_slot: Option<u16>,
    /// Controlling TTY basename.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tty: Option<String>,
    /// Terminal tab title, best effort.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminal_title: Option<String>,
    /// Scratch directory, present only when it exists on disk.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scratch_dir: Option<String>,
    /// `true` exactly when `scratch_dir` is present; absent otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scratch_dir_verified: Option<bool>,
    /// Directives queued or surfaced and not yet acknowledged.
    pub inbox_pending: u32,
    /// Unix seconds of the most recent directive's last transition.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_directive_at: Option<u64>,
}

impl SessionRow {
    /// Build the always-present fields; every optional starts absent and
    /// `inbox_pending` starts at 0.
    #[must_use]
    pub fn new(
        pid: u32,
        started_at: u64,
        surface: impl Into<String>,
        cwd: impl Into<String>,
        handle_dir: impl Into<String>,
    ) -> Self {
        Self {
            pid,
            started_at,
            surface: surface.into(),
            session_id: None,
            name: None,
            label: None,
            label_source: None,
            label_fallback: false,
            repo: None,
            branch: None,
            is_self: None,
            cwd: cwd.into(),
            handle_dir: handle_dir.into(),
            account_slot: None,
            tty: None,
            terminal_title: None,
            scratch_dir: None,
            scratch_dir_verified: None,
            inbox_pending: 0,
            last_directive_at: None,
        }
    }

    /// Set the session id (`None` keeps it absent).
    #[must_use]
    pub fn with_session_id(mut self, v: impl Into<Option<String>>) -> Self {
        self.session_id = v.into();
        self
    }

    /// Set the session name (`None` keeps it absent).
    #[must_use]
    pub fn with_name(mut self, v: impl Into<Option<String>>) -> Self {
        self.name = v.into();
        self
    }

    /// Set the effective label (`None` keeps it absent).
    #[must_use]
    pub fn with_label(mut self, v: impl Into<Option<String>>) -> Self {
        self.label = v.into();
        self
    }

    /// Set the label source (`None` keeps it absent).
    #[must_use]
    pub fn with_label_source(mut self, v: impl Into<Option<String>>) -> Self {
        self.label_source = v.into();
        self
    }

    /// Mark the label as a lookup fallback (`false` keeps the key absent).
    #[must_use]
    pub fn with_label_fallback(mut self, v: bool) -> Self {
        self.label_fallback = v;
        self
    }

    /// Set the repo label (`None` keeps it absent).
    #[must_use]
    pub fn with_repo(mut self, v: impl Into<Option<String>>) -> Self {
        self.repo = v.into();
        self
    }

    /// Set the branch label (`None` keeps it absent).
    #[must_use]
    pub fn with_branch(mut self, v: impl Into<Option<String>>) -> Self {
        self.branch = v.into();
        self
    }

    /// Mark this row as the caller's own (`false` keeps it absent).
    #[must_use]
    pub fn with_self(mut self, v: bool) -> Self {
        self.is_self = v.then_some(true);
        self
    }

    /// Set the account slot (`None` keeps it absent).
    #[must_use]
    pub fn with_account_slot(mut self, v: impl Into<Option<u16>>) -> Self {
        self.account_slot = v.into();
        self
    }

    /// Set the TTY (`None` keeps it absent).
    #[must_use]
    pub fn with_tty(mut self, v: impl Into<Option<String>>) -> Self {
        self.tty = v.into();
        self
    }

    /// Set the terminal title (`None` keeps it absent).
    #[must_use]
    pub fn with_terminal_title(mut self, v: impl Into<Option<String>>) -> Self {
        self.terminal_title = v.into();
        self
    }

    /// Set the scratch dir. `Some` also sets `scratch_dir_verified = true`;
    /// `None` leaves BOTH keys absent, so they can never disagree.
    #[must_use]
    pub fn with_scratch_dir(mut self, v: impl Into<Option<String>>) -> Self {
        self.scratch_dir = v.into();
        self.scratch_dir_verified = self.scratch_dir.as_ref().map(|_| true);
        self
    }

    /// Set the pending-directive count.
    #[must_use]
    pub fn with_inbox_pending(mut self, n: u32) -> Self {
        self.inbox_pending = n;
        self
    }

    /// Set the last directive time (`None` keeps it absent).
    #[must_use]
    pub fn with_last_directive_at(mut self, v: impl Into<Option<u64>>) -> Self {
        self.last_directive_at = v.into();
        self
    }
}

/// Success payload flattened into the `csq.sessions.v1` envelope.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct SessionsPayload {
    /// This host's name.
    pub host: String,
    /// When the listing was taken, unix seconds.
    pub generated_at: u64,
    /// Live sessions; the key stays present when empty ("none live").
    pub sessions: Vec<SessionRow>,
    /// `true` when the listing may not be whole: the process table hides processes from
    /// the caller, the caller is `restricted`, or `unreadable_pids` is non-empty. Absent
    /// (never `false`, never null) when the listing is whole.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub incomplete: bool,
    /// `true` when the caller cannot read process information at all (a sandbox), so
    /// `sessions` says nothing about what is running. Absent when not applicable.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub restricted: bool,
    /// Pids that may be a session and could not be read, in listing order. Absent when
    /// empty.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unreadable_pids: Vec<u32>,
}

impl SessionsPayload {
    /// Build a listing payload.
    #[must_use]
    pub fn new(host: impl Into<String>, generated_at: u64, sessions: Vec<SessionRow>) -> Self {
        Self {
            host: host.into(),
            generated_at,
            sessions,
            incomplete: false,
            restricted: false,
            unreadable_pids: Vec::new(),
        }
    }

    /// Record what the listing could not see. `incomplete` is also set when `restricted` or
    /// `unreadable_pids` is non-empty, because either means the listing is not whole.
    #[must_use]
    pub fn with_gaps(
        mut self,
        incomplete: bool,
        restricted: bool,
        unreadable_pids: Vec<u32>,
    ) -> Self {
        self.incomplete = incomplete || restricted || !unreadable_pids.is_empty();
        self.restricted = restricted;
        self.unreadable_pids = unreadable_pids;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Envelope;
    use serde_json::json;

    #[test]
    fn minimal_row_omits_every_unknown_optional_not_null() {
        let row = SessionRow::new(7, 100, "claude-code", "/c", "/h");
        let v = serde_json::to_value(&row).unwrap();
        assert_eq!(
            v,
            json!({"pid":7,"started_at":100,"surface":"claude-code","cwd":"/c",
                   "handle_dir":"/h","inbox_pending":0})
        );
        for k in [
            "session_id",
            "name",
            "label",
            "label_source",
            "label_fallback",
            "repo",
            "branch",
            "self",
            "account_slot",
            "tty",
            "terminal_title",
            "scratch_dir",
            "scratch_dir_verified",
            "last_directive_at",
        ] {
            assert!(v.get(k).is_none(), "{k} must be absent, not null");
        }
    }

    #[test]
    fn scratch_dir_sets_verified_together_and_clears_together() {
        let row = SessionRow::new(1, 2, "claude-code", "/c", "/h")
            .with_scratch_dir("/private/tmp/claude-501/p/s".to_string());
        let v = serde_json::to_value(&row).unwrap();
        assert_eq!(v["scratch_dir"], "/private/tmp/claude-501/p/s");
        assert_eq!(v["scratch_dir_verified"], true);
        let v = serde_json::to_value(row.with_scratch_dir(None)).unwrap();
        assert!(v.get("scratch_dir").is_none() && v.get("scratch_dir_verified").is_none());
    }

    #[test]
    fn payload_envelope_is_one_line_with_flattened_keys_and_empty_list_kept() {
        let env = Envelope::success(
            "csq.sessions.v1",
            None,
            SessionsPayload::new("h1", 1790900000, Vec::new()),
        );
        let line = env.to_line().unwrap();
        assert!(!line.contains('\n'));
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(
            v,
            json!({"schema":"csq.sessions.v1","ok":true,"host":"h1",
                   "generated_at":1790900000u64,"sessions":[]})
        );
    }

    #[test]
    fn gaps_are_absent_when_whole_and_present_when_not() {
        let whole = SessionsPayload::new("h", 1, Vec::new()).with_gaps(false, false, Vec::new());
        let v = serde_json::to_value(&whole).unwrap();
        for k in ["incomplete", "restricted", "unreadable_pids"] {
            assert!(v.get(k).is_none(), "{k} must be absent when whole");
        }
        let v = serde_json::to_value(SessionsPayload::new("h", 1, Vec::new()).with_gaps(
            false,
            false,
            vec![4, 9],
        ))
        .unwrap();
        assert_eq!(v["incomplete"], true, "unreadable pids make it incomplete");
        assert_eq!(v["unreadable_pids"], json!([4, 9]));
        assert!(v.get("restricted").is_none());
        let v = serde_json::to_value(SessionsPayload::new("h", 1, Vec::new()).with_gaps(
            false,
            true,
            Vec::new(),
        ))
        .unwrap();
        assert_eq!(
            (v["incomplete"].clone(), v["restricted"].clone()),
            (json!(true), json!(true))
        );
    }

    #[test]
    fn full_row_carries_all_keys() {
        let row = SessionRow::new(17259, 1790726000, "claude-code", "/c", "/h")
            .with_session_id("sid".to_string())
            .with_name("csq-04".to_string())
            .with_label("worker".to_string())
            .with_label_source("self".to_string())
            .with_repo("csq".to_string())
            .with_branch("main".to_string())
            .with_self(true)
            .with_account_slot(9u16)
            .with_tty("ttys003".to_string())
            .with_inbox_pending(2)
            .with_last_directive_at(5u64);
        let v = serde_json::to_value(&row).unwrap();
        assert_eq!(v["session_id"], "sid");
        assert_eq!(v["account_slot"], 9);
        assert_eq!(v["name"], "csq-04", "name stays the registry name");
        assert_eq!(v["label"], "worker");
        assert_eq!(v["label_source"], "self");
        assert_eq!(v["repo"], "csq");
        assert_eq!(v["branch"], "main");
        assert_eq!(v["self"], true, "wire key is `self`, not `is_self`");
        assert!(
            serde_json::to_value(SessionRow::new(1, 2, "codex", "/c", "/h").with_self(false))
                .unwrap()
                .get("self")
                .is_none()
        );
        assert_eq!(v["inbox_pending"], 2);
        assert_eq!(v["last_directive_at"], 5);
    }
}
