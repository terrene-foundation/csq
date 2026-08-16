//! `csq.capabilities.v1` — the op-discovery + self-description payload DTO.
//!
//! A consumer calls `csq sdk capabilities --json` to learn which ops this binary
//! implements BEFORE invoking one, instead of discovering an unsupported op by hitting
//! a non-enveloped clap error. The `edition` field lets the consumer distinguish an op
//! that is absent-because-community from one that is absent-because-unimplemented.
//!
//! `providers[]` extends the same self-description to providers (an internal ticket): a host
//! embedding csq iterates this array instead of hand-rolling its own provider
//! allowlist, so a provider csq adds (native `kimi-cli`/`grok`, a new 3P catalog
//! entry) is visible with zero host-side code changes. Each entry also carries
//! `login` (an internal ticket): whether `csq login --provider <id>` can be driven by a host
//! with no local TTY/browser, and the process SHAPE it must handle if not — so a
//! host never has to discover drivability by attempting a login and hanging on a
//! blocking read it can never satisfy (the exact failure `csq login --provider
//! codex` produced before its own stdin-EOF guard existed).
//!
//! This crate holds only the wire SHAPE. The app (`csq-core::sdk::capabilities::build`)
//! supplies the op list it actually implements, its `EDITION`, and the provider/feature
//! values (derived from `csq-core`'s canonical provider union,
//! `csq_core::providers::registry::all`) — the SDK never feature-gates edition and
//! never depends on csq-core (R1: every payload struct here is hand-authored, never a
//! blanket `#[derive(Serialize)]` on an internal csq-core type).

use serde::Serialize;

/// Identifies the build producing this envelope.
///
/// `#[non_exhaustive]`: construct via [`ToolInfo::new`].
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct ToolInfo {
    /// Always `"csq"`.
    pub name: &'static str,
    /// This build's version (the workspace version every crate here inherits
    /// via `version.workspace = true`), supplied by the app as
    /// `env!("CARGO_PKG_VERSION")`.
    pub version: &'static str,
    /// Duplicates the top-level `edition` field (kept there for the pre-existing
    /// consumer — removing it would be a breaking wire change). Nesting it here
    /// too lets a consumer read everything about the build from one `tool` object.
    pub edition: &'static str,
}

impl ToolInfo {
    /// Build a `ToolInfo` from its three always-present fields (there are no
    /// optional fields on this DTO).
    #[must_use]
    pub fn new(name: &'static str, version: &'static str, edition: &'static str) -> Self {
        Self {
            name,
            version,
            edition,
        }
    }
}

/// Feature flags scoped to `csq exec` (`csq.exec.v1`).
///
/// `#[non_exhaustive]`: construct via [`ExecFeatures::new`].
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct ExecFeatures {
    /// Provider ids reachable through `csq exec --provider <id>` in THIS build —
    /// `csq_core::providers::registry::exec_routable_provider_ids()`, edition-filtered
    /// by the app. Native session surfaces (`kimi-cli`, `grok`) and the enterprise
    /// direct-API providers (`azure`, `vertex`) are never in this list — `exec` has
    /// no spawn path to either.
    pub providers_routable: Vec<&'static str>,
}

impl ExecFeatures {
    /// Build an `ExecFeatures` (its one field is always present).
    #[must_use]
    pub fn new(providers_routable: Vec<&'static str>) -> Self {
        Self { providers_routable }
    }
}

/// What THIS build implements, grouped by op. Every flag MUST be derived from
/// something real; a flag that cannot be honestly derived is omitted rather than
/// hardcoded — see `csq-core/src/sdk/capabilities.rs::implemented_ops`'s doc for the
/// same discipline applied to `ops`.
///
/// `#[non_exhaustive]`: construct via [`Features::new`].
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct Features {
    /// `csq exec` feature flags.
    pub exec: ExecFeatures,
}

impl Features {
    /// Build a `Features` (its one field is always present).
    #[must_use]
    pub fn new(exec: ExecFeatures) -> Self {
        Self { exec }
    }
}

/// Defines `LoginFlow` and `LoginFlow::ALL` from ONE list of variant
/// identifiers, so the two CANNOT diverge — there is no edit that adds a
/// variant to the enum without that same edit adding it to `ALL`, because
/// both are generated from this single macro expansion. `#[non_exhaustive]`
/// only restricts EXHAUSTIVE MATCHING from outside this crate; it does
/// nothing to protect a hand-maintained `&[...]` data literal like the one
/// this replaces, which had no mechanism forcing it to track the enum at
/// all — see `LoginFlow::ALL`'s doc below for the incident this fixes.
macro_rules! login_flow {
    (
        $(
            $(#[$doc:meta])*
            $variant:ident
        ),+ $(,)?
    ) => {
        /// Closed vocabulary describing what `csq login --provider <id>` itself DOES when
        /// invoked for a provider — the process SHAPE a host must handle, not the OAuth
        /// grant type (several variants below share `AuthType::OAuth` yet require
        /// completely different host handling).
        ///
        /// Serializes as a stable `snake_case` string, matching [`crate::SdkErrorCode`]'s
        /// convention. Additive: a new variant is a compat event exactly like
        /// [`crate::SdkErrorCode`]'s.
        ///
        /// `#[non_exhaustive]`: closed-per-version, not closed-forever — this vocabulary
        /// already grew once (`ExternalPrerequisite` landed after the first four names
        /// turned out to be incomplete on contact with gemini's no-headless-auth reality),
        /// so a sixth flow is a "when", not an "if". Sealing forces an external `match` to
        /// carry a `_ =>` fallback, exactly the [`crate::SdkErrorCode`] treatment. Unit-variant
        /// construction (`LoginFlow::DeviceCode`) is unaffected — only exhaustive matching
        /// is restricted, and only outside this crate.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
        #[serde(rename_all = "snake_case")]
        #[non_exhaustive]
        pub enum LoginFlow {
            $(
                $(#[$doc])*
                $variant
            ),+
        }

        impl LoginFlow {
            /// Every variant, in declaration order. THE canonical enumeration — any
            /// code that needs "all login flows" MUST read this rather than writing its
            /// own list.
            ///
            /// Generated by the SAME `login_flow!` macro expansion that defines
            /// `LoginFlow` itself, from the SAME identifier list — there is only
            /// one place a variant name is written, so `ALL` structurally cannot
            /// omit a variant the enum has. This replaces a HAND-MAINTAINED
            /// `&[...]` literal that carried a doc claiming it "restores the
            /// completeness check at test time" while implementing nothing that
            /// enforced it: `#[non_exhaustive]` forces a wildcard arm on every
            /// CROSS-CRATE match, but the old `ALL` was a plain data literal in
            /// THIS crate, never itself matched against `Self` — so adding a
            /// variant, adding its required in-crate `as_str` arm (exhaustive, no
            /// wildcard, so the compiler forces that one), and never touching
            /// `ALL` compiled clean and left both csq-core completeness tests
            /// (`every_login_flow_has_specific_instructions`,
            /// `attended_session_classification_is_explicit_for_every_known_flow`)
            /// iterating a short list — green, while missing exactly the variant
            /// they exist to catch.
            ///
            /// `csq-core`'s `Surface::ALL` carries the identical LIVE defect, not
            /// merely a historical antecedent: its own completeness test
            /// (`surface_all_covers_every_variant`) runs an exhaustive match over
            /// values DRAWN FROM `Surface::ALL`'s own contents, not over
            /// `Surface`'s full variant space — so a variant `ALL` never included
            /// is a value that loop can never produce, and the "exhaustive match"
            /// guards nothing `ALL` didn't already contain. `.coc/`'s
            /// `applies_to: [all]` silently meant a THREE-element set for the
            /// entire life of the Kimi and Grok surfaces under exactly this shape
            /// before `Surface::ALL` existed; the post-fix version reintroduced
            /// the same class in its own regression guard. Not fixed here —
            /// flagged for its own follow-up.
            pub const ALL: &'static [LoginFlow] = &[$(LoginFlow::$variant),+];
        }
    };
}

login_flow! {
    /// The vendor CLI prints a short code + a verification URL that the user
    /// completes on ANY device (phone, another browser) — `csq login` never
    /// blocks on a TTY read to obtain it. A host can capture the code + URL from
    /// the child's stdout and hand them to the user out-of-band. Kimi, Grok.
    DeviceCode,
    /// `csq login` spawns a vendor binary that manages its OWN local browser +
    /// loopback OAuth callback end-to-end; csq only waits for the child to exit.
    /// There is no code or prompt for a host to feed programmatically — a real
    /// browser must be reachable from the machine running the child. Claude.
    BrowserSubprocess,
    /// `csq login` blocks on an interactive stdin read (an explicit
    /// confirmation) before it proceeds, and refuses immediately on stdin EOF
    /// rather than hanging — but only once that blocking read is reached, which
    /// is exactly the read [`crate::SdkErrorCode::InteractionRequired`] exists to
    /// pre-empt. Codex.
    TtyRequired,
    /// `csq login` drives NOTHING interactively for this provider — it only
    /// verifies a credential file some OTHER, fully out-of-band process (the
    /// bare vendor CLI, run once by hand, outside csq's control) already
    /// produced. Gemini (gemini-cli v0.41.2+ has no non-interactive auth
    /// surface of its own to shell out to).
    ExternalPrerequisite,
    /// This provider is never reachable through `csq login` at all — it is
    /// configured via `csq setkey <id>` (a pasted Bearer API key), not an
    /// OAuth-shaped login. The 3P Bearer/None catalog entries and the
    /// enterprise-only direct-API providers.
    NotSupported,
}

impl LoginFlow {
    /// The stable wire string for this flow (matches the `Serialize` output).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DeviceCode => "device_code",
            Self::BrowserSubprocess => "browser_subprocess",
            Self::TtyRequired => "tty_required",
            Self::ExternalPrerequisite => "external_prerequisite",
            Self::NotSupported => "not_supported",
        }
    }
}

/// Per-provider login-driving metadata (an internal ticket) — whether a host with no local
/// TTY/browser can drive `csq login --provider <id>` to completion, the process
/// [`LoginFlow`] shape if not, and static instructions a host can show verbatim.
///
/// `#[non_exhaustive]`: read-only consumer data, same class as [`ProviderSummary`]
/// below — construct via [`ProviderLogin::new`] (all three fields are always
/// present — no optional fields on this DTO).
#[derive(Debug, Clone, Copy, Serialize)]
#[non_exhaustive]
pub struct ProviderLogin {
    /// `true` iff a host with no local TTY and no local browser can drive this
    /// provider's login to completion (capturing a device code and relaying it
    /// out-of-band counts as headless-drivable; blocking on a local stdin
    /// confirmation or a local browser callback does not).
    pub headless_drivable: bool,
    /// The process shape `csq login --provider <id>` follows for this provider.
    pub flow: LoginFlow,
    /// Human- and machine-readable next step. Generic per [`LoginFlow`] (not
    /// hand-tuned per provider id), so it stays derived from the flow rather than
    /// becoming a second per-provider table.
    pub instructions: &'static str,
}

impl ProviderLogin {
    /// Build a `ProviderLogin` from its three always-present fields.
    #[must_use]
    pub fn new(headless_drivable: bool, flow: LoginFlow, instructions: &'static str) -> Self {
        Self {
            headless_drivable,
            flow,
            instructions,
        }
    }
}

/// One provider entry in `providers[]` — a hand-authored view over
/// `csq_core::providers::registry::ProviderDescriptor` (never serialized directly,
/// per R1: the internal type carries fields, like the backing `wrapped`/`native`
/// descriptor references, that are not wire-shape).
///
/// `#[non_exhaustive]`: construct via [`ProviderSummary::new`] (the six
/// always-present fields — `login` carries no `skip_serializing_if` and is
/// always on the wire, so it is required alongside `id`/`name`/`surface`/
/// `kind`/`default_model`, not builder-attached like `binary`) then
/// [`ProviderSummary::with_binary`] for native providers.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct ProviderSummary {
    /// Short id accepted by `csq models list <id>`, `csq login --provider <id>`,
    /// `csq exec --provider <id>` (when also in `features.exec.providers_routable`).
    pub id: &'static str,
    /// Display name.
    pub name: &'static str,
    /// Dispatch-axis surface tag (`Surface::as_str()` — `"claude-code"`, `"codex"`,
    /// `"gemini"`, `"kimi"`, `"grok"`).
    pub surface: &'static str,
    /// Who owns the credential: `"wrapped"` (csq owns an OAuth token or Bearer key)
    /// or `"native"` (a self-authenticating vendor binary owns its own auth).
    pub kind: &'static str,
    /// Default model id. For a native CLI this is the DISPLAY value; the model csq
    /// actually pins at spawn may differ (vendor-CLI-internal detail, not exposed).
    pub default_model: &'static str,
    /// The vendor binary csq dispatches to (`"kimi"`, `"grok"`) — present only for
    /// `kind: "native"`, so a host knows what to tell the user to install.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary: Option<&'static str>,
    /// Login-driving metadata for this provider (an internal ticket).
    pub login: ProviderLogin,
}

impl ProviderSummary {
    /// Build a `ProviderSummary` from its six always-present fields; `binary`
    /// starts `None` — attach it with [`Self::with_binary`] for a native provider.
    #[must_use]
    pub fn new(
        id: &'static str,
        name: &'static str,
        surface: &'static str,
        kind: &'static str,
        default_model: &'static str,
        login: ProviderLogin,
    ) -> Self {
        Self {
            id,
            name,
            surface,
            kind,
            default_model,
            binary: None,
            login,
        }
    }

    /// Attach the vendor binary (native providers only).
    #[must_use]
    pub fn with_binary(mut self, binary: &'static str) -> Self {
        self.binary = Some(binary);
        self
    }
}

/// The `csq.capabilities.v1` payload: build identity, implemented ops, edition,
/// feature flags, and the full provider union.
///
/// `#[non_exhaustive]`: construct via [`CapabilitiesPayload::new`] (all five
/// fields are always present — no optional fields on this DTO).
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct CapabilitiesPayload {
    /// Build identity (name/version/edition).
    pub tool: ToolInfo,
    /// Short op identifiers (`"exec.v1"`, …) — the `.vN`-suffixed op names, without
    /// the `csq.` prefix carried by the envelope `schema` field.
    pub ops: Vec<&'static str>,
    /// This build's edition (`"community"` | `"enterprise"`), supplied by the app.
    /// Kept at the top level (pre-existing field, additive-only) alongside
    /// `tool.edition`.
    pub edition: &'static str,
    /// Feature flags this build honestly implements, grouped by op.
    pub features: Features,
    /// Every provider this build knows, wrapped first then native — the union
    /// `csq_core::providers::registry::all()`, edition-filtered by the app so a
    /// community build never advertises an enterprise-only provider it cannot serve.
    pub providers: Vec<ProviderSummary>,
}

impl CapabilitiesPayload {
    /// Build a `CapabilitiesPayload` from its five always-present fields.
    #[must_use]
    pub fn new(
        tool: ToolInfo,
        ops: Vec<&'static str>,
        edition: &'static str,
        features: Features,
        providers: Vec<ProviderSummary>,
    ) -> Self {
        Self {
            tool,
            ops,
            edition,
            features,
            providers,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Envelope, SCHEMA_CAPABILITIES_V1};

    fn sample_payload() -> CapabilitiesPayload {
        CapabilitiesPayload {
            tool: ToolInfo {
                name: "csq",
                version: "2.18.0",
                edition: "community",
            },
            ops: vec!["exec.v1", "capabilities.v1", "verify.v1"],
            edition: "community",
            features: Features {
                exec: ExecFeatures {
                    providers_routable: vec!["claude", "gemini", "codex"],
                },
            },
            providers: vec![
                ProviderSummary {
                    id: "claude",
                    name: "Claude",
                    surface: "claude-code",
                    kind: "wrapped",
                    default_model: "opus",
                    binary: None,
                    login: ProviderLogin {
                        headless_drivable: false,
                        flow: LoginFlow::BrowserSubprocess,
                        instructions: "run `csq login <slot>` from a machine with a reachable local browser",
                    },
                },
                ProviderSummary {
                    id: "grok",
                    name: "Grok (native CLI)",
                    surface: "grok",
                    kind: "native",
                    default_model: "grok-4.5",
                    binary: Some("grok"),
                    login: ProviderLogin {
                        headless_drivable: true,
                        flow: LoginFlow::DeviceCode,
                        instructions: "run `csq login <slot> --provider grok`; open the printed URL on any device and enter the code",
                    },
                },
            ],
        }
    }

    #[test]
    fn capabilities_payload_serializes_ops_and_edition() {
        // The SDK owns the SHAPE; construct it directly (the app owns the values).
        let env = Envelope::success(SCHEMA_CAPABILITIES_V1, None, sample_payload());
        let v: serde_json::Value = serde_json::from_str(&env.to_line().unwrap()).unwrap();
        assert_eq!(v["schema"], "csq.capabilities.v1");
        assert_eq!(v["ok"], true);
        assert_eq!(v["edition"], "community");
        let ops: Vec<&str> = v["ops"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o.as_str().unwrap())
            .collect();
        assert!(ops.contains(&"exec.v1"));
        assert!(ops.contains(&"verify.v1"));
    }

    /// Additive-only guarantee (an internal ticket): every field the pre-existing consumer reads
    /// keeps its name and JSON type at the top level.
    #[test]
    fn preexisting_fields_keep_name_type_and_top_level_position() {
        let env = Envelope::success(SCHEMA_CAPABILITIES_V1, None, sample_payload());
        let v: serde_json::Value = serde_json::from_str(&env.to_line().unwrap()).unwrap();
        assert_eq!(v["schema"], "csq.capabilities.v1");
        assert!(v["ok"].is_boolean());
        assert!(v["ops"].is_array());
        assert!(v["edition"].is_string());
    }

    #[test]
    fn tool_object_present_with_name_version_edition() {
        let env = Envelope::success(SCHEMA_CAPABILITIES_V1, None, sample_payload());
        let v: serde_json::Value = serde_json::from_str(&env.to_line().unwrap()).unwrap();
        assert_eq!(v["tool"]["name"], "csq");
        assert_eq!(v["tool"]["version"], "2.18.0");
        assert_eq!(v["tool"]["edition"], "community");
    }

    #[test]
    fn features_exec_providers_routable_present() {
        let env = Envelope::success(SCHEMA_CAPABILITIES_V1, None, sample_payload());
        let v: serde_json::Value = serde_json::from_str(&env.to_line().unwrap()).unwrap();
        let routable: Vec<&str> = v["features"]["exec"]["providers_routable"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p.as_str().unwrap())
            .collect();
        assert_eq!(routable, vec!["claude", "gemini", "codex"]);
    }

    /// Providers array carries the per-provider shape; native entries carry
    /// `binary`, wrapped entries omit it (not `null`).
    #[test]
    fn providers_array_shape_and_binary_present_only_for_native() {
        let env = Envelope::success(SCHEMA_CAPABILITIES_V1, None, sample_payload());
        let v: serde_json::Value = serde_json::from_str(&env.to_line().unwrap()).unwrap();
        let providers = v["providers"].as_array().unwrap();
        assert_eq!(providers.len(), 2);

        let claude = providers.iter().find(|p| p["id"] == "claude").unwrap();
        assert_eq!(claude["kind"], "wrapped");
        assert!(
            claude.get("binary").is_none(),
            "wrapped provider must omit binary, not null"
        );

        let grok = providers.iter().find(|p| p["id"] == "grok").unwrap();
        assert_eq!(grok["kind"], "native");
        assert_eq!(grok["binary"], "grok");
        assert_eq!(grok["surface"], "grok");
        assert_eq!(grok["default_model"], "grok-4.5");
    }

    /// AC (an internal ticket): every entry carries a `login` object with the three fields,
    /// correctly distinguishing a headless-drivable flow (grok, device code) from
    /// a non-headless one (claude, browser subprocess).
    #[test]
    fn providers_carry_login_object() {
        let env = Envelope::success(SCHEMA_CAPABILITIES_V1, None, sample_payload());
        let v: serde_json::Value = serde_json::from_str(&env.to_line().unwrap()).unwrap();
        let providers = v["providers"].as_array().unwrap();

        let claude = providers.iter().find(|p| p["id"] == "claude").unwrap();
        assert_eq!(claude["login"]["headless_drivable"], false);
        assert_eq!(claude["login"]["flow"], "browser_subprocess");
        assert!(!claude["login"]["instructions"].as_str().unwrap().is_empty());

        let grok = providers.iter().find(|p| p["id"] == "grok").unwrap();
        assert_eq!(grok["login"]["headless_drivable"], true);
        assert_eq!(grok["login"]["flow"], "device_code");
        assert!(!grok["login"]["instructions"].as_str().unwrap().is_empty());
    }

    /// `LoginFlow` wire strings are stable snake_case, matching `as_str()`.
    #[test]
    fn login_flow_wire_strings_match_as_str() {
        for (flow, wire) in [
            (LoginFlow::DeviceCode, "device_code"),
            (LoginFlow::BrowserSubprocess, "browser_subprocess"),
            (LoginFlow::TtyRequired, "tty_required"),
            (LoginFlow::ExternalPrerequisite, "external_prerequisite"),
            (LoginFlow::NotSupported, "not_supported"),
        ] {
            assert_eq!(flow.as_str(), wire);
            let json = serde_json::to_string(&flow).unwrap();
            assert_eq!(json, format!("\"{wire}\""));
        }
    }

    /// No credential material, key env VALUES, or host filesystem paths anywhere
    /// on the DTO's field set (`security.md` MUST-2, `tauri-commands.md` MUST-3) —
    /// structural guard: every field is a `&'static str` / `Option<&'static str>`
    /// literal or an id/label, never anything sourced from a live credential.
    /// Walks BOTH the top-level `ProviderSummary` keys and the nested `login`
    /// object's keys, so a future field added to either struct is covered.
    #[test]
    fn provider_summary_has_no_credential_shaped_fields() {
        let p = ProviderSummary {
            id: "claude",
            name: "Claude",
            surface: "claude-code",
            kind: "wrapped",
            default_model: "opus",
            binary: None,
            login: ProviderLogin {
                headless_drivable: false,
                flow: LoginFlow::BrowserSubprocess,
                instructions:
                    "run `csq login <slot>` from a machine with a reachable local browser",
            },
        };
        let v = serde_json::to_value(&p).unwrap();
        let obj = v.as_object().unwrap();
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        if let Some(login_obj) = obj.get("login").and_then(|l| l.as_object()) {
            keys.extend(login_obj.keys().map(String::as_str));
        }
        for forbidden in ["token", "key", "secret", "credential", "path", "home"] {
            assert!(
                !keys.iter().any(|k| k.contains(forbidden)),
                "ProviderSummary (incl. nested login) must not carry a \
                 {forbidden}-shaped field; got {keys:?}"
            );
        }
        // The `instructions` prose itself must not leak an expanded host path —
        // literal doc strings like "~/.grok/auth.json" are fine (unexpanded),
        // an interpolated `/Users/...` or `/home/...` value is not.
        let instructions = v["login"]["instructions"].as_str().unwrap();
        assert!(
            !instructions.contains("/Users/") && !instructions.contains("/home/"),
            "login.instructions must not carry an expanded host path: {instructions:?}"
        );
    }
}
