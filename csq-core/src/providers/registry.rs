//! THE canonical provider enumeration — the union of the two descriptor tables.
//!
//! csq describes providers in **two** static tables, for two genuinely different
//! things:
//!
//! - [`crate::providers::catalog::PROVIDERS`] — **wrapped** providers. csq runs someone else's CLI
//!   (usually `claude`) against the provider's endpoint and OWNS the credential
//!   (OAuth token or Bearer key) on disk.
//! - [`crate::providers::native::NATIVE_CLIS`] — **native** providers. A self-authenticating vendor
//!   binary (`kimi`, `grok`) that csq dispatches to but whose credentials it never
//!   stores.
//!
//! Both are correct, and neither is the whole set. This module is the ONE place
//! that joins them, so a surface that needs "every provider csq knows" reads
//! [`all`] instead of picking a table and silently under-reporting the other.
//!
//! # Why this exists
//!
//! Every consumer that reached for one table alone has drifted. Measured on
//! csq 2.18.0, before this module:
//!
//! ```text
//! $ csq models list --json grok
//! Error: unknown provider: grok     # rc=1 — yet Surface::Grok, GROK, and
//!                                   # SurfaceCli::Grok all exist in csq-core
//! ```
//!
//! `csq models list` enumerated `PROVIDERS`, which legitimately does not contain
//! native-only Grok — so a provider csq fully supports was unreachable through
//! its own machine-readable surface. [`Surface::ALL`]'s own doc records the
//! identical failure one layer down: `.coc/`'s `applies_to: [all]` silently meant
//! a THREE-element set for the entire life of the Kimi/Grok surfaces, because
//! `parse_applies_to` carried its own hardcoded list.
//!
//! The structural defense is the `every_surface_has_a_descriptor` test: a compile-time-
//! adjacent guard asserting every [`Surface::ALL`] variant is represented here. A
//! sixth surface that forgets to register reds that test instead of shipping a
//! provider nobody can list.

use crate::providers::catalog::{Surface, PROVIDERS};
use crate::providers::native::{NativeCli, NATIVE_CLIS};
use crate::providers::Provider;

/// How csq reaches a provider — which determines who owns the credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderKind {
    /// csq spawns a wrapped CLI (`claude`, `codex`, `gemini`) and owns the
    /// credential on disk — OAuth tokens or a Bearer API key.
    Wrapped,
    /// csq spawns the vendor's own self-authenticating binary (`kimi`, `grok`)
    /// and stores NO credential; the vendor owns its auth under a per-slot home.
    Native,
}

impl ProviderKind {
    /// Stable tag for machine-readable surfaces (`csq sdk capabilities --json`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            ProviderKind::Wrapped => "wrapped",
            ProviderKind::Native => "native",
        }
    }
}

/// A read-only, uniform view over one provider from either table.
///
/// The `wrapped` / `native` fields expose the full underlying descriptor for
/// callers that need a field this view does not lift (settings filename, key env
/// var, device-code host, …). Exactly one is `Some`, keyed by [`Self::kind`] —
/// pinned by the `exactly_one_backing_descriptor` test.
#[derive(Debug, Clone, Copy)]
pub struct ProviderDescriptor {
    /// Short id accepted by `csq models list <id>`, `csq login --provider <id>`.
    /// Unique across the union — pinned by the `ids_are_unique_across_both_tables` test.
    pub id: &'static str,
    /// Display name.
    pub name: &'static str,
    /// Dispatch-axis surface.
    pub surface: Surface,
    /// Who owns the credential.
    pub kind: ProviderKind,
    /// Default model id. For a native CLI this is the DISPLAY value; the model
    /// csq actually pins at spawn is [`NativeCli::pinned_model`].
    pub default_model: &'static str,
    /// The backing wrapped descriptor. `Some` iff `kind == Wrapped`.
    pub wrapped: Option<&'static Provider>,
    /// The backing native descriptor. `Some` iff `kind == Native`.
    pub native: Option<&'static NativeCli>,
}

impl ProviderDescriptor {
    /// True for providers whose ONLY servicing path is the enterprise Phase-2b
    /// direct-API client (`crate::phase2b`, `#[cfg(feature = "enterprise")]`) —
    /// currently Azure OpenAI (`"azure"`) and GCP Vertex AI (`"vertex"`, an internal ticket).
    ///
    /// `catalog::PROVIDERS` carries their descriptors edition-uniformly (so e.g.
    /// error messages can name them), but neither the `csq setkey azure|vertex`
    /// CLI subcommands (`#[cfg(feature = "enterprise")]` in
    /// `csq/src/cli/mod.rs`) nor `crate::phase2b` itself compile in a community
    /// build — a community consumer has NO path to configure or route to them.
    /// Any surface that advertises "providers a host can actually use in THIS
    /// build" (`csq sdk capabilities --json` `providers[]`) MUST exclude these
    /// when the `enterprise` feature is off, or it lists two providers the
    /// community binary cannot serve.
    #[must_use]
    pub fn enterprise_only(&self) -> bool {
        matches!(self.id, "azure" | "vertex")
    }

    fn from_wrapped(p: &'static Provider) -> Self {
        Self {
            id: p.id,
            name: p.name,
            surface: p.surface,
            kind: ProviderKind::Wrapped,
            default_model: p.default_model,
            wrapped: Some(p),
            native: None,
        }
    }

    fn from_native(n: &'static NativeCli) -> Self {
        Self {
            id: n.id,
            name: n.display_name,
            surface: n.surface,
            kind: ProviderKind::Native,
            default_model: n.default_model,
            wrapped: None,
            native: Some(n),
        }
    }
}

/// Every provider csq knows, wrapped first then native, each in table order.
///
/// THE canonical enumeration. Any surface that needs "all providers" MUST read
/// this rather than iterating one table — see the module doc for what iterating
/// one table has already cost.
#[must_use]
pub fn all() -> Vec<ProviderDescriptor> {
    PROVIDERS
        .iter()
        .map(ProviderDescriptor::from_wrapped)
        .chain(
            NATIVE_CLIS
                .iter()
                .copied()
                .map(ProviderDescriptor::from_native),
        )
        .collect()
}

/// Resolve a provider id against the union. Case-sensitive, exact match —
/// mirroring `catalog::get_provider`, so behavior for a wrapped id is unchanged.
#[must_use]
pub fn lookup(id: &str) -> Option<ProviderDescriptor> {
    all().into_iter().find(|d| d.id == id)
}

/// Every known provider id, in [`all`] order. Intended for the `known` array of
/// a typed `E_UNKNOWN_PROVIDER` error, so the operator sees what IS accepted
/// rather than only what was rejected.
#[must_use]
pub fn known_ids() -> Vec<&'static str> {
    all().into_iter().map(|d| d.id).collect()
}

/// How `csq exec --provider <id>` (`csq.exec.v1`, S1) would dispatch a given
/// provider id — the ONE definition of that routing decision. `ExecSurface`
/// (`csq/src/cli/commands/exec.rs`) is private to the `csq` binary crate and
/// cannot be named here (this module cannot depend on it — see the module
/// doc), so this enum is `csq-core`'s own vocabulary for the same decision;
/// [`exec_route_for_provider_id`]'s caller in `exec.rs::resolve_slot` maps
/// each variant onto its own `ExecSurface` one-for-one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecRoute {
    /// Spawn `claude` directly against the id's own Claude Code surface.
    Claude,
    /// Spawn `gemini`.
    Gemini,
    /// Spawn `codex exec`.
    Codex,
    /// Spawn `claude`, with the named 3P catalog provider's `ANTHROPIC_BASE_URL`
    /// pinned via the resolved slot's `settings.json` (env-transport 3P:
    /// DeepSeek, Bearer Kimi, Z.AI, MiniMax, Ollama — the catalog id is carried
    /// so the caller can look up a healthy slot bound to THAT provider).
    ThirdParty(&'static str),
}

/// True iff `p` is an env-transport 3P provider reachable via `csq exec`'s
/// `ClaudeViaThirdParty`-shaped dispatch: it pins `ANTHROPIC_BASE_URL` and is
/// not `claude` itself (which routes directly as [`ExecRoute::Claude`]).
/// Excludes the enterprise Phase-2b direct-API-only providers (`azure`,
/// `vertex`), which carry no `ANTHROPIC_BASE_URL` passthrough — routing them
/// through a `claude` spawn would silently talk to an endpoint they cannot
/// serve.
fn is_env_transport_third_party(p: &Provider) -> bool {
    p.id != "claude" && p.base_url_env_var == Some("ANTHROPIC_BASE_URL")
}

/// Resolve a provider id (case-insensitive) to how `csq exec --provider <id>`
/// would route it, or `None` if `csq.exec.v1` has no dispatch for it (an
/// unknown id, a native session surface, or an enterprise direct-API-only
/// provider). THE single source of the exec-routing decision — both
/// `exec.rs::resolve_slot`'s `--provider` arm and [`exec_routable_provider_ids`]
/// (in turn `csq sdk capabilities --json`'s `features.exec.providers_routable`)
/// consume this function, so they cannot disagree about which ids are routable
/// without a change to this one place.
#[must_use]
pub fn exec_route_for_provider_id(id: &str) -> Option<ExecRoute> {
    let lower = id.to_ascii_lowercase();
    match lower.as_str() {
        "gemini" => return Some(ExecRoute::Gemini),
        "codex" => return Some(ExecRoute::Codex),
        "claude" => return Some(ExecRoute::Claude),
        _ => {}
    }
    let p = PROVIDERS.iter().find(|p| p.id == lower)?;
    is_env_transport_third_party(p).then_some(ExecRoute::ThirdParty(p.id))
}

/// Provider ids reachable through `csq exec --provider <id>` (`csq.exec.v1`, S1).
///
/// Derived from [`all`] filtered through [`exec_route_for_provider_id`] — NOT a
/// second hand-maintained list. Any id for which that function returns `Some`
/// appears here, and only such ids; the two cannot drift because this one is
/// computed from the other.
#[must_use]
pub fn exec_routable_provider_ids() -> Vec<&'static str> {
    all()
        .into_iter()
        .map(|d| d.id)
        .filter(|id| exec_route_for_provider_id(id).is_some())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The structural guard this module exists for. Every `Surface::ALL`
    /// variant MUST be reachable through the union; a sixth surface that
    /// forgets to register reds here instead of shipping a provider that no
    /// machine-readable surface can list.
    ///
    /// Non-vacuity: this test fails if `all()` iterates only `PROVIDERS`
    /// (Grok is native-only and absent from that table) or only `NATIVE_CLIS`
    /// (ClaudeCode/Codex/Gemini are absent from that one).
    #[test]
    fn every_surface_has_a_descriptor() {
        let descriptors = all();
        for surface in Surface::ALL {
            assert!(
                descriptors.iter().any(|d| d.surface == *surface),
                "surface {surface} has no ProviderDescriptor — a provider csq \
                 dispatches to would be invisible to every --json surface. \
                 Register it in PROVIDERS or NATIVE_CLIS."
            );
        }
    }

    /// The regression this module was built to fix: `grok` resolves.
    #[test]
    fn grok_resolves_through_the_union() {
        let d = lookup("grok").expect(
            "native-only `grok` must resolve — it did not before the union \
             (csq models list --json grok → `Error: unknown provider: grok`)",
        );
        assert_eq!(d.surface, Surface::Grok);
        assert_eq!(d.kind, ProviderKind::Native);
        assert!(d.native.is_some());
        assert!(!d.default_model.is_empty());
    }

    /// Wrapped lookups keep working, and keep their wrapped classification.
    #[test]
    fn wrapped_providers_still_resolve_and_are_classified_wrapped() {
        for id in ["claude", "codex", "gemini", "ollama", "deepseek"] {
            let d = lookup(id).unwrap_or_else(|| panic!("wrapped `{id}` must resolve"));
            assert_eq!(d.kind, ProviderKind::Wrapped, "{id}");
            assert!(d.wrapped.is_some(), "{id}");
        }
    }

    /// The bearer `kimi` (runs `claude` against kimi.com) and the native
    /// `kimi-cli` (runs the `kimi` binary) are DIFFERENT providers and both
    /// must be reachable. Collapsing them would silently drop one surface.
    #[test]
    fn bearer_kimi_and_native_kimi_cli_are_distinct_entries() {
        let bearer = lookup("kimi").expect("bearer kimi must resolve");
        let native = lookup("kimi-cli").expect("native kimi-cli must resolve");
        assert_eq!(bearer.kind, ProviderKind::Wrapped);
        assert_eq!(native.kind, ProviderKind::Native);
        assert_eq!(bearer.surface, Surface::ClaudeCode);
        assert_eq!(native.surface, Surface::Kimi);
    }

    /// `lookup` is only well-defined if ids do not collide across the tables.
    #[test]
    fn ids_are_unique_across_both_tables() {
        let ids = known_ids();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            ids.len(),
            "duplicate provider id across PROVIDERS + NATIVE_CLIS makes \
             `lookup` order-dependent; ids: {ids:?}"
        );
    }

    /// The `kind` discriminant and the backing-descriptor options must agree,
    /// or a caller matching on one and reading the other gets `None` on a
    /// path it believes is infallible.
    #[test]
    fn exactly_one_backing_descriptor() {
        for d in all() {
            match d.kind {
                ProviderKind::Wrapped => {
                    assert!(d.wrapped.is_some() && d.native.is_none(), "{}", d.id);
                }
                ProviderKind::Native => {
                    assert!(d.native.is_some() && d.wrapped.is_none(), "{}", d.id);
                }
            }
        }
    }

    /// An unknown id resolves to `None` and the known-id list is non-empty, so
    /// a typed `E_UNKNOWN_PROVIDER` always has something useful to report.
    #[test]
    fn unknown_id_is_none_and_known_ids_are_reportable() {
        assert!(lookup("nosuchprovider").is_none());
        let known = known_ids();
        assert!(known.len() >= PROVIDERS.len() + NATIVE_CLIS.len());
        assert!(known.contains(&"grok"));
    }

    /// `azure`/`vertex` are the ONLY enterprise-only descriptors — every other
    /// provider (wrapped or native) is usable in a community build.
    #[test]
    fn enterprise_only_is_exactly_azure_and_vertex() {
        let enterprise_only_ids: Vec<&str> = all()
            .into_iter()
            .filter(ProviderDescriptor::enterprise_only)
            .map(|d| d.id)
            .collect();
        assert_eq!(
            {
                let mut v = enterprise_only_ids;
                v.sort_unstable();
                v
            },
            vec!["azure", "vertex"]
        );
    }

    /// The exact routable set `csq exec --provider <id>` accepts today, pinned
    /// so a change to `resolve_slot`'s arms (or to this function) is a visible
    /// diff instead of a silent divergence between the two copies.
    #[test]
    fn exec_routable_provider_ids_matches_known_resolve_slot_arms() {
        let mut ids = exec_routable_provider_ids();
        ids.sort_unstable();
        assert_eq!(
            ids,
            vec!["claude", "codex", "deepseek", "gemini", "kimi", "mm", "ollama", "zai"],
            "must mirror csq/src/cli/commands/exec.rs::resolve_slot's provider-match arms"
        );
    }

    /// Non-vacuity for the exec-routable predicate: native session surfaces and
    /// the enterprise direct-API providers are NOT in the routable set.
    #[test]
    fn exec_routable_provider_ids_excludes_native_and_enterprise_only() {
        let ids = exec_routable_provider_ids();
        for excluded in ["kimi-cli", "grok", "azure", "vertex"] {
            assert!(
                !ids.contains(&excluded),
                "{excluded} must not be exec-routable (native session surface or \
                 enterprise-only direct-API provider)"
            );
        }
    }
}
