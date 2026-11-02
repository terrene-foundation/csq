//! Chat adapter over the shared credential-context grammar.
pub(super) use crate::context::{escaped_boundary, token_shaped};
pub(super) fn context(s: &str, i: usize) -> Option<(usize, usize)> {
    crate::context::context(s, i, crate::context::ContextProfile::Chat)
}
