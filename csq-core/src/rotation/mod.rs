//! Account rotation — swap, pick best, auto-rotate.

pub mod picker;
pub mod swap;

pub use picker::{pick_best, suggest, Suggestion};
pub use swap::swap_to;
