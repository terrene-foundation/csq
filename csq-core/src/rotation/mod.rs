//! Account rotation — swap, pick best, auto-rotate.

pub mod config;
pub mod picker;
pub mod swap;

pub use config::RotationConfig;
pub use picker::{pick_best, suggest, Suggestion};
pub use swap::swap_to;
