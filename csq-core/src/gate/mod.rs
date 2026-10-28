//! Native hook registry admission and dispatch. Hook logic remains owned by the authoring system.
mod canonical;
pub mod dispatch;
pub mod legacy;
pub mod matcher;
pub mod mcp;
pub mod messaging;
mod output;
pub mod pin;
pub mod policy;
pub mod process;
pub mod registry;
pub mod runtime_mapping;
pub mod settings;
pub mod status;
