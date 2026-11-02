//! Explicit launch and actual-child types for governed vendor processes.

#[cfg(all(not(windows), test))]
pub(crate) use std::process::ChildStdin;
#[cfg(all(not(windows), any(feature = "cli", test)))]
pub(crate) use std::process::ChildStdout;
#[cfg(not(windows))]
pub(crate) use std::process::{Child, Command, Stdio};

#[cfg(windows)]
pub(crate) use super::windows_process::CustodyChild as Child;
#[cfg(all(windows, feature = "cli"))]
pub(crate) use super::windows_process::LoginRead as ChildStdout;
#[cfg(all(windows, test))]
pub(crate) use super::windows_process::LoginWrite as ChildStdin;
#[cfg(windows)]
pub(crate) use csq_core::platform::launch_plan::{LaunchPlan as Command, LaunchStdio as Stdio};
