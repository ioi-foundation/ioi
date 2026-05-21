// apps/autopilot/src-tauri/src/kernel/events.rs

#[path = "events/clarification.rs"]
mod clarification;
#[path = "events/emission.rs"]
mod emission;
#[path = "events/stream/mod.rs"]
mod stream;
#[path = "events/support.rs"]
mod support;

pub(crate) use emission::{build_event, register_artifact, register_event};
pub use stream::monitor_kernel_events;
pub(crate) use support::is_waiting_prompt_active;
