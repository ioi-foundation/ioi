// apps/autopilot/src-tauri/src/kernel/events.rs

#[path = "events/clarification.rs"]
mod clarification;
#[path = "events/emission.rs"]
mod emission;
#[path = "events/stream.rs"]
mod stream;
#[path = "events/support.rs"]
mod support;

pub use stream::monitor_kernel_events;
