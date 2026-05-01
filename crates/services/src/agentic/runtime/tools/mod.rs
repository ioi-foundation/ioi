mod builtins;
pub mod contracts;
mod discovery;
mod mcp;
pub(crate) mod services;
pub(crate) mod skills;

pub use discovery::discover_tools;

#[cfg(test)]
pub(crate) use builtins::should_expose_headless_browser_followups;
