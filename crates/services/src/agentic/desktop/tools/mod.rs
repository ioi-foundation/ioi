mod builtins;
mod discovery;
mod mcp;
mod services;
mod skills;

pub use discovery::discover_tools;

#[cfg(test)]
pub(crate) use builtins::should_expose_headless_browser_followups;
