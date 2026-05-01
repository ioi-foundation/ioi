//! Web retrieval pipeline lane.
//!
//! The queue lane owns the ready-work entrypoint; web-specific helpers live under
//! `service::queue::web_pipeline` until the queue processor can be split without
//! changing execution behavior.
