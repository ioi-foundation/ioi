//! Chat product-shell facade.
//!
//! The current user-facing shell is chat-centric rather than a builder-style
//! studio. This module re-exports the existing Studio kernel during migration
//! so callers can adopt `chat` naming first while the compatibility layer
//! remains available.

#[allow(unused_imports)]
pub use crate::kernel::studio::*;
