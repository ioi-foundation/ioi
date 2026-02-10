// Path: crates/api/src/services/capabilities.rs

//! This module previously defined service-specific capability traits.
//! With the architectural shift to a generic `handle_service_call` method
//! on the `BlockchainService` trait, specialized handler traits like
//! `IbcPayloadHandler` are no longer necessary.
//!
//! All service-specific logic is now dispatched through `handle_service_call`,
//! making this module's contents obsolete. It is kept as a placeholder
//! in case future, non-dispatch capabilities (beyond lifecycle hooks like
//! `OnEndBlock` or `TxDecorator`) are needed.

// The IbcPayloadHandler trait has been removed.
// All dispatch logic is now handled by the `BlockchainService::handle_service_call` method.

// The ServiceCapabilities trait has been removed for the same reason.
