//! # DePIN SDK Validator
//!
//! Validator implementation with container architecture for the DePIN SDK.

pub mod config;
pub mod common;
pub mod standard;
pub mod hybrid;

use std::error::Error;
use depin_sdk_core::validator::ValidatorModel;