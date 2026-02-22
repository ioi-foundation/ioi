// Path: crates/services/src/wallet_network/mail_transport/mod.rs

mod client;
mod constants;
mod imap_ops;
mod mailbox;
mod message;
mod model;
mod util;

pub(crate) use client::mail_provider_for_config;
pub(crate) use model::{MailProviderCredentials, MailProviderMessage};
