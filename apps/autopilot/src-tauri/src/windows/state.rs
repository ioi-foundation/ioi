use once_cell::sync::Lazy;
use std::sync::Mutex;

use super::ChatSessionLayout;

pub(super) static CHAT_SESSION_LAYOUT: Lazy<Mutex<ChatSessionLayout>> =
    Lazy::new(|| Mutex::new(ChatSessionLayout::default()));
