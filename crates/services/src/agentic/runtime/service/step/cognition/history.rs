#![allow(dead_code)]

use crate::agentic::runtime::service::actions::safe_truncate;
use crate::agentic::runtime::types::{CommandExecution, MAX_PROMPT_HISTORY};
use ioi_types::app::agentic::ChatMessage;
use serde_json::Value;
use std::collections::{HashSet, VecDeque};

const BROWSER_OBSERVATION_CONTEXT_MAX_CHARS: usize = 1_800;
const BROWSER_SNAPSHOT_TOOL_PREFIX: &str = "Tool Output (browser__inspect):";
const PENDING_BROWSER_STATE_MAX_CHARS: usize = 560;
const SUCCESS_SIGNAL_MAX_CHARS: usize = 280;

#[path = "history/browser_snapshot.rs"]
mod browser_snapshot;
#[path = "history/filters.rs"]
mod filters;
#[path = "history/navigation.rs"]
mod navigation;
#[path = "history/signals.rs"]
mod signals;
#[cfg(test)]
#[path = "history/tests.rs"]
mod tests;

pub(super) use self::signals::{
    build_browser_observation_context_from_snapshot_with_history,
    build_browser_snapshot_success_signal_context, build_recent_browser_observation_context,
    build_recent_command_history_context, build_recent_session_events_context,
    build_recent_success_signal_context_with_snapshot,
};
#[cfg(test)]
pub(super) use self::signals::{
    build_browser_snapshot_pending_state_context, build_recent_success_signal_context,
};
pub(crate) use self::signals::{
    build_browser_snapshot_pending_state_context_with_history,
    build_recent_pending_browser_state_context,
    build_recent_pending_browser_state_context_with_current_snapshot,
    build_recent_pending_browser_state_context_with_snapshot,
    latest_recent_pending_browser_state_context,
};
use self::{browser_snapshot::*, filters::*, navigation::*, signals::*};
