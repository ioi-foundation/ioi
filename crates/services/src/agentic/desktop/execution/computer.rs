// Path: crates/services/src/agentic/desktop/execution/computer.rs

use super::{ToolExecutionResult, ToolExecutor};
use ioi_types::app::agentic::AgentTool;
use std::collections::BTreeMap;

mod click;
mod dispatch;
mod input;
mod semantics;
mod signals;
mod targeting;
mod tree;
mod ui_find;
mod verification;

pub(super) use click::{click_element_by_id, click_element_by_id_with_button, exec_click};
pub use input::{build_cursor_click_sequence, build_cursor_drag_sequence};
pub use semantics::{find_semantic_ui_match, UiFindSemanticMatch};
pub(super) use tree::fetch_lensed_tree;

pub async fn handle(
    exec: &ToolExecutor,
    tool: AgentTool,
    som_map: Option<&BTreeMap<u32, (i32, i32, i32, i32)>>,
    semantic_map: Option<&BTreeMap<u32, String>>,
    active_lens: Option<&str>,
) -> ToolExecutionResult {
    dispatch::handle(exec, tool, som_map, semantic_map, active_lens).await
}

#[cfg(test)]
mod tests;
