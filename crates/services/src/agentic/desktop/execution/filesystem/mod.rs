use super::{ToolExecutionResult, ToolExecutor};
use ioi_types::app::agentic::AgentTool;

mod handler;
mod list;
mod ops;
mod patch;
mod path;
mod search;

use list::list_directory_entries;
use ops::{
    copy_path_deterministic, create_directory_deterministic, delete_path_deterministic,
    move_path_deterministic,
};
#[cfg(test)]
use patch::fuzzy_find_indices;
use patch::{apply_patch, edit_line_content};
#[cfg(test)]
use path::resolve_home_directory;
use path::resolve_tool_path;
use search::search_files;

pub use handler::handle;

#[cfg(test)]
mod tests;
