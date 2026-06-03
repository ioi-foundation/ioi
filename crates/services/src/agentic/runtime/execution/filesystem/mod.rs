use super::{ToolExecutionResult, ToolExecutor};
use ioi_types::app::agentic::AgentTool;

mod boundary;
mod handler;
mod ignore;
mod list;
mod ops;
mod patch;
mod path;
mod search;

use list::list_directory_entries;
use ops::{
    copy_path_deterministic, create_directory_deterministic,
    create_zip_from_directory_deterministic, delete_path_deterministic, move_path_deterministic,
    stat_path_deterministic,
};
#[cfg(test)]
use patch::fuzzy_find_indices;
use patch::{apply_patch, edit_line_content};
#[cfg(test)]
use path::resolve_home_directory;
pub(crate) use path::resolve_tool_path;
use search::search_files;

use boundary::ensure_within_workspace_path;
pub use handler::handle;
#[cfg(test)]
use handler::workspace_change_status_output;
use ignore::ensure_not_ignored_workspace_path;

#[cfg(test)]
mod tests;
