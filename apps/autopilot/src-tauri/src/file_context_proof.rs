use crate::kernel::file_context::{
    apply_exclude_file_context_path, apply_include_file_context_path, apply_pin_file_context_path,
    apply_remove_file_context_path,
};
use crate::kernel::state::now;
use crate::models::SessionFileContext;
use crate::open_or_create_memory_runtime;
use crate::orchestrator::{
    get_local_sessions, load_local_task, load_session_file_context, save_session_file_context,
};
use serde::Serialize;
use std::env;
use std::path::{Path, PathBuf};
use std::sync::Arc;

fn env_text(key: &str) -> Option<String> {
    env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn bool_env(key: &str) -> bool {
    env::var(key)
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn cli_data_dir() -> Result<PathBuf, String> {
    if let Some(override_path) = env_text("AUTOPILOT_DATA_DIR") {
        return Ok(PathBuf::from(override_path));
    }

    let home = env_text("HOME").ok_or_else(|| "HOME is not set.".to_string())?;
    let mut base = PathBuf::from(home);
    base.push(".local/share/ai.ioi.autopilot");

    let profile = env_text("AUTOPILOT_DATA_PROFILE").or_else(|| {
        if bool_env("AUTOPILOT_LOCAL_GPU_DEV") {
            Some("desktop-localgpu".to_string())
        } else {
            None
        }
    });

    if let Some(profile) = profile {
        Ok(base.join("profiles").join(profile))
    } else {
        Ok(base)
    }
}

#[derive(Serialize)]
struct ProofSnapshot {
    session_id: String,
    workspace_root: Option<String>,
    context: SessionFileContext,
}

fn latest_session_id(memory_runtime: &Arc<ioi_memory::MemoryRuntime>) -> Result<String, String> {
    let sessions = get_local_sessions(memory_runtime);
    for session in sessions {
        let session_id = session.session_id.clone();
        if load_local_task(memory_runtime, &session_id).is_some() {
            return Ok(session_id);
        }
    }
    Err("No retained local session task was found.".to_string())
}

fn load_snapshot(memory_runtime: &Arc<ioi_memory::MemoryRuntime>) -> Result<ProofSnapshot, String> {
    let session_id = latest_session_id(memory_runtime)?;
    let sessions = get_local_sessions(memory_runtime);
    let workspace_root = sessions
        .iter()
        .find(|session| session.session_id == session_id)
        .and_then(|session| session.workspace_root.clone());
    let context = load_session_file_context(
        memory_runtime,
        Some(session_id.as_str()),
        workspace_root.as_deref(),
    );
    Ok(ProofSnapshot {
        session_id,
        workspace_root,
        context,
    })
}

fn mutate_latest_path(
    memory_runtime: &Arc<ioi_memory::MemoryRuntime>,
    path: &str,
    mutate: fn(&mut SessionFileContext, &str) -> Result<(), String>,
) -> Result<ProofSnapshot, String> {
    let mut snapshot = load_snapshot(memory_runtime)?;
    mutate(&mut snapshot.context, path)?;
    snapshot.context.updated_at_ms = now();
    save_session_file_context(
        memory_runtime,
        Some(snapshot.session_id.as_str()),
        &snapshot.context,
    );
    load_snapshot(memory_runtime)
}

fn print_json<T: Serialize>(value: &T) -> Result<(), String> {
    let text = serde_json::to_string_pretty(value)
        .map_err(|error| format!("JSON encode failed: {error}"))?;
    println!("{text}");
    Ok(())
}

pub fn run_cli() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let command = args.next().ok_or_else(|| usage().to_string())?;

    let data_dir = cli_data_dir()?;
    let memory_runtime = Arc::new(open_or_create_memory_runtime(Path::new(&data_dir))?);

    match command.as_str() {
        "show-latest" => {
            let snapshot = load_snapshot(&memory_runtime)?;
            print_json(&snapshot)
        }
        "pin-latest" => {
            let path = args
                .next()
                .ok_or_else(|| "Usage: chat_file_context_proof pin-latest <path>".to_string())?;
            let snapshot = mutate_latest_path(&memory_runtime, &path, apply_pin_file_context_path)?;
            print_json(&snapshot)
        }
        "include-latest" => {
            let path = args.next().ok_or_else(|| {
                "Usage: chat_file_context_proof include-latest <path>".to_string()
            })?;
            let snapshot =
                mutate_latest_path(&memory_runtime, &path, apply_include_file_context_path)?;
            print_json(&snapshot)
        }
        "exclude-latest" => {
            let path = args.next().ok_or_else(|| {
                "Usage: chat_file_context_proof exclude-latest <path>".to_string()
            })?;
            let snapshot =
                mutate_latest_path(&memory_runtime, &path, apply_exclude_file_context_path)?;
            print_json(&snapshot)
        }
        "remove-latest" => {
            let path = args
                .next()
                .ok_or_else(|| "Usage: chat_file_context_proof remove-latest <path>".to_string())?;
            let snapshot =
                mutate_latest_path(&memory_runtime, &path, apply_remove_file_context_path)?;
            print_json(&snapshot)
        }
        _ => Err(format!("Unknown command '{command}'. {}", usage())),
    }
}

fn usage() -> &'static str {
    "Usage: chat_file_context_proof <show-latest|pin-latest PATH|include-latest PATH|exclude-latest PATH|remove-latest PATH>"
}
