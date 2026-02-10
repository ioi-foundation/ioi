// apps/autopilot/src-tauri/src/project.rs

use crate::orchestrator::{GraphEdge, GraphNode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

// Define the file format structure
#[derive(Debug, Serialize, Deserialize)]
pub struct ProjectFile {
    pub version: String,
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    pub global_config: Option<Value>,
    // [NEW] Metadata for tracking
    pub metadata: Option<ProjectMetadata>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProjectMetadata {
    pub name: String,
    pub created_at: u64,
    pub last_modified: u64,
    pub author: Option<String>,
}

#[tauri::command]
pub fn save_project(path: String, project: ProjectFile) -> Result<(), String> {
    // 1. Enforce versioning
    let mut final_project = project;
    final_project.version = "1.0.0".to_string();

    // 2. Update metadata
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    if let Some(ref mut meta) = final_project.metadata {
        meta.last_modified = now;
    } else {
        final_project.metadata = Some(ProjectMetadata {
            name: std::path::Path::new(&path)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("Untitled")
                .to_string(),
            created_at: now,
            last_modified: now,
            author: None,
        });
    }

    let json = serde_json::to_string_pretty(&final_project).map_err(|e| e.to_string())?;

    // 3. Ensure directory exists
    let path_buf = PathBuf::from(&path);
    if let Some(parent) = path_buf.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }

    // 4. Atomic Write (Write to .tmp then rename)
    let temp_path = format!("{}.tmp", path);
    let mut file = fs::File::create(&temp_path).map_err(|e| e.to_string())?;
    file.write_all(json.as_bytes()).map_err(|e| e.to_string())?;

    // Sync to disk to ensure data is flushed
    file.sync_all().map_err(|e| e.to_string())?;

    // Rename to overwrite target
    fs::rename(temp_path, path).map_err(|e| e.to_string())?;

    println!("[Project] Saved successfully to {}", path_buf.display());
    Ok(())
}

#[tauri::command]
pub fn load_project(path: String) -> Result<ProjectFile, String> {
    let content = fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let project: ProjectFile = serde_json::from_str(&content).map_err(|e| e.to_string())?;

    // Basic validation
    if project.nodes.is_empty() && project.global_config.is_none() {
        println!("[Project] Warning: Loaded empty project from {}", path);
    } else {
        println!(
            "[Project] Loaded {} nodes from {}",
            project.nodes.len(),
            path
        );
    }

    Ok(project)
}
