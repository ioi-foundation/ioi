use super::*;
use crate::models::{EventStatus, InterventionRecord, InterventionStatus, NotificationSeverity};
use chrono::{DateTime, Utc};
use ioi_crypto::algorithms::hash::sha256;
use ioi_services::agentic::desktop::agent_playbooks::builtin_agent_playbooks;
use ioi_services::agentic::desktop::utils::load_agent_state_checkpoint;
use ioi_services::agentic::desktop::worker_templates::builtin_worker_templates;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::PathBuf;
use tauri::Manager;

include!("tools.rs");
include!("local_engine_support.rs");
include!("playbooks.rs");
include!("local_engine_commands.rs");
include!("skill_context.rs");
include!("atlas.rs");
