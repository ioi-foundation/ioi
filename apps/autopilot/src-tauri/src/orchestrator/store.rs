use crate::models::{AgentEvent, AgentTask, Artifact, SessionSummary};
use ioi_crypto::algorithms::hash::sha256;
use ioi_scs::{FrameType, RetentionClass, SovereignContextStore};
use serde::Deserialize;
use std::sync::{Arc, Mutex};

pub const SESSION_INDEX_KEY: [u8; 32] = [
    0x53, 0x45, 0x53, 0x53, 0x49, 0x4F, 0x4E, 0x5F, 0x49, 0x4E, 0x44, 0x45, 0x53, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];

fn scoped_storage_key(scope: &str, id: &str) -> Option<[u8; 32]> {
    let preimage = format!("autopilot::{}::{}", scope, id);
    match sha256(preimage.as_bytes()) {
        Ok(digest) => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(digest.as_ref());
            Some(arr)
        }
        Err(_) => None,
    }
}

fn read_latest_json<T: for<'de> Deserialize<'de>>(
    store: &SovereignContextStore,
    key: &[u8; 32],
) -> Option<T> {
    let frame_ids = store.session_index.get(key)?;
    let last_id = *frame_ids.last()?;
    let payload = store.read_frame_payload(last_id).ok()?;
    serde_json::from_slice::<T>(&payload).ok()
}

fn read_latest_payload(store: &SovereignContextStore, key: &[u8; 32]) -> Option<Vec<u8>> {
    let frame_ids = store.session_index.get(key)?;
    let last_id = *frame_ids.last()?;
    let payload = store.read_frame_payload(last_id).ok()?;
    Some(payload.to_vec())
}

pub fn append_event(scs: &Arc<Mutex<SovereignContextStore>>, event: &AgentEvent) {
    let Some(key) = scoped_storage_key("thread_events", &event.thread_id) else {
        return;
    };

    let Ok(mut store) = scs.lock() else {
        return;
    };

    let mut events = read_latest_json::<Vec<AgentEvent>>(&store, &key).unwrap_or_default();
    events.push(event.clone());

    let Ok(payload) = serde_json::to_vec(&events) else {
        return;
    };

    let _ = store.append_frame(
        FrameType::System,
        &payload,
        0,
        [0u8; 32],
        key,
        RetentionClass::Archival,
    );
}

pub fn load_events(
    scs: &Arc<Mutex<SovereignContextStore>>,
    thread_id: &str,
    limit: Option<usize>,
    cursor: Option<usize>,
) -> Vec<AgentEvent> {
    let Some(key) = scoped_storage_key("thread_events", thread_id) else {
        return Vec::new();
    };

    let events = if let Ok(store) = scs.lock() {
        read_latest_json::<Vec<AgentEvent>>(&store, &key).unwrap_or_default()
    } else {
        Vec::new()
    };

    if events.is_empty() {
        return events;
    }

    let start = cursor.unwrap_or(0).min(events.len());
    let remaining = &events[start..];
    if let Some(limit) = limit {
        remaining.iter().take(limit).cloned().collect()
    } else {
        remaining.to_vec()
    }
}

pub fn append_artifact(
    scs: &Arc<Mutex<SovereignContextStore>>,
    artifact: &Artifact,
    content: &[u8],
) {
    let Some(index_key) = scoped_storage_key("thread_artifacts", &artifact.thread_id) else {
        return;
    };
    let Some(content_key) = scoped_storage_key("artifact_content", &artifact.artifact_id) else {
        return;
    };

    let Ok(mut store) = scs.lock() else {
        return;
    };

    let mut artifacts = read_latest_json::<Vec<Artifact>>(&store, &index_key).unwrap_or_default();
    artifacts.retain(|a| a.artifact_id != artifact.artifact_id);
    artifacts.push(artifact.clone());

    if let Ok(index_payload) = serde_json::to_vec(&artifacts) {
        let _ = store.append_frame(
            FrameType::System,
            &index_payload,
            0,
            [0u8; 32],
            index_key,
            RetentionClass::Archival,
        );
    }

    let _ = store.append_frame(
        FrameType::System,
        content,
        0,
        [0u8; 32],
        content_key,
        RetentionClass::Archival,
    );
}

pub fn load_artifacts(scs: &Arc<Mutex<SovereignContextStore>>, thread_id: &str) -> Vec<Artifact> {
    let Some(key) = scoped_storage_key("thread_artifacts", thread_id) else {
        return Vec::new();
    };

    if let Ok(store) = scs.lock() {
        read_latest_json::<Vec<Artifact>>(&store, &key).unwrap_or_default()
    } else {
        Vec::new()
    }
}

pub fn load_artifact_content(
    scs: &Arc<Mutex<SovereignContextStore>>,
    artifact_id: &str,
) -> Option<Vec<u8>> {
    let key = scoped_storage_key("artifact_content", artifact_id)?;
    let store = scs.lock().ok()?;
    read_latest_payload(&store, &key)
}

pub fn get_local_sessions(scs: &Arc<Mutex<SovereignContextStore>>) -> Vec<SessionSummary> {
    if let Ok(store) = scs.lock() {
        read_latest_json::<Vec<SessionSummary>>(&store, &SESSION_INDEX_KEY).unwrap_or_default()
    } else {
        Vec::new()
    }
}

pub fn save_local_session_summary(
    scs: &Arc<Mutex<SovereignContextStore>>,
    summary: SessionSummary,
) {
    let mut sessions = get_local_sessions(scs);
    if let Some(pos) = sessions
        .iter()
        .position(|s| s.session_id == summary.session_id)
    {
        sessions[pos] = summary;
    } else {
        sessions.push(summary);
    }
    sessions.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

    let Ok(bytes) = serde_json::to_vec(&sessions) else {
        return;
    };

    let Ok(mut store) = scs.lock() else {
        return;
    };

    let _ = store.append_frame(
        FrameType::System,
        &bytes,
        0,
        [0u8; 32],
        SESSION_INDEX_KEY,
        RetentionClass::Archival,
    );
}

fn get_session_storage_key(session_id: &str) -> Option<[u8; 32]> {
    if session_id.len() == 64 {
        if let Ok(bytes) = hex::decode(session_id) {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            return Some(arr);
        }
    }

    match sha256(session_id.as_bytes()) {
        Ok(digest) => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(digest.as_ref());
            Some(arr)
        }
        Err(_) => None,
    }
}

pub fn save_local_task_state(scs: &Arc<Mutex<SovereignContextStore>>, task: &AgentTask) {
    let sid = task.session_id.as_deref().unwrap_or(&task.id);
    let Some(key) = get_session_storage_key(sid) else {
        return;
    };

    let Ok(bytes) = serde_json::to_vec(task) else {
        return;
    };

    let Ok(mut store) = scs.lock() else {
        return;
    };

    let _ = store.append_frame(
        FrameType::System,
        &bytes,
        0,
        [0u8; 32],
        key,
        RetentionClass::Archival,
    );
}

pub fn load_local_task(
    scs: &Arc<Mutex<SovereignContextStore>>,
    session_id: &str,
) -> Option<AgentTask> {
    let key = get_session_storage_key(session_id)?;

    let store = scs.lock().ok()?;
    read_latest_json::<AgentTask>(&store, &key)
}
