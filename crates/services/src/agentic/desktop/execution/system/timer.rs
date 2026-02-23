use super::{ToolExecutionResult, ToolExecutor};
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::KernelEvent;
use serde::Serialize;
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize)]
struct TimerRecord {
    timer_id: String,
    session_id_hex: String,
    duration_seconds: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<String>,
    created_at_epoch_ms: u64,
    target_epoch_ms: u64,
    status: String,
}

#[derive(Default)]
struct TimerStore {
    records: BTreeMap<String, TimerRecord>,
    tasks: BTreeMap<String, tokio::task::AbortHandle>,
}

static TIMER_STORE: OnceLock<Arc<Mutex<TimerStore>>> = OnceLock::new();

fn timer_store() -> Arc<Mutex<TimerStore>> {
    TIMER_STORE
        .get_or_init(|| Arc::new(Mutex::new(TimerStore::default())))
        .clone()
}

fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn timer_id_for(
    session_id: [u8; 32],
    duration_seconds: u64,
    label: Option<&str>,
    now_ms: u64,
) -> Result<String, String> {
    let seed = format!(
        "ioi::timer::{}::{}::{}::{}",
        hex::encode(session_id),
        duration_seconds,
        label.unwrap_or(""),
        now_ms
    );
    let digest = sha256(seed.as_bytes()).map_err(|e| e.to_string())?;
    Ok(hex::encode(digest.as_ref()))
}

pub(super) async fn handle_timer_set(
    exec: &ToolExecutor,
    duration_seconds: u64,
    label: Option<&str>,
    session_id: [u8; 32],
) -> ToolExecutionResult {
    if duration_seconds == 0 {
        return ToolExecutionResult::failure(
            "ERROR_CLASS=InvalidArgument timer__set requires duration_seconds > 0",
        );
    }
    if duration_seconds > 86_400 * 30 {
        return ToolExecutionResult::failure(
            "ERROR_CLASS=InvalidArgument timer__set duration is capped at 30 days",
        );
    }

    let now_ms = now_epoch_ms();
    let target_epoch_ms = now_ms.saturating_add(duration_seconds.saturating_mul(1_000));
    let label_clean = label
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let timer_id = match timer_id_for(session_id, duration_seconds, label_clean.as_deref(), now_ms)
    {
        Ok(id) => id,
        Err(err) => {
            return ToolExecutionResult::failure(format!(
                "ERROR_CLASS=UnexpectedState failed to derive timer id: {}",
                err
            ));
        }
    };

    let record = TimerRecord {
        timer_id: timer_id.clone(),
        session_id_hex: hex::encode(session_id),
        duration_seconds,
        label: label_clean.clone(),
        created_at_epoch_ms: now_ms,
        target_epoch_ms,
        status: "active".to_string(),
    };

    let store = timer_store();
    {
        let mut guard = match store.lock() {
            Ok(guard) => guard,
            Err(_) => {
                return ToolExecutionResult::failure(
                    "ERROR_CLASS=UnexpectedState timer store lock poisoned",
                );
            }
        };
        guard.records.insert(timer_id.clone(), record.clone());
    }

    let store_for_task = store.clone();
    let timer_id_for_task = timer_id.clone();
    let tx = exec.event_sender.clone();
    let target_epoch_ms_for_task = target_epoch_ms;
    let task = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(duration_seconds)).await;

        let mut completed = false;
        {
            let mut guard = match store_for_task.lock() {
                Ok(guard) => guard,
                Err(_) => return,
            };
            if let Some(record) = guard.records.get_mut(&timer_id_for_task) {
                if record.status == "active" {
                    record.status = "completed".to_string();
                    completed = true;
                }
            }
            guard.tasks.remove(&timer_id_for_task);
        }

        if completed {
            if let Some(tx) = tx.as_ref() {
                let _ = tx.send(KernelEvent::SystemUpdate {
                    component: "timer".to_string(),
                    status: format!(
                        "timer_completed id={} target_epoch_ms={}",
                        timer_id_for_task, target_epoch_ms_for_task
                    ),
                });
            }
        }
    });
    {
        let mut guard = match store.lock() {
            Ok(guard) => guard,
            Err(_) => {
                return ToolExecutionResult::failure(
                    "ERROR_CLASS=UnexpectedState timer store lock poisoned",
                );
            }
        };
        guard.tasks.insert(timer_id.clone(), task.abort_handle());
    }

    let payload = json!({
        "timer_id": timer_id,
        "status": "scheduled",
        "duration_seconds": duration_seconds,
        "created_at_epoch_ms": now_ms,
        "target_epoch_ms": target_epoch_ms,
        "target_epoch_seconds": target_epoch_ms / 1000,
        "label": label_clean,
    });
    ToolExecutionResult::success(payload.to_string())
}

pub(super) async fn handle_timer_cancel(
    exec: &ToolExecutor,
    timer_id: &str,
) -> ToolExecutionResult {
    let id = timer_id.trim();
    if id.is_empty() {
        return ToolExecutionResult::failure(
            "ERROR_CLASS=InvalidArgument timer__cancel requires timer_id",
        );
    }

    let store = timer_store();
    let mut cancelled = false;
    let mut prior_status = String::new();
    let mut handle: Option<tokio::task::AbortHandle> = None;
    {
        let mut guard = match store.lock() {
            Ok(guard) => guard,
            Err(_) => {
                return ToolExecutionResult::failure(
                    "ERROR_CLASS=UnexpectedState timer store lock poisoned",
                );
            }
        };
        if let Some(record) = guard.records.get_mut(id) {
            prior_status = record.status.clone();
            if record.status == "active" {
                record.status = "cancelled".to_string();
                cancelled = true;
            }
        }
        handle = guard.tasks.remove(id);
    }
    if let Some(handle) = handle {
        handle.abort();
    }

    if cancelled {
        if let Some(tx) = exec.event_sender.as_ref() {
            let _ = tx.send(KernelEvent::SystemUpdate {
                component: "timer".to_string(),
                status: format!("timer_cancelled id={}", id),
            });
        }
    }

    let payload = json!({
        "timer_id": id,
        "cancelled": cancelled,
        "prior_status": prior_status,
    });
    ToolExecutionResult::success(payload.to_string())
}

pub(super) async fn handle_timer_list() -> ToolExecutionResult {
    let store = timer_store();
    let mut timers = Vec::<TimerRecord>::new();
    {
        let guard = match store.lock() {
            Ok(guard) => guard,
            Err(_) => {
                return ToolExecutionResult::failure(
                    "ERROR_CLASS=UnexpectedState timer store lock poisoned",
                );
            }
        };
        timers.extend(guard.records.values().cloned());
    }
    timers.sort_by(|left, right| {
        left.target_epoch_ms
            .cmp(&right.target_epoch_ms)
            .then_with(|| left.timer_id.cmp(&right.timer_id))
    });

    let payload = json!({
        "timers": timers,
    });
    ToolExecutionResult::success(payload.to_string())
}
