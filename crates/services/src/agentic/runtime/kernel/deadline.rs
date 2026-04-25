use serde::{Deserialize, Serialize};
use std::future::Future;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionDeadline {
    pub started_at_ms: u64,
    pub deadline_at_ms: u64,
    pub budget_class: String,
    pub timeout_policy: String,
}

impl ExecutionDeadline {
    pub fn from_timeout_ms(timeout_ms: u64, budget_class: impl Into<String>) -> Self {
        let started_at_ms = unix_ms_now();
        Self {
            started_at_ms,
            deadline_at_ms: started_at_ms.saturating_add(timeout_ms),
            budget_class: budget_class.into(),
            timeout_policy: format!("timeout_ms={}", timeout_ms),
        }
    }

    pub fn remaining_duration(&self) -> Duration {
        let now = unix_ms_now();
        if now >= self.deadline_at_ms {
            Duration::from_millis(0)
        } else {
            Duration::from_millis(self.deadline_at_ms - now)
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("execution deadline exceeded: {timeout_policy}")]
pub struct ExecutionDeadlineExceeded {
    pub timeout_policy: String,
}

pub async fn with_deadline<F, T>(
    deadline: &ExecutionDeadline,
    future: F,
) -> Result<T, ExecutionDeadlineExceeded>
where
    F: Future<Output = T>,
{
    match tokio::time::timeout(deadline.remaining_duration(), future).await {
        Ok(value) => Ok(value),
        Err(_) => Err(ExecutionDeadlineExceeded {
            timeout_policy: deadline.timeout_policy.clone(),
        }),
    }
}

fn unix_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
