use super::super::*;
use chromiumoxide::cdp::browser_protocol::page::{FrameTree, GetFrameTreeParams};
use chromiumoxide::cdp::browser_protocol::target::TargetId;
use futures::StreamExt;
use std::collections::{HashMap, HashSet};
use tokio::task::JoinHandle;
use tokio::time::{sleep, Duration};

const TEMP_BROWSER_TARGET_ATTACH_SETTLE: Duration = Duration::from_millis(75);
const TEMP_BROWSER_TARGET_PAGE_RETRY_DELAY: Duration = Duration::from_millis(25);
const TEMP_BROWSER_TARGET_PAGE_RETRIES: usize = 20;

#[derive(Debug, Clone)]
pub(crate) struct BrowserFrameTarget {
    #[allow(dead_code)]
    pub(crate) frame_id: String,
    pub(crate) target_id: String,
    pub(crate) parent_frame_id: Option<String>,
    pub(crate) parent_target_id: Option<String>,
    pub(crate) child_frame_ids: Vec<String>,
    pub(crate) target_type: String,
}

#[derive(Debug)]
pub(crate) struct MultiTargetObservationContext {
    pub(crate) pages_by_target: HashMap<String, Page>,
    pub(crate) frames_by_id: HashMap<String, BrowserFrameTarget>,
    pub(crate) frame_order: Vec<String>,
    pub(crate) root_frame_by_target: HashMap<String, String>,
}

pub(crate) struct TemporaryBrowserConnection {
    browser: Browser,
    handler_task: JoinHandle<()>,
}

impl TemporaryBrowserConnection {
    pub(crate) async fn connect(debugger_ws_url: &str) -> std::result::Result<Self, BrowserError> {
        let (browser, mut handler) = Browser::connect(debugger_ws_url.to_string())
            .await
            .map_err(|e| {
                BrowserError::Internal(format!("Temporary browser target connection failed: {}", e))
            })?;

        let handler_task =
            tokio::spawn(async move { while let Some(_event) = handler.next().await {} });

        Ok(Self {
            browser,
            handler_task,
        })
    }

    pub(crate) async fn page_for_target(
        &self,
        target_id: &TargetId,
    ) -> std::result::Result<Page, BrowserError> {
        let mut last_error = None;
        for _ in 0..TEMP_BROWSER_TARGET_PAGE_RETRIES {
            match self.browser.get_page(target_id.clone()).await {
                Ok(page) => return Ok(page),
                Err(error) => {
                    last_error = Some(error.to_string());
                    sleep(TEMP_BROWSER_TARGET_PAGE_RETRY_DELAY).await;
                }
            }
        }

        Err(BrowserError::Internal(format!(
            "Temporary browser target '{}' never exposed an attached CDP page handle: {}",
            target_id.as_ref(),
            last_error.unwrap_or_else(|| "page handle unavailable".to_string())
        )))
    }

    pub(crate) async fn discover_observation_context(
        &mut self,
        active_target_id: &str,
    ) -> std::result::Result<MultiTargetObservationContext, BrowserError> {
        let target_infos = self.browser.fetch_targets().await.map_err(|e| {
            BrowserError::Internal(format!("Temporary target discovery failed: {}", e))
        })?;
        sleep(TEMP_BROWSER_TARGET_ATTACH_SETTLE).await;

        let mut pages_by_target = HashMap::new();
        let mut frames_by_id = HashMap::new();
        let mut root_frame_by_target = HashMap::new();

        for target_info in target_infos
            .into_iter()
            .filter(|info| matches!(info.r#type.as_str(), "page" | "iframe"))
        {
            let target_id = target_info.target_id.clone();
            let target_key = target_id.as_ref().to_string();
            let target_type = target_info.r#type.clone();

            let page = match self.page_for_target(&target_id).await {
                Ok(page) => page,
                Err(error) => {
                    log::debug!(
                        target: "browser",
                        "Skipping temporary browser target '{}' because its page handle is unavailable: {}",
                        target_key,
                        error
                    );
                    continue;
                }
            };

            let frame_tree = match page.execute(GetFrameTreeParams::default()).await {
                Ok(result) => result.frame_tree.clone(),
                Err(error) => {
                    log::debug!(
                        target: "browser",
                        "Skipping temporary browser target '{}' because Page.getFrameTree failed: {}",
                        target_key,
                        error
                    );
                    continue;
                }
            };

            collect_target_frames(
                &frame_tree,
                &target_key,
                &target_type,
                &mut frames_by_id,
                &mut root_frame_by_target,
                None,
            );
            pages_by_target.insert(target_key, page);
        }

        let active_root_frame_id = root_frame_by_target
            .get(active_target_id)
            .cloned()
            .ok_or_else(|| {
                BrowserError::Internal(format!(
                    "Temporary browser target discovery could not find the active target '{}'",
                    active_target_id
                ))
            })?;

        let mut reachable = HashSet::new();
        let mut frame_order = Vec::new();
        collect_reachable_frames(
            &active_root_frame_id,
            &frames_by_id,
            &mut reachable,
            &mut frame_order,
        );

        frames_by_id.retain(|frame_id, _| reachable.contains(frame_id));
        root_frame_by_target.retain(|_, frame_id| reachable.contains(frame_id));
        pages_by_target.retain(|target_id, _| {
            root_frame_by_target
                .get(target_id)
                .is_some_and(|frame_id| reachable.contains(frame_id))
        });

        for frame in frames_by_id.values_mut() {
            frame
                .child_frame_ids
                .retain(|child| reachable.contains(child));
        }

        let parent_targets = frames_by_id
            .iter()
            .map(|(frame_id, frame)| {
                let parent_target = frame
                    .parent_frame_id
                    .as_ref()
                    .and_then(|parent_frame_id| frames_by_id.get(parent_frame_id))
                    .map(|parent| parent.target_id.clone());
                (frame_id.clone(), parent_target)
            })
            .collect::<HashMap<_, _>>();

        for (frame_id, parent_target_id) in parent_targets {
            if let Some(frame) = frames_by_id.get_mut(&frame_id) {
                frame.parent_target_id = parent_target_id;
            }
        }

        Ok(MultiTargetObservationContext {
            pages_by_target,
            frames_by_id,
            frame_order,
            root_frame_by_target,
        })
    }
}

impl Drop for TemporaryBrowserConnection {
    fn drop(&mut self) {
        self.handler_task.abort();
    }
}

fn collect_target_frames(
    frame_tree: &FrameTree,
    target_id: &str,
    target_type: &str,
    frames_by_id: &mut HashMap<String, BrowserFrameTarget>,
    root_frame_by_target: &mut HashMap<String, String>,
    parent_frame_id: Option<String>,
) {
    let frame_id = frame_tree.frame.id.as_ref().to_string();
    root_frame_by_target
        .entry(target_id.to_string())
        .or_insert_with(|| frame_id.clone());

    let actual_parent = frame_tree
        .frame
        .parent_id
        .as_ref()
        .map(|parent| parent.as_ref().to_string())
        .or(parent_frame_id.clone());

    let child_frame_ids = frame_tree
        .child_frames
        .as_ref()
        .map(|children| {
            children
                .iter()
                .map(|child| child.frame.id.as_ref().to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    match frames_by_id.get_mut(&frame_id) {
        Some(existing) => {
            if actual_parent.is_some() && existing.parent_frame_id.is_none() {
                existing.parent_frame_id = actual_parent.clone();
            }
            for child_frame_id in &child_frame_ids {
                if !existing
                    .child_frame_ids
                    .iter()
                    .any(|child| child == child_frame_id)
                {
                    existing.child_frame_ids.push(child_frame_id.clone());
                }
            }
            if target_type == "iframe" {
                existing.target_id = target_id.to_string();
                existing.target_type = target_type.to_string();
            }
        }
        None => {
            frames_by_id.insert(
                frame_id.clone(),
                BrowserFrameTarget {
                    frame_id: frame_id.clone(),
                    target_id: target_id.to_string(),
                    parent_frame_id: actual_parent.clone(),
                    parent_target_id: None,
                    child_frame_ids,
                    target_type: target_type.to_string(),
                },
            );
        }
    }

    if let Some(children) = &frame_tree.child_frames {
        for child in children {
            collect_target_frames(
                child,
                target_id,
                target_type,
                frames_by_id,
                root_frame_by_target,
                Some(frame_id.clone()),
            );
        }
    }
}

fn collect_reachable_frames(
    frame_id: &str,
    frames_by_id: &HashMap<String, BrowserFrameTarget>,
    reachable: &mut HashSet<String>,
    order: &mut Vec<String>,
) {
    if !reachable.insert(frame_id.to_string()) {
        return;
    }
    order.push(frame_id.to_string());

    let Some(frame) = frames_by_id.get(frame_id) else {
        return;
    };

    for child_frame_id in &frame.child_frame_ids {
        collect_reachable_frames(child_frame_id, frames_by_id, reachable, order);
    }
}
