use super::harness::build_executor_with_events;
use anyhow::{anyhow, Result};
use axum::{response::Html, routing::get, Router};
use ioi_services::agentic::desktop::types::ExecutionTier;
use ioi_types::app::agentic::{AgentTool, WebEvidenceBundle};
use ioi_types::app::{KernelEvent, WorkloadActivityKind, WorkloadNetFetchReceipt, WorkloadReceipt};
use serde_json::Value;
use std::net::SocketAddr;
use tokio::sync::{broadcast, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{sleep, Duration};

const RELIABILITY_WEB_SEARCH_FIXTURE_URLS_ENV: &str = "IOI_RELIABILITY_WEB_SEARCH_FIXTURE_URLS";

struct ScopedEnvVar {
    key: &'static str,
    previous: Option<String>,
}

impl ScopedEnvVar {
    fn set(key: &'static str, value: String) -> Self {
        let previous = std::env::var(key).ok();
        std::env::set_var(key, value);
        Self { key, previous }
    }
}

impl Drop for ScopedEnvVar {
    fn drop(&mut self) {
        if let Some(previous) = self.previous.as_ref() {
            std::env::set_var(self.key, previous);
        } else {
            std::env::remove_var(self.key);
        }
    }
}

struct WebFixtureServer {
    addr: SocketAddr,
    shutdown_tx: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

impl WebFixtureServer {
    fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn article_alpha_url(&self) -> String {
        format!("{}/article/alpha", self.base_url())
    }

    fn article_beta_url(&self) -> String {
        format!("{}/article/beta", self.base_url())
    }

    fn payload_url_with_query(&self) -> String {
        format!("{}/api/payload?token=secret#frag", self.base_url())
    }

    async fn stop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

async fn spawn_web_fixture_server() -> Result<WebFixtureServer> {
    let app = Router::new()
        .route(
            "/article/alpha",
            get(|| async {
                Html(
                    r#"<!doctype html>
<html>
  <head><title>Reliability Fixture Alpha</title></head>
  <body>
    <article>
      <h1>Reliability Fixture Alpha</h1>
      <p>This deterministic fixture validates web__read extraction and citation coverage.</p>
      <p>Payload marker: ALPHA_RELIABILITY_MARKER_2026.</p>
    </article>
  </body>
</html>"#,
                )
            }),
        )
        .route(
            "/article/beta",
            get(|| async {
                Html(
                    r#"<!doctype html>
<html>
  <head><title>Reliability Fixture Beta</title></head>
  <body>
    <article>
      <h1>Reliability Fixture Beta</h1>
      <p>This fallback source keeps web__search deterministic when multiple URLs are required.</p>
    </article>
  </body>
</html>"#,
                )
            }),
        )
        .route(
            "/api/payload",
            get(|| async {
                (
                    [("content-type", "application/json; charset=utf-8")],
                    r#"{"status":"ok","payload":"deterministic_payload","version":1}"#,
                )
            }),
        );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| anyhow!("failed to bind web fixture server: {}", e))?;
    let addr = listener
        .local_addr()
        .map_err(|e| anyhow!("failed to resolve fixture server local addr: {}", e))?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await;
    });

    Ok(WebFixtureServer {
        addr,
        shutdown_tx: Some(shutdown_tx),
        task: Some(task),
    })
}

fn drain_events(rx: &mut broadcast::Receiver<KernelEvent>, all_events: &mut Vec<KernelEvent>) {
    while let Ok(event) = rx.try_recv() {
        all_events.push(event);
    }
}

fn count_lifecycle_phase(events: &[KernelEvent], step_index: u32, phase: &str) -> usize {
    events
        .iter()
        .filter_map(|event| match event {
            KernelEvent::WorkloadActivity(activity) if activity.step_index == step_index => {
                Some(&activity.kind)
            }
            _ => None,
        })
        .filter(|kind| {
            matches!(
                kind,
                WorkloadActivityKind::Lifecycle {
                    phase: event_phase,
                    ..
                } if event_phase == phase
            )
        })
        .count()
}

fn receipts_for_step(events: &[KernelEvent], step_index: u32) -> Vec<WorkloadReceipt> {
    events
        .iter()
        .filter_map(|event| match event {
            KernelEvent::WorkloadReceipt(receipt_event)
                if receipt_event.step_index == step_index =>
            {
                Some(receipt_event.receipt.clone())
            }
            _ => None,
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires local web fixture server for deterministic retrieval flow"]
async fn web_retrieval_and_net_fetch_emit_deterministic_receipts_and_anti_loop() -> Result<()> {
    let mut fixture = spawn_web_fixture_server().await?;
    let (tx, mut rx) = broadcast::channel(256);
    let (exec, _gui, browser) =
        build_executor_with_events(ExecutionTier::DomHeadless, None, Some(tx));
    let session_id = [0xE7; 32];
    let visual_phash = [0u8; 32];
    let mut all_events: Vec<KernelEvent> = Vec::new();

    let fixture_urls = format!(
        "{},{}",
        fixture.article_alpha_url(),
        fixture.article_beta_url()
    );
    let _fixture_env = ScopedEnvVar::set(RELIABILITY_WEB_SEARCH_FIXTURE_URLS_ENV, fixture_urls);

    let search_result = exec
        .execute(
            AgentTool::WebSearch {
                query: "phase0 reliability deterministic fixture".to_string(),
                query_contract: None,
                retrieval_contract: None,
                limit: Some(3),
                url: None,
            },
            session_id,
            1,
            visual_phash,
            None,
            None,
            None,
        )
        .await;
    sleep(Duration::from_millis(40)).await;
    drain_events(&mut rx, &mut all_events);
    if !search_result.success {
        browser.stop().await;
        fixture.stop().await;
        return Err(anyhow!("web__search failed: {:?}", search_result.error));
    }
    let search_bundle: WebEvidenceBundle = serde_json::from_str(
        search_result
            .history_entry
            .as_deref()
            .ok_or_else(|| anyhow!("web__search returned no history payload"))?,
    )?;
    assert_eq!(search_bundle.backend, "edge:search:fixture");
    assert!(!search_bundle.sources.is_empty());

    let read_url = search_bundle
        .sources
        .first()
        .map(|source| source.url.clone())
        .ok_or_else(|| anyhow!("web__search fixture returned zero sources"))?;

    let read_result = exec
        .execute(
            AgentTool::WebRead {
                url: read_url,
                max_chars: Some(8_000),
            },
            session_id,
            2,
            visual_phash,
            None,
            None,
            None,
        )
        .await;
    sleep(Duration::from_millis(40)).await;
    drain_events(&mut rx, &mut all_events);
    if !read_result.success {
        browser.stop().await;
        fixture.stop().await;
        return Err(anyhow!("web__read failed: {:?}", read_result.error));
    }
    let read_bundle: WebEvidenceBundle = serde_json::from_str(
        read_result
            .history_entry
            .as_deref()
            .ok_or_else(|| anyhow!("web__read returned no history payload"))?,
    )?;
    let read_document = read_bundle
        .documents
        .first()
        .ok_or_else(|| anyhow!("web__read returned no documents"))?;
    assert!(
        read_document
            .content_text
            .contains("ALPHA_RELIABILITY_MARKER_2026"),
        "expected deterministic fixture marker in web__read output"
    );

    let net_fetch_result = exec
        .execute(
            AgentTool::NetFetch {
                url: fixture.payload_url_with_query(),
                max_chars: Some(512),
            },
            session_id,
            3,
            visual_phash,
            None,
            None,
            None,
        )
        .await;
    sleep(Duration::from_millis(40)).await;
    drain_events(&mut rx, &mut all_events);
    if !net_fetch_result.success {
        browser.stop().await;
        fixture.stop().await;
        return Err(anyhow!("net__fetch failed: {:?}", net_fetch_result.error));
    }
    let net_fetch_payload: Value = serde_json::from_str(
        net_fetch_result
            .history_entry
            .as_deref()
            .ok_or_else(|| anyhow!("net__fetch returned no history payload"))?,
    )?;
    let payload_text = net_fetch_payload
        .get("body_text")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert!(
        payload_text.contains("deterministic_payload"),
        "expected deterministic payload marker from net__fetch fixture"
    );

    let invalid_fetch_result = exec
        .execute(
            AgentTool::NetFetch {
                url: "://not-a-valid-url".to_string(),
                max_chars: Some(128),
            },
            session_id,
            4,
            visual_phash,
            None,
            None,
            None,
        )
        .await;
    sleep(Duration::from_millis(40)).await;
    drain_events(&mut rx, &mut all_events);
    assert!(!invalid_fetch_result.success);
    assert!(
        invalid_fetch_result
            .error
            .unwrap_or_default()
            .contains("ERROR_CLASS=TargetNotFound"),
        "expected invalid URL parse to map into TargetNotFound"
    );

    for success_step in [1u32, 2, 3] {
        let receipts = receipts_for_step(&all_events, success_step);
        assert_eq!(
            receipts.len(),
            1,
            "anti-loop guard: expected one receipt for success step {}",
            success_step
        );
        assert_eq!(
            count_lifecycle_phase(&all_events, success_step, "started"),
            1,
            "anti-loop guard: expected one start lifecycle for step {}",
            success_step
        );
        assert_eq!(
            count_lifecycle_phase(&all_events, success_step, "completed"),
            1,
            "anti-loop guard: expected one completed lifecycle for step {}",
            success_step
        );
    }

    let invalid_receipts = receipts_for_step(&all_events, 4);
    assert_eq!(
        invalid_receipts.len(),
        1,
        "anti-loop guard: expected one receipt for invalid fetch step"
    );
    match &invalid_receipts[0] {
        WorkloadReceipt::NetFetch(WorkloadNetFetchReceipt {
            success,
            error_class,
            ..
        }) => {
            assert!(!*success);
            assert_eq!(error_class.as_deref(), Some("TargetNotFound"));
        }
        other => {
            browser.stop().await;
            fixture.stop().await;
            return Err(anyhow!(
                "expected net fetch receipt for invalid step, got {:?}",
                other
            ));
        }
    }
    assert_eq!(
        count_lifecycle_phase(&all_events, 4, "started"),
        1,
        "anti-loop guard: invalid fetch step should emit one start lifecycle"
    );
    assert_eq!(
        count_lifecycle_phase(&all_events, 4, "failed"),
        1,
        "anti-loop guard: invalid fetch step should emit one failed lifecycle"
    );

    browser.stop().await;
    fixture.stop().await;
    Ok(())
}
