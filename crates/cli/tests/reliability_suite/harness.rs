use anyhow::{anyhow, Result};
use async_trait::async_trait;
use axum::{response::Html, routing::get, Router};
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::drivers::os::{OsDriver, WindowInfo};
use ioi_api::vm::inference::{mock::MockInferenceRuntime, InferenceRuntime};
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::mcp::McpManager;
use ioi_drivers::terminal::TerminalDriver;
use ioi_services::agentic::desktop::execution::{ToolExecutionResult, ToolExecutor};
use ioi_services::agentic::desktop::types::ExecutionTier;
use ioi_types::app::KernelEvent;
use ioi_types::app::{ActionRequest, ContextSlice};
use ioi_types::error::VmError;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use tokio::process::{Child, Command};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::{sleep, Duration};

#[derive(Default)]
pub struct RecordingGuiDriver {
    injected: Mutex<Vec<InputEvent>>,
}

impl RecordingGuiDriver {
    pub fn take_events(&self) -> Vec<InputEvent> {
        let mut guard = self.injected.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut *guard)
    }
}

#[async_trait]
impl GuiDriver for RecordingGuiDriver {
    async fn capture_screen(
        &self,
        _crop_rect: Option<(i32, i32, u32, u32)>,
    ) -> Result<Vec<u8>, VmError> {
        Err(VmError::HostError(
            "capture_screen not implemented in reliability harness".to_string(),
        ))
    }

    async fn capture_raw_screen(&self) -> Result<Vec<u8>, VmError> {
        Err(VmError::HostError(
            "capture_raw_screen not implemented in reliability harness".to_string(),
        ))
    }

    async fn capture_tree(&self) -> Result<String, VmError> {
        Err(VmError::HostError(
            "capture_tree not implemented in reliability harness".to_string(),
        ))
    }

    async fn capture_context(&self, _intent: &ActionRequest) -> Result<ContextSlice, VmError> {
        Err(VmError::HostError(
            "capture_context not implemented in reliability harness".to_string(),
        ))
    }

    async fn inject_input(&self, event: InputEvent) -> Result<(), VmError> {
        let mut guard = self.injected.lock().unwrap_or_else(|e| e.into_inner());
        guard.push(event);
        Ok(())
    }

    async fn get_element_center(&self, _id: u32) -> Result<Option<(u32, u32)>, VmError> {
        Ok(None)
    }

    async fn get_cursor_position(&self) -> Result<(u32, u32), VmError> {
        Ok((0, 0))
    }

    async fn register_som_overlay(
        &self,
        _map: HashMap<u32, (i32, i32, i32, i32)>,
    ) -> Result<(), VmError> {
        Ok(())
    }
}

struct StaticOsDriver {
    active_window: Option<WindowInfo>,
}

impl StaticOsDriver {
    fn new(active_window: Option<WindowInfo>) -> Self {
        Self { active_window }
    }
}

#[async_trait]
impl OsDriver for StaticOsDriver {
    async fn get_active_window_title(&self) -> Result<Option<String>, VmError> {
        Ok(self.active_window.as_ref().map(|win| win.title.clone()))
    }

    async fn get_active_window_info(&self) -> Result<Option<WindowInfo>, VmError> {
        Ok(self.active_window.clone())
    }

    async fn focus_window(&self, _title_query: &str) -> Result<bool, VmError> {
        Ok(false)
    }

    async fn set_clipboard(&self, _content: &str) -> Result<(), VmError> {
        Ok(())
    }

    async fn get_clipboard(&self) -> Result<String, VmError> {
        Ok(String::new())
    }
}

pub fn build_executor(
    tier: ExecutionTier,
    active_window: Option<WindowInfo>,
) -> (ToolExecutor, Arc<RecordingGuiDriver>, Arc<BrowserDriver>) {
    build_executor_with_events(tier, active_window, None)
}

pub fn build_executor_with_events(
    tier: ExecutionTier,
    active_window: Option<WindowInfo>,
    event_sender: Option<tokio::sync::broadcast::Sender<KernelEvent>>,
) -> (ToolExecutor, Arc<RecordingGuiDriver>, Arc<BrowserDriver>) {
    let gui = Arc::new(RecordingGuiDriver::default());
    let os: Arc<dyn OsDriver> = Arc::new(StaticOsDriver::new(active_window.clone()));
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    browser.set_lease(true);
    let mcp = Arc::new(McpManager::new());
    let inference: Arc<dyn InferenceRuntime> = Arc::new(MockInferenceRuntime::default());

    let executor = ToolExecutor::new(
        gui.clone(),
        os,
        terminal,
        browser.clone(),
        mcp,
        event_sender,
        None,
        inference,
        None,
    )
    .with_window_context(active_window, None, Some(tier));

    (executor, gui, browser)
}

pub fn describe_result(result: &ToolExecutionResult) -> String {
    format!(
        "success={} history={:?} error={:?}",
        result.success, result.history_entry, result.error
    )
}

fn escape_xml_attr_value(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn unescape_xml_attr_value(value: &str) -> String {
    value
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

fn normalize_label(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim()
        .to_ascii_lowercase()
}

fn extract_xml_attribute(line: &str, attr: &str) -> Option<String> {
    let prefix = format!("{attr}=\"");
    let start = line.find(&prefix)? + prefix.len();
    let rest = &line[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

pub fn extract_node_id_by_name(xml: &str, name: &str) -> Option<String> {
    let target = normalize_label(name);
    let escaped_name = escape_xml_attr_value(name);
    let name_marker = format!(" name=\"{escaped_name}\"");
    let value_marker = format!(" value=\"{escaped_name}\"");
    let mut fuzzy_match_id: Option<String> = None;

    for line in xml.lines() {
        let Some(id) = extract_xml_attribute(line, "id") else {
            continue;
        };

        if line.contains(&name_marker) || line.contains(&value_marker) {
            return Some(id);
        }

        let mut exact_match = false;
        let mut fuzzy_match = false;
        for attr in ["name", "value"] {
            if let Some(raw) = extract_xml_attribute(line, attr) {
                let decoded = unescape_xml_attr_value(&raw);
                let normalized = normalize_label(&decoded);
                if normalized == target {
                    exact_match = true;
                    break;
                }
                if normalized.contains(&target) || target.contains(&normalized) {
                    fuzzy_match = true;
                }
            }
        }

        if exact_match {
            return Some(id);
        }
        if fuzzy_match && fuzzy_match_id.is_none() {
            fuzzy_match_id = Some(id);
        }
    }
    fuzzy_match_id
}

pub struct FixtureServer {
    addr: SocketAddr,
    shutdown_tx: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

impl FixtureServer {
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub async fn stop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

pub async fn spawn_browser_fixture_server() -> Result<FixtureServer> {
    let app = Router::new().route(
        "/",
        get(|| async { Html(include_str!("fixtures/browser_snapshot_click/index.html")) }),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| anyhow!("failed to bind fixture server: {}", e))?;
    let addr = listener
        .local_addr()
        .map_err(|e| anyhow!("failed to read fixture server addr: {}", e))?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await;
    });

    Ok(FixtureServer {
        addr,
        shutdown_tx: Some(shutdown_tx),
        task: Some(task),
    })
}

pub struct GuiFixtureApp {
    child: Child,
}

impl GuiFixtureApp {
    pub async fn spawn() -> Result<Self> {
        if std::env::var("DISPLAY").is_err() && std::env::var("WAYLAND_DISPLAY").is_err() {
            return Err(anyhow!(
                "GUI fixture requires DISPLAY or WAYLAND_DISPLAY to be set"
            ));
        }

        let script = r#"
import sys

def run_gtk():
    import gi
    gi.require_version("Gtk", "3.0")
    from gi.repository import Gtk, GLib

    win = Gtk.Window(title="IOI GUI Click Fixture")
    win.set_default_size(420, 240)
    win.move(120, 120)
    win.connect("destroy", Gtk.main_quit)

    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
    box.set_border_width(24)
    btn = Gtk.Button(label="Confirm Reliability")
    lbl = Gtk.Label(label="ready")

    def _clicked(_btn):
        lbl.set_text("clicked")

    def _close():
        win.destroy()
        return False

    btn.connect("clicked", _clicked)
    box.pack_start(btn, False, False, 0)
    box.pack_start(lbl, False, False, 0)
    win.add(box)
    win.show_all()
    GLib.timeout_add_seconds(30, _close)
    Gtk.main()


def run_tk():
    import tkinter as tk

    root = tk.Tk()
    root.title("IOI GUI Click Fixture")
    root.geometry("420x240+120+120")
    state = tk.StringVar(value="ready")

    def _clicked():
        state.set("clicked")

    frame = tk.Frame(root)
    frame.pack(expand=True, fill="both")
    btn = tk.Button(frame, text="Confirm Reliability", command=_clicked)
    btn.pack(pady=24)
    lbl = tk.Label(frame, textvariable=state)
    lbl.pack(pady=6)
    root.after(30000, root.destroy)
    root.mainloop()


try:
    run_gtk()
except Exception:
    run_tk()
"#;

        let child = Command::new("python3")
            .arg("-c")
            .arg(script)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| anyhow!("failed to spawn tkinter fixture app: {}", e))?;

        let mut app = Self { child };
        sleep(Duration::from_millis(2200)).await;

        if let Some(status) = app
            .child
            .try_wait()
            .map_err(|e| anyhow!("failed to inspect fixture app status: {}", e))?
        {
            return Err(anyhow!("fixture app exited early with status {}", status));
        }

        Ok(app)
    }

    pub async fn stop(&mut self) {
        match self.child.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) => {
                let _ = self.child.kill().await;
                let _ = self.child.wait().await;
            }
            Err(_) => {}
        }
    }
}
