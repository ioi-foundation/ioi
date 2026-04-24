use axum::{
    extract::State as AxumState,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use flate2::read::GzDecoder;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{hash_map::DefaultHasher, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::hash::{Hash, Hasher};
use std::io::{copy, BufWriter};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Manager, Runtime, State};
use tokio::sync::oneshot;
use url::Url;

const OPENVSCODE_VERSION: &str = "1.109.5";
const OPENVSCODE_BOOT_TIMEOUT: Duration = Duration::from_secs(90);

#[derive(Default)]
pub struct WorkspaceIdeManager {
    session: Mutex<Option<WorkspaceIdeHandle>>,
}

struct WorkspaceIdeHandle {
    root_path: String,
    workbench_url: String,
    version: String,
    process_id: u32,
    port: u16,
    bridge_port: u16,
    bridge_url: String,
    bridge_path: String,
    log_path: String,
    child: Child,
    bridge_shutdown: Option<oneshot::Sender<()>>,
    bridge_task: Option<tauri::async_runtime::JoinHandle<()>>,
    bridge_state: Arc<BridgeRuntimeState>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceIdeSessionInfo {
    pub root_path: String,
    pub workbench_url: String,
    pub version: String,
    pub process_id: u32,
    pub port: u16,
    pub bridge_port: u16,
    pub bridge_url: String,
    pub bridge_path: String,
    pub log_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceIdeBridgeRequest {
    pub request_id: String,
    pub request_type: String,
    #[serde(default)]
    pub context: Value,
    #[serde(default)]
    pub payload: Value,
    pub timestamp_ms: u64,
}

#[derive(Clone)]
struct BridgeRuntimeState {
    snapshot: Arc<Mutex<Value>>,
    requests: Arc<Mutex<VecDeque<WorkspaceIdeBridgeRequest>>>,
}

impl BridgeRuntimeState {
    fn new() -> Self {
        Self {
            snapshot: Arc::new(Mutex::new(Value::Object(Default::default()))),
            requests: Arc::new(Mutex::new(VecDeque::new())),
        }
    }
}

async fn bridge_get_state(
    AxumState(state): AxumState<BridgeRuntimeState>,
) -> Result<Json<Value>, StatusCode> {
    let snapshot = state
        .snapshot
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .clone();
    Ok(Json(snapshot))
}

async fn bridge_post_request(
    AxumState(state): AxumState<BridgeRuntimeState>,
    Json(request): Json<WorkspaceIdeBridgeRequest>,
) -> impl IntoResponse {
    eprintln!(
        "[Workspace IDE] bridge request queued id={} type={}",
        request.request_id, request.request_type
    );
    match state.requests.lock() {
        Ok(mut queue) => {
            queue.push_back(request);
            StatusCode::ACCEPTED
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn spawn_bridge_server(
    port: u16,
    state: BridgeRuntimeState,
) -> Result<(oneshot::Sender<()>, tauri::async_runtime::JoinHandle<()>), String> {
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let app = Router::new()
        .route("/state", get(bridge_get_state))
        .route("/requests", post(bridge_post_request))
        .with_state(state);

    let listener = std::net::TcpListener::bind(address).map_err(|error| {
        format!(
            "Failed to bind workspace IDE bridge at {}: {}",
            address, error
        )
    })?;
    listener.set_nonblocking(true).map_err(|error| {
        format!(
            "Failed to set workspace IDE bridge listener nonblocking: {}",
            error
        )
    })?;

    let task = tauri::async_runtime::spawn(async move {
        let listener = match tokio::net::TcpListener::from_std(listener) {
            Ok(listener) => listener,
            Err(error) => {
                eprintln!("[Workspace IDE] Failed to adopt bridge listener: {}", error);
                return;
            }
        };

        let server = axum::serve(listener, app).with_graceful_shutdown(async move {
            let _ = shutdown_rx.await;
        });

        if let Err(error) = server.await {
            eprintln!("[Workspace IDE] Bridge server exited with error: {}", error);
        }
    });

    Ok((shutdown_tx, task))
}

fn platform_label() -> Result<&'static str, String> {
    match std::env::consts::OS {
        "linux" => Ok("linux"),
        "macos" => Ok("darwin"),
        "windows" => Ok("win32"),
        other => Err(format!(
            "Workspace IDE is not supported on platform '{}'.",
            other
        )),
    }
}

fn architecture_label() -> Result<&'static str, String> {
    match std::env::consts::ARCH {
        "x86_64" => Ok("x64"),
        "aarch64" => Ok("arm64"),
        other => Err(format!(
            "Workspace IDE is not supported on architecture '{}'.",
            other
        )),
    }
}

fn workspace_ide_root<R: Runtime>(app: &AppHandle<R>) -> PathBuf {
    crate::autopilot_data_dir_for(app).join("workspace-ide")
}

fn workspace_runtime_root<R: Runtime>(app: &AppHandle<R>, root_path: &Path) -> PathBuf {
    workspace_ide_root(app)
        .join("runtime")
        .join(hashed_workspace_id(&root_path.to_string_lossy()))
}

fn workspace_bridge_root<R: Runtime>(app: &AppHandle<R>, root_path: &Path) -> PathBuf {
    workspace_runtime_root(app, root_path).join("bridge")
}

fn release_slug() -> Result<String, String> {
    Ok(format!(
        "openvscode-server-v{}-{}-{}",
        OPENVSCODE_VERSION,
        platform_label()?,
        architecture_label()?
    ))
}

fn archive_download_url() -> Result<String, String> {
    let slug = release_slug()?;
    Ok(format!(
        "https://github.com/gitpod-io/openvscode-server/releases/download/openvscode-server-v{version}/{slug}.tar.gz",
        version = OPENVSCODE_VERSION
    ))
}

fn install_binary_path<R: Runtime>(app: &AppHandle<R>) -> Result<PathBuf, String> {
    let slug = release_slug()?;
    let binary_name = if cfg!(target_os = "windows") {
        "openvscode-server.cmd"
    } else {
        "openvscode-server"
    };

    Ok(workspace_ide_root(app)
        .join("vendor")
        .join(slug)
        .join("bin")
        .join(binary_name))
}

fn ensure_openvscode_installation<R: Runtime>(app: &AppHandle<R>) -> Result<PathBuf, String> {
    let binary_path = install_binary_path(app)?;
    if binary_path.exists() {
        return Ok(binary_path);
    }

    let root = workspace_ide_root(app);
    let downloads_dir = root.join("downloads");
    let vendor_dir = root.join("vendor");
    fs::create_dir_all(&downloads_dir).map_err(|error| {
        format!(
            "Failed to create workspace IDE download directory: {}",
            error
        )
    })?;
    fs::create_dir_all(&vendor_dir)
        .map_err(|error| format!("Failed to create workspace IDE vendor directory: {}", error))?;

    let archive_path = downloads_dir.join(format!("{}.tar.gz", release_slug()?));
    if !archive_path.exists() {
        let url = archive_download_url()?;
        let response = Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|error| format!("Failed to prepare OpenVSCode download client: {}", error))?
            .get(url.clone())
            .send()
            .and_then(|response| response.error_for_status())
            .map_err(|error| {
                format!(
                    "Failed to download OpenVSCode Server from {}: {}",
                    url, error
                )
            })?;

        let archive_file = File::create(&archive_path)
            .map_err(|error| format!("Failed to create OpenVSCode archive file: {}", error))?;
        let mut writer = BufWriter::new(archive_file);
        let mut response_reader = response;
        copy(&mut response_reader, &mut writer)
            .map_err(|error| format!("Failed to write OpenVSCode archive: {}", error))?;
    }

    let archive_file = File::open(&archive_path)
        .map_err(|error| format!("Failed to read OpenVSCode archive: {}", error))?;
    let decoder = GzDecoder::new(archive_file);
    let mut archive = tar::Archive::new(decoder);
    archive
        .unpack(&vendor_dir)
        .map_err(|error| format!("Failed to unpack OpenVSCode archive: {}", error))?;

    if !binary_path.exists() {
        return Err(format!(
            "OpenVSCode Server was unpacked but '{}' is still missing.",
            binary_path.display()
        ));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(&binary_path)
            .map_err(|error| format!("Failed to read OpenVSCode binary metadata: {}", error))?
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&binary_path, permissions).map_err(|error| {
            format!(
                "Failed to update permissions for '{}': {}",
                binary_path.display(),
                error
            )
        })?;
    }

    Ok(binary_path)
}

fn copy_dir_recursive(source: &Path, destination: &Path) -> Result<(), String> {
    fs::create_dir_all(destination).map_err(|error| {
        format!(
            "Failed to create bundled extension directory '{}': {}",
            destination.display(),
            error
        )
    })?;

    let entries = fs::read_dir(source).map_err(|error| {
        format!(
            "Failed to read bundled extension source '{}': {}",
            source.display(),
            error
        )
    })?;

    for entry in entries {
        let entry = entry.map_err(|error| {
            format!(
                "Failed to enumerate bundled extension entry in '{}': {}",
                source.display(),
                error
            )
        })?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let file_type = entry.file_type().map_err(|error| {
            format!(
                "Failed to inspect bundled extension entry '{}': {}",
                source_path.display(),
                error
            )
        })?;

        if file_type.is_dir() {
            copy_dir_recursive(&source_path, &destination_path)?;
        } else {
            fs::copy(&source_path, &destination_path).map_err(|error| {
                format!(
                    "Failed to copy bundled extension file '{}' to '{}': {}",
                    source_path.display(),
                    destination_path.display(),
                    error
                )
            })?;
        }
    }

    Ok(())
}

fn ensure_bundled_extension<R: Runtime>(
    app: &AppHandle<R>,
    extensions_dir: &Path,
) -> Result<(), String> {
    let resolved_resource = app
        .path()
        .resolve(
            "openvscode-extension/ioi-workbench",
            tauri::path::BaseDirectory::Resource,
        )
        .ok();
    let bundled_root = match resolved_resource {
        Some(path) if path.exists() => path,
        _ => {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../openvscode-extension/ioi-workbench")
        }
    };
    if !bundled_root.exists() {
        return Err(format!(
            "Bundled IOI workbench extension source '{}' is missing.",
            bundled_root.display()
        ));
    }
    let target_root = extensions_dir.join("ioi.ioi-workbench");

    if target_root.exists() {
        fs::remove_dir_all(&target_root).map_err(|error| {
            format!(
                "Failed to replace bundled IOI workbench extension at '{}': {}",
                target_root.display(),
                error
            )
        })?;
    }

    copy_dir_recursive(&bundled_root, &target_root)
}

fn file_uri_for_path(path: &Path) -> Result<String, String> {
    Url::from_file_path(path)
        .map(|uri| uri.to_string())
        .map_err(|_| format!("Failed to convert '{}' into a file URI.", path.display()))
}

fn hashed_workspace_id(root_path: &str) -> String {
    let mut hasher = DefaultHasher::new();
    root_path.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

fn workbench_url(port: u16, root_path: &Path) -> Result<String, String> {
    let folder_uri = file_uri_for_path(root_path)?;
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("folder", &folder_uri)
        .finish();
    Ok(format!("http://127.0.0.1:{port}/?{query}"))
}

fn ensure_openvscode_user_settings(user_data_dir: &Path) -> Result<(), String> {
    let settings_dir = user_data_dir.join("User");
    fs::create_dir_all(&settings_dir).map_err(|error| {
        format!(
            "Failed to create OpenVSCode user settings directory '{}': {}",
            settings_dir.display(),
            error
        )
    })?;
    let settings_path = settings_dir.join("settings.json");
    let mut settings = if settings_path.exists() {
        let contents = fs::read_to_string(&settings_path).map_err(|error| {
            format!(
                "Failed to read OpenVSCode user settings '{}': {}",
                settings_path.display(),
                error
            )
        })?;
        match serde_json::from_str::<Value>(&contents) {
            Ok(Value::Object(object)) => object,
            Ok(_) | Err(_) => serde_json::Map::new(),
        }
    } else {
        serde_json::Map::new()
    };

    settings.insert(
        "security.workspace.trust.enabled".to_string(),
        Value::Bool(false),
    );
    settings.insert(
        "security.workspace.trust.startupPrompt".to_string(),
        Value::String("never".to_string()),
    );
    settings.insert(
        "security.workspace.trust.banner".to_string(),
        Value::String("never".to_string()),
    );

    let contents = serde_json::to_string_pretty(&Value::Object(settings)).map_err(|error| {
        format!(
            "Failed to serialize OpenVSCode user settings '{}': {}",
            settings_path.display(),
            error
        )
    })?;
    fs::write(&settings_path, format!("{contents}\n")).map_err(|error| {
        format!(
            "Failed to write OpenVSCode user settings '{}': {}",
            settings_path.display(),
            error
        )
    })
}

fn wait_for_server_ready(workbench_url: &str) -> Result<(), String> {
    let client = Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .map_err(|error| format!("Failed to build OpenVSCode health client: {}", error))?;
    let deadline = Instant::now() + OPENVSCODE_BOOT_TIMEOUT;

    while Instant::now() < deadline {
        if let Ok(response) = client.get(workbench_url).send() {
            if response.status().is_success() {
                return Ok(());
            }
        }
        thread::sleep(Duration::from_millis(400));
    }

    Err(format!(
        "OpenVSCode Server did not become ready within {} seconds.",
        OPENVSCODE_BOOT_TIMEOUT.as_secs()
    ))
}

fn kill_session(handle: &mut WorkspaceIdeHandle) {
    if let Some(shutdown) = handle.bridge_shutdown.take() {
        let _ = shutdown.send(());
    }
    if let Some(task) = handle.bridge_task.take() {
        task.abort();
    }
    let _ = handle.child.kill();
    let _ = handle.child.wait();
}

fn current_session_info(handle: &WorkspaceIdeHandle) -> WorkspaceIdeSessionInfo {
    WorkspaceIdeSessionInfo {
        root_path: handle.root_path.clone(),
        workbench_url: handle.workbench_url.clone(),
        version: handle.version.clone(),
        process_id: handle.process_id,
        port: handle.port,
        bridge_port: handle.bridge_port,
        bridge_url: handle.bridge_url.clone(),
        bridge_path: handle.bridge_path.clone(),
        log_path: handle.log_path.clone(),
    }
}

fn ensure_bridge_dirs(bridge_root: &Path) -> Result<(), String> {
    fs::create_dir_all(bridge_root).map_err(|error| {
        format!(
            "Failed to create workspace IDE bridge directory '{}': {}",
            bridge_root.display(),
            error
        )
    })
}

#[tauri::command]
pub fn ensure_workspace_ide_session<R: Runtime>(
    root: String,
    app: AppHandle<R>,
    manager: State<WorkspaceIdeManager>,
) -> Result<WorkspaceIdeSessionInfo, String> {
    let root_path = PathBuf::from(&root)
        .canonicalize()
        .map_err(|error| format!("Failed to resolve workspace IDE root '{}': {}", root, error))?;
    if !root_path.is_dir() {
        return Err(format!(
            "Workspace IDE root '{}' is not a directory.",
            root_path.display()
        ));
    }

    let mut session_guard = manager
        .session
        .lock()
        .map_err(|_| "Failed to lock workspace IDE session state.".to_string())?;

    if let Some(existing) = session_guard.as_mut() {
        match existing.child.try_wait() {
            Ok(Some(_)) => {
                *session_guard = None;
            }
            Ok(None) if existing.root_path == root_path.to_string_lossy() => {
                return Ok(current_session_info(existing));
            }
            Ok(None) => {
                kill_session(existing);
                *session_guard = None;
            }
            Err(_) => {
                *session_guard = None;
            }
        }
    }

    let binary_path = ensure_openvscode_installation(&app)?;
    let port = portpicker::pick_unused_port()
        .ok_or_else(|| "Failed to allocate a port for OpenVSCode Server.".to_string())?;
    let bridge_port = portpicker::pick_unused_port()
        .ok_or_else(|| "Failed to allocate a port for the Workspace IDE bridge.".to_string())?;
    let ide_root = workspace_ide_root(&app);
    let workspace_id = hashed_workspace_id(&root_path.to_string_lossy());
    let runtime_root = workspace_runtime_root(&app, &root_path);
    let user_data_dir = runtime_root.join("user-data");
    let server_data_dir = runtime_root.join("server-data");
    let extensions_dir = runtime_root.join("extensions");
    let bridge_root = workspace_bridge_root(&app, &root_path);
    let logs_dir = ide_root.join("logs");
    fs::create_dir_all(&user_data_dir)
        .map_err(|error| format!("Failed to create OpenVSCode user-data directory: {}", error))?;
    ensure_openvscode_user_settings(&user_data_dir)?;
    fs::create_dir_all(&server_data_dir).map_err(|error| {
        format!(
            "Failed to create OpenVSCode server-data directory: {}",
            error
        )
    })?;
    fs::create_dir_all(&extensions_dir).map_err(|error| {
        format!(
            "Failed to create OpenVSCode extensions directory: {}",
            error
        )
    })?;
    ensure_bridge_dirs(&bridge_root)?;
    let bridge_state = Arc::new(BridgeRuntimeState::new());
    let (bridge_shutdown, bridge_task) = spawn_bridge_server(bridge_port, (*bridge_state).clone())?;
    fs::create_dir_all(&logs_dir)
        .map_err(|error| format!("Failed to create OpenVSCode log directory: {}", error))?;
    ensure_bundled_extension(&app, &extensions_dir)?;

    let log_path = logs_dir.join(format!("workspace-ide-{workspace_id}.log"));
    let stdout_log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|error| format!("Failed to open OpenVSCode log file: {}", error))?;
    let stderr_log = stdout_log
        .try_clone()
        .map_err(|error| format!("Failed to clone OpenVSCode log handle: {}", error))?;

    let mut command = Command::new(&binary_path);
    command
        .arg("--host")
        .arg("127.0.0.1")
        .arg("--port")
        .arg(port.to_string())
        .arg("--without-connection-token")
        .arg("--telemetry-level")
        .arg("off")
        .arg("--accept-server-license-terms")
        .arg("--disable-workspace-trust")
        .arg("--user-data-dir")
        .arg(&user_data_dir)
        .arg("--server-data-dir")
        .arg(&server_data_dir)
        .arg("--extensions-dir")
        .arg(&extensions_dir)
        .env("IOI_WORKSPACE_IDE_BRIDGE_ROOT", &bridge_root)
        .env(
            "IOI_WORKSPACE_IDE_BRIDGE_URL",
            format!("http://127.0.0.1:{bridge_port}"),
        )
        .env(
            "IOI_WORKSPACE_IDE_ROOT_PATH",
            root_path.to_string_lossy().to_string(),
        )
        .current_dir(&root_path)
        .stdout(Stdio::from(stdout_log))
        .stderr(Stdio::from(stderr_log));

    let mut child = command.spawn().map_err(|error| {
        format!(
            "Failed to launch OpenVSCode Server '{}': {}",
            binary_path.display(),
            error
        )
    })?;

    let workbench_url = workbench_url(port, &root_path)?;
    if let Err(error) = wait_for_server_ready(&workbench_url) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }

    let handle = WorkspaceIdeHandle {
        root_path: root_path.to_string_lossy().to_string(),
        workbench_url: workbench_url.clone(),
        version: OPENVSCODE_VERSION.to_string(),
        process_id: child.id(),
        port,
        bridge_port,
        bridge_url: format!("http://127.0.0.1:{bridge_port}"),
        bridge_path: bridge_root.to_string_lossy().to_string(),
        log_path: log_path.to_string_lossy().to_string(),
        child,
        bridge_shutdown: Some(bridge_shutdown),
        bridge_task: Some(bridge_task),
        bridge_state,
    };

    let info = current_session_info(&handle);
    *session_guard = Some(handle);
    Ok(info)
}

#[tauri::command]
pub fn stop_workspace_ide_session(manager: State<WorkspaceIdeManager>) -> Result<(), String> {
    let mut session_guard = manager
        .session
        .lock()
        .map_err(|_| "Failed to lock workspace IDE session state.".to_string())?;
    if let Some(existing) = session_guard.as_mut() {
        kill_session(existing);
    }
    *session_guard = None;
    Ok(())
}

#[tauri::command]
pub fn write_workspace_ide_bridge_state<R: Runtime>(
    root: String,
    state: Value,
    _app: AppHandle<R>,
    manager: State<WorkspaceIdeManager>,
) -> Result<(), String> {
    let root_path = PathBuf::from(&root).canonicalize().map_err(|error| {
        format!(
            "Failed to resolve workspace bridge root '{}': {}",
            root, error
        )
    })?;
    let mut session_guard = manager
        .session
        .lock()
        .map_err(|_| "Failed to lock workspace IDE session state.".to_string())?;
    if let Some(session) = session_guard.as_mut() {
        if session.root_path == root_path.to_string_lossy() {
            let mut snapshot = session
                .bridge_state
                .snapshot
                .lock()
                .map_err(|_| "Failed to lock workspace IDE bridge snapshot.".to_string())?;
            *snapshot = state;
        }
    }

    Ok(())
}

#[tauri::command]
pub fn take_workspace_ide_bridge_requests<R: Runtime>(
    root: String,
    _app: AppHandle<R>,
    manager: State<WorkspaceIdeManager>,
) -> Result<Vec<WorkspaceIdeBridgeRequest>, String> {
    let root_path = PathBuf::from(&root).canonicalize().map_err(|error| {
        format!(
            "Failed to resolve workspace bridge root '{}': {}",
            root, error
        )
    })?;

    let mut session_guard = manager
        .session
        .lock()
        .map_err(|_| "Failed to lock workspace IDE session state.".to_string())?;
    if let Some(session) = session_guard.as_mut() {
        if session.root_path == root_path.to_string_lossy() {
            let mut queue =
                session.bridge_state.requests.lock().map_err(|_| {
                    "Failed to lock workspace IDE bridge request queue.".to_string()
                })?;
            let drained: Vec<WorkspaceIdeBridgeRequest> = queue.drain(..).collect();
            if !drained.is_empty() {
                eprintln!(
                    "[Workspace IDE] bridge requests drained root={} count={} types={}",
                    session.root_path,
                    drained.len(),
                    drained
                        .iter()
                        .map(|request| request.request_type.as_str())
                        .collect::<Vec<_>>()
                        .join(",")
                );
            }
            return Ok(drained);
        }
    }
    Ok(Vec::new())
}
