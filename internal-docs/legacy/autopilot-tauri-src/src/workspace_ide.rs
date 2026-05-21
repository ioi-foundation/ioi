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
use serde_json::{json, Value};
use std::collections::{hash_map::DefaultHasher, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::hash::{Hash, Hasher};
use std::io::{copy, BufWriter};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Manager, Runtime, State};
use tokio::sync::oneshot;
use url::Url;

const OPENVSCODE_VERSION: &str = "1.109.5";
const OPENVSCODE_BOOT_TIMEOUT: Duration = Duration::from_secs(90);
const OPENVSCODE_AUTOPILOT_LEGACY_CHROME_PATCH_MARKER: &str =
    "/* IOI Autopilot owns OpenVSCode command center and chat chrome v2 */";
const OPENVSCODE_AUTOPILOT_WORKBENCH_JS_PATCH_MARKER: &str =
    "/* IOI Autopilot native workbench contribution replacement v2 */";
const OPENVSCODE_COMMAND_CENTER_GETTER_SOURCE: &str =
    "get ec(){return!this.zb&&this.Eb.getValue(\"window.commandCenter\")!==!1}";
const OPENVSCODE_COMMAND_CENTER_GETTER_PATCHED: &str = "get ec(){return!1}";
const OPENVSCODE_COMMAND_CENTER_CONTRIBUTION_SOURCE: &str = r#"JAt=class{constructor(e,t,i,n){this.a=new O,this.b=this.a.add(new E),this.onDidChangeVisibility=this.b.event,this.element=document.createElement("div"),this.element.classList.add("command-center");const o=i.createInstance(ur,this.element,I.CommandCenter,{contextMenu:I.TitleBarContext,hiddenItemStrategy:-1,toolbarOptions:{primaryGroup:()=>!0},telemetrySource:"commandCenter",actionViewItemProvider:(r,a)=>r instanceof cu&&r.item.submenu===I.CommandCenterCenter?i.createInstance(QAt,r,e,{...a,hoverDelegate:t}):Dc(i,r,{...a,hoverDelegate:t})});this.a.add(H.filter(n.onShow,()=>P2t(this.element),this.a)(this.c.bind(this,!1))),this.a.add(n.onHide(this.c.bind(this,!0))),this.a.add(o)}c(e){this.element.classList.toggle("hide",!e),this.b.fire()}dispose(){this.a.dispose()}}"#;
const OPENVSCODE_COMMAND_CENTER_CONTRIBUTION_PATCHED: &str = r#"JAt=class{constructor(e,t,i,n){this.a=new O,this.b=this.a.add(new E),this.onDidChangeVisibility=this.b.event,this.element=document.createElement("div"),this.element.classList.add("command-center","hide"),this.element.setAttribute("data-ioi-native-command-center-disabled","true")}c(e){this.element.classList.toggle("hide",!0),this.b.fire()}dispose(){this.a.dispose()}}"#;
const OPENVSCODE_UPSTREAM_CHAT_REGISTRATION_SOURCE: &str = r#"var Krn=we("chat-view-icon",P.chatSparkle,d(6027,null)),Ire=ce.as(xn.ViewContainersRegistry).registerViewContainer({id:S3,title:L(6058,"Chat"),icon:Krn,ctorDescriptor:new Bt(Xu,[S3,{mergeViewWithContainerWhenSingleView:!0}]),storageId:S3,hideIfEmpty:!0,order:1},2,{isDefault:!0,doNotRegisterOpenCommand:!0}),Jrn={id:mr,containerIcon:Ire.icon,containerTitle:Ire.title.value,singleViewPaneContainerTitle:Ire.title.value,name:L(6059,"Chat"),canToggleVisibility:!1,canMoveView:!0,openCommandActionDescriptor:{id:S3,title:Ire.title,mnemonicTitle:d(6028,null),keybindings:{primary:2599,mac:{primary:2343}},order:1},ctorDescriptor:new Bt(wmt),when:C.or(C.or(ee.Setup.hidden,ee.Setup.disabled)?.negate(),ee.panelParticipantRegistered,ee.extensionInvalid)};ce.as(xn.ViewsRegistry).registerViews([Jrn],Ire);"#;
const OPENVSCODE_UPSTREAM_CHAT_REGISTRATION_PATCHED: &str = r#"var Krn=we("chat-view-icon",P.chatSparkle,d(6027,null)),Ire={id:"ioi.disabled.upstream.chat",icon:Krn,title:{value:"Chat",original:"Chat"}},Jrn={id:"ioi.disabled.upstream.chat.view",containerIcon:Ire.icon,containerTitle:Ire.title.value,singleViewPaneContainerTitle:Ire.title.value,name:"Disabled upstream Chat",canToggleVisibility:!1,canMoveView:!1,openCommandActionDescriptor:void 0,ctorDescriptor:void 0,when:C.false};"#;
const OPENVSCODE_AUTOPILOT_NATIVE_PATCH_SCHEMA_VERSION: &str = "ioi.openvscode-managed-patch.v1";
const OPENVSCODE_AUTOPILOT_NATIVE_PATCH_ID: &str =
    "openvscode-native-autopilot-contribution-replacement";

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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceIdeBridgeCommand {
    pub command_id: String,
    pub command: String,
    #[serde(default)]
    pub args: Vec<Value>,
    pub timestamp_ms: u64,
}

#[derive(Clone)]
struct BridgeRuntimeState {
    snapshot: Arc<Mutex<Value>>,
    requests: Arc<Mutex<VecDeque<WorkspaceIdeBridgeRequest>>>,
    commands: Arc<Mutex<VecDeque<WorkspaceIdeBridgeCommand>>>,
}

impl BridgeRuntimeState {
    fn new() -> Self {
        Self {
            snapshot: Arc::new(Mutex::new(Value::Object(Default::default()))),
            requests: Arc::new(Mutex::new(VecDeque::new())),
            commands: Arc::new(Mutex::new(VecDeque::new())),
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

async fn bridge_get_commands(
    AxumState(state): AxumState<BridgeRuntimeState>,
) -> Result<Json<Vec<WorkspaceIdeBridgeCommand>>, StatusCode> {
    let mut queue = state
        .commands
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let drained: Vec<WorkspaceIdeBridgeCommand> = queue.drain(..).collect();
    if !drained.is_empty() {
        eprintln!(
            "[Workspace IDE] bridge commands drained count={} commands={}",
            drained.len(),
            drained
                .iter()
                .map(|command| command.command.as_str())
                .collect::<Vec<_>>()
                .join(",")
        );
    }
    Ok(Json(drained))
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
        .route("/commands", get(bridge_get_commands))
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
        ensure_openvscode_native_patch_manifest(&binary_path)?;
        ensure_openvscode_native_workbench_js_patch(&binary_path)?;
        ensure_openvscode_legacy_shell_chrome_patch_removed(&binary_path)?;
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

    ensure_openvscode_native_patch_manifest(&binary_path)?;
    ensure_openvscode_native_workbench_js_patch(&binary_path)?;
    ensure_openvscode_legacy_shell_chrome_patch_removed(&binary_path)?;

    Ok(binary_path)
}

fn openvscode_install_root_from_binary(binary_path: &Path) -> Result<PathBuf, String> {
    binary_path
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| {
            format!(
                "Failed to resolve OpenVSCode install root from '{}'.",
                binary_path.display()
            )
        })
}

fn openvscode_native_patch_manifest(install_root: &Path) -> Value {
    json!({
        "schemaVersion": OPENVSCODE_AUTOPILOT_NATIVE_PATCH_SCHEMA_VERSION,
        "patchId": OPENVSCODE_AUTOPILOT_NATIVE_PATCH_ID,
        "openvscodeVersion": OPENVSCODE_VERSION,
        "installRoot": install_root.to_string_lossy(),
        "runtimeTruth": {
            "source": "daemon-runtime",
            "agentgresRecordsOperationalTruth": true,
            "walletAuthorizesPower": true,
            "openvscodeOwnsRuntimeState": false
        },
        "normalLaunchContract": {
            "autopilotHeaderOwnsGlobalCommandCenter": true,
            "singleChatContribution": "ioi.chat",
            "upstreamChatContributionAllowed": false,
            "reactFlowShadowRuntimeTruthAllowed": false
        },
        "steps": [
            {
                "id": "disable-upstream-chat-contribution",
                "kind": "native-workbench-patch",
                "target": "workbench.panel.chat container + workbench.panel.chat.view.copilot view registration",
                "status": "installed-native-workbench-contribution-noop",
                "temporaryCompatibility": false,
                "mechanism": "managed-workbench-js-contribution-noop-and-profile-feature-gate",
                "patchMarker": OPENVSCODE_AUTOPILOT_WORKBENCH_JS_PATCH_MARKER
            },
            {
                "id": "disable-upstream-command-center",
                "kind": "native-workbench-patch",
                "target": "TitlebarPart.commandCenter getter + CommandCenter contribution renderer + managed profile keybindings",
                "status": "installed-native-workbench-overlay",
                "temporaryCompatibility": false,
                "mechanism": "managed-workbench-js-contribution-noop-and-profile-keybinding",
                "patchMarker": OPENVSCODE_AUTOPILOT_WORKBENCH_JS_PATCH_MARKER
            },
            {
                "id": "install-ioi-workbench-contribution",
                "kind": "extension-contribution",
                "target": "ioi.ioi-workbench secondarySidebar/ioi-chat",
                "status": "installed-native-chat-container",
                "temporaryCompatibility": false
            },
            {
                "id": "bridge-workbench-context",
                "kind": "runtime-projection",
                "target": "WorkbenchContextSnapshot",
                "status": "planned",
                "temporaryCompatibility": false
            },
            {
                "id": "export-native-target-index",
                "kind": "inspection-projection",
                "target": "WorkbenchInspectionTargetIndex",
                "status": "planned",
                "temporaryCompatibility": false
            },
            {
                "id": "workflow-code-generation-receipts",
                "kind": "workflow-projection",
                "target": "WorkflowCodeGenerationReceipt",
                "status": "planned",
                "temporaryCompatibility": false
            }
        ]
    })
}

fn ensure_openvscode_native_workbench_js_patch(binary_path: &Path) -> Result<(), String> {
    let workbench_script_path = openvscode_workbench_script_path(binary_path)?;
    patch_openvscode_native_workbench_js(&workbench_script_path)
}

fn openvscode_workbench_script_path(binary_path: &Path) -> Result<PathBuf, String> {
    let install_root = openvscode_install_root_from_binary(binary_path)?;
    Ok(install_root
        .join("out")
        .join("vs")
        .join("code")
        .join("browser")
        .join("workbench")
        .join("workbench.js"))
}

fn openvscode_native_workbench_js_patch_owned(binary_path: &Path) -> bool {
    openvscode_workbench_script_path(binary_path)
        .ok()
        .and_then(|workbench_script_path| fs::read_to_string(workbench_script_path).ok())
        .map(|contents| {
            contents.contains(OPENVSCODE_AUTOPILOT_WORKBENCH_JS_PATCH_MARKER)
                && contents.contains(OPENVSCODE_COMMAND_CENTER_GETTER_PATCHED)
                && contents.contains(OPENVSCODE_COMMAND_CENTER_CONTRIBUTION_PATCHED)
                && contents.contains(OPENVSCODE_UPSTREAM_CHAT_REGISTRATION_PATCHED)
                && !contents.contains(OPENVSCODE_UPSTREAM_CHAT_REGISTRATION_SOURCE)
                && !contents.contains("registerViewContainer({id:S3,title:L(6058,\"Chat\")")
                && !contents.contains("registerViews([Jrn],Ire)")
        })
        .unwrap_or(false)
}

fn patch_openvscode_native_workbench_js(workbench_script_path: &Path) -> Result<(), String> {
    let script = fs::read_to_string(workbench_script_path).map_err(|error| {
        format!(
            "Failed to read OpenVSCode workbench script '{}': {}",
            workbench_script_path.display(),
            error
        )
    })?;

    let mut next_script = script;
    if !next_script.contains(OPENVSCODE_COMMAND_CENTER_GETTER_PATCHED) {
        if next_script.contains(OPENVSCODE_COMMAND_CENTER_GETTER_SOURCE) {
            next_script = next_script.replace(
                OPENVSCODE_COMMAND_CENTER_GETTER_SOURCE,
                OPENVSCODE_COMMAND_CENTER_GETTER_PATCHED,
            );
        } else {
            return Err(format!(
                "Failed to locate OpenVSCode command-center getter in '{}'. Expected OpenVSCode {} bundle shape.",
                workbench_script_path.display(),
                OPENVSCODE_VERSION
            ));
        }
    }

    if !next_script.contains(OPENVSCODE_COMMAND_CENTER_CONTRIBUTION_PATCHED) {
        if next_script.contains(OPENVSCODE_COMMAND_CENTER_CONTRIBUTION_SOURCE) {
            next_script = next_script.replace(
                OPENVSCODE_COMMAND_CENTER_CONTRIBUTION_SOURCE,
                OPENVSCODE_COMMAND_CENTER_CONTRIBUTION_PATCHED,
            );
        } else {
            return Err(format!(
                "Failed to locate OpenVSCode CommandCenter contribution renderer in '{}'. Expected OpenVSCode {} bundle shape.",
                workbench_script_path.display(),
                OPENVSCODE_VERSION
            ));
        }
    }

    if !next_script.contains(OPENVSCODE_UPSTREAM_CHAT_REGISTRATION_PATCHED) {
        if next_script.contains(OPENVSCODE_UPSTREAM_CHAT_REGISTRATION_SOURCE) {
            next_script = next_script.replace(
                OPENVSCODE_UPSTREAM_CHAT_REGISTRATION_SOURCE,
                OPENVSCODE_UPSTREAM_CHAT_REGISTRATION_PATCHED,
            );
        } else {
            return Err(format!(
                "Failed to locate OpenVSCode upstream Chat contribution registration in '{}'. Expected OpenVSCode {} bundle shape.",
                workbench_script_path.display(),
                OPENVSCODE_VERSION
            ));
        }
    }

    if !next_script.contains(OPENVSCODE_AUTOPILOT_WORKBENCH_JS_PATCH_MARKER) {
        next_script = format!(
            "{}\n{}",
            OPENVSCODE_AUTOPILOT_WORKBENCH_JS_PATCH_MARKER, next_script
        );
    }

    if fs::read_to_string(workbench_script_path)
        .map(|existing| existing == next_script)
        .unwrap_or(false)
    {
        return Ok(());
    }

    fs::write(workbench_script_path, next_script).map_err(|error| {
        format!(
            "Failed to write OpenVSCode native workbench contribution patch '{}': {}",
            workbench_script_path.display(),
            error
        )
    })
}

fn ensure_openvscode_native_patch_manifest(binary_path: &Path) -> Result<(), String> {
    let install_root = openvscode_install_root_from_binary(binary_path)?;
    let manifest_dir = install_root.join(".ioi-autopilot");
    fs::create_dir_all(&manifest_dir).map_err(|error| {
        format!(
            "Failed to create OpenVSCode managed patch directory '{}': {}",
            manifest_dir.display(),
            error
        )
    })?;

    let manifest_path = manifest_dir.join("managed-openvscode-patch.json");
    let manifest = openvscode_native_patch_manifest(&install_root);
    let contents = format!(
        "{}\n",
        serde_json::to_string_pretty(&manifest).map_err(|error| {
            format!(
                "Failed to serialize OpenVSCode managed patch manifest: {}",
                error
            )
        })?
    );

    if fs::read_to_string(&manifest_path)
        .map(|existing| existing == contents)
        .unwrap_or(false)
    {
        return Ok(());
    }

    fs::write(&manifest_path, contents).map_err(|error| {
        format!(
            "Failed to write OpenVSCode managed patch manifest '{}': {}",
            manifest_path.display(),
            error
        )
    })
}

fn ensure_openvscode_legacy_shell_chrome_patch_removed(binary_path: &Path) -> Result<(), String> {
    let install_root = openvscode_install_root_from_binary(binary_path)?;
    let stylesheet_paths = [
        install_root
            .join("extensions")
            .join("theme-2026")
            .join("themes")
            .join("styles.css"),
        install_root
            .join("out")
            .join("vs")
            .join("code")
            .join("browser")
            .join("workbench")
            .join("workbench.css"),
    ];

    for stylesheet_path in stylesheet_paths {
        remove_openvscode_legacy_stylesheet_chrome_patch(&stylesheet_path)?;
    }

    Ok(())
}

fn remove_openvscode_legacy_stylesheet_chrome_patch(stylesheet_path: &Path) -> Result<(), String> {
    let stylesheet = fs::read_to_string(&stylesheet_path).map_err(|error| {
        format!(
            "Failed to read OpenVSCode shell stylesheet '{}': {}",
            stylesheet_path.display(),
            error
        )
    })?;

    let Some(marker_start) = stylesheet.find(OPENVSCODE_AUTOPILOT_LEGACY_CHROME_PATCH_MARKER)
    else {
        return Ok(());
    };

    let mut cleaned = stylesheet[..marker_start].trim_end().to_string();
    if !cleaned.is_empty() {
        cleaned.push('\n');
    }

    fs::write(&stylesheet_path, cleaned).map_err(|error| {
        format!(
            "Failed to remove OpenVSCode legacy shell stylesheet patch '{}': {}",
            stylesheet_path.display(),
            error
        )
    })
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
    settings.insert(
        "workbench.startupEditor".to_string(),
        Value::String("none".to_string()),
    );
    settings.insert("window.commandCenter".to_string(), Value::Bool(false));
    settings.insert(
        "window.customTitleBarVisibility".to_string(),
        Value::String("never".to_string()),
    );
    settings.insert(
        "workbench.layoutControl.enabled".to_string(),
        Value::Bool(false),
    );
    settings.insert(
        "workbench.navigationControl.enabled".to_string(),
        Value::Bool(false),
    );
    settings.insert(
        "workbench.secondarySideBar.defaultVisibility".to_string(),
        Value::String("visible".to_string()),
    );
    settings.insert("chat.disableAIFeatures".to_string(), Value::Bool(true));
    settings.insert("chat.agent.enabled".to_string(), Value::Bool(false));
    settings.insert("chat.agentsControl.enabled".to_string(), Value::Bool(false));
    settings.insert(
        "chat.unifiedAgentsBar.enabled".to_string(),
        Value::Bool(false),
    );
    settings.insert("chat.viewSessions.enabled".to_string(), Value::Bool(false));
    settings.insert(
        "chat.agentSessionProjection.enabled".to_string(),
        Value::Bool(false),
    );
    settings.insert(
        "workbench.experimental.share.enabled".to_string(),
        Value::Bool(false),
    );
    settings.insert(
        "workbench.welcomePage.walkthroughs.openOnInstall".to_string(),
        Value::Bool(false),
    );
    settings.insert(
        "git.openRepositoryInParentFolders".to_string(),
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

fn ensure_openvscode_user_keybindings(user_data_dir: &Path) -> Result<(), String> {
    let settings_dir = user_data_dir.join("User");
    fs::create_dir_all(&settings_dir).map_err(|error| {
        format!(
            "Failed to create OpenVSCode user keybindings directory '{}': {}",
            settings_dir.display(),
            error
        )
    })?;
    let keybindings_path = settings_dir.join("keybindings.json");
    let keybindings = json!([
        {
            "key": "ctrl+p",
            "command": "-workbench.action.quickOpen"
        },
        {
            "key": "ctrl+e",
            "command": "-workbench.action.quickOpen"
        },
        {
            "key": "ctrl+shift+p",
            "command": "-workbench.action.showCommands"
        },
        {
            "key": "f1",
            "command": "-workbench.action.showCommands"
        },
        {
            "key": "ctrl+alt+l",
            "command": "-workbench.action.quickOpen"
        },
        {
            "key": "ctrl+shift+alt+l",
            "command": "-workbench.action.quickOpen"
        },
        {
            "key": "ctrl+k",
            "command": "ioi.commandCenter.open"
        },
        {
            "key": "ctrl+p",
            "command": "ioi.commandCenter.open"
        },
        {
            "key": "ctrl+shift+p",
            "command": "ioi.commandCenter.open",
            "args": {
                "initialQuery": ">"
            }
        },
        {
            "key": "f1",
            "command": "ioi.commandCenter.open",
            "args": {
                "initialQuery": ">"
            }
        },
        {
            "key": "cmd+k",
            "command": "ioi.commandCenter.open"
        },
        {
            "key": "cmd+p",
            "command": "ioi.commandCenter.open"
        },
        {
            "key": "cmd+shift+p",
            "command": "ioi.commandCenter.open",
            "args": {
                "initialQuery": ">"
            }
        }
    ]);
    let contents = serde_json::to_string_pretty(&keybindings).map_err(|error| {
        format!(
            "Failed to serialize OpenVSCode user keybindings '{}': {}",
            keybindings_path.display(),
            error
        )
    })?;
    fs::write(&keybindings_path, format!("{contents}\n")).map_err(|error| {
        format!(
            "Failed to write OpenVSCode user keybindings '{}': {}",
            keybindings_path.display(),
            error
        )
    })
}

fn openvscode_user_config_owned(user_data_dir: &Path) -> bool {
    let settings_path = user_data_dir.join("User").join("settings.json");
    let keybindings_path = user_data_dir.join("User").join("keybindings.json");

    let settings_ready = fs::read_to_string(&settings_path)
        .ok()
        .and_then(|contents| serde_json::from_str::<Value>(&contents).ok())
        .and_then(|value| value.as_object().cloned())
        .map(|settings| {
            settings.get("window.commandCenter") == Some(&Value::Bool(false))
                && settings.get("window.customTitleBarVisibility")
                    == Some(&Value::String("never".to_string()))
                && settings.get("workbench.layoutControl.enabled") == Some(&Value::Bool(false))
                && settings.get("workbench.navigationControl.enabled") == Some(&Value::Bool(false))
                && settings.get("workbench.secondarySideBar.defaultVisibility")
                    == Some(&Value::String("visible".to_string()))
                && settings.get("chat.disableAIFeatures") == Some(&Value::Bool(true))
                && settings.get("chat.agent.enabled") == Some(&Value::Bool(false))
                && settings.get("chat.agentsControl.enabled") == Some(&Value::Bool(false))
                && settings.get("chat.unifiedAgentsBar.enabled") == Some(&Value::Bool(false))
                && settings.get("chat.viewSessions.enabled") == Some(&Value::Bool(false))
                && settings.get("chat.agentSessionProjection.enabled") == Some(&Value::Bool(false))
                && settings.get("workbench.experimental.share.enabled") == Some(&Value::Bool(false))
                && settings.get("git.openRepositoryInParentFolders")
                    == Some(&Value::String("never".to_string()))
        })
        .unwrap_or(false);

    let keybindings_ready = fs::read_to_string(&keybindings_path)
        .map(|contents| {
            contents.contains("\"-workbench.action.quickOpen\"")
                && contents.contains("\"-workbench.action.showCommands\"")
                && contents.contains("\"ioi.commandCenter.open\"")
        })
        .unwrap_or(false);

    settings_ready && keybindings_ready
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

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

#[tauri::command]
pub fn ensure_workspace_ide_session<R: Runtime>(
    root: String,
    app: AppHandle<R>,
    manager: State<WorkspaceIdeManager>,
) -> Result<WorkspaceIdeSessionInfo, String> {
    let root_path = crate::resolve_autopilot_workspace_root(&root)
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
                let existing_runtime_root = workspace_runtime_root(&app, &root_path);
                let existing_user_data_dir = existing_runtime_root.join("user-data");
                let native_patch_owned = install_binary_path(&app)
                    .map(|binary_path| openvscode_native_workbench_js_patch_owned(&binary_path))
                    .unwrap_or(false);
                if openvscode_user_config_owned(&existing_user_data_dir) && native_patch_owned {
                    return Ok(current_session_info(existing));
                }

                kill_session(existing);
                *session_guard = None;
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
    ensure_openvscode_user_keybindings(&user_data_dir)?;
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
pub fn enqueue_workspace_ide_bridge_command<R: Runtime>(
    root: String,
    command_id: String,
    command: String,
    args: Vec<Value>,
    _app: AppHandle<R>,
    manager: State<WorkspaceIdeManager>,
) -> Result<WorkspaceIdeBridgeCommand, String> {
    let root_path = PathBuf::from(&root).canonicalize().map_err(|error| {
        format!(
            "Failed to resolve workspace bridge command root '{}': {}",
            root, error
        )
    })?;
    let session_guard = manager
        .session
        .lock()
        .map_err(|_| "Failed to lock workspace IDE session state.".to_string())?;
    let Some(session) = session_guard.as_ref() else {
        return Err("Workspace IDE session is not running.".to_string());
    };
    if session.root_path != root_path.to_string_lossy() {
        return Err(format!(
            "Workspace IDE session root '{}' does not match requested root '{}'.",
            session.root_path,
            root_path.display()
        ));
    }

    let next = WorkspaceIdeBridgeCommand {
        command_id,
        command,
        args,
        timestamp_ms: unix_time_ms(),
    };
    let mut queue = session
        .bridge_state
        .commands
        .lock()
        .map_err(|_| "Failed to lock workspace IDE bridge command queue.".to_string())?;
    eprintln!(
        "[Workspace IDE] bridge command queued root={} id={} command={}",
        session.root_path, next.command_id, next.command
    );
    queue.push_back(next.clone());
    Ok(next)
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

#[cfg(test)]
mod tests {
    use super::{
        ensure_openvscode_legacy_shell_chrome_patch_removed,
        ensure_openvscode_native_patch_manifest, ensure_openvscode_native_workbench_js_patch,
        ensure_openvscode_user_keybindings, ensure_openvscode_user_settings,
        openvscode_native_patch_manifest, openvscode_native_workbench_js_patch_owned,
        openvscode_user_config_owned, OPENVSCODE_AUTOPILOT_LEGACY_CHROME_PATCH_MARKER,
        OPENVSCODE_AUTOPILOT_NATIVE_PATCH_ID, OPENVSCODE_AUTOPILOT_NATIVE_PATCH_SCHEMA_VERSION,
        OPENVSCODE_AUTOPILOT_WORKBENCH_JS_PATCH_MARKER,
        OPENVSCODE_COMMAND_CENTER_CONTRIBUTION_PATCHED,
        OPENVSCODE_COMMAND_CENTER_CONTRIBUTION_SOURCE, OPENVSCODE_COMMAND_CENTER_GETTER_PATCHED,
        OPENVSCODE_COMMAND_CENTER_GETTER_SOURCE, OPENVSCODE_UPSTREAM_CHAT_REGISTRATION_PATCHED,
        OPENVSCODE_UPSTREAM_CHAT_REGISTRATION_SOURCE,
    };
    use serde_json::Value;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_user_data(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "autopilot-workspace-ide-{name}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("temporary user-data directory should be created");
        path
    }

    fn temp_openvscode_binary(name: &str) -> PathBuf {
        let root = temp_user_data(name);
        let bin_dir = root.join("bin");
        let theme_dir = root.join("extensions").join("theme-2026").join("themes");
        let workbench_dir = root
            .join("out")
            .join("vs")
            .join("code")
            .join("browser")
            .join("workbench");
        fs::create_dir_all(&bin_dir).expect("OpenVSCode bin dir should be created");
        fs::create_dir_all(&theme_dir).expect("OpenVSCode theme dir should be created");
        fs::create_dir_all(&workbench_dir).expect("OpenVSCode workbench dir should be created");
        let binary = bin_dir.join("openvscode-server");
        fs::write(&binary, "#!/bin/sh\n").expect("OpenVSCode binary stub should be written");
        fs::write(
            theme_dir.join("styles.css"),
            ".monaco-workbench .part.titlebar { color: inherit; }\n",
        )
        .expect("OpenVSCode stylesheet should be written");
        fs::write(
            workbench_dir.join("workbench.css"),
            ".monaco-workbench .part.titlebar { display: flex; }\n",
        )
        .expect("OpenVSCode workbench stylesheet should be written");
        fs::write(
            workbench_dir.join("workbench.js"),
            format!(
                "var nFe=class{{{}Xb(){{this.vb.clear()}}}};{};{};\n",
                OPENVSCODE_COMMAND_CENTER_GETTER_SOURCE,
                OPENVSCODE_COMMAND_CENTER_CONTRIBUTION_SOURCE,
                OPENVSCODE_UPSTREAM_CHAT_REGISTRATION_SOURCE
            ),
        )
        .expect("OpenVSCode workbench script should be written");
        binary
    }

    #[test]
    fn openvscode_user_config_defers_global_search_to_autopilot() {
        let user_data_dir = temp_user_data("command-center-owned-by-autopilot");

        ensure_openvscode_user_settings(&user_data_dir)
            .expect("OpenVSCode settings should be written");
        ensure_openvscode_user_keybindings(&user_data_dir)
            .expect("OpenVSCode keybindings should be written");

        let settings_path = user_data_dir.join("User").join("settings.json");
        let settings: Value = serde_json::from_str(
            &fs::read_to_string(&settings_path).expect("settings should be readable"),
        )
        .expect("settings should be json");
        assert_eq!(
            settings.get("window.commandCenter"),
            Some(&Value::Bool(false))
        );
        assert_eq!(
            settings.get("window.customTitleBarVisibility"),
            Some(&Value::String("never".to_string()))
        );
        assert_eq!(
            settings.get("workbench.layoutControl.enabled"),
            Some(&Value::Bool(false))
        );
        assert_eq!(
            settings.get("workbench.navigationControl.enabled"),
            Some(&Value::Bool(false))
        );
        assert_eq!(
            settings.get("workbench.secondarySideBar.defaultVisibility"),
            Some(&Value::String("visible".to_string()))
        );
        assert_eq!(
            settings.get("chat.disableAIFeatures"),
            Some(&Value::Bool(true))
        );
        assert_eq!(
            settings.get("chat.agent.enabled"),
            Some(&Value::Bool(false))
        );
        assert_eq!(
            settings.get("chat.agentsControl.enabled"),
            Some(&Value::Bool(false))
        );
        assert_eq!(
            settings.get("chat.unifiedAgentsBar.enabled"),
            Some(&Value::Bool(false))
        );
        assert_eq!(
            settings.get("chat.viewSessions.enabled"),
            Some(&Value::Bool(false))
        );
        assert_eq!(
            settings.get("chat.agentSessionProjection.enabled"),
            Some(&Value::Bool(false))
        );
        assert_eq!(
            settings.get("workbench.experimental.share.enabled"),
            Some(&Value::Bool(false))
        );
        assert_eq!(
            settings.get("git.openRepositoryInParentFolders"),
            Some(&Value::String("never".to_string()))
        );

        let keybindings = fs::read_to_string(user_data_dir.join("User").join("keybindings.json"))
            .expect("keybindings should be readable");
        assert!(keybindings.contains("\"-workbench.action.quickOpen\""));
        assert!(keybindings.contains("\"-workbench.action.showCommands\""));
        assert!(keybindings.contains("\"ioi.commandCenter.open\""));
        assert!(openvscode_user_config_owned(&user_data_dir));

        let _ = fs::remove_dir_all(user_data_dir);
    }

    #[test]
    fn openvscode_user_config_owned_requires_disabled_chrome_and_keybindings() {
        let user_data_dir = temp_user_data("owned-contract");

        ensure_openvscode_user_settings(&user_data_dir)
            .expect("OpenVSCode settings should be written");
        assert!(
            !openvscode_user_config_owned(&user_data_dir),
            "settings alone should not claim ownership because keybindings still route quick-open to OpenVSCode"
        );

        ensure_openvscode_user_keybindings(&user_data_dir)
            .expect("OpenVSCode keybindings should be written");
        assert!(openvscode_user_config_owned(&user_data_dir));

        let settings_path = user_data_dir.join("User").join("settings.json");
        let mut settings: Value = serde_json::from_str(
            &fs::read_to_string(&settings_path).expect("settings should be readable"),
        )
        .expect("settings should be json");
        settings["window.commandCenter"] = Value::Bool(true);
        fs::write(
            &settings_path,
            serde_json::to_string_pretty(&settings).expect("settings should serialize"),
        )
        .expect("settings mutation should be written");
        assert!(
            !openvscode_user_config_owned(&user_data_dir),
            "stale OpenVSCode sessions must relaunch when the substrate owns command center chrome"
        );

        ensure_openvscode_user_settings(&user_data_dir)
            .expect("OpenVSCode settings should restore managed chat posture");
        let mut settings: Value = serde_json::from_str(
            &fs::read_to_string(&settings_path).expect("settings should be readable"),
        )
        .expect("settings should be json");
        settings["workbench.navigationControl.enabled"] = Value::Bool(true);
        fs::write(
            &settings_path,
            serde_json::to_string_pretty(&settings).expect("settings should serialize"),
        )
        .expect("settings mutation should be written");
        assert!(
            !openvscode_user_config_owned(&user_data_dir),
            "stale OpenVSCode sessions must relaunch when navigation controls can re-enable command center chrome"
        );

        ensure_openvscode_user_settings(&user_data_dir)
            .expect("OpenVSCode settings should restore managed navigation posture");
        let mut settings: Value = serde_json::from_str(
            &fs::read_to_string(&settings_path).expect("settings should be readable"),
        )
        .expect("settings should be json");
        settings["chat.disableAIFeatures"] = Value::Bool(false);
        fs::write(
            &settings_path,
            serde_json::to_string_pretty(&settings).expect("settings should serialize"),
        )
        .expect("settings mutation should be written");
        assert!(
            !openvscode_user_config_owned(&user_data_dir),
            "stale OpenVSCode sessions must relaunch when upstream native chat is re-enabled"
        );

        ensure_openvscode_user_settings(&user_data_dir)
            .expect("OpenVSCode settings should restore managed chat posture");
        let mut settings: Value = serde_json::from_str(
            &fs::read_to_string(&settings_path).expect("settings should be readable"),
        )
        .expect("settings should be json");
        settings["chat.agentsControl.enabled"] = Value::Bool(true);
        fs::write(
            &settings_path,
            serde_json::to_string_pretty(&settings).expect("settings should serialize"),
        )
        .expect("settings mutation should be written");
        assert!(
            !openvscode_user_config_owned(&user_data_dir),
            "stale OpenVSCode sessions must relaunch when upstream agent controls can re-enable command center chrome"
        );

        ensure_openvscode_user_settings(&user_data_dir)
            .expect("OpenVSCode settings should restore managed chat posture");
        let mut settings: Value = serde_json::from_str(
            &fs::read_to_string(&settings_path).expect("settings should be readable"),
        )
        .expect("settings should be json");
        settings["window.customTitleBarVisibility"] = Value::String("windowed".to_string());
        fs::write(
            &settings_path,
            serde_json::to_string_pretty(&settings).expect("settings should serialize"),
        )
        .expect("settings mutation should be written");
        assert!(
            !openvscode_user_config_owned(&user_data_dir),
            "stale OpenVSCode sessions must relaunch when upstream titlebar chrome is visible"
        );

        ensure_openvscode_user_settings(&user_data_dir)
            .expect("OpenVSCode settings should restore managed titlebar posture");
        let mut settings: Value = serde_json::from_str(
            &fs::read_to_string(&settings_path).expect("settings should be readable"),
        )
        .expect("settings should be json");
        settings["git.openRepositoryInParentFolders"] = Value::String("prompt".to_string());
        fs::write(
            &settings_path,
            serde_json::to_string_pretty(&settings).expect("settings should serialize"),
        )
        .expect("settings mutation should be written");
        assert!(
            !openvscode_user_config_owned(&user_data_dir),
            "stale OpenVSCode sessions must relaunch when Git parent-repository prompts can cover the native chat composer"
        );

        let _ = fs::remove_dir_all(user_data_dir);
    }

    #[test]
    fn openvscode_legacy_shell_chrome_patch_is_removed() {
        let binary_path = temp_openvscode_binary("legacy-command-center-shell-patch");
        let install_root = binary_path
            .parent()
            .and_then(Path::parent)
            .expect("test binary should have install root")
            .to_path_buf();
        let stylesheet_path = install_root
            .join("extensions")
            .join("theme-2026")
            .join("themes")
            .join("styles.css");
        let workbench_stylesheet_path = install_root
            .join("out")
            .join("vs")
            .join("code")
            .join("browser")
            .join("workbench")
            .join("workbench.css");
        fs::write(
            &stylesheet_path,
            format!(
                ".monaco-workbench .part.titlebar {{ color: inherit; }}\n\n{}\n.legacy {{ display: none !important; }}\n",
                OPENVSCODE_AUTOPILOT_LEGACY_CHROME_PATCH_MARKER
            ),
        )
        .expect("legacy stylesheet patch should be seeded");
        fs::write(
            &workbench_stylesheet_path,
            format!(
                ".monaco-workbench .part.titlebar {{ display: flex; }}\n\n{}\n.legacy {{ visibility: hidden !important; }}\n",
                OPENVSCODE_AUTOPILOT_LEGACY_CHROME_PATCH_MARKER
            ),
        )
        .expect("legacy workbench stylesheet patch should be seeded");

        ensure_openvscode_legacy_shell_chrome_patch_removed(&binary_path)
            .expect("OpenVSCode legacy shell chrome patch should be removed");
        ensure_openvscode_legacy_shell_chrome_patch_removed(&binary_path)
            .expect("OpenVSCode legacy shell chrome patch removal should be idempotent");

        let stylesheet =
            fs::read_to_string(&stylesheet_path).expect("stylesheet should be readable");
        assert!(!stylesheet.contains(OPENVSCODE_AUTOPILOT_LEGACY_CHROME_PATCH_MARKER));
        assert!(!stylesheet.contains(".legacy"));
        assert!(stylesheet.contains(".part.titlebar"));

        let workbench_stylesheet = fs::read_to_string(&workbench_stylesheet_path)
            .expect("workbench stylesheet should be readable");
        assert!(!workbench_stylesheet.contains(OPENVSCODE_AUTOPILOT_LEGACY_CHROME_PATCH_MARKER));
        assert!(!workbench_stylesheet.contains(".legacy"));
        assert!(workbench_stylesheet.contains(".part.titlebar"));

        let _ = fs::remove_dir_all(install_root);
    }

    #[test]
    fn openvscode_native_workbench_js_patch_disables_command_center_getter() {
        let binary_path = temp_openvscode_binary("native-command-center-workbench-js-patch");
        let install_root = binary_path
            .parent()
            .and_then(Path::parent)
            .expect("test binary should have install root")
            .to_path_buf();
        let workbench_script_path = install_root
            .join("out")
            .join("vs")
            .join("code")
            .join("browser")
            .join("workbench")
            .join("workbench.js");

        ensure_openvscode_native_workbench_js_patch(&binary_path)
            .expect("OpenVSCode native workbench command-center patch should be applied");
        let first = fs::read_to_string(&workbench_script_path)
            .expect("workbench script should be readable");
        ensure_openvscode_native_workbench_js_patch(&binary_path)
            .expect("OpenVSCode native workbench command-center patch should be idempotent");
        let second = fs::read_to_string(&workbench_script_path)
            .expect("workbench script should be readable");

        assert_eq!(first, second);
        assert!(first.contains(OPENVSCODE_AUTOPILOT_WORKBENCH_JS_PATCH_MARKER));
        assert!(first.contains(OPENVSCODE_COMMAND_CENTER_GETTER_PATCHED));
        assert!(first.contains(OPENVSCODE_COMMAND_CENTER_CONTRIBUTION_PATCHED));
        assert!(first.contains(OPENVSCODE_UPSTREAM_CHAT_REGISTRATION_PATCHED));
        assert!(!first.contains(OPENVSCODE_COMMAND_CENTER_GETTER_SOURCE));
        assert!(!first.contains(OPENVSCODE_COMMAND_CENTER_CONTRIBUTION_SOURCE));
        assert!(!first.contains(OPENVSCODE_UPSTREAM_CHAT_REGISTRATION_SOURCE));
        assert!(!first.contains("i.createInstance(ur,this.element,I.CommandCenter"));
        assert!(first.contains("data-ioi-native-command-center-disabled"));
        assert!(!first.contains("registerViewContainer({id:S3,title:L(6058,\"Chat\")"));
        assert!(!first.contains("registerViews([Jrn],Ire)"));
        assert!(!first.contains("workbench.panel.chat.view.${PUe}"));
        assert!(first.contains("ioi.disabled.upstream.chat"));
        assert!(
            first.starts_with(OPENVSCODE_AUTOPILOT_WORKBENCH_JS_PATCH_MARKER),
            "native patch marker should make managed workbench overlays auditable"
        );

        let _ = fs::remove_dir_all(install_root);
    }

    #[test]
    fn openvscode_native_workbench_js_patch_ownership_requires_upstream_chat_noop() {
        let binary_path = temp_openvscode_binary("native-chat-patch-owned");
        let install_root = binary_path
            .parent()
            .and_then(Path::parent)
            .expect("test binary should have install root")
            .to_path_buf();

        assert!(
            !openvscode_native_workbench_js_patch_owned(&binary_path),
            "unpatched OpenVSCode bundles must not be reused because upstream Chat can paint before IOI Chat"
        );

        ensure_openvscode_native_workbench_js_patch(&binary_path)
            .expect("OpenVSCode native contribution patch should be applied");

        assert!(
            openvscode_native_workbench_js_patch_owned(&binary_path),
            "managed OpenVSCode bundles are reusable only after upstream Chat registration is replaced"
        );

        let _ = fs::remove_dir_all(install_root);
    }

    #[test]
    fn openvscode_native_patch_manifest_tracks_replacement_contract() {
        let binary_path = temp_openvscode_binary("native-patch-manifest");
        let install_root = binary_path
            .parent()
            .and_then(Path::parent)
            .expect("test binary should have install root")
            .to_path_buf();

        let manifest = openvscode_native_patch_manifest(&install_root);
        assert_eq!(
            manifest.get("schemaVersion"),
            Some(&Value::String(
                OPENVSCODE_AUTOPILOT_NATIVE_PATCH_SCHEMA_VERSION.to_string()
            ))
        );
        assert_eq!(
            manifest.get("patchId"),
            Some(&Value::String(
                OPENVSCODE_AUTOPILOT_NATIVE_PATCH_ID.to_string()
            ))
        );
        assert_eq!(
            manifest
                .pointer("/runtimeTruth/openvscodeOwnsRuntimeState")
                .and_then(Value::as_bool),
            Some(false),
            "OpenVSCode patch metadata must describe projection, not runtime ownership"
        );
        assert_eq!(
            manifest
                .pointer("/normalLaunchContract/upstreamChatContributionAllowed")
                .and_then(Value::as_bool),
            Some(false)
        );

        let steps = manifest
            .get("steps")
            .and_then(Value::as_array)
            .expect("patch manifest should include steps");
        let step_ids: Vec<&str> = steps
            .iter()
            .filter_map(|step| step.get("id").and_then(Value::as_str))
            .collect();
        assert!(step_ids.contains(&"disable-upstream-chat-contribution"));
        assert!(step_ids.contains(&"disable-upstream-command-center"));
        assert!(step_ids.contains(&"install-ioi-workbench-contribution"));
        assert!(step_ids.contains(&"bridge-workbench-context"));
        assert!(step_ids.contains(&"export-native-target-index"));
        assert!(step_ids.contains(&"workflow-code-generation-receipts"));

        let upstream_chat_step = steps
            .iter()
            .find(|step| {
                step.get("id").and_then(Value::as_str) == Some("disable-upstream-chat-contribution")
            })
            .expect("upstream chat replacement step should exist");
        assert_eq!(
            upstream_chat_step
                .get("temporaryCompatibility")
                .and_then(Value::as_bool),
            Some(false),
            "upstream Chat replacement should be profile/contribution-owned, not CSS-owned"
        );

        let manifest_text =
            serde_json::to_string(&manifest).expect("patch manifest should serialize");
        assert!(!manifest_text.contains("OpenAI"));
        assert!(!manifest_text.contains("Anthropic"));
        assert!(!manifest_text.contains("provider"));

        let _ = fs::remove_dir_all(install_root);
    }

    #[test]
    fn openvscode_native_patch_manifest_is_written_idempotently() {
        let binary_path = temp_openvscode_binary("native-patch-manifest-write");
        let install_root = binary_path
            .parent()
            .and_then(Path::parent)
            .expect("test binary should have install root")
            .to_path_buf();
        let manifest_path = install_root
            .join(".ioi-autopilot")
            .join("managed-openvscode-patch.json");

        ensure_openvscode_native_patch_manifest(&binary_path)
            .expect("OpenVSCode native patch manifest should be written");
        let first = fs::read_to_string(&manifest_path)
            .expect("OpenVSCode native patch manifest should be readable");
        ensure_openvscode_native_patch_manifest(&binary_path)
            .expect("OpenVSCode native patch manifest should be idempotent");
        let second = fs::read_to_string(&manifest_path)
            .expect("OpenVSCode native patch manifest should still be readable");

        assert_eq!(first, second);
        assert!(first.contains(OPENVSCODE_AUTOPILOT_NATIVE_PATCH_SCHEMA_VERSION));
        assert!(first.contains("disable-upstream-chat-contribution"));
        assert!(first.contains("managed-workbench-js-contribution-noop-and-profile-feature-gate"));
        assert!(first.contains("workbench.panel.chat.view.copilot"));

        let _ = fs::remove_dir_all(install_root);
    }
}
