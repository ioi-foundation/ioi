use portable_pty::{native_pty_system, ChildKiller, CommandBuilder, MasterPty, PtySize};
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use tauri::State;

use super::paths::{now_ms, resolve_root_path};

const TERMINAL_MAX_CHUNKS: usize = 2400;

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceTerminalSession {
    pub session_id: String,
    pub shell: String,
    pub root_path: String,
    pub started_at_ms: u64,
    pub cols: u16,
    pub rows: u16,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceTerminalOutputChunk {
    pub sequence: u64,
    pub text: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceTerminalReadResult {
    pub session_id: String,
    pub cursor: u64,
    pub chunks: Vec<WorkspaceTerminalOutputChunk>,
    pub running: bool,
    pub exit_code: Option<i32>,
}

#[derive(Default)]
pub struct WorkspaceTerminalManager {
    sessions: Mutex<HashMap<String, Arc<WorkspaceTerminalHandle>>>,
}

#[derive(Clone)]
pub(crate) struct WorkspaceTerminalBridge {
    session: Arc<WorkspaceTerminalHandle>,
}

struct WorkspaceTerminalHandle {
    session: WorkspaceTerminalSession,
    writer: Mutex<Box<dyn Write + Send>>,
    master: Mutex<Box<dyn MasterPty + Send>>,
    killer: Mutex<Box<dyn ChildKiller + Send + Sync>>,
    output: Mutex<VecDeque<WorkspaceTerminalOutputChunk>>,
    next_sequence: AtomicU64,
    running: AtomicBool,
    exit_code: Mutex<Option<i32>>,
}

fn default_terminal_shell() -> String {
    #[cfg(windows)]
    {
        std::env::var("COMSPEC")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "powershell.exe".to_string())
    }

    #[cfg(not(windows))]
    {
        std::env::var("SHELL")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "/bin/bash".to_string())
    }
}

fn push_terminal_output(session: &Arc<WorkspaceTerminalHandle>, text: String) {
    if text.is_empty() {
        return;
    }

    let sequence = session.next_sequence.fetch_add(1, Ordering::Relaxed) + 1;
    let mut output = session
        .output
        .lock()
        .expect("terminal output lock poisoned");
    output.push_back(WorkspaceTerminalOutputChunk { sequence, text });
    while output.len() > TERMINAL_MAX_CHUNKS {
        output.pop_front();
    }
}

fn spawn_terminal_session(
    root: &PathBuf,
    cols: u16,
    rows: u16,
) -> Result<Arc<WorkspaceTerminalHandle>, String> {
    let pty_system = native_pty_system();
    let pty_size = PtySize {
        rows,
        cols,
        pixel_width: 0,
        pixel_height: 0,
    };
    let pair = pty_system
        .openpty(pty_size)
        .map_err(|error| format!("Failed to open PTY: {}", error))?;
    let shell = default_terminal_shell();
    let mut command = CommandBuilder::new(&shell);
    command.cwd(root);
    command.env("TERM", "xterm-256color");
    command.env("COLORTERM", "truecolor");
    command.env("TERM_PROGRAM", "Autopilot");

    let mut child = pair
        .slave
        .spawn_command(command)
        .map_err(|error| format!("Failed to spawn workspace shell: {}", error))?;
    drop(pair.slave);
    let killer = child.clone_killer();
    let mut reader = pair
        .master
        .try_clone_reader()
        .map_err(|error| format!("Failed to clone PTY reader: {}", error))?;
    let writer = pair
        .master
        .take_writer()
        .map_err(|error| format!("Failed to access PTY writer: {}", error))?;

    let session = Arc::new(WorkspaceTerminalHandle {
        session: WorkspaceTerminalSession {
            session_id: uuid::Uuid::new_v4().to_string(),
            shell,
            root_path: root.display().to_string(),
            started_at_ms: now_ms(),
            cols,
            rows,
        },
        writer: Mutex::new(writer),
        master: Mutex::new(pair.master),
        killer: Mutex::new(killer),
        output: Mutex::new(VecDeque::new()),
        next_sequence: AtomicU64::new(0),
        running: AtomicBool::new(true),
        exit_code: Mutex::new(None),
    });

    let read_session = Arc::clone(&session);
    thread::spawn(move || {
        let mut buffer = [0_u8; 4096];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => {
                    push_terminal_output(
                        &read_session,
                        String::from_utf8_lossy(&buffer[..count]).to_string(),
                    );
                }
                Err(error) => {
                    push_terminal_output(
                        &read_session,
                        format!("\r\n[autopilot] terminal read error: {}\r\n", error),
                    );
                    break;
                }
            }
        }
    });

    let wait_session = Arc::clone(&session);
    thread::spawn(move || match child.wait() {
        Ok(status) => {
            wait_session.running.store(false, Ordering::Relaxed);
            let code = i32::try_from(status.exit_code()).unwrap_or(1);
            let mut exit_code = wait_session
                .exit_code
                .lock()
                .expect("terminal exit lock poisoned");
            *exit_code = Some(code);
            drop(exit_code);
            push_terminal_output(
                &wait_session,
                format!("\r\n[autopilot] shell exited with code {}\r\n", code),
            );
        }
        Err(error) => {
            wait_session.running.store(false, Ordering::Relaxed);
            let mut exit_code = wait_session
                .exit_code
                .lock()
                .expect("terminal exit lock poisoned");
            *exit_code = Some(1);
            drop(exit_code);
            push_terminal_output(
                &wait_session,
                format!("\r\n[autopilot] shell wait failed: {}\r\n", error),
            );
        }
    });

    Ok(session)
}

fn terminal_read_result(
    session_id: String,
    session: &Arc<WorkspaceTerminalHandle>,
    cursor: u64,
) -> Result<WorkspaceTerminalReadResult, String> {
    let chunks = session
        .output
        .lock()
        .map_err(|_| "Failed to lock terminal output.".to_string())?
        .iter()
        .filter(|chunk| chunk.sequence > cursor)
        .cloned()
        .collect::<Vec<_>>();
    let next_cursor = chunks.last().map(|chunk| chunk.sequence).unwrap_or(cursor);
    let exit_code = *session
        .exit_code
        .lock()
        .map_err(|_| "Failed to lock terminal exit state.".to_string())?;

    Ok(WorkspaceTerminalReadResult {
        session_id,
        cursor: next_cursor,
        chunks,
        running: session.running.load(Ordering::Relaxed),
        exit_code,
    })
}

fn terminal_write_bytes(session: &Arc<WorkspaceTerminalHandle>, data: &[u8]) -> Result<(), String> {
    let mut writer = session
        .writer
        .lock()
        .map_err(|_| "Failed to lock terminal writer.".to_string())?;
    writer
        .write_all(data)
        .map_err(|error| format!("Failed to write to terminal: {}", error))?;
    writer
        .flush()
        .map_err(|error| format!("Failed to flush terminal input: {}", error))?;
    Ok(())
}

fn terminal_write_input(session: &Arc<WorkspaceTerminalHandle>, data: &str) -> Result<(), String> {
    terminal_write_bytes(session, data.as_bytes())
}

fn terminal_resize(
    session: &Arc<WorkspaceTerminalHandle>,
    cols: u16,
    rows: u16,
) -> Result<(), String> {
    session
        .master
        .lock()
        .map_err(|_| "Failed to lock terminal PTY.".to_string())?
        .resize(PtySize {
            rows: rows.max(12),
            cols: cols.max(40),
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|error| format!("Failed to resize terminal: {}", error))?;
    Ok(())
}

fn terminal_close(session: Arc<WorkspaceTerminalHandle>) -> Result<(), String> {
    session.running.store(false, Ordering::Relaxed);
    let kill_result = session
        .killer
        .lock()
        .map_err(|_| "Failed to lock terminal killer.".to_string())?
        .kill();
    if let Err(error) = kill_result {
        push_terminal_output(
            &session,
            format!(
                "\r\n[autopilot] failed to close shell cleanly: {}\r\n",
                error
            ),
        );
    }
    Ok(())
}

impl WorkspaceTerminalBridge {
    pub(crate) fn open(root: &str, cols: u16, rows: u16) -> Result<Self, String> {
        let root_path = resolve_root_path(root)?;
        let session = spawn_terminal_session(&root_path, cols.max(40), rows.max(12))?;
        Ok(Self { session })
    }

    pub(crate) fn session(&self) -> WorkspaceTerminalSession {
        self.session.session.clone()
    }

    pub(crate) fn read(&self, cursor: u64) -> Result<WorkspaceTerminalReadResult, String> {
        terminal_read_result(
            self.session.session.session_id.clone(),
            &self.session,
            cursor,
        )
    }

    pub(crate) fn write(&self, data: &str) -> Result<(), String> {
        terminal_write_input(&self.session, data)
    }

    pub(crate) fn write_bytes(&self, data: &[u8]) -> Result<(), String> {
        terminal_write_bytes(&self.session, data)
    }

    pub(crate) fn close(&self) -> Result<(), String> {
        terminal_close(Arc::clone(&self.session))
    }
}

pub fn workspace_terminal_create(
    root: String,
    cols: u16,
    rows: u16,
    manager: State<'_, WorkspaceTerminalManager>,
) -> Result<WorkspaceTerminalSession, String> {
    let bridge = WorkspaceTerminalBridge::open(&root, cols, rows)?;
    let descriptor = bridge.session();
    let mut sessions = manager
        .sessions
        .lock()
        .map_err(|_| "Failed to lock terminal session registry.".to_string())?;
    sessions.insert(descriptor.session_id.clone(), bridge.session);
    Ok(descriptor)
}

pub fn workspace_terminal_read(
    session_id: String,
    cursor: u64,
    manager: State<'_, WorkspaceTerminalManager>,
) -> Result<WorkspaceTerminalReadResult, String> {
    let sessions = manager
        .sessions
        .lock()
        .map_err(|_| "Failed to lock terminal session registry.".to_string())?;
    let Some(session) = sessions.get(&session_id).cloned() else {
        return Err("Terminal session not found.".to_string());
    };
    drop(sessions);

    terminal_read_result(session_id, &session, cursor)
}

pub fn workspace_terminal_write(
    session_id: String,
    data: String,
    manager: State<'_, WorkspaceTerminalManager>,
) -> Result<(), String> {
    let sessions = manager
        .sessions
        .lock()
        .map_err(|_| "Failed to lock terminal session registry.".to_string())?;
    let Some(session) = sessions.get(&session_id).cloned() else {
        return Err("Terminal session not found.".to_string());
    };
    drop(sessions);

    terminal_write_input(&session, &data)
}

pub fn workspace_terminal_resize(
    session_id: String,
    cols: u16,
    rows: u16,
    manager: State<'_, WorkspaceTerminalManager>,
) -> Result<(), String> {
    let sessions = manager
        .sessions
        .lock()
        .map_err(|_| "Failed to lock terminal session registry.".to_string())?;
    let Some(session) = sessions.get(&session_id).cloned() else {
        return Err("Terminal session not found.".to_string());
    };
    drop(sessions);

    terminal_resize(&session, cols, rows)
}

pub fn workspace_terminal_close(
    session_id: String,
    manager: State<'_, WorkspaceTerminalManager>,
) -> Result<(), String> {
    let session = {
        let mut sessions = manager
            .sessions
            .lock()
            .map_err(|_| "Failed to lock terminal session registry.".to_string())?;
        sessions.remove(&session_id)
    };

    let Some(session) = session else {
        return Ok(());
    };

    terminal_close(session)
}
