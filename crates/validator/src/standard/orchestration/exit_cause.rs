// Path: crates/validator/src/standard/orchestration/exit_cause.rs
//! Exit-cause records for the orchestration process (P7, build Ruling 12's second amendment:
//! "three majority orchestrators exited SILENTLY within 1.2 s of each other (no panic, no OOM, no
//! harness kill) … P7 adds exit-cause logging and investigates").
//!
//! Every exit path the process controls appends one JSON line to
//! `<config dir>/orchestration-exit.jsonl` (fsync'd) and writes `ORCHESTRATION_EXIT: <cause>` to
//! stderr WITHOUT panicking if stderr is gone: a clean return, an error return, a handled signal
//! (SIGINT, SIGTERM, SIGHUP, SIGQUIT) and a panic. A silent exit therefore narrows to what no
//! handler can record: SIGKILL (the kernel OOM killer or a harness kill) or an abort.
//!
//! **Investigation notes** (the trunk's orchestration binary): SIGTERM, SIGHUP and SIGQUIT were
//! not handled (only Ctrl-C was), so a parent's TERM or a closing session's HUP ended the process
//! with no line at all; and the panic hook printed with `eprintln!`, which itself panics when
//! stderr's pipe is closed (a dead log collector), turning a panic into an abort with no output.
//! Both are now recorded (`record_exit_cause` never panics on a dead stderr).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// The file, under the orchestrator's config directory, that collects exit-cause lines.
pub const EXIT_CAUSE_FILE: &str = "orchestration-exit.jsonl";

static EXIT_CAUSE_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Sets the directory exit causes are recorded in (once; later calls are ignored).
pub fn set_exit_cause_dir(dir: &Path) {
    let _ = EXIT_CAUSE_DIR.set(dir.to_path_buf());
}

/// Records one exit cause: a JSON line in the exit-cause file (if its directory is set) and a
/// stderr line. Never panics, even when stderr or the directory is unavailable.
pub fn record_exit_cause(cause: &str) {
    if let Some(dir) = EXIT_CAUSE_DIR.get() {
        let _ = append_exit_cause(dir, cause);
    }
    let _ = writeln!(std::io::stderr(), "ORCHESTRATION_EXIT: {cause}");
}

/// Appends `cause` to `dir/EXIT_CAUSE_FILE` as `{"at_ms", "pid", "cause"}` and syncs it.
pub fn append_exit_cause(dir: &Path, cause: &str) -> std::io::Result<()> {
    let at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0);
    let line = serde_json::json!({
        "at_ms": at_ms,
        "pid": std::process::id(),
        "cause": cause,
    })
    .to_string();
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join(EXIT_CAUSE_FILE))?;
    file.write_all(line.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_exit_cause_is_one_parseable_line_appended() {
        let dir = tempfile::tempdir().unwrap();
        append_exit_cause(dir.path(), "signal: SIGTERM").unwrap();
        append_exit_cause(dir.path(), "error: config \"x\" invalid").unwrap();
        let text = std::fs::read_to_string(dir.path().join(EXIT_CAUSE_FILE)).unwrap();
        let lines: Vec<serde_json::Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["cause"], "signal: SIGTERM");
        assert_eq!(lines[1]["cause"], "error: config \"x\" invalid");
        assert_eq!(lines[1]["pid"], std::process::id());
    }

    #[test]
    fn record_exit_cause_writes_the_durable_line_once_the_directory_is_set() {
        // The only test that sets the process-wide directory.
        let dir = tempfile::tempdir().unwrap();
        set_exit_cause_dir(dir.path());
        record_exit_cause("test: durable write");
        let text = std::fs::read_to_string(dir.path().join(EXIT_CAUSE_FILE)).unwrap();
        let line: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(line["cause"], "test: durable write");
    }

    #[test]
    fn an_unwritable_directory_is_an_error_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("absent");
        assert!(append_exit_cause(&missing, "x").is_err());
    }
}
