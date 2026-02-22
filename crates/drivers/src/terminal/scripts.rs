use anyhow::Result;
use std::env;
use std::path::Path;

#[cfg(unix)]
pub(crate) fn resolve_shell_path() -> String {
    env::var("SHELL")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .filter(|value| Path::new(value).is_file())
        .unwrap_or_else(|| "/bin/sh".to_string())
}

#[cfg(unix)]
pub(crate) fn build_shell_command_line(command: &str, args: &[String]) -> String {
    if args.is_empty() {
        return command.to_string();
    }
    let mut out = String::from(command);
    for arg in args {
        out.push(' ');
        out.push_str(&quote_sh_argument(arg));
    }
    out
}

#[cfg(windows)]
pub(crate) fn resolve_comspec_path() -> String {
    env::var("COMSPEC")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .filter(|value| Path::new(value).is_file())
        .unwrap_or_else(|| "cmd.exe".to_string())
}

#[cfg(windows)]
pub(crate) fn build_cmd_command_line(command: &str, args: &[String]) -> String {
    if args.is_empty() {
        // Allow compound commands ("echo hi", "dir && echo ok") to behave like unix session mode.
        // The caller can include quotes in `command` when needed (for paths with spaces).
        return command.to_string();
    }
    let mut out = String::from(command);
    for arg in args {
        out.push(' ');
        out.push_str(&quote_cmd_argument(arg));
    }
    out
}

#[cfg(windows)]
pub(crate) fn quote_cmd_argument(arg: &str) -> String {
    if arg.is_empty() {
        return "\"\"".to_string();
    }

    let mut s = arg.to_string();

    let safe = s.chars().all(|ch| {
        ch.is_ascii_alphanumeric()
            || matches!(ch, '_' | '-' | '.' | '\\' | '/' | ':' | '@' | '+' | '=')
    });
    if safe {
        return s;
    }

    // Minimal quoting: wrap in double quotes and escape embedded quotes for cmd parsing.
    s = s.replace('"', "\"\"");
    format!("\"{}\"", s)
}

#[cfg(windows)]
pub(crate) fn build_session_script_windows(
    cwd: Option<&Path>,
    cmd_line: &str,
    stdin_path: Option<&Path>,
    rc_prefix: &str,
    done_marker: &str,
    end_label: &str,
) -> String {
    let mut script = String::new();
    script.push_str("set ioi_rc=0\r\n");

    if let Some(dir) = cwd {
        let dir_str = dir.to_string_lossy().to_string();
        script.push_str(&format!("cd /d {}\r\n", quote_cmd_argument(&dir_str)));
        script.push_str("if errorlevel 1 (\r\n");
        script.push_str(&format!(
            "  echo ioi: failed to cd to {}\r\n",
            quote_cmd_argument(&dir_str)
        ));
        script.push_str("  set ioi_rc=%errorlevel%\r\n");
        script.push_str(&format!("  goto {}\r\n", end_label));
        script.push_str(")\r\n");
    }

    if let Some(path) = stdin_path {
        let path_str = path.to_string_lossy().to_string();
        script.push_str(&format!(
            "{} < {} 2>&1\r\n",
            cmd_line,
            quote_cmd_argument(&path_str)
        ));
    } else {
        script.push_str(&format!("{} 2>&1\r\n", cmd_line));
    }
    script.push_str("set ioi_rc=%errorlevel%\r\n");

    script.push_str(&format!(":{}\r\n", end_label));
    script.push_str(&format!("echo {}%ioi_rc%\r\n", rc_prefix));
    script.push_str(&format!("echo {}\r\n", done_marker));
    script
}

#[cfg(unix)]
pub(crate) fn quote_sh_argument(arg: &str) -> String {
    if arg.is_empty() {
        return "''".to_string();
    }

    if arg.chars().all(|ch| {
        ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '/' | ':' | '@' | '+')
    }) {
        return arg.to_string();
    }

    format!("'{}'", arg.replace('\'', "'\"'\"'"))
}

#[cfg(unix)]
pub(crate) fn build_session_script(
    cwd: Option<&Path>,
    cmd_line: &str,
    stdin_data: Option<&[u8]>,
    rc_prefix: &str,
    done_marker: &str,
    marker_id: u64,
) -> Result<String> {
    let mut script = String::new();
    script.push_str("ioi_rc=0\n");

    if let Some(dir) = cwd {
        let dir_str = dir.to_string_lossy().to_string();
        script.push_str(&format!("if ! cd {}; then\n", quote_sh_argument(&dir_str)));
        script.push_str("  ioi_rc=$?\n");
        script.push_str("else\n");
    }

    if let Some(bytes) = stdin_data {
        let data = String::from_utf8_lossy(bytes).to_string();
        let delimiter = choose_heredoc_delimiter(marker_id, &data);
        script.push_str(&format!("  {cmd_line} <<'{delimiter}'\n"));
        script.push_str(&data);
        if !data.ends_with('\n') {
            script.push('\n');
        }
        script.push_str(&format!("{delimiter}\n"));
        script.push_str("  ioi_rc=$?\n");
    } else {
        script.push_str(&format!("  {cmd_line}\n"));
        script.push_str("  ioi_rc=$?\n");
    }

    if cwd.is_some() {
        script.push_str("fi\n");
    }

    script.push_str(&format!("echo \"{rc_prefix}$ioi_rc\"\n"));
    script.push_str(&format!("echo \"{done_marker}\"\n"));
    Ok(script)
}

#[cfg(unix)]
fn choose_heredoc_delimiter(marker_id: u64, data: &str) -> String {
    // Ensure the delimiter cannot occur in the payload to avoid premature heredoc termination.
    for attempt in 0..10u32 {
        let candidate = format!("__IOI_STDIN_{}_{}__", marker_id, attempt);
        if !data.contains(&candidate) {
            return candidate;
        }
    }
    "__IOI_STDIN_FALLBACK__".to_string()
}
