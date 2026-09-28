//! Hardened host-side `git` over guest-writable workspaces (MASTER-GUIDE W0.4 / G14).
//!
//! The Hypervisor daemon and this kernel run `git` ON THE HOST, as the daemon's user, inside
//! workspaces an agent (the guest) can write. Plain `git -C <workspace> status` reads the guest's
//! `.git/config`, and several keys there name programs git will execute: `core.fsmonitor`, hooks
//! (and `core.hooksPath`), `core.pager`, `diff.external`, diff drivers (`command`, `textconv`),
//! filter drivers (`clean`, `smudge`, `process`), gpg programs, credential helpers,
//! `core.sshCommand` and remote helpers on a lazy fetch. Each is host code execution the guest
//! chooses. [`workspace_git`] is the only way host code here should run git on a workspace:
//!
//! * system and global config are not read (`GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`)
//!   and the environment is cleared;
//! * every program-naming key is pinned with a command-line `-c` — the highest-precedence config
//!   scope, so it beats `.git/config`, `config.worktree` and any `include.path`;
//! * filter drivers are keyed by an arbitrary name, so the drivers the repository configures are
//!   enumerated first (`git config --list`, which executes nothing) and each is pinned empty — an
//!   empty filter command is no filter; a name `-c` cannot address exactly is refused;
//! * diff-family commands get `--no-ext-diff --no-textconv`; `diff`/`status` never recurse into
//!   submodules (each has its own guest-controlled config);
//! * every transport is refused (`GIT_ALLOW_PROTOCOL` names no real protocol), so a promisor
//!   remote's lazy fetch cannot run `remote.*.uploadpack` or a remote helper;
//! * the git dir and work tree are passed explicitly, so a guest `core.worktree` cannot aim
//!   `git add -A` at the host's home, and `safe.bareRepository=explicit` refuses a bare repository
//!   planted in the workspace.
//!
//! Remote operations never belong here: the daemon runs them from a neutral repository that only
//! borrows the workspace's object store (`hypervisor_daemon_routes/host_git.rs`).
//!
//! Residual (recorded): the filter enumeration and the command that follows are two processes, so
//! a guest process still running in that window could add a filter name between them. Closing it
//! fully means running git inside the cell (W2).

use std::path::{Path, PathBuf};
use std::process::Command;

/// Program-naming (or program-triggering) keys pinned on every workspace git call.
const PINNED_CONFIG: &[&str] = &[
    "core.fsmonitor=false",
    "core.hooksPath=/dev/null",
    "core.pager=cat",
    "core.editor=:",
    "sequence.editor=:",
    "core.askPass=",
    "core.sshCommand=false",
    "core.attributesFile=/dev/null",
    "credential.helper=",
    "commit.gpgSign=false",
    "tag.gpgSign=false",
    "tag.forceSignAnnotated=false",
    "push.gpgSign=false",
    "log.showSignature=false",
    "gpg.program=false",
    "gc.auto=0",
    "maintenance.auto=false",
    "submodule.recurse=false",
    "fetch.recurseSubmodules=false",
    "protocol.allow=never",
    "safe.bareRepository=explicit",
];

/// A protocol name no transport answers to: with `GIT_ALLOW_PROTOCOL` set, git allows ONLY the
/// listed protocols, so this refuses file, ssh, http(s), git, ext and every remote helper.
const NO_TRANSPORT: &str = "ioi-no-transport";

/// Where a workspace's repository lives, found the way git's own discovery finds it: the nearest
/// ancestor (inclusive) holding a `.git` directory, gitfile or symlink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoLayout {
    /// The `.git` entry itself (a directory, or a gitfile git resolves).
    pub git_dir: PathBuf,
    /// The directory containing it: the work tree, never a guest-chosen `core.worktree`.
    pub work_tree: PathBuf,
}

pub fn discover_repo(dir: &Path) -> Option<RepoLayout> {
    let start = std::fs::canonicalize(dir).ok()?;
    start.ancestors().find_map(|ancestor| {
        let dot_git = ancestor.join(".git");
        std::fs::symlink_metadata(&dot_git).ok().map(|_| RepoLayout {
            git_dir: dot_git,
            work_tree: ancestor.to_path_buf(),
        })
    })
}

/// The subcommand in a git argv: the first argument that is neither a global option nor the
/// value of `-c` / `-C`.
fn subcommand_index(args: &[&str]) -> Option<usize> {
    let mut index = 0;
    while index < args.len() {
        match args[index] {
            "-c" | "-C" => index += 2,
            arg if arg.starts_with('-') => index += 1,
            _ => return Some(index),
        }
    }
    None
}

/// Flags that keep a subcommand from reaching a guest-configured program.
fn subcommand_hardening(subcommand: &str) -> &'static [&'static str] {
    match subcommand {
        "diff" => &["--no-ext-diff", "--no-textconv", "--ignore-submodules=all"],
        "status" => &["--ignore-submodules=all"],
        "show" | "log" | "diff-tree" | "diff-index" | "diff-files" | "whatchanged" => {
            &["--no-ext-diff", "--no-textconv"]
        }
        _ => &[],
    }
}

/// The caller's argv with the subcommand's hardening flags inserted right after it.
pub fn hardened_args(args: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = args.iter().map(|arg| (*arg).to_string()).collect();
    if let Some(index) = subcommand_index(args) {
        let flags = subcommand_hardening(args[index]);
        for (offset, flag) in flags.iter().enumerate() {
            out.insert(index + 1 + offset, (*flag).to_string());
        }
    }
    out
}

/// The bare workspace-profile command: cleared environment, no system/global config, no pager,
/// no editor, no prompt, no transport, every program-naming key pinned. No repository selection.
fn base_workspace_command(cwd: &Path) -> Command {
    let mut command = Command::new("git");
    command.current_dir(cwd).env_clear();
    for key in ["PATH", "HOME", "LANG", "LC_ALL", "TZ"] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    command
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_PAGER", "cat")
        .env("PAGER", "cat")
        .env("GIT_EDITOR", ":")
        .env("GIT_SEQUENCE_EDITOR", ":")
        .env("GIT_ASKPASS", "")
        .env("GIT_ALLOW_PROTOCOL", NO_TRANSPORT)
        .env("GIT_PROTOCOL_FROM_USER", "0")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .arg("--no-pager");
    for pinned in PINNED_CONFIG {
        command.arg("-c").arg(pinned);
    }
    command
}

fn select_repo(command: &mut Command, layout: &RepoLayout) {
    command
        .arg(format!("--git-dir={}", layout.git_dir.display()))
        .arg(format!("--work-tree={}", layout.work_tree.display()));
}

/// The filter drivers the repository configures (all scopes git reads for it, includes followed).
/// `git config --list` reads config and executes nothing. A driver name git's `-c` parser could
/// not address exactly (it contains `=` or a newline) is refused: fail closed rather than run
/// with a filter left armed.
fn configured_filter_drivers(cwd: &Path, layout: &RepoLayout) -> Result<Vec<String>, String> {
    let mut command = base_workspace_command(cwd);
    select_repo(&mut command, layout);
    let output = command
        .args(["config", "--list", "--name-only", "-z"])
        .output()
        .map_err(|error| format!("host git config probe could not start: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "host git refused: the workspace git config could not be read ({})",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let mut drivers: Vec<String> = Vec::new();
    for name in String::from_utf8_lossy(&output.stdout).split(['\0', '\n']) {
        let Some(rest) = name.strip_prefix("filter.") else {
            continue;
        };
        let Some((driver, key)) = rest.rsplit_once('.') else {
            continue;
        };
        if !matches!(key, "clean" | "smudge" | "process" | "required") {
            continue;
        }
        if driver.contains('=') || driver.contains('\n') || driver.is_empty() {
            return Err(format!(
                "host git refused: filter driver name {driver:?} cannot be neutralized"
            ));
        }
        if !drivers.iter().any(|known| known == driver) {
            drivers.push(driver.to_string());
        }
    }
    Ok(drivers)
}

/// A hardened `git` command over a guest-writable workspace. `dir` is the directory git runs in
/// (the workspace root or a subdirectory of it); `args` is the git argv exactly as a caller would
/// write it after `git` (global `-c` options first are fine). The returned command is ready to
/// `.output()`; callers may add environment (e.g. `GIT_INDEX_FILE`) but must not change the
/// program or clear the environment.
///
/// `Err` means git must not run: the repository's config could not be read or names a filter
/// driver that cannot be neutralized. Callers treat it exactly like a failed git.
pub fn workspace_git(dir: impl AsRef<Path>, args: &[&str]) -> Result<Command, String> {
    let cwd = dir.as_ref();
    let subcommand = subcommand_index(args).map(|index| args[index]);
    let mut command = base_workspace_command(cwd);
    // `init` creates the repository in `cwd`; resolving an ancestor repository there would
    // re-initialize the wrong one. Everything else runs against an explicitly selected repo.
    if subcommand != Some("init") {
        if let Some(layout) = discover_repo(cwd) {
            for driver in configured_filter_drivers(cwd, &layout)? {
                for key in ["clean", "smudge", "process"] {
                    command.arg("-c").arg(format!("filter.{driver}.{key}="));
                }
                command.arg("-c").arg(format!("filter.{driver}.required=false"));
            }
            select_repo(&mut command, &layout);
        }
    }
    command.args(hardened_args(args));
    Ok(command)
}

/// Run a hardened workspace git and return `(success, stdout, stderr)`. Refusal and spawn failure
/// are both reported as an unsuccessful run whose stderr names the reason.
pub fn run_workspace_git(dir: impl AsRef<Path>, args: &[&str]) -> (bool, String, String) {
    let mut command = match workspace_git(dir, args) {
        Ok(command) => command,
        Err(reason) => return (false, String::new(), reason),
    };
    match command.output() {
        Ok(output) => (
            output.status.success(),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ),
        Err(error) => (false, String::new(), format!("git spawn: {error}")),
    }
}

