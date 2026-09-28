//! Host-side `git` over guest-writable workspaces (MASTER-GUIDE W0.4 / G14).
//!
//! The daemon runs `git` ON THE HOST, as the daemon's own user, inside workspaces that an agent
//! (the guest) can write. Plain `git -C <workspace> status` reads the guest's `.git/config`, and a
//! handful of keys there name programs git will execute: `core.fsmonitor`, hooks (and
//! `core.hooksPath`), `core.pager`, `diff.external`, diff drivers (`command`, `textconv`), filter
//! drivers (`clean`, `smudge`, `process`), gpg programs, credential helpers, `core.sshCommand` and
//! remote helpers on a lazy fetch. Any one of them is host code execution chosen by the guest.
//!
//! Every host git call against a workspace therefore goes through [`workspace_git`] (implemented
//! once, in `ioi_services::agentic::runtime::kernel::host_git`, so the daemon routes and the
//! kernel's coding-tool / repository-workflow reads share it), which never lets guest
//! configuration choose a program:
//!
//! * system and global config are not read (`GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`)
//!   and the environment is cleared, so nothing ambient leaks in either direction;
//! * every program-naming key the guest can set is pinned with a command-line `-c`, the
//!   highest-precedence config scope, so it beats `.git/config`, `config.worktree` and any
//!   `include.path` the guest points at;
//! * filter drivers are keyed by an arbitrary name, so the drivers the repository actually
//!   configures are enumerated first (`git config --list`, which executes nothing) and each one is
//!   pinned empty — an empty filter command is no filter;
//! * diff-family commands get `--no-ext-diff --no-textconv`, and `diff`/`status` never recurse into
//!   submodules (a submodule has its own guest-controlled config);
//! * every transport is refused (`GIT_ALLOW_PROTOCOL` names no real protocol), so a promisor
//!   remote's lazy fetch cannot run `remote.*.uploadpack` or a remote helper;
//! * the git dir and work tree are passed explicitly, so a guest-set `core.worktree` cannot aim
//!   `git add -A` at the host's home directory, and `safe.bareRepository=explicit` refuses a bare
//!   repository planted in the workspace.
//!
//! Operations that must reach a remote (the SCM publication port) never run in the workspace at
//! all: [`NeutralRepo`] is a daemon-owned bare repository that borrows the workspace's object
//! store through `objects/info/alternates`. Objects are content-addressed data; reading them runs
//! nothing, and the guest's config, hooks, `url.*.insteadOf` and remote definitions are never read.
//!
//! Residual (recorded, not closed here): the filter-driver enumeration and the command that
//! follows are two processes, so a guest process still running during that window could add a new
//! filter name between them. The post-run diff runs after the harness's PID namespace is gone; the
//! thread/environment read routes can race a live agent. Closing it fully means running git inside
//! the cell (W2).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) use ioi_services::agentic::runtime::kernel::host_git::{
    run_workspace_git, workspace_git,
};
#[cfg(test)]
use ioi_services::agentic::runtime::kernel::host_git::hardened_args;

/// Keys pinned on the remote-facing profile. Operator (system/global) config is honoured there —
/// credentials and ssh settings live in it — but no repository the guest wrote is ever read.
const REMOTE_PINNED_CONFIG: &[&str] = &[
    "core.fsmonitor=false",
    "core.hooksPath=/dev/null",
    "core.pager=cat",
    "safe.bareRepository=explicit",
    "submodule.recurse=false",
];

/// The protocols the remote-facing profile may use. `ext::` and remote helpers stay refused.
const REMOTE_PROTOCOLS: &str = "file:git:http:https:ssh";

/// Environment variables that could redirect a remote-profile git at another repository or
/// smuggle config in. The workspace profile clears the whole environment instead.
const REDIRECTING_ENV: &[&str] = &[
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_COMMON_DIR",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_NAMESPACE",
    "GIT_CONFIG",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_COUNT",
    "GIT_EXTERNAL_DIFF",
    "GIT_EXEC_PATH",
    "GIT_TEMPLATE_DIR",
    "GIT_PAGER",
    "GIT_EDITOR",
    "GIT_SEQUENCE_EDITOR",
    "GIT_ASKPASS",
    "SSH_ASKPASS",
];

/// A remote-profile git command run from `cwd` (never a guest workspace): operator system/global
/// config and environment are honoured (credentials, ssh agent, proxies), redirecting `GIT_*`
/// variables are dropped, hooks and fsmonitor are pinned off, and only real network/file
/// protocols are allowed (no `ext::`, no remote helpers).
pub(crate) fn remote_git(cwd: &Path) -> Command {
    let mut command = Command::new("git");
    command.current_dir(cwd);
    for key in REDIRECTING_ENV {
        command.env_remove(key);
    }
    if let Some(parent) = cwd.parent() {
        command.env("GIT_CEILING_DIRECTORIES", parent);
    }
    command
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ALLOW_PROTOCOL", REMOTE_PROTOCOLS)
        .env("GIT_PAGER", "cat")
        .arg("--no-pager");
    for pinned in REMOTE_PINNED_CONFIG {
        command.arg("-c").arg(pinned);
    }
    command
}

static NEUTRAL_REPO_SEQ: AtomicU64 = AtomicU64::new(1);

/// A daemon-owned, throwaway bare repository for remote operations. With `alternates`, it reads
/// objects from a workspace's object store without ever reading that workspace's config, hooks or
/// remotes. Removed on drop.
pub(crate) struct NeutralRepo {
    root: PathBuf,
    git_dir: PathBuf,
}

impl NeutralRepo {
    pub(crate) fn create(object_format: &str, alternates: Option<&Path>) -> Result<Self, String> {
        let root = std::env::temp_dir().join(format!(
            "ioi-host-git-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos())
                .unwrap_or(0),
            NEUTRAL_REPO_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).map_err(|error| format!("neutral repo root: {error}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700));
        }
        let repo = Self {
            git_dir: root.join("repo.git"),
            root,
        };
        let output = remote_git(&repo.root)
            .args(["init", "--bare", "-q", "--template="])
            .arg(format!("--object-format={object_format}"))
            .arg(&repo.git_dir)
            .output()
            .map_err(|error| format!("neutral repo init could not start: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "neutral repo init failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        if let Some(objects) = alternates {
            std::fs::write(
                repo.git_dir.join("objects").join("info").join("alternates"),
                format!("{}\n", objects.display()),
            )
            .map_err(|error| format!("neutral repo alternates: {error}"))?;
        }
        Ok(repo)
    }

    /// A remote-profile git command against this repository.
    pub(crate) fn git(&self) -> Command {
        let mut command = remote_git(&self.root);
        command.arg(format!("--git-dir={}", self.git_dir.display()));
        command
    }
}

impl Drop for NeutralRepo {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// The absolute object directory and object format of a workspace repository, read with the
/// hardened workspace profile.
pub(crate) fn workspace_object_store(workspace: &str) -> Result<(PathBuf, String), String> {
    let (ok, stdout, stderr) = run_workspace_git(
        workspace,
        &[
            "rev-parse",
            "--path-format=absolute",
            "--git-common-dir",
            "--show-object-format",
        ],
    );
    if !ok {
        return Err(format!("workspace object store: {}", stderr.trim()));
    }
    let mut lines = stdout.lines();
    let common = lines
        .next()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .ok_or_else(|| "workspace object store: no git common dir".to_string())?;
    let format = lines
        .next()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .unwrap_or("sha1");
    Ok((Path::new(common).join("objects"), format.to_string()))
}

/// A hardened remote clone into a fresh directory. Runs from a neutral directory (never inside a
/// repository), with hooks and fsmonitor pinned off and only real protocols allowed.
pub(crate) fn clone_depth1(remote_uri: &str, into: &str) -> bool {
    let Ok(neutral) = NeutralRepo::create("sha1", None) else {
        return false;
    };
    remote_git(&neutral.root)
        .args(["clone", "--depth", "1", "--", remote_uri, into])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// Fixture shared by the host-git exit tests here and in the route files that call host git.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// A repository whose `.git/config` and hooks try every host-execution vector git offers.
    /// Each vector's program touches its own sentinel under `sentinels`.
    pub(crate) struct HostileRepo {
        pub(crate) _root: tempfile::TempDir,
        pub(crate) workspace: PathBuf,
        pub(crate) sentinels: PathBuf,
        pub(crate) outside: PathBuf,
    }

    pub(crate) const VECTORS: &[&str] = &[
        "fsmonitor",
        "pager",
        "editor",
        "sshcommand",
        "askpass",
        "gitproxy",
        "clean",
        "smudge",
        "process",
        "textconv",
        "diffcommand",
        "external",
        "gpg",
        "credential",
        "uploadpack",
        "sequence-editor",
    ];

    pub(crate) const HOOKS: &[&str] = &[
        "pre-commit",
        "prepare-commit-msg",
        "commit-msg",
        "post-commit",
        "post-checkout",
        "post-index-change",
        "reference-transaction",
        "pre-auto-gc",
        "fsmonitor-watchman",
        "pre-push",
        "post-rewrite",
    ];

    fn plain_git(dir: &Path, args: &[&str]) {
        let status = Command::new("git")
            .current_dir(dir)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .args(["-c", "user.name=fixture", "-c", "user.email=fixture@local"])
            .args(args)
            .status()
            .expect("fixture git");
        assert!(status.success(), "fixture git {args:?} failed");
    }

    fn write_exec(path: &Path, body: &str) {
        std::fs::write(path, body).expect("write script");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
                .expect("chmod script");
        }
    }

    impl HostileRepo {
        pub(crate) fn plant() -> Self {
            let root = tempfile::tempdir().expect("tempdir");
            let base = root.path().to_path_buf();
            let workspace = base.join("workspace");
            let sentinels = base.join("sentinels");
            let scripts = base.join("scripts");
            let hooks = base.join("hooks");
            let outside = base.join("outside");
            for dir in [&workspace, &sentinels, &scripts, &hooks, &outside] {
                std::fs::create_dir_all(dir).expect("mkdir");
            }
            plain_git(&workspace, &["init", "-q"]);
            std::fs::write(workspace.join("tracked.txt"), "committed\n").expect("seed");
            plain_git(&workspace, &["add", "tracked.txt"]);
            plain_git(&workspace, &["commit", "-q", "-m", "seed"]);
            // Host secret outside the workspace: a guest-set core.worktree must not pull it in.
            std::fs::write(outside.join("host-secret.txt"), "host secret\n").expect("secret");

            let script = |vector: &str| -> String {
                let path = scripts.join(format!("{vector}.sh"));
                write_exec(
                    &path,
                    &format!(
                        "#!/bin/sh\ntouch '{}'\nexit 0\n",
                        sentinels.join(vector).display()
                    ),
                );
                path.display().to_string()
            };
            let mut paths = std::collections::BTreeMap::new();
            for vector in VECTORS {
                paths.insert(*vector, script(vector));
            }
            for hook in HOOKS {
                let body = format!(
                    "#!/bin/sh\ntouch '{}'\nexit 0\n",
                    sentinels.join(format!("hook-{hook}")).display()
                );
                write_exec(&hooks.join(hook), &body);
                write_exec(&workspace.join(".git").join("hooks").join(hook), &body);
            }
            let config = format!(
                "[core]\n\tfsmonitor = {fsmonitor}\n\tpager = {pager}\n\teditor = {editor}\n\
                 \tsshCommand = {sshcommand}\n\taskPass = {askpass}\n\tgitProxy = {gitproxy}\n\
                 \thooksPath = {hooks}\n\tworktree = {outside}\n\
                 [sequence]\n\teditor = {sequence_editor}\n\
                 [filter \"evil\"]\n\tclean = {clean}\n\tsmudge = {smudge}\n\trequired = true\n\
                 [filter \"evil.dotted\"]\n\tprocess = {process}\n\
                 [diff \"evil\"]\n\ttextconv = {textconv}\n\tcommand = {diffcommand}\n\
                 [diff]\n\texternal = {external}\n\
                 [commit]\n\tgpgSign = true\n[gpg]\n\tprogram = {gpg}\n\
                 [credential]\n\thelper = !{credential}\n\
                 [remote \"origin\"]\n\turl = file://{outside}/no-such-remote\n\tuploadpack = {uploadpack}\n\
                 \tpromisor = true\n\tpartialclonefilter = blob:none\n\
                 [pager]\n\tstatus = {pager}\n\tdiff = {pager}\n",
                fsmonitor = paths["fsmonitor"],
                pager = paths["pager"],
                editor = paths["editor"],
                sshcommand = paths["sshcommand"],
                askpass = paths["askpass"],
                gitproxy = paths["gitproxy"],
                hooks = hooks.display(),
                outside = outside.display(),
                sequence_editor = paths["sequence-editor"],
                clean = paths["clean"],
                smudge = paths["smudge"],
                process = paths["process"],
                textconv = paths["textconv"],
                diffcommand = paths["diffcommand"],
                external = paths["external"],
                gpg = paths["gpg"],
                credential = paths["credential"],
                uploadpack = paths["uploadpack"],
            );
            let config_path = workspace.join(".git").join("config");
            let mut existing = std::fs::read_to_string(&config_path).expect("read config");
            existing.push_str(&config);
            std::fs::write(&config_path, existing).expect("plant config");
            let attributes = "* filter=evil diff=evil\n*.md filter=evil.dotted\n";
            std::fs::write(workspace.join(".gitattributes"), attributes).expect("attrs");
            std::fs::create_dir_all(workspace.join(".git").join("info")).expect("info");
            std::fs::write(
                workspace.join(".git").join("info").join("attributes"),
                attributes,
            )
            .expect("info attrs");
            // Guest edits after the seed commit, so status/diff have work to do.
            std::fs::write(workspace.join("tracked.txt"), "committed\nguest edit\n")
                .expect("edit");
            std::fs::write(workspace.join("notes.md"), "guest note\n").expect("md");
            Self {
                _root: root,
                workspace,
                sentinels,
                outside,
            }
        }

        pub(crate) fn fired(&self) -> Vec<String> {
            let mut fired: Vec<String> = std::fs::read_dir(&self.sentinels)
                .map(|entries| {
                    entries
                        .flatten()
                        .map(|entry| entry.file_name().to_string_lossy().into_owned())
                        .collect()
                })
                .unwrap_or_default();
            fired.sort();
            fired
        }

        pub(crate) fn clear(&self) {
            for entry in std::fs::read_dir(&self.sentinels).expect("sentinels").flatten() {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }

    pub(crate) fn plain_git_for_tests(dir: &Path, args: &[&str]) {
        plain_git(dir, args)
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    #[test]
    fn host_git_control_proves_the_planted_config_is_live() {
        // Without hardening the planted repository DOES execute on the host — the premise the
        // hardened tests below rely on, so they cannot pass vacuously.
        let repo = HostileRepo::plant();
        let _ = Command::new("git")
            .current_dir(&repo.workspace)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .args(["status", "--porcelain"])
            .output();
        let fired = repo.fired();
        assert!(
            fired.iter().any(|vector| vector == "fsmonitor"),
            "unhardened git status should run the planted fsmonitor; fired={fired:?}"
        );
    }

    #[test]
    fn host_git_hardened_workspace_operations_execute_nothing_planted() {
        let repo = HostileRepo::plant();
        repo.clear();
        let ws = repo.workspace.to_str().expect("utf8 path");
        let identity = ["-c", "user.email=daemon@local", "-c", "user.name=daemon"];
        let worktree = repo.outside.join("wt").display().to_string();
        let mut runs: Vec<(Vec<String>, bool)> = Vec::new();
        let mut run = |args: Vec<&str>| {
            let (ok, _stdout, stderr) = run_workspace_git(ws, &args);
            assert!(
                !stderr.contains("host git refused"),
                "hardened git refused {args:?}: {stderr}"
            );
            runs.push((args.iter().map(|arg| arg.to_string()).collect(), ok));
        };
        run(vec!["rev-parse", "--is-inside-work-tree"]);
        run(vec!["rev-parse", "--show-toplevel"]);
        run(vec!["status", "--porcelain"]);
        run(vec!["-c", "core.quotePath=false", "status", "--porcelain=v1", "-z"]);
        run(vec!["status", "--porcelain", "-uall"]);
        run(vec!["diff", "--numstat", "HEAD"]);
        run(vec!["diff", "HEAD"]);
        run(vec!["diff", "--binary"]);
        run(vec!["diff", "--stat"]);
        run(vec!["diff", "--name-status", "HEAD"]);
        run(vec!["diff", "--no-index", "--", "/dev/null", "notes.md"]);
        run(vec!["show", "HEAD:tracked.txt"]);
        run(vec!["branch", "--show-current"]);
        let mut add = identity.to_vec();
        add.extend(["add", "-A"]);
        run(add);
        run(vec!["diff", "--cached", "--", "tracked.txt"]);
        let mut commit = identity.to_vec();
        commit.extend(["commit", "-q", "-m", "daemon commit"]);
        run(commit);
        run(vec!["worktree", "add", "-q", "-b", "daemon-wt", &worktree, "HEAD"]);
        let fired = repo.fired();
        assert!(
            fired.is_empty(),
            "planted config/hooks executed on the host through hardened git: {fired:?}"
        );
        // The operations themselves still worked (hardening is not a silent no-op).
        for (args, ok) in &runs {
            if args.first().map(String::as_str) == Some("diff")
                && args.iter().any(|arg| arg == "--no-index")
            {
                continue; // exits 1 when there is a difference
            }
            assert!(*ok, "hardened git {args:?} failed");
        }
        // The guest's core.worktree did not redirect `add -A` at the host directory.
        let (ok, tree, _) = run_workspace_git(ws, &["ls-tree", "-r", "--name-only", "HEAD"]);
        assert!(ok);
        assert!(tree.contains("tracked.txt") && tree.contains("notes.md"), "{tree}");
        assert!(!tree.contains("host-secret.txt"), "core.worktree leaked: {tree}");
    }

    #[test]
    fn host_git_kernel_coding_tool_and_repository_workflow_reads_execute_nothing_planted() {
        use ioi_services::agentic::runtime::kernel::coding_tool_execution::run_git_read_only;
        use ioi_services::agentic::runtime::kernel::repository_workflow::{
            RepositoryWorkflowProjectionCore, RepositoryWorkflowProjectionRequest,
        };
        let repo = HostileRepo::plant();
        repo.clear();
        let status = run_git_read_only(
            &repo.workspace,
            &["status".to_string(), "--porcelain".to_string()],
        )
        .expect("coding-tool git status");
        assert!(status.ok && status.stdout.contains("tracked.txt"), "{}", status.stderr);
        let diff = run_git_read_only(
            &repo.workspace,
            &["diff".to_string(), "--stat".to_string(), "HEAD".to_string()],
        )
        .expect("coding-tool git diff");
        assert!(diff.ok, "{}", diff.stderr);
        let request: RepositoryWorkflowProjectionRequest = serde_json::from_value(serde_json::json!({
            "projection_kind": "repository_context",
            "workspace_root": repo.workspace.to_string_lossy(),
        }))
        .expect("request");
        let record = RepositoryWorkflowProjectionCore
            .project(request)
            .expect("repository workflow projection");
        assert_eq!(
            record.repository_context.get("isGitRepository"),
            Some(&serde_json::Value::Bool(true)),
            "{}",
            record.repository_context
        );
        let fired = repo.fired();
        assert!(fired.is_empty(), "kernel git reads executed planted config: {fired:?}");
    }

    #[test]
    fn host_git_refuses_an_unneutralizable_filter_name() {
        let repo = HostileRepo::plant();
        let config_path = repo.workspace.join(".git").join("config");
        let mut config = std::fs::read_to_string(&config_path).expect("config");
        config.push_str("[filter \"a=b\"]\n\tclean = /bin/false\n");
        std::fs::write(&config_path, config).expect("write");
        let refused = workspace_git(&repo.workspace, &["status", "--porcelain"]);
        assert!(refused.is_err(), "a filter name with '=' must refuse git");
    }

    #[test]
    fn host_git_neutral_repo_pushes_workspace_objects_without_reading_its_config() {
        let repo = HostileRepo::plant();
        let ws = repo.workspace.to_str().expect("utf8").to_string();
        let remote = repo.outside.join("remote.git");
        plain_git_for_tests(&repo.outside, &["init", "-q", "--bare", "remote.git"]);
        // A guest url rewrite aimed at a repository it controls (with hooks) must not be honoured.
        let config_path = repo.workspace.join(".git").join("config");
        let mut config = std::fs::read_to_string(&config_path).expect("config");
        config.push_str(&format!(
            "[url \"{}\"]\n\tpushInsteadOf = {}\n",
            repo.outside.join("hijack.git").display(),
            remote.display()
        ));
        std::fs::write(&config_path, config).expect("write");
        repo.clear();
        let (ok, head, _) = run_workspace_git(&ws, &["rev-parse", "HEAD"]);
        assert!(ok);
        let head = head.trim().to_string();
        let (objects, format) = workspace_object_store(&ws).expect("object store");
        let neutral = NeutralRepo::create(&format, Some(&objects)).expect("neutral repo");
        let output = neutral
            .git()
            .args(["push", remote.to_str().unwrap(), &format!("{head}:refs/heads/published")])
            .output()
            .expect("push");
        assert!(
            output.status.success(),
            "neutral push failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let listed = remote_git(&repo.outside)
            .args(["ls-remote", remote.to_str().unwrap(), "refs/heads/published"])
            .output()
            .expect("ls-remote");
        assert!(String::from_utf8_lossy(&listed.stdout).starts_with(&head));
        assert!(!repo.outside.join("hijack.git").exists());
        assert!(repo.fired().is_empty(), "fired: {:?}", repo.fired());
    }

    #[test]
    fn host_git_subcommand_hardening_lands_after_the_subcommand() {
        assert_eq!(
            hardened_args(&["-c", "core.quotePath=false", "status", "-z"]),
            vec!["-c", "core.quotePath=false", "status", "--ignore-submodules=all", "-z"]
        );
        assert_eq!(
            hardened_args(&["show", "HEAD:a"]),
            vec!["show", "--no-ext-diff", "--no-textconv", "HEAD:a"]
        );
        assert_eq!(hardened_args(&["rev-parse", "HEAD"]), vec!["rev-parse", "HEAD"]);
    }
}
