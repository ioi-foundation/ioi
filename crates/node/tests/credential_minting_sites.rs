//! BUILD-DELTA #36: THE CREDENTIAL-MINTING INVENTORY IS THE COMPILER'S.
//!
//! The syn walker that lived here re-implemented rustc's module, `#[path]`, `include!` and `cfg`
//! resolution in a test, and five review rounds each found another corner it got wrong. It is
//! RETIRED (the Hypervisor Director's ruling "Batch-3 Codex r5 = FAIL, 3 MAJOR + 1 MINOR" (3): no
//! second, weaker gate is kept beside the first). The inventory is crates/node/mint-gate:
//! - LAYER 1, in CI (`cargo run --locked -p ioi-node-mint-gate`): clippy's RESOLVED inventory of
//!   every randomness draw in the production code, for every pinned configuration, compared both
//!   ways with draw-sites.tsv, with the credential mints' regions pinned (mints.tsv) and the canary
//!   counted in every invocation;
//! - LAYER 2, required pre-merge (`crates/node/mint-gate/expanded-scan.sh`): the registered
//!   credential prefixes and the randomness primitives in the EXPANDED production source, compared
//!   both ways with expanded-sites.tsv. Its caller passes EXP_TOOLCHAIN (the pinned 1.93.1
//!   toolchain's directory) and CARGO_HOME, both resolved before HOME is replaced; there is no
//!   fallback to any host's path.
//!
//! This file pins only that the inventory cannot silently stop running: CI runs layer 1, the
//! workspace builds the gate and its canary, the gate's pinned inputs and registries exist, and
//! layer 2 takes its toolchain and cargo home from its caller alone: a missing argument and an
//! unset, empty or invalid input are each refused by name (exit 3), and its preflight's OK line
//! names exactly what it checked.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(relative: &str) -> String {
    std::fs::read_to_string(repo().join(relative))
        .unwrap_or_else(|error| panic!("{relative} does not read: {error}"))
}

/// CI runs layer 1 as its own step, beside the security regression tests.
#[test]
fn ci_runs_the_compiler_resolved_minting_inventory() {
    let ci = read(".github/workflows/ci.yml");
    let runs: Vec<&str> = ci
        .lines()
        .filter_map(|line| line.trim().strip_prefix("run: "))
        .filter(|command| command.contains("ioi-node-mint-gate"))
        .collect();
    assert_eq!(
        runs,
        ["cargo run --locked -p ioi-node-mint-gate"],
        "exactly one CI step runs the minting inventory, plainly"
    );
}

/// The workspace builds the gate and its canary, and the gate's pinned inputs and registries exist.
#[test]
fn the_minting_gate_and_its_registries_are_in_the_tree() {
    let workspace = read("Cargo.toml");
    for member in [
        "\"crates/node/mint-gate\"",
        "\"crates/node/mint-gate/canary\"",
    ] {
        assert!(workspace.contains(member), "the workspace lists {member}");
    }
    for file in [
        "clippy.toml",
        "deps.pin",
        "DEPENDENCY-REVIEW.md",
        "draw-sites.tsv",
        "hand-outs.tsv",
        "mints.tsv",
        "prefixes.tsv",
        "expanded-sites.tsv",
        "expanded-scan.sh",
        "expand-wrapper.sh",
        "src/main.rs",
        "canary/src/lib.rs",
        "canary/src/bin/mint-gate-canary.rs",
    ] {
        let path = repo().join("crates/node/mint-gate").join(file);
        assert!(path.is_file(), "{} exists", path.display());
    }
}

const SCAN: &str = "crates/node/mint-gate/expanded-scan.sh";

/// The pinned toolchain's directory, as the caller resolves it BEFORE it replaces HOME: from this
/// test's own environment, by the toolchain rustup selects for the repo (rust-toolchain.toml).
fn caller_toolchain() -> String {
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    let out = Command::new(&rustc)
        .args(["--print", "sysroot"])
        .current_dir(repo())
        .output()
        .unwrap_or_else(|error| panic!("{rustc} --print sysroot: {error}"));
    assert!(out.status.success(), "{rustc} --print sysroot failed");
    String::from_utf8(out.stdout)
        .expect("a UTF-8 sysroot")
        .trim()
        .to_string()
}

/// The cargo home, as the caller resolves it BEFORE it replaces HOME: this test's own CARGO_HOME
/// (rustup sets it for cargo and its children), else its own HOME's `.cargo`.
fn caller_cargo_home() -> String {
    std::env::var("CARGO_HOME").unwrap_or_else(|_| {
        let home = std::env::var("HOME").expect("the caller has a HOME");
        format!("{home}/.cargo")
    })
}

/// Runs layer 2 with exactly `args` under a cleared environment: PATH, the given HOME and exactly
/// `vars`.
fn scan(home: &Path, args: &[&str], vars: &[(&str, &str)]) -> (Option<i32>, String) {
    let Output { status, stdout, .. } = Command::new("bash")
        .arg(repo().join(SCAN))
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", home)
        .envs(vars.iter().copied())
        .output()
        .expect("bash runs the scan");
    (status.code(), String::from_utf8_lossy(&stdout).into_owned())
}

/// Runs layer 2's `--preflight` (its input, argument, network, wrapper and workspace checks; it
/// builds nothing) on this repo, as `scan` does.
fn preflight(home: &Path, vars: &[(&str, &str)]) -> (Option<i32>, String) {
    let root = repo();
    scan(
        home,
        &["--preflight", root.to_str().expect("a UTF-8 repo path")],
        vars,
    )
}

/// Asserts a refusal BY NAME: exit 3 and the first line naming it.
fn refused(case: &str, (code, stdout): (Option<i32>, String), first_line: &str) {
    assert_eq!(code, Some(3), "{case}: {stdout}");
    assert!(
        stdout.starts_with(&format!("EXPANDED-SCAN CANNOT RUN: {first_line}")),
        "{case} is refused by name (\"{first_line}\") first: {stdout}"
    );
}

/// No host's path is a fallback (the Hypervisor Director's ruling "BATCH 3 SHIPS THIS HOST'S HOME
/// PATH"): the scan names no home directory and never consults rustup's home or a default for its
/// two inputs; each one unset is refused BY NAME, before anything else runs.
#[test]
fn layer_two_refuses_an_unset_toolchain_or_cargo_home_by_name() {
    let text = read(SCAN);
    for (index, line) in text.lines().enumerate() {
        let n = index + 1;
        for home_dir in ["/home/", "/Users/", "/root/"] {
            assert!(
                !line.contains(home_dir),
                "{SCAN}:{n} names a home directory: {line}"
            );
        }
        if line.trim_start().starts_with('#') {
            continue;
        }
        assert!(
            !line.contains("RUSTUP_HOME"),
            "{SCAN}:{n} consults rustup's home instead of EXP_TOOLCHAIN: {line}"
        );
        for input in ["EXP_TOOLCHAIN", "CARGO_HOME"] {
            let defaulted = line
                .match_indices(&format!("${{{input}:-"))
                .any(|(at, _)| !line[at..].starts_with(&format!("${{{input}:-}}")));
            assert!(!defaulted, "{SCAN}:{n} gives {input} a fallback: {line}");
        }
    }
    let home = tempfile::tempdir().expect("a fresh HOME");
    let toolchain = caller_toolchain();
    let cargo_home = caller_cargo_home();
    let cases: [(&str, Vec<(&str, &str)>); 5] = [
        ("EXP_TOOLCHAIN", vec![]),
        ("EXP_TOOLCHAIN", vec![("CARGO_HOME", cargo_home.as_str())]),
        ("CARGO_HOME", vec![("EXP_TOOLCHAIN", toolchain.as_str())]),
        (
            "EXP_TOOLCHAIN",
            vec![("EXP_TOOLCHAIN", ""), ("CARGO_HOME", cargo_home.as_str())],
        ),
        (
            "CARGO_HOME",
            vec![("EXP_TOOLCHAIN", toolchain.as_str()), ("CARGO_HOME", "")],
        ),
    ];
    for (unset, vars) in cases {
        let (code, stdout) = preflight(home.path(), &vars);
        assert_eq!(code, Some(3), "{unset} unset (set: {vars:?}): {stdout}");
        assert!(
            stdout.starts_with(&format!("EXPANDED-SCAN CANNOT RUN: {unset} is not set:")),
            "{unset} unset (set: {vars:?}) is refused by name first: {stdout}"
        );
    }
}

/// A missing positional argument is refused BY NAME (exit 3, CANNOT RUN), never by bash's own
/// "unbound variable" (exit 1, which the scan's header reserves for findings). Both inputs are
/// passed, so each refusal is the argument's own.
#[test]
fn layer_two_refuses_a_missing_argument_by_name() {
    let home = tempfile::tempdir().expect("a fresh HOME");
    let absent = tempfile::tempdir().expect("a temp dir");
    let absent = absent.path().join("absent");
    let absent = absent.to_str().expect("a UTF-8 temp path");
    let root = repo();
    let root = root.to_str().expect("a UTF-8 repo path");
    let toolchain = caller_toolchain();
    let cargo_home = caller_cargo_home();
    let vars = [
        ("EXP_TOOLCHAIN", toolchain.as_str()),
        ("CARGO_HOME", cargo_home.as_str()),
    ];
    let worktree = "the <subject worktree> argument is missing";
    let cases: [(&str, Vec<&str>, String); 6] = [
        ("no argument", vec![], worktree.to_string()),
        (
            "--preflight alone",
            vec!["--preflight"],
            worktree.to_string(),
        ),
        (
            "--preflight with an empty worktree",
            vec!["--preflight", ""],
            worktree.to_string(),
        ),
        (
            "a scan with no out dir",
            vec![root],
            "the <NEW out dir> argument is missing".to_string(),
        ),
        (
            "--preflight with a worktree that is not a directory",
            vec!["--preflight", absent],
            format!("the <subject worktree> argument is not a directory: {absent}"),
        ),
        (
            "--preflight with a second argument",
            vec!["--preflight", root, "extra"],
            "--preflight takes only the <subject worktree> argument".to_string(),
        ),
    ];
    for (case, args, first_line) in cases {
        refused(case, scan(home.path(), &args, &vars), &first_line);
    }
}

/// An invalid toolchain variable is refused BY NAME (exit 3), naming EXP_TOOLCHAIN or CARGO_HOME:
/// a relative path, a path that is no directory, a toolchain without its binaries or whose rustc
/// is not the pinned 1.93.1, and a cargo home without an index or without crate files. The other
/// input is the caller's own each time, so each refusal is the named input's.
#[test]
fn layer_two_refuses_an_invalid_toolchain_or_cargo_home_by_name() {
    let home = tempfile::tempdir().expect("a fresh HOME");
    let toolchain = caller_toolchain();
    let cargo_home = caller_cargo_home();
    let scratch = tempfile::tempdir().expect("a scratch dir");
    let path = |name: &str| {
        scratch
            .path()
            .join(name)
            .to_str()
            .expect("UTF-8")
            .to_string()
    };
    let absent = path("absent");
    let empty = path("empty");
    std::fs::create_dir(&empty).expect("an empty dir");
    // A "toolchain" whose bin/cargo and bin/rustc exist and run, but print no 1.93.1 version.
    let other = path("other-toolchain");
    std::fs::create_dir_all(format!("{other}/bin")).expect("its bin dir");
    for tool in ["cargo", "rustc"] {
        std::os::unix::fs::symlink("/bin/true", format!("{other}/bin/{tool}"))
            .expect("a tool that prints no version");
    }
    // A cargo home with an empty index and cache (both directories exist).
    let bare = path("bare-cargo-home");
    for dir in [
        "registry/index/some-index/.cache",
        "registry/cache/some-index",
    ] {
        std::fs::create_dir_all(format!("{bare}/{dir}")).expect("an empty registry dir");
    }
    // A cargo home with a cached index entry but no crate file.
    let indexed = path("indexed-cargo-home");
    for dir in [
        "registry/index/some-index/.cache/so",
        "registry/cache/some-index",
    ] {
        std::fs::create_dir_all(format!("{indexed}/{dir}")).expect("a registry dir");
    }
    std::fs::write(
        format!("{indexed}/registry/index/some-index/.cache/so/some"),
        "x",
    )
    .expect("an index entry");

    let tc = |value: &str| {
        vec![
            ("EXP_TOOLCHAIN", value.to_string()),
            ("CARGO_HOME", cargo_home.clone()),
        ]
    };
    let ch = |value: &str| {
        vec![
            ("EXP_TOOLCHAIN", toolchain.clone()),
            ("CARGO_HOME", value.to_string()),
        ]
    };
    let cases: [(&str, Vec<(&str, String)>, String); 8] = [
        (
            "a relative EXP_TOOLCHAIN",
            tc("relative/toolchain"),
            "EXP_TOOLCHAIN=relative/toolchain is not an absolute path".to_string(),
        ),
        (
            "an EXP_TOOLCHAIN that is no directory",
            tc(&absent),
            format!("EXP_TOOLCHAIN={absent} is not a directory"),
        ),
        (
            "an EXP_TOOLCHAIN without bin/cargo",
            tc(&empty),
            format!("EXP_TOOLCHAIN={empty} has no executable bin/cargo"),
        ),
        (
            "an EXP_TOOLCHAIN whose rustc is not 1.93.1",
            tc(&other),
            format!("EXP_TOOLCHAIN={other} is not the pinned 1.93.1: its bin/rustc --version says"),
        ),
        (
            "a relative CARGO_HOME",
            ch("relative/cargo"),
            "CARGO_HOME=relative/cargo is not an absolute path".to_string(),
        ),
        (
            "a CARGO_HOME that is no directory",
            ch(&absent),
            format!("CARGO_HOME={absent} is not a directory"),
        ),
        (
            "a CARGO_HOME whose index and cache are empty",
            ch(&bare),
            format!("CARGO_HOME={bare} holds no offline registry: no index under registry/index has a non-empty .cache"),
        ),
        (
            "a CARGO_HOME with an index but no crate file",
            ch(&indexed),
            format!("CARGO_HOME={indexed} holds no offline registry: registry/cache holds no .crate file"),
        ),
    ];
    for (case, vars, first_line) in cases {
        let vars: Vec<(&str, &str)> = vars.iter().map(|(k, v)| (*k, v.as_str())).collect();
        refused(case, preflight(home.path(), &vars), &first_line);
    }
}

/// A cargo home whose cached index holds one entry and whose registry/cache holds ONE entry,
/// `name`, made by `make` (given the entry's path).
fn cargo_home_with_one_cached_entry(
    scratch: &Path,
    label: &str,
    name: &str,
    make: impl FnOnce(&Path),
) -> String {
    let home = scratch.join(label);
    let index = home.join("registry/index/some-index/.cache/so");
    std::fs::create_dir_all(&index).expect("an index dir");
    std::fs::write(index.join("some"), "x").expect("an index entry");
    let cache = home.join("registry/cache/some-index");
    std::fs::create_dir_all(&cache).expect("a cache dir");
    make(&cache.join(name));
    home.to_str().expect("a UTF-8 temp path").to_string()
}

/// Only a REGULAR file in registry/cache counts as a `.crate` file (Codex batch-4 delta r1's
/// MINOR: the count matched any entry by its NAME, so a cargo home holding no crate archive passed
/// it, and the OK line reported the entry as a checked `.crate` file). `make` puts an entry that
/// is no regular file at the path it is given; preflight must refuse that cargo home BY NAME
/// (exit 3), as it refuses one with no crate file at all. The control is the same cargo home with
/// a regular file of that name, which passes the count, so the entry's type alone decides.
fn refuses_a_crate_entry_that_is_no_regular_file(case: &str, name: &str, make: impl FnOnce(&Path)) {
    let home = tempfile::tempdir().expect("a fresh HOME");
    let scratch = tempfile::tempdir().expect("a scratch dir");
    let toolchain = caller_toolchain();

    let control = cargo_home_with_one_cached_entry(scratch.path(), "control", name, |path| {
        std::fs::write(path, "a crate archive").expect("a regular crate file")
    });
    let (code, stdout) = preflight(
        home.path(),
        &[
            ("EXP_TOOLCHAIN", toolchain.as_str()),
            ("CARGO_HOME", control.as_str()),
        ],
    );
    assert!(
        code == Some(0) && stdout.contains(" and 1 .crate files in registry/cache;"),
        "the control, a regular file named {name}, passes the count: {stdout}"
    );

    let cargo_home = cargo_home_with_one_cached_entry(scratch.path(), "case", name, make);
    refused(
        case,
        preflight(
            home.path(),
            &[
                ("EXP_TOOLCHAIN", toolchain.as_str()),
                ("CARGO_HOME", cargo_home.as_str()),
            ],
        ),
        &format!(
            "CARGO_HOME={cargo_home} holds no offline registry: registry/cache holds no .crate file"
        ),
    );
}

/// A DIRECTORY named x.crate is no crate file: a cargo home whose registry/cache holds only it is
/// refused by name (exit 3).
#[test]
fn layer_two_refuses_a_cargo_home_whose_only_crate_is_a_directory_by_name() {
    refuses_a_crate_entry_that_is_no_regular_file(
        "a cargo home whose only .crate entry is a directory",
        "x.crate",
        |path| std::fs::create_dir(path).expect("a directory named x.crate"),
    );
}

/// A DANGLING SYMLINK named y.crate is no crate file: a cargo home whose registry/cache holds only
/// it is refused by name (exit 3).
#[test]
fn layer_two_refuses_a_cargo_home_whose_only_crate_is_a_dangling_symlink_by_name() {
    refuses_a_crate_entry_that_is_no_regular_file(
        "a cargo home whose only .crate entry is a dangling symlink",
        "y.crate",
        |path| {
            let target = path.with_file_name("absent-target.crate");
            std::os::unix::fs::symlink(&target, path).expect("a symlink named y.crate");
            assert!(
                !target.exists() && path.symlink_metadata().is_ok() && !path.exists(),
                "y.crate is a dangling symlink"
            );
        },
    );
}

/// The scan never reaches a fallback for its two inputs, and with both passed, resolved from this
/// test's own environment before HOME is replaced, its preflight runs under a FRESH, EMPTY HOME and
/// leaves it empty: its toolchain is EXP_TOOLCHAIN's and its registry CARGO_HOME's. The OK line
/// names exactly what was checked and what was not. Two controls are refused, so the pass is not
/// vacuous: an empty cargo home, and a directory that is no toolchain. The preflight requires the
/// isolated network the scan itself requires (CI runs this target under `unshare -rn`).
#[test]
fn layer_two_runs_with_the_callers_toolchain_and_cargo_home_under_a_fresh_home() {
    let home = tempfile::tempdir().expect("a fresh HOME");
    let empty = tempfile::tempdir().expect("an empty directory");
    let toolchain = caller_toolchain();
    let cargo_home = caller_cargo_home();
    let empty_dir = empty.path().to_str().expect("a UTF-8 temp path");

    // The scan mode, with NEITHER input passed and an out dir that already EXISTS (its first
    // check after the inputs and the toolchain, so nothing is built or written): the first
    // refusal must name EXP_TOOLCHAIN. A script with a host-path fallback goes on without either
    // input, past its toolchain checks, to the out-dir refusal (or, on a host without the
    // fallback's path, to a refusal naming that path).
    let existing_out = tempfile::tempdir().expect("an out dir that exists");
    let root = repo();
    let (code, stdout) = scan(
        home.path(),
        &[
            root.to_str().expect("a UTF-8 repo path"),
            existing_out.path().to_str().expect("a UTF-8 temp path"),
        ],
        &[],
    );
    assert!(
        code == Some(3)
            && stdout.starts_with("EXPANDED-SCAN CANNOT RUN: EXP_TOOLCHAIN is not set:"),
        "with neither input passed, the scan must refuse EXP_TOOLCHAIN by name before any other \
         check; it went on without it (a fallback was reached): {stdout}"
    );

    let (code, stdout) = preflight(
        home.path(),
        &[
            ("EXP_TOOLCHAIN", toolchain.as_str()),
            ("CARGO_HOME", cargo_home.as_str()),
        ],
    );
    assert_eq!(code, Some(0), "both passed, fresh HOME: {stdout}");
    let checked = [
        format!(
            "EXPANDED-SCAN PREFLIGHT OK: checked: EXP_TOOLCHAIN={toolchain} has executable \
             bin/cargo and bin/rustc and its rustc is the pinned 1.93.1 (rustc 1.93.1 "
        ),
        format!("; CARGO_HOME={cargo_home} has an index with a non-empty .cache ("),
        " .crate files in registry/cache; the network has only lo; the subject has \
         expand-wrapper.sh; EXP_TOOLCHAIN's cargo read the subject's workspace offline and locked \
         (metadata only, no dependency resolved) under HOME="
            .to_string(),
        format!("HOME={}: ", home.path().display()),
        " inventoried target roots. NOT checked: that the registry holds every locked \
         dependency, the gate's build (--plan), the expansion build, the out dir\n"
            .to_string(),
    ];
    assert!(
        stdout.starts_with(&checked[0]),
        "the OK line opens with the toolchain checks: {stdout}"
    );
    for part in &checked[1..] {
        assert!(
            stdout.contains(part.as_str()),
            "the OK line names exactly what was checked [{part}]: {stdout}"
        );
    }
    assert!(
        !stdout.contains("holds an offline registry"),
        "the OK line claims no more than its registry checks: {stdout}"
    );
    let left: Vec<_> = std::fs::read_dir(home.path())
        .expect("the fresh HOME reads")
        .collect();
    assert!(
        left.is_empty(),
        "the scan wrote nothing under HOME: {left:?}"
    );

    let (code, stdout) = preflight(
        home.path(),
        &[
            ("EXP_TOOLCHAIN", toolchain.as_str()),
            ("CARGO_HOME", empty_dir),
        ],
    );
    refused(
        "an empty cargo home",
        (code, stdout),
        &format!("CARGO_HOME={empty_dir} holds no offline registry"),
    );
    let (code, stdout) = preflight(
        home.path(),
        &[
            ("EXP_TOOLCHAIN", empty_dir),
            ("CARGO_HOME", cargo_home.as_str()),
        ],
    );
    refused(
        "a directory that is no toolchain",
        (code, stdout),
        &format!("EXP_TOOLCHAIN={empty_dir} has no executable bin/cargo"),
    );
}
