//! THE CREDENTIAL-MINTING INVENTORY (BUILD-DELTA #36; the batch-3 minting lint REPLACED BY THE
//! COMPILER: the Hypervisor Director's ruling "Batch-3 Codex r5 = FAIL, 3 MAJOR + 1 MINOR" and the
//! IOI Director's concurrence with four amendments, 2026-10-13 12:43 EDT). The retired syn walker
//! re-implemented rustc's module, cfg and include resolution in a test, and five review rounds each
//! found another corner of it. Here the compiler decides what is production code.
//!
//! LAYER 1 (CI runs it everywhere; `cargo run --locked -p ioi-node-mint-gate`): DRAW SITES.
//! - `clippy.toml` (beside this crate, read through CLIPPY_CONF_DIR) lists every randomness
//!   primitive the inventoried code can name: rand's RNG types, free functions and trait methods,
//!   rand_core, getrandom, uuid's random constructors, libc's entropy calls, and every direct
//!   dependency's public randomness API from the per-dependency review (DEPENDENCY-REVIEW.md), plus
//!   the inventoried code's OWN functions that hand a drawn value out (hand-outs.tsv), so their
//!   callers are sites too. Its sha256, the inventoried packages' features and direct dependencies
//!   and the CONFIGURATIONS are pinned in `deps.pin`: a dependency or feature change re-opens the
//!   review, and a new feature fails until its configuration is added.
//! - For EVERY pinned configuration (each shipped feature set of ioi-node, and every feature in
//!   two builds, `all-hash` and `all-kzg`: ioi-node's commitment features are mutually exclusive,
//!   so `--all-features` does not build; every feature and every production target must be in
//!   some configuration), clippy runs over the production targets (ioi-node's binaries,
//!   ioi-services' library) and the canary, `--message-format=json`, with
//!   `clippy::disallowed_methods` and `disallowed_types`
//!   FORCE-WARNED (an `#[allow]` cannot hide a use), `--no-deps` (dependencies are reviewed at their
//!   public API instead) and `--cap-lints warn` (an in-source `deny` cannot abort the inventory).
//!   Clippy reports every use by its RESOLVED path, through aliases, renamed imports, UFCS calls,
//!   function values, local and external macros, `include!`, `#[path]` and `cfg_attr`, and never
//!   reports code a non-test build of that configuration does not compile.
//! - Every report is attributed to its ENCLOSING ITEM by `syn` at the compiler's outermost call
//!   site (source.rs), counted per configuration, and compared with draw-sites.tsv BOTH WAYS: an
//!   unregistered site, a changed count or a registered site no longer reported FAILS.
//! - A registered credential MINT (mints.tsv) pins the digest of its REGION: the smallest
//!   expression, statement or block of the minting function holding its reported draws and its
//!   prefixed literals, so a change to how the credential is built from its draw re-opens review.
//! - NON-VACUITY, counted in EVERY invocation: the canary binary
//!   (canary/src/bin/mint-gate-canary.rs) uses every external deny-list entry once on a marked line,
//!   and each must be reported there exactly once; its planted PRODUCTION mint must be reported; its
//!   planted `#[cfg(test)]` mint must NOT be; and a draw inside an EXTERNAL crate's macro (the
//!   canary library's) must be reported at its invocation. A missing toolchain, a build failure, a
//!   target not checked or an unparsable report FAILS (CANNOT RUN, exit 3); nothing is skipped.
//!
//! LAYER 2 (REQUIRED pre-merge; `expanded-scan.sh` then `-- --expanded <dir>`): MINT FORMATS and
//! PRIMITIVES in the EXPANDED production source (`-Zunpretty=expanded`, the pinned
//! nightly-2026-08-08, offline, every configuration, every production target), so a mint with no
//! draw at all, a prefix assembled by `concat!`, and a draw an external macro generates are seen in
//! the compiler's own text (expanded.rs), compared with expanded-sites.tsv both ways, with the same
//! canary checks.
//!
//! NAMED LIMITS (stated, not hidden): a unit-struct VALUE `OsRng` is not a clippy type use (only its
//! imports and type positions are), so a draw through it is reported by the RNG method called on it
//! in the inventoried code, by a deny-listed dependency function it is passed to, and by layer 2's
//! `OsRng` token; a randomness API of a dependency that the review missed is not a site until the
//! review lists it (the review re-opens on every dependency change); a dependency's INTERNAL draws
//! (TLS handshakes, hash-map seeds, `select!` fairness) are that dependency's code; a credential
//! built with no draw and no registered prefix (a new prefix in a function without a credential
//! word) is not seen; the gate inventories, it does not prove that a draw executes or reaches the
//! credential (the behavioural entropy tests do).
//!
//! Usage: `cargo run --locked -p ioi-node-mint-gate [-- --print] [--configs a,b] [--expanded DIR]
//! [--plan]`. Prints libtest-style lines (`test mint_gate::<check> ... ok|FAILED`). Exit: 0 PASS;
//! 1 FAIL; 3 CANNOT RUN. `--configs` runs a subset: never a pass (`MINT-GATE PARTIAL`).

mod expanded;
mod pins;
mod source;

use pins::{Config, ConfigSpec, Entry, Row};
use proc_macro2::LineColumn;
use serde_json::Value;
use sha2::{Digest, Sha256};
use source::SourceFile;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

const NODE: &str = "ioi-node";
const SERVICES: &str = "ioi-services";
const CANARY: &str = "ioi-node-mint-gate-canary";
const GATE_DIR: &str = "crates/node/mint-gate";
const CANARY_BIN: &str = "crates/node/mint-gate/canary/src/bin/mint-gate-canary.rs";
const CANARY_LIB: &str = "crates/node/mint-gate/canary/src/lib.rs";
const PREBUILD: &str = ".github/actions/prebuild-node-profile/action.yml";
/// The four distribution profiles (crates/node/Cargo.toml): each is a pinned configuration.
const PROFILES: [&str; 4] = [
    "local-mode",
    "validator-mode",
    "provider-mode",
    "bridge-mode",
];
/// The reason suffix of an entry proven by its REAL call sites instead of the canary (a dependency API the
/// inventoried code already calls): it must be reported at one of them.
const WITNESS: &str = "[witness: its real call sites]";
const LINTS: [(&str, &str); 2] = [
    ("clippy::disallowed_types", "disallowed_types"),
    ("clippy::disallowed_methods", "disallowed_methods"),
];

#[derive(Default)]
struct Verdicts {
    failed: usize,
    passed: usize,
}

impl Verdicts {
    fn check(&mut self, name: &str, ok: bool, detail: &str) {
        println!(
            "test mint_gate::{name} ... {}",
            if ok { "ok" } else { "FAILED" }
        );
        if ok {
            self.passed += 1;
        } else {
            self.failed += 1;
            for line in detail.lines() {
                println!("    {line}");
            }
        }
    }
}

fn cannot(why: &str) -> ExitCode {
    println!("test mint_gate::can_run ... FAILED");
    for line in why.lines() {
        println!("    CANNOT RUN: {line}");
    }
    println!("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out");
    println!("MINT-GATE EXIT 3");
    ExitCode::from(3)
}

fn cargo() -> String {
    std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string())
}

fn offline() -> bool {
    std::env::var("CARGO_NET_OFFLINE").is_ok_and(|value| value == "true")
}

// =================================================================================================
// METADATA: features, direct dependencies, the targets each configuration builds
// =================================================================================================

fn metadata(root: &Path, config_args: &[String]) -> Result<Value, String> {
    let mut command = Command::new(cargo());
    command
        .current_dir(root)
        .args(["metadata", "--format-version", "1", "--locked"]);
    if offline() {
        command.arg("--offline");
    }
    command.args(config_args);
    let out = command
        .output()
        .map_err(|error| format!("cargo metadata: {error}"))?;
    if !out.status.success() {
        return Err(format!(
            "cargo metadata {config_args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
                .lines()
                .last()
                .unwrap_or_default()
        ));
    }
    serde_json::from_slice(&out.stdout).map_err(|error| format!("cargo metadata output: {error}"))
}

/// A workspace package (source null) by name.
fn package<'m>(meta: &'m Value, name: &str) -> Result<&'m Value, String> {
    meta["packages"]
        .as_array()
        .and_then(|packages| {
            packages
                .iter()
                .find(|p| p["name"] == name && p["source"].is_null())
        })
        .ok_or_else(|| format!("{name} is not a workspace package"))
}

fn resolve_node<'m>(meta: &'m Value, id: &Value) -> Result<&'m Value, String> {
    meta["resolve"]["nodes"]
        .as_array()
        .and_then(|nodes| nodes.iter().find(|n| &n["id"] == id))
        .ok_or_else(|| "a package is not in the resolve graph".to_string())
}

/// Package id -> name, for every package in the graph.
fn names(meta: &Value) -> BTreeMap<String, String> {
    meta["packages"]
        .as_array()
        .map(|packages| {
            packages
                .iter()
                .map(|p| {
                    (
                        p["id"].as_str().unwrap_or_default().to_string(),
                        p["name"].as_str().unwrap_or_default().to_string(),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

/// `package dependency version` for each direct NORMAL dependency of the inventoried packages.
fn direct_deps(meta: &Value) -> Result<BTreeSet<String>, String> {
    let mut packages: BTreeMap<String, (String, String)> = BTreeMap::new();
    for p in meta["packages"].as_array().cloned().unwrap_or_default() {
        packages.insert(
            p["id"].as_str().unwrap_or_default().to_string(),
            (
                p["name"].as_str().unwrap_or_default().to_string(),
                p["version"].as_str().unwrap_or_default().to_string(),
            ),
        );
    }
    let mut out = BTreeSet::new();
    for name in [NODE, SERVICES] {
        let node = resolve_node(meta, &package(meta, name)?["id"])?;
        for dep in node["deps"].as_array().cloned().unwrap_or_default() {
            let normal = dep["dep_kinds"]
                .as_array()
                .is_some_and(|kinds| kinds.iter().any(|kind| kind["kind"].is_null()));
            if normal {
                if let Some((dep_name, version)) =
                    packages.get(dep["pkg"].as_str().unwrap_or_default())
                {
                    out.insert(format!("{name} {dep_name} {version}"));
                }
            }
        }
    }
    Ok(out)
}

/// The enabled features of a workspace package in a resolve, by name.
fn enabled_features(meta: &Value, name: &str) -> Result<BTreeSet<String>, String> {
    let package = package(meta, name)?;
    Ok(resolve_node(meta, &package["id"])?["features"]
        .as_array()
        .map(|features| {
            features
                .iter()
                .filter_map(|f| f.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default())
}

/// The targets a configuration must check, as `package kind name` labels, and the enabled
/// features of ioi-node and ioi-services there, as `package feature`. With `every_target`, an
/// ioi-node target's required features are ignored: every production target is listed.
fn expected_targets(
    meta: &Value,
    every_target: bool,
) -> Result<(BTreeSet<String>, BTreeSet<String>), String> {
    let enabled = enabled_features(meta, NODE)?;
    let mut enabled_labels: BTreeSet<String> =
        enabled.iter().map(|f| format!("{NODE} {f}")).collect();
    enabled_labels.extend(
        enabled_features(meta, SERVICES)?
            .into_iter()
            .map(|f| format!("{SERVICES} {f}")),
    );
    let mut out = BTreeSet::new();
    for name in [NODE, SERVICES, CANARY] {
        for target in package(meta, name)?["targets"]
            .as_array()
            .cloned()
            .unwrap_or_default()
        {
            let kinds: Vec<String> = target["kind"]
                .as_array()
                .map(|k| {
                    k.iter()
                        .filter_map(|k| k.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            let kind = if kinds.iter().any(|k| k == "bin") {
                "bin"
            } else if kinds.iter().any(|k| k == "lib" || k == "rlib") {
                "lib"
            } else {
                continue;
            };
            let required: Vec<String> = target["required-features"]
                .as_array()
                .map(|r| {
                    r.iter()
                        .filter_map(|r| r.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            if !every_target && name == NODE && required.iter().any(|f| !enabled.contains(f)) {
                continue;
            }
            out.insert(format!(
                "{name} {kind} {}",
                target["name"].as_str().unwrap_or_default()
            ));
        }
    }
    Ok((out, enabled_labels))
}

// =================================================================================================
// LAYER 1: THE COMPILER'S REPORT
// =================================================================================================

#[derive(Clone, Debug, PartialEq, Eq)]
struct Position {
    file: String,
    line: usize,
    column: usize,
}

#[derive(Clone, Debug)]
struct Report {
    lint: &'static str,
    what: String,
    primary: Position,
    call_site: Position,
    package: String,
    target: String,
}

#[derive(Default)]
struct Run {
    reports: Vec<Report>,
    errors: Vec<String>,
    /// `package kind name` of every target the compiler checked.
    checked: BTreeSet<String>,
    finished_ok: bool,
}

fn normalized(root: &Path, file: &str) -> String {
    let joined = if Path::new(file).is_absolute() {
        PathBuf::from(file)
    } else {
        root.join(file)
    };
    let mut out = PathBuf::new();
    for component in joined.components() {
        match component {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    match out.strip_prefix(root) {
        Ok(relative) => relative.to_string_lossy().replace('\\', "/"),
        Err(_) => out.to_string_lossy().to_string(),
    }
}

/// A file outside the workspace named the same way on every machine: a registry crate's file by
/// `<registry>/<crate>-<version>/...`, anything else outside the tree by its own path.
fn portable(file: &str) -> String {
    match file.split_once("/registry/src/") {
        Some((_, rest)) => match rest.split_once('/') {
            Some((_, inside)) => format!("<registry>/{inside}"),
            None => file.to_string(),
        },
        None => file.to_string(),
    }
}

fn position(root: &Path, span: &Value) -> Option<Position> {
    Some(Position {
        file: normalized(root, span.get("file_name")?.as_str()?),
        line: span.get("line_start")?.as_u64()? as usize,
        column: span.get("column_start")?.as_u64()? as usize,
    })
}

fn target_label(names: &BTreeMap<String, String>, value: &Value) -> Option<String> {
    let package = names.get(value["package_id"].as_str()?)?;
    let target = &value["target"];
    let kinds: Vec<&str> = target["kind"]
        .as_array()?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let kind = if kinds.contains(&"bin") {
        "bin"
    } else if kinds.contains(&"lib") || kinds.contains(&"rlib") {
        "lib"
    } else if kinds.contains(&"custom-build") {
        "build-script"
    } else {
        kinds.first()?
    };
    Some(format!("{package} {kind} {}", target["name"].as_str()?))
}

fn read_run(root: &Path, names: &BTreeMap<String, String>, json: &str) -> Result<Run, String> {
    let mut run = Run::default();
    for line in json.lines() {
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        match value.get("reason").and_then(Value::as_str) {
            Some("compiler-artifact") => {
                if let Some(label) = target_label(names, &value) {
                    run.checked.insert(label);
                }
            }
            Some("build-finished") => run.finished_ok = value["success"].as_bool() == Some(true),
            Some("compiler-message") => {
                let message = &value["message"];
                let code = message["code"]["code"].as_str().unwrap_or_default();
                let text = message["message"].as_str().unwrap_or_default();
                let spans = message["spans"].as_array().cloned().unwrap_or_default();
                let primary = spans
                    .iter()
                    .find(|span| span["is_primary"].as_bool() == Some(true));
                if let Some((_, short)) = LINTS.iter().find(|(reported, _)| *reported == code) {
                    let span =
                        primary.ok_or_else(|| format!("a {code} report has no primary span"))?;
                    let mut call = span.clone();
                    while let Some(expansion) = call.get("expansion").filter(|e| !e.is_null()) {
                        call = expansion["span"].clone();
                    }
                    let what = text
                        .split('`')
                        .nth(1)
                        .map(str::to_string)
                        .ok_or_else(|| format!("a {code} report names no path: {text}"))?;
                    let package = value["package_id"]
                        .as_str()
                        .and_then(|id| names.get(id))
                        .ok_or_else(|| format!("a {code} report names no known package"))?
                        .clone();
                    let target = target_label(names, &value)
                        .ok_or_else(|| format!("a {code} report names no target"))?;
                    run.reports.push(Report {
                        lint: short,
                        what,
                        primary: position(root, span)
                            .ok_or_else(|| format!("a {code} report has no position"))?,
                        call_site: position(root, &call).ok_or_else(|| {
                            format!("a {code} report's call site has no position")
                        })?,
                        package,
                        target,
                    });
                } else if message["level"].as_str() == Some("error")
                    && !text.starts_with("aborting due to")
                {
                    let at = primary
                        .and_then(|span| position(root, span))
                        .map(|p| format!("{}:{}", p.file, p.line))
                        .unwrap_or_default();
                    run.errors.push(format!("{at} {code} {text}"));
                }
            }
            _ => {}
        }
    }
    Ok(run)
}

struct Sources {
    root: PathBuf,
    files: BTreeMap<String, SourceFile>,
}

impl Sources {
    fn file(&mut self, file: &str) -> Result<&SourceFile, String> {
        if !self.files.contains_key(file) {
            let path = self.root.join(file);
            let text = pins::read_file(&path)?;
            self.files
                .insert(file.to_string(), SourceFile::parse(file, text)?);
        }
        Ok(&self.files[file])
    }

    fn item(&mut self, at: &Position) -> Result<String, String> {
        let column = at.column.saturating_sub(1);
        let file = self.file(&at.file)?;
        file.enclosing(LineColumn {
            line: at.line,
            column,
        })
        .map(|item| item.path.clone())
        .ok_or_else(|| {
            format!(
                "{}:{}:{} lies in no item of its file",
                at.file, at.line, at.column
            )
        })
    }
}

/// Layer-1 key: (target, file, item, lint, what).
type Found = BTreeMap<Vec<String>, usize>;

fn in_canary(report: &Report) -> bool {
    report.package == CANARY
}

/// The sites of one run, outside the canary, and every call-site position per (target, file, item).
fn sites(
    sources: &mut Sources,
    run: &Run,
    positions: &mut BTreeMap<(String, String, String), Vec<LineColumn>>,
) -> Result<Found, String> {
    let mut out: Found = BTreeMap::new();
    for report in run.reports.iter().filter(|r| !in_canary(r)) {
        let item = sources.item(&report.call_site)?;
        let mut what = report.what.clone();
        if report.primary != report.call_site {
            // The draw lies in a macro's body: name where. A macro defined outside the tree (a
            // dependency's, the toolchain's) is named by its file alone if that file cannot be read.
            match sources.item(&report.primary) {
                Ok(primary_item) => {
                    if primary_item != item || report.primary.file != report.call_site.file {
                        what = format!(
                            "{what} (via {} | {primary_item})",
                            portable(&report.primary.file)
                        );
                    }
                }
                Err(_) if report.primary.file.starts_with('/') => {
                    what = format!("{what} (via {})", portable(&report.primary.file));
                }
                Err(error) => return Err(error),
            }
        }
        positions
            .entry((
                report.target.clone(),
                report.call_site.file.clone(),
                item.clone(),
            ))
            .or_default()
            .push(LineColumn {
                line: report.call_site.line,
                column: report.call_site.column.saturating_sub(1),
            });
        *out.entry(vec![
            report.target.clone(),
            report.call_site.file.clone(),
            item,
            report.lint.to_string(),
            what,
        ])
        .or_default() += 1;
    }
    Ok(out)
}

/// The canary's marks: line -> mark text (`deny: <path>`, `canary: <kind>`).
fn canary_marks(text: &str) -> BTreeMap<usize, String> {
    let mut out = BTreeMap::new();
    for (number, line) in text.lines().enumerate() {
        // A mark is a trailing comment on a line of code (comment-only lines are prose).
        if line.trim_start().starts_with("//") {
            continue;
        }
        if let Some((_, mark)) = line.rsplit_once("// ") {
            let mark = mark.trim();
            let deny = mark
                .strip_prefix("deny: ")
                .is_some_and(|path| !path.is_empty() && !path.contains(char::is_whitespace));
            if deny || mark.starts_with("canary: ") {
                out.insert(number + 1, mark.to_string());
            }
        }
    }
    out
}

/// The canary checks of one layer-1 run; returns the counts line.
fn layer1_canary(
    verdicts: &mut Verdicts,
    config: &str,
    run: &Run,
    external: &[&Entry],
    marks: &BTreeMap<usize, String>,
) -> String {
    let at_canary: Vec<&Report> = run
        .reports
        .iter()
        .filter(|r| r.call_site.file == CANARY_BIN)
        .collect();
    let deny_marks: BTreeMap<usize, String> = marks
        .iter()
        .filter_map(|(line, mark)| {
            mark.strip_prefix("deny: ")
                .map(|path| (*line, path.to_string()))
        })
        .collect();
    let mut findings = Vec::new();
    let mark_paths: Vec<&String> = deny_marks.values().collect();
    for entry in external {
        let marked = mark_paths.iter().filter(|p| ***p == entry.path).count();
        if marked != 1 {
            findings.push(format!(
                "{}: marked on {marked} canary lines (want exactly 1)",
                entry.path
            ));
        }
    }
    for path in &mark_paths {
        if !external.iter().any(|e| &e.path == *path) {
            findings.push(format!(
                "a canary line marks {path}, which is not an external deny-list entry"
            ));
        }
    }
    for (line, path) in &deny_marks {
        let hits = at_canary
            .iter()
            .filter(|r| r.call_site.line == *line && &r.what == path)
            .count();
        if hits != 1 {
            findings.push(format!(
                "line {line} (deny: {path}) reported {hits} times (want exactly 1: a mistyped, unresolved or silenced entry is 0)"
            ));
        }
    }
    let marked_lines: BTreeSet<usize> = marks.keys().copied().collect();
    for report in &at_canary {
        if !marked_lines.contains(&report.call_site.line) {
            findings.push(format!(
                "line {} reports {} but carries no mark",
                report.call_site.line, report.what
            ));
        }
    }
    let lines_of = |kind: &str| -> Vec<usize> {
        marks
            .iter()
            .filter(|(_, mark)| mark.as_str() == format!("canary: {kind}"))
            .map(|(line, _)| *line)
            .collect()
    };
    let production: usize = lines_of("production")
        .iter()
        .map(|line| {
            at_canary
                .iter()
                .filter(|r| r.call_site.line == *line)
                .count()
        })
        .sum();
    let external_macro: usize = lines_of("external macro")
        .iter()
        .map(|line| {
            at_canary
                .iter()
                .filter(|r| r.call_site.line == *line && r.primary.file == CANARY_LIB)
                .count()
        })
        .sum();
    let test_only_lines = lines_of("test-only");
    let test_only: usize = test_only_lines
        .iter()
        .map(|line| {
            run.reports
                .iter()
                .filter(|r| r.call_site.file == CANARY_BIN && r.call_site.line == *line)
                .count()
        })
        .sum();
    if lines_of("production").is_empty() || production == 0 {
        findings.push("the planted PRODUCTION mint's draw was NOT reported".to_string());
    }
    if external_macro == 0 {
        findings.push(
            "the draw inside the canary library's EXTERNAL macro was NOT reported at its invocation (layer 2 must then see it)"
                .to_string(),
        );
    }
    if test_only_lines.is_empty() || test_only != 0 {
        findings.push(format!(
            "the planted cfg(test)-only mint: {} marked lines, {test_only} reports (want >= 1 line and 0 reports)",
            test_only_lines.len()
        ));
    }
    verdicts.check(
        &format!("{config}_the_canary_reports_every_entry_and_both_plants"),
        findings.is_empty(),
        &findings.join("\n"),
    );
    format!(
        "CANARY {config}: deny entries {}/{} reported once each; production plant {production} reports (FOUND); external macro {external_macro} (FOUND at its invocation); cfg(test) plant {test_only} reports (IGNORED)",
        deny_marks
            .iter()
            .filter(|(line, path)| at_canary
                .iter()
                .filter(|r| r.call_site.line == **line && &r.what == *path)
                .count()
                == 1)
            .count(),
        external.len()
    )
}

fn clippy_run(
    root: &Path,
    gate: &Path,
    out_dir: &Path,
    config: &Config,
) -> Result<(String, Option<i32>, PathBuf), String> {
    let json_path = out_dir.join(format!("clippy-{}.json", config.name));
    let err_path = out_dir.join(format!("clippy-{}.stderr", config.name));
    let (Ok(json_file), Ok(err_file)) = (
        std::fs::File::create(&json_path),
        std::fs::File::create(&err_path),
    ) else {
        return Err(format!("cannot write into {}", out_dir.display()));
    };
    let mut command = Command::new(cargo());
    command
        .current_dir(root)
        .env("CLIPPY_CONF_DIR", gate)
        .args([
            "clippy",
            "--locked",
            "--keep-going",
            "-p",
            NODE,
            "-p",
            SERVICES,
            "-p",
            CANARY,
            "--message-format=json",
        ]);
    if offline() {
        command.arg("--offline");
    }
    command.args(config.cargo_args());
    command
        .args([
            "--",
            "--no-deps",
            "--cap-lints",
            "warn",
            "-A",
            "clippy::all",
            "--force-warn",
            "clippy::disallowed_types",
            "--force-warn",
            "clippy::disallowed_methods",
        ])
        .stdin(Stdio::null())
        .stdout(json_file)
        .stderr(err_file);
    let status = command
        .status()
        .map_err(|error| format!("cargo clippy: {error}"))?;
    let json = pins::read_file(&json_path)?;
    Ok((json, status.code(), err_path))
}

// =================================================================================================
// THE GATE
// =================================================================================================

struct Options {
    print: bool,
    plan: bool,
    subset: Option<BTreeSet<String>>,
    expanded: Option<PathBuf>,
}

fn options() -> Result<Options, String> {
    let mut options = Options {
        print: false,
        plan: false,
        subset: None,
        expanded: None,
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--print" => options.print = true,
            "--plan" => options.plan = true,
            "--configs" => {
                options.subset = Some(
                    args.next()
                        .ok_or("--configs needs a list")?
                        .split(',')
                        .map(str::to_string)
                        .collect(),
                )
            }
            "--expanded" => {
                options.expanded = Some(PathBuf::from(args.next().ok_or("--expanded needs a dir")?))
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    Ok(options)
}

struct Registries {
    draw_rows: Vec<Row>,
    expanded_rows: Vec<Row>,
    hand_outs: Vec<Vec<String>>,
    mints: Vec<Vec<String>>,
    prefixes: Vec<String>,
}

fn registries(gate: &Path, configs: &[Config]) -> Result<Registries, String> {
    let read = |name: &str| pins::read_file(&gate.join(name));
    let prefixes: Vec<String> = pins::read_table("prefixes.tsv", &read("prefixes.tsv")?, 2)?
        .into_iter()
        .map(|row| row[0].clone())
        .collect();
    if prefixes.is_empty() {
        return Err("prefixes.tsv registers no credential prefix".to_string());
    }
    Ok(Registries {
        draw_rows: pins::read_rows("draw-sites.tsv", &read("draw-sites.tsv")?, 5, configs)?,
        expanded_rows: pins::read_rows(
            "expanded-sites.tsv",
            &read("expanded-sites.tsv")?,
            4,
            configs,
        )?,
        hand_outs: pins::read_table("hand-outs.tsv", &read("hand-outs.tsv")?, 4)?,
        mints: pins::read_table("mints.tsv", &read("mints.tsv")?, 6)?,
        prefixes,
    })
}

fn main() -> ExitCode {
    let options = match options() {
        Ok(options) => options,
        Err(error) => return cannot(&error),
    };
    let root = match PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
    {
        Ok(root) => root,
        Err(error) => return cannot(&format!("no workspace root: {error}")),
    };
    let gate = root.join(GATE_DIR);
    let mut verdicts = Verdicts::default();

    // 1. The toolchain: the pinned one, with clippy (layer 1 only; layer 2's nightly is checked by
    // expanded-scan.sh).
    let channel = std::fs::read_to_string(root.join("rust-toolchain.toml"))
        .ok()
        .and_then(|text| {
            text.lines()
                .find_map(|line| line.trim().strip_prefix("channel = \""))
                .map(|rest| rest.trim_end_matches('"').to_string())
        });
    let Some(channel) = channel else {
        return cannot("rust-toolchain.toml names no channel");
    };
    let version = |args: &[&str]| -> Result<String, String> {
        let out = Command::new(args[0])
            .args(&args[1..])
            .current_dir(&root)
            .output()
            .map_err(|error| format!("{}: {error}", args.join(" ")))?;
        if !out.status.success() {
            return Err(format!(
                "{}: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    };
    let cargo_path = cargo();
    if options.expanded.is_none() && !options.plan {
        let rustc = match version(&["rustc", "--version"]) {
            Ok(v) => v,
            Err(error) => return cannot(&error),
        };
        let clippy = match version(&[&cargo_path, "clippy", "--version"]) {
            Ok(v) => v,
            Err(error) => return cannot(&format!("clippy is not installed: {error}")),
        };
        let minor = channel.split('.').nth(1).unwrap_or_default();
        println!("MINT-GATE toolchain: {rustc} | {clippy} (pinned {channel})");
        if !(rustc.starts_with(&format!("rustc {channel} "))
            && clippy.starts_with(&format!("clippy 0.1.{minor} ")))
        {
            return cannot(&format!(
                "the toolchain is {rustc} | {clippy}; rust-toolchain.toml pins {channel}"
            ));
        }
    }

    // 2. The pins.
    let deny_text = match pins::read_file(&gate.join("clippy.toml")) {
        Ok(text) => text,
        Err(error) => return cannot(&error),
    };
    let entries = match pins::deny_list(&deny_text) {
        Ok(entries) => entries,
        Err(error) => return cannot(&error),
    };
    let pin = match pins::read_file(&gate.join("deps.pin")).and_then(|t| pins::read_pin(&t)) {
        Ok(pin) => pin,
        Err(error) => return cannot(&error),
    };
    let deny_sha = hex::encode(Sha256::digest(deny_text.as_bytes()));
    println!(
        "MINT-GATE deny list: {deny_sha} ({} types, {} functions); configurations: {}",
        entries.iter().filter(|e| e.section == "types").count(),
        entries.iter().filter(|e| e.section == "methods").count(),
        pin.configs
            .iter()
            .map(|c| c.name.as_str())
            .collect::<Vec<_>>()
            .join(" ")
    );
    let mut paths: Vec<&String> = entries.iter().map(|e| &e.path).collect();
    paths.sort();
    let repeated: Vec<&&String> = paths
        .windows(2)
        .filter(|pair| pair[0] == pair[1])
        .map(|pair| &pair[0])
        .collect();
    let written = deny_text.matches("{ path = \"").count();
    verdicts.check(
        "deny_list_is_the_one_the_dependency_review_confirmed",
        deny_sha == pin.deny_list_sha256 && repeated.is_empty() && written == entries.len(),
        &format!(
            "clippy.toml sha256 {deny_sha}, deps.pin confirms {}; repeated entries {repeated:?}; {written} written, {} read: re-open DEPENDENCY-REVIEW.md and re-confirm",
            pin.deny_list_sha256,
            entries.len()
        ),
    );
    let plain = match metadata(&root, &[]) {
        Ok(meta) => meta,
        Err(error) => return cannot(&error),
    };
    let mut features = BTreeSet::new();
    let mut own_crates: Vec<String> = vec!["ioi_services".to_string()];
    for name in [NODE, SERVICES] {
        let p = match package(&plain, name) {
            Ok(p) => p,
            Err(error) => return cannot(&error),
        };
        for feature in p["features"]
            .as_object()
            .map(|f| f.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default()
        {
            if feature != "default" {
                features.insert(format!("{name} {feature}"));
            }
        }
        if name == NODE {
            for target in p["targets"].as_array().cloned().unwrap_or_default() {
                if target["kind"]
                    .as_array()
                    .is_some_and(|k| k.iter().any(|k| k == "bin"))
                {
                    own_crates.push(
                        target["name"]
                            .as_str()
                            .unwrap_or_default()
                            .replace('-', "_"),
                    );
                }
            }
        }
    }
    let added: Vec<&String> = features.difference(&pin.features).collect();
    let gone: Vec<&String> = pin.features.difference(&features).collect();
    verdicts.check(
        "features_equal_the_pin",
        added.is_empty() && gone.is_empty(),
        &format!(
            "NEW OR CHANGED FEATURES: {added:?}\nPINNED BUT GONE: {gone:?}\n(a new feature is a new configuration: add the shipped feature set that uses it to deps.pin's `config` lines, then re-pin)"
        ),
    );
    // `cargo metadata` has no package selection, so `--all-features` would resolve every workspace member's optional
    // dependencies: every feature of the inventoried packages is named instead (clippy's `--all-features` applies to the
    // selected packages only).
    let every_feature: Vec<String> = features.iter().map(|f| f.replacen(' ', "/", 1)).collect();
    let meta_args = |config: &Config| -> Vec<String> {
        match &config.spec {
            ConfigSpec::All => vec!["--features".to_string(), every_feature.join(",")],
            _ => config.cargo_args(),
        }
    };
    let all_meta = match metadata(&root, &["--features".to_string(), every_feature.join(",")]) {
        Ok(meta) => meta,
        Err(error) => return cannot(&error),
    };
    let mut deps = match direct_deps(&plain) {
        Ok(deps) => deps,
        Err(error) => return cannot(&error),
    };
    match direct_deps(&all_meta) {
        Ok(more) => deps.extend(more),
        Err(error) => return cannot(&error),
    }
    let added: Vec<&String> = deps.difference(&pin.deps).collect();
    let gone: Vec<&String> = pin.deps.difference(&deps).collect();
    verdicts.check(
        "direct_dependencies_equal_the_reviewed_pin",
        added.is_empty() && gone.is_empty(),
        &format!(
            "NOT REVIEWED (new or changed): {added:?}\nPINNED BUT GONE: {gone:?}\n(a dependency change re-opens DEPENDENCY-REVIEW.md: its randomness API goes into clippy.toml, or the review records it has none)"
        ),
    );
    // The shipped feature sets are configurations: the CI node profile and the four profiles.
    let prebuild = std::fs::read_to_string(root.join(PREBUILD)).unwrap_or_default();
    let node_features: Option<BTreeSet<String>> = prebuild.lines().find_map(|line| {
        line.trim()
            .strip_prefix("NODE_FEATURES=\"")
            .and_then(|rest| rest.strip_suffix('"'))
            .map(|list| list.split(',').map(|f| format!("{NODE}/{f}")).collect())
    });
    let config_sets: Vec<(String, BTreeSet<String>)> = pin
        .configs
        .iter()
        .filter_map(|c| match &c.spec {
            ConfigSpec::Features(list) => Some((c.name.clone(), list.iter().cloned().collect())),
            _ => None,
        })
        .collect();
    let mut unshipped = Vec::new();
    match &node_features {
        Some(set) if config_sets.iter().any(|(_, s)| s == set) => {}
        other => unshipped.push(format!(
            "the CI node profile {other:?} ({PREBUILD} NODE_FEATURES)"
        )),
    }
    for profile in PROFILES {
        let want: BTreeSet<String> = [format!("{NODE}/{profile}")].into_iter().collect();
        if !config_sets.iter().any(|(_, s)| *s == want) {
            unshipped.push(format!("the distribution profile {profile}"));
        }
    }
    // Every feature is covered by every_feature_is_compiled_in_some_configuration and every target
    // by every_target_is_checked_in_some_configuration: ioi-node's commitment features are mutually
    // exclusive (orchestration.rs picks its DefaultVerifier by one of them), so `--all-features`
    // does not build and the every-feature build is two configurations (deps.pin).
    if !pin.configs.iter().any(|c| c.spec == ConfigSpec::Default) {
        unshipped.push("the default build".to_string());
    }
    verdicts.check(
        "every_shipped_feature_set_is_a_configuration",
        unshipped.is_empty(),
        &format!("NOT A PINNED CONFIGURATION: {unshipped:?}"),
    );

    let configs: Vec<Config> = match &options.subset {
        Some(subset) => {
            if let Some(unknown) = subset
                .iter()
                .find(|n| !pin.configs.iter().any(|c| &c.name == *n))
            {
                return cannot(&format!(
                    "--configs names {unknown}, which deps.pin does not pin"
                ));
            }
            pin.configs
                .iter()
                .filter(|c| subset.contains(&c.name))
                .cloned()
                .collect()
        }
        None => pin.configs.clone(),
    };
    // The targets each configuration must check.
    let mut expected: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut metas: BTreeMap<String, Value> = BTreeMap::new();
    let mut enabled_anywhere: BTreeSet<String> = BTreeSet::new();
    for config in &pin.configs {
        let meta = match metadata(&root, &meta_args(config)) {
            Ok(meta) => meta,
            Err(error) => return cannot(&error),
        };
        match expected_targets(&meta, false) {
            Ok((targets, enabled)) => {
                enabled_anywhere.extend(enabled);
                expected.insert(config.name.clone(), targets);
            }
            Err(error) => return cannot(&error),
        }
        metas.insert(config.name.clone(), meta);
    }
    let features_not_enabled: Vec<&String> = pin
        .features
        .iter()
        .filter(|f| !enabled_anywhere.contains(*f))
        .collect();
    verdicts.check(
        "every_feature_is_compiled_in_some_configuration",
        features_not_enabled.is_empty(),
        &format!("features no configuration enables: {features_not_enabled:?}"),
    );
    let every_target = match expected_targets(&plain, true) {
        Ok((targets, _)) => targets,
        Err(error) => return cannot(&error),
    };
    let checked_somewhere: BTreeSet<&String> = expected.values().flatten().collect();
    let targets_unchecked: Vec<&String> = every_target
        .iter()
        .filter(|t| !checked_somewhere.contains(t))
        .collect();
    verdicts.check(
        "every_target_is_checked_in_some_configuration",
        targets_unchecked.is_empty(),
        &format!("production targets no configuration checks: {targets_unchecked:?}"),
    );
    if options.plan {
        for config in &configs {
            println!("PLAN {} {}", config.name, config.cargo_args().join(" "));
        }
        return ExitCode::SUCCESS;
    }
    let registries = match registries(&gate, &pin.configs) {
        Ok(r) => r,
        Err(error) => return cannot(&error),
    };
    let canary_text = match pins::read_file(&root.join(CANARY_BIN)) {
        Ok(text) => text,
        Err(error) => return cannot(&error),
    };
    let marks = canary_marks(&canary_text);
    let is_own = |path: &str| {
        own_crates
            .iter()
            .any(|c| path.starts_with(&format!("{c}::")))
    };
    let witnessed: Vec<&Entry> = entries
        .iter()
        .filter(|e| !is_own(&e.path) && e.reason.ends_with(WITNESS))
        .collect();
    let external: Vec<&Entry> = entries
        .iter()
        .filter(|e| !is_own(&e.path) && !e.reason.ends_with(WITNESS))
        .collect();
    let own_entries: Vec<&Entry> = entries.iter().filter(|e| is_own(&e.path)).collect();

    let result = match &options.expanded {
        None => layer1(
            &root,
            &gate,
            &mut verdicts,
            &configs,
            &metas,
            &expected,
            &registries,
            &external,
            &witnessed,
            &own_entries,
            &marks,
            options.print,
        ),
        Some(dir) => layer2(
            &mut verdicts,
            &configs,
            &metas,
            &expected,
            &registries,
            dir,
            options.print,
        ),
    };
    if let Err(error) = result {
        return cannot(&error);
    }
    let ok = verdicts.failed == 0;
    println!(
        "test result: {}. {} passed; {} failed; 0 ignored; 0 measured; 0 filtered out",
        if ok { "ok" } else { "FAILED" },
        verdicts.passed,
        verdicts.failed
    );
    let rc = if ok { 0 } else { 1 };
    if options.subset.is_some() {
        println!(
            "MINT-GATE PARTIAL (configurations {}; never a pass) EXIT {rc}",
            configs
                .iter()
                .map(|c| c.name.as_str())
                .collect::<Vec<_>>()
                .join(",")
        );
    } else {
        println!("MINT-GATE {} EXIT {rc}", if ok { "PASS" } else { "FAIL" });
    }
    ExitCode::from(rc)
}

#[allow(clippy::too_many_arguments)]
fn layer1(
    root: &Path,
    gate: &Path,
    verdicts: &mut Verdicts,
    configs: &[Config],
    metas: &BTreeMap<String, Value>,
    expected: &BTreeMap<String, BTreeSet<String>>,
    registries: &Registries,
    external: &[&Entry],
    witnessed: &[&Entry],
    own_entries: &[&Entry],
    marks: &BTreeMap<usize, String>,
    print: bool,
) -> Result<(), String> {
    let target_dir = std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| root.join("target"));
    let out_dir = target_dir.join("mint-gate");
    std::fs::create_dir_all(&out_dir)
        .map_err(|error| format!("cannot create {}: {error}", out_dir.display()))?;
    let mut sources = Sources {
        root: root.to_path_buf(),
        files: BTreeMap::new(),
    };
    let mut per_config: BTreeMap<String, Found> = BTreeMap::new();
    let mut checked_in: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut positions: BTreeMap<(String, String, String), Vec<LineColumn>> = BTreeMap::new();
    let mut reported_paths: BTreeSet<String> = BTreeSet::new();
    let mut canary_lines = Vec::new();
    for config in configs {
        let names = names(&metas[&config.name]);
        let (json, code, err_path) = clippy_run(root, gate, &out_dir, config)?;
        let run = read_run(root, &names, &json)?;
        println!(
            "MINT-GATE {}: clippy exit {code:?}; {} force-warned reports; targets checked {}",
            config.name,
            run.reports.len(),
            run.checked.len()
        );
        let want = &expected[&config.name];
        let unchecked: Vec<&String> = want.difference(&run.checked).collect();
        if code != Some(0) || !run.finished_ok || !run.errors.is_empty() || !unchecked.is_empty() {
            let tail = std::fs::read_to_string(&err_path).unwrap_or_default();
            let tail: Vec<&str> = tail.lines().rev().take(12).collect();
            return Err(format!(
                "configuration {}: the inventory did not build: exit {code:?}, build-finished success {}, errors {:#?}, targets not checked {unchecked:?}\nstderr tail:\n{}",
                config.name,
                run.finished_ok,
                run.errors,
                tail.into_iter().rev().collect::<Vec<_>>().join("\n")
            ));
        }
        verdicts.check(
            &format!("{}_the_inventory_checked_every_target", config.name),
            true,
            "",
        );
        let foreign: Vec<String> = run
            .reports
            .iter()
            .filter(|r| ![NODE, SERVICES, CANARY].contains(&r.package.as_str()))
            .map(|r| {
                format!(
                    "{} {}:{} {}",
                    r.package, r.call_site.file, r.call_site.line, r.what
                )
            })
            .collect();
        verdicts.check(
            &format!("{}_the_inventory_is_the_production_code_only", config.name),
            foreign.is_empty(),
            &format!("reports from other packages (--no-deps must keep the lints off them): {foreign:#?}"),
        );
        canary_lines.push(layer1_canary(verdicts, &config.name, &run, external, marks));
        for report in run.reports.iter().filter(|r| !in_canary(r)) {
            reported_paths.insert(report.what.clone());
        }
        let found = sites(&mut sources, &run, &mut positions)?;
        checked_in.insert(config.name.clone(), run.checked.clone());
        per_config.insert(config.name.clone(), found);
    }
    for line in &canary_lines {
        println!("{line}");
    }
    // The registry, both ways, per configuration.
    let mut drift = Vec::new();
    for config in configs {
        let checked = &checked_in[&config.name];
        drift.extend(pins::compare(
            &config.name,
            &per_config[&config.name],
            &registries.draw_rows,
            &|key: &[String]| checked.contains(&key[0]),
        ));
    }
    verdicts.check(
        "every_draw_site_is_registered",
        drift.is_empty(),
        &drift.join("\n"),
    );
    // Hand-outs: every own entry is reviewed and reported at its callers; every row holds a draw.
    let mut findings = Vec::new();
    let table_paths: BTreeSet<&String> = registries.hand_outs.iter().map(|r| &r[2]).collect();
    for entry in own_entries {
        if !table_paths.contains(&entry.path) {
            findings.push(format!(
                "{}: an own deny-list entry with no row in hand-outs.tsv",
                entry.path
            ));
        }
        if !reported_paths.contains(&entry.path) {
            findings.push(format!(
                "{}: an own deny-list entry reported at NO caller (unresolved, or no caller)",
                entry.path
            ));
        }
    }
    let all_sites: BTreeSet<(String, String)> = per_config
        .values()
        .flat_map(|found| found.keys().map(|k| (k[1].clone(), k[2].clone())))
        .collect();
    for row in &registries.hand_outs {
        if !own_entries.iter().any(|e| e.path == row[2]) {
            findings.push(format!(
                "{} | {}: its path {} is not in clippy.toml",
                row[0], row[1], row[2]
            ));
        }
        if !all_sites.contains(&(row[0].clone(), row[1].clone())) {
            findings.push(format!(
                "{} | {}: listed as a hand-out but holds no reported draw",
                row[0], row[1]
            ));
        }
    }
    let unwitnessed: Vec<&String> = witnessed
        .iter()
        .map(|e| &e.path)
        .filter(|path| !reported_paths.contains(*path))
        .collect();
    verdicts.check(
        "every_witness_entry_is_reported_at_a_real_call_site",
        unwitnessed.is_empty(),
        &format!("NOT REPORTED outside the canary in any configuration: {unwitnessed:?} (move it to the canary or drop it with the review)"),
    );
    verdicts.check(
        "every_hand_out_is_reviewed_and_its_callers_are_sites",
        findings.is_empty(),
        &findings.join("\n"),
    );
    // The mints' regions.
    let mut findings = Vec::new();
    let mut regions = Vec::new();
    for row in &registries.mints {
        let (target, file, item, prefix, digest) = (&row[0], &row[1], &row[2], &row[3], &row[4]);
        for config in configs {
            if checked_in[&config.name].contains(target)
                && !per_config[&config.name]
                    .keys()
                    .any(|k| &k[0] == target && &k[1] == file && &k[2] == item)
            {
                findings.push(format!(
                    "MINT LOST ITS DRAW [{}]: {target} | {file} | {item} reports no draw",
                    config.name
                ));
            }
        }
        let at = positions
            .get(&(target.clone(), file.clone(), item.clone()))
            .cloned()
            .unwrap_or_default();
        let prefix = (prefix != "-").then_some(prefix.as_str());
        match sources
            .file(file)
            .and_then(|source| source.region(item, &at, prefix))
        {
            Ok((computed, short, literals)) => {
                if prefix.is_some() && literals == 0 {
                    findings.push(format!("MINT LOST ITS PREFIX: {target} | {file} | {item} holds no {prefix:?} literal"));
                }
                if &computed != digest {
                    findings.push(format!(
                        "MINT REGION CHANGED: {target} | {file} | {item}: digest {computed} (registered {digest}): {short}"
                    ));
                }
                regions.push(format!(
                    "{target}\t{file}\t{item}\t{}\t{computed}\t{}",
                    row[3], row[5]
                ));
            }
            Err(error) => {
                findings.push(format!("MINT REGION: {target} | {file} | {item}: {error}"))
            }
        }
    }
    verdicts.check(
        "every_mint_region_is_the_reviewed_one",
        findings.is_empty(),
        &findings.join("\n"),
    );
    if print {
        println!("MINT-GATE PRINT draw-sites.tsv");
        let rows = pins::rows_for(configs, &per_config, &|config: &str, key: &[String]| {
            checked_in.get(config).is_some_and(|c| c.contains(&key[0]))
        });
        for (key, configs, count) in rows {
            let label = registries
                .draw_rows
                .iter()
                .find(|r| r.key == key)
                .map(|r| r.label.clone())
                .unwrap_or_else(|| "LABEL".to_string());
            println!("{}\t{}\t{count}\t{label}", key.join("\t"), configs.render());
        }
        println!("MINT-GATE PRINT mints.tsv");
        for line in regions {
            println!("{line}");
        }
        println!("MINT-GATE PRINT end");
    }
    Ok(())
}

/// LAYER 2: judge the expansions expanded-scan.sh produced under `dir`.
fn layer2(
    verdicts: &mut Verdicts,
    configs: &[Config],
    metas: &BTreeMap<String, Value>,
    expected: &BTreeMap<String, BTreeSet<String>>,
    registries: &Registries,
    dir: &Path,
    print: bool,
) -> Result<(), String> {
    let mut per_config: BTreeMap<String, Found> = BTreeMap::new();
    let mut checked_in: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut scanned: BTreeMap<String, expanded::Hits> = BTreeMap::new();
    let mut canary_lines = Vec::new();
    for config in configs {
        let names = names(&metas[&config.name]);
        let json = pins::read_file(&dir.join(format!("{}.json", config.name)))?;
        // Every checked target's unit and its expansion (expand-wrapper.sh names it by crate and hash).
        let mut units: BTreeMap<String, PathBuf> = BTreeMap::new();
        let mut finished = false;
        for line in json.lines() {
            let Ok(value) = serde_json::from_str::<Value>(line) else {
                continue;
            };
            if value["reason"] == "build-finished" {
                finished = value["success"].as_bool() == Some(true);
            }
            if value["reason"] != "compiler-artifact" {
                continue;
            }
            let Some(label) = target_label(&names, &value) else {
                continue;
            };
            if !expected[&config.name].contains(&label) {
                continue;
            }
            let crate_name = value["target"]["name"]
                .as_str()
                .unwrap_or_default()
                .replace('-', "_");
            let unit = value["filenames"]
                .as_array()
                .and_then(|files| {
                    files.iter().filter_map(Value::as_str).find_map(|file| {
                        let stem = Path::new(file).file_stem()?.to_str()?;
                        let stem = stem.strip_prefix("lib").unwrap_or(stem);
                        stem.strip_prefix(&crate_name)
                            .filter(|rest| rest.starts_with('-'))
                            .map(|rest| format!("{crate_name}{rest}"))
                    })
                })
                .ok_or_else(|| {
                    format!(
                        "configuration {}: {label} has no hashed unit file",
                        config.name
                    )
                })?;
            units.insert(label, dir.join("units").join(format!("{unit}.rs")));
        }
        let missing: Vec<&String> = expected[&config.name]
            .iter()
            .filter(|label| !units.contains_key(*label))
            .collect();
        if !finished || !missing.is_empty() {
            return Err(format!(
                "configuration {}: the expansion build did not finish (success {finished}) or did not check {missing:?}",
                config.name
            ));
        }
        let mut found: Found = BTreeMap::new();
        for (label, path) in &units {
            let key = path.display().to_string();
            if !scanned.contains_key(&key) {
                let text = pins::read_file(path)?;
                if text.trim().is_empty() {
                    return Err(format!("the expansion {key} is EMPTY"));
                }
                let hits = expanded::scan(&text, &registries.prefixes)
                    .map_err(|error| format!("{key}: {error}"))?;
                scanned.insert(key.clone(), hits);
            }
            let hits = &scanned[&key];
            if label.starts_with(&format!("{CANARY} ")) {
                if label.contains(" bin ") {
                    canary_lines.push(layer2_canary(verdicts, &config.name, hits));
                }
                continue;
            }
            for ((item, kind, what), count) in hits {
                *found
                    .entry(vec![
                        label.clone(),
                        item.clone(),
                        kind.clone(),
                        what.clone(),
                    ])
                    .or_default() += count;
            }
        }
        println!(
            "MINT-GATE {} (expanded): {} targets, {} sites",
            config.name,
            units.len(),
            found.len()
        );
        checked_in.insert(config.name.clone(), units.keys().cloned().collect());
        per_config.insert(config.name.clone(), found);
    }
    for line in &canary_lines {
        println!("{line}");
    }
    let mut drift = Vec::new();
    for config in configs {
        let checked = &checked_in[&config.name];
        drift.extend(pins::compare(
            &config.name,
            &per_config[&config.name],
            &registries.expanded_rows,
            &|key: &[String]| checked.contains(&key[0]),
        ));
    }
    verdicts.check(
        "every_expanded_mint_format_and_primitive_is_registered",
        drift.is_empty(),
        &drift.join("\n"),
    );
    if print {
        println!("MINT-GATE PRINT expanded-sites.tsv");
        let rows = pins::rows_for(configs, &per_config, &|config: &str, key: &[String]| {
            checked_in.get(config).is_some_and(|c| c.contains(&key[0]))
        });
        for (key, configs, count) in rows {
            let label = registries
                .expanded_rows
                .iter()
                .find(|r| r.key == key)
                .map(|r| r.label.clone())
                .unwrap_or_else(|| "LABEL".to_string());
            println!("{}\t{}\t{count}\t{label}", key.join("\t"), configs.render());
        }
        println!("MINT-GATE PRINT end");
    }
    Ok(())
}

/// The canary checks of one expansion of the canary binary.
fn layer2_canary(verdicts: &mut Verdicts, config: &str, hits: &expanded::Hits) -> String {
    let count = |item_part: &str, kind: &str| -> usize {
        hits.iter()
            .filter(|((item, k, _), _)| item.contains(item_part) && k == kind)
            .map(|(_, n)| n)
            .sum()
    };
    let production_prefix = count("fn planted_production_mint", "prefix");
    let production_draw = count("fn planted_production_mint", "primitive");
    let external = count("fn external_macro_draw", "primitive");
    let test_only: usize = hits
        .iter()
        .filter(|((item, _, _), _)| item.contains("planted_test_only"))
        .map(|(_, n)| n)
        .sum();
    let ok = production_prefix > 0 && production_draw > 0 && external > 0 && test_only == 0;
    verdicts.check(
        &format!("{config}_the_expanded_canary_shows_both_plants"),
        ok,
        &format!(
            "production plant: {production_prefix} prefixed literals, {production_draw} primitives (want >= 1 each); external macro draw: {external} primitives (want >= 1); cfg(test) plant: {test_only} (want 0)"
        ),
    );
    format!(
        "CANARY {config} (expanded): production plant {production_prefix} prefix + {production_draw} primitive (FOUND); external macro {external} (FOUND); cfg(test) plant {test_only} (IGNORED)"
    )
}

#[cfg(test)]
mod tests;
