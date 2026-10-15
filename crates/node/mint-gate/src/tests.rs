//! The gate's own logic on fixtures (the compiler runs are the ticket's).

use super::*;
use crate::pins::{compare, deny_list, read_pin, read_rows, rows_for, Configs};

fn configs() -> Vec<Config> {
    read_pin("confirmed-deny-list-sha256 x\nfeature ioi-node a\nconfig default default\nconfig all all\nconfig p ioi-node/a\n")
        .expect("pin")
        .configs
}

#[test]
fn the_pin_and_the_deny_list_read_strictly() {
    let pin = read_pin(
        "# c\nconfirmed-deny-list-sha256 ab\nfeature ioi-node x\nconfig default default\nconfig every all\nconfig p ioi-node/x,ioi-node/y\ndep ioi-node rand 0.8.5\n",
    )
    .expect("pin");
    assert_eq!(pin.configs.len(), 3);
    assert_eq!(
        pin.configs[2].cargo_args(),
        ["--features", "ioi-node/x,ioi-node/y"]
    );
    assert_eq!(pin.configs[1].cargo_args(), ["--all-features"]);
    assert!(pin.configs[0].cargo_args().is_empty());
    assert!(
        read_pin("confirmed-deny-list-sha256 ab\nfeature a b\nconfig p x\n").is_err(),
        "a feature not written package/feature"
    );
    assert!(
        read_pin("confirmed-deny-list-sha256 ab\nfeature a b\nconfig d default\nbogus\n").is_err()
    );
    let entries = deny_list(
        "disallowed-types = [\n  { path = \"a::B\", reason = \"r\" },\n]\ndisallowed-methods = [\n  { path = \"a::f\", reason = \"r s\" },\n]\n",
    )
    .expect("deny list");
    assert_eq!(entries.len(), 2);
    assert_eq!(
        (entries[0].section, entries[0].path.as_str()),
        ("types", "a::B")
    );
    assert_eq!(
        (entries[1].section, entries[1].reason.as_str()),
        ("methods", "r s")
    );
    assert!(deny_list("disallowed-methods = [\n  { path = \"a::f\", reason = \"r\" }, { path = \"a::g\", reason = \"r\" },\n]\n").is_err());
}

#[test]
fn a_registry_compares_both_ways_per_configuration() {
    let known = configs();
    let rows = read_rows(
        "t.tsv",
        "t\tf\tfn a\tl\tw\t*\t2\tMINT x\nt\tf\tfn b\tl\tw\tp\t1\tDRAW y\n",
        5,
        &known,
    )
    .expect("rows");
    let key = |item: &str| {
        vec![
            "t".into(),
            "f".into(),
            item.to_string(),
            "l".into(),
            "w".into(),
        ]
    };
    let mut found: BTreeMap<Vec<String>, usize> = BTreeMap::new();
    found.insert(key("fn a"), 2);
    assert!(compare("default", &found, &rows, &|_| true).is_empty());
    let drift = compare("p", &found, &rows, &|_| true).join("\n");
    assert!(
        drift.contains("GONE [p]") && drift.contains("fn b"),
        "{drift}"
    );
    found.insert(key("fn a"), 3);
    found.insert(key("fn c"), 1);
    let drift = compare("default", &found, &rows, &|_| true).join("\n");
    assert!(
        drift.contains("CHANGED [default]") && drift.contains("x3 (registered x2)"),
        "{drift}"
    );
    assert!(
        drift.contains("UNREGISTERED [default]") && drift.contains("fn c"),
        "{drift}"
    );
    // `*` holds only where the target is checked.
    found.clear();
    assert!(compare("default", &found, &rows, &|_| false).is_empty());
    assert!(read_rows("t.tsv", "t\tf\tfn a\tl\tw\tnope\t1\tx\n", 5, &known).is_err());
    assert!(read_rows("t.tsv", "t\tf\tfn a\tl\tw\t*\t1\tLABEL\n", 5, &known).is_err());
    // Print grouping: one count everywhere checked is `*`; otherwise named configurations.
    let mut per: BTreeMap<String, BTreeMap<Vec<String>, usize>> = BTreeMap::new();
    for c in &known {
        let mut f = BTreeMap::new();
        f.insert(key("fn a"), 1);
        if c.name == "p" {
            f.insert(key("fn b"), 4);
        }
        per.insert(c.name.clone(), f);
    }
    let rows = rows_for(&known, &per, &|_, _| true);
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].1, Configs::Every);
    assert_eq!(rows[1].1.render(), "p");
}

const SOURCE: &str = "mod outer {
    pub fn dial() -> u32 {
        let x = 1;
        let secret = [0u8; 4];
        let token = format!(\"ioi_pat_{}\", secret[0]);
        x + token.len() as u32
    }
    impl Thing {
        fn go(&self) {}
    }
}
";

#[test]
fn positions_map_to_items_and_a_fragment_is_one_item() {
    let parsed = SourceFile::parse("x.rs", SOURCE.to_string()).expect("parse");
    let at = |line, column| {
        parsed
            .enclosing(LineColumn { line, column })
            .map(|item| item.path.clone())
    };
    assert_eq!(at(3, 12).as_deref(), Some("mod outer > fn dial"));
    assert_eq!(at(9, 12).as_deref(), Some("mod outer > impl Thing > fn go"));
    let fragment =
        SourceFile::parse("f.rs", "{\n    let b = 1u8;\n    b\n}\n".to_string()).expect("fragment");
    assert!(fragment.fragment);
    assert_eq!(
        fragment
            .enclosing(LineColumn { line: 2, column: 4 })
            .map(|i| i.path.as_str()),
        Some(source::FRAGMENT)
    );
    assert!(SourceFile::parse("bad.rs", "\"unterminated".to_string()).is_err());
}

#[test]
fn a_mint_region_binds_its_draw_and_its_prefix_and_moves_with_either() {
    let parsed = SourceFile::parse("x.rs", SOURCE.to_string()).expect("parse");
    // The draw (line 4) and the prefix literal (line 5) are bound by the smallest node holding both: the body.
    let draw = [LineColumn {
        line: 4,
        column: 21,
    }];
    let (digest, short, literals) = parsed
        .region("mod outer > fn dial", &draw, Some("ioi_pat_"))
        .expect("region");
    assert_eq!(literals, 1);
    assert!(short.starts_with('{'), "{short}");
    // The building statement changed: the digest moves.
    let changed = SOURCE.replace("secret[0]", "7u8");
    let (moved, _, _) = SourceFile::parse("x.rs", changed)
        .expect("parse")
        .region("mod outer > fn dial", &draw, Some("ioi_pat_"))
        .expect("region");
    assert_ne!(digest, moved);
    // A comment or reformatting is not a change.
    let commented = SOURCE.replace("let x = 1;", "let x = 1; // a comment\n");
    let (same, _, _) = SourceFile::parse("x.rs", commented)
        .expect("parse")
        .region("mod outer > fn dial", &draw, Some("ioi_pat_"))
        .expect("region");
    assert_eq!(digest, same);
    // Without a prefix, the smallest node holding the draw is the region.
    let (_, short, _) = parsed
        .region("mod outer > fn dial", &draw, None)
        .expect("region");
    assert!(short.starts_with('[') && short.contains("0u8"), "{short}");
    assert!(parsed.region("mod outer > fn nope", &draw, None).is_err());
}

#[test]
fn the_expanded_scan_counts_prefixes_primitives_and_shapes_by_item() {
    let text = r##"
#![doc = "ioi_pat_ in a crate doc"]
use rand::RngCore;
/// ioi_pat_ in a doc comment
mod a {
    pub fn mint_token() -> String {
        let mut b = [0u8; 4];
        ::rand::RngCore::fill_bytes(&mut ::rand::rngs::OsRng, &mut b);
        ::alloc::fmt::format(format_args!("ioi_pat_{0}", 1));
        ::alloc::fmt::format(format_args!("zzk_{0}", 2))
    }
    pub fn plain() -> String { "zzk_".to_string() }
    fn tagged() -> Tagged<{ 2 }> { Tagged(uuid::Uuid::new_v4()) }
    impl<T: Into<Vec<u8>>> X<T> for Y where T: Fn() -> u8 {
        fn go(&self) { let _ = "/dev/urandom"; }
    }
    const P: &str = "wec_";
    static R: &'static str = "x";
    macro_rules! m { () => { rand::thread_rng() }; }
}
"##;
    let hits = expanded::scan(text, &["ioi_pat_".to_string(), "wec_".to_string()]).expect("scan");
    let get = |item: &str, kind: &str, what: &str| {
        hits.get(&(item.to_string(), kind.to_string(), what.to_string()))
            .copied()
            .unwrap_or(0)
    };
    assert_eq!(
        get("mod a > fn mint_token", "prefix", "ioi_pat_"),
        1,
        "{hits:#?}"
    );
    assert_eq!(get("mod a > fn mint_token", "primitive", "OsRng"), 1);
    assert_eq!(get("mod a > fn mint_token", "primitive", "rand::"), 2);
    assert_eq!(get("mod a > fn mint_token", "shaped", "zzk_"), 1);
    assert_eq!(
        get("mod a > fn plain", "shaped", "zzk_"),
        0,
        "not a credential-named function"
    );
    assert_eq!(
        get("mod a > fn tagged", "primitive", "new_v4"),
        1,
        "a const-generic brace is not the body"
    );
    assert_eq!(get("use rand::RngCore", "primitive", "rand::"), 1);
    assert_eq!(get("mod a > const P", "prefix", "wec_"), 1);
    assert_eq!(get("mod a > macro_rules m", "primitive", "thread_rng"), 1);
    let go = hits
        .iter()
        .find(|((item, kind, _), _)| item.ends_with("> fn go") && kind == "primitive")
        .map(|((item, _, what), _)| (item.clone(), what.clone()));
    assert_eq!(
        go,
        Some((
            "mod a > impl <T:Into<Vec<u8>>>X<T>forYwhereT:Fn()->u8 > fn go".to_string(),
            "/dev/urandom".to_string()
        ))
    );
    let docs: usize = hits
        .iter()
        .filter(|((_, kind, what), _)| kind == "prefix" && what == "ioi_pat_")
        .map(|(_, n)| n)
        .sum();
    assert_eq!(docs, 1, "doc attributes are not code: {hits:#?}");
    assert!(expanded::scan("\"unterminated", &[]).is_err());
}

#[test]
fn a_report_keeps_its_target_its_call_site_and_every_error() {
    let root = PathBuf::from("/w");
    let mut names = BTreeMap::new();
    names.insert(
        "path+file:///w/crates/node#ioi-node@0.1.0".to_string(),
        NODE.to_string(),
    );
    let span = |file: &str, line: u64, expansion: Value| serde_json::json!({"file_name": file, "line_start": line, "column_start": 5, "is_primary": true, "expansion": expansion});
    let message = serde_json::json!({
        "reason": "compiler-message",
        "package_id": "path+file:///w/crates/node#ioi-node@0.1.0",
        "target": {"kind": ["bin"], "name": "hypervisor-daemon"},
        "message": {"code": {"code": "clippy::disallowed_methods"}, "level": "warning",
                    "message": "use of a disallowed method `uuid::Uuid::new_v4`",
                    "spans": [span("crates/x/src/lib.rs", 3, serde_json::json!({"span": span("crates/node/src/a.rs", 9, Value::Null)}))]}
    });
    let error = serde_json::json!({"reason": "compiler-message", "package_id": "p", "message": {"code": null, "level": "error", "message": "boom", "spans": []}});
    let artifact = serde_json::json!({"reason": "compiler-artifact", "package_id": "path+file:///w/crates/node#ioi-node@0.1.0", "target": {"kind": ["bin"], "name": "hypervisor-daemon"}});
    let done = serde_json::json!({"reason": "build-finished", "success": true});
    let json = [message, error, artifact, done]
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    let run = read_run(&root, &names, &json).expect("run");
    assert_eq!(run.reports.len(), 1);
    let report = &run.reports[0];
    assert_eq!(report.what, "uuid::Uuid::new_v4");
    assert_eq!(report.target, "ioi-node bin hypervisor-daemon");
    assert_eq!((report.primary.line, report.call_site.line), (3, 9));
    assert_eq!(report.call_site.file, "crates/node/src/a.rs");
    assert_eq!(run.errors.len(), 1);
    assert!(run.checked.contains("ioi-node bin hypervisor-daemon"));
    assert!(run.finished_ok);
}

#[test]
fn the_canary_marks_read_by_line() {
    let marks = canary_marks(
        "//! Every line marked `// deny: <path>` is prose here.\nfn a() {\n    let _ = x(); // deny: a::x\n    y(); // canary: production\n    z(); // deny: two words\n}\n",
    );
    assert_eq!(marks.get(&3).map(String::as_str), Some("deny: a::x"));
    assert_eq!(
        marks.get(&4).map(String::as_str),
        Some("canary: production")
    );
    assert_eq!(marks.len(), 2, "{marks:?}");
}

#[test]
fn a_file_outside_the_tree_is_named_portably() {
    assert_eq!(
        portable("/home/u/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tokio-1.42.0/src/macros/select.rs"),
        "<registry>/tokio-1.42.0/src/macros/select.rs"
    );
    assert_eq!(portable("crates/node/src/a.rs"), "crates/node/src/a.rs");
}

#[test]
fn a_configuration_lists_its_targets_and_the_features_it_enables() {
    let target = |kind: &str, name: &str, required: &[&str]| serde_json::json!({"kind": [kind], "name": name, "required-features": required});
    let meta = serde_json::json!({
        "packages": [
            {"name": "ioi-node", "id": "n", "source": null, "targets": [
                target("bin", "plain", &[]), target("bin", "kzg-only", &["commitment-kzg"])]},
            {"name": "ioi-services", "id": "s", "source": null, "targets": [target("lib", "ioi_services", &[])]},
            {"name": "ioi-node-mint-gate-canary", "id": "c", "source": null, "targets": [
                target("bin", "mint-gate-canary", &[]), target("lib", "ioi_node_mint_gate_canary", &[])]},
        ],
        "resolve": {"nodes": [
            {"id": "n", "features": ["commitment-hash"]},
            {"id": "s", "features": ["agentic", "gas-escrow"]},
            {"id": "c", "features": []},
        ]}
    });
    let (targets, enabled) = expected_targets(&meta, false).expect("targets");
    assert!(targets.contains("ioi-node bin plain"));
    assert!(
        !targets.contains("ioi-node bin kzg-only"),
        "a binary whose required feature is off is not this configuration's: {targets:?}"
    );
    assert!(targets.contains("ioi-services lib ioi_services"));
    assert!(targets.contains("ioi-node-mint-gate-canary bin mint-gate-canary"));
    let want: BTreeSet<String> = [
        "ioi-node commitment-hash",
        "ioi-services agentic",
        "ioi-services gas-escrow",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    assert_eq!(enabled, want, "ioi-services' features count as enabled too");
    let (every, _) = expected_targets(&meta, true).expect("every target");
    assert!(
        every.contains("ioi-node bin kzg-only"),
        "every production target is listed whatever its required features: {every:?}"
    );
    assert_eq!(every.len(), targets.len() + 1);
}

#[test]
fn a_binary_named_like_a_dependency_is_not_own_code() {
    let node = serde_json::json!({
        "targets": [
            {"kind": ["bin"], "name": "hypervisor-daemon"},
            {"kind": ["bin"], "name": "ioi-validator"},
            {"kind": ["lib"], "name": "not_a_bin"},
        ],
        "dependencies": [
            {"name": "ioi-validator", "rename": null},
            {"name": "rand", "rename": null},
            {"name": "getrandom", "rename": "getrandom02"},
        ]
    });
    assert_eq!(own_bin_crates(&node), ["hypervisor_daemon"]);
}

// ---- Codex batch-3 r6 (BUILD-DELTA #36): the hand-out reconcile, the resolved-feature pin and the feature scopes ----

const SINKS_SOURCE: &str = r#"
fn ret() -> String {
    uuid::Uuid::new_v4().to_string()
}
fn mut_param(out: &mut String) {
    *out = uuid::Uuid::new_v4().to_string();
}
fn field(holder: &std::sync::Mutex<Vec<String>>) {
    let fresh = uuid::Uuid::new_v4().to_string();
    holder.lock().unwrap().push(fresh);
}
fn channel(tx: std::sync::mpsc::Sender<String>) {
    let fresh = uuid::Uuid::new_v4().to_string();
    let _ = tx.send(fresh);
}
fn stat() {
    let fresh = uuid::Uuid::new_v4().to_string();
    *SINK.lock().unwrap() = Some(fresh);
}
fn capture() {
    let fresh = uuid::Uuid::new_v4().to_string();
    std::thread::spawn(move || drop(fresh));
}
fn fill(out: &mut [u8]) {
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, out);
}
impl S {
    fn through_a_lock(&self) {
        let id = uuid::Uuid::new_v4();
        let mut map = self.sessions.write().unwrap();
        map.insert(id, 1);
    }
}
fn once() -> &'static str {
    static NONCE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    NONCE.get_or_init(|| uuid::Uuid::new_v4().to_string())
}
fn through_out_parameter() -> [u8; 16] {
    let mut secret = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut secret);
    secret
}
fn local_only() {
    let fresh = uuid::Uuid::new_v4().to_string();
    let _n = fresh.len();
}
fn logged() {
    let fresh = uuid::Uuid::new_v4();
    println!("{fresh}");
}
"#;

/// Every draw position in a fixture: the start of each `uuid::Uuid::new_v4` and `rand::RngCore::fill_bytes` path,
/// grouped by enclosing item as the gate groups clippy's reports.
fn fixture_holders(parsed: &SourceFile, text: &str) -> BTreeMap<String, Vec<LineColumn>> {
    let mut out: BTreeMap<String, Vec<LineColumn>> = BTreeMap::new();
    for (number, line) in text.lines().enumerate() {
        for needle in ["uuid::Uuid::new_v4", "rand::RngCore::fill_bytes"] {
            for (column, _) in line.match_indices(needle) {
                let at = LineColumn {
                    line: number + 1,
                    column,
                };
                let item = parsed.enclosing(at).expect("an item").path.clone();
                out.entry(item).or_default().push(at);
            }
        }
    }
    out
}

#[test]
fn every_sink_kind_makes_a_hand_out_candidate() {
    let parsed = SourceFile::parse("s.rs", SINKS_SOURCE.to_string()).expect("parse");
    let holders = fixture_holders(&parsed, SINKS_SOURCE);
    assert_eq!(holders.len(), 12, "{holders:?}");
    let found = reconcile_file(&parsed, &holders).expect("reconcile");
    let kinds = |item: &str| found.get(item).map(handouts::kinds);
    assert_eq!(kinds("fn ret").as_deref(), Some(handouts::RETURN));
    assert_eq!(kinds("fn mut_param").as_deref(), Some(handouts::MUT_PARAM));
    assert_eq!(kinds("fn field").as_deref(), Some(handouts::NON_LOCAL));
    assert_eq!(kinds("fn channel").as_deref(), Some(handouts::CHANNEL));
    assert_eq!(kinds("fn stat").as_deref(), Some(handouts::STATIC));
    assert_eq!(kinds("fn capture").as_deref(), Some(handouts::CAPTURE));
    assert_eq!(kinds("fn fill").as_deref(), Some(handouts::MUT_PARAM));
    assert_eq!(
        kinds("impl S > fn through_a_lock").as_deref(),
        Some(handouts::NON_LOCAL)
    );
    assert_eq!(
        kinds("fn once").as_deref(),
        Some(format!("{},{}", handouts::RETURN, handouts::STATIC).as_str())
    );
    assert_eq!(
        kinds("fn through_out_parameter").as_deref(),
        Some(handouts::RETURN)
    );
    assert_eq!(kinds("fn local_only"), None, "{found:?}");
    assert_eq!(kinds("fn logged"), None, "I/O is a named limit: {found:?}");
    // The evidence names the line of each sink.
    let ret = handouts::render(&found["fn ret"]);
    assert_eq!(ret, "return@3", "{ret}");
}

// ---- Codex batch-3 r7 (BUILD-DELTA #36): a draw handed out through `?` as an error, and a `&mut` parameter reached
// through more than three reborrows (the Hypervisor Director's ruling "Codex batch-3 r7 (review-a at 223d39b32) = FAIL",
// RULED (1)) ----

const R7_SOURCE: &str = r#"
fn via_question_mark() -> Result<(), String> {
    Err::<(), String>(uuid::Uuid::new_v4().to_string())?;
    Ok(())
}
fn through_reborrows(out: &mut String) {
    let a = out;
    let b = a;
    let c = b;
    let d = c;
    *d = uuid::Uuid::new_v4().to_string();
}
fn through_six_reborrows(out: &mut String) {
    let a = &mut *out;
    let b = a;
    let c = &mut *b;
    let d = c;
    let e = d;
    let f = &mut *e;
    f.push_str(&uuid::Uuid::new_v4().to_string());
}
fn via_map_err() -> Result<u8, String> {
    let fresh = uuid::Uuid::new_v4().to_string();
    "7".parse::<u8>().map_err(|_| fresh.clone())?;
    Ok(0)
}
fn via_a_tracked_local() -> Result<(), String> {
    let held: Result<(), String> = Err(uuid::Uuid::new_v4().to_string());
    held?;
    Ok(())
}
fn via_a_callee_error() -> Result<(), String> {
    let fresh = uuid::Uuid::new_v4().to_string();
    check(&fresh)?;
    Ok(())
}
fn via_the_ok_half() -> Result<(), String> {
    let id = Ok::<_, String>(uuid::Uuid::new_v4())?;
    let _ = id;
    Ok(())
}
fn inside_a_closure() -> Result<(), String> {
    let run = || -> Result<(), String> {
        Err(uuid::Uuid::new_v4().to_string())?;
        Ok(())
    };
    let _ = run();
    Ok(())
}
fn oscillating(out: &mut String, shared: &std::sync::Mutex<String>) {
    let a = out;
    let b = shared;
    let a = b;
    let b = a;
    *b = uuid::Uuid::new_v4().to_string();
}
"#;

fn r7_found() -> BTreeMap<String, handouts::Sinks> {
    let parsed = SourceFile::parse("r7.rs", R7_SOURCE.to_string()).expect("parse");
    let holders = fixture_holders(&parsed, R7_SOURCE);
    assert_eq!(holders.len(), 9, "{holders:?}");
    reconcile_file(&parsed, &holders).expect("reconcile")
}

#[test]
fn a_draw_handed_out_as_an_error_through_question_mark_is_a_return_sink() {
    // Codex r7 MAJOR (a), as written: the draw reaches the caller as the `Err` that `?` returns.
    let found = r7_found();
    assert_eq!(
        found.get("fn via_question_mark").map(handouts::render),
        Some("return@3".to_string()),
        "{found:?}"
    );
}

#[test]
fn a_mut_parameter_reached_through_four_or_more_reborrows_is_a_mut_parameter_sink() {
    // Codex r7 MAJOR (b), as written (four reborrows), and six through `&mut *` reborrows: alias discovery runs to a
    // fixpoint, not three passes.
    let found = r7_found();
    assert_eq!(
        found.get("fn through_reborrows").map(handouts::render),
        Some("&mut parameter@11".to_string()),
        "{found:?}"
    );
    assert_eq!(
        found.get("fn through_six_reborrows").map(handouts::render),
        Some("&mut parameter@20".to_string()),
        "{found:?}"
    );
}

#[test]
fn question_mark_and_alias_discovery_keep_their_named_bounds() {
    let found = r7_found();
    let kinds = |item: &str| found.get(item).map(handouts::kinds);
    // An error the function builds from the drawn value: an error adapter's argument, a tracked local.
    assert_eq!(
        found.get("fn via_map_err").map(handouts::render),
        Some("closure capture@24; return@24".to_string()),
        "{found:?}"
    );
    assert_eq!(
        found.get("fn via_a_tracked_local").map(handouts::render),
        Some("return@29".to_string()),
        "{found:?}"
    );
    // Named limits: a callee's error is the callee's; `?` unwrapping the Ok half hands nothing out; a `?` inside a
    // closure leaves the closure, not the function.
    assert_eq!(kinds("fn via_a_callee_error"), None, "{found:?}");
    assert_eq!(kinds("fn via_the_ok_half"), None, "{found:?}");
    assert_eq!(kinds("fn inside_a_closure"), None, "{found:?}");
    // Alias discovery that does not reach a fixpoint within the function's binding bound is not guessed: the holder
    // is unanalyzed, a candidate until reviewed.
    assert!(
        found
            .get("fn oscillating")
            .is_some_and(|s| s.contains_key(handouts::UNANALYZED)),
        "{found:?}"
    );
}

#[test]
fn a_holder_that_is_not_a_function_is_reviewed_as_it_is() {
    assert_eq!(handouts::item_sinks("use rand::RngCore", 3), None);
    assert_eq!(
        handouts::item_sinks("fn f > static KEY", 4).map(|s| handouts::kinds(&s)),
        Some(handouts::STATIC.to_string())
    );
    assert_eq!(
        handouts::item_sinks(source::FRAGMENT, 1).map(|s| handouts::kinds(&s)),
        Some(handouts::UNANALYZED.to_string())
    );
}

#[test]
fn the_reviewed_exclusions_read_strictly_from_the_dependency_review() {
    let text = "# x\n\n<!-- reconcile-exclusions begin -->\n| file | item | sinks | reason |\n|---|---|---|---|\n| a.rs | fn f | return | a name, not a credential |\n| b.rs | impl X > fn g | closure capture,return | compared only |\n<!-- reconcile-exclusions end -->\n| c.rs | fn h | return | outside the markers |\n";
    let rows = read_exclusions(text).expect("exclusions");
    assert_eq!(rows.len(), 2);
    assert_eq!(
        rows[1],
        [
            "b.rs",
            "impl X > fn g",
            "closure capture,return",
            "compared only"
        ]
    );
    assert!(read_exclusions("<!-- reconcile-exclusions begin -->\n| h | h | h | h |\n|-|-|-|-|\n| a.rs | fn f | return |\n<!-- reconcile-exclusions end -->\n").is_err());
    assert!(read_exclusions("no markers").is_err());
}

/// A resolved graph: ioi-node depends (optionally) on ioi-validator and on rand, and (dev) on tempfile.
fn pin_meta(
    node_depends_on_validator: bool,
    validator: &[&str],
    edge: &[&str],
    vm_wasm: &[&str],
) -> Value {
    let dep = |name: &str, kind: Option<&str>, optional: bool, default: bool, features: &[&str]| {
        serde_json::json!({"name": name, "rename": null, "kind": kind, "target": null, "optional": optional,
            "uses_default_features": default, "features": features})
    };
    let mut node_deps = vec![
        serde_json::json!({"pkg": "r", "dep_kinds": [{"kind": null, "target": null}]}),
        serde_json::json!({"pkg": "t", "dep_kinds": [{"kind": "dev", "target": null}]}),
    ];
    if node_depends_on_validator {
        node_deps
            .push(serde_json::json!({"pkg": "v", "dep_kinds": [{"kind": null, "target": null}]}));
    }
    serde_json::json!({
        "packages": [
            {"name": "ioi-node", "id": "n", "version": "0.1.0", "source": null,
             "features": {"default": [], "vm-wasm": vm_wasm, "consensus-aft": ["ioi-validator/consensus-aft"]},
             "dependencies": [dep("ioi-validator", None, true, false, edge), dep("rand", None, false, true, &[]),
                dep("tempfile", Some("dev"), false, true, &[])], "targets": []},
            {"name": "ioi-services", "id": "s", "version": "0.1.0", "source": null, "features": {}, "dependencies": [], "targets": []},
            {"name": "ioi-node-mint-gate-canary", "id": "c", "version": "0.1.0", "source": null,
             "features": {"seal-signer": ["ioi-validator/consensus-aft"]},
             "dependencies": [dep("ioi-validator", None, false, false, &[])], "targets": []},
            {"name": "ioi-validator", "id": "v", "version": "0.1.0", "source": null,
             "features": {"consensus-aft": [], "consensus-pos": []}, "dependencies": [], "targets": []},
            {"name": "rand", "id": "r", "version": "0.8.5", "source": "registry+x", "features": {"std": []}, "dependencies": [], "targets": []},
            {"name": "tempfile", "id": "t", "version": "3.0.0", "source": "registry+x", "features": {}, "dependencies": [], "targets": []},
            {"name": "unrelated", "id": "u", "version": "1.0.0", "source": "registry+x", "features": {}, "dependencies": [], "targets": []}
        ],
        "resolve": {"nodes": [
            {"id": "n", "features": ["default"], "deps": node_deps},
            {"id": "s", "features": [], "deps": []},
            {"id": "c", "features": [], "deps": [{"pkg": "v", "dep_kinds": [{"kind": null, "target": null}]}]},
            {"id": "v", "features": validator, "deps": []},
            {"id": "r", "features": ["std"], "deps": []},
            {"id": "t", "features": [], "deps": []},
            {"id": "u", "features": [], "deps": []}
        ]}
    })
}

#[test]
fn the_pin_records_dependency_selections_forwarding_and_resolved_features() {
    let base = pin_meta(true, &["consensus-aft"], &[], &["ioi-validator/vm-wasm"]);
    let ids = closure(&base).expect("closure");
    assert_eq!(
        ids.iter().map(String::as_str).collect::<Vec<_>>(),
        ["c", "n", "r", "s", "v"],
        "normal and build edges from the inventoried packages and the canary; dev edges and unreached packages are out"
    );
    let (forwards, selects) = manifest_lines(&base, &ids);
    assert!(
        forwards.contains("forward ioi-node consensus-aft ioi-validator/consensus-aft"),
        "{forwards:?}"
    );
    assert!(
        forwards.contains("forward ioi-node default -"),
        "{forwards:?}"
    );
    assert!(
        selects.contains("select ioi-node ioi-validator normal * optional default-features=no -"),
        "{selects:?}"
    );
    assert!(
        !selects.iter().any(|s| s.contains("tempfile")),
        "dev dependencies are not selections: {selects:?}"
    );
    // Codex r6 MAJOR 2's plant: the validator line requests consensus-aft; names, versions and feature names unchanged.
    let planted = pin_meta(
        true,
        &["consensus-aft"],
        &["consensus-aft"],
        &["ioi-validator/vm-wasm"],
    );
    let (planted_forwards, planted_selects) =
        manifest_lines(&planted, &closure(&planted).expect("closure"));
    assert_eq!(planted_forwards, forwards);
    let added: Vec<&String> = planted_selects.difference(&selects).collect();
    assert_eq!(
        added,
        ["select ioi-node ioi-validator normal * optional default-features=no consensus-aft"]
    );
    // A new forward changes the forwarding line by name.
    let forwarded = pin_meta(
        true,
        &["consensus-aft", "consensus-pos"],
        &[],
        &["ioi-validator/vm-wasm", "ioi-validator/consensus-pos"],
    );
    let (forwarded_lines, _) = manifest_lines(&forwarded, &closure(&forwarded).expect("closure"));
    let added: Vec<&String> = forwarded_lines.difference(&forwards).collect();
    assert_eq!(
        added,
        ["forward ioi-node vm-wasm ioi-validator/consensus-pos,ioi-validator/vm-wasm"]
    );
    // Resolved features per configuration, grouped, read back and compared both ways.
    let known = configs();
    let mut facts: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    for config in &known {
        let meta = if config.name == "p" {
            &forwarded
        } else {
            &base
        };
        facts.insert(
            config.name.clone(),
            resolved_facts(meta, &closure(meta).expect("closure")),
        );
    }
    assert_eq!(
        facts["default"].get("rand@0.8.5").map(String::as_str),
        Some("std")
    );
    assert_eq!(
        facts["default"]
            .get("ioi-services@0.1.0")
            .map(String::as_str),
        Some("-")
    );
    assert!(!facts["default"].contains_key("tempfile@3.0.0"));
    let lines = resolved_lines(&known, &facts);
    assert!(
        lines.contains(&"resolved * rand@0.8.5 std".to_string()),
        "{lines:?}"
    );
    assert!(
        lines.contains(&"resolved default,all ioi-validator@0.1.0 consensus-aft".to_string()),
        "{lines:?}"
    );
    assert!(
        lines.contains(&"resolved p ioi-validator@0.1.0 consensus-aft,consensus-pos".to_string()),
        "{lines:?}"
    );
    let pin_text = format!(
        "confirmed-deny-list-sha256 x\nfeature ioi-node a\nconfig default default\nconfig all all\nconfig p ioi-node/a\n{}\n{}\n{}\n",
        forwards.iter().cloned().collect::<Vec<_>>().join("\n"),
        selects.iter().cloned().collect::<Vec<_>>().join("\n"),
        lines.join("\n")
    );
    let pin = read_pin(&pin_text).expect("the pin reads its own lines back");
    assert_eq!(pin.forwards, forwards);
    assert_eq!(pin.selects, selects);
    let pinned = pins::expand_resolved(&pin.resolved, &known).expect("expand");
    assert!(resolved_drift(&known, &pinned, &facts).is_empty());
    let mut moved = facts.clone();
    moved.get_mut("default").expect("default").insert(
        "ioi-validator@0.1.0".into(),
        "consensus-aft,consensus-pos".into(),
    );
    let drift = resolved_drift(&known, &pinned, &moved).join("\n");
    assert!(
        drift.contains("CHANGED [default] ioi-validator@0.1.0"),
        "{drift}"
    );
}

#[test]
fn a_feature_scope_follows_each_configurations_resolved_graph() {
    let on = pin_meta(true, &["consensus-aft"], &[], &[]);
    let (state, why) = scope_state(&on, "ioi-validator", "consensus-aft");
    assert!(state, "{why}");
    // The default build: only the canary depends on ioi-validator, so the inventoried code cannot name it.
    let (state, why) = scope_state(
        &pin_meta(false, &["consensus-aft"], &[], &[]),
        "ioi-validator",
        "consensus-aft",
    );
    assert!(!state && why.contains("not a resolved dependency"), "{why}");
    let (state, why) = scope_state(
        &pin_meta(true, &[], &[], &[]),
        "ioi-validator",
        "consensus-aft",
    );
    assert!(!state && why.contains("not resolved"), "{why}");
    let ids = closure(&on).expect("closure");
    assert!(feature_resolved(
        &on,
        &ids,
        "ioi-validator",
        "consensus-aft"
    ));
    assert!(!feature_resolved(
        &on,
        &ids,
        "ioi-validator",
        "consensus-pos"
    ));
    assert!(!feature_resolved(&on, &ids, "rand", "small_rng"));
}

#[test]
fn a_scoped_canary_mark_names_its_scope() {
    let marks = canary_marks("fn a() {\n    let _ = k::g; // deny-in seal-signer: k::g\n    let _ = k::h; // deny-in : k::h\n}\n");
    assert_eq!(
        marks.get(&2).map(String::as_str),
        Some("deny-in seal-signer: k::g")
    );
    assert_eq!(marks.len(), 1, "{marks:?}");
    assert_eq!(
        deny_mark("deny-in seal-signer: k::g"),
        Some(("k::g".to_string(), Some("seal-signer".to_string())))
    );
    assert_eq!(deny_mark("deny: k::g"), Some(("k::g".to_string(), None)));
    assert_eq!(deny_mark("canary: production"), None);
}
