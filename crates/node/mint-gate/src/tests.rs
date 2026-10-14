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
