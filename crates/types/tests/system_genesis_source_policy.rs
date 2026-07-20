use std::collections::BTreeSet;

use proc_macro2::{TokenStream, TokenTree};
use syn::visit::{self, Visit};
use syn::{Attribute, File, Item, ItemExternCrate, ItemUse, Path, UseTree};

const COMPILER_SOURCE: &str = include_str!("../src/app/system_genesis.rs");

const ALLOWED_PRODUCTION_IMPORTS: &[&str] = &[
    "crate::app::generated::architecture_contracts::AutonomousSystemGenesisV1",
    "crate::app::generated::architecture_contracts::AutonomousSystemInitialProfileBundleV1",
    "crate::app::generated::architecture_contracts::AutonomousSystemSequenceZeroMaterializationV1",
    "crate::app::generated::architecture_contracts::validate_architecture_contract",
    "dcrypt::algorithms::hash::HashFunction",
    "dcrypt::algorithms::hash::Sha256",
    "serde::Serialize",
    "serde_json::Map",
    "serde_json::Value",
    "std::collections::BTreeMap",
    "std::collections::BTreeSet",
];

const FORBIDDEN_CAPABILITY_PREFIXES: &[(&str, &[&str])] = &[
    ("filesystem", &["std::fs", "tokio::fs"]),
    (
        "network",
        &["std::net", "tokio::net", "reqwest", "hyper::client"],
    ),
    ("clock", &["std::time", "chrono", "time::OffsetDateTime"]),
    ("random", &["rand", "getrandom", "uuid::Uuid"]),
    ("environment", &["std::env", "env", "option_env"]),
    (
        "process",
        &["std::process", "std::thread", "tokio::process"],
    ),
    (
        "daemon",
        &["ioi_daemon", "hypervisor_daemon", "DaemonClient"],
    ),
    (
        "wallet",
        &[
            "wallet_network",
            "wallet",
            "WalletClient",
            "WalletAuthority",
        ],
    ),
    ("agentgres", &["agentgres", "Agentgres", "sqlx", "diesel"]),
];

#[derive(Debug, Default)]
struct SourcePolicyReport {
    imports: BTreeSet<String>,
    forbidden_capabilities: BTreeSet<String>,
}

fn parse_and_analyze(source: &str) -> SourcePolicyReport {
    let file = syn::parse_file(source).expect("source probe parses as Rust");
    analyze_file(&file)
}

fn analyze_file(file: &File) -> SourcePolicyReport {
    let mut report = SourcePolicyReport::default();
    for item in &file.items {
        analyze_production_item(item, &mut report);
    }
    report
}

fn analyze_production_item(item: &Item, report: &mut SourcePolicyReport) {
    if item_is_cfg_test(item) {
        return;
    }
    let mut visitor = CapabilityVisitor {
        imports: &mut report.imports,
        forbidden_capabilities: &mut report.forbidden_capabilities,
    };
    visitor.visit_item(item);
}

fn item_is_cfg_test(item: &Item) -> bool {
    item_attrs(item).iter().any(attribute_is_cfg_test)
}

fn item_attrs(item: &Item) -> &[Attribute] {
    match item {
        Item::Const(item) => &item.attrs,
        Item::Enum(item) => &item.attrs,
        Item::ExternCrate(item) => &item.attrs,
        Item::Fn(item) => &item.attrs,
        Item::ForeignMod(item) => &item.attrs,
        Item::Impl(item) => &item.attrs,
        Item::Macro(item) => &item.attrs,
        Item::Mod(item) => &item.attrs,
        Item::Static(item) => &item.attrs,
        Item::Struct(item) => &item.attrs,
        Item::Trait(item) => &item.attrs,
        Item::TraitAlias(item) => &item.attrs,
        Item::Type(item) => &item.attrs,
        Item::Union(item) => &item.attrs,
        Item::Use(item) => &item.attrs,
        _ => &[],
    }
}

fn attribute_is_cfg_test(attribute: &Attribute) -> bool {
    if !attribute.path().is_ident("cfg") {
        return false;
    }
    attribute
        .parse_args::<Path>()
        .is_ok_and(|path| path.is_ident("test"))
}

fn flatten_use_tree(prefix: String, tree: &UseTree, paths: &mut Vec<String>) {
    match tree {
        UseTree::Path(path) => {
            let prefix = join_path(&prefix, &path.ident.to_string());
            flatten_use_tree(prefix, &path.tree, paths);
        }
        UseTree::Name(name) => paths.push(join_path(&prefix, &name.ident.to_string())),
        UseTree::Rename(rename) => paths.push(format!(
            "{} as {}",
            join_path(&prefix, &rename.ident.to_string()),
            rename.rename,
        )),
        UseTree::Glob(_) => paths.push(join_path(&prefix, "*")),
        UseTree::Group(group) => {
            for tree in &group.items {
                flatten_use_tree(prefix.clone(), tree, paths);
            }
        }
    }
}

fn join_path(prefix: &str, segment: &str) -> String {
    if prefix.is_empty() {
        segment.to_owned()
    } else {
        format!("{prefix}::{segment}")
    }
}

struct CapabilityVisitor<'a> {
    imports: &'a mut BTreeSet<String>,
    forbidden_capabilities: &'a mut BTreeSet<String>,
}

impl<'ast> Visit<'ast> for CapabilityVisitor<'_> {
    fn visit_item(&mut self, item: &'ast Item) {
        if !item_is_cfg_test(item) {
            visit::visit_item(self, item);
        }
    }

    fn visit_item_use(&mut self, item_use: &'ast ItemUse) {
        let mut paths = Vec::new();
        flatten_use_tree(String::new(), &item_use.tree, &mut paths);
        for path in paths {
            classify_path(&path, self.forbidden_capabilities);
            self.imports.insert(path);
        }
        visit::visit_item_use(self, item_use);
    }

    fn visit_item_extern_crate(&mut self, item: &'ast ItemExternCrate) {
        let alias = item
            .rename
            .as_ref()
            .map(|(_, alias)| format!(" as {alias}"))
            .unwrap_or_default();
        self.imports
            .insert(format!("extern crate {}{alias}", item.ident));
        visit::visit_item_extern_crate(self, item);
    }

    fn visit_path(&mut self, path: &'ast Path) {
        let rendered = path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>()
            .join("::");
        classify_path(&rendered, self.forbidden_capabilities);
        visit::visit_path(self, path);
    }

    fn visit_macro(&mut self, expression: &'ast syn::Macro) {
        let rendered = expression
            .path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>()
            .join("::");
        if matches!(
            rendered.as_str(),
            "include" | "include_bytes" | "include_str"
        ) {
            self.forbidden_capabilities.insert("filesystem".to_owned());
        }
        classify_path(&rendered, self.forbidden_capabilities);
        classify_token_paths(&expression.tokens, self.forbidden_capabilities);
        visit::visit_macro(self, expression);
    }
}

fn classify_token_paths(tokens: &TokenStream, violations: &mut BTreeSet<String>) {
    let trees = tokens.clone().into_iter().collect::<Vec<_>>();
    for (index, tree) in trees.iter().enumerate() {
        if let TokenTree::Group(group) = tree {
            classify_token_paths(&group.stream(), violations);
        }
        let TokenTree::Ident(first) = tree else {
            continue;
        };
        let mut path = first.to_string();
        classify_path(&path, violations);
        let mut cursor = index + 1;
        while cursor + 2 < trees.len()
            && matches!(&trees[cursor], TokenTree::Punct(punct) if punct.as_char() == ':')
            && matches!(&trees[cursor + 1], TokenTree::Punct(punct) if punct.as_char() == ':')
        {
            let TokenTree::Ident(segment) = &trees[cursor + 2] else {
                break;
            };
            path.push_str("::");
            path.push_str(&segment.to_string());
            classify_path(&path, violations);
            cursor += 3;
        }
    }
}

fn classify_path(path: &str, violations: &mut BTreeSet<String>) {
    let canonical_path = path.split_once(" as ").map_or(path, |(path, _)| path);
    for (class, prefixes) in FORBIDDEN_CAPABILITY_PREFIXES {
        if prefixes.iter().any(|prefix| {
            canonical_path == *prefix
                || canonical_path
                    .strip_prefix(prefix)
                    .is_some_and(|suffix| suffix.starts_with("::"))
        }) {
            violations.insert((*class).to_owned());
        }
    }
}

#[test]
fn system_genesis_production_imports_are_exact_and_effect_free() {
    let report = parse_and_analyze(COMPILER_SOURCE);
    assert_eq!(
        report.imports,
        ALLOWED_PRODUCTION_IMPORTS
            .iter()
            .map(|path| (*path).to_owned())
            .collect(),
        "production imports drifted outside the pinned pure compiler surface",
    );
    assert!(
        report.forbidden_capabilities.is_empty(),
        "production compiler reached effect-capable paths: {:?}",
        report.forbidden_capabilities,
    );
}

#[test]
fn system_genesis_source_policy_catches_grouped_aliased_imports() {
    let report = parse_and_analyze("use std::{fs as disk}; fn compile() { disk::read(\"x\"); }");
    assert_eq!(
        report.forbidden_capabilities,
        BTreeSet::from(["filesystem".to_owned()]),
    );
    assert!(report.imports.contains("std::fs as disk"));

    let nested = parse_and_analyze("fn compile() { use std::{fs as disk}; disk::read(\"x\"); }");
    assert_eq!(
        nested.forbidden_capabilities,
        BTreeSet::from(["filesystem".to_owned()]),
    );
    assert!(nested.imports.contains("std::fs as disk"));

    let extern_alias = parse_and_analyze(
        "extern crate std as runtime; fn compile() { runtime::fs::read(\"x\"); }",
    );
    assert!(
        extern_alias.imports.contains("extern crate std as runtime"),
        "extern-crate aliases must enter the exact production import census",
    );
}

#[test]
fn system_genesis_source_policy_ignores_only_structural_cfg_test_items() {
    let actual_test_item =
        "#[cfg(test)] fn probe() { std::fs::read(\"fixture\"); }\nfn compile() {}";
    assert!(
        parse_and_analyze(actual_test_item)
            .forbidden_capabilities
            .is_empty(),
        "a real cfg(test) item belongs outside the production surface",
    );

    let fake_marker =
        "// #[cfg(test)]\nfn compile() {}\n/* #[cfg(test)] */\nfn effect() { std::fs::read(\"x\"); }";
    assert_eq!(
        parse_and_analyze(fake_marker).forbidden_capabilities,
        BTreeSet::from(["filesystem".to_owned()]),
        "comment text must not truncate production analysis",
    );
}

#[test]
fn system_genesis_source_policy_descends_into_macro_tokens() {
    let formatted =
        parse_and_analyze("fn compile() { let _ = format!(\"{:?}\", std::fs::read(\"x\")); }");
    assert_eq!(
        formatted.forbidden_capabilities,
        BTreeSet::from(["filesystem".to_owned()]),
        "a forbidden path inside macro arguments escaped",
    );

    let local_macro = parse_and_analyze(
        "macro_rules! effect { () => { std::process::Command::new(\"x\") } } fn compile() { effect!(); }",
    );
    assert_eq!(
        local_macro.forbidden_capabilities,
        BTreeSet::from(["process".to_owned()]),
        "a forbidden path inside a local macro definition escaped",
    );

    let harmless_literal =
        parse_and_analyze("fn compile() { let _ = format!(\"std::fs is documentation\"); }");
    assert!(
        harmless_literal.forbidden_capabilities.is_empty(),
        "string-literal text must not be treated as executable syntax",
    );
}

#[test]
fn system_genesis_source_policy_covers_every_effect_capability_class() {
    for (class, probe) in [
        ("filesystem", "fn f() { std::fs::read(\"x\"); }"),
        ("network", "fn f() { std::net::TcpStream::connect(\"x\"); }"),
        ("clock", "fn f() { std::time::SystemTime::now(); }"),
        ("random", "fn f() { rand::random::<u64>(); }"),
        ("environment", "fn f() { std::env::var(\"X\"); }"),
        ("process", "fn f() { std::process::Command::new(\"x\"); }"),
        ("daemon", "fn f() { ioi_daemon::connect(); }"),
        ("wallet", "fn f() { wallet_network::WalletClient::new(); }"),
        ("agentgres", "fn f() { agentgres::connect(); }"),
    ] {
        assert_eq!(
            parse_and_analyze(probe).forbidden_capabilities,
            BTreeSet::from([class.to_owned()]),
            "{class}: syntax-aware probe escaped",
        );
    }
}
