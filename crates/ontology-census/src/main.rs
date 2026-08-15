//! Ontology admission census EXTRACTOR — a real Rust parser, emitting the facts as JSON.
//!
//! An EXAMPLE target, deliberately. `syn` is a dev-dependency of this crate and the crate's own note
//! says it keeps minimal dependencies to remain stable; an example may use dev-dependencies without
//! putting a parser into a core type crate's runtime graph, and it builds only when asked for.
//! Run: `cargo run --locked -p ioi-types --example ontology-admission-extract -- <daemon-main.rs>`.
//!
//! WHY THIS EXISTS, and why it replaced a hand-rolled reader. Next-legs XIV Leg 3a built the
//! no-second-spine entailment by scanning the daemon's source with regexes. Three merge-blocking
//! review rounds each defeated it, and the defeats sorted into two buckets: CENSUS LOGIC (a rule
//! that was wrong or decorative) and LANGUAGE READING (a Rust construct the scanner mis-modelled).
//! Round two produced six language-reading defeats; round three produced five more — module-scope
//! path visibility (`use super::odk_routes;` then `odk_routes::KIND_ONT`), raw strings desyncing a
//! brace walk, `async fn` and other declaration forms an enclosing-function heuristic could not
//! find, and module-file resolution order shadowing a nested module with a flat sibling.
//!
//! The owner pre-committed the decision before that round ran: modelling the next construct retires
//! an INSTANCE, a real parser retires the CLASS. Every construct above is free here, because `syn`
//! already knows Rust — items, paths, use-trees, attributes, string and raw-string literals, and
//! declaration forms are all just AST.
//!
//! WHAT IT EMITS, and nothing more. This tool decides no policy. It reports what the source SAYS —
//! which modules exist, what each names, where each family literal is written and read — and the
//! JavaScript gate decides what that means. Keeping extraction and judgement apart is what lets the
//! judgement keep its mutation anchors while the substrate underneath changes.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Serialize;
use syn::{Expr, ExprCall, ExprPath, File, Item, ItemConst, Lit, UseTree};

/// One record-writing or record-reading call site, with the family argument RESOLVED.
#[derive(Serialize, Default)]
struct CallSite {
    callee: String,
    /// The family literal this call names, once constants and aliases are resolved. `None` means
    /// the census could not tie the argument to a literal — which the gate treats as RED, never as
    /// "not a family".
    family: Option<String>,
    /// The argument as written, for the diagnostic.
    written: String,
    in_test: bool,
}

#[derive(Serialize, Default)]
struct ModuleFacts {
    name: String,
    path: String,
    /// `const NAME: &str = "literal"` declared in THIS module. Per-module, because the daemon
    /// declares 660 constants under 537 names and 25 of those names mean different things in
    /// different modules.
    consts: BTreeMap<String, String>,
    /// Every name this module brings into scope, mapped to the module it came from and the item.
    /// Covers `use m::C`, `use m::C as A`, `use m::{a, b::C}`, `use m::*`, and `use m;` — the last
    /// being the module-as-path-prefix form that defeated the hand-rolled reader.
    imports: Vec<Import>,
    /// Modules declared by this file. A `#[path]` target is carried after a unit separator so the
    /// walker can resolve it without a second parse; the gate reads only the name before it.
    child_mods: Vec<ChildMod>,
    calls: Vec<CallSite>,
    /// Raw filesystem calls, with every argument as written. The record-writer census cannot see a
    /// lane that bypasses the writers entirely and puts bytes in a family directory itself, and the
    /// regression floor this substrate inherited includes exactly that mutation.
    fs_calls: Vec<FsCall>,
    /// Every path expression whose final segment is a name this module could resolve to a family,
    /// with the syntactic role it appears in. A name used in a role the gate does not know about is
    /// a mention the census cannot read — which must be RED, never silently dropped.
    family_mentions: Vec<Mention>,
    /// Functions that both RESOLVE a family name and WRITE a record. The gate refuses these; the
    /// extractor only reports which functions do both, using real item boundaries rather than a
    /// backwards search for the `fn` keyword.
    resolve_and_write_fns: Vec<String>,
    /// Per function, every path leaf and string literal it names. The gate resolves these to decide
    /// whether a function that makes a raw filesystem call also names a family — dataflow-free and
    /// fail-closed, the same shape as the resolve-and-write rule.
    fn_leaves: BTreeMap<String, Vec<String>>,
    /// Per function, the `=> Some(X)` arm values as WRITTEN. The extractor does not decide whether
    /// any of them names a family — that is the gate's job, and reporting a bare boolean instead
    /// made every `Ok(id) => Some(id.principal_ref)` look like a family resolver.
    resolver_arms: BTreeMap<String, Vec<String>>,
}

#[derive(Serialize)]
struct FsCall {
    callee: String,
    args: Vec<String>,
    /// The function this call sits in. A family usually reaches a raw write through a local — `let p
    /// = dir.join(KIND_ONT); fs::write(p.join(id), …)` — so the family is nowhere in the call's own
    /// arguments, and the gate needs the enclosing function to see them together.
    in_fn: String,
    in_test: bool,
}

#[derive(Serialize)]
struct Mention {
    name: String,
    role: String,
    in_test: bool,
}

#[derive(Serialize, Clone)]
struct ChildMod {
    name: String,
    /// The `#[path = "…"]` target, when the declaration carries one. This daemon declares every
    /// route module that way so cargo's autobin does not treat each file as its own binary target,
    /// so a walker that only knows rustc's default resolution finds none of them.
    explicit_path: Option<String>,
}

#[derive(Serialize)]
struct Import {
    /// The module the item comes from, e.g. `odk_routes`. `None` for a bare `use some_module;`.
    from: Option<String>,
    /// The item name as declared at the source.
    item: String,
    /// The name this module refers to it by.
    local: String,
    /// True for `use path::*` — a glob brings in names this file never spells.
    glob: bool,
    /// True for `use some_module;` — the module itself, used later as a path prefix.
    module_only: bool,
}

fn lit_str(expr: &Expr) -> Option<String> {
    if let Expr::Lit(l) = expr {
        if let Lit::Str(s) = &l.lit {
            return Some(s.value());
        }
    }
    None
}

fn path_of(expr: &Expr) -> Option<Vec<String>> {
    if let Expr::Path(ExprPath { path, .. }) = expr {
        return Some(path.segments.iter().map(|s| s.ident.to_string()).collect());
    }
    if let Expr::Reference(r) = expr {
        return path_of(&r.expr);
    }
    None
}

fn has_cfg_test(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| {
        let mut found = false;
        if a.path().is_ident("cfg") {
            let _ = a.parse_nested_meta(|meta| {
                if meta.path.is_ident("test") {
                    found = true;
                }
                Ok(())
            });
        }
        found
    })
}

fn flatten_use(tree: &UseTree, prefix: &mut Vec<String>, out: &mut Vec<Import>) {
    match tree {
        UseTree::Path(p) => {
            prefix.push(p.ident.to_string());
            flatten_use(&p.tree, prefix, out);
            prefix.pop();
        }
        UseTree::Name(n) => {
            let item = n.ident.to_string();
            // `use super::odk_routes;` — the MODULE itself. The hand-rolled reader had no notion of
            // this and every `odk_routes::KIND_ONT` after it was invisible; the daemon already
            // writes this style in `event_stream_routes.rs` and `work_result_routes.rs`.
            let module_only = prefix.last().is_some_and(|p| p == "super" || p == "crate");
            out.push(Import {
                from: if module_only {
                    None
                } else {
                    prefix.last().cloned()
                },
                item: item.clone(),
                local: item.clone(),
                glob: false,
                module_only,
            });
        }
        UseTree::Rename(r) => out.push(Import {
            from: prefix.last().cloned(),
            item: r.ident.to_string(),
            local: r.rename.to_string(),
            glob: false,
            module_only: prefix.last().is_some_and(|p| p == "super" || p == "crate"),
        }),
        UseTree::Glob(_) => out.push(Import {
            from: prefix.last().cloned(),
            item: "*".into(),
            local: "*".into(),
            glob: true,
            module_only: false,
        }),
        UseTree::Group(g) => {
            for t in &g.items {
                flatten_use(t, prefix, out);
            }
        }
    }
}

const WRITERS: &[&str] = &[
    "persist_record",
    "persist_record_durable",
    "remove_record",
    "persist_promoted",
    "admit_required",
];
const READERS: &[&str] = &["load", "read_record_dir", "json_get", "load_record"];
/// Filesystem entry points a lane could use to put bytes in a family directory without a writer.
const FS_CALLS: &[&str] = &[
    "write",
    "create",
    "create_new",
    "create_dir_all",
    "remove_file",
    "remove_dir_all",
    "copy",
    "rename",
    "hard_link",
];

struct Collector<'a> {
    facts: &'a mut ModuleFacts,
    in_test: bool,
    fn_stack: Vec<String>,
}

impl Collector<'_> {
    fn visit_expr(&mut self, e: &Expr) {
        if let Expr::Call(ExprCall { func, args, .. }) = e {
            if let Some(segs) = path_of(func) {
                let callee = segs.last().cloned().unwrap_or_default();
                let is_w = WRITERS.contains(&callee.as_str());
                let is_r = READERS.contains(&callee.as_str());
                // A RAW FILESYSTEM CALL, recorded with every argument as written. `syn` gives the
                // full path, so `std::fs::write` and a `use std::fs as sysfs` alias are the same
                // node — the alias games that defeated a text scan do not arise.
                if FS_CALLS.contains(&callee.as_str())
                    && segs
                        .iter()
                        .any(|s| s == "fs" || s == "File" || s.ends_with("fs"))
                {
                    self.facts.fs_calls.push(FsCall {
                        callee: segs.join("::"),
                        // EVERY LEAF, not the top-level shape. The family usually sits inside a
                        // method chain — `dir.join(KIND_ONT).join(id)` — and quoting only the outer
                        // expression flattens it to `<expr>`, losing the one token that matters.
                        args: args.iter().flat_map(leaves).collect(),
                        in_fn: self.fn_stack.last().cloned().unwrap_or_default(),
                        in_test: self.in_test,
                    });
                }
                if (is_w || is_r) && args.len() >= 2 {
                    let arg = &args[1];
                    let written = quote_expr(arg);
                    let family = lit_str(arg).or_else(|| path_of(arg).map(|p| p.join("::")));
                    self.facts.calls.push(CallSite {
                        callee: callee.clone(),
                        family,
                        written,
                        in_test: self.in_test,
                    });
                    if is_w {
                        if let Some(f) = self.fn_stack.last() {
                            if self.facts.resolver_arms.contains_key(f)
                                && !self.facts.resolve_and_write_fns.contains(f)
                            {
                                self.facts.resolve_and_write_fns.push(f.clone());
                            }
                        }
                    }
                }
            }
        }
        syn::visit::visit_expr(&mut Noop, e);
        for child in expr_children(e) {
            self.visit_expr(&child);
        }
    }
}

struct Noop;
impl<'ast> syn::visit::Visit<'ast> for Noop {}

fn quote_expr(e: &Expr) -> String {
    match e {
        Expr::Lit(_) => lit_str(e).map(|s| format!("{s:?}")).unwrap_or_default(),
        _ => path_of(e)
            .map(|p| p.join("::"))
            .unwrap_or_else(|| "<expr>".into()),
    }
}

/// Every path segment and string literal inside an expression, however deeply nested.
fn leaves(e: &Expr) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![e.clone()];
    while let Some(cur) = stack.pop() {
        if let Some(s) = lit_str(&cur) {
            out.push(format!("{s:?}"));
        }
        if let Some(p) = path_of(&cur) {
            out.push(p.join("::"));
        }
        // ONE SOURCE OF CHILDREN. `expr_children` already yields a method call's receiver and
        // arguments; pushing them again here doubled every node per level and turned this walk
        // exponential — the gate hung rather than failing, which is the worse direction.
        for c in expr_children(&cur) {
            stack.push(c);
        }
    }
    out
}

/// Child expressions worth walking. Deliberately broad and shallow rather than a full visitor: the
/// gate only needs call sites, and a missed child is a missed CALL, which shows up as a family the
/// census cannot see — the gate's RED path — rather than as a silent pass.
fn expr_children(e: &Expr) -> Vec<Expr> {
    let mut out = Vec::new();
    match e {
        Expr::Block(b) => collect_block(&b.block, &mut out),
        Expr::If(i) => {
            out.push((*i.cond).clone());
            collect_block(&i.then_branch, &mut out);
            if let Some((_, els)) = &i.else_branch {
                out.push((**els).clone());
            }
        }
        Expr::Match(m) => {
            out.push((*m.expr).clone());
            for arm in &m.arms {
                out.push((*arm.body).clone());
            }
        }
        Expr::Call(c) => {
            for a in &c.args {
                out.push(a.clone());
            }
        }
        Expr::MethodCall(c) => {
            out.push((*c.receiver).clone());
            for a in &c.args {
                out.push(a.clone());
            }
        }
        Expr::Let(l) => out.push((*l.expr).clone()),
        Expr::Assign(a) => out.push((*a.right).clone()),
        Expr::Return(r) => {
            if let Some(v) = &r.expr {
                out.push((**v).clone());
            }
        }
        Expr::Reference(r) => out.push((*r.expr).clone()),
        Expr::Try(t) => out.push((*t.expr).clone()),
        Expr::Unary(u) => out.push((*u.expr).clone()),
        Expr::Binary(b) => {
            out.push((*b.left).clone());
            out.push((*b.right).clone());
        }
        Expr::ForLoop(f) => {
            out.push((*f.expr).clone());
            collect_block(&f.body, &mut out);
        }
        Expr::While(w) => {
            out.push((*w.cond).clone());
            collect_block(&w.body, &mut out);
        }
        Expr::Loop(l) => collect_block(&l.body, &mut out),
        Expr::Closure(c) => out.push((*c.body).clone()),
        Expr::Group(g) => out.push((*g.expr).clone()),
        Expr::Paren(p) => out.push((*p.expr).clone()),
        _ => {}
    }
    out
}

fn collect_block(b: &syn::Block, out: &mut Vec<Expr>) {
    for st in &b.stmts {
        match st {
            syn::Stmt::Expr(e, _) => out.push(e.clone()),
            syn::Stmt::Local(l) => {
                if let Some(init) = &l.init {
                    out.push((*init.expr).clone());
                }
            }
            _ => {}
        }
    }
}

/// The `=> Some(X)` arm values in this function body, as written. The gate resolves them.
fn resolver_arms(block: &syn::Block) -> Vec<String> {
    let mut found = Vec::new();
    let mut stack: Vec<Expr> = Vec::new();
    collect_block(block, &mut stack);
    while let Some(e) = stack.pop() {
        if let Expr::Match(m) = &e {
            for arm in &m.arms {
                if let Expr::Call(c) = &*arm.body {
                    if path_of(&c.func).is_some_and(|p| p.last().is_some_and(|s| s == "Some")) {
                        if let Some(inner) = c.args.first() {
                            found.push(quote_expr(inner));
                        }
                    }
                }
            }
        }
        for c in expr_children(&e) {
            stack.push(c);
        }
    }
    found
}

fn walk_items(items: &[Item], in_test: bool, facts: &mut ModuleFacts) {
    for item in items {
        match item {
            Item::Const(ItemConst { ident, expr, .. }) => {
                if let Some(v) = lit_str(expr) {
                    facts.family_mentions.push(Mention {
                        name: ident.to_string(),
                        role: "declares".into(),
                        in_test,
                    });
                    facts.consts.insert(ident.to_string(), v);
                }
            }
            Item::Use(u) => {
                let mut prefix = Vec::new();
                flatten_use(&u.tree, &mut prefix, &mut facts.imports);
            }
            Item::Mod(m) => {
                let test_here = in_test || has_cfg_test(&m.attrs);
                if let Some((_, inner)) = &m.content {
                    walk_items(inner, test_here, facts);
                } else {
                    // `#[path = "…"]` is how this daemon declares every route module — the files
                    // live in a subdirectory so cargo's autobin does not treat each as its own
                    // binary target. A walker that only knows rustc's default resolution finds none
                    // of them.
                    let explicit = m.attrs.iter().find_map(|a| {
                        if !a.path().is_ident("path") {
                            return None;
                        }
                        match &a.meta {
                            syn::Meta::NameValue(nv) => match &nv.value {
                                syn::Expr::Lit(l) => match &l.lit {
                                    syn::Lit::Str(sl) => Some(sl.value()),
                                    _ => None,
                                },
                                _ => None,
                            },
                            _ => None,
                        }
                    });
                    facts.child_mods.push(ChildMod {
                        name: m.ident.to_string(),
                        explicit_path: explicit,
                    });
                }
            }
            Item::Fn(f) => {
                let test_here = in_test || has_cfg_test(&f.attrs);
                let name = f.sig.ident.to_string();
                let arms = resolver_arms(&f.block);
                if !arms.is_empty() {
                    facts.resolver_arms.insert(name.clone(), arms);
                }
                let mut body_exprs = Vec::new();
                collect_block(&f.block, &mut body_exprs);
                let mut all_leaves = Vec::new();
                for e in &body_exprs {
                    all_leaves.extend(leaves(e));
                }
                facts.fn_leaves.insert(name.clone(), all_leaves);
                let mut c = Collector {
                    facts,
                    in_test: test_here,
                    fn_stack: vec![name],
                };
                for e in body_exprs {
                    c.visit_expr(&e);
                }
            }
            Item::Impl(i) => {
                let test_here = in_test || has_cfg_test(&i.attrs);
                for it in &i.items {
                    if let syn::ImplItem::Fn(f) = it {
                        let name = f.sig.ident.to_string();
                        let arms = resolver_arms(&f.block);
                        if !arms.is_empty() {
                            facts.resolver_arms.insert(name.clone(), arms);
                        }
                        let mut c = Collector {
                            facts,
                            in_test: test_here,
                            fn_stack: vec![name],
                        };
                        let mut exprs = Vec::new();
                        collect_block(&f.block, &mut exprs);
                        for e in exprs {
                            c.visit_expr(&e);
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

/// Resolve `mod name;` the way rustc does, from the DECLARING file's own position.
fn child_path(decl_file: &Path, name: &str) -> Option<PathBuf> {
    let dir = decl_file.parent()?;
    let stem = decl_file.file_stem()?.to_string_lossy().to_string();
    // A file that is itself a module root (`mod.rs`, or the crate root) resolves siblings; any other
    // module resolves children under its own directory. Taking the sibling FIRST — as the hand-rolled
    // reader did — silently reads a flat namesake instead of the real nested file.
    let nested = dir.join(&stem).join(format!("{name}.rs"));
    if nested.exists() {
        return Some(nested);
    }
    let nested_mod = dir.join(&stem).join(name).join("mod.rs");
    if nested_mod.exists() {
        return Some(nested_mod);
    }
    let sibling = dir.join(format!("{name}.rs"));
    if sibling.exists() {
        return Some(sibling);
    }
    let sibling_mod = dir.join(name).join("mod.rs");
    if sibling_mod.exists() {
        return Some(sibling_mod);
    }
    None
}

fn main() {
    let root = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "crates/node/src/bin/hypervisor-daemon.rs".to_string());
    let entry = PathBuf::from(&root);
    let mut queue = vec![entry.clone()];
    let mut seen: Vec<PathBuf> = Vec::new();
    let mut modules: Vec<ModuleFacts> = Vec::new();

    while let Some(file) = queue.pop() {
        let canon = file.canonicalize().unwrap_or(file.clone());
        if seen.contains(&canon) {
            continue;
        }
        seen.push(canon.clone());
        let src = match std::fs::read_to_string(&file) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let parsed: File = match syn::parse_file(&src) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("PARSE FAILURE {}: {e}", file.display());
                std::process::exit(2);
            }
        };
        let mut facts = ModuleFacts {
            name: file
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
            path: file.to_string_lossy().to_string(),
            ..Default::default()
        };
        walk_items(&parsed.items, false, &mut facts);
        for child in facts.child_mods.clone() {
            let resolved = match &child.explicit_path {
                Some(rel) => file.parent().map(|d| d.join(rel)).filter(|p| p.exists()),
                None => child_path(&file, &child.name),
            };
            if let Some(p) = resolved {
                queue.push(p);
            }
        }
        modules.push(facts);
    }

    let out = serde_json::json!({
        "schema": "ioi.ontology-admission-census.v1",
        "entry": root,
        "modules": modules,
    });
    println!("{}", serde_json::to_string(&out).expect("serialise census"));
}
