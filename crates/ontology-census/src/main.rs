//! Ontology admission census EXTRACTOR — a real Rust parser, emitting the facts as JSON.
//!
//! Its own crate, deliberately. `syn` is a dev-dependency of `ioi-types`, whose note says it keeps
//! minimal dependencies to remain stable, and `.gitignore` excludes `examples/` wholesale, so an
//! example target would never reach CI. A small crate of its own puts the parser nowhere near a core
//! type crate's runtime graph and still ships.
//!
//! WHY THIS EXISTS, and why hand-rolling was abandoned TWICE. Next-legs XIV Leg 3a first built the
//! no-second-spine entailment by scanning the daemon's source with regexes. Three merge-blocking
//! review rounds each defeated it, and the defeats sorted into two buckets: CENSUS LOGIC (a rule that
//! was wrong or decorative) and LANGUAGE READING (a Rust construct the scanner mis-modelled). The
//! owner pre-committed the decision before round three ran: modelling the next construct retires an
//! INSTANCE, a real parser retires the CLASS.
//!
//! The first attempt at that ruling was executed IN NAME ONLY. `syn` was added to the dependency
//! graph, the files were parsed into an AST — and the traversal on top stayed hand-rolled, a private
//! `expr_children` covering roughly fifteen of syn's forty-odd `Expr` variants. A `Visit` impl with
//! ZERO overrides was instantiated and driven across every expression, so the code READ as though a
//! complete visitor were running while it did nothing at all. A fourth review demonstrated twelve of
//! fourteen ordinary second-admitter constructs passing green: `.await` (775 of them in this daemon),
//! `tokio::spawn` (34), impl methods (81 impl blocks), match-arm guards, struct literals, nested
//! items, `let … else`, `unsafe` blocks, macro arguments, method-call writers. The scar the owner
//! bound from it: A PRE-COMMITTED BOUNDARY IS EXECUTED BY ITS MECHANISM, NOT BY ITS DEPENDENCY.
//!
//! So the traversal here IS `syn::visit::Visit`, with overrides only where a fact must be recorded.
//! Every expression position, every `Stmt::Item`, every `ImplItem` and `TraitItem`, every arm guard
//! and `let … else` block is reached by syn's own default recursion. The one thing syn does not walk
//! is a macro's token stream, so that is scanned explicitly rather than left as a hole.
//!
//! POSITIVE CLASSIFICATION, NEVER ABSENCE. The same review found the deeper defect: a construct the
//! walk missed produced no entry, and every judgement downstream was derived from the entries — so a
//! COVERAGE GAP was indistinguishable from SAFETY. This tool therefore reports every mention of a
//! name of interest together with the SYNTACTIC ROLE it appears in, and the gate holds a closed set
//! of roles it can classify. A mention in a role the gate does not know is RED. A gap in coverage now
//! reads as a finding, which is the only direction that can be trusted.
//!
//! WHAT IT EMITS, and nothing more. This tool decides no policy — it does not know what an ontology
//! family is; the caller passes the prefixes it cares about. It reports what the source SAYS, and the
//! JavaScript gate decides what that means. Keeping extraction and judgement apart is what lets the
//! judgement keep its mutation anchors while the substrate underneath changes.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use proc_macro2::TokenTree;
use serde::Serialize;
use syn::visit::{self, Visit};
use syn::{Expr, File, Lit, UseTree};

/// This file's own bytes, baked in at COMPILE time. A binary built from different source reports a
/// different digest than the source on disk hashes to, which is how the gate refuses a stale
/// extractor without trusting a timestamp — cargo treats a source whose mtime moved backwards as
/// up-to-date, and an mtime comparison then passes on exactly the hazard it claims to catch.
const SELF_SOURCE: &str = include_str!("main.rs");

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    h
}

/// A name of interest, recorded WITH the syntactic role it appears in. The role is the gate's whole
/// defence against a coverage gap reading as safety: the gate classifies every role or goes RED.
#[derive(Serialize)]
struct Mention {
    name: String,
    role: String,
    in_fn: String,
    in_test: bool,
}

/// A call to a record writer or reader, with every leaf in its argument subtree.
#[derive(Serialize)]
struct CallSite {
    callee: String,
    kind: &'static str,
    /// Every string literal and constant-shaped path leaf anywhere under this call's arguments. The
    /// family usually sits inside a chain — `dir.join(KIND_ONT).join(id)` — so quoting the top-level
    /// argument flattens away the one token that matters.
    leaves: Vec<String>,
    in_fn: String,
    in_test: bool,
}

#[derive(Serialize)]
struct FsCall {
    callee: String,
    leaves: Vec<String>,
    in_fn: String,
    in_test: bool,
}

#[derive(Serialize, Clone)]
struct ChildMod {
    name: String,
    /// The `#[path = "…"]` target, when the declaration carries one. This daemon declares every route
    /// module that way so cargo's autobin does not treat each file as its own binary target, so a
    /// walker that only knows rustc's default resolution finds none of them.
    explicit_path: Option<String>,
    in_test: bool,
}

#[derive(Serialize)]
struct Import {
    /// The module the item comes from, e.g. `odk_routes`. `None` for a bare `use some_module;`.
    from: Option<String>,
    item: String,
    local: String,
    glob: bool,
    /// True for `use super::odk_routes;` and `use super::odk_routes as ont;` — the MODULE itself,
    /// used later as a path prefix. Both forms are in this daemon today, and a resolver that only
    /// matches item names treats every `ont::KIND_ONT` after one as an unresolvable runtime value.
    module_only: bool,
}

#[derive(Serialize, Default)]
struct ModuleFacts {
    /// THE IDENTITY: the module's path from the repo root. Keying by file stem collapses two files
    /// that share a basename into one module, which MERGES their admitters — precisely the hole this
    /// census exists to see. `hypervisor_daemon_routes/shadow/odk_routes.rs` reported as `odk_routes`
    /// once made a second admitter read as the recorded one.
    key: String,
    /// The file stem, for diagnostics and for resolving `mod::CONST` paths. Never an identity.
    stem: String,
    /// `const NAME: &str = "literal"` and `static NAME: &str = "literal"` declared in THIS module.
    /// Per-module, because the daemon declares 660 constants under 537 names and 25 of those names
    /// mean different things in different modules.
    consts: BTreeMap<String, String>,
    /// `const NAME: &str = other::PLACE;` — a constant defined as another constant. Three of these
    /// exist in this daemon and the previous resolver could follow none of them.
    const_refs: BTreeMap<String, String>,
    /// A constant whose initialiser this extractor cannot read to a literal — `concat!(…)`, a call, a
    /// cast. Reported, never dropped: the gate decides, and an unreadable initialiser whose tokens
    /// mention a name of interest is a finding, not an absence.
    const_opaque: Vec<String>,
    imports: Vec<Import>,
    child_mods: Vec<ChildMod>,
    calls: Vec<CallSite>,
    fs_calls: Vec<FsCall>,
    mentions: Vec<Mention>,
    /// Every function this module declares — free, impl method, or trait default — mapped to the
    /// leaves in its body. Declared for EVERY function, so a lookup miss is a real absence rather
    /// than the silent empty list an impl method used to produce for a third of this daemon.
    fn_leaves: BTreeMap<String, Vec<String>>,
    /// Per function, the leaves of every `=> Some(X)` match-arm value.
    resolver_arms: BTreeMap<String, Vec<String>>,
    /// Functions that both RESOLVE a family name and WRITE a record.
    resolve_and_write_fns: Vec<String>,
}

/// A constant-shaped identifier: the only shape a family name reaches a call site under, other than
/// a string literal, given Rust's naming lint.
fn is_const_ident(s: &str) -> bool {
    s.len() > 1
        && s.chars().any(|c| c.is_ascii_uppercase())
        && s.chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// TEST CLASSIFICATION FAILS TOWARD PRODUCTION. Only a bare `#[cfg(test)]` marks a subtree as test.
/// Anything that could compile into a production build — `cfg(any(test, …))`, `cfg(all(test, …))`,
/// `cfg_attr`, a feature gate — classifies as PRODUCTION. The direction matters: the recorded
/// admission map is built from production writes, and a test write mistaken for production only ever
/// widens what must be justified, while a production write mistaken for a test write silently
/// pre-authorises a second spine. That mistake was live: three families were recorded as
/// multi-admitter on the strength of fixtures, which authorised the fixture's module to write them
/// for real.
fn is_bare_cfg_test(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| {
        a.path().is_ident("cfg")
            && matches!(&a.meta, syn::Meta::List(l) if l.tokens.to_string().trim() == "test")
    })
}

fn path_segments(p: &syn::Path) -> Vec<String> {
    p.segments.iter().map(|s| s.ident.to_string()).collect()
}

/// Every string literal and constant-shaped path leaf under an expression, found by syn's own
/// recursion rather than a hand-rolled child list.
#[derive(Default)]
struct LeafGrab {
    out: Vec<String>,
}

impl<'ast> Visit<'ast> for LeafGrab {
    fn visit_expr(&mut self, e: &'ast Expr) {
        match e {
            Expr::Lit(l) => {
                if let Lit::Str(s) = &l.lit {
                    self.out.push(s.value());
                }
            }
            Expr::Path(p) => {
                let segs = path_segments(&p.path);
                if segs.last().is_some_and(|s| is_const_ident(s)) {
                    self.out.push(segs.join("::"));
                }
            }
            _ => {}
        }
        visit::visit_expr(self, e);
    }

    fn visit_macro(&mut self, m: &'ast syn::Macro) {
        grab_tokens(m.tokens.clone(), &mut self.out);
        visit::visit_macro(self, m);
    }
}

fn grab_tokens(ts: proc_macro2::TokenStream, out: &mut Vec<String>) {
    for t in ts {
        match t {
            TokenTree::Literal(l) => {
                let raw = l.to_string();
                if raw.starts_with('"') || raw.starts_with('r') {
                    if let Ok(s) = syn::parse_str::<syn::LitStr>(&raw) {
                        out.push(s.value());
                    }
                }
            }
            TokenTree::Ident(i) => {
                let n = i.to_string();
                if is_const_ident(&n) {
                    out.push(n);
                }
            }
            TokenTree::Group(g) => grab_tokens(g.stream(), out),
            TokenTree::Punct(_) => {}
        }
    }
}

/// Every identifier in a token stream, however deeply grouped.
fn macro_token_idents(ts: proc_macro2::TokenStream) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![ts];
    while let Some(s) = stack.pop() {
        for t in s {
            match t {
                TokenTree::Ident(i) => out.push(i.to_string()),
                TokenTree::Group(g) => stack.push(g.stream()),
                _ => {}
            }
        }
    }
    out
}

fn expr_leaves(e: &Expr) -> Vec<String> {
    let mut g = LeafGrab::default();
    g.visit_expr(e);
    g.out
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

/// THE CENSUS COLLECTOR — a real `syn::visit::Visit`. Every override records a fact and then hands
/// control back to syn's default recursion, so no construct is reachable only because this file
/// happens to name it.
struct Collector {
    facts: ModuleFacts,
    test_depth: usize,
    fn_stack: Vec<String>,
    /// The syntactic role a mention found right now sits in. Pushed by the constructs that give a
    /// name its meaning — a writer's arguments, a reader's, a raw filesystem call's, a constant's
    /// initialiser — and inherited by everything beneath.
    roles: Vec<String>,
    /// Indices into `facts.calls` / `facts.fs_calls` for the calls currently open, so every leaf
    /// found beneath one is attributed to it however deeply it nests.
    open_calls: Vec<usize>,
    open_fs: Vec<usize>,
    interests: Vec<String>,
    wrote_in_fn: Vec<bool>,
}

impl Collector {
    fn in_test(&self) -> bool {
        self.test_depth > 0
    }

    fn role(&self) -> String {
        self.roles
            .last()
            .cloned()
            .unwrap_or_else(|| "module".into())
    }

    fn cur_fn(&self) -> String {
        self.fn_stack.last().cloned().unwrap_or_default()
    }

    fn interesting(&self, s: &str) -> bool {
        self.interests.iter().any(|p| s.starts_with(p.as_str()))
    }

    /// Record one leaf: attribute it to every open call, to the enclosing function, and — when it is
    /// a name of interest — to the mention log with its role.
    fn leaf(&mut self, text: String) {
        for i in self.open_calls.clone() {
            self.facts.calls[i].leaves.push(text.clone());
        }
        for i in self.open_fs.clone() {
            self.facts.fs_calls[i].leaves.push(text.clone());
        }
        let f = self.cur_fn();
        if !f.is_empty() {
            self.facts
                .fn_leaves
                .entry(f.clone())
                .or_default()
                .push(text.clone());
        }
        // The interest test reads the LAST SEGMENT, not the whole path. Judging
        // `crate::ontology_projection_routes::RECORD_DIR` by the joined string finds a lowercase
        // character and discards it — which is exactly how a module that writes another module's
        // family under a fully-qualified path disappeared from the admitter map.
        let tail = text.rsplit("::").next().unwrap_or(&text).to_string();
        if self.interesting(&text) || is_const_ident(&tail) {
            let role = self.role();
            self.facts.mentions.push(Mention {
                name: text,
                role,
                in_fn: f,
                in_test: self.in_test(),
            });
        }
    }

    fn enter_fn(&mut self, name: String, attrs: &[syn::Attribute]) -> bool {
        let test = is_bare_cfg_test(attrs);
        if test {
            self.test_depth += 1;
        }
        self.facts.fn_leaves.entry(name.clone()).or_default();
        self.fn_stack.push(name);
        self.wrote_in_fn.push(false);
        self.roles.push("fn-body".into());
        test
    }

    fn exit_fn(&mut self, test: bool) {
        self.roles.pop();
        let wrote = self.wrote_in_fn.pop().unwrap_or(false);
        if let Some(name) = self.fn_stack.pop() {
            // RULE 7, structurally: a function that RESOLVES a family name may not also WRITE a
            // record. Conservative, dataflow-free, fail-closed — widening it later is a governed act.
            if wrote
                && self.facts.resolver_arms.contains_key(&name)
                && !self.facts.resolve_and_write_fns.contains(&name)
            {
                self.facts.resolve_and_write_fns.push(name);
            }
        }
        if test {
            self.test_depth -= 1;
        }
    }

    /// Classify a call, open it, and name the role its whole argument subtree inherits.
    fn open_call(&mut self, callee_segs: &[String], is_method: bool) -> (bool, bool, bool) {
        let Some(name) = callee_segs.last() else {
            return (false, false, false);
        };
        let is_w = WRITERS.contains(&name.as_str());
        let is_r = READERS.contains(&name.as_str());
        // A raw filesystem entry point, recognised on the FULL path syn gives, so `std::fs::write`
        // and a `use std::fs as sysfs` alias are the same node.
        let is_fs = FS_CALLS.contains(&name.as_str())
            && (is_method
                || callee_segs
                    .iter()
                    .any(|s| s == "fs" || s == "File" || s.ends_with("fs")));
        if is_w || is_r {
            self.facts.calls.push(CallSite {
                callee: callee_segs.join("::"),
                kind: if is_w { "write" } else { "read" },
                leaves: Vec::new(),
                in_fn: self.cur_fn(),
                in_test: self.in_test(),
            });
            let idx = self.facts.calls.len() - 1;
            self.open_calls.push(idx);
            self.roles
                .push(if is_w { "write-arg" } else { "read-arg" }.into());
            if is_w {
                if let Some(last) = self.wrote_in_fn.last_mut() {
                    *last = true;
                }
            }
            return (true, true, false);
        }
        if is_fs {
            self.facts.fs_calls.push(FsCall {
                callee: callee_segs.join("::"),
                leaves: Vec::new(),
                in_fn: self.cur_fn(),
                in_test: self.in_test(),
            });
            let idx = self.facts.fs_calls.len() - 1;
            self.open_fs.push(idx);
            self.roles.push("fs-arg".into());
            return (true, false, true);
        }
        (false, false, false)
    }

    fn close_call(&mut self, opened: (bool, bool, bool)) {
        let (opened_any, was_record, was_fs) = opened;
        if !opened_any {
            return;
        }
        self.roles.pop();
        if was_record {
            self.open_calls.pop();
        }
        if was_fs {
            self.open_fs.pop();
        }
    }
}

impl<'ast> Visit<'ast> for Collector {
    fn visit_expr(&mut self, e: &'ast Expr) {
        match e {
            Expr::Lit(l) => {
                if let Lit::Str(s) = &l.lit {
                    self.leaf(s.value());
                }
            }
            Expr::Path(p) => {
                let segs = path_segments(&p.path);
                if segs.last().is_some_and(|s| is_const_ident(s)) {
                    self.leaf(segs.join("::"));
                }
            }
            _ => {}
        }
        let opened = match e {
            Expr::Call(c) => match &*c.func {
                Expr::Path(p) => self.open_call(&path_segments(&p.path), false),
                _ => (false, false, false),
            },
            Expr::MethodCall(m) => self.open_call(&[m.method.to_string()], true),
            _ => (false, false, false),
        };
        visit::visit_expr(self, e);
        self.close_call(opened);
    }

    /// syn does not walk a macro's tokens — they are not parsed as expressions. Left alone this is a
    /// hole exactly the size of `json!`, `format!` and `write!`, so the tokens are scanned here.
    fn visit_macro(&mut self, m: &'ast syn::Macro) {
        let mac = path_segments(&m.path).last().cloned().unwrap_or_default();
        let mut found = Vec::new();
        grab_tokens(m.tokens.clone(), &mut found);
        // A WRITER CALL INSIDE MACRO TOKENS IS STILL A WRITER CALL. syn hands over the token stream
        // unparsed, so `json!({ "w": persist_record(d, KIND, id, r) })` reaches `visit_expr` as
        // nothing at all. Naming a writer anywhere in the tokens re-attributes every family leaf in
        // them to the writing role — over-attribution, deliberately, because the alternative is a
        // write the census reports as a mere mention.
        let names_writer = macro_token_idents(m.tokens.clone())
            .iter()
            .any(|i| WRITERS.contains(&i.as_str()));
        self.roles.push(if names_writer {
            "write-arg".to_string()
        } else {
            format!("macro:{mac}")
        });
        for t in found {
            self.leaf(t);
        }
        self.roles.pop();
        visit::visit_macro(self, m);
    }

    fn visit_item_const(&mut self, i: &'ast syn::ItemConst) {
        let test = is_bare_cfg_test(&i.attrs);
        if test {
            self.test_depth += 1;
        }
        self.record_const(&i.ident.to_string(), &i.expr);
        self.roles.push("const-init".into());
        visit::visit_item_const(self, i);
        self.roles.pop();
        if test {
            self.test_depth -= 1;
        }
    }

    /// `static` was invisible to the previous extractor entirely, so the rule forbidding a foreign
    /// module from DECLARING a family name was defeated by changing one keyword.
    fn visit_item_static(&mut self, i: &'ast syn::ItemStatic) {
        let test = is_bare_cfg_test(&i.attrs);
        if test {
            self.test_depth += 1;
        }
        self.record_const(&i.ident.to_string(), &i.expr);
        self.roles.push("static-init".into());
        visit::visit_item_static(self, i);
        self.roles.pop();
        if test {
            self.test_depth -= 1;
        }
    }

    fn visit_item_use(&mut self, i: &'ast syn::ItemUse) {
        let mut prefix = Vec::new();
        flatten_use(&i.tree, &mut prefix, &mut self.facts.imports);
        visit::visit_item_use(self, i);
    }

    fn visit_item_mod(&mut self, i: &'ast syn::ItemMod) {
        let test = is_bare_cfg_test(&i.attrs);
        if test {
            self.test_depth += 1;
        }
        if i.content.is_none() {
            let explicit = i.attrs.iter().find_map(|a| {
                if !a.path().is_ident("path") {
                    return None;
                }
                match &a.meta {
                    syn::Meta::NameValue(nv) => match &nv.value {
                        Expr::Lit(l) => match &l.lit {
                            Lit::Str(sl) => Some(sl.value()),
                            _ => None,
                        },
                        _ => None,
                    },
                    _ => None,
                }
            });
            self.facts.child_mods.push(ChildMod {
                name: i.ident.to_string(),
                explicit_path: explicit,
                in_test: self.in_test(),
            });
        }
        visit::visit_item_mod(self, i);
        if test {
            self.test_depth -= 1;
        }
    }

    fn visit_item_fn(&mut self, i: &'ast syn::ItemFn) {
        let t = self.enter_fn(i.sig.ident.to_string(), &i.attrs);
        visit::visit_item_fn(self, i);
        self.exit_fn(t);
    }

    /// Impl methods are 81 blocks of this daemon's house style. The previous extractor ran a
    /// collector over them but never created their `fn_leaves` entry, so the raw-filesystem rule's
    /// "and the function around it names a family" half looked up an empty list for 32% of the
    /// production filesystem calls in the tree — dead for every one of them.
    fn visit_impl_item_fn(&mut self, i: &'ast syn::ImplItemFn) {
        let t = self.enter_fn(i.sig.ident.to_string(), &i.attrs);
        visit::visit_impl_item_fn(self, i);
        self.exit_fn(t);
    }

    fn visit_trait_item_fn(&mut self, i: &'ast syn::TraitItemFn) {
        let t = self.enter_fn(i.sig.ident.to_string(), &i.attrs);
        visit::visit_trait_item_fn(self, i);
        self.exit_fn(t);
    }

    fn visit_item_impl(&mut self, i: &'ast syn::ItemImpl) {
        let test = is_bare_cfg_test(&i.attrs);
        if test {
            self.test_depth += 1;
        }
        visit::visit_item_impl(self, i);
        if test {
            self.test_depth -= 1;
        }
    }

    fn visit_expr_match(&mut self, m: &'ast syn::ExprMatch) {
        for arm in &m.arms {
            if let Expr::Call(c) = &*arm.body {
                if let Expr::Path(p) = &*c.func {
                    if path_segments(&p.path).last().is_some_and(|s| s == "Some") {
                        if let Some(inner) = c.args.first() {
                            let leaves = expr_leaves(inner);
                            if !leaves.is_empty() {
                                self.facts
                                    .resolver_arms
                                    .entry(self.cur_fn())
                                    .or_default()
                                    .extend(leaves);
                            }
                        }
                    }
                }
            }
        }
        visit::visit_expr_match(self, m);
    }
}

impl Collector {
    fn record_const(&mut self, name: &str, expr: &Expr) {
        match expr {
            Expr::Lit(l) => match &l.lit {
                Lit::Str(s) => {
                    self.facts.consts.insert(name.to_string(), s.value());
                }
                _ => self.facts.const_opaque.push(name.to_string()),
            },
            Expr::Path(p) => {
                self.facts
                    .const_refs
                    .insert(name.to_string(), path_segments(&p.path).join("::"));
            }
            Expr::Reference(r) => self.record_const(name, &r.expr),
            _ => self.facts.const_opaque.push(name.to_string()),
        }
    }
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
        UseTree::Rename(r) => {
            let module_only = prefix.last().is_some_and(|p| p == "super" || p == "crate");
            out.push(Import {
                from: if module_only {
                    None
                } else {
                    prefix.last().cloned()
                },
                item: r.ident.to_string(),
                local: r.rename.to_string(),
                glob: false,
                module_only,
            });
        }
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

/// Resolve `mod name;` the way rustc does, from the DECLARING file's own position. A file that is
/// itself a module root resolves siblings; any other module resolves children under its own
/// directory. Taking the sibling FIRST silently reads a flat namesake instead of the real nested file.
fn child_path(decl_file: &Path, name: &str) -> Option<PathBuf> {
    let dir = decl_file.parent()?;
    let stem = decl_file.file_stem()?.to_string_lossy().to_string();
    for cand in [
        dir.join(&stem).join(format!("{name}.rs")),
        dir.join(&stem).join(name).join("mod.rs"),
        dir.join(format!("{name}.rs")),
        dir.join(name).join("mod.rs"),
    ] {
        if cand.exists() {
            return Some(cand);
        }
    }
    None
}

fn repo_key(p: &Path, root: &Path) -> String {
    p.strip_prefix(root)
        .unwrap_or(p)
        .to_string_lossy()
        .replace('\\', "/")
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mut entry = String::new();
    let mut interests: Vec<String> = Vec::new();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--interest" => interests.push(args.next().unwrap_or_default()),
            other => entry = other.to_string(),
        }
    }
    if entry.is_empty() {
        entry = "crates/node/src/bin/hypervisor-daemon.rs".to_string();
    }
    let entry_path = PathBuf::from(&entry);
    let repo_root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

    let mut queue = vec![entry_path.clone()];
    let mut seen: Vec<PathBuf> = Vec::new();
    let mut modules: Vec<ModuleFacts> = Vec::new();

    while let Some(file) = queue.pop() {
        let canon = file.canonicalize().unwrap_or_else(|_| file.clone());
        if seen.contains(&canon) {
            continue;
        }
        seen.push(canon.clone());
        // A module the walker cannot READ is not a module it may skip: the census's closed world is
        // exactly the set of files it opened, and a silent `continue` shrinks that world without
        // shrinking the claim.
        let src = match std::fs::read_to_string(&file) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("UNREADABLE MODULE {}: {e}", file.display());
                std::process::exit(2);
            }
        };
        let parsed: File = match syn::parse_file(&src) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("PARSE FAILURE {}: {e}", file.display());
                std::process::exit(2);
            }
        };
        let mut c = Collector {
            facts: ModuleFacts {
                key: repo_key(&canon, &repo_root),
                stem: file
                    .file_stem()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string(),
                ..Default::default()
            },
            test_depth: 0,
            fn_stack: Vec::new(),
            roles: Vec::new(),
            open_calls: Vec::new(),
            open_fs: Vec::new(),
            interests: interests.clone(),
            wrote_in_fn: Vec::new(),
        };
        for item in &parsed.items {
            c.visit_item(item);
        }
        let facts = c.facts;
        for child in &facts.child_mods {
            let resolved = match &child.explicit_path {
                Some(rel) => file.parent().map(|d| d.join(rel)).filter(|p| p.exists()),
                None => child_path(&file, &child.name),
            };
            match resolved {
                Some(p) => queue.push(p),
                None => {
                    // An unresolvable `mod` is a module the census cannot see. Dropping it silently
                    // is how a census loses eight modules and still reports a passing count.
                    eprintln!(
                        "UNRESOLVED MODULE `{}` declared in {}",
                        child.name,
                        file.display()
                    );
                    std::process::exit(2);
                }
            }
        }
        modules.push(facts);
    }

    let out = serde_json::json!({
        "schema": "ioi.ontology-admission-census.v2",
        "entry": entry,
        "extractor_source_fnv1a64": format!("{:016x}", fnv1a64(SELF_SOURCE.as_bytes())),
        "interests": interests,
        "writers": WRITERS,
        "readers": READERS,
        "fs_calls": FS_CALLS,
        "modules": modules,
    });
    println!("{}", serde_json::to_string(&out).expect("serialise census"));
}
