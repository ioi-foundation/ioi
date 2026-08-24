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
//! complete visitor were running while it did nothing at all. A fourth review demonstrated ordinary
//! second-admitter constructs passing green against it — every one of them is now a committed anchor
//! of class `construct` in `apps/hypervisor/ontology-admission-census.mutants.v1.json`, replayable
//! rather than recounted. The scar the owner bound from it:
//! A PRE-COMMITTED BOUNDARY IS EXECUTED BY ITS MECHANISM, NOT BY ITS DEPENDENCY. So the traversal
//! here IS `syn::visit::Visit`, with overrides only where a fact must be recorded.
//!
//! AND WHY A CLOSED SET OF ROLES WAS STILL NOT ENOUGH. The fourth round's repair reported every
//! mention WITH its syntactic role and let the gate hold a closed set of roles, so that a construct
//! the walk stopped reading would surface as an UNKNOWN ROLE rather than as an absence. A fifth
//! review defeated that too, and the diagnosis the owner bound as a scar is exact:
//!
//!     A CLOSED SET OF ROLES CLOSES NOTHING UNLESS THE SET OF THINGS THAT PRODUCE A ROLE IS ITSELF
//!     ENTAILED.
//!
//! Roles were produced by AST positions this file happened to override. A family name in a position
//! no override reached — a `match` arm PATTERN, an attribute's tokens, a byte string, a file pulled
//! in by `include!`, a name assembled by `concat!` from pieces none of which is a family name —
//! produced NO mention at all, so there was no role to be unknown about. Ten such mutants were
//! planted; SEVEN of them passed the landing gate completely green once the mutant's own commit
//! re-derived its population pins, which is what a landing commit does as a matter of routine. Only
//! three were caught on a claim. Every one of the ten is a committed anchor in
//! `apps/hypervisor/ontology-admission-census.mutants.v1.json`, so that count is replayable against
//! the commit before this one rather than asserted here.
//!
//! SO MENTIONS ARE DERIVED FROM THE RAW TOKEN STREAM, AND THE AST ONLY ASSIGNS ROLES. Every file is
//! parsed ONCE into a `proc_macro2::TokenStream`; that stream is walked exhaustively — every literal,
//! every identifier, at every depth of every group — and it is the TOTAL population of mentions, by
//! construction, because a name that is in the file is a token in the file. The same stream is then
//! handed to `syn` and the visitor labels the positions it understands. The gate matches the two by
//! SOURCE POSITION. A token the role-assigner never labelled is a SILENT MENTION and is RED. A
//! coverage gap can no longer read as safety, because the thing being counted is no longer produced
//! by the thing that might be incomplete.
//!
//! TWO TOTALITY EDGES, both fail-closed, because "the tokens of the file" is only total if the set
//! of files and the set of tokens are themselves total:
//!   1. `include!` SPLICES another file's tokens into this one. A target this walk has not read is
//!      RED-UNRESOLVED and aborts extraction — never absent. Resolved targets are spliced into the
//!      INCLUDING module's facts, which is what `include!` means.
//!   2. A CONSTRUCTED name never appears as a token. `concat!` and `stringify!` are FOLLOWED INTO
//!      THEIR EXPANSION and the assembled value is emitted as a synthesised mention at the macro's
//!      own position; an assembly with a piece this census cannot read is reported as unreadable and
//!      the gate refuses it.
//!
//! AND TWO BOUNDARIES THAT ARE NAMED RATHER THAN CLOSED, because a design that has been falsified
//! twice does not earn a third hardening edge — that is construct-modelling one layer up, and the
//! owner ruled it out by name.
//!
//!   · THE FILE SET IS NOT RUSTC'S FILE SET. `mod` has no totality edge equivalent to `include!`'s
//!     and is not getting one. A `#[cfg_attr(…, path = …)]` redirect is invisible here — this walk
//!     reads only a bare `#[path]` — and a `mod` declared inside a `macro_rules!` body never reaches
//!     `visit_item_mod` at all, because syn hands macro tokens over unparsed. In both cases rustc
//!     compiles one file and this census reads another, or none. Demonstrated: a syntactically
//!     invalid decoy makes the daemon build clean and this extractor exit non-zero. Neither
//!     construct exists in the daemon today; entailing the file set belongs to the run that entails
//!     the resolver.
//!   · RESOLUTION IS NOT TOTAL, AND THAT IS THE REAL BOUND. See the gate's header: the token
//!     population is total, but the population the gate JUDGES is `token ∩ resolves-to-a-family`,
//!     and resolution is a partial function. Its failures are no longer silent — every one is
//!     counted in a named, pinned bucket — but they are not adjudicated either.
//!
//! WHAT IT EMITS, and nothing more. This tool decides no policy — it does not know what an ontology
//! family is; the caller passes the prefixes it cares about. It reports what the source SAYS, and the
//! JavaScript gate decides what that means. Keeping extraction and judgement apart is what lets the
//! judgement keep its mutation anchors while the substrate underneath changes.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use proc_macro2::{LineColumn, TokenStream, TokenTree};
use serde::Serialize;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, File, Lit, Pat, UseTree};

/// This file's own bytes, baked in at COMPILE time, so the binary can report which source it was
/// built from. It is NOT compared against the source on disk — a digest the gate computes from the
/// same source it then builds certifies nothing, because tampering moves both sides. The gate holds
/// a COMMITTED PIN and compares both the binary's baked digest and the on-disk bytes against it.
const SELF_SOURCE: &str = include_str!("main.rs");

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    h
}

/// A name of interest, recorded WITH the syntactic role it appears in AND the source position the
/// token walk will independently have found. The position is what makes the two populations
/// comparable; the role is what the gate classifies.
#[derive(Serialize)]
struct Mention {
    name: String,
    role: String,
    in_fn: String,
    in_test: bool,
    src: String,
    line: usize,
    col: usize,
    /// True when this value was SYNTHESISED rather than read from a token — the expansion of a
    /// compile-time `concat!`/`stringify!`. No single token carries the assembled text, so the
    /// gate's reverse totality check exempts these and pins them separately.
    synthesized: bool,
}

/// EVERY literal and constant-shaped identifier in the file's raw token stream. This is the census's
/// total population: the AST assigns roles to positions in here, and a position it never assigns is
/// the finding.
#[derive(Serialize)]
struct TokenMention {
    text: String,
    /// `str` for a string literal (raw forms included), `byte-str` for `b"…"`, `ident` for a
    /// constant-shaped identifier. Byte strings are here because they were a live silence: a family
    /// name spelled `b"odk-…"` reached a writer through `from_utf8` with no mention at all.
    kind: &'static str,
    src: String,
    line: usize,
    col: usize,
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

/// Every syntactically direct free-function call. M03.4 uses this population to resolve owner-seam
/// calls after the complete module (including all `use` aliases) has been visited.
#[derive(Serialize)]
struct NamedCall {
    callee: String,
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

/// An `include!`/`include_str!`/`include_bytes!` site. `include!` SPLICES Rust source and is
/// followed; the other two carry data and are recorded so the gate can pin the population.
#[derive(Serialize)]
struct IncludeSite {
    mac: String,
    arg: Option<String>,
    resolved: Option<String>,
    spliced: bool,
    in_test: bool,
    src: String,
    line: usize,
}

/// A string ASSEMBLY. Compile-time assemblies (`concat!`, `stringify!`) are recorded wherever they
/// appear and followed into their expansion when readable. Runtime assemblies are recorded only
/// where they sit inside a writer's or filesystem call's own arguments — the population the gate
/// judges — and the boundary is the open-call stack, not a name list.
#[derive(Serialize)]
struct Assembly {
    kind: String,
    compile_time: bool,
    pieces: Vec<String>,
    readable: bool,
    assembled: Option<String>,
    in_fn: String,
    in_test: bool,
    in_write_arg: bool,
    in_fs_arg: bool,
    src: String,
    line: usize,
    col: usize,
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
    /// Every file whose tokens are part of this module — the module's own file first, then anything
    /// `include!` spliced into it.
    sources: Vec<String>,
    /// `const NAME: &str = "literal"` and `static NAME: &str = "literal"` declared in THIS module.
    /// Per-module, because the daemon declares hundreds of constants and some names mean different
    /// things in different modules.
    consts: BTreeMap<String, String>,
    /// `Type::NAME` associated constants, keyed by their qualified spelling. Kept out of `consts`
    /// because Rust namespaces them by type and flattening them into the module map would let one
    /// impl's constant answer for a bare name it does not define.
    assoc_consts: BTreeMap<String, String>,
    /// `const NAME: &str = other::PLACE;` — a constant defined as another constant.
    const_refs: BTreeMap<String, String>,
    /// A constant whose initialiser this extractor cannot read to a literal — `env!(…)`, a call, a
    /// cast. Reported, never dropped: the gate decides, and an unreadable initialiser is a finding.
    const_opaque: Vec<String>,
    imports: Vec<Import>,
    child_mods: Vec<ChildMod>,
    calls: Vec<CallSite>,
    named_calls: Vec<NamedCall>,
    fs_calls: Vec<FsCall>,
    mentions: Vec<Mention>,
    token_mentions: Vec<TokenMention>,
    includes: Vec<IncludeSite>,
    assemblies: Vec<Assembly>,
    /// Every function this module declares — free, impl method, or trait default — mapped to the
    /// leaves in its body. Declared for EVERY function, so a lookup miss is a real absence rather
    /// than the silent empty list an impl method used to produce.
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

/// The position a path MENTION is anchored at: its LAST segment's identifier, which is the token the
/// raw walk independently records. Anchoring at the whole path's span would not correspond to any
/// single token and the two populations could never be matched.
fn path_pos(p: &syn::Path) -> LineColumn {
    p.segments
        .last()
        .map(|s| s.ident.span().start())
        .unwrap_or(LineColumn { line: 0, column: 0 })
}

/// A string literal's value, whether it is written `"…"`, `r#"…"#` or `b"…"`. Byte strings were a
/// live silence: `std::str::from_utf8(b"odk-…")` put a family name in a writer's arguments with no
/// mention recorded anywhere.
fn lit_text(l: &Lit) -> Option<String> {
    match l {
        Lit::Str(s) => Some(s.value()),
        Lit::ByteStr(b) => String::from_utf8(b.value()).ok(),
        // `c"odk-…"`. A review found this exact hole after byte strings were added for the same
        // reason: the population claim is over EVERY literal form the language has, and enumerating
        // two of three is the claim being false about the third.
        Lit::CStr(c) => c.value().to_str().ok().map(str::to_owned),
        _ => None,
    }
}

fn token_lit_text(l: &proc_macro2::Literal) -> Option<(String, &'static str)> {
    let raw = l.to_string();
    if let Ok(s) = syn::parse_str::<syn::LitStr>(&raw) {
        return Some((s.value(), "str"));
    }
    if let Ok(b) = syn::parse_str::<syn::LitByteStr>(&raw) {
        return String::from_utf8(b.value()).ok().map(|v| (v, "byte-str"));
    }
    if let Ok(c) = syn::parse_str::<syn::LitCStr>(&raw) {
        return c.value().to_str().ok().map(|v| (v.to_owned(), "c-str"));
    }
    None
}

/// THE TOTAL POPULATION. Every literal and every constant-shaped identifier in a token stream, at
/// every depth of every group, with the position of the token itself. Nothing here consults the AST,
/// which is the point: a construct syn models badly, or a position this file forgot to override,
/// cannot remove a token from a file.
fn token_walk(ts: TokenStream, src: &str, out: &mut Vec<TokenMention>) {
    for t in ts {
        match t {
            TokenTree::Literal(l) => {
                if let Some((v, kind)) = token_lit_text(&l) {
                    let p = l.span().start();
                    out.push(TokenMention {
                        text: v,
                        kind,
                        src: src.to_string(),
                        line: p.line,
                        col: p.column,
                    });
                }
            }
            TokenTree::Ident(i) => {
                let n = i.to_string();
                if is_const_ident(&n) {
                    let p = i.span().start();
                    out.push(TokenMention {
                        text: n,
                        kind: "ident",
                        src: src.to_string(),
                        line: p.line,
                        col: p.column,
                    });
                }
            }
            TokenTree::Group(g) => token_walk(g.stream(), src, out),
            TokenTree::Punct(_) => {}
        }
    }
}

/// Every string literal and constant-shaped path leaf under an expression, found by syn's own
/// recursion rather than a hand-rolled child list. Used where only the VALUES matter.
#[derive(Default)]
struct LeafGrab {
    out: Vec<String>,
}

impl<'ast> Visit<'ast> for LeafGrab {
    fn visit_expr(&mut self, e: &'ast Expr) {
        match e {
            Expr::Lit(l) => {
                if let Some(v) = lit_text(&l.lit) {
                    self.out.push(v);
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
        for (v, _) in token_values(m.tokens.clone()) {
            self.out.push(v);
        }
        visit::visit_macro(self, m);
    }
}

/// Literal values and constant-shaped identifiers in a token stream, WITH their positions AND WITH
/// THEIR PATH QUALIFIERS.
///
/// REBUILDING THE QUALIFIER IS NOT A NICETY — IT IS THE DIFFERENCE BETWEEN A RIGHT ANSWER AND A
/// CONFIDENT WRONG ONE. An earlier version recorded `TokenTree::Ident` bare, so
/// `json!({ "w": persist_record(d, super::odk_routes::KIND_ONT, i, r) })` produced the mention
/// `KIND_ONT` with the qualifier thrown away. The gate then resolved that bare tail against the
/// LOCAL module's constant table — and a module declaring its own `const KIND_ONT` made the census
/// adjudicate another module's family constant as innocent, at zero delta to every pin. Twenty-three
/// constant names in this daemon are declared in more than one module with different values, so the
/// collision is ordinary rather than contrived.
///
/// The qualifier is IN THE TOKENS; only this function was discarding it. `::` arrives as two joint
/// `Punct(':')`, so walking back over `Ident ':' ':'` reassembles the path rustc actually resolves,
/// and the position stays the LAST segment's — the same anchor the raw token walk and the AST both
/// record, so the three populations still match.
fn token_values(ts: TokenStream) -> Vec<(String, LineColumn)> {
    let mut out = Vec::new();
    fn walk(ts: TokenStream, out: &mut Vec<(String, LineColumn)>) {
        let items: Vec<TokenTree> = ts.into_iter().collect();
        for (i, t) in items.iter().enumerate() {
            match t {
                TokenTree::Literal(l) => {
                    if let Some((v, _)) = token_lit_text(l) {
                        out.push((v, l.span().start()));
                    }
                }
                TokenTree::Ident(id) => {
                    let n = id.to_string();
                    if !is_const_ident(&n) {
                        continue;
                    }
                    let mut segs = vec![n];
                    let mut j = i;
                    while j >= 3
                        && matches!(&items[j - 1], TokenTree::Punct(p) if p.as_char() == ':')
                        && matches!(&items[j - 2], TokenTree::Punct(p) if p.as_char() == ':')
                    {
                        let TokenTree::Ident(prev) = &items[j - 3] else {
                            break;
                        };
                        segs.push(prev.to_string());
                        j -= 3;
                    }
                    segs.reverse();
                    out.push((segs.join("::"), id.span().start()));
                }
                TokenTree::Group(g) => walk(g.stream(), out),
                TokenTree::Punct(_) => {}
            }
        }
    }
    walk(ts, &mut out);
    out
}

fn expr_leaves(e: &Expr) -> Vec<String> {
    let mut g = LeafGrab::default();
    g.visit_expr(e);
    g.out
}

/// Split a macro's tokens on top-level commas — `concat!`'s argument list.
fn comma_pieces(ts: TokenStream) -> Vec<Vec<TokenTree>> {
    let mut out: Vec<Vec<TokenTree>> = vec![Vec::new()];
    for t in ts {
        if let TokenTree::Punct(p) = &t {
            if p.as_char() == ',' {
                out.push(Vec::new());
                continue;
            }
        }
        out.last_mut().expect("non-empty").push(t);
    }
    if out.last().is_some_and(|v| v.is_empty()) {
        out.pop();
    }
    out
}

const WRITERS: &[&str] = &[
    "persist_record",
    "persist_record_durable",
    "remove_record",
    "persist_promoted",
    "admit_required",
];
const READERS: &[&str] = &["load", "read_record_dir", "json_get", "load_record"];
/// Cross-module owner seams introduced by M03.4. They are not record writers themselves at the
/// call site, but every production caller is part of the authority boundary and must be surfaced
/// to the verifier. Otherwise moving a literal write behind a `pub(crate)` function merely moves
/// the census blind spot one call outward.
const OWNER_SEAMS: &[&str] = &[
    "persist_execution_state",
    "persist_materialized_state",
    "run_receipt_checked",
];
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
/// COMPILE-TIME name assembly: the two constructs that can produce a `&'static str` family name
/// without the name ever existing as a token. Both are followed into their expansion.
const COMPILE_ASSEMBLY: &[&str] = &["concat", "stringify"];
/// RUNTIME assembly. Recorded only inside a writer's or filesystem call's own arguments.
const ASSEMBLY_MACROS: &[&str] = &[
    "format",
    "format_args",
    "write",
    "writeln",
    "print",
    "println",
    "eprint",
    "eprintln",
    "panic",
];
const ASSEMBLY_METHODS: &[&str] = &[
    "push_str",
    "join",
    "concat",
    "replace",
    "replacen",
    "insert_str",
    "to_owned",
    "to_string",
];
/// The file-splicing and file-reading macros. `include!` is followed; the data forms are pinned.
const INCLUDE_MACROS: &[&str] = &["include", "include_str", "include_bytes"];

/// THE CENSUS COLLECTOR — a real `syn::visit::Visit`. Every override records a fact and then hands
/// control back to syn's default recursion, so no construct is reachable only because this file
/// happens to name it. The visitor's job is to LABEL positions; the token walk owns the population.
struct Collector {
    facts: ModuleFacts,
    test_depth: usize,
    fn_stack: Vec<String>,
    /// The syntactic role a mention found right now sits in. Pushed by the constructs that give a
    /// name its meaning — a writer's arguments, a reader's, a raw filesystem call's, a constant's
    /// initialiser, a pattern, an attribute — and inherited by everything beneath.
    roles: Vec<String>,
    /// Indices into `facts.calls` / `facts.fs_calls` for the calls currently open, so every leaf
    /// found beneath one is attributed to it however deeply it nests.
    open_calls: Vec<usize>,
    open_fs: Vec<usize>,
    interests: Vec<String>,
    wrote_in_fn: Vec<bool>,
    /// The enclosing `impl`/`trait` type name, so an associated constant is recorded under the
    /// qualified spelling that actually reaches it.
    impl_ty: Vec<String>,
    /// The file whose tokens are being labelled right now — the module's own, or a spliced include.
    cur_src: String,
}

impl Collector {
    fn in_test(&self) -> bool {
        self.test_depth > 0
    }

    fn cur_impl_ty(&self) -> String {
        self.impl_ty.last().cloned().unwrap_or_default()
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
    /// a name of interest — to the mention log with its role and the position of the token it came
    /// from. The position is what lets the gate match this population against the token walk's.
    fn leaf(&mut self, text: String, pos: LineColumn) {
        self.leaf_at(text, pos, None, false);
    }

    fn leaf_at(&mut self, text: String, pos: LineColumn, role: Option<&str>, synthesized: bool) {
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
            let role = role.map(|r| r.to_string()).unwrap_or_else(|| self.role());
            self.facts.mentions.push(Mention {
                name: text,
                role,
                in_fn: f,
                in_test: self.in_test(),
                src: self.cur_src.clone(),
                line: pos.line,
                col: pos.column,
                synthesized,
            });
        }
    }

    /// Label a whole token stream — a macro's arguments, an attribute's tokens — under one role.
    fn token_leaves(&mut self, ts: TokenStream, role: &str) {
        self.roles.push(role.to_string());
        for (v, p) in token_values(ts) {
            self.leaf(v, p);
        }
        self.roles.pop();
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

    fn record_assembly(
        &mut self,
        kind: String,
        compile_time: bool,
        pieces: Vec<String>,
        readable: bool,
        assembled: Option<String>,
        pos: LineColumn,
    ) {
        self.facts.assemblies.push(Assembly {
            kind,
            compile_time,
            pieces,
            readable,
            assembled,
            in_fn: self.cur_fn(),
            in_test: self.in_test(),
            in_write_arg: !self.open_calls.is_empty(),
            in_fs_arg: !self.open_fs.is_empty(),
            src: self.cur_src.clone(),
            line: pos.line,
            col: pos.column,
        });
    }

    /// FOLLOW A COMPILE-TIME ASSEMBLY INTO ITS EXPANSION. `concat!("od", "k-domain-ontologies")`
    /// names a family that appears in no token; evaluating it here is what makes the token
    /// population total for constructed names too. An assembly with a piece this census cannot read
    /// — `env!`, a nested macro — is recorded UNREADABLE and the gate refuses it rather than
    /// guessing at what it expands to.
    fn follow_compile_assembly(&mut self, mac: &str, tokens: TokenStream, pos: LineColumn) {
        if mac == "stringify" {
            let text = tokens.to_string();
            self.record_assembly(
                "stringify".into(),
                true,
                vec![text.clone()],
                true,
                Some(text.clone()),
                pos,
            );
            let role = self.role();
            self.leaf_at(text, pos, Some(&role), true);
            return;
        }
        let mut pieces = Vec::new();
        let mut readable = true;
        for piece in comma_pieces(tokens) {
            match piece.as_slice() {
                [TokenTree::Literal(l)] => match token_lit_text(l) {
                    Some((v, _)) => pieces.push(v),
                    None => readable = false,
                },
                _ => readable = false,
            }
        }
        let assembled = if readable {
            Some(pieces.concat())
        } else {
            None
        };
        self.record_assembly(
            "concat".into(),
            true,
            pieces,
            readable,
            assembled.clone(),
            pos,
        );
        if let Some(v) = assembled {
            let role = self.role();
            self.leaf_at(v, pos, Some(&role), true);
        }
    }

    /// A COMPILE-TIME ASSEMBLY NESTED INSIDE ANOTHER MACRO'S TOKENS. syn hands a macro's tokens over
    /// unparsed, so `json!({ "k": concat!("od", "k-…") })` never reaches `visit_macro` for the inner
    /// `concat!` at all — the outer scan sees two innocent literals and the assembled name exists
    /// nowhere. Most of this daemon's compile-time assemblies sit in exactly that position, under
    /// `include_str!`: the expression walk alone found TWO, and the gate's pinned population — which
    /// is where that number reproduces — is EIGHT. Leaving it to the expression walk would have
    /// pinned two and called the population closed.
    fn follow_nested_assembly(&mut self, ts: TokenStream) {
        let items: Vec<TokenTree> = ts.into_iter().collect();
        for (i, t) in items.iter().enumerate() {
            if let TokenTree::Group(g) = t {
                let is_assembly_args = i >= 2
                    && matches!(&items[i - 1], TokenTree::Punct(p) if p.as_char() == '!')
                    && matches!(&items[i - 2], TokenTree::Ident(id) if COMPILE_ASSEMBLY.contains(&id.to_string().as_str()));
                if is_assembly_args {
                    let TokenTree::Ident(id) = &items[i - 2] else {
                        unreachable!("guarded by the match above")
                    };
                    self.follow_compile_assembly(&id.to_string(), g.stream(), id.span().start());
                }
                self.follow_nested_assembly(g.stream());
            }
        }
    }

    fn record_const(&mut self, name: &str, expr: &Expr) {
        match expr {
            Expr::Lit(l) => match lit_text(&l.lit) {
                Some(v) => {
                    self.facts.consts.insert(name.to_string(), v);
                }
                None => self.facts.const_opaque.push(name.to_string()),
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

    /// An associated constant — `impl Shadow { const FAM: &str = "…"; }`. Kept under its QUALIFIED
    /// spelling so it answers for `Shadow::FAM` and never for a bare `FAM` it does not define.
    fn record_assoc_const(&mut self, ty: &str, name: &str, expr: &Expr) {
        if let Expr::Lit(l) = expr {
            if let Some(v) = lit_text(&l.lit) {
                self.facts.assoc_consts.insert(format!("{ty}::{name}"), v);
                return;
            }
        }
        if let Expr::Reference(r) = expr {
            return self.record_assoc_const(ty, name, &r.expr);
        }
        self.facts.const_opaque.push(format!("{ty}::{name}"));
    }

    /// The DECLARATION SITE of a constant is a token of the name too. Labelling it is not decoration:
    /// the token walk finds `KIND_ONT` where it is declared, that identifier resolves to a family,
    /// and an unlabelled position is by construction a silent mention.
    fn decl_name(&mut self, ident: &syn::Ident) {
        let n = ident.to_string();
        if !is_const_ident(&n) {
            return;
        }
        let pos = ident.span().start();
        self.leaf_at(n, pos, Some("decl-name"), false);
    }
}

impl<'ast> Visit<'ast> for Collector {
    fn visit_expr(&mut self, e: &'ast Expr) {
        match e {
            Expr::Lit(l) => {
                if let Some(v) = lit_text(&l.lit) {
                    self.leaf(v, l.lit.span().start());
                }
            }
            Expr::Path(p) => {
                let segs = path_segments(&p.path);
                if segs.last().is_some_and(|s| is_const_ident(s)) {
                    self.leaf(segs.join("::"), path_pos(&p.path));
                }
            }
            _ => {}
        }
        // RUNTIME ASSEMBLY inside a writer's or filesystem call's arguments. `+` on strings and the
        // string-building methods are how a family name is composed from pieces that are each
        // innocent; the gate tests the pieces against family-name fragments.
        if !self.open_calls.is_empty() || !self.open_fs.is_empty() {
            match e {
                Expr::Binary(b) if matches!(b.op, syn::BinOp::Add(_)) => {
                    let mut pieces = expr_leaves(&b.left);
                    pieces.extend(expr_leaves(&b.right));
                    let pos = b.op.span().start();
                    self.record_assembly("binary-add".into(), false, pieces, false, None, pos);
                }
                Expr::MethodCall(mc)
                    if ASSEMBLY_METHODS.contains(&mc.method.to_string().as_str()) =>
                {
                    let mut pieces = expr_leaves(&mc.receiver);
                    for a in &mc.args {
                        pieces.extend(expr_leaves(a));
                    }
                    self.record_assembly(
                        format!("method:{}", mc.method),
                        false,
                        pieces,
                        false,
                        None,
                        mc.method.span().start(),
                    );
                }
                _ => {}
            }
        }
        let opened = match e {
            Expr::Call(c) => match &*c.func {
                Expr::Path(p) => {
                    let segs = path_segments(&p.path);
                    self.facts.named_calls.push(NamedCall {
                        callee: segs.join("::"),
                        in_fn: self.cur_fn(),
                        in_test: self.in_test(),
                    });
                    self.open_call(&segs, false)
                }
                _ => (false, false, false),
            },
            Expr::MethodCall(m) => self.open_call(&[m.method.to_string()], true),
            _ => (false, false, false),
        };
        visit::visit_expr(self, e);
        self.close_call(opened);
    }

    /// syn does not walk a macro's tokens — they are not parsed as expressions. Left alone this is a
    /// hole exactly the size of `json!`, `format!` and `write!`, so the tokens are scanned here, and
    /// the file-splicing and name-assembling macros are followed rather than merely scanned.
    fn visit_macro(&mut self, m: &'ast syn::Macro) {
        let mac = path_segments(&m.path).last().cloned().unwrap_or_default();

        if INCLUDE_MACROS.contains(&mac.as_str()) {
            let arg = match comma_pieces(m.tokens.clone()).first().map(|p| p.as_slice()) {
                Some([TokenTree::Literal(l)]) => token_lit_text(l).map(|(v, _)| v),
                _ => None,
            };
            let pos = m
                .path
                .segments
                .last()
                .map(|s| s.ident.span().start())
                .unwrap_or(LineColumn { line: 0, column: 0 });
            self.facts.includes.push(IncludeSite {
                mac: mac.clone(),
                arg,
                resolved: None,
                spliced: false,
                in_test: self.in_test(),
                src: self.cur_src.clone(),
                line: pos.line,
            });
        }

        let mac_pos = m
            .path
            .segments
            .last()
            .map(|s| s.ident.span().start())
            .unwrap_or(LineColumn { line: 0, column: 0 });
        if COMPILE_ASSEMBLY.contains(&mac.as_str()) {
            self.follow_compile_assembly(&mac, m.tokens.clone(), mac_pos);
        } else if ASSEMBLY_MACROS.contains(&mac.as_str())
            && (!self.open_calls.is_empty() || !self.open_fs.is_empty())
        {
            let pieces = token_values(m.tokens.clone())
                .into_iter()
                .map(|(v, _)| v)
                .collect();
            self.record_assembly(format!("macro:{mac}"), false, pieces, false, None, mac_pos);
        }
        self.follow_nested_assembly(m.tokens.clone());

        // A WRITER CALL INSIDE MACRO TOKENS IS STILL A WRITER CALL. syn hands over the token stream
        // unparsed, so `json!({ "w": persist_record(d, KIND, id, r) })` reaches `visit_expr` as
        // nothing at all. Naming a writer anywhere in the tokens re-attributes every family leaf in
        // them to the writing role — over-attribution, deliberately, because the alternative is a
        // write the census reports as a mere mention.
        let names_writer = token_idents(m.tokens.clone())
            .iter()
            .any(|i| WRITERS.contains(&i.as_str()));
        let role = if names_writer {
            "write-arg".to_string()
        } else {
            format!("macro:{mac}")
        };
        self.token_leaves(m.tokens.clone(), &role);
        visit::visit_macro(self, m);
    }

    /// An ATTRIBUTE's tokens are tokens of the file. `#[serde(rename = "odk-…")]` mints a family
    /// name in a position no expression visitor reaches, and it was a demonstrated silence.
    fn visit_attribute(&mut self, a: &'ast syn::Attribute) {
        let name = path_segments(a.path()).last().cloned().unwrap_or_default();
        let role = format!("attr:{name}");
        match &a.meta {
            syn::Meta::List(l) => self.token_leaves(l.tokens.clone(), &role),
            syn::Meta::NameValue(nv) => {
                if let Expr::Lit(l) = &nv.value {
                    if let Some(v) = lit_text(&l.lit) {
                        let pos = l.lit.span().start();
                        self.leaf_at(v, pos, Some(&role), false);
                    }
                }
            }
            syn::Meta::Path(_) => {}
        }
        // Deliberately NOT delegating to syn's default: it would re-walk `Meta::NameValue`'s
        // expression through `visit_expr` and record the same position twice.
    }

    /// A PATTERN carries literals and constant paths. `match kind { k @ "odk-…" => write(k) }` was a
    /// live, fully-green second admitter: the family name reached a writer and no expression
    /// position ever held it.
    fn visit_pat(&mut self, p: &'ast Pat) {
        match p {
            Pat::Lit(l) => {
                if let Some(v) = lit_text(&l.lit) {
                    let pos = l.lit.span().start();
                    self.leaf_at(v, pos, Some("pattern-lit"), false);
                }
            }
            Pat::Path(pp) => {
                let segs = path_segments(&pp.path);
                if segs.last().is_some_and(|s| is_const_ident(s)) {
                    let pos = path_pos(&pp.path);
                    self.leaf_at(segs.join("::"), pos, Some("pattern-path"), false);
                }
            }
            Pat::TupleStruct(t) => {
                let segs = path_segments(&t.path);
                if segs.last().is_some_and(|s| is_const_ident(s)) {
                    let pos = path_pos(&t.path);
                    self.leaf_at(segs.join("::"), pos, Some("pattern-path"), false);
                }
            }
            Pat::Struct(s) => {
                let segs = path_segments(&s.path);
                if segs.last().is_some_and(|s| is_const_ident(s)) {
                    let pos = path_pos(&s.path);
                    self.leaf_at(segs.join("::"), pos, Some("pattern-path"), false);
                }
            }
            Pat::Ident(i) => self.decl_name(&i.ident),
            _ => {}
        }
        visit::visit_pat(self, p);
    }

    /// Constant-shaped identifiers in TYPE position — a const generic argument, an associated type
    /// path. Rare in this daemon and labelled anyway, because "rare" is not "entailed".
    fn visit_type_path(&mut self, t: &'ast syn::TypePath) {
        let segs = path_segments(&t.path);
        if segs.last().is_some_and(|s| is_const_ident(s)) {
            let pos = path_pos(&t.path);
            self.leaf_at(segs.join("::"), pos, Some("type-path"), false);
        }
        visit::visit_type_path(self, t);
    }

    fn visit_item_const(&mut self, i: &'ast syn::ItemConst) {
        let test = is_bare_cfg_test(&i.attrs);
        if test {
            self.test_depth += 1;
        }
        self.record_const(&i.ident.to_string(), &i.expr);
        self.decl_name(&i.ident);
        self.roles.push("const-init".into());
        visit::visit_item_const(self, i);
        self.roles.pop();
        if test {
            self.test_depth -= 1;
        }
    }

    /// `static` was invisible to an earlier extractor entirely, so the rule forbidding a foreign
    /// module from DECLARING a family name was defeated by changing one keyword.
    fn visit_item_static(&mut self, i: &'ast syn::ItemStatic) {
        let test = is_bare_cfg_test(&i.attrs);
        if test {
            self.test_depth += 1;
        }
        self.record_const(&i.ident.to_string(), &i.expr);
        self.decl_name(&i.ident);
        self.roles.push("static-init".into());
        visit::visit_item_static(self, i);
        self.roles.pop();
        if test {
            self.test_depth -= 1;
        }
    }

    fn visit_impl_item_const(&mut self, i: &'ast syn::ImplItemConst) {
        let test = is_bare_cfg_test(&i.attrs);
        if test {
            self.test_depth += 1;
        }
        self.record_assoc_const(&self.cur_impl_ty(), &i.ident.to_string(), &i.expr);
        self.decl_name(&i.ident);
        self.roles.push("const-init".into());
        visit::visit_impl_item_const(self, i);
        self.roles.pop();
        if test {
            self.test_depth -= 1;
        }
    }

    fn visit_trait_item_const(&mut self, i: &'ast syn::TraitItemConst) {
        let test = is_bare_cfg_test(&i.attrs);
        if test {
            self.test_depth += 1;
        }
        if let Some((_, e)) = &i.default {
            self.record_assoc_const(&self.cur_impl_ty(), &i.ident.to_string(), e);
        }
        self.decl_name(&i.ident);
        self.roles.push("const-init".into());
        visit::visit_trait_item_const(self, i);
        self.roles.pop();
        if test {
            self.test_depth -= 1;
        }
    }

    fn visit_foreign_item_static(&mut self, i: &'ast syn::ForeignItemStatic) {
        self.decl_name(&i.ident);
        visit::visit_foreign_item_static(self, i);
    }

    /// A `use` tree's identifiers are tokens of the file, and one of them may be a constant this
    /// census resolves to a family. `use super::odk_routes::KIND_ONT as ONT_DIR;` puts TWO such
    /// tokens in the file and neither sits in any expression.
    fn visit_item_use(&mut self, i: &'ast syn::ItemUse) {
        let mut prefix = Vec::new();
        flatten_use(&i.tree, &mut prefix, &mut self.facts.imports);
        let mut idents = Vec::new();
        use_tree_idents(&i.tree, &mut idents);
        for id in idents {
            let n = id.to_string();
            if is_const_ident(&n) {
                self.leaf_at(n, id.span().start(), Some("use-path"), false);
            }
        }
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

    /// Impl methods are the daemon's house style. An earlier extractor ran a collector over them but
    /// never created their `fn_leaves` entry, so the raw-filesystem rule's "and the function around
    /// it names a family" half looked up an empty list for every production filesystem call that
    /// sits in an impl method — dead for every one of them.
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
        self.impl_ty.push(type_name(&i.self_ty));
        visit::visit_item_impl(self, i);
        self.impl_ty.pop();
        if test {
            self.test_depth -= 1;
        }
    }

    fn visit_item_trait(&mut self, i: &'ast syn::ItemTrait) {
        let test = is_bare_cfg_test(&i.attrs);
        if test {
            self.test_depth += 1;
        }
        self.impl_ty.push(i.ident.to_string());
        visit::visit_item_trait(self, i);
        self.impl_ty.pop();
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

fn type_name(t: &syn::Type) -> String {
    match t {
        syn::Type::Path(p) => path_segments(&p.path).join("::"),
        syn::Type::Reference(r) => type_name(&r.elem),
        _ => String::new(),
    }
}

fn use_tree_idents<'a>(tree: &'a UseTree, out: &mut Vec<&'a syn::Ident>) {
    match tree {
        UseTree::Path(p) => {
            out.push(&p.ident);
            use_tree_idents(&p.tree, out);
        }
        UseTree::Name(n) => out.push(&n.ident),
        UseTree::Rename(r) => {
            out.push(&r.ident);
            out.push(&r.rename);
        }
        UseTree::Glob(_) => {}
        UseTree::Group(g) => {
            for t in &g.items {
                use_tree_idents(t, out);
            }
        }
    }
}

/// Every identifier in a token stream, however deeply grouped.
fn token_idents(ts: TokenStream) -> Vec<String> {
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

fn die(msg: String) -> ! {
    eprintln!("{msg}");
    std::process::exit(2);
}

/// Read a file, tokenise it ONCE, and parse the AST FROM THE SAME TOKEN STREAM. Sharing the stream
/// is not an optimisation — it is what makes the two populations comparable: every span the visitor
/// reports is literally a span the token walk saw, so a position mismatch can only mean the visitor
/// failed to label a token, never that two parses disagreed about where a token is.
fn read_and_parse(file: &Path) -> (TokenStream, File) {
    let src = match std::fs::read_to_string(file) {
        Ok(s) => s,
        // A module the walker cannot READ is not a module it may skip: the census's closed world is
        // exactly the set of files it opened, and a silent `continue` shrinks that world without
        // shrinking the claim.
        Err(e) => die(format!("UNREADABLE MODULE {}: {e}", file.display())),
    };
    let ts: TokenStream = match src.parse() {
        Ok(t) => t,
        Err(e) => die(format!("TOKENISE FAILURE {}: {e}", file.display())),
    };
    let parsed: File = match syn::parse2(ts.clone()) {
        Ok(p) => p,
        Err(e) => die(format!("PARSE FAILURE {}: {e}", file.display())),
    };
    (ts, parsed)
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
        let key = repo_key(&canon, &repo_root);
        let (ts, parsed) = read_and_parse(&file);

        let mut c = Collector {
            facts: ModuleFacts {
                key: key.clone(),
                stem: file
                    .file_stem()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string(),
                sources: vec![key.clone()],
                ..Default::default()
            },
            test_depth: 0,
            fn_stack: Vec::new(),
            roles: Vec::new(),
            open_calls: Vec::new(),
            open_fs: Vec::new(),
            interests: interests.clone(),
            wrote_in_fn: Vec::new(),
            impl_ty: Vec::new(),
            cur_src: key.clone(),
        };
        token_walk(ts, &key, &mut c.facts.token_mentions);
        for item in &parsed.items {
            c.visit_item(item);
        }

        // `include!` SPLICES another file's source into this one, so its tokens are this module's
        // tokens and its writes are this module's writes. A target that cannot be resolved or read
        // is RED-UNRESOLVED and aborts — an include the walk has not read is the one thing a total
        // token population cannot survive.
        let mut inc_i = 0;
        while inc_i < c.facts.includes.len() {
            let (mac, arg, from_src) = {
                let s = &c.facts.includes[inc_i];
                (s.mac.clone(), s.arg.clone(), s.src.clone())
            };
            inc_i += 1;
            if mac != "include" {
                continue;
            }
            let Some(rel) = arg else {
                die(format!(
                    "UNREADABLE include! ARGUMENT in {from_src} — a spliced file this census cannot name is a hole in its token population"
                ));
            };
            let base = repo_root.join(&from_src);
            let target = match base.parent().map(|d| d.join(&rel)) {
                Some(p) if p.exists() => p,
                _ => die(format!(
                    "UNRESOLVED include!(\"{rel}\") in {from_src} — the spliced file is not on disk where the include names it"
                )),
            };
            let tcanon = target.canonicalize().unwrap_or_else(|_| target.clone());
            let tkey = repo_key(&tcanon, &repo_root);
            if c.facts.sources.contains(&tkey) {
                continue;
            }
            let (tts, tparsed) = read_and_parse(&target);
            c.facts.sources.push(tkey.clone());
            c.facts.includes[inc_i - 1].resolved = Some(tkey.clone());
            c.facts.includes[inc_i - 1].spliced = true;
            token_walk(tts, &tkey, &mut c.facts.token_mentions);
            c.cur_src = tkey;
            for item in &tparsed.items {
                c.visit_item(item);
            }
            c.cur_src = key.clone();
        }

        let facts = c.facts;
        for child in &facts.child_mods {
            let resolved = match &child.explicit_path {
                Some(rel) => file.parent().map(|d| d.join(rel)).filter(|p| p.exists()),
                None => child_path(&file, &child.name),
            };
            match resolved {
                Some(p) => queue.push(p),
                // An unresolvable `mod` is a module the census cannot see. Dropping it silently
                // is how a census loses eight modules and still reports a passing count.
                None => die(format!(
                    "UNRESOLVED MODULE `{}` declared in {}",
                    child.name,
                    file.display()
                )),
            }
        }
        modules.push(facts);
    }

    let out = serde_json::json!({
        "schema": "ioi.ontology-admission-census.v3",
        "entry": entry,
        "extractor_source_fnv1a64": format!("{:016x}", fnv1a64(SELF_SOURCE.as_bytes())),
        "interests": interests,
        "writers": WRITERS,
        "readers": READERS,
        "owner_seams": OWNER_SEAMS,
        "fs_calls": FS_CALLS,
        "compile_assembly": COMPILE_ASSEMBLY,
        "assembly_macros": ASSEMBLY_MACROS,
        "assembly_methods": ASSEMBLY_METHODS,
        "include_macros": INCLUDE_MACROS,
        "modules": modules,
    });
    println!("{}", serde_json::to_string(&out).expect("serialise census"));
}
