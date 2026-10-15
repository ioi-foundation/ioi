//! THE HAND-OUT RECONCILE (BUILD-DELTA #36; Codex batch-3 r6 MAJOR 3, the Hypervisor Director's ruling
//! (3) and the IOI Director's amendment (1): hand-out SINKS, not only return values). An own function
//! whose body holds a REPORTED draw (layer 1: a deny-list use at its call site; layer 2: a primitive
//! in its expansion) and in which THIS SYNTACTIC ANALYSIS sees the drawn value reach a SINK is a
//! CANDIDATE hand-out: every caller would use a draw without naming a deny-list entry. The gate FAILS
//! on a candidate that is neither registered (hand-outs.tsv and an own clippy.toml entry, so its
//! callers are sites) nor excluded with its reason (DEPENDENCY-REVIEW.md, by its exact sink kinds).
//! It is NOT a completeness proof: it sees what its rules below model, under the NAMED LIMITS, and
//! no flow class it does not model (completeness is BUILD-DELTA #42's; main.rs states the claim).
//!
//! The SINKS, decided from the function's own syntax (`syn`; the compiler decided what is
//! production code and where the draw is):
//! - `return`: the function's value (its tail, through blocks, `if`, `match`, `async` blocks and
//!   closures, or a `return` outside a closure) carries the drawn value, or a `?` outside a closure
//!   returns an ERROR that carries it (Codex batch-3 r7 MAJOR (a)): an error the function builds,
//!   `Err(..)` of a tracked value, a tracked argument of an error adapter (`map_err`, `ok_or`,
//!   `ok_or_else`, `or`, `or_else`, `context`, `with_context`, `wrap_err`, `wrap_err_with`,
//!   `and_then`; a closure argument by what it captures or a draw inside it), the receiver's error
//!   through an adapter that keeps it (`map`, `inspect`, `as_ref`, `cloned`, ...), or a tracked
//!   local or place (its error or its value: over-approximated);
//! - `&mut parameter`: it is written into a place rooted at a `&mut` parameter (`&mut self`
//!   included), passed to a method of one, or a draw fills one;
//! - `non-local write`: it is written into, or passed to a WRITE method of, a place rooted outside
//!   the function's locals: a field of `self` or of a parameter reached through a shared reference
//!   or a shared handle (`&T`, `Arc`, `State`, ...), through an interior-mutability step (`lock`,
//!   `write`, `borrow_mut`, ...) or a write verb (`insert`, `push`, `set`, `store`, ...);
//! - `channel send`: it is the argument of a `send`-family method or function;
//! - `static`: it is written into, or passed to a write method of, a static (an UPPER_CASE path),
//!   or the draw lies in a static's or a const's initializer;
//! - `closure capture`: a closure or an `async` block mentions it without binding it.
//!
//! The drawn value is TRACKED flow-insensitively and by NAME: a draw's expression, every local a
//! `let`, an assignment, a `for`, `if let`, `while let` or `match` pattern binds from a tracked
//! value, every local a draw or a tracked call fills through `&mut`, and every local a method with a
//! tracked argument is called on. This over-approximates (a candidate is reviewed, not assumed).
//! ALIASES (a local bound from a place rooted outside the locals points into it, through any number
//! of reborrows) are discovered to a FIXPOINT (Codex batch-3 r7 MAJOR (b)): each pass follows one
//! more binding, so N bound names settle within N passes and pass N + 1 confirms it; a function whose
//! aliases still change then (a name re-bound in a cycle of differently rooted places) is not
//! guessed: it is an `unanalyzed item`, a candidate until reviewed.
//! NAMED LIMITS (flows this cannot see; stated in the gate's header claim): a CALLEE that stores a
//! value passed to it (one level: only the function holding the draw is read), or returns it in the
//! error `?` propagates (a call's error, or a method's outside the error adapters, is the callee's);
//! I/O (a file, a socket, a child process, a log line, a database behind its own method name
//! outside the write verbs); unsafe raw-pointer writes; shared state reached through a handle a
//! call returns (`let h = registry(); h.insert(v)`) or through a method outside the
//! interior-mutability list (`let mut slot = STATE.lock().map_err(..)?; *slot = v` reads `slot` as
//! a local); the inside of a macro other than `write!`/`writeln!` (its arguments are read as
//! tokens); a `return` or a `?` inside a closure or an `async` block (it leaves the closure, whose
//! value is read from its tail and its captures only); a name bound from several places takes the
//! class of its last binding in source order (one class per name).

use crate::source::range;
use proc_macro2::{LineColumn, TokenStream, TokenTree};
use quote::ToTokens;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use syn::visit::Visit;
use syn::{BinOp, Expr, FnArg, Pat, ReturnType, Stmt, Type};

pub const RETURN: &str = "return";
pub const MUT_PARAM: &str = "&mut parameter";
pub const NON_LOCAL: &str = "non-local write";
pub const CHANNEL: &str = "channel send";
pub const STATIC: &str = "static";
pub const CAPTURE: &str = "closure capture";
/// A holder the reconcile cannot read as a function (a fragment, a type, a function without a
/// body): a candidate until reviewed.
pub const UNANALYZED: &str = "unanalyzed item";

/// Sink kind -> the lines where the drawn value reaches it.
pub type Sinks = BTreeMap<&'static str, BTreeSet<usize>>;

/// The send family: a channel send whatever the receiver.
const SEND: &[&str] = &[
    "send",
    "try_send",
    "send_async",
    "blocking_send",
    "send_timeout",
    "unbounded_send",
    "start_send",
    "feed",
    "send_replace",
    "send_modify",
    "send_if_modified",
    "broadcast",
    "try_broadcast",
];

/// Methods whose result still points into the receiver (an alias, not a copy).
const ALIASING: &[&str] = &[
    "lock",
    "write",
    "read",
    "try_lock",
    "try_write",
    "try_read",
    "blocking_lock",
    "blocking_write",
    "lock_owned",
    "write_owned",
    "borrow_mut",
    "borrow",
    "get_mut",
    "as_mut",
    "as_deref_mut",
    "deref_mut",
    "entry",
    "or_insert",
    "or_insert_with",
    "or_default",
    "get_or_insert_with",
    "unwrap",
    "expect",
    "unwrap_or_else",
    "iter_mut",
    "values_mut",
    "last_mut",
    "first_mut",
    "clone",
];

/// Steps that make a shared place writable (interior mutability).
const INTERIOR: &[&str] = &[
    "lock",
    "write",
    "try_lock",
    "try_write",
    "blocking_lock",
    "blocking_write",
    "lock_owned",
    "write_owned",
    "borrow_mut",
    "get_mut",
];

/// Write verbs: a method of a shared place (a concurrent map, a cell, a once-cell, an atomic, a
/// store handle) that keeps its argument.
const WRITE_VERBS: &[&str] = &[
    "insert",
    "push",
    "push_back",
    "push_front",
    "push_str",
    "extend",
    "extend_from_slice",
    "append",
    "set",
    "replace",
    "swap",
    "store",
    "get_or_init",
    "get_or_insert_with",
    "get_or_try_init",
    "put",
    "save",
    "persist",
    "record",
    "upsert",
    "add",
    "enqueue",
    "register",
    "write_all",
    "entry",
];

/// Error adapters whose argument becomes the error `?` returns (the receiver's is replaced).
const ERROR_REPLACE: &[&str] = &["map_err", "ok_or", "ok_or_else", "or", "or_else"];

/// Error adapters that keep the receiver's error and may add their argument to it.
const ERROR_ADD: &[&str] = &[
    "context",
    "with_context",
    "wrap_err",
    "wrap_err_with",
    "and_then",
];

/// Adapters whose result keeps the receiver's error unchanged.
const ERROR_KEEP: &[&str] = &[
    "map",
    "inspect",
    "inspect_err",
    "as_ref",
    "as_mut",
    "as_deref",
    "as_deref_mut",
    "cloned",
    "copied",
    "clone",
    "flatten",
];

/// By-value parameter types that are handles to shared state.
const SHARED_HANDLES: &[&str] = &[
    "Arc",
    "Rc",
    "Weak",
    "State",
    "Extension",
    "Data",
    "Mutex",
    "RwLock",
];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Class {
    Local,
    MutParam,
    NonLocal,
    Static,
}

fn ptr(e: &Expr) -> usize {
    e as *const Expr as usize
}

fn key(at: LineColumn) -> (usize, usize) {
    (at.line, at.column)
}

fn contains(range: (LineColumn, LineColumn), at: LineColumn) -> bool {
    key(range.0) <= key(at) && key(at) < key(range.1)
}

fn size(range: (LineColumn, LineColumn)) -> (usize, usize) {
    let lines = range.1.line - range.0.line;
    (
        lines,
        if lines == 0 {
            range.1.column.saturating_sub(range.0.column)
        } else {
            usize::MAX - range.0.column
        },
    )
}

fn line_of(tokens: TokenStream) -> usize {
    range(tokens).map(|(start, _)| start.line).unwrap_or(0)
}

fn is_upper(name: &str) -> bool {
    name.chars().any(|c| c.is_ascii_uppercase())
        && name
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

fn is_assign_op(op: &BinOp) -> bool {
    matches!(
        op,
        BinOp::AddAssign(_)
            | BinOp::SubAssign(_)
            | BinOp::MulAssign(_)
            | BinOp::DivAssign(_)
            | BinOp::RemAssign(_)
            | BinOp::BitXorAssign(_)
            | BinOp::BitAndAssign(_)
            | BinOp::BitOrAssign(_)
            | BinOp::ShlAssign(_)
            | BinOp::ShrAssign(_)
    )
}

/// The identifiers a pattern binds.
fn pat_idents(pat: &Pat, out: &mut BTreeSet<String>) {
    struct Idents<'o>(&'o mut BTreeSet<String>);
    impl<'ast> Visit<'ast> for Idents<'_> {
        fn visit_pat_ident(&mut self, node: &'ast syn::PatIdent) {
            self.0.insert(node.ident.to_string());
            syn::visit::visit_pat_ident(self, node);
        }
        fn visit_expr(&mut self, _: &'ast Expr) {}
    }
    Idents(out).visit_pat(pat);
}

/// Every identifier a token stream holds (a macro's arguments).
fn token_idents(tokens: &TokenStream, out: &mut BTreeSet<String>) {
    for token in tokens.clone() {
        match token {
            TokenTree::Ident(ident) => {
                out.insert(ident.to_string());
            }
            TokenTree::Group(group) => token_idents(&group.stream(), out),
            _ => {}
        }
    }
}

/// The class of a parameter of this type.
fn type_class(ty: &Type) -> Class {
    match ty {
        Type::Reference(r) if r.mutability.is_some() => Class::MutParam,
        Type::Reference(_) | Type::TraitObject(_) | Type::ImplTrait(_) | Type::Ptr(_) => {
            Class::NonLocal
        }
        Type::Paren(p) => type_class(&p.elem),
        Type::Group(g) => type_class(&g.elem),
        Type::Path(p) => match p.path.segments.last() {
            Some(last) if SHARED_HANDLES.contains(&last.ident.to_string().as_str()) => {
                Class::NonLocal
            }
            _ => Class::Local,
        },
        _ => Class::Local,
    }
}

/// Collects every expression of a body with its range (nested items excluded), the calls' callees,
/// and every binding.
struct Collect {
    exprs: Vec<(usize, LineColumn, LineColumn)>,
    callee: HashMap<usize, usize>,
    stmts: Vec<(LineColumn, LineColumn, StmtKind)>,
    bound: BTreeSet<String>,
}

#[derive(Clone)]
enum StmtKind {
    Local(BTreeSet<String>),
    Macro(usize),
    Other,
}

impl<'ast> Visit<'ast> for Collect {
    fn visit_item(&mut self, _: &'ast syn::Item) {}
    fn visit_expr(&mut self, node: &'ast Expr) {
        if let Some((start, end)) = range(node.to_token_stream()) {
            self.exprs.push((ptr(node), start, end));
        }
        if let Expr::Call(call) = node {
            self.callee.insert(ptr(&call.func), ptr(node));
        }
        syn::visit::visit_expr(self, node);
    }
    fn visit_stmt(&mut self, node: &'ast Stmt) {
        if let Some((start, end)) = range(node.to_token_stream()) {
            let kind = match node {
                Stmt::Local(local) => {
                    let mut names = BTreeSet::new();
                    pat_idents(&local.pat, &mut names);
                    StmtKind::Local(names)
                }
                Stmt::Macro(m) => StmtKind::Macro(m as *const syn::StmtMacro as usize),
                _ => StmtKind::Other,
            };
            self.stmts.push((start, end, kind));
        }
        syn::visit::visit_stmt(self, node);
    }
    fn visit_pat(&mut self, node: &'ast Pat) {
        pat_idents(node, &mut self.bound);
        syn::visit::visit_pat(self, node);
    }
}

struct Analysis<'a> {
    block: &'a syn::Block,
    returns_value: bool,
    params: HashMap<String, Class>,
    bound: BTreeSet<String>,
    alias: HashMap<String, Class>,
    seeds: HashSet<usize>,
    macro_seeds: HashSet<usize>,
    tracked: BTreeSet<String>,
    sinks: Sinks,
}

/// The sinks a function's drawn value reaches. `draws` are the reported positions (line, 0-based
/// column) inside the function.
pub fn analyze(sig: &syn::Signature, block: &syn::Block, draws: &[LineColumn]) -> Sinks {
    let returns_value = match &sig.output {
        ReturnType::Default => false,
        ReturnType::Type(_, ty) => {
            !matches!(&**ty, Type::Tuple(t) if t.elems.is_empty())
                && !matches!(&**ty, Type::Never(_))
        }
    };
    let mut params = HashMap::new();
    for input in &sig.inputs {
        match input {
            FnArg::Receiver(receiver) => {
                params.insert("self".to_string(), type_class(&receiver.ty));
            }
            FnArg::Typed(typed) => {
                let mut names = BTreeSet::new();
                pat_idents(&typed.pat, &mut names);
                for name in names {
                    params.insert(name, type_class(&typed.ty));
                }
            }
        }
    }
    let mut collect = Collect {
        exprs: Vec::new(),
        callee: HashMap::new(),
        stmts: Vec::new(),
        bound: BTreeSet::new(),
    };
    collect.visit_block(block);
    let mut a = Analysis {
        block,
        returns_value,
        params,
        bound: collect.bound.clone(),
        alias: HashMap::new(),
        seeds: HashSet::new(),
        macro_seeds: HashSet::new(),
        tracked: BTreeSet::new(),
        sinks: Sinks::new(),
    };
    let output_range = match &sig.output {
        ReturnType::Type(_, ty) => range(ty.to_token_stream()),
        ReturnType::Default => None,
    };
    for at in draws {
        let innermost = collect
            .exprs
            .iter()
            .filter(|(_, start, end)| contains((*start, *end), *at))
            .min_by_key(|(_, start, end)| size((*start, *end)));
        if let Some((id, _, _)) = innermost {
            a.seeds.insert(*collect.callee.get(id).unwrap_or(id));
            continue;
        }
        let stmt = collect
            .stmts
            .iter()
            .filter(|(start, end, _)| contains((*start, *end), *at))
            .min_by_key(|(start, end, _)| size((*start, *end)));
        match stmt {
            Some((_, _, StmtKind::Local(names))) => a.tracked.extend(names.iter().cloned()),
            Some((_, _, StmtKind::Macro(id))) => {
                a.macro_seeds.insert(*id);
            }
            _ => {
                if output_range.is_some_and(|r| contains(r, *at)) {
                    a.sink(RETURN, at.line);
                }
            }
        }
    }
    // Aliases: a local bound from a place rooted outside the locals points into it. To a FIXPOINT
    // (Codex batch-3 r7 MAJOR (b)), bounded by the function's bound names: N names settle within N
    // passes, the next confirms; still changing after N + 1 passes is unanalyzed, not guessed.
    let limit = collect.bound.len() + 1;
    let mut settled = false;
    for _ in 0..limit {
        let mut aliases = Aliases {
            a: &a,
            found: Vec::new(),
        };
        aliases.visit_block(block);
        let mut next = a.alias.clone();
        for (name, class) in aliases.found {
            next.insert(name, class);
        }
        if next == a.alias {
            settled = true;
            break;
        }
        a.alias = next;
    }
    if !settled {
        let line = draws.iter().map(|d| d.line).min().unwrap_or(0);
        a.sink(UNANALYZED, line);
    }
    // Track to a fixpoint, then record the sinks with the final tracking.
    let pre_sinks = a.sinks.clone();
    loop {
        let before = a.tracked.len();
        a.sinks = pre_sinks.clone();
        let mut pass = Pass {
            a: &mut a,
            depth: 0,
        };
        pass.visit_block(block);
        if a.tracked.len() == before {
            break;
        }
    }
    if a.returns_value && a.block_value(a.block) {
        let line = a
            .block
            .stmts
            .last()
            .map(|s| line_of(s.to_token_stream()))
            .unwrap_or(0);
        a.sink(RETURN, line);
    }
    a.sinks
}

struct Aliases<'a, 'b> {
    a: &'b Analysis<'a>,
    found: Vec<(String, Class)>,
}

impl<'ast> Visit<'ast> for Aliases<'_, '_> {
    fn visit_item(&mut self, _: &'ast syn::Item) {}
    fn visit_local(&mut self, node: &'ast syn::Local) {
        if let Some(init) = &node.init {
            if let Some((class, _, _)) = self.a.root(&init.expr) {
                if class != Class::Local {
                    let mut names = BTreeSet::new();
                    pat_idents(&node.pat, &mut names);
                    for name in names {
                        self.found.push((name, class));
                    }
                }
            }
        }
        syn::visit::visit_local(self, node);
    }
}

impl Analysis<'_> {
    fn sink(&mut self, kind: &'static str, line: usize) {
        self.sinks.entry(kind).or_default().insert(line);
    }

    /// The class of a name a place is rooted at. An unbound CamelCase name is a type or a unit value
    /// (writing into it writes a temporary): no place.
    fn class_of(&self, name: &str) -> Option<Class> {
        if let Some(class) = self.alias.get(name) {
            return Some(*class);
        }
        if let Some(class) = self.params.get(name) {
            return Some(*class);
        }
        if self.bound.contains(name) {
            return Some(Class::Local);
        }
        if is_upper(name) {
            return Some(Class::Static);
        }
        if name.starts_with(|c: char| c.is_ascii_uppercase()) {
            return None;
        }
        Some(Class::NonLocal)
    }

    /// The root of a place: its class, its name, and whether an interior-mutability step lies on
    /// the way to it.
    fn root(&self, e: &Expr) -> Option<(Class, String, bool)> {
        match e {
            Expr::Path(p) if p.qself.is_none() => {
                let segments = &p.path.segments;
                let last = segments.last()?.ident.to_string();
                if segments.len() == 1 {
                    self.class_of(&last).map(|class| (class, last, false))
                } else if is_upper(&last) {
                    Some((Class::Static, last, false))
                } else {
                    // A path to an item (a function, a unit value): no place.
                    None
                }
            }
            Expr::Field(f) => self.root(&f.base),
            Expr::Index(i) => self.root(&i.expr),
            Expr::Unary(u) => self.root(&u.expr),
            Expr::Reference(r) => self.root(&r.expr),
            Expr::Paren(p) => self.root(&p.expr),
            Expr::Group(g) => self.root(&g.expr),
            Expr::Try(t) => self.root(&t.expr),
            Expr::Await(a) => self.root(&a.base),
            Expr::Cast(c) => self.root(&c.expr),
            Expr::MethodCall(m) => {
                let name = m.method.to_string();
                if ALIASING.contains(&name.as_str()) {
                    self.root(&m.receiver).map(|(class, root, interior)| {
                        (class, root, interior || INTERIOR.contains(&name.as_str()))
                    })
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn tokens_tracked(&self, tokens: &TokenStream) -> bool {
        let mut idents = BTreeSet::new();
        token_idents(tokens, &mut idents);
        idents.iter().any(|i| self.tracked.contains(i))
    }

    /// Does a block's VALUE carry the drawn value?
    fn block_value(&self, block: &syn::Block) -> bool {
        match block.stmts.last() {
            Some(Stmt::Expr(e, None)) => self.t(e),
            Some(Stmt::Macro(m)) if m.semi_token.is_none() => {
                self.macro_seeds
                    .contains(&(m as *const syn::StmtMacro as usize))
                    || self.tokens_tracked(&m.mac.tokens)
            }
            _ => false,
        }
    }

    /// The identifiers a closure or an async block uses without binding them.
    fn captures_tracked(
        &self,
        inputs: Option<&syn::punctuated::Punctuated<Pat, syn::Token![,]>>,
        body: &Expr,
    ) -> bool {
        struct Mentions {
            used: BTreeSet<String>,
            bound: BTreeSet<String>,
        }
        impl<'ast> Visit<'ast> for Mentions {
            fn visit_item(&mut self, _: &'ast syn::Item) {}
            fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
                if node.qself.is_none() && node.path.segments.len() == 1 {
                    self.used.insert(node.path.segments[0].ident.to_string());
                }
                syn::visit::visit_expr_path(self, node);
            }
            fn visit_macro(&mut self, node: &'ast syn::Macro) {
                token_idents(&node.tokens, &mut self.used);
            }
            fn visit_pat(&mut self, node: &'ast Pat) {
                pat_idents(node, &mut self.bound);
                syn::visit::visit_pat(self, node);
            }
        }
        let mut m = Mentions {
            used: BTreeSet::new(),
            bound: BTreeSet::new(),
        };
        if let Some(inputs) = inputs {
            for pat in inputs {
                pat_idents(pat, &mut m.bound);
            }
        }
        m.visit_expr(body);
        m.used
            .iter()
            .any(|name| self.tracked.contains(name) && !m.bound.contains(name))
    }

    /// Does an expression's VALUE carry the drawn value?
    fn t(&self, e: &Expr) -> bool {
        if self.seeds.contains(&ptr(e)) {
            return true;
        }
        match e {
            Expr::Path(p) => {
                p.qself.is_none()
                    && p.path.segments.len() == 1
                    && self.tracked.contains(&p.path.segments[0].ident.to_string())
            }
            Expr::Block(b) => self.block_value(&b.block),
            Expr::Unsafe(b) => self.block_value(&b.block),
            Expr::Async(b) => self.block_value(&b.block) || self.captures_tracked(None, e),
            Expr::Const(b) => self.block_value(&b.block),
            Expr::TryBlock(b) => self.block_value(&b.block),
            Expr::If(i) => {
                self.block_value(&i.then_branch)
                    || i.else_branch.as_ref().is_some_and(|(_, e)| self.t(e))
            }
            Expr::Match(m) => m.arms.iter().any(|arm| self.t(&arm.body)),
            Expr::Loop(l) => {
                struct Breaks<'x, 'y> {
                    a: &'x Analysis<'y>,
                    hit: bool,
                }
                impl<'ast> Visit<'ast> for Breaks<'_, '_> {
                    fn visit_item(&mut self, _: &'ast syn::Item) {}
                    fn visit_expr_break(&mut self, node: &'ast syn::ExprBreak) {
                        if node.expr.as_ref().is_some_and(|e| self.a.t(e)) {
                            self.hit = true;
                        }
                        syn::visit::visit_expr_break(self, node);
                    }
                }
                let mut breaks = Breaks {
                    a: self,
                    hit: false,
                };
                breaks.visit_block(&l.body);
                breaks.hit
            }
            Expr::While(_)
            | Expr::ForLoop(_)
            | Expr::Assign(_)
            | Expr::Return(_)
            | Expr::Break(_)
            | Expr::Continue(_)
            | Expr::Lit(_)
            | Expr::Infer(_) => false,
            Expr::Closure(c) => self.t(&c.body) || self.captures_tracked(Some(&c.inputs), &c.body),
            Expr::Macro(m) => self.tokens_tracked(&m.mac.tokens),
            Expr::Let(l) => self.t(&l.expr),
            Expr::Binary(b) => !is_assign_op(&b.op) && (self.t(&b.left) || self.t(&b.right)),
            Expr::Call(c) => self.t(&c.func) || c.args.iter().any(|a| self.t(a)),
            Expr::MethodCall(m) => self.t(&m.receiver) || m.args.iter().any(|a| self.t(a)),
            Expr::Unary(u) => self.t(&u.expr),
            Expr::Field(f) => self.t(&f.base),
            Expr::Index(i) => self.t(&i.expr) || self.t(&i.index),
            Expr::Reference(r) => self.t(&r.expr),
            Expr::RawAddr(r) => self.t(&r.expr),
            Expr::Cast(c) => self.t(&c.expr),
            Expr::Paren(p) => self.t(&p.expr),
            Expr::Group(g) => self.t(&g.expr),
            Expr::Tuple(t) => t.elems.iter().any(|e| self.t(e)),
            Expr::Array(a) => a.elems.iter().any(|e| self.t(e)),
            Expr::Struct(s) => {
                s.fields.iter().any(|f| self.t(&f.expr))
                    || s.rest.as_ref().is_some_and(|r| self.t(r))
            }
            Expr::Repeat(r) => self.t(&r.expr),
            Expr::Range(r) => {
                r.start.as_ref().is_some_and(|e| self.t(e))
                    || r.end.as_ref().is_some_and(|e| self.t(e))
            }
            Expr::Try(t) => self.t(&t.expr),
            Expr::Await(a) => self.t(&a.base),
            Expr::Yield(y) => y.expr.as_ref().is_some_and(|e| self.t(e)),
            other => self.tokens_tracked(&other.to_token_stream()),
        }
    }

    /// Does the ERROR that `?` returns from this operand carry the drawn value (Codex batch-3 r7
    /// MAJOR (a))? An error the function builds: `Err(..)` of a tracked value, an error adapter's
    /// tracked argument, the receiver's error through an adapter that keeps it, or a tracked local
    /// or place (either half: over-approximated). A call's error, and a method's outside the error
    /// adapters, is its callee's (a named limit).
    fn err(&self, e: &Expr) -> bool {
        match e {
            Expr::Call(c) => {
                let is_err = matches!(
                    &*c.func,
                    Expr::Path(p) if p.path.segments.last().is_some_and(|s| s.ident == "Err")
                );
                is_err && c.args.iter().any(|a| self.t(a))
            }
            Expr::MethodCall(m) => {
                let name = m.method.to_string();
                let name = name.as_str();
                let argument = m.args.iter().any(|a| self.carries(a));
                (ERROR_REPLACE.contains(&name) && argument)
                    || (ERROR_ADD.contains(&name) && (argument || self.err(&m.receiver)))
                    || (ERROR_KEEP.contains(&name) && self.err(&m.receiver))
            }
            Expr::Await(a) => self.err(&a.base),
            Expr::Paren(p) => self.err(&p.expr),
            Expr::Group(g) => self.err(&g.expr),
            Expr::Block(b) => self.block_err(&b.block),
            Expr::Unsafe(b) => self.block_err(&b.block),
            Expr::Async(b) => self.block_err(&b.block),
            Expr::If(i) => {
                self.block_err(&i.then_branch)
                    || i.else_branch.as_ref().is_some_and(|(_, e)| self.err(e))
            }
            Expr::Match(m) => m.arms.iter().any(|arm| self.err(&arm.body)),
            other => self.t(other),
        }
    }

    /// The error of a block's value.
    fn block_err(&self, block: &syn::Block) -> bool {
        match block.stmts.last() {
            Some(Stmt::Expr(e, None)) => self.err(e),
            _ => self.block_value(block),
        }
    }

    /// Does an error adapter's argument carry the drawn value? A closure by what it captures or a
    /// draw inside it (its own parameters are its inputs, the original error or value); anything
    /// else by its value.
    fn carries(&self, arg: &Expr) -> bool {
        match arg {
            Expr::Closure(c) => {
                self.captures_tracked(Some(&c.inputs), &c.body) || self.seeded(&c.body)
            }
            other => self.t(other),
        }
    }

    /// Does an expression hold a reported draw?
    fn seeded(&self, e: &Expr) -> bool {
        struct Seeded<'x, 'y> {
            a: &'x Analysis<'y>,
            hit: bool,
        }
        impl<'ast> Visit<'ast> for Seeded<'_, '_> {
            fn visit_item(&mut self, _: &'ast syn::Item) {}
            fn visit_expr(&mut self, node: &'ast Expr) {
                if self.a.seeds.contains(&ptr(node)) {
                    self.hit = true;
                }
                syn::visit::visit_expr(self, node);
            }
            fn visit_stmt_macro(&mut self, node: &'ast syn::StmtMacro) {
                if self
                    .a
                    .macro_seeds
                    .contains(&(node as *const syn::StmtMacro as usize))
                {
                    self.hit = true;
                }
                syn::visit::visit_stmt_macro(self, node);
            }
        }
        let mut seeded = Seeded {
            a: self,
            hit: false,
        };
        seeded.visit_expr(e);
        seeded.hit
    }
}

struct Pass<'a, 'b> {
    a: &'b mut Analysis<'a>,
    /// Closures and async blocks entered: a `return` inside one is not the function's.
    depth: usize,
}

impl Pass<'_, '_> {
    fn track(&mut self, names: BTreeSet<String>) {
        self.a.tracked.extend(names);
    }

    /// A tracked value is written into `place` (an assignment when `method` is None, else the
    /// argument of `place.method(..)`).
    fn write_into(&mut self, place: &Expr, method: Option<&str>, line: usize) {
        let Some((class, name, interior)) = self.a.root(place) else {
            return;
        };
        let verb = method.is_none_or(|m| WRITE_VERBS.contains(&m));
        match class {
            Class::Local => {
                self.a.tracked.insert(name);
            }
            Class::MutParam => self.a.sink(MUT_PARAM, line),
            Class::NonLocal if interior || verb => self.a.sink(NON_LOCAL, line),
            Class::Static if interior || verb => self.a.sink(STATIC, line),
            _ => {}
        }
    }

    /// A tracked call fills its `&mut` arguments, and hands a `&mut` parameter passed on to it.
    fn out_arguments<'e>(&mut self, args: impl Iterator<Item = &'e Expr>, line: usize) {
        for arg in args {
            match arg {
                Expr::Reference(r) if r.mutability.is_some() => {
                    self.write_into(&r.expr, None, line)
                }
                Expr::Path(p)
                    if p.qself.is_none()
                        && p.path.segments.len() == 1
                        && self.a.class_of(&p.path.segments[0].ident.to_string())
                            == Some(Class::MutParam) =>
                {
                    self.a.sink(MUT_PARAM, line)
                }
                _ => {}
            }
        }
    }

    fn write_macro(&mut self, mac: &syn::Macro) {
        let name = mac
            .path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default();
        if (name == "write" || name == "writeln") && self.a.tokens_tracked(&mac.tokens) {
            let first: TokenStream = mac
                .tokens
                .clone()
                .into_iter()
                .take_while(|t| !matches!(t, TokenTree::Punct(p) if p.as_char() == ','))
                .collect();
            if let Ok(dest) = syn::parse2::<Expr>(first) {
                let line = line_of(mac.to_token_stream());
                self.write_into(&dest, None, line);
            }
        }
    }
}

impl<'ast> Visit<'ast> for Pass<'_, '_> {
    fn visit_item(&mut self, _: &'ast syn::Item) {}

    fn visit_local(&mut self, node: &'ast syn::Local) {
        if let Some(init) = &node.init {
            if self.a.t(&init.expr) {
                let mut names = BTreeSet::new();
                pat_idents(&node.pat, &mut names);
                self.track(names);
            }
        }
        syn::visit::visit_local(self, node);
    }

    fn visit_stmt_macro(&mut self, node: &'ast syn::StmtMacro) {
        self.write_macro(&node.mac);
        syn::visit::visit_stmt_macro(self, node);
    }

    fn visit_expr(&mut self, node: &'ast Expr) {
        let line = || line_of(node.to_token_stream());
        match node {
            Expr::Assign(a) => {
                if self.a.t(&a.right) {
                    self.write_into(&a.left, None, line());
                }
            }
            Expr::Binary(b) if is_assign_op(&b.op) => {
                if self.a.t(&b.right) {
                    self.write_into(&b.left, None, line());
                }
            }
            Expr::MethodCall(m) => {
                let name = m.method.to_string();
                let tracked_argument = m.args.iter().any(|a| self.a.t(a));
                if tracked_argument && SEND.contains(&name.as_str()) {
                    self.a.sink(CHANNEL, line());
                } else if tracked_argument {
                    self.write_into(&m.receiver, Some(&name), line());
                }
                if self.a.t(&m.receiver) {
                    for arg in &m.args {
                        if let Expr::Closure(c) = arg {
                            let mut names = BTreeSet::new();
                            for pat in &c.inputs {
                                pat_idents(pat, &mut names);
                            }
                            self.track(names);
                        }
                    }
                }
                if self.a.t(node) {
                    self.out_arguments(m.args.iter(), line());
                }
            }
            Expr::Call(c) => {
                let tracked_argument = c.args.iter().any(|a| self.a.t(a));
                let send = match &*c.func {
                    Expr::Path(p) => p
                        .path
                        .segments
                        .last()
                        .is_some_and(|s| SEND.contains(&s.ident.to_string().as_str())),
                    _ => false,
                };
                if tracked_argument && send {
                    self.a.sink(CHANNEL, line());
                }
                if self.a.t(node) {
                    self.out_arguments(c.args.iter(), line());
                }
            }
            Expr::ForLoop(f) => {
                if self.a.t(&f.expr) {
                    let mut names = BTreeSet::new();
                    pat_idents(&f.pat, &mut names);
                    self.track(names);
                }
            }
            Expr::Let(l) => {
                if self.a.t(&l.expr) {
                    let mut names = BTreeSet::new();
                    pat_idents(&l.pat, &mut names);
                    self.track(names);
                }
            }
            Expr::Match(m) => {
                if self.a.t(&m.expr) {
                    let mut names = BTreeSet::new();
                    for arm in &m.arms {
                        pat_idents(&arm.pat, &mut names);
                    }
                    self.track(names);
                }
            }
            Expr::Return(r) => {
                if self.depth == 0
                    && self.a.returns_value
                    && r.expr.as_ref().is_some_and(|e| self.a.t(e))
                {
                    self.a.sink(RETURN, line());
                }
            }
            // `?` returns its operand's error to the caller (Codex batch-3 r7 MAJOR (a)).
            Expr::Try(t) => {
                if self.depth == 0 && self.a.returns_value && self.a.err(&t.expr) {
                    self.a.sink(RETURN, line());
                }
            }
            Expr::Macro(m) => self.write_macro(&m.mac),
            _ => {}
        }
        match node {
            Expr::Closure(c) => {
                if self.a.captures_tracked(Some(&c.inputs), &c.body) {
                    self.a.sink(CAPTURE, line());
                }
                self.depth += 1;
                syn::visit::visit_expr(self, node);
                self.depth -= 1;
            }
            Expr::Async(_) => {
                if self.a.captures_tracked(None, node) {
                    self.a.sink(CAPTURE, line());
                }
                self.depth += 1;
                syn::visit::visit_expr(self, node);
                self.depth -= 1;
            }
            _ => syn::visit::visit_expr(self, node),
        }
    }
}

/// The sinks of a holder that is not a function: a static's or a const's initializer is a static
/// sink, an import holds no value, anything else is unanalyzed.
pub fn item_sinks(item: &str, line: usize) -> Option<Sinks> {
    let last = item.rsplit(" > ").next().unwrap_or(item);
    let mut sinks = Sinks::new();
    if last.starts_with("use ") {
        return None;
    }
    if last.starts_with("static ") || last.starts_with("const ") {
        sinks.entry(STATIC).or_default().insert(line);
    } else {
        sinks.entry(UNANALYZED).or_default().insert(line);
    }
    Some(sinks)
}

/// `kind,kind` (sorted): an exclusion row records exactly these.
pub fn kinds(sinks: &Sinks) -> String {
    sinks.keys().copied().collect::<Vec<_>>().join(",")
}

/// `kind@line,line; kind@line`.
pub fn render(sinks: &Sinks) -> String {
    sinks
        .iter()
        .map(|(kind, lines)| {
            format!(
                "{kind}@{}",
                lines
                    .iter()
                    .map(usize::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}
