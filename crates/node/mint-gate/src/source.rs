//! THE SOURCE MAP of layer 1: every item of a file the compiler reported a draw in, by `syn`, with
//! its position, so a diagnostic span is attributed to its ENCLOSING item. syn decides nothing
//! about what is production code (the compiler did, by reporting the span); it only names where a
//! reported position lies. A file that is not a whole Rust file (an `include!` fragment: an
//! expression or a statement list) is one item, `<include! fragment>`.
//!
//! It also computes a registered MINT's REGION: the smallest expression, statement or block of the
//! minting function that holds every draw the compiler reported there and every literal carrying
//! the mint's prefix. Its token rendering's digest is pinned, so a change to how the credential is
//! built from its draw re-opens the review (comments and formatting are not tokens).

use proc_macro2::{Delimiter, LineColumn, TokenStream, TokenTree};
use quote::ToTokens;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const FRAGMENT: &str = "<include! fragment>";

pub fn sha16(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))[..16].to_string()
}

/// One item of a source file: its path (`mod wire > impl ClientWriter > fn refuse`) and where it
/// starts and ends (line, 0-based column).
#[derive(Clone, Debug)]
pub struct Item {
    pub path: String,
    pub start: LineColumn,
    pub end: LineColumn,
}

/// The first and last positions of a token stream.
pub fn range(tokens: TokenStream) -> Option<(LineColumn, LineColumn)> {
    let mut out: Option<(LineColumn, LineColumn)> = None;
    for token in tokens {
        let span = match &token {
            TokenTree::Group(group) => group.span(),
            other => other.span(),
        };
        let (start, end) = (span.start(), span.end());
        out = Some(match out {
            None => (start, end),
            Some((low, high)) => (min(low, start), max(high, end)),
        });
    }
    out
}

fn key(at: LineColumn) -> (usize, usize) {
    (at.line, at.column)
}

fn min(a: LineColumn, b: LineColumn) -> LineColumn {
    if key(b) < key(a) {
        b
    } else {
        a
    }
}

fn max(a: LineColumn, b: LineColumn) -> LineColumn {
    if key(b) > key(a) {
        b
    } else {
        a
    }
}

fn contains(range: (LineColumn, LineColumn), at: LineColumn) -> bool {
    key(range.0) <= key(at) && key(at) < key(range.1)
}

/// Tokens rendered without spaces (item names built from types and use trees).
pub fn compact(tokens: TokenStream) -> String {
    tokens.to_string().split_whitespace().collect()
}

/// What `Mapper` collects when asked for one function's region.
struct Capture {
    path: String,
    positions: Vec<LineColumn>,
    /// (rendering, start, end) of every expression, statement and block of the function, and the
    /// function itself.
    nodes: Vec<(String, LineColumn, LineColumn)>,
    found: bool,
}

struct Nodes<'c> {
    out: &'c mut Vec<(String, LineColumn, LineColumn)>,
}

impl Nodes<'_> {
    fn push(&mut self, tokens: TokenStream) {
        if let Some((start, end)) = range(tokens.clone()) {
            self.out.push((tokens.to_string(), start, end));
        }
    }
}

impl<'ast> syn::visit::Visit<'ast> for Nodes<'_> {
    fn visit_expr(&mut self, node: &'ast syn::Expr) {
        self.push(node.to_token_stream());
        syn::visit::visit_expr(self, node);
    }
    fn visit_stmt(&mut self, node: &'ast syn::Stmt) {
        self.push(node.to_token_stream());
        syn::visit::visit_stmt(self, node);
    }
    fn visit_block(&mut self, node: &'ast syn::Block) {
        self.push(node.to_token_stream());
        syn::visit::visit_block(self, node);
    }
}

struct Mapper {
    stack: Vec<String>,
    /// How many items each (parent path, segment) has had, for ordinals.
    seen: BTreeMap<(String, String), usize>,
    items: Vec<Item>,
    capture: Option<Capture>,
}

impl Mapper {
    fn enter(&mut self, segment: String, tokens: TokenStream, _is_fn: bool) -> String {
        let parent = self.stack.join(" > ");
        let n = self.seen.entry((parent, segment.clone())).or_insert(0);
        *n += 1;
        let segment = if *n > 1 {
            format!("{segment} #{n}")
        } else {
            segment
        };
        self.stack.push(segment);
        let zero = LineColumn { line: 0, column: 0 };
        let (start, end) = range(tokens).unwrap_or((zero, zero));
        let path = self.stack.join(" > ");
        self.items.push(Item {
            path: path.clone(),
            start,
            end,
        });
        path
    }

    fn leave(&mut self) {
        self.stack.pop();
    }

    /// A function: if it is the captured one, collect its nodes.
    fn function(&mut self, name: String, tokens: TokenStream, visit_nodes: &dyn Fn(&mut Nodes)) {
        let path = self.enter(format!("fn {name}"), tokens.clone(), true);
        if let Some(capture) = self.capture.as_mut() {
            if capture.path == path {
                capture.found = true;
                let mut nodes = Nodes {
                    out: &mut capture.nodes,
                };
                nodes.push(tokens);
                visit_nodes(&mut nodes);
            }
        }
    }
}

impl<'ast> syn::visit::Visit<'ast> for Mapper {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        self.enter(format!("mod {}", node.ident), node.to_token_stream(), false);
        syn::visit::visit_item_mod(self, node);
        self.leave();
    }
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        self.function(
            node.sig.ident.to_string(),
            node.to_token_stream(),
            &|nodes| syn::visit::Visit::visit_block(nodes, &node.block),
        );
        syn::visit::visit_item_fn(self, node);
        self.leave();
    }
    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        let self_ty = compact(node.self_ty.to_token_stream());
        let segment = match &node.trait_ {
            Some((bang, path, _)) => format!(
                "impl {}{} for {self_ty}",
                if bang.is_some() { "!" } else { "" },
                compact(path.to_token_stream())
            ),
            None => format!("impl {self_ty}"),
        };
        self.enter(segment, node.to_token_stream(), false);
        syn::visit::visit_item_impl(self, node);
        self.leave();
    }
    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        self.function(
            node.sig.ident.to_string(),
            node.to_token_stream(),
            &|nodes| syn::visit::Visit::visit_block(nodes, &node.block),
        );
        syn::visit::visit_impl_item_fn(self, node);
        self.leave();
    }
    fn visit_item_trait(&mut self, node: &'ast syn::ItemTrait) {
        self.enter(
            format!("trait {}", node.ident),
            node.to_token_stream(),
            false,
        );
        syn::visit::visit_item_trait(self, node);
        self.leave();
    }
    fn visit_trait_item_fn(&mut self, node: &'ast syn::TraitItemFn) {
        self.function(
            node.sig.ident.to_string(),
            node.to_token_stream(),
            &|nodes| {
                if let Some(block) = &node.default {
                    syn::visit::Visit::visit_block(nodes, block);
                }
            },
        );
        syn::visit::visit_trait_item_fn(self, node);
        self.leave();
    }
    fn visit_impl_item_const(&mut self, node: &'ast syn::ImplItemConst) {
        self.enter(
            format!("const {}", node.ident),
            node.to_token_stream(),
            false,
        );
        syn::visit::visit_impl_item_const(self, node);
        self.leave();
    }
    fn visit_trait_item_const(&mut self, node: &'ast syn::TraitItemConst) {
        self.enter(
            format!("const {}", node.ident),
            node.to_token_stream(),
            false,
        );
        syn::visit::visit_trait_item_const(self, node);
        self.leave();
    }
    fn visit_item_struct(&mut self, node: &'ast syn::ItemStruct) {
        self.enter(
            format!("struct {}", node.ident),
            node.to_token_stream(),
            false,
        );
        syn::visit::visit_item_struct(self, node);
        self.leave();
    }
    fn visit_item_enum(&mut self, node: &'ast syn::ItemEnum) {
        self.enter(
            format!("enum {}", node.ident),
            node.to_token_stream(),
            false,
        );
        syn::visit::visit_item_enum(self, node);
        self.leave();
    }
    fn visit_item_const(&mut self, node: &'ast syn::ItemConst) {
        self.enter(
            format!("const {}", node.ident),
            node.to_token_stream(),
            false,
        );
        syn::visit::visit_item_const(self, node);
        self.leave();
    }
    fn visit_item_static(&mut self, node: &'ast syn::ItemStatic) {
        self.enter(
            format!("static {}", node.ident),
            node.to_token_stream(),
            false,
        );
        syn::visit::visit_item_static(self, node);
        self.leave();
    }
    fn visit_item_type(&mut self, node: &'ast syn::ItemType) {
        self.enter(
            format!("type {}", node.ident),
            node.to_token_stream(),
            false,
        );
        syn::visit::visit_item_type(self, node);
        self.leave();
    }
    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        self.enter(
            format!("use {}", compact(node.tree.to_token_stream())),
            node.to_token_stream(),
            false,
        );
        syn::visit::visit_item_use(self, node);
        self.leave();
    }
    fn visit_item_macro(&mut self, node: &'ast syn::ItemMacro) {
        let segment = match &node.ident {
            Some(name) => format!("macro_rules {name}"),
            None => format!("macro {}!", compact(node.mac.path.to_token_stream())),
        };
        self.enter(segment, node.to_token_stream(), false);
        syn::visit::visit_item_macro(self, node);
        self.leave();
    }
}

/// A parsed source file: its items, or one `<include! fragment>` item for a file that is not a
/// whole Rust file.
pub struct SourceFile {
    pub items: Vec<Item>,
    pub text: String,
    pub fragment: bool,
}

fn mapper(capture: Option<Capture>) -> Mapper {
    Mapper {
        stack: Vec::new(),
        seen: BTreeMap::new(),
        items: Vec::new(),
        capture,
    }
}

impl SourceFile {
    pub fn parse(name: &str, text: String) -> Result<SourceFile, String> {
        match syn::parse_file(&text) {
            Ok(file) => {
                let mut m = mapper(None);
                syn::visit::Visit::visit_file(&mut m, &file);
                Ok(SourceFile {
                    items: m.items,
                    text,
                    fragment: false,
                })
            }
            Err(_) => {
                // Not a whole file: an `include!` fragment. It must still be Rust tokens.
                let tokens: TokenStream = text.parse().map_err(|error| {
                    format!("{name} is neither a Rust file nor Rust tokens: {error:?}")
                })?;
                let zero = LineColumn { line: 0, column: 0 };
                let (start, _) = range(tokens).unwrap_or((zero, zero));
                let end = LineColumn {
                    line: usize::MAX,
                    column: 0,
                };
                Ok(SourceFile {
                    items: vec![Item {
                        path: FRAGMENT.to_string(),
                        start: LineColumn {
                            line: start.line.min(1),
                            column: 0,
                        },
                        end,
                    }],
                    text,
                    fragment: true,
                })
            }
        }
    }

    /// The innermost item containing (line, 0-based column).
    pub fn enclosing(&self, at: LineColumn) -> Option<&Item> {
        self.items
            .iter()
            .filter(|item| contains((item.start, item.end), at))
            .min_by_key(|item| {
                (
                    item.end.line.saturating_sub(item.start.line),
                    if item.end.line == item.start.line {
                        item.end.column.saturating_sub(item.start.column)
                    } else {
                        0
                    },
                    std::cmp::Reverse(key(item.start)),
                )
            })
    }

    /// A registered mint's REGION in this file: the smallest expression, statement or block of the
    /// function at `path` holding every position in `positions` and every non-doc literal whose
    /// content contains `prefix` (when given). Returns (digest, rendering's first 160 chars, number
    /// of prefix literals found).
    pub fn region(
        &self,
        path: &str,
        positions: &[LineColumn],
        prefix: Option<&str>,
    ) -> Result<(String, String, usize), String> {
        if self.fragment {
            return Err(format!(
                "{path}: a mint cannot be registered in an include! fragment"
            ));
        }
        let file = syn::parse_file(&self.text).map_err(|error| error.to_string())?;
        let mut m = mapper(Some(Capture {
            path: path.to_string(),
            positions: positions.to_vec(),
            nodes: Vec::new(),
            found: false,
        }));
        syn::visit::Visit::visit_file(&mut m, &file);
        let capture = m.capture.take().expect("the capture");
        if !capture.found {
            return Err(format!("no function {path:?} in the file"));
        }
        let mut wanted = capture.positions.clone();
        let mut literals = 0;
        if let Some(prefix) = prefix {
            let (_, function_start, function_end) = capture
                .nodes
                .first()
                .cloned()
                .ok_or("the function has no tokens")?;
            let tokens: TokenStream = self
                .text
                .parse()
                .map_err(|error| format!("the file does not tokenize: {error:?}"))?;
            for at in literal_positions(tokens, prefix) {
                if contains((function_start, function_end), at) {
                    wanted.push(at);
                    literals += 1;
                }
            }
        }
        if wanted.is_empty() {
            return Err(format!("{path}: no draw and no prefixed literal to bind"));
        }
        let best = capture
            .nodes
            .iter()
            .filter(|(_, start, end)| wanted.iter().all(|at| contains((*start, *end), *at)))
            .min_by_key(|(_, start, end)| {
                (
                    end.line - start.line,
                    if end.line == start.line {
                        end.column - start.column
                    } else {
                        usize::MAX - start.column
                    },
                )
            })
            .ok_or_else(|| format!("{path}: no node of the function holds every bound position"))?;
        let short: String = best.0.chars().take(160).collect();
        Ok((sha16(&best.0), short, literals))
    }
}

/// Is `tokens[at..]` a doc attribute (`#[doc ...]` or `#![doc ...]`)? Returns how many tokens it
/// spans.
pub fn doc_attribute(tokens: &[TokenTree], at: usize) -> Option<usize> {
    let TokenTree::Punct(hash) = tokens.get(at)? else {
        return None;
    };
    if hash.as_char() != '#' {
        return None;
    }
    let mut next = at + 1;
    if let Some(TokenTree::Punct(bang)) = tokens.get(next) {
        if bang.as_char() == '!' {
            next += 1;
        }
    }
    let TokenTree::Group(group) = tokens.get(next)? else {
        return None;
    };
    if group.delimiter() != Delimiter::Bracket {
        return None;
    }
    match group.stream().into_iter().next() {
        Some(TokenTree::Ident(ident)) if ident == "doc" => Some(next + 1 - at),
        _ => None,
    }
}

/// The content of a string-like literal (`"…"`, raw, byte and C forms), as written between its
/// quotes after escapes are resolved, or None for any other literal.
pub fn string_content(literal: &proc_macro2::Literal) -> Option<String> {
    match syn::parse_str::<syn::Lit>(&literal.to_string()).ok()? {
        syn::Lit::Str(s) => Some(s.value()),
        syn::Lit::ByteStr(s) => Some(String::from_utf8_lossy(&s.value()).to_string()),
        syn::Lit::CStr(s) => Some(s.value().to_string_lossy().to_string()),
        _ => None,
    }
}

/// The start of every non-doc string literal in `tokens` whose content contains `needle`.
pub fn literal_positions(tokens: TokenStream, needle: &str) -> Vec<LineColumn> {
    fn walk(tokens: TokenStream, needle: &str, out: &mut Vec<LineColumn>) {
        let tokens: Vec<TokenTree> = tokens.into_iter().collect();
        let mut at = 0;
        while at < tokens.len() {
            if let Some(skip) = doc_attribute(&tokens, at) {
                at += skip;
                continue;
            }
            match &tokens[at] {
                TokenTree::Group(group) => walk(group.stream(), needle, out),
                TokenTree::Literal(literal) => {
                    if string_content(literal).is_some_and(|content| content.contains(needle)) {
                        out.push(literal.span().start());
                    }
                }
                _ => {}
            }
            at += 1;
        }
    }
    let mut out = Vec::new();
    walk(tokens, needle, &mut out);
    out
}
