//! LAYER 2: the scan of the EXPANDED production source (`rustc -Zunpretty=expanded` on the pinned
//! nightly, one unit per production target and configuration, produced by expanded-scan.sh). The
//! compiler has already done everything the retired walker re-implemented: `mod` and `#[path]`
//! resolution, `cfg` and `cfg_attr` evaluation, `include!` inlining, macro expansion (an external
//! crate's macro included), and the removal of what a non-test build never compiles. What is left is
//! ONE token stream per target, read with the tokenizer proc macros use (`proc_macro2`), so no
//! comment and no doc attribute is code, and every literal is one token.
//!
//! In it, every occurrence of
//! - a REGISTERED CREDENTIAL PREFIX (prefixes.tsv) inside a string literal (`prefix`),
//! - a RANDOMNESS PRIMITIVE: the identifiers in `PRIMITIVE_IDENTS`, a path through `rand::`,
//!   `rand_core::` or `ring::rand`, and a string literal naming `/dev/urandom` or `/dev/random`
//!   (`primitive`),
//! - and, in a function whose name holds a credential keyword, a literal shaped like an
//!   UNREGISTERED prefix (`<word>_` or `<word>_{…}`) (`shaped`)
//!
//! is attributed to its enclosing item path (`mod a > impl B > fn c`) and counted. The item path is
//! a label: a misattribution moves a count between rows but cannot hide an occurrence, because every
//! occurrence is counted somewhere and the counts are compared with the registry both ways.

use crate::source::{compact, doc_attribute, string_content};
use proc_macro2::{Delimiter, Spacing, TokenStream, TokenTree};
use std::collections::BTreeMap;

/// Identifiers that name a randomness primitive wherever they appear (rand's RNG types and
/// functions, getrandom, uuid's random constructor, ring's RNG).
pub const PRIMITIVE_IDENTS: &[&str] = &[
    "OsRng",
    "ThreadRng",
    "StdRng",
    "SmallRng",
    "thread_rng",
    "getrandom",
    "getentropy",
    "new_v4",
    "new_v7",
    "now_v7",
    "from_entropy",
    "SystemRandom",
];

/// Path heads that name a randomness crate or module: `<head> ::`.
pub const PRIMITIVE_HEADS: &[&str] = &["rand", "rand_core"];

/// Literals naming the kernel's randomness devices.
pub const RANDOM_DEVICES: &[&str] = &["/dev/urandom", "/dev/random"];

/// Words that make a function credential-named (the retired lint's discovery names).
pub const CREDENTIAL_WORDS: &[&str] = &[
    "token", "secret", "bearer", "key", "verifier", "state", "nonce", "jwt",
];

/// (item path, kind, what) -> count.
pub type Hits = BTreeMap<(String, String, String), usize>;

struct Scan<'a> {
    prefixes: &'a [String],
    seen: BTreeMap<(String, String), usize>,
    hits: Hits,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Header {
    /// fn, impl, trait, mod, struct, enum, union: the body is the first brace group at angle depth
    /// 0; a `;` at depth 0 first means there is none.
    Braced,
    /// macro_rules NAME: the body is the next group.
    Macro,
    /// const NAME, static NAME, use: everything to the next `;` is the item.
    Statement,
}

fn ident(token: Option<&TokenTree>) -> Option<String> {
    match token {
        Some(TokenTree::Ident(id)) => Some(id.to_string()),
        _ => None,
    }
}

fn punct(token: Option<&TokenTree>) -> Option<(char, Spacing)> {
    match token {
        Some(TokenTree::Punct(p)) => Some((p.as_char(), p.spacing())),
        _ => None,
    }
}

fn is_punct(token: Option<&TokenTree>, c: char) -> bool {
    punct(token).is_some_and(|(p, _)| p == c)
}

fn is_path_sep(tokens: &[TokenTree], at: usize) -> bool {
    matches!(punct(tokens.get(at)), Some((':', Spacing::Joint)))
        && is_punct(tokens.get(at + 1), ':')
}

/// A `<head>_` or `<head>_{…}` shaped literal's head, if the literal is one.
pub fn shaped_head(content: &str) -> Option<String> {
    let head: String = content
        .chars()
        .take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '_')
        .collect();
    (head.len() >= 3
        && head.len() <= 20
        && head.ends_with('_')
        && (content.len() == head.len() || content[head.len()..].starts_with('{')))
    .then_some(head)
}

impl Scan<'_> {
    fn hit(&mut self, path: &[String], kind: &str, what: &str) {
        let item = if path.is_empty() {
            "<crate root>".to_string()
        } else {
            path.join(" > ")
        };
        *self
            .hits
            .entry((item, kind.to_string(), what.to_string()))
            .or_default() += 1;
    }

    fn segment(&mut self, path: &[String], segment: String) -> String {
        let n = self
            .seen
            .entry((path.join(" > "), segment.clone()))
            .or_insert(0);
        *n += 1;
        if *n > 1 {
            format!("{segment} #{n}")
        } else {
            segment
        }
    }

    fn credential_fn(path: &[String]) -> bool {
        path.iter()
            .rev()
            .find_map(|segment| segment.strip_prefix("fn "))
            .is_some_and(|name| {
                let name = name.split(" #").next().unwrap_or_default().to_lowercase();
                CREDENTIAL_WORDS.iter().any(|word| name.contains(word))
            })
    }

    /// The hits of one token (not a group).
    fn token(&mut self, tokens: &[TokenTree], at: usize, path: &[String]) {
        match &tokens[at] {
            TokenTree::Literal(literal) => {
                let Some(content) = string_content(literal) else {
                    return;
                };
                let mut registered = false;
                for prefix in self.prefixes {
                    if content.contains(prefix.as_str()) {
                        registered = true;
                        let what = prefix.clone();
                        self.hit(path, "prefix", &what);
                    }
                }
                for device in RANDOM_DEVICES {
                    if content.contains(device) {
                        self.hit(path, "primitive", device);
                    }
                }
                if !registered && Self::credential_fn(path) {
                    if let Some(head) = shaped_head(&content) {
                        self.hit(path, "shaped", &head);
                    }
                }
            }
            TokenTree::Ident(id) => {
                let name = id.to_string();
                if PRIMITIVE_IDENTS.contains(&name.as_str()) {
                    self.hit(path, "primitive", &name);
                }
                if PRIMITIVE_HEADS.contains(&name.as_str()) && is_path_sep(tokens, at + 1) {
                    self.hit(path, "primitive", &format!("{name}::"));
                }
                if name == "ring"
                    && is_path_sep(tokens, at + 1)
                    && ident(tokens.get(at + 3)).as_deref() == Some("rand")
                {
                    self.hit(path, "primitive", "ring::rand");
                }
            }
            _ => {}
        }
    }

    /// An item header starting at `at`, if one does: (segment, kind, tokens it spans before its
    /// body or end).
    fn header(tokens: &[TokenTree], at: usize) -> Option<(String, Header)> {
        let word = ident(tokens.get(at))?;
        let after_quote = at > 0 && is_punct(tokens.get(at - 1), '\'');
        let after_star = at > 0 && is_punct(tokens.get(at - 1), '*');
        match word.as_str() {
            "fn" | "mod" | "trait" | "struct" | "enum" | "union" => {
                let name = ident(tokens.get(at + 1))?;
                Some((format!("{word} {name}"), Header::Braced))
            }
            // `impl Trait` in a type position (an argument, a return type, a bound) is not an item.
            "impl" => {
                let in_type = at > 0
                    && (matches!(
                        punct(tokens.get(at - 1)),
                        Some((':' | ',' | '<' | '>' | '&' | '=' | '+' | '(', _))
                    ) || ident(tokens.get(at - 1)).as_deref() == Some("dyn"));
                (!in_type).then(|| ("impl".to_string(), Header::Braced))
            }
            "macro_rules" if is_punct(tokens.get(at + 1), '!') => {
                let name = ident(tokens.get(at + 2))?;
                Some((format!("macro_rules {name}"), Header::Macro))
            }
            "const" | "static" if !after_quote && !after_star => {
                let mut next = at + 1;
                if ident(tokens.get(next)).as_deref() == Some("mut") {
                    next += 1;
                }
                let name = match tokens.get(next) {
                    Some(TokenTree::Ident(id)) => id.to_string(),
                    _ => return None,
                };
                is_punct(tokens.get(next + 1), ':')
                    .then(|| (format!("{word} {name}"), Header::Statement))
            }
            "use" => Some(("use".to_string(), Header::Statement)),
            _ => None,
        }
    }

    fn walk(&mut self, stream: TokenStream, path: &mut Vec<String>) {
        let tokens: Vec<TokenTree> = stream.into_iter().collect();
        let mut at = 0;
        while at < tokens.len() {
            if let Some(skip) = doc_attribute(&tokens, at) {
                at += skip;
                continue;
            }
            if let Some((segment, kind)) = Self::header(&tokens, at) {
                at = self.item(&tokens, at, segment, kind, path);
                continue;
            }
            match &tokens[at] {
                TokenTree::Group(group) => self.walk(group.stream(), path),
                _ => self.token(&tokens, at, path),
            }
            at += 1;
        }
    }

    /// One item from its header at `at`; returns the index after it.
    fn item(
        &mut self,
        tokens: &[TokenTree],
        start: usize,
        segment: String,
        kind: Header,
        path: &mut Vec<String>,
    ) -> usize {
        let mut at = start;
        // An impl's name is its header up to its body; a use item's is its tree.
        let segment = match segment.as_str() {
            "impl" | "use" => {
                let mut end = at + 1;
                let mut depth = 0usize;
                while end < tokens.len() {
                    match &tokens[end] {
                        TokenTree::Punct(p) if p.as_char() == ';' && depth == 0 => break,
                        TokenTree::Group(g)
                            if g.delimiter() == Delimiter::Brace
                                && depth == 0
                                && segment == "impl" =>
                        {
                            break
                        }
                        TokenTree::Punct(p) if p.as_char() == '<' => depth += 1,
                        TokenTree::Punct(p)
                            if p.as_char() == '>'
                                && !(end > 0
                                    && matches!(
                                        punct(tokens.get(end - 1)),
                                        Some(('-' | '=', Spacing::Joint))
                                    )) =>
                        {
                            depth = depth.saturating_sub(1)
                        }
                        _ => {}
                    }
                    end += 1;
                }
                let text = compact(
                    tokens[at + 1..end.min(tokens.len())]
                        .iter()
                        .cloned()
                        .collect(),
                );
                format!("{segment} {text}")
            }
            _ => segment,
        };
        let segment = self.segment(path, segment);
        path.push(segment);
        at += 1;
        let mut depth = 0usize;
        while at < tokens.len() {
            if let Some(skip) = doc_attribute(tokens, at) {
                at += skip;
                continue;
            }
            match (&tokens[at], kind) {
                (TokenTree::Group(group), Header::Macro) => {
                    self.walk(group.stream(), path);
                    at += 1;
                    if is_punct(tokens.get(at), ';') {
                        at += 1;
                    }
                    break;
                }
                (TokenTree::Group(group), Header::Braced)
                    if group.delimiter() == Delimiter::Brace && depth == 0 =>
                {
                    self.walk(group.stream(), path);
                    at += 1;
                    break;
                }
                (TokenTree::Punct(p), Header::Braced | Header::Statement)
                    if p.as_char() == ';' && depth == 0 =>
                {
                    at += 1;
                    break;
                }
                (TokenTree::Punct(p), Header::Braced) if p.as_char() == '<' => {
                    depth += 1;
                    at += 1;
                }
                (TokenTree::Punct(p), Header::Braced)
                    if p.as_char() == '>'
                        && !matches!(
                            punct(tokens.get(at - 1)),
                            Some(('-' | '=', Spacing::Joint))
                        ) =>
                {
                    depth = depth.saturating_sub(1);
                    at += 1;
                }
                (TokenTree::Group(group), _) => {
                    self.walk(group.stream(), path);
                    at += 1;
                }
                _ => {
                    self.token(tokens, at, path);
                    at += 1;
                }
            }
        }
        path.pop();
        at
    }
}

/// Every hit of one expanded target.
pub fn scan(text: &str, prefixes: &[String]) -> Result<Hits, String> {
    let stream: TokenStream = text
        .parse()
        .map_err(|error| format!("the expansion does not tokenize: {error:?}"))?;
    let mut scan = Scan {
        prefixes,
        seen: BTreeMap::new(),
        hits: BTreeMap::new(),
    };
    scan.walk(stream, &mut Vec::new());
    Ok(scan.hits)
}
