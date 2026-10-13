//! BUILD-DELTA #36 — a LINT that finds credential-minting sites in ordinary source shapes. It is not a proof, not a
//! closed guard, and it does not establish that any credential is random.
//!
//! WHAT IT DOES. In the non-test source of crates/node/src and crates/services/src, it finds string literals that start
//! with a registered credential prefix (`ioi_mnt_`, `ioi_pat_`, `ioi_lease_`, `wec_`, `wbt_`, `whk_`, `idisp_`, …) used to
//! build a value (`format!`, `+`, `.to_owned()`, `push_str`, `String::from`, `.join(`), and functions named like a credential
//! (token, secret, bearer, key, verifier, state, nonce, jwt) that build a `<prefix>_`-shaped value. Each must be a
//! registered (file, site, prefix, occurrence) or be reviewed by site; a registered function or file that disappears,
//! a second mint of a prefix, and a mint built from a hash slice or a clock fail.
//!
//! HOW IT READS THE SOURCE: the way the compiler does, with syn's FULL parser. From each crate root (`src/lib.rs`,
//! `src/main.rs`, `src/bin/*.rs`, `src/bin/*/main.rs`) it follows every `mod` declaration (`#[path]` included, with the
//! compiler's module-directory rules) and every `include!` (a fragment is parsed AT ITS INCLUDE SITE, as items in item
//! position and as one expression inside a function, never standalone). What a non-test build never compiles is not
//! production code: an item, statement, match arm or struct-literal field carrying a `cfg` that cannot hold without
//! `test` (`#[cfg(test)]`, `#[cfg(all(test, …))]`), everything inside it, recursively, and a module file reached only
//! through such a declaration. A file no root reaches is read standalone as a module; a file that parses neither as a
//! module nor at a found `include!` site, and an `include!` or `mod` whose file is not in the tree, FAIL the sweep.
//! Each function is identified by its SITE: its file, then the inline modules, the impl's self type (`Type`, or
//! `<Type as Trait>`) or the trait, and any enclosing function inside that file's module, then its name (a free
//! function at file level is just its name). Its body is its parsed block (`ItemFn`/`ImplItemFn`/`TraitItemFn`
//! `.block`); a nested function is its own site; documentation (doc comments, `#[doc]`) is dropped everywhere. Inside
//! a body every registered fragment is matched as a token sequence, through the tokenizer proc macros use
//! (`proc_macro2`): comments are gone and every literal is one opaque token. The scanner section names the API
//! discovery can build on (a function-local `const` is visible in a function's body tokens).
//!
//! WHAT IT GUARANTEES: AN INVENTORY. Every mint site it knows is named (file, site, prefix, occurrence, or a
//! primitive's exact draw and building code), and removing or replacing a registered draw at its site is flagged: a
//! primitive entry and a prefixed mint's registered draw (`fed_by`) are matched as token sequences in the body of the
//! ONE production function at the registered site (none, or more than one, is a violation), where no comment and no
//! literal content can satisfy them, so a commented-out draw, a copy of it in any literal, or a same-named function
//! elsewhere is a removed draw. It does NOT prove that the draw executes or that its output reaches the credential: a
//! draw in a dead branch, a decoy copy beside a constant, and a buffer overwritten after the draw (`secret.fill(0)`) all
//! pass this lint BY DESIGN (`a_dead_branch_or_decoy_draw_is_a_documented_lint_limit` pins that). The EXECUTION
//! property is guarded BEHAVIOURALLY. NOW: the editor connection token, by preview_editor_lease_tokens.rs
//! `two_editor_runtime_starts_get_different_nonzero_tokens`. PLANNED (deferred, not yet in the tree): every site by
//! BUILD-DELTA #36d's 256-draw entropy tests (the editor host is #36d-e), and the type-level guard of BUILD-DELTA #42.
//! It is not evidence that a credential is random.
//!
//! KNOWN GAPS (covered by review now, and by the PLANNED behavioural entropy tests of BUILD-DELTA #36d and type-level
//! guard of BUILD-DELTA #42): a function-local `const` holding a registered prefix; a mint built by a helper in another file; a
//! prefix assembled by a macro (`concat!`, `stringify!`) or at run time; a credential whose prefix is not in the list;
//! a credential minted in a function whose name holds none of the keywords and no registered prefix; weak entropy at
//! run time. Macro invocation bodies are tokens, not syntax: a function defined inside one is not a site (its prefixed
//! literals are "outside any function"), and an `include!` inside one is not followed (its file is then read standalone,
//! or fails). A `cfg` other than `test` (a feature, a platform) is read as production code. A pass means none of the
//! accidental shapes above was found, and nothing more.

use quote::ToTokens;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use syn::visit_mut::VisitMut;

struct Mint {
    file: &'static str,
    function: &'static str,
    /// The literal prefix this function mints (`ioi_mnt_`), or "" for a primitive that mints without one.
    prefix: &'static str,
    /// Which occurrence of the prefix in the function this entry describes (0-based, in source order).
    nth: usize,
    /// For a prefix mint: text the mint's own statement must contain (the RNG/uuid call, or the variable the RNG filled).
    /// For a primitive: text the function body must contain.
    inline: &'static str,
    /// Text the function must contain BEFORE the statement, filling the variable `inline` names ("" when inline suffices).
    fed_by: &'static str,
    /// Statement fragments tolerated for this mint (a one-way id of the secret, never the secret).
    tolerates: &'static [&'static str],
    note: &'static str,
}

const DISCOVERY_NAMES: &[&str] = &[
    "token", "secret", "bearer", "key", "verifier", "state", "nonce", "jwt",
];

/// Concrete credential prefixes.
const PREFIXES: &[&str] = &[
    "ioi_mnt_",
    "ioi_pat_",
    "ioi_lease_",
    "wec_",
    "wbt_",
    "whk_",
    "idisp_",
    "ioi_sess_",
    "ioi_bootstrap_",
    "ioi_api_",
];

const MINTS: &[Mint] = &[
    Mint { file: "node/src/bin/hypervisor-daemon.rs", function: "async_main", prefix: "idisp_", nth: 0, inline: "uuid::Uuid::new_v4()", fed_by: "", tolerates: &[], note: "per-boot internal dispatch secret: two UUIDv4 (244 bits), process memory only" },
    Mint { file: "node/src/bin/hypervisor_daemon_routes/authority_routes.rs", function: "issue_bearer_capability_lease", prefix: "ioi_lease_", nth: 0, inline: "hex::encode(secret)", fed_by: "rand::rngs::OsRng.fill_bytes(&mut secret)", tolerates: &[], note: "env-ops capability lease bearer: 32 bytes from the OS RNG" },
    Mint { file: "node/src/bin/hypervisor_daemon_routes/editor_host.rs", function: "start_oss_runtime", prefix: "", nth: 0, inline: "rand::rngs::OsRng.fill_bytes(&mut secret);", fed_by: "", tolerates: &[], note: "editor runtime connection token (BUILD-DELTA #31(c)): its draw, 32 bytes from the OS RNG; no prefix and no credential keyword, so only this entry sees it" },
    Mint { file: "node/src/bin/hypervisor_daemon_routes/editor_host.rs", function: "start_oss_runtime", prefix: "", nth: 0, inline: "(hex::encode(secret), hex::encode(nonce))", fed_by: "", tolerates: &[], note: "editor runtime connection token: its building statement, the hex of that draw" },
    Mint { file: "node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs", function: "handle_api_token_create", prefix: "ioi_pat_", nth: 0, inline: "uuid::Uuid::new_v4()", fed_by: "", tolerates: &[], note: "API access tokens: two UUIDv4" },
    Mint { file: "node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs", function: "gen_opaque", prefix: "", nth: 0, inline: "uuid::Uuid::new_v4()", fed_by: "", tolerates: &[], note: "bootstrap, session, SCIM and invite tokens: two UUIDv4 behind one primitive" },
    Mint { file: "node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs", function: "random_token", prefix: "", nth: 0, inline: "rand::thread_rng()", fed_by: "", tolerates: &[], note: "OAuth state, nonce and PKCE verifier: the thread CSPRNG, seeded from the OS" },
    Mint { file: "node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs", function: "mint_github_app_jwt", prefix: "", nth: 0, inline: "jwt_encode(", fed_by: "", tolerates: &[], note: "GitHub App JWT: SIGNED with the App private key (RS256), not random; its secrecy is the key's" },
    Mint { file: "node/src/bin/hypervisor_daemon_routes/managed_runtime_routes.rs", function: "handle_backup_export", prefix: "", nth: 0, inline: "uuid::Uuid::new_v4()", fed_by: "", tolerates: &[], note: "managed backup export download token: UUIDv4 (122 bits), stored as a hash" },
    Mint { file: "node/src/bin/hypervisor_daemon_routes/orchestration_routes.rs", function: "new_webhook_token", prefix: "whk_", nth: 0, inline: "uuid::Uuid::new_v4()", fed_by: "", tolerates: &[], note: "automation webhook trigger token: two UUIDv4" },
    Mint { file: "node/src/bin/hypervisor_daemon_routes/orchestration_routes.rs", function: "handle_automation_webhook", prefix: "whk_", nth: 0, inline: "uuid::Uuid::new_v4()", fed_by: "", tolerates: &[], note: "webhook EVENT id (whk_evt_), not a credential: a UUIDv4" },
    Mint { file: "node/src/bin/hypervisor_daemon_routes/workload_effect_boundary.rs", function: "mint_guest_effect_capability", prefix: "wec_", nth: 0, inline: "hex::encode(random)", fed_by: "OsRng.fill_bytes(&mut random)", tolerates: &[], note: "workload effect capability token: 32 bytes from the OS RNG" },
    Mint { file: "node/src/bin/hypervisor_daemon_routes/workload_effect_boundary.rs", function: "mint_guest_effect_capability", prefix: "wec_", nth: 1, inline: "Sha256::digest(token.as_bytes())", fed_by: "", tolerates: &["[.."], note: "workload effect capability ID, not the credential: a one-way 32-hex prefix of the token's SHA-256" },
    Mint { file: "node/src/bin/hypervisor_daemon_routes/workload_effect_boundary.rs", function: "mint_guest_governed_provider_effect_capability", prefix: "wbt_", nth: 0, inline: "hex::encode(trigger_random)", fed_by: "OsRng.fill_bytes(&mut trigger_random)", tolerates: &[], note: "host trigger: 32 bytes from the OS RNG" },
    Mint { file: "services/src/agentic/runtime/kernel/model_mount/capability_token_control.rs", function: "plan_capability_token_control", prefix: "ioi_mnt_", nth: 0, inline: "hex_lower(&secret)", fed_by: "OsRng.fill_bytes(&mut secret)", tolerates: &[], note: "model-mount capability token: 32 bytes from the OS RNG, id drawn separately" },
    Mint { file: "services/src/agentic/runtime/connectors/google_auth.rs", function: "random_url_safe_token", prefix: "", nth: 0, inline: "rand::thread_rng()", fed_by: "", tolerates: &[], note: "Google OAuth state and PKCE verifier primitive: the thread CSPRNG" },
    Mint { file: "services/src/agentic/runtime/connectors/google_auth.rs", function: "login", prefix: "", nth: 0, inline: "random_url_safe_token(48)", fed_by: "", tolerates: &[], note: "Google OAuth state (24 bytes) and PKCE code_verifier (48 bytes) come from that primitive" },
    Mint { file: "services/src/agentic/runtime/connectors/google_auth.rs", function: "login", prefix: "", nth: 0, inline: "random_url_safe_token(24)", fed_by: "", tolerates: &[], note: "Google OAuth state: a 24-byte draw from that primitive" },
];

/// A function that builds a value carrying a registered credential prefix and is NOT a credential: a name keyed by
/// something public. Accepted only on an EXACT (file, function, prefix) match, only for one occurrence in that
/// function, and only when that occurrence's statement contains the reviewed `statement` fragment exactly (the same
/// prefix a real bearer mints, so any other way of building it there, an RNG draw included, is a violation); an entry
/// whose function no longer builds it is stale. The list is not a wildcard: the same shape anywhere else, or a second one in the same function, is still
/// a violation. These are not mints and are kept out of `MINTS`.
struct NonMint {
    file: &'static str,
    function: &'static str,
    prefix: &'static str,
    /// The exact statement fragment that builds the value; the matched statement must contain it verbatim.
    statement: &'static str,
    reason: &'static str,
}

const REVIEWED_NON_MINTS: &[NonMint] = &[
    NonMint { file: "node/src/bin/hypervisor_daemon_routes/editor_proxy.rs", function: "lease_cookie_name", prefix: "ioi_lease_", statement: "format!(\"ioi_lease_{public_port}\")", reason: "builds the cookie NAME; the cookie VALUE is the access token minted by issue_bearer_capability_lease" },
];

/// Credential-NAMED functions that build a `<prefix>_{..}` value and were reviewed: each is an identifier or key, or a
/// nonce with its own entropy, not a bearer. Reviewed by name; a new one must be added here with its reason.
const DISCOVERY_REVIEWED: &[(&str, &str, &str)] = &[
    ("node/src/bin/hypervisor_daemon_routes/authority_challenge_routes.rs", "process_nonce", "in-flight marker for this process: 96 random bits, not presented anywhere"),
    ("node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs", "session_create_intent_key", "a record key derived from a session ref, not a credential"),
    ("node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs", "session_record_key", "a record key derived from a session ref, not a credential"),
    ("node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs", "session_receipt_key", "a record key derived from a session ref, not a credential"),
    ("node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs", "launch_record_key", "a record key, not a credential"),
    ("node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs", "standing_draw_nonce", "an anti-replay nonce: nanoseconds then 64 random bits; it authorizes nothing by itself"),
    ("node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs", "handle_secret_create", "sec_ is the public id of a stored secret (a hash of scope and name); the value is sealed"),
    ("node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs", "handle_api_token_create", "pat_ is the token's public id, a short hash of the token's SHA-256 (BUILD-DELTA #40); the token is the ioi_pat_ mint, registered above"),
    ("node/src/bin/hypervisor_daemon_routes/provider_spend_reconciliation_routes.rs", "handle_provider_billing_statement_admit", "pbs_ is a statement id"),
    ("node/src/bin/hypervisor_daemon_routes/state_machine_routes.rs", "handle_state_machine_create", "sm_ is a state-machine id"),
    ("services/src/agentic/automation.rs", "monitor_workflow_id_from_keywords", "a workflow id built from keywords"),
    ("services/src/agentic/runtime/kernel/approval.rs", "approval_state_update_thread_id_for_agent_id", "a thread id"),
];

// ---------------------------------------------------------------------------------------------------------------
// The scanner. It reads the tree the way the compiler does, with syn's full parser (`parse_tree`): crate roots, `mod`
// declarations (`#[path]` included) and `include!` sites are followed, what a non-test build never compiles is set
// aside, and each production function becomes a `Func`: its file, its SITE (the registry's `function` field: inline
// modules, impl self type or trait, enclosing functions, then its name, joined by `::`) and its body's TOKENS, through
// the tokenizer proc macros use (`proc_macro2`): comments are dropped, documentation attributes are dropped, and every
// literal (string, raw string, byte string, C string, char, byte char, number) is ONE opaque token, so no comment and
// no literal content can satisfy anything it matches. Its API, for discovery to build on: `parse_tree` (a tree's
// production functions, the tokens outside every function body, and the violations reading it), `string_content`
// (a string literal's contents), `pattern` (a code fragment as a token sequence) and `find_tokens` /
// `contains_tokens` (the token-sequence matcher). The tests feed it the real tree and planted counterexamples.
// ---------------------------------------------------------------------------------------------------------------

/// One token of a body. A group is flattened into its opening delimiter, its contents and its closing delimiter; a
/// literal keeps its exact source text (quotes, prefixes and hashes included) and is never looked inside, except by
/// `string_content`.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Tok {
    Ident(String),
    Punct(char),
    Lit(String),
    Open(char),
    Close(char),
}

/// The length of a documentation attribute at the start of `trees` (`#[doc …]` or `#![doc …]`, which is what a doc
/// comment becomes), or None.
fn doc_attribute(trees: &[proc_macro2::TokenTree]) -> Option<usize> {
    use proc_macro2::TokenTree;
    let TokenTree::Punct(hash) = trees.first()? else {
        return None;
    };
    if hash.as_char() != '#' {
        return None;
    }
    let at = match trees.get(1)? {
        TokenTree::Punct(bang) if bang.as_char() == '!' => 2,
        _ => 1,
    };
    let TokenTree::Group(group) = trees.get(at)? else {
        return None;
    };
    let is_doc = group.delimiter() == proc_macro2::Delimiter::Bracket
        && matches!(group.stream().into_iter().next(), Some(TokenTree::Ident(ident)) if ident == "doc");
    is_doc.then_some(at + 1)
}

fn flatten(stream: proc_macro2::TokenStream, out: &mut Vec<Tok>) {
    let trees: Vec<proc_macro2::TokenTree> = stream.into_iter().collect();
    let mut at = 0;
    while at < trees.len() {
        if let Some(len) = doc_attribute(&trees[at..]) {
            at += len;
            continue;
        }
        match &trees[at] {
            proc_macro2::TokenTree::Ident(ident) => out.push(Tok::Ident(ident.to_string())),
            proc_macro2::TokenTree::Punct(punct) => out.push(Tok::Punct(punct.as_char())),
            proc_macro2::TokenTree::Literal(literal) => out.push(Tok::Lit(literal.to_string())),
            proc_macro2::TokenTree::Group(group) => {
                let (open, close) = match group.delimiter() {
                    proc_macro2::Delimiter::Parenthesis => ('(', ')'),
                    proc_macro2::Delimiter::Brace => ('{', '}'),
                    proc_macro2::Delimiter::Bracket => ('[', ']'),
                    proc_macro2::Delimiter::None => ('\u{0}', '\u{0}'),
                };
                out.push(Tok::Open(open));
                flatten(group.stream(), out);
                out.push(Tok::Close(close));
            }
        }
        at += 1;
    }
}

/// A parsed node's tokens.
fn tokens(node: &impl ToTokens) -> Vec<Tok> {
    let mut out = Vec::new();
    flatten(node.to_token_stream(), &mut out);
    out
}

/// A code fragment as a token sequence, or why it does not tokenize.
fn file_tokens(text: &str) -> Result<Vec<Tok>, String> {
    let stream = proc_macro2::TokenStream::from_str(text).map_err(|error| error.to_string())?;
    let mut out = Vec::new();
    flatten(stream, &mut out);
    Ok(out)
}

/// A code fragment as a token sequence. A fragment may leave delimiters open (`jwt_encode(`, `[..`): they are closed to
/// tokenize it and the closing tokens are dropped, so the pattern is a prefix of the code it names.
fn pattern(fragment: &str) -> Vec<Tok> {
    let mut unclosed = Vec::new();
    for c in fragment.chars() {
        match c {
            '(' => unclosed.push(')'),
            '[' => unclosed.push(']'),
            '{' => unclosed.push('}'),
            ')' | ']' | '}' => {
                unclosed.pop();
            }
            _ => {}
        }
    }
    let closers: String = unclosed.iter().rev().collect();
    let mut toks = file_tokens(&format!("{fragment}{closers}"))
        .unwrap_or_else(|error| panic!("the pattern {fragment:?} tokenizes: {error}"));
    toks.truncate(toks.len() - closers.chars().count());
    toks
}

/// Where `needle` first occurs in `haystack`, as a contiguous token sequence.
fn find_tokens(haystack: &[Tok], needle: &[Tok]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn contains_tokens(haystack: &[Tok], needle: &[Tok]) -> bool {
    find_tokens(haystack, needle).is_some()
}

/// One past the token that closes the group opened at `open`.
fn group_end(toks: &[Tok], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (k, tok) in toks.iter().enumerate().skip(open) {
        match tok {
            Tok::Open(_) => depth += 1,
            Tok::Close(_) => {
                depth -= 1;
                if depth == 0 {
                    return Some(k + 1);
                }
            }
            _ => {}
        }
    }
    None
}

// ---- reading the tree the way the compiler does -----------------------------------------------------------------

/// Whether a `cfg` predicate can hold in a non-test build: Some(false) when it needs `test` (or can never hold),
/// Some(true) when it always holds, None when it depends on anything else (a feature, a platform).
fn cfg_holds(meta: &syn::Meta) -> Option<bool> {
    match meta {
        syn::Meta::Path(path) if path.is_ident("test") => Some(false),
        syn::Meta::List(list)
            if ["all", "any", "not"]
                .iter()
                .any(|op| list.path.is_ident(op)) =>
        {
            let args = list
                .parse_args_with(
                    syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
                )
                .ok()?;
            let values: Vec<Option<bool>> = args.iter().map(cfg_holds).collect();
            if list.path.is_ident("not") {
                return match values.as_slice() {
                    [value] => value.map(|v| !v),
                    _ => None,
                };
            }
            // all(): one false is false, all true is true; any(): one true is true, all false is false
            let all = list.path.is_ident("all");
            if values.contains(&Some(!all)) {
                Some(!all)
            } else if values.iter().all(|value| *value == Some(all)) {
                Some(all)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// An item, statement, arm or field that a non-test build never compiles: it carries a `cfg` that cannot hold there.
fn test_only(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("cfg")
            && attr
                .parse_args::<syn::Meta>()
                .ok()
                .and_then(|meta| cfg_holds(&meta))
                == Some(false)
    })
}

fn item_attrs(item: &syn::Item) -> &[syn::Attribute] {
    match item {
        syn::Item::Const(item) => &item.attrs,
        syn::Item::Enum(item) => &item.attrs,
        syn::Item::ExternCrate(item) => &item.attrs,
        syn::Item::Fn(item) => &item.attrs,
        syn::Item::ForeignMod(item) => &item.attrs,
        syn::Item::Impl(item) => &item.attrs,
        syn::Item::Macro(item) => &item.attrs,
        syn::Item::Mod(item) => &item.attrs,
        syn::Item::Static(item) => &item.attrs,
        syn::Item::Struct(item) => &item.attrs,
        syn::Item::Trait(item) => &item.attrs,
        syn::Item::TraitAlias(item) => &item.attrs,
        syn::Item::Type(item) => &item.attrs,
        syn::Item::Union(item) => &item.attrs,
        syn::Item::Use(item) => &item.attrs,
        _ => &[],
    }
}

fn impl_item_attrs(item: &syn::ImplItem) -> &[syn::Attribute] {
    match item {
        syn::ImplItem::Const(item) => &item.attrs,
        syn::ImplItem::Fn(item) => &item.attrs,
        syn::ImplItem::Type(item) => &item.attrs,
        syn::ImplItem::Macro(item) => &item.attrs,
        _ => &[],
    }
}

fn trait_item_attrs(item: &syn::TraitItem) -> &[syn::Attribute] {
    match item {
        syn::TraitItem::Const(item) => &item.attrs,
        syn::TraitItem::Fn(item) => &item.attrs,
        syn::TraitItem::Type(item) => &item.attrs,
        syn::TraitItem::Macro(item) => &item.attrs,
        _ => &[],
    }
}

fn expr_attrs(expr: &syn::Expr) -> &[syn::Attribute] {
    use syn::Expr;
    match expr {
        Expr::Array(e) => &e.attrs,
        Expr::Assign(e) => &e.attrs,
        Expr::Async(e) => &e.attrs,
        Expr::Await(e) => &e.attrs,
        Expr::Binary(e) => &e.attrs,
        Expr::Block(e) => &e.attrs,
        Expr::Break(e) => &e.attrs,
        Expr::Call(e) => &e.attrs,
        Expr::Cast(e) => &e.attrs,
        Expr::Closure(e) => &e.attrs,
        Expr::Const(e) => &e.attrs,
        Expr::Continue(e) => &e.attrs,
        Expr::Field(e) => &e.attrs,
        Expr::ForLoop(e) => &e.attrs,
        Expr::Group(e) => &e.attrs,
        Expr::If(e) => &e.attrs,
        Expr::Index(e) => &e.attrs,
        Expr::Infer(e) => &e.attrs,
        Expr::Let(e) => &e.attrs,
        Expr::Lit(e) => &e.attrs,
        Expr::Loop(e) => &e.attrs,
        Expr::Macro(e) => &e.attrs,
        Expr::Match(e) => &e.attrs,
        Expr::MethodCall(e) => &e.attrs,
        Expr::Paren(e) => &e.attrs,
        Expr::Path(e) => &e.attrs,
        Expr::Range(e) => &e.attrs,
        Expr::RawAddr(e) => &e.attrs,
        Expr::Reference(e) => &e.attrs,
        Expr::Repeat(e) => &e.attrs,
        Expr::Return(e) => &e.attrs,
        Expr::Struct(e) => &e.attrs,
        Expr::Try(e) => &e.attrs,
        Expr::TryBlock(e) => &e.attrs,
        Expr::Tuple(e) => &e.attrs,
        Expr::Unary(e) => &e.attrs,
        Expr::Unsafe(e) => &e.attrs,
        Expr::While(e) => &e.attrs,
        Expr::Yield(e) => &e.attrs,
        _ => &[],
    }
}

/// A statement's attributes. syn puts an expression statement's attributes on the leftmost operand of an
/// assignment, a binary operation or a cast.
fn stmt_attrs(stmt: &syn::Stmt) -> &[syn::Attribute] {
    match stmt {
        syn::Stmt::Local(local) => &local.attrs,
        syn::Stmt::Item(item) => item_attrs(item),
        syn::Stmt::Macro(mac) => &mac.attrs,
        syn::Stmt::Expr(expr, _) => {
            let mut expr = expr;
            loop {
                expr = match expr {
                    syn::Expr::Assign(e) => &e.left,
                    syn::Expr::Binary(e) => &e.left,
                    syn::Expr::Cast(e) => &e.expr,
                    other => return expr_attrs(other),
                };
            }
        }
    }
}

/// An item inside a body that holds functions of its own (each its own site, never part of the body).
fn holds_functions(item: &syn::Item) -> bool {
    matches!(
        item,
        syn::Item::Fn(_) | syn::Item::Impl(_) | syn::Item::Trait(_) | syn::Item::Mod(_)
    )
}

/// The path an `include!` (or `std::include!`, `core::include!`) names, as written; None for any other macro.
fn include_path(mac: &syn::Macro) -> Option<Result<String, String>> {
    let segments: Vec<String> = mac
        .path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect();
    let is_include = match segments.as_slice() {
        [only] => only == "include",
        [root, last] => (root == "std" || root == "core") && last == "include",
        _ => false,
    };
    is_include.then(|| {
        mac.parse_body::<syn::LitStr>()
            .map(|lit| lit.value())
            .map_err(|error| error.to_string())
    })
}

/// The first `#[path = "…"]` of a module declaration (the one the compiler uses).
fn path_attr(attrs: &[syn::Attribute]) -> Option<String> {
    let attr = attrs.iter().find(|attr| attr.path().is_ident("path"))?;
    let syn::Meta::NameValue(pair) = &attr.meta else {
        return None;
    };
    let syn::Expr::Lit(syn::ExprLit {
        lit: syn::Lit::Str(path),
        ..
    }) = &pair.value
    else {
        return None;
    };
    Some(path.value())
}

fn parent(rel: &str) -> &str {
    rel.rsplit_once('/').map_or("", |(dir, _)| dir)
}

/// `base` joined with a relative `path`, `.` and `..` resolved.
fn join(base: &str, path: &str) -> String {
    let mut parts: Vec<&str> = base.split('/').filter(|part| !part.is_empty()).collect();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            part => parts.push(part),
        }
    }
    parts.join("/")
}

fn ident_name(ident: &syn::Ident) -> String {
    ident.to_string().trim_start_matches("r#").to_string()
}

/// A type or path as compact text (`Foo<T>`, `<Foo as Bar>`), for a site.
fn compact(node: &impl ToTokens) -> String {
    let text: Vec<char> = node.to_token_stream().to_string().chars().collect();
    let word = |c: Option<&char>| c.is_some_and(|c| c.is_alphanumeric() || *c == '_' || *c == '\'');
    let mut out = String::new();
    for (k, c) in text.iter().enumerate() {
        if *c == ' ' && !(word(out.chars().last().as_ref()) && word(text.get(k + 1))) {
            continue;
        }
        out.push(*c);
    }
    out
}

fn impl_segment(imp: &syn::ItemImpl) -> String {
    let ty = compact(&imp.self_ty);
    match &imp.trait_ {
        Some((negative, path, _)) => format!(
            "<{ty} as {}{}>",
            if negative.is_some() { "!" } else { "" },
            compact(path)
        ),
        None => ty,
    }
}

/// A crate root in the tree, at any depth (a crate may sit inside another's src): `…/src/lib.rs`, `…/src/main.rs`,
/// `…/src/bin/*.rs` or `…/src/bin/*/main.rs`.
fn crate_root(rel: &str) -> bool {
    let parts: Vec<&str> = rel.split('/').collect();
    match parts.as_slice() {
        [.., "src", "lib.rs" | "main.rs"] => true,
        [.., "src", "bin", file] => file.ends_with(".rs"),
        [.., "src", "bin", _, "main.rs"] => true,
        _ => false,
    }
}

/// One production function as the compiler sees it.
#[derive(Clone)]
struct Func {
    /// The file its definition's text is in.
    file: String,
    /// Its site inside that file's module: inline modules, an impl's self type (`Type`, or `<Type as Trait>`) or a
    /// trait, enclosing functions, then its name, joined by `::` (a free function at file level is just its name).
    site: String,
    name: String,
    /// Its parsed block's tokens, braces included: each `include!` is replaced by its fragment's code; nested functions
    /// (their own sites), what a non-test build never compiles, and documentation are left out.
    body: Vec<Tok>,
}

/// A tree read as production code.
#[derive(Default)]
struct Tree {
    funcs: Vec<Func>,
    /// Tokens of production code outside every function body (a `const`, a `static`, an item macro, a signature).
    outside: Vec<(String, Vec<Tok>)>,
    /// Files that do not parse where production code reads them (a registered entry in one "cannot be read").
    unreadable: BTreeSet<String>,
    violations: Vec<String>,
}

/// Where a module's out-of-line submodules are found, as the compiler keeps it: a directory and, for a module file
/// that is not a `mod.rs` (nor a crate root, nor loaded by `#[path]`), its own name as one more directory.
#[derive(Clone)]
struct ModDir {
    dir: String,
    relative: Option<String>,
}

/// What an item is read inside of: its module directory (None inside a function body, where `mod x;` cannot be),
/// the site segments so far, and whether a non-test build never compiles it.
#[derive(Clone)]
struct Ctx {
    dir: Option<ModDir>,
    site: Vec<String>,
    test: bool,
}

struct Walk<'a> {
    files: &'a BTreeMap<String, &'a str>,
    tree: Tree,
    /// Every file read in some context (a module, or an `include!` site), test code included.
    reached: BTreeSet<String>,
    /// The module files walked as production code, and as test code, each once.
    production: BTreeSet<String>,
    test: BTreeSet<String>,
    /// The `include!` chain being read: a fragment that includes itself is a violation, not a loop.
    chain: Vec<String>,
}

impl Walk<'_> {
    /// A violation in production code; test code is read only to reach the files it declares or includes.
    fn violation(&mut self, test: bool, text: String) {
        if !test {
            self.tree.violations.push(text);
        }
    }

    fn outside(&mut self, rel: &str, test: bool, node: &impl ToTokens) {
        if !test {
            self.tree.outside.push((rel.to_string(), tokens(node)));
        }
    }

    fn module(&mut self, rel: &str, dir: ModDir, test: bool) {
        let first = if test {
            !self.production.contains(rel) && self.test.insert(rel.to_string())
        } else {
            self.production.insert(rel.to_string())
        };
        if !first {
            return;
        }
        self.reached.insert(rel.to_string());
        match syn::parse_file(self.files[rel]) {
            Ok(file) => {
                let test = test || test_only(&file.attrs);
                let ctx = Ctx {
                    dir: Some(dir),
                    site: Vec::new(),
                    test,
                };
                self.items(rel, &file.items, &ctx);
            }
            Err(error) => {
                if !test {
                    self.tree.unreadable.insert(rel.to_string());
                }
                self.violation(
                    test,
                    format!("{rel}: the module does not parse ({error}); the sweep cannot read it"),
                );
            }
        }
    }

    fn items(&mut self, rel: &str, items: &[syn::Item], ctx: &Ctx) {
        for item in items {
            let here = Ctx {
                test: ctx.test || test_only(item_attrs(item)),
                ..ctx.clone()
            };
            match item {
                syn::Item::Fn(function) => {
                    let mut signature = function.clone();
                    signature.block.stmts.clear();
                    self.outside(rel, here.test, &signature);
                    self.function(rel, &function.sig.ident, &function.block, &here);
                }
                syn::Item::Mod(module) => self.module_item(rel, module, &here),
                syn::Item::Impl(imp) => {
                    let mut shell = imp.clone();
                    shell
                        .items
                        .retain(|member| !test_only(impl_item_attrs(member)));
                    for member in &mut shell.items {
                        if let syn::ImplItem::Fn(function) = member {
                            function.block.stmts.clear();
                        }
                    }
                    self.outside(rel, here.test, &shell);
                    let site = [here.site.clone(), vec![impl_segment(imp)]].concat();
                    for member in &imp.items {
                        if let syn::ImplItem::Fn(function) = member {
                            let inner = Ctx {
                                dir: None,
                                site: site.clone(),
                                test: here.test || test_only(&function.attrs),
                            };
                            self.function(rel, &function.sig.ident, &function.block, &inner);
                        }
                    }
                }
                syn::Item::Trait(definition) => {
                    let mut shell = definition.clone();
                    shell
                        .items
                        .retain(|member| !test_only(trait_item_attrs(member)));
                    for member in &mut shell.items {
                        if let syn::TraitItem::Fn(function) = member {
                            if let Some(block) = &mut function.default {
                                block.stmts.clear();
                            }
                        }
                    }
                    self.outside(rel, here.test, &shell);
                    let site = [here.site.clone(), vec![ident_name(&definition.ident)]].concat();
                    for member in &definition.items {
                        if let syn::TraitItem::Fn(function) = member {
                            if let Some(block) = &function.default {
                                let inner = Ctx {
                                    dir: None,
                                    site: site.clone(),
                                    test: here.test || test_only(&function.attrs),
                                };
                                self.function(rel, &function.sig.ident, block, &inner);
                            }
                        }
                    }
                }
                syn::Item::Macro(mac) if include_path(&mac.mac).is_some() => {
                    self.include_items(rel, &mac.mac, &here)
                }
                other => self.outside(rel, here.test, other),
            }
        }
    }

    /// A `mod`: an inline one is read in place; an out-of-line one is found by the compiler's rules (`#[path]` relative
    /// to the module directory; else `<name>.rs` or `<name>/mod.rs` under it) and read as its own module.
    fn module_item(&mut self, rel: &str, module: &syn::ItemMod, ctx: &Ctx) {
        let name = ident_name(&module.ident);
        let path = path_attr(&module.attrs);
        if let Some((_, items)) = &module.content {
            let mut shell = module.clone();
            if let Some((_, inner)) = &mut shell.content {
                inner.clear();
            }
            self.outside(rel, ctx.test, &shell);
            let dir = ctx.dir.as_ref().map(|dir| match &path {
                Some(path) => ModDir {
                    dir: join(&dir.dir, path),
                    relative: None,
                },
                None => ModDir {
                    dir: join(
                        &join(&dir.dir, dir.relative.as_deref().unwrap_or("")),
                        &name,
                    ),
                    relative: None,
                },
            });
            let inner = Ctx {
                dir,
                site: [ctx.site.clone(), vec![name]].concat(),
                test: ctx.test,
            };
            self.items(rel, items, &inner);
            return;
        }
        self.outside(rel, ctx.test, module);
        let Some(dir) = &ctx.dir else {
            self.violation(
                ctx.test,
                format!("{rel}: `mod {name};` inside a function body; the sweep cannot read it"),
            );
            return;
        };
        let (target, child) = match path {
            Some(path) => {
                let target = join(&dir.dir, &path);
                let child = ModDir {
                    dir: parent(&target).to_string(),
                    relative: None,
                };
                (target, child)
            }
            None => {
                let base = join(&dir.dir, dir.relative.as_deref().unwrap_or(""));
                let primary = join(&base, &format!("{name}.rs"));
                let secondary = join(&base, &format!("{name}/mod.rs"));
                match (
                    self.files.contains_key(&primary),
                    self.files.contains_key(&secondary),
                ) {
                    (true, false) => {
                        let child = ModDir {
                            dir: parent(&primary).to_string(),
                            relative: Some(name.clone()),
                        };
                        (primary, child)
                    }
                    (false, true) => {
                        let child = ModDir {
                            dir: parent(&secondary).to_string(),
                            relative: None,
                        };
                        (secondary, child)
                    }
                    (true, true) => {
                        self.violation(
                            ctx.test,
                            format!("{rel}: `mod {name};` names both {primary} and {secondary}"),
                        );
                        return;
                    }
                    (false, false) => {
                        self.violation(ctx.test, format!("{rel}: `mod {name};` names {primary} or {secondary}, and neither is in the tree; the sweep cannot read it"));
                        return;
                    }
                }
            }
        };
        if !self.files.contains_key(&target) {
            self.violation(
                ctx.test,
                format!("{rel}: `mod {name};` names {target}, which is not in the tree; the sweep cannot read it"),
            );
            return;
        }
        self.module(&target, child, ctx.test);
    }

    /// The file an `include!` in `rel` names, now reached; None (with a violation) when its path is not a literal,
    /// its file is not in the tree, or it is already being included.
    fn fragment(&mut self, rel: &str, mac: &syn::Macro, test: bool) -> Option<String> {
        let path = match include_path(mac)? {
            Ok(path) if !path.starts_with('/') => path,
            Ok(path) => {
                self.violation(
                    test,
                    format!(
                        "{rel}: include!({path:?}) is an absolute path; the sweep cannot read it"
                    ),
                );
                return None;
            }
            Err(error) => {
                self.violation(test, format!("{rel}: an include! whose path is not a string literal ({error}); the sweep cannot read it"));
                return None;
            }
        };
        let target = join(parent(rel), &path);
        if !self.files.contains_key(&target) {
            self.violation(test, format!("{rel}: include!({path:?}) names {target}, which is not in the tree; the sweep cannot read it"));
            return None;
        }
        if self.chain.contains(&target) {
            self.violation(
                test,
                format!("{rel}: include!({path:?}) includes {target} inside itself"),
            );
            return None;
        }
        self.reached.insert(target.clone());
        Some(target)
    }

    /// An `include!` in item position: its fragment is read as items of the including module, at the include site.
    /// As the compiler does, a `mod` declaration inside the fragment is found from the FRAGMENT's directory.
    fn include_items(&mut self, rel: &str, mac: &syn::Macro, ctx: &Ctx) {
        let Some(target) = self.fragment(rel, mac, ctx.test) else {
            return;
        };
        match syn::parse_file(self.files[&target]) {
            Ok(file) => {
                let inner = Ctx {
                    dir: ctx.dir.as_ref().map(|_| ModDir {
                        dir: parent(&target).to_string(),
                        relative: None,
                    }),
                    ..ctx.clone()
                };
                self.chain.push(target.clone());
                self.items(&target, &file.items, &inner);
                self.chain.pop();
            }
            Err(error) => {
                if !ctx.test {
                    self.tree.unreadable.insert(target.clone());
                }
                self.violation(ctx.test, format!("{target}: the fragment does not parse as items at its include! site in {rel} ({error}); the sweep cannot read it"));
            }
        }
    }

    fn function(&mut self, rel: &str, ident: &syn::Ident, block: &syn::Block, ctx: &Ctx) {
        let name = ident_name(ident);
        let site = [ctx.site.clone(), vec![name.clone()]].concat();
        let mut body = block.clone();
        let nested = {
            let mut prune = Prune {
                walk: self,
                files: vec![rel.to_string()],
                test: ctx.test,
                nested: Vec::new(),
            };
            prune.visit_block_mut(&mut body);
            prune.nested
        };
        if !ctx.test {
            self.tree.funcs.push(Func {
                file: rel.to_string(),
                site: site.join("::"),
                name,
                body: tokens(&body),
            });
        }
        for (file, test, item) in nested {
            let inner = Ctx {
                dir: None,
                site: site.clone(),
                test,
            };
            self.items(&file, std::slice::from_ref(&item), &inner);
        }
    }
}

/// Builds a function body the way the compiler does: each `include!` in statement or expression position is replaced
/// by its fragment parsed as one expression (and read in the fragment's file); what a non-test build never compiles
/// (a statement, match arm or struct-literal field with a `cfg` that cannot hold) is read as test code and left out;
/// a nested item that holds functions is set aside as its own site.
struct Prune<'w, 'a> {
    walk: &'w mut Walk<'a>,
    /// The file whose text is being read: the function's, or a fragment an `include!` spliced in.
    files: Vec<String>,
    test: bool,
    /// Items inside the body that hold functions: (file, test, item).
    nested: Vec<(String, bool, syn::Item)>,
}

impl Prune<'_, '_> {
    fn file(&self) -> String {
        self.files.last().cloned().unwrap_or_default()
    }

    /// Read a node as test code: its `include!` files are reached and its nested items walked as test code.
    fn as_test(&mut self, read: impl FnOnce(&mut Self)) {
        let was = self.test;
        self.test = true;
        read(self);
        self.test = was;
    }

    /// The fragment an `include!` in expression position names, parsed as one expression and read in its own file.
    fn spliced(&mut self, mac: &syn::Macro) -> Option<syn::Expr> {
        let rel = self.file();
        let target = self.walk.fragment(&rel, mac, self.test)?;
        match syn::parse_str::<syn::Expr>(self.walk.files[&target]) {
            Ok(mut expr) => {
                self.walk.chain.push(target.clone());
                self.files.push(target);
                self.visit_expr_mut(&mut expr);
                self.files.pop();
                self.walk.chain.pop();
                Some(expr)
            }
            Err(error) => {
                if !self.test {
                    self.walk.tree.unreadable.insert(target.clone());
                }
                self.walk.violation(self.test, format!("{target}: the fragment does not parse as an expression at its include! site in {rel} ({error}); the sweep cannot read it"));
                None
            }
        }
    }
}

impl VisitMut for Prune<'_, '_> {
    fn visit_block_mut(&mut self, block: &mut syn::Block) {
        for stmt in std::mem::take(&mut block.stmts) {
            if !self.test && test_only(stmt_attrs(&stmt)) {
                // read in a block of its own, so its include! sites and nested items are reached as test code
                let mut alone = syn::Block {
                    brace_token: Default::default(),
                    stmts: vec![stmt],
                };
                self.as_test(|prune| prune.visit_block_mut(&mut alone));
                continue;
            }
            match stmt {
                syn::Stmt::Item(item) if holds_functions(&item) => {
                    let file = self.file();
                    self.nested.push((file, self.test, item));
                }
                syn::Stmt::Macro(mac) if include_path(&mac.mac).is_some() => {
                    match self.spliced(&mac.mac) {
                        Some(expr) => block.stmts.push(syn::Stmt::Expr(expr, mac.semi_token)),
                        None => block.stmts.push(syn::Stmt::Macro(mac)),
                    }
                }
                mut other => {
                    self.visit_stmt_mut(&mut other);
                    block.stmts.push(other);
                }
            }
        }
    }

    fn visit_expr_mut(&mut self, expr: &mut syn::Expr) {
        let include = match &*expr {
            syn::Expr::Macro(mac) if include_path(&mac.mac).is_some() => Some(mac.mac.clone()),
            _ => None,
        };
        match include {
            Some(mac) => {
                if let Some(spliced) = self.spliced(&mac) {
                    *expr = spliced;
                }
            }
            None => syn::visit_mut::visit_expr_mut(self, expr),
        }
    }

    fn visit_expr_match_mut(&mut self, node: &mut syn::ExprMatch) {
        if !self.test {
            let (kept, dropped): (Vec<syn::Arm>, Vec<syn::Arm>) = std::mem::take(&mut node.arms)
                .into_iter()
                .partition(|arm| !test_only(&arm.attrs));
            node.arms = kept;
            for mut arm in dropped {
                self.as_test(|prune| prune.visit_arm_mut(&mut arm));
            }
        }
        syn::visit_mut::visit_expr_match_mut(self, node);
    }

    fn visit_expr_struct_mut(&mut self, node: &mut syn::ExprStruct) {
        if !self.test {
            for pair in std::mem::take(&mut node.fields).into_pairs() {
                let (mut field, comma) = pair.into_tuple();
                if test_only(&field.attrs) {
                    self.as_test(|prune| prune.visit_field_value_mut(&mut field));
                    continue;
                }
                node.fields.push_value(field);
                if let Some(comma) = comma {
                    node.fields.push_punct(comma);
                }
            }
        }
        syn::visit_mut::visit_expr_struct_mut(self, node);
    }
}

/// The tree read as production code: from each crate root, then each file no root reached, standalone. syn's parser
/// recurses with the source's nesting, so it reads on a thread of its own with a large stack.
fn parse_tree(files: &[(String, String)]) -> Tree {
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .name("parse_tree".to_string())
            .stack_size(512 << 20)
            .spawn_scoped(scope, || read_tree(files))
            .expect("the parse thread starts")
            .join()
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
    })
}

fn read_tree(files: &[(String, String)]) -> Tree {
    let map: BTreeMap<String, &str> = files
        .iter()
        .map(|(rel, text)| (rel.clone(), text.as_str()))
        .collect();
    let mut walk = Walk {
        files: &map,
        tree: Tree::default(),
        reached: BTreeSet::new(),
        production: BTreeSet::new(),
        test: BTreeSet::new(),
        chain: Vec::new(),
    };
    for rel in map.keys().filter(|rel| crate_root(rel)) {
        let dir = ModDir {
            dir: parent(rel).to_string(),
            relative: None,
        };
        walk.module(rel, dir, false);
    }
    // A file no root reaches is read as `mod <name>;` would load it; one that may include others goes first, so a
    // fragment it includes is read at its include site, not standalone.
    let mut orphans: Vec<&String> = map
        .keys()
        .filter(|rel| !walk.reached.contains(*rel))
        .collect();
    orphans.sort_by_key(|rel| !map[*rel].contains("include!"));
    for rel in orphans {
        if walk.reached.contains(rel) {
            continue;
        }
        if let Err(error) = syn::parse_file(map[rel]) {
            walk.reached.insert(rel.clone());
            walk.tree.unreadable.insert(rel.clone());
            walk.tree.violations.push(format!("{rel}: the file parses neither as a module nor at a found include! site ({error}); the sweep cannot read it"));
            continue;
        }
        let stem = rel.rsplit('/').next().unwrap_or("").trim_end_matches(".rs");
        let dir = ModDir {
            dir: parent(rel).to_string(),
            relative: (!["mod", "lib", "main"].contains(&stem)).then(|| stem.to_string()),
        };
        walk.module(rel, dir, false);
    }
    walk.tree
}

// ---- the sweep ----------------------------------------------------------------------------------------------------

/// A string literal's contents (`"…"`, `r"…"`, `r#"…"#`, and the byte and C forms of each), or None for any other
/// literal.
fn string_content(lit: &str) -> Option<&str> {
    let rest = ["br", "cr", "b", "c", "r", ""].iter().find_map(|prefix| {
        lit.strip_prefix(prefix).filter(|rest| {
            rest.starts_with('"') || (prefix.ends_with('r') && rest.starts_with('#'))
        })
    })?;
    let hashes = rest.chars().take_while(|c| *c == '#').count();
    let body = &rest[hashes..];
    let close = format!("\"{}", "#".repeat(hashes));
    (body.len() >= 1 + close.len() && body.starts_with('"') && body.ends_with(&close))
        .then(|| &body[1..body.len() - close.len()])
}

/// The statement holding the token at `at` inside `range`: from after the previous `;`, `{`, `}` or `,` to the end of
/// the call holding it (its innermost unclosed `(`), else to the next `;`.
fn statement_around(toks: &[Tok], at: usize, range: (usize, usize)) -> (usize, usize) {
    let mut start = range.0;
    for k in (range.0..at).rev() {
        if matches!(
            toks[k],
            Tok::Punct(';') | Tok::Open('{') | Tok::Close('}') | Tok::Punct(',')
        ) {
            start = k + 1;
            break;
        }
    }
    let mut depth = 0usize;
    let mut open = None;
    for k in (start..at).rev() {
        match toks[k] {
            Tok::Close(')') => depth += 1,
            Tok::Open('(') => {
                if depth == 0 {
                    open = Some(k);
                    break;
                }
                depth -= 1;
            }
            _ => {}
        }
    }
    if let Some(end) = open.and_then(|open| group_end(toks, open)) {
        if end <= range.1 {
            return (start, end);
        }
    }
    let end = (at..range.1)
        .find(|&k| toks[k] == Tok::Punct(';'))
        .unwrap_or(range.1);
    (start, end)
}

struct Candidate {
    prefix: &'static str,
    statement: (usize, usize),
}

fn patterns(fragments: &[&str]) -> Vec<Vec<Tok>> {
    fragments.iter().map(|fragment| pattern(fragment)).collect()
}

fn is_building(statement: &[Tok]) -> bool {
    static BUILDING: std::sync::OnceLock<Vec<Vec<Tok>>> = std::sync::OnceLock::new();
    BUILDING
        .get_or_init(|| {
            patterns(&[
                "+",
                "push_str",
                "to_owned",
                "String::from",
                "format!",
                "concat!",
                ".join(",
                ".to_string()",
                ".into()",
            ])
        })
        .iter()
        .any(|p| contains_tokens(statement, p))
}

fn is_comparing(statement: &[Tok]) -> bool {
    static COMPARING: std::sync::OnceLock<Vec<Vec<Tok>>> = std::sync::OnceLock::new();
    COMPARING
        .get_or_init(|| {
            patterns(&[
                "starts_with",
                "strip_prefix",
                "matches!",
                "==",
                "!=",
                ".eq(",
                "ends_with",
                ".contains(",
            ])
        })
        .iter()
        .any(|p| contains_tokens(statement, p))
}

/// Every string literal in `toks` that starts with a registered prefix: (position, prefix, contents).
fn prefixed_literals(toks: &[Tok]) -> Vec<(usize, &'static str, &str)> {
    let mut out = Vec::new();
    for (at, tok) in toks.iter().enumerate() {
        let Tok::Lit(lit) = tok else {
            continue;
        };
        let Some(content) = string_content(lit) else {
            continue;
        };
        if let Some(prefix) = PREFIXES.iter().find(|p| content.starts_with(**p)) {
            out.push((at, *prefix, content));
        }
    }
    out
}

/// Every prefixed string literal in a function body that is used to BUILD a value (not to compare against one).
fn candidates(body: &[Tok]) -> Vec<Candidate> {
    let mut out = Vec::new();
    for (at, prefix, content) in prefixed_literals(body) {
        let statement = statement_around(body, at, (0, body.len()));
        let stmt = &body[statement.0..statement.1];
        let building = content.contains('{') || is_building(stmt);
        let comparing = is_comparing(stmt);
        if !building || (comparing && !content.contains('{')) {
            continue;
        }
        out.push(Candidate { prefix, statement });
    }
    out
}

/// String literals shaped like `<word>_` or `<word>_{..}` in a function body, used to BUILD a value: prefixes this
/// lint was not told about.
fn shaped_prefixes(body: &[Tok]) -> Vec<String> {
    let mut out = Vec::new();
    for (at, tok) in body.iter().enumerate() {
        let Tok::Lit(lit) = tok else {
            continue;
        };
        let Some(content) = string_content(lit) else {
            continue;
        };
        let head: String = content
            .chars()
            .take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '_')
            .collect();
        if !(head.len() >= 3
            && head.len() <= 20
            && head.ends_with('_')
            && (content.len() == head.len() || content[head.len()..].starts_with('{')))
        {
            continue;
        }
        if !content.contains('{') {
            let (a, z) = statement_around(body, at, (0, body.len()));
            let stmt = &body[a..z];
            if !is_building(stmt) || is_comparing(stmt) {
                continue;
            }
        }
        out.push(head);
    }
    out
}

/// Scan the given files. One line per violation; empty means no accidental shape inside this lint's scope.
fn scan(files: &[(String, String)]) -> Vec<String> {
    let forbidden_fragments = [
        "[..",
        "hash_json(",
        "create_hash",
        "as_millis",
        "as_secs",
        "as_nanos",
        "SystemTime",
        "Instant::now",
    ];
    let forbidden: Vec<(&str, Vec<Tok>)> = forbidden_fragments
        .iter()
        .map(|fragment| (*fragment, pattern(fragment)))
        .collect();
    let tree = parse_tree(files);
    let mut violations = tree.violations.clone();
    let mut found: Vec<(String, String, String, usize)> = Vec::new(); // (file, site, prefix, occurrences)
    let mut non_mints_built: Vec<(String, String)> = Vec::new(); // (file, site) of reviewed non-mints seen

    // 1. a registered prefix held outside every function body
    for (rel, toks) in &tree.outside {
        for (_, prefix, _) in prefixed_literals(toks) {
            violations.push(format!("{rel}: `{prefix}…` is held outside any function (a const or static): register the mint that uses it"));
        }
    }
    for func in &tree.funcs {
        let (rel, site, toks) = (&func.file, &func.site, &func.body);
        // 2. every mint candidate against the registry, by (file, site, prefix, nth)
        let mut seen: Vec<String> = Vec::new(); // the prefix of each candidate, in order
        for cand in candidates(toks) {
            let nth = seen.iter().filter(|p| *p == cand.prefix).count();
            seen.push(cand.prefix.to_string());
            let statement = &toks[cand.statement.0..cand.statement.1];
            if let Some(non_mint) = REVIEWED_NON_MINTS
                .iter()
                .find(|n| n.file == rel && n.function == site && n.prefix == cand.prefix)
            {
                if nth > 0 {
                    violations.push(format!("{rel}: `{site}` builds `{}…` more than once; only one reviewed non-mint is accepted there", cand.prefix));
                } else if !contains_tokens(statement, &pattern(non_mint.statement)) {
                    violations.push(format!(
                        "{rel}: `{site}` builds `{}…` other than by its reviewed statement {:?}",
                        cand.prefix, non_mint.statement
                    ));
                } else {
                    non_mints_built.push((rel.clone(), site.clone()));
                }
                continue;
            }
            let Some(mint) = MINTS.iter().find(|m| {
                m.file == rel && m.function == site && m.prefix == cand.prefix && m.nth == nth
            }) else {
                let known = MINTS
                    .iter()
                    .any(|m| m.file == rel && m.function == site && m.prefix == cand.prefix);
                violations.push(if known {
                    format!(
                        "{rel}: `{site}` mints `{}…` more times than the registry says (occurrence {})",
                        cand.prefix,
                        nth + 1
                    )
                } else {
                    format!(
                        "{rel}: `{}…` is minted in `{site}`, which is not a registered minting site",
                        cand.prefix
                    )
                });
                continue;
            };
            if !contains_tokens(statement, &pattern(mint.inline)) {
                violations.push(format!(
                    "{rel}: the `{}…` mint in `{site}` is not formed from its registered source {:?}",
                    cand.prefix, mint.inline
                ));
            }
            if !mint.fed_by.is_empty()
                && !contains_tokens(&toks[..cand.statement.0], &pattern(mint.fed_by))
            {
                violations.push(format!(
                    "{rel}: the `{}…` mint in `{site}` is not preceded by its registered draw {:?}",
                    cand.prefix, mint.fed_by
                ));
            }
            for (fragment, tokens) in &forbidden {
                if contains_tokens(statement, tokens) && !mint.tolerates.contains(fragment) {
                    violations.push(format!(
                        "{rel}: the `{}…` mint in `{site}` is built from a derivation ({fragment:?})",
                        cand.prefix
                    ));
                }
            }
        }
        for prefix in &seen {
            if let Some(entry) = found
                .iter_mut()
                .find(|(f, s, p, _)| f == rel && s == site && p == prefix)
            {
                entry.3 += 1;
            } else {
                found.push((rel.clone(), site.clone(), prefix.clone(), 1));
            }
        }
        // 3. discovery: a credential-named function that builds a prefix-shaped value is registered or reviewed by site
        let lower = func.name.to_lowercase();
        if !DISCOVERY_NAMES.iter().any(|w| lower.contains(w)) {
            continue;
        }
        for head in shaped_prefixes(toks) {
            let registered = MINTS
                .iter()
                .any(|m| m.file == rel && m.function == site && m.prefix == head);
            let reviewed = DISCOVERY_REVIEWED
                .iter()
                .any(|(f, s, _)| f == rel && s == site);
            if !registered && !reviewed {
                violations.push(format!(
                    "{rel}: `{site}` builds a `{head}…` value and is neither registered nor reviewed"
                ));
            }
        }
    }
    // 4. the registry against the tree: every registered file and site exists as exactly one production function,
    // every registered mint is found, and every reviewed non-mint is still built where it was reviewed
    for non_mint in REVIEWED_NON_MINTS {
        if !files.iter().any(|(rel, _)| rel == non_mint.file) {
            violations.push(format!(
                "{}: the reviewed non-mint `{}`'s file is missing from the tree: remove it",
                non_mint.file, non_mint.function
            ));
        } else if !non_mints_built
            .iter()
            .any(|(f, s)| f == non_mint.file && s == non_mint.function)
        {
            violations.push(format!(
                "{}: the reviewed non-mint `{}` no longer builds `{}…` by {:?} ({}): remove it",
                non_mint.file,
                non_mint.function,
                non_mint.prefix,
                non_mint.statement,
                non_mint.reason
            ));
        }
    }
    let mut missing_files: Vec<&str> = Vec::new();
    for mint in MINTS {
        let rel = mint.file;
        if !files.iter().any(|(r, _)| r == rel) {
            if !missing_files.contains(&rel) {
                missing_files.push(rel);
                violations.push(format!(
                    "{rel}: the registered file is missing from the tree"
                ));
            }
            continue;
        }
        let sites: Vec<&Func> = tree
            .funcs
            .iter()
            .filter(|f| f.file == rel && f.site == mint.function)
            .collect();
        let func = match sites.as_slice() {
            [func] => *func,
            [] if tree.unreadable.contains(rel) => {
                violations.push(format!(
                    "{rel}: the registered minting function `{}` cannot be read: its file does not parse",
                    mint.function
                ));
                continue;
            }
            [] => {
                violations.push(format!(
                    "{rel}: the registered minting function `{}` no longer exists",
                    mint.function
                ));
                continue;
            }
            many => {
                violations.push(format!(
                    "{rel}: the registered minting function `{}` is {} production functions at that site; the registry cannot tell which one mints",
                    mint.function,
                    many.len()
                ));
                continue;
            }
        };
        if mint.prefix.is_empty() {
            // The function body's tokens: a primitive's draw in a comment or inside any literal is not a draw.
            if !contains_tokens(&func.body, &pattern(mint.inline)) {
                violations.push(format!(
                    "{rel}: `{}` ({}) no longer shows {:?}",
                    mint.function, mint.note, mint.inline
                ));
            }
        } else {
            let count = found
                .iter()
                .find(|(f, s, p, _)| f == rel && s == mint.function && p == mint.prefix)
                .map_or(0, |e| e.3);
            if count <= mint.nth {
                violations.push(format!(
                    "{rel}: `{}` no longer mints `{}…` (occurrence {} registered, {} found)",
                    mint.function,
                    mint.prefix,
                    mint.nth + 1,
                    count
                ));
            }
        }
    }
    violations.sort();
    violations.dedup();
    violations
}

fn crates_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path
                .file_name()
                .is_some_and(|n| n == "tests" || n == "target")
            {
                continue;
            }
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

fn real_tree() -> Vec<(String, String)> {
    let mut paths = Vec::new();
    rust_files(&crates_dir().join("node/src"), &mut paths);
    rust_files(&crates_dir().join("services/src"), &mut paths);
    paths.sort();
    paths
        .into_iter()
        .map(|path| {
            let rel = path
                .strip_prefix(crates_dir())
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{rel}: {e}"));
            (rel, text)
        })
        .collect()
}

/// The real tree with one file's text edited: the planted counterexamples.
fn tree_with(rel: &str, edit: impl Fn(&str) -> String) -> Vec<(String, String)> {
    let mut tree = real_tree();
    let entry = tree
        .iter_mut()
        .find(|(r, _)| r == rel)
        .unwrap_or_else(|| panic!("{rel} is in the tree"));
    entry.1 = edit(&entry.1);
    tree
}

/// The real tree with one file's text edited and new files added: the planted counterexamples that need a second file.
fn tree_adding(
    rel: &str,
    edit: impl Fn(&str) -> String,
    added: &[(&str, &str)],
) -> Vec<(String, String)> {
    let mut tree = tree_with(rel, edit);
    for (path, text) in added {
        assert!(!tree.iter().any(|(r, _)| r == path), "{path} is a new file");
        tree.push((path.to_string(), text.to_string()));
    }
    tree.sort();
    tree
}

const KERNEL: &str = "services/src/agentic/runtime/kernel/model_mount/capability_token_control.rs";
const ORCH: &str = "node/src/bin/hypervisor_daemon_routes/orchestration_routes.rs";
const AUTH: &str = "node/src/bin/hypervisor_daemon_routes/authority_routes.rs";

const PROXY: &str = "node/src/bin/hypervisor_daemon_routes/editor_proxy.rs";
const EDITOR_HOST: &str = "node/src/bin/hypervisor_daemon_routes/editor_host.rs";

/// The editor runtime's connection token (BUILD-DELTA #31(c)) carries no prefix and its function no credential
/// keyword, so only the registry can see it: its 32-byte OS-random draw replaced by a constant, or its building
/// statement replaced by a constant, is a violation at that site.
#[test]
fn an_editor_connection_token_built_from_a_constant_fails_the_sweep() {
    let drawn_constant = tree_with(EDITOR_HOST, |text| {
        let planted = text.replacen(
            "        rand::rngs::OsRng.fill_bytes(&mut secret);\n",
            "        secret = [0u8; 32];\n",
            1,
        );
        assert_ne!(planted, text, "the planted draw edit applies");
        planted
    });
    let violations = scan(&drawn_constant);
    assert!(
        violations
            .iter()
            .any(|v| v.contains("editor_host.rs") && v.contains("start_oss_runtime")),
        "the draw replaced by a constant is caught at its site: {violations:?}"
    );
    let built_constant = tree_with(EDITOR_HOST, |text| {
        let planted = text.replacen(
            "        (hex::encode(secret), hex::encode(nonce))\n",
            "        (\"0\".repeat(64), hex::encode(nonce))\n",
            1,
        );
        assert_ne!(planted, text, "the planted building edit applies");
        planted
    });
    let violations = scan(&built_constant);
    assert!(
        violations
            .iter()
            .any(|v| v.contains("editor_host.rs") && v.contains("start_oss_runtime")),
        "the token built from a constant is caught at its site: {violations:?}"
    );
}

/// A registered draw commented out is a removed draw: the editor connection token's primitive draw, and the draw a
/// prefixed mint is registered as fed by (`issue_bearer_capability_lease`), each turned into a comment, is a violation
/// at its site.
#[test]
fn a_commented_out_draw_fails_the_sweep_at_its_site() {
    let editor = tree_with(EDITOR_HOST, |text| {
        let planted = text.replacen(
            "        rand::rngs::OsRng.fill_bytes(&mut secret);\n",
            "        // rand::rngs::OsRng.fill_bytes(&mut secret);\n",
            1,
        );
        assert_ne!(planted, text, "the planted comment applies");
        planted
    });
    let violations = scan(&editor);
    assert!(
        violations
            .iter()
            .any(|v| v.contains("editor_host.rs") && v.contains("start_oss_runtime")),
        "a commented-out primitive draw is caught at its site: {violations:?}"
    );
    let lease = tree_with(AUTH, |text| {
        let planted = text.replacen(
            "rand::rngs::OsRng.fill_bytes(&mut secret)",
            "// rand::rngs::OsRng.fill_bytes(&mut secret)\n",
            1,
        );
        assert_ne!(planted, text, "the planted comment applies");
        planted
    });
    let violations = scan(&lease);
    assert!(
        violations
            .iter()
            .any(|v| v.contains("issue_bearer_capability_lease") && v.contains("registered draw")),
        "a commented-out registered draw of a prefixed mint is caught at its site: {violations:?}"
    );
}

/// No literal and no raw-identifier decoy can satisfy a registered draw: the editor connection token's draw, and the lease
/// mint's registered draw (`issue_bearer_capability_lease`), each replaced by a copy of its text inside a raw C string
/// (`cr#"…"#`), and the editor draw replaced by a copy inside a C string, a byte string, a raw byte string, a string
/// between a byte char and a char, or by a raw identifier named like the draw (`r#fill_bytes`) that is not called, is a
/// violation at its site.
#[test]
fn a_registered_draw_inside_a_literal_or_a_raw_identifier_decoy_fails_the_sweep() {
    let draw = "        rand::rngs::OsRng.fill_bytes(&mut secret);\n";
    let editor_cases = [
        (
            "a raw C string",
            "        let _ = cr#\"\" rand::rngs::OsRng.fill_bytes(&mut secret); \"\"#;\n",
        ),
        (
            "a C string",
            "        let _ = c\" rand::rngs::OsRng.fill_bytes(&mut secret); \";\n",
        ),
        (
            "a byte string",
            "        let _ = b\" rand::rngs::OsRng.fill_bytes(&mut secret); \";\n",
        ),
        (
            "a raw byte string",
            "        let _ = br#\" rand::rngs::OsRng.fill_bytes(&mut secret); \"#;\n",
        ),
        (
            "a string between a byte char and a char",
            "        let _ = (b'\"', \" rand::rngs::OsRng.fill_bytes(&mut secret); \", '\"');\n",
        ),
        (
            "a raw identifier named like the draw, not called",
            "        let r#fill_bytes = (rand::rngs::OsRng, &mut secret);\n",
        ),
    ];
    let mut accepted = Vec::new();
    for (shape, replacement) in editor_cases {
        let tree = tree_with(EDITOR_HOST, |text| {
            let planted = text.replacen(draw, replacement, 1);
            assert_ne!(planted, text, "the planted {shape} applies");
            planted
        });
        let violations = scan(&tree);
        if !violations
            .iter()
            .any(|v| v.contains("editor_host.rs") && v.contains("start_oss_runtime"))
        {
            accepted.push(format!("editor draw in {shape}"));
        }
    }
    let lease = tree_with(AUTH, |text| {
        let planted = text.replacen(
            "    rand::rngs::OsRng.fill_bytes(&mut secret);\n",
            "    let _ = cr#\"\" rand::rngs::OsRng.fill_bytes(&mut secret) \"\"#;\n",
            1,
        );
        assert_ne!(planted, text, "the planted raw C string applies");
        planted
    });
    let violations = scan(&lease);
    if !violations
        .iter()
        .any(|v| v.contains("issue_bearer_capability_lease") && v.contains("registered draw"))
    {
        accepted.push("lease draw in a raw C string".to_string());
    }
    assert!(
        accepted.is_empty(),
        "each copy of a registered draw that is not the draw is a violation at its site; accepted: {accepted:?}"
    );
}

/// DOCUMENTED LIMITS, pinned so no pass is read as more than an inventory: a registered draw kept in a dead branch, or a
/// decoy copy of it in a closure that never runs, passes this lint. The EXECUTION property is guarded behaviourally:
/// NOW for the editor connection token, by preview_editor_lease_tokens.rs
/// two_editor_runtime_starts_get_different_nonzero_tokens (two starts give two different non-zero tokens); PLANNED
/// (deferred) for every site, by BUILD-DELTA #36d's 256-draw entropy tests (the editor host is #36d-e), and at the type
/// level by BUILD-DELTA #42.
#[test]
fn a_dead_branch_or_decoy_draw_is_a_documented_lint_limit() {
    for (shape, replacement) in [
        (
            "a dead branch",
            "        if false {\n            rand::rngs::OsRng.fill_bytes(&mut secret);\n        }\n",
        ),
        (
            "a decoy closure that never runs",
            "        let _decoy = || rand::rngs::OsRng.fill_bytes(&mut secret);\n",
        ),
    ] {
        let tree = tree_with(EDITOR_HOST, |text| {
            let planted = text.replacen(
                "        rand::rngs::OsRng.fill_bytes(&mut secret);\n",
                replacement,
                1,
            );
            assert_ne!(planted, text, "the planted {shape} applies");
            planted
        });
        let violations = scan(&tree);
        assert!(
            !violations.iter().any(|v| v.contains("editor_host.rs")),
            "{shape} passes the lint by design (a documented limit; the behavioural guards catch it): {violations:?}"
        );
    }
}

/// A reviewed non-mint whose file is missing from the tree is a violation, as a registered mint's missing file is:
/// its exemption never goes stale silently.
#[test]
fn a_reviewed_non_mint_whose_file_is_missing_fails_the_sweep() {
    let tree: Vec<(String, String)> = real_tree()
        .into_iter()
        .filter(|(rel, _)| rel != PROXY)
        .collect();
    let violations = scan(&tree);
    assert!(
        violations
            .iter()
            .any(|v| v.contains("editor_proxy.rs") && v.contains("missing")),
        "a missing reviewed non-mint file is caught: {violations:?}"
    );
}

/// A reviewed non-mint is accepted only where and as it was reviewed: the same `ioi_lease_` cookie-name shape in
/// another function, a second one inside the reviewed function, and an RNG-built `ioi_lease_` value in place of the
/// reviewed statement inside the reviewed function are each still a violation.
#[test]
fn a_reviewed_non_mint_is_accepted_only_on_its_exact_site() {
    let elsewhere = tree_with(PROXY, |text| {
        format!("{text}\npub(crate) fn another_cookie_name(public_port: u16) -> String {{\n    format!(\"ioi_lease_{{public_port}}\")\n}}\n")
    });
    let violations = scan(&elsewhere);
    assert!(
        violations.iter().any(|v| v.contains("another_cookie_name")),
        "the same shape in another function is caught: {violations:?}"
    );
    let twice = tree_with(PROXY, |text| {
        text.replacen(
            "    format!(\"ioi_lease_{public_port}\")\n",
            "    let _again = format!(\"ioi_lease_{public_port}\");\n    format!(\"ioi_lease_{public_port}\")\n",
            1,
        )
    });
    let violations = scan(&twice);
    assert!(
        violations
            .iter()
            .any(|v| v.contains("lease_cookie_name") && v.contains("more than once")),
        "a second occurrence in the reviewed function is caught: {violations:?}"
    );
    let minted_there = tree_with(PROXY, |text| {
        text.replacen(
            "    format!(\"ioi_lease_{public_port}\")\n",
            "    let mut secret = [0u8; 32];\n    rand::rngs::OsRng.fill_bytes(&mut secret);\n    format!(\"ioi_lease_{}\", hex::encode(secret))\n",
            1,
        )
    });
    let violations = scan(&minted_there);
    assert!(
        violations.iter().any(|v| v.contains("lease_cookie_name")
            && v.contains("other than by its reviewed statement")),
        "an RNG-built bearer in place of the reviewed statement is caught: {violations:?}"
    );
}

#[test]
fn the_real_tree_has_no_unregistered_mint_and_every_registered_mint_shows_its_entropy() {
    let violations = scan(&real_tree());
    assert!(
        violations.is_empty(),
        "minting sites outside the registry:\n{}",
        violations.join("\n")
    );
}

#[test]
fn a_second_derived_ioi_mnt_mint_in_the_kernel_file_fails_the_sweep() {
    let tree = tree_with(KERNEL, |text| {
        text.replacen(
            "let minted = format!(\"ioi_mnt_{}\", hex_lower(&secret));",
            "let minted = format!(\"ioi_mnt_{}\", hex_lower(&secret));\n            let second = format!(\"ioi_mnt_{}\", &create_hash[..32]);",
            1,
        )
    });
    let violations = scan(&tree);
    assert!(
        violations.iter().any(|v| v.contains("ioi_mnt_")),
        "the planted second mint is caught: {violations:?}"
    );
}

#[test]
fn a_timestamp_derived_whk_mint_fails_the_sweep() {
    let tree = tree_with(ORCH, |text| {
        let start = text.find("fn new_webhook_token() -> String {").unwrap();
        let end = start + text[start..].find("\n}\n").unwrap() + 3;
        format!(
            "{}fn new_webhook_token() -> String {{\n    format!(\"whk_{{}}\", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis())\n}}\n{}",
            &text[..start],
            &text[end..]
        )
    });
    let violations = scan(&tree);
    assert!(
        violations.iter().any(|v| v.contains("whk_")),
        "the planted timestamp mint is caught: {violations:?}"
    );
}

#[test]
fn a_mint_in_an_unregistered_function_fails_the_sweep() {
    let tree = tree_with(ORCH, |text| {
        format!("{text}\nfn mint_a_capability() -> String {{\n    format!(\"wec_{{}}\", 1)\n}}\n")
    });
    let violations = scan(&tree);
    assert!(
        violations.iter().any(|v| v.contains("mint_a_capability")),
        "{violations:?}"
    );
}

#[test]
fn a_credential_named_function_building_a_new_prefix_fails_the_sweep() {
    let tree = tree_with(AUTH, |text| {
        format!("{text}\nfn fresh_secret_key() -> String {{\n    format!(\"zzk_{{}}\", 7)\n}}\n")
    });
    let violations = scan(&tree);
    assert!(
        violations.iter().any(|v| v.contains("fresh_secret_key")),
        "{violations:?}"
    );
}

#[test]
fn a_registered_minting_function_that_disappears_fails_the_sweep() {
    let tree = tree_with(ORCH, |text| {
        text.replacen("fn new_webhook_token()", "fn renamed_webhook_token()", 1)
    });
    let violations = scan(&tree);
    assert!(
        violations.iter().any(|v| v.contains("new_webhook_token")),
        "{violations:?}"
    );
}

#[test]
fn a_mint_inside_a_test_module_is_not_a_production_mint() {
    let tree = tree_with(AUTH, |text| {
        format!("{text}\n#[cfg(test)]\nmod planted {{\n    fn bearer() -> String {{\n        format!(\"ioi_pat_{{}}\", 1)\n    }}\n}}\n")
    });
    assert!(scan(&tree).is_empty());
}

// ---- plants for the shapes the scan was extended to cover (each must fail the scan) ---------------------------

const GOOGLE: &str = "services/src/agentic/runtime/connectors/google_auth.rs";
const LIFECYCLE: &str = "node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs";

#[test]
fn a_prefix_joined_by_to_owned_and_plus_fails_the_sweep() {
    let tree = tree_with(AUTH, |text| {
        format!("{text}\nfn make_value(tail: &str) -> String {{\n    \"ioi_pat_\".to_owned() + tail\n}}\n")
    });
    let violations = scan(&tree);
    assert!(
        violations.iter().any(|v| v.contains("make_value")),
        "{violations:?}"
    );
}

#[test]
fn a_prefix_built_with_push_str_fails_the_sweep() {
    let tree = tree_with(AUTH, |text| {
        format!("{text}\nfn make_value(tail: &str) -> String {{\n    let mut out = String::new();\n    out.push_str(\"whk_\");\n    out.push_str(tail);\n    out\n}}\n")
    });
    let violations = scan(&tree);
    assert!(
        violations.iter().any(|v| v.contains("make_value")),
        "{violations:?}"
    );
}

#[test]
fn a_prefix_held_in_a_const_and_used_in_format_fails_the_sweep() {
    let tree = tree_with(AUTH, |text| {
        format!("{text}\nconst MINT_PREFIX: &str = \"wec_\";\nfn make_value(n: u64) -> String {{\n    format!(\"{{MINT_PREFIX}}{{n}}\")\n}}\n")
    });
    let violations = scan(&tree);
    assert!(
        violations.iter().any(|v| v.contains("wec_")),
        "{violations:?}"
    );
}

#[test]
fn a_registered_mint_fed_by_something_other_than_the_registered_source_fails_the_sweep() {
    // the function still holds the registered OsRng draw elsewhere, but the formatted value no longer comes from it
    let tree = tree_with(KERNEL, |text| {
        text.replacen(
            "let minted = format!(\"ioi_mnt_{}\", hex_lower(&secret));",
            "let minted = format!(\"ioi_mnt_{}\", hex_lower(&id_material));",
            1,
        )
    });
    let violations = scan(&tree);
    assert!(
        violations.iter().any(|v| v.contains("ioi_mnt_")),
        "{violations:?}"
    );
}

#[test]
fn a_nested_block_comment_cannot_hide_a_following_credential_function() {
    let tree = tree_with(AUTH, |text| {
        format!("{text}\n/* outer /* inner */ \" still a comment */\nfn leak_secret_token() -> String {{\n    format!(\"zzk_{{}}\", 1)\n}}\n")
    });
    let violations = scan(&tree);
    assert!(
        violations.iter().any(|v| v.contains("leak_secret_token")),
        "{violations:?}"
    );
}

#[test]
fn a_raw_byte_string_cannot_hide_a_following_credential_function() {
    let tree = tree_with(AUTH, |text| {
        format!("{text}\nconst RAW: &[u8] = br#\"}} \" fn \"#;\nfn leak_secret_token() -> String {{\n    format!(\"zzk_{{}}\", 2)\n}}\n")
    });
    let violations = scan(&tree);
    assert!(
        violations.iter().any(|v| v.contains("leak_secret_token")),
        "{violations:?}"
    );
}

#[test]
fn a_quote_character_literal_cannot_hide_a_following_credential_function() {
    let tree = tree_with(AUTH, |text| {
        format!("{text}\nfn quote() -> char {{\n    '\"'\n}}\nfn leak_secret_token() -> String {{\n    format!(\"zzk_{{}}\", 3)\n}}\n")
    });
    let violations = scan(&tree);
    assert!(
        violations.iter().any(|v| v.contains("leak_secret_token")),
        "{violations:?}"
    );
}

#[test]
fn a_registered_file_that_is_missing_fails_the_sweep() {
    let mut tree = real_tree();
    tree.retain(|(rel, _)| rel != ORCH);
    let violations = scan(&tree);
    assert!(
        violations
            .iter()
            .any(|v| v.contains("orchestration_routes.rs") && v.contains("missing")),
        "{violations:?}"
    );
}

#[test]
fn a_google_state_that_is_no_longer_drawn_at_random_fails_the_sweep() {
    let tree = tree_with(GOOGLE, |text| {
        text.replacen(
            "let state = random_url_safe_token(24);",
            "let state = String::from(\"fixed-state\");",
            1,
        )
    });
    let violations = scan(&tree);
    assert!(
        violations
            .iter()
            .any(|v| v.contains("random_url_safe_token(24)")),
        "{violations:?}"
    );
}

#[test]
fn a_prefix_assembled_from_pieces_is_a_named_out_of_scope_shape_not_a_pass() {
    // A prefix split across macro pieces is OUTSIDE this lint's scope (the header names it; review and BUILD-DELTA #42
    // cover it). This test pins that the lint does not claim to catch it, so nobody reads a pass as more than it is.
    let tree = tree_with(LIFECYCLE, |text| {
        format!("{text}\nfn make_value() -> String {{\n    concat!(\"ioi_p\", \"at_\", \"x\").to_string()\n}}\n")
    });
    assert!(scan(&tree).is_empty());
}

// ---- the function-discovery counterexamples (Codex batch-3 r4) and the include!/#[path] controls --------------

/// A registered site is the function at its MODULE PATH (its file, the inline modules and impl self type inside it,
/// then its name), never a same-named function elsewhere. With the editor connection token's production draw replaced
/// by a constant, a same-named function holding the draw in a `#[cfg(test)]` module, a same-named method of another
/// type, or a same-named function in another inline module, each placed before the registered function, does not stand
/// in for it: the removed draw is still a violation at the site. Control: each shadow beside the intact draw is no
/// violation there.
#[test]
fn a_same_named_shadow_never_stands_in_for_a_registered_site() {
    let body = "        use rand::RngCore;\n        let mut secret = [0u8; 32];\n        let nonce = [0u8; 8];\n        rand::rngs::OsRng.fill_bytes(&mut secret);\n        let _ = (hex::encode(secret), hex::encode(nonce));\n";
    let shadows = [
        (
            "a same-named #[cfg(test)] function in a test module",
            format!("#[cfg(test)]\nmod inventory_shadow {{\n    fn start_oss_runtime() {{\n{body}    }}\n}}\n\n"),
        ),
        (
            "a same-named method of another type",
            format!("pub(crate) struct InventoryShadow;\n\nimpl InventoryShadow {{\n    fn start_oss_runtime(&self) {{\n{body}    }}\n}}\n\n"),
        ),
        (
            "a same-named function in another inline module",
            format!("mod inventory_shadow {{\n    fn start_oss_runtime() {{\n{body}    }}\n}}\n\n"),
        ),
    ];
    let site = "pub(crate) async fn start_oss_runtime(";
    let draw = "        rand::rngs::OsRng.fill_bytes(&mut secret);\n";
    let at_site = |v: &String| v.contains("editor_host.rs") && v.contains("start_oss_runtime");
    let mut accepted = Vec::new();
    for (shape, shadow) in &shadows {
        let control = tree_with(EDITOR_HOST, |text| {
            let planted = text.replacen(site, &format!("{shadow}{site}"), 1);
            assert_ne!(planted, text, "the planted {shape} applies");
            planted
        });
        let violations = scan(&control);
        assert!(
            !violations.iter().any(at_site),
            "{shape} beside the intact draw is no violation at the site: {violations:?}"
        );
        let tree = tree_with(EDITOR_HOST, |text| {
            let without = text.replacen(draw, "        secret = [0u8; 32];\n", 1);
            assert_ne!(without, text, "the production draw edit applies");
            let planted = without.replacen(site, &format!("{shadow}{site}"), 1);
            assert_ne!(planted, without, "the planted {shape} applies");
            planted
        });
        if !scan(&tree).iter().any(at_site) {
            accepted.push(*shape);
        }
    }
    assert!(
        accepted.is_empty(),
        "a shadow stood in for the registered site whose draw was removed: {accepted:?}"
    );
}

/// A function's body is the block the parser says it is: a const-generic argument's brace group in a `where` bound or
/// in the return type is not the body, so a credential-named function building a new prefix after such a signature is
/// still found.
#[test]
fn a_const_generic_brace_group_in_a_signature_is_not_the_function_body() {
    let shapes = [
        (
            "a `where` bound",
            "fresh_secret_key",
            "trait Tag<const N: usize> {}\nimpl Tag<1> for () {}\n\nfn fresh_secret_key() -> String\nwhere\n    (): Tag<{ 1 }>,\n{\n    format!(\"zzk_{}\", 7)\n}\n",
        ),
        (
            "the return type",
            "fresh_secret_token",
            "pub struct Tagged<const N: usize>(String);\n\nfn fresh_secret_token() -> Tagged<{ 2 }> {\n    Tagged(format!(\"zzk_{}\", 8))\n}\n",
        ),
    ];
    let mut accepted = Vec::new();
    for (shape, function, planted) in shapes {
        let tree = tree_with(AUTH, |text| format!("{text}\n{planted}"));
        if !scan(&tree).iter().any(|v| v.contains(function)) {
            accepted.push(shape);
        }
    }
    assert!(
        accepted.is_empty(),
        "a const-generic brace group hid the body of: {accepted:?}"
    );
}

/// Documentation is not code: a doc comment or a `#[doc]` attribute holding a registered prefix, on an item or on a
/// statement inside a function, is never a mint candidate (its text never becomes a value).
#[test]
fn a_doc_comment_is_never_a_mint_candidate() {
    for (shape, planted) in [
        ("a doc comment on an item", "///ioi_pat_example\nfn harmless() {}\n"),
        ("a #[doc] attribute on an item", "#[doc = \"ioi_pat_example\"]\nfn harmless() {}\n"),
        (
            "a doc comment on a statement",
            "fn harmless() -> String {\n    ///ioi_pat_example\n    let plain = String::from(\"plain\");\n    plain\n}\n",
        ),
    ] {
        let tree = tree_with(AUTH, |text| format!("{text}\n{planted}"));
        let violations = scan(&tree);
        assert!(
            violations.is_empty(),
            "{shape} is not a mint candidate: {violations:?}"
        );
    }
}

const DRAW_FRAGMENT: &str = "node/src/bin/hypervisor_daemon_routes/editor_host_draw.rs";

/// `include!` is read the way the compiler reads it: a fragment's code is part of the function at its include site.
/// The editor connection token's draw moved into a fragment included in its place is still the registered draw at
/// that site; a constant included there instead is a violation at the site.
#[test]
fn a_registered_draw_in_an_include_fragment_is_read_at_its_include_site() {
    let draw = "        rand::rngs::OsRng.fill_bytes(&mut secret);\n";
    let at_site = |v: &String| v.contains("editor_host.rs") && v.contains("start_oss_runtime");
    let moved = |fragment: &str| {
        tree_adding(
            EDITOR_HOST,
            |text| {
                let planted =
                    text.replacen(draw, "        include!(\"editor_host_draw.rs\");\n", 1);
                assert_ne!(planted, text, "the planted include! applies");
                planted
            },
            &[(DRAW_FRAGMENT, fragment)],
        )
    };
    let violations = scan(&moved("rand::rngs::OsRng.fill_bytes(&mut secret)\n"));
    assert!(
        !violations.iter().any(at_site),
        "the draw included at its site is the registered draw: {violations:?}"
    );
    let violations = scan(&moved("secret = [0u8; 32]\n"));
    assert!(
        violations.iter().any(at_site),
        "a constant included at the site is caught there: {violations:?}"
    );
}

/// A mint in an `include!` fragment is a mint in the function that includes it: an unregistered prefixed mint moved
/// into a fragment fails the sweep naming the including function.
#[test]
fn an_unregistered_mint_in_an_include_fragment_fails_at_its_including_function() {
    let tree = tree_adding(
        AUTH,
        |text| {
            format!(
                "{text}\nfn make_value() -> String {{\n    include!(\"authority_value.rs\")\n}}\n"
            )
        },
        &[(
            "node/src/bin/hypervisor_daemon_routes/authority_value.rs",
            "format!(\"ioi_pat_{}\", 1)\n",
        )],
    );
    let violations = scan(&tree);
    assert!(
        violations
            .iter()
            .any(|v| v.contains("make_value") && v.contains("ioi_pat_")),
        "{violations:?}"
    );
}

/// Every file is read: a file that parses neither as a module nor at a found `include!` site fails the sweep (its code
/// cannot be seen), and so does an `include!` of a file that is not in the tree. Control: the same fragment included by
/// a production function is read there and is no violation.
#[test]
fn a_file_read_neither_as_a_module_nor_at_an_include_site_fails_the_sweep() {
    let fragment = (
        "node/src/bin/hypervisor_daemon_routes/authority_fragment.rs",
        "{\n    let _unit = ();\n}\n",
    );
    let orphan = tree_adding(AUTH, |text| text.to_string(), &[fragment]);
    let violations = scan(&orphan);
    assert!(
        violations
            .iter()
            .any(|v| v.contains("authority_fragment.rs")),
        "a fragment no file includes is caught: {violations:?}"
    );
    let included = tree_adding(
        AUTH,
        |text| {
            format!(
                "{text}\nfn uses_the_fragment() {{\n    include!(\"authority_fragment.rs\");\n}}\n"
            )
        },
        &[fragment],
    );
    let violations = scan(&included);
    assert!(
        violations.is_empty(),
        "the same fragment read at its include site is no violation: {violations:?}"
    );
    let missing = tree_with(AUTH, |text| {
        format!("{text}\nfn uses_a_missing_fragment() {{\n    include!(\"authority_missing.rs\");\n}}\n")
    });
    let violations = scan(&missing);
    assert!(
        violations
            .iter()
            .any(|v| v.contains("authority_missing.rs")),
        "an include! of a file not in the tree is caught: {violations:?}"
    );
}

/// `mod` declarations are followed the way the compiler follows them, `#[path]` included: a module file reached only
/// through a `#[cfg(test)]` declaration is test code, so a mint in it is not a production mint. Control: the same file
/// declared without the `cfg(test)` is production code, and its mint fails the sweep.
#[test]
fn a_module_file_reached_only_through_cfg_test_is_not_production_code() {
    let module = (
        "node/src/bin/hypervisor_daemon_routes/authority_planted.rs",
        "pub(crate) fn bearer() -> String {\n    format!(\"ioi_pat_{}\", 1)\n}\n",
    );
    let test_only = tree_adding(
        AUTH,
        |text| format!("{text}\n#[cfg(test)]\n#[path = \"authority_planted.rs\"]\nmod planted;\n"),
        &[module],
    );
    let violations = scan(&test_only);
    assert!(
        violations.is_empty(),
        "a module reached only through cfg(test) is test code: {violations:?}"
    );
    let production = tree_adding(
        AUTH,
        |text| format!("{text}\n#[path = \"authority_planted.rs\"]\nmod planted;\n"),
        &[module],
    );
    let violations = scan(&production);
    assert!(
        violations
            .iter()
            .any(|v| v.contains("authority_planted.rs") && v.contains("bearer")),
        "the same module declared for production is read: {violations:?}"
    );
}

// ---- Codex batch-3 r5's four counterexamples (named REDs; each must be caught) ----------------------------------

const SERVICES_ROOT: &str = "services/src/lib.rs";

/// r5 MAJOR 1: a `#[cfg(test)]` ARRAY ELEMENT is compiled out of a non-test build, so a draw kept only there is a
/// removed draw: the editor connection token's production draw replaced by Codex's array, whose only draw is in a
/// cfg(test) element (the non-test build leaves `secret` zeroed), is a violation at the registered site.
#[test]
fn r5_major_1_a_cfg_test_array_element_never_stands_in_for_a_registered_draw() {
    let tree = tree_with(EDITOR_HOST, |text| {
        let planted = text.replacen(
            "        rand::rngs::OsRng.fill_bytes(&mut secret);\n",
            "        let _ = [\n            #[cfg(test)]\n            {\n                rand::rngs::OsRng.fill_bytes(&mut secret);\n                0u8\n            },\n            0u8,\n        ];\n",
            1,
        );
        assert_ne!(planted, text, "the planted array applies");
        planted
    });
    let violations = scan(&tree);
    assert!(
        violations
            .iter()
            .any(|v| v.contains("editor_host.rs") && v.contains("start_oss_runtime")),
        "a draw kept only in a cfg(test) array element is a removed draw at its site: {violations:?}"
    );
}

/// r5 MAJOR 2: the compiler resolves a module's children by HOW the file was loaded: `r5_shared.rs` loaded through
/// `#[path]` has its children beside it (`r5_leaf.rs`, harmless), loaded through `mod r5_shared;` it has them in
/// `r5_shared/` (`r5_shared/r5_leaf.rs`, a production `ioi_pat_` mint). That mint reached only that way (and through a
/// `#[cfg(test)]` path) is production code and fails the sweep.
#[test]
fn r5_major_2_a_file_loaded_through_path_and_through_mod_keeps_both_subtrees() {
    let tree = tree_adding(
        SERVICES_ROOT,
        |text| {
            format!(
                "{text}\n#[path = \"r5_shared.rs\"]\nmod r5_first;\n\nmod r5_shared;\n\n#[cfg(test)]\n#[path = \"r5_shared/r5_leaf.rs\"]\nmod r5_fixture;\n"
            )
        },
        &[
            ("services/src/r5_shared.rs", "pub mod r5_leaf;\n"),
            ("services/src/r5_leaf.rs", "pub fn harmless() {}\n"),
            (
                "services/src/r5_shared/r5_leaf.rs",
                "pub fn bearer() -> String {\n    format!(\"ioi_pat_{}\", 7)\n}\n",
            ),
        ],
    );
    let violations = scan(&tree);
    assert!(
        violations
            .iter()
            .any(|v| v.contains("r5_shared/r5_leaf.rs") && v.contains("ioi_pat_")),
        "the production mint in the subtree only `mod r5_shared;` reaches fails the sweep: {violations:?}"
    );
}

/// r5 MAJOR 3: `cfg_attr(not(test), path = ...)` selects the file a non-test build compiles, so `r5_hidden.rs` (an
/// `ioi_pat_` mint) IS module `r5_selected` in production; that it is also reached through a `#[cfg(test)]` path does
/// not make it test code, and the mint fails the sweep.
#[test]
fn r5_major_3_a_cfg_attr_path_selects_the_production_file() {
    let tree = tree_adding(
        SERVICES_ROOT,
        |text| {
            format!(
                "{text}\n#[cfg_attr(not(test), path = \"r5_hidden.rs\")]\nmod r5_selected;\n\n#[cfg(test)]\n#[path = \"r5_hidden.rs\"]\nmod r5_fixture;\n"
            )
        },
        &[
            ("services/src/r5_selected.rs", "pub fn harmless() {}\n"),
            (
                "services/src/r5_hidden.rs",
                "pub fn bearer() -> String {\n    format!(\"ioi_pat_{}\", 7)\n}\n",
            ),
        ],
    );
    let violations = scan(&tree);
    assert!(
        violations
            .iter()
            .any(|v| v.contains("r5_hidden.rs") && v.contains("ioi_pat_")),
        "the file a cfg_attr path selects for production is read as production: {violations:?}"
    );
}

/// r5 MINOR: `include ! ("r5_a.rs")` (the whitespace spelling) is an include site: two otherwise unreferenced files,
/// `r5_a.rs` (an expression) and `r5_z.rs` (a function including it), are a valid tree and no violation, whatever the
/// order in which they are read.
#[test]
fn r5_minor_an_include_site_is_found_whatever_its_spelling_and_order() {
    let tree = tree_adding(
        SERVICES_ROOT,
        |text| text.to_string(),
        &[
            ("services/src/r5_a.rs", "42u8\n"),
            (
                "services/src/r5_z.rs",
                "fn harmless() {\n    let _ = include ! (\"r5_a.rs\");\n}\n",
            ),
        ],
    );
    let violations = scan(&tree);
    assert!(
        violations.is_empty(),
        "an expression fragment included with the spelling `include !` is read at its include site: {violations:?}"
    );
}
