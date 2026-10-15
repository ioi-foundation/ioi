//! T-API (DESIGN v2 (4)): the REVIEWED INTERFACES of the trusted crates, pinned. Any new public
//! item, impl, derive, cfg, macro, feature or dependency in `ioi-proxy-digest` or
//! `ioi-editor-proxy-ipc` changes a pin here and so needs review. This is an interface review
//! obligation, not a source census claiming exhaustive prevention of future Rust changes.
//!
//! The interface listing (api/<crate>.api) holds COMPLETE declarations, one per line, with
//! comments removed and whitespace normalized: every public item with its attributes (a struct,
//! enum or union with its whole body, so every field and variant; a function's whole signature,
//! however many lines; a public trait's header and every member signature; a `pub use` with its
//! whole list; a public const/static/type with its type and value), every impl block's header with
//! its public members (all members for a trait impl), and every module declaration, extern crate,
//! macro_rules! body and crate attribute. Bodies of functions are not interface. The manifest
//! listing (api/<crate>.manifest) holds every dependency's NORMALIZED specification (version,
//! path, features, default-features, optional, package, workspace), whether it is written inline
//! or as a [dependencies.<name>] table, plus [features] and [lib].
//!
//! `CF_API_OUT=<dir>` writes the current listings to <dir> instead of comparing (how the pins in
//! `api/` were produced).

use std::fs;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the workspace root")
}

/// Every top-level src/*.rs of the crate (sorted by name; src/tests/ is the cfg(test) module), as
/// (file name, text).
fn crate_files(crate_dir: &str) -> Vec<(String, String)> {
    let src = root().join(crate_dir).join("src");
    let mut files: Vec<PathBuf> = fs::read_dir(&src)
        .expect("src")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().map(|x| x == "rs").unwrap_or(false))
        .collect();
    files.sort();
    files
        .into_iter()
        .map(|file| {
            (
                file.file_name().unwrap().to_string_lossy().into_owned(),
                fs::read_to_string(&file).expect("source"),
            )
        })
        .collect()
}

/// The crate's interface listing.
fn interface(crate_dir: &str) -> String {
    interface_of(&crate_files(crate_dir))
}

/// The source with every comment (line, block, doc) removed and every whitespace run collapsed to
/// one space; string, byte-string, raw-string and char literals are kept verbatim.
fn strip(src: &str) -> String {
    let c: Vec<char> = src.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    let mut space = false;
    let push = |out: &mut String, space: &mut bool, ch: char| {
        if *space && !out.is_empty() {
            out.push(' ');
        }
        *space = false;
        out.push(ch);
    };
    while i < c.len() {
        let ch = c[i];
        if ch == '/' && c.get(i + 1) == Some(&'/') {
            while i < c.len() && c[i] != '\n' {
                i += 1;
            }
            space = true;
            continue;
        }
        if ch == '/' && c.get(i + 1) == Some(&'*') {
            let mut depth = 0;
            while i < c.len() {
                if c[i] == '/' && c.get(i + 1) == Some(&'*') {
                    depth += 1;
                    i += 2;
                } else if c[i] == '*' && c.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    i += 1;
                }
            }
            space = true;
            continue;
        }
        if ch.is_whitespace() {
            space = true;
            i += 1;
            continue;
        }
        // A raw string r"..." / r#"..."# (optionally b-prefixed).
        let raw_at = if ch == 'r' {
            Some(i + 1)
        } else if ch == 'b' && c.get(i + 1) == Some(&'r') {
            Some(i + 2)
        } else {
            None
        };
        if let Some(mut j) = raw_at {
            let ident_before = i > 0 && (c[i - 1].is_alphanumeric() || c[i - 1] == '_');
            let mut hashes = 0;
            while c.get(j) == Some(&'#') {
                hashes += 1;
                j += 1;
            }
            if !ident_before && c.get(j) == Some(&'"') {
                let close: String = std::iter::once('"')
                    .chain(std::iter::repeat('#').take(hashes))
                    .collect();
                let rest: String = c[j + 1..].iter().collect();
                let end = rest
                    .find(&close)
                    .map(|k| j + 1 + k + close.len())
                    .unwrap_or(c.len());
                for &raw in &c[i..end] {
                    push(&mut out, &mut space, raw);
                }
                i = end;
                continue;
            }
        }
        if ch == '"' {
            push(&mut out, &mut space, ch);
            i += 1;
            while i < c.len() {
                out.push(c[i]);
                if c[i] == '\\' && i + 1 < c.len() {
                    out.push(c[i + 1]);
                    i += 2;
                    continue;
                }
                i += 1;
                if c[i - 1] == '"' {
                    break;
                }
            }
            continue;
        }
        if ch == '\'' {
            // A char literal ('x', '\n', '\'') or a lifetime ('a, 'static).
            let len = if c.get(i + 1) == Some(&'\\') {
                let mut k = i + 3;
                while k < c.len() && c[k] != '\'' {
                    k += 1;
                }
                k + 1 - i
            } else if c.get(i + 2) == Some(&'\'') {
                3
            } else {
                1
            };
            for &lit in &c[i..(i + len).min(c.len())] {
                push(&mut out, &mut space, lit);
            }
            i += len;
            continue;
        }
        push(&mut out, &mut space, ch);
        i += 1;
    }
    out
}

/// Normalizes the spacing that rustfmt's line breaks leave inside a collapsed declaration.
fn tidy(text: &str) -> String {
    let mut s = text.trim().to_string();
    for (from, to) in [
        ("  ", " "),
        ("{ ", "{"),
        (" }", "}"),
        ("( ", "("),
        (" )", ")"),
        ("[ ", "["),
        (" ]", "]"),
        (" ,", ","),
        (",)", ")"),
        (",]", "]"),
        (",}", "}"),
    ] {
        while s.contains(from) {
            s = s.replace(from, to);
        }
    }
    s
}

/// The index just past the bracket that closes the one opening at `open` (string- and
/// char-literal aware; `s` is stripped text).
fn close_of(s: &[char], open: usize) -> usize {
    let mut depth = 0i32;
    let mut i = open;
    while i < s.len() {
        match s[i] {
            '"' => {
                i += 1;
                while i < s.len() && s[i] != '"' {
                    if s[i] == '\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            '\'' if s.get(i + 1) == Some(&'\\') => {
                i += 3;
                while i < s.len() && s[i] != '\'' {
                    i += 1;
                }
            }
            '\'' if s.get(i + 2) == Some(&'\'') => i += 2,
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    s.len()
}

/// One statement of a module or block body: its attributes, its text up to its body (or its
/// terminating `;`), and its brace body's inner text if it has one.
struct Stmt {
    attrs: Vec<String>,
    head: String,
    body: Option<String>,
}

/// Splits a module or block body (stripped text) into statements.
fn statements(text: &str) -> Vec<Stmt> {
    let s: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    let mut attrs = Vec::new();
    while i < s.len() {
        if s[i] == ' ' || s[i] == ';' {
            i += 1;
            continue;
        }
        if s[i] == '#' && (s.get(i + 1) == Some(&'[') || s.get(i + 1) == Some(&'!')) {
            let open = if s[i + 1] == '[' { i + 1 } else { i + 2 };
            let end = close_of(&s, open);
            let attr: String = s[i..end].iter().collect();
            if s[i + 1] == '!' {
                out.push(Stmt {
                    attrs: Vec::new(),
                    head: tidy(&attr),
                    body: None,
                });
            } else {
                attrs.push(tidy(&attr));
            }
            i = end;
            continue;
        }
        let start = i;
        let head_text: String = s[start..s.len().min(start + 80)].iter().collect();
        let value_like = matches!(keyword(&head_text), "use" | "const" | "static" | "type");
        let mut j = i;
        let mut body = None;
        let mut end = s.len();
        while j < s.len() {
            match s[j] {
                ';' => {
                    end = j;
                    j += 1;
                    break;
                }
                '(' | '[' => j = close_of(&s, j),
                '{' if value_like => j = close_of(&s, j),
                '{' => {
                    let close = close_of(&s, j);
                    end = j;
                    body = Some(s[j + 1..close - 1].iter().collect::<String>());
                    j = close;
                    break;
                }
                '"' => {
                    j += 1;
                    while j < s.len() && s[j] != '"' {
                        if s[j] == '\\' {
                            j += 1;
                        }
                        j += 1;
                    }
                    j += 1;
                }
                '\'' if s.get(j + 1) == Some(&'\\') => {
                    j += 3;
                    while j < s.len() && s[j] != '\'' {
                        j += 1;
                    }
                    j += 1;
                }
                '\'' if s.get(j + 2) == Some(&'\'') => j += 3,
                _ => j += 1,
            }
        }
        let head: String = s[start..end].iter().collect();
        out.push(Stmt {
            attrs: std::mem::take(&mut attrs),
            head: tidy(&head),
            body,
        });
        i = j;
    }
    out
}

/// The statement's text with its attributes (and, for a type with a body, the whole body).
fn decl(st: &Stmt, with_body: bool) -> String {
    let mut parts = st.attrs.clone();
    match (&st.body, with_body) {
        (Some(body), true) => parts.push(tidy(&format!("{} {{ {} }}", st.head, body))),
        (Some(_), false) => parts.push(format!("{} {{ .. }}", st.head)),
        (None, _) => parts.push(format!("{};", st.head)),
    }
    parts.join(" ")
}

/// True for a public (not restricted) visibility.
fn is_pub(head: &str) -> bool {
    head.starts_with("pub ") && !head.starts_with("pub(")
}

/// The keyword after the visibility and the fn/impl/trait qualifiers ("const fn" is "fn"; a
/// "const NAME" item is "const").
fn keyword(head: &str) -> &str {
    let mut rest = head;
    if let Some(r) = rest.strip_prefix("pub ") {
        rest = r;
    } else if rest.starts_with("pub(") {
        if let Some(k) = rest.find(") ") {
            rest = &rest[k + 2..];
        }
    }
    let qualifiers = ["unsafe ", "const ", "async ", "default ", "extern \"C\" "];
    let items = [
        "fn ",
        "impl",
        "trait ",
        "unsafe ",
        "async ",
        "extern \"C\" ",
    ];
    loop {
        let next = qualifiers.iter().find_map(|q| {
            rest.strip_prefix(q)
                .filter(|after| items.iter().any(|i| after.starts_with(i)))
        });
        match next {
            Some(after) => rest = after,
            None => break,
        }
    }
    rest.split([' ', '<', '!', '(', '{', ';'])
        .next()
        .unwrap_or("")
}

/// The interface listing of a crate's files (see the module doc).
fn interface_of(files: &[(String, String)]) -> String {
    let mut out = String::new();
    for (name, text) in files {
        for st in statements(&strip(text)) {
            let kw = keyword(&st.head);
            let public = is_pub(&st.head);
            let line = match kw {
                _ if st.head.starts_with("#!") => Some(st.head.clone()),
                "mod" | "extern" => Some(decl(&st, false)),
                "macro_rules" => Some(decl(&st, true)),
                "struct" | "enum" | "union" | "use" | "const" | "static" | "type" if public => {
                    Some(decl(&st, true))
                }
                "fn" if public => Some(decl(&st, false).replace(" { .. }", "")),
                "trait" if public => {
                    out.push_str(&format!("{}: {}\n", name, decl(&st, false)));
                    let owner = decl(&st, false).replace(" { .. }", "");
                    for member in statements(st.body.as_deref().unwrap_or("")) {
                        out.push_str(&format!(
                            "{}: {} => {}\n",
                            name,
                            owner,
                            decl(&member, false).replace(" { .. }", "")
                        ));
                    }
                    None
                }
                "impl" => {
                    out.push_str(&format!("{}: {}\n", name, decl(&st, false)));
                    let owner = decl(&st, false).replace(" { .. }", "");
                    let trait_impl = st.head.contains(" for ");
                    for member in statements(st.body.as_deref().unwrap_or("")) {
                        if trait_impl || is_pub(&member.head) {
                            out.push_str(&format!(
                                "{}: {} => {}\n",
                                name,
                                owner,
                                decl(&member, !matches!(keyword(&member.head), "fn"))
                                    .replace(" { .. }", "")
                            ));
                        }
                    }
                    None
                }
                _ => None,
            };
            if let Some(line) = line {
                out.push_str(&format!("{}: {}\n", name, line));
            }
        }
    }
    out
}

fn check_pin(crate_dir: &str, pin: &str) {
    let current = interface(crate_dir);
    if let Ok(dir) = std::env::var("CF_API_OUT") {
        fs::create_dir_all(&dir).expect("api out");
        fs::write(Path::new(&dir).join(pin), &current).expect("api write");
        return;
    }
    let pinned = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("api").join(pin))
        .unwrap_or_default();
    if current != pinned {
        let missing: Vec<&str> = pinned
            .lines()
            .filter(|l| !current.lines().any(|c| c == *l))
            .collect();
        let added: Vec<&str> = current
            .lines()
            .filter(|l| !pinned.lines().any(|p| p == *l))
            .collect();
        panic!(
            "T-API: the reviewed interface of {} changed (re-pin api/{} with CF_API_OUT after review)\n+ {}\n- {}",
            crate_dir,
            pin,
            added.join("\n+ "),
            missing.join("\n- ")
        );
    }
}

#[test]
fn t_api_the_outbound_digest_interface_is_pinned() {
    check_pin("crates/editor-proxy-digest", "ioi-proxy-digest.api");
}

#[test]
fn t_api_the_codec_interface_is_pinned() {
    check_pin("crates/editor-proxy-codec", "ioi-editor-proxy-ipc.api");
}

/// The crate's manifest text.
fn manifest_text(crate_dir: &str) -> String {
    fs::read_to_string(root().join(crate_dir).join("Cargo.toml")).expect("manifest")
}

/// The manifest's normalized listing and whether a [features] table exists.
fn manifest(crate_dir: &str) -> (Vec<String>, bool) {
    manifest_of(&manifest_text(crate_dir))
}

/// A TOML value, normalized: quotes removed, an array's items sorted and joined by ",", an inline
/// table's keys sorted as "k=v" joined by "; ".
fn norm_value(v: &str) -> String {
    let v = v.trim();
    if let Some(inner) = v.strip_prefix('[').and_then(|x| x.strip_suffix(']')) {
        let mut items: Vec<String> = split_top(inner)
            .iter()
            .map(|x| norm_value(x))
            .filter(|x| !x.is_empty())
            .collect();
        items.sort();
        return format!("[{}]", items.join(","));
    }
    if let Some(inner) = v.strip_prefix('{').and_then(|x| x.strip_suffix('}')) {
        let mut fields = std::collections::BTreeMap::new();
        for pair in split_top(inner) {
            if let Some((k, val)) = pair.split_once('=') {
                fields.insert(norm_key(k), norm_value(val));
            }
        }
        return fields
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("; ");
    }
    v.trim_matches('"').trim_matches('\'').to_string()
}

fn norm_key(k: &str) -> String {
    k.trim().trim_matches('"').trim_matches('\'').to_string()
}

/// Splits on commas outside brackets, braces and quotes.
fn split_top(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0;
    let mut quoted = false;
    let mut cur = String::new();
    for ch in s.chars() {
        match ch {
            '"' => quoted = !quoted,
            '[' | '{' if !quoted => depth += 1,
            ']' | '}' if !quoted => depth -= 1,
            ',' if !quoted && depth == 0 => {
                out.push(std::mem::take(&mut cur));
                continue;
            }
            _ => {}
        }
        cur.push(ch);
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

/// A line without its `#` comment (outside quotes).
fn uncomment(line: &str) -> &str {
    let mut quoted = false;
    for (i, ch) in line.char_indices() {
        match ch {
            '"' => quoted = !quoted,
            '#' if !quoted => return &line[..i],
            _ => {}
        }
    }
    line
}

/// The NORMALIZED dependency, [features] and [lib] listing of a manifest text (inline and
/// [dependencies.<name>] table forms give the same lines), and whether a [features] table exists.
fn manifest_of(text: &str) -> (Vec<String>, bool) {
    use std::collections::BTreeMap;
    let mut deps: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    let mut other: Vec<String> = Vec::new();
    let mut features = false;
    let mut section = String::new();
    let mut table_dep: Option<String> = None;
    let mut pending = String::new();
    let dep_kind = |sec: &str| -> Option<String> {
        for kind in ["dependencies", "build-dependencies", "dev-dependencies"] {
            if sec == kind {
                return Some(kind.to_string());
            }
            if sec.starts_with("target.") && sec.ends_with(&format!(".{}", kind)) {
                return Some(sec.to_string());
            }
        }
        None
    };
    for raw in text.lines() {
        let line = uncomment(raw).trim();
        if line.is_empty() {
            continue;
        }
        if pending.is_empty() && line.starts_with('[') && !line.contains('=') {
            section = line
                .trim_start_matches('[')
                .trim_end_matches(']')
                .trim()
                .to_string();
            table_dep = None;
            if section == "features" {
                features = true;
            }
            for kind in ["dependencies.", "build-dependencies.", "dev-dependencies."] {
                if let Some(k) = section.rfind(kind) {
                    let (base, name) = (&section[..k + kind.len() - 1], &section[k + kind.len()..]);
                    if dep_kind(base).is_some() {
                        let key = format!("{} {}", dep_kind(base).unwrap(), norm_key(name));
                        deps.entry(key.clone()).or_default();
                        table_dep = Some(key);
                    }
                }
            }
            continue;
        }
        pending.push_str(line);
        pending.push(' ');
        let opens = pending.matches(['[', '{']).count();
        let closes = pending.matches([']', '}']).count();
        if opens > closes {
            continue;
        }
        let stmt = std::mem::take(&mut pending);
        let Some((k, v)) = stmt.split_once('=') else {
            continue;
        };
        let (k, v) = (norm_key(k), v.trim().to_string());
        if let Some(dep) = &table_dep {
            deps.get_mut(dep).unwrap().insert(k, norm_value(&v));
        } else if let Some(kind) = dep_kind(&section) {
            let entry = deps.entry(format!("{} {}", kind, k)).or_default();
            if v.starts_with('{') {
                for pair in split_top(v.trim_start_matches('{').trim_end_matches('}')) {
                    if let Some((fk, fv)) = pair.split_once('=') {
                        entry.insert(norm_key(fk), norm_value(fv));
                    }
                }
            } else {
                entry.insert("version".to_string(), norm_value(&v));
            }
        } else if section == "features" || section == "lib" {
            other.push(format!("[{}] {} = {}", section, k, norm_value(&v)));
        }
    }
    let mut out: Vec<String> = deps
        .iter()
        .map(|(dep, fields)| {
            format!(
                "[{}]: {}",
                dep,
                fields
                    .iter()
                    .map(|(k, v)| format!("{}={}", k, v))
                    .collect::<Vec<_>>()
                    .join("; ")
            )
        })
        .collect();
    other.sort();
    out.extend(other);
    (out, features)
}

fn check_manifest_pin(crate_dir: &str, pin: &str) {
    let (current, features) = manifest(crate_dir);
    assert!(
        !features,
        "T-API: {} has no cargo features (no feature exposes a test encoder)",
        crate_dir
    );
    let current: String = current.iter().map(|l| format!("{}\n", l)).collect();
    if let Ok(dir) = std::env::var("CF_API_OUT") {
        fs::create_dir_all(&dir).expect("api out");
        fs::write(Path::new(&dir).join(pin), &current).expect("api write");
        return;
    }
    let pinned = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("api").join(pin))
        .unwrap_or_default();
    assert_eq!(
        current, pinned,
        "T-API: the normalized dependency specification of {} changed (re-pin api/{} with CF_API_OUT after review)",
        crate_dir, pin
    );
}

#[test]
fn t_api_no_features_and_exactly_the_reviewed_dependencies() {
    check_manifest_pin("crates/editor-proxy-digest", "ioi-proxy-digest.manifest");
    check_manifest_pin("crates/editor-proxy-codec", "ioi-editor-proxy-ipc.manifest");
}

fn all_sources(crate_dir: &str) -> Vec<(String, String)> {
    fn walk(dir: &Path, out: &mut Vec<(String, String)>) {
        let mut entries: Vec<PathBuf> = fs::read_dir(dir)
            .expect("dir")
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().map(|x| x == "rs").unwrap_or(false) {
                out.push((
                    path.display().to_string(),
                    fs::read_to_string(&path).expect("source"),
                ));
            }
        }
    }
    let mut out = Vec::new();
    walk(&root().join(crate_dir).join("src"), &mut out);
    out
}

#[test]
fn t_api_production_forbids_unsafe_and_gates_test_code() {
    for crate_dir in ["crates/editor-proxy-digest", "crates/editor-proxy-codec"] {
        let lib = fs::read_to_string(root().join(crate_dir).join("src/lib.rs")).expect("lib.rs");
        assert!(
            lib.contains("\n#![forbid(unsafe_code)]\n"),
            "T-API: {} forbids unsafe code",
            crate_dir
        );
        assert!(
            lib.contains("\n#![no_std]\n"),
            "T-API: {} is no_std",
            crate_dir
        );
        for (path, text) in all_sources(crate_dir) {
            assert!(
                !text.contains("cfg(feature"),
                "T-API: {} uses a feature cfg",
                path
            );
            assert!(
                !text.contains("unsafe {") && !text.contains("unsafe fn"),
                "T-API: unsafe in {}",
                path
            );
            assert!(
                !text.contains("macro_export"),
                "T-API: an exported macro in {}",
                path
            );
        }
    }
    let lib =
        fs::read_to_string(root().join("crates/editor-proxy-codec/src/lib.rs")).expect("lib.rs");
    assert!(
        lib.contains("\n#[cfg(test)]\nmod tests;\n"),
        "T-API: the test-only encoder's module is cfg(test)"
    );
    assert!(
        lib.contains("#[cfg(any(test, fuzzing))]\npub mod fuzz_support;\n"),
        "T-API: the fuzz interpreter is cfg(test)/cfg(fuzzing) only"
    );
    // Every test_only_ item is behind a test/fuzzing cfg: a cfg'd impl block or its own cfg.
    for (path, text) in all_sources("crates/editor-proxy-codec") {
        if path.contains("/src/tests/") {
            continue;
        }
        let lines: Vec<&str> = text.lines().collect();
        let mut block_gated = false;
        for (i, line) in lines.iter().enumerate() {
            if line.starts_with("impl") {
                let mut j = i;
                block_gated = false;
                while j > 0 {
                    j -= 1;
                    let above = lines[j].trim();
                    if above.starts_with("///") {
                        continue;
                    }
                    block_gated = above == "#[cfg(any(test, fuzzing))]" || above == "#[cfg(test)]";
                    break;
                }
            } else if line.starts_with('}') {
                block_gated = false;
            }
            if line.contains("fn test_only_") {
                let own = lines[..i]
                    .iter()
                    .rev()
                    .map(|l| l.trim())
                    .find(|l| !l.starts_with("///"))
                    .map(|l| l == "#[cfg(test)]" || l == "#[cfg(any(test, fuzzing))]")
                    .unwrap_or(false);
                assert!(
                    block_gated || own,
                    "T-API: {}:{} test_only_ item is not cfg-gated",
                    path,
                    i + 1
                );
            }
        }
    }
}

// ---- the pins DETECT interface and dependency changes (Codex #85 U1 r1 MAJOR 3) ----------------
//
// Each test applies ONE textual change to a copy of a trusted crate's real source or manifest and
// requires the collector's listing to change (so the pin comparison above fails on it).

/// The crate's files with exactly one occurrence of `old` in `file` replaced by `new`.
fn edited(crate_dir: &str, file: &str, old: &str, new: &str) -> Vec<(String, String)> {
    let mut files = crate_files(crate_dir);
    let entry = files
        .iter_mut()
        .find(|(name, _)| name == file)
        .expect("SETUP: the file");
    assert_eq!(
        entry.1.matches(old).count(),
        1,
        "SETUP: the anchor occurs once"
    );
    entry.1 = entry.1.replacen(old, new, 1);
    files
}

/// The manifest text with exactly one occurrence of `old` replaced by `new`.
fn edited_manifest(crate_dir: &str, old: &str, new: &str) -> String {
    let text = manifest_text(crate_dir);
    assert_eq!(
        text.matches(old).count(),
        1,
        "SETUP: the anchor occurs once"
    );
    text.replacen(old, new, 1)
}

const CODEC: &str = "crates/editor-proxy-codec";
const DIGEST: &str = "crates/editor-proxy-digest";

#[test]
fn t_api_pin_detects_a_changed_argument_type() {
    let changed = edited(
        CODEC,
        "wire.rs",
        "        digests: &[Sha256Digest],\n    ) -> Result<OutboundAdmit, TooManyLeaseCandidates> {",
        "        digests: &[[u8; 32]],\n    ) -> Result<OutboundAdmit, TooManyLeaseCandidates> {",
    );
    assert_ne!(
        interface_of(&changed),
        interface(CODEC),
        "T-API: a changed argument type in a pinned multiline signature (OutboundAdmit::new) changes the listing"
    );
}

#[test]
fn t_api_pin_detects_an_added_enum_variant() {
    let changed = edited(
        CODEC,
        "refusal.rs",
        "    RateExceeded,\n}",
        "    RateExceeded,\n    /// Added.\n    Extra,\n}",
    );
    assert_ne!(
        interface_of(&changed),
        interface(CODEC),
        "T-API: an added variant of a public enum (IpcRefusal) changes the listing"
    );
}

#[test]
fn t_api_pin_detects_a_changed_trait_method() {
    let changed = edited(
        CODEC,
        "wire.rs",
        "    fn encode_frame(&self) -> Frame;",
        "    fn encode_frame(&self, extra: u8) -> Frame;",
    );
    assert_ne!(
        interface_of(&changed),
        interface(CODEC),
        "T-API: a changed method of a public trait (EncodeP2d) changes the listing"
    );
}

#[test]
fn t_api_pin_detects_a_changed_reexport_list() {
    let changed = edited(
        CODEC,
        "lib.rs",
        "    P2dRecv, MAX_FRAME,\n};",
        "    P2dRecv, MAX_FRAME, RECV_BUF_LEN,\n};",
    );
    assert_ne!(
        interface_of(&changed),
        interface(CODEC),
        "T-API: an added name in a multiline re-export (pub use wire::{{...}}) changes the listing"
    );
}

#[test]
fn t_api_pin_detects_a_changed_dependency_feature() {
    let changed = edited_manifest(
        CODEC,
        "ioi-proxy-digest = { path = \"../editor-proxy-digest\" }",
        "ioi-proxy-digest = { path = \"../editor-proxy-digest\", features = [\"std\"] }",
    );
    assert_ne!(
        manifest_of(&changed),
        manifest(CODEC),
        "T-API: an added dependency feature changes the pinned dependency specification"
    );
}

#[test]
fn t_api_pin_detects_a_changed_default_features_flag() {
    let changed = edited_manifest(
        DIGEST,
        "sha2 = { version = \"0.10\", default-features = false }",
        "sha2 = { version = \"0.10\" }",
    );
    assert_ne!(
        manifest_of(&changed),
        manifest(DIGEST),
        "T-API: dropping default-features = false changes the pinned dependency specification"
    );
}

#[test]
fn t_api_pin_reads_table_form_dependencies() {
    let same = edited_manifest(
        DIGEST,
        "[dependencies]\nsha2 = { version = \"0.10\", default-features = false }",
        "[dependencies.sha2]\nversion = \"0.10\"\ndefault-features = false",
    );
    assert_eq!(
        manifest_of(&same),
        manifest(DIGEST),
        "T-API: the same dependency written as a [dependencies.sha2] table has the same pinned specification"
    );
    let featured = edited_manifest(
        DIGEST,
        "[dependencies]\nsha2 = { version = \"0.10\", default-features = false }",
        "[dependencies.sha2]\nversion = \"0.10\"\ndefault-features = false\nfeatures = [\"asm\"]",
    );
    assert_ne!(
        manifest_of(&featured),
        manifest(DIGEST),
        "T-API: a feature added in a [dependencies.sha2] table changes the pinned specification"
    );
}

// ---- the pins see INSIDE inline modules and read QUOTED target-table headers (Codex #85 U1 r2 MAJOR 1)
//
// As above: one textual change to a copy of the real source or manifest (or two changes compared), and the listing
// must change.

#[test]
fn t_api_pin_detects_a_changed_constant_inside_an_inline_module() {
    let changed = edited(
        CODEC,
        "fuzz_support.rs",
        "    pub const NOP: u8 = 0x00;",
        "    pub const NOP: u16 = 0x00;",
    );
    assert_ne!(
        interface_of(&changed),
        interface(CODEC),
        "T-API: a changed type of a public constant inside an inline module (fuzz_support::op::NOP) changes the listing"
    );
}

#[test]
fn t_api_pin_detects_an_added_declaration_inside_a_private_module() {
    let changed = edited(
        CODEC,
        "wire.rs",
        "    pub trait Sealed {}",
        "    pub trait Sealed {}\n    /// Added.\n    pub struct Leak;",
    );
    assert_ne!(
        interface_of(&changed),
        interface(CODEC),
        "T-API: a public declaration added inside a private inline module (wire::sealed) changes the listing"
    );
}

#[test]
fn t_api_pin_reads_nested_inline_modules() {
    let nested = |value: &str| {
        edited(
            CODEC,
            "fuzz_support.rs",
            "    pub const NOP: u8 = 0x00;",
            &format!(
                "    pub const NOP: u8 = 0x00;\n    /// Added.\n    pub mod inner {{\n        /// Added.\n        pub const X: u8 = {};\n    }}",
                value
            ),
        )
    };
    assert_ne!(
        interface_of(&nested("1")),
        interface_of(&nested("2")),
        "T-API: a changed constant inside a module nested in an inline module (op::inner::X) changes the listing"
    );
}

/// The codec manifest's last line (its [lints.rust] table's only entry).
const CODEC_LAST_LINE: &str =
    "unexpected_cfgs = { level = \"warn\", check-cfg = [\"cfg(fuzzing)\"] }";

/// The codec manifest with `tables` appended after its last table ([lints.rust]).
fn codec_manifest_with(tables: &str) -> String {
    edited_manifest(
        CODEC,
        CODEC_LAST_LINE,
        &format!("{}\n\n{}", CODEC_LAST_LINE, tables),
    )
}

#[test]
fn t_api_pin_reads_a_quoted_target_table_header() {
    let linux = |feature: &str| {
        codec_manifest_with(&format!(
            "[target.'cfg(target_os = \"linux\")'.dependencies]\nserde = {{ version = \"1\", features = [\"{}\"] }}",
            feature
        ))
    };
    assert_ne!(
        manifest_of(&linux("derive")),
        manifest(CODEC),
        "T-API: a dependency added under a quoted target-table header ([target.'cfg(target_os = \"linux\")'.dependencies]) changes the pinned specification"
    );
    assert_ne!(
        manifest_of(&linux("derive")),
        manifest_of(&linux("std")),
        "T-API: a changed feature of a dependency under a quoted target-table header changes the pinned specification"
    );
    assert_eq!(
        manifest_of(&codec_manifest_with(
            "[target.'cfg(target_os = \"linux\")'.dependencies.serde]\nversion = \"1\"\nfeatures = [\"derive\"]"
        )),
        manifest_of(&linux("derive")),
        "T-API: the same dependency written as a [target.'cfg(...)'.dependencies.serde] table has the same pinned specification"
    );
    let quoted = manifest_of(&codec_manifest_with(
        "[target.'cfg(target_os = \"a.b#c\")'.dependencies]\nserde = \"1\"",
    ));
    assert!(
        quoted
            .0
            .iter()
            .any(|l| l == "[target.cfg(target_os = \"a.b#c\").dependencies serde]: version=1"),
        "T-API: a quoted target name is ONE key (its '.' and '#' are inside the quotes): {:?}",
        quoted.0
    );
}
